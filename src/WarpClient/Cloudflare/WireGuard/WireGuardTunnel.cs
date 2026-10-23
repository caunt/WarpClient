using System.Buffers.Binary;
using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;

using Nito.AsyncEx;

using Warp.Cloudflare.Registration;
using Warp.Networking;

namespace Warp.Cloudflare.WireGuard;

/// <summary>
/// WARP's WireGuard tunnel: a standard WireGuard initiator that also writes Cloudflare's three-byte routing tag (the
/// registration's <c>client_id</c>) into the reserved header bytes of every message it sends.
/// </summary>
/// <remarks>
/// The tag is written after the MACs are computed and cleared from received messages before they are parsed, because
/// Cloudflare authenticates the header with those bytes set to zero. Cookie replies sent under load are not supported.
/// </remarks>
internal sealed class WireGuardTunnel : IPacketTunnel
{
    private const int MaximumMessageLength = 2048;
    private const int RoutingTagLength = 3;
    private static readonly TimeSpan HandshakeRetry = TimeSpan.FromSeconds(seconds: 5);
    private static readonly TimeSpan HandshakeTimeout = TimeSpan.FromSeconds(seconds: 90);
    private static readonly TimeSpan KeepaliveInterval = TimeSpan.FromSeconds(seconds: 25);
    private static readonly TimeSpan RekeyAfter = TimeSpan.FromSeconds(seconds: 120);
    private static readonly TimeSpan RejectAfter = TimeSpan.FromSeconds(seconds: 180);
    private static readonly TimeSpan TimerInterval = TimeSpan.FromSeconds(seconds: 1);

    private readonly IUdpConnection _connection;
    private readonly AsyncLock _mutex = new();
    private readonly WireGuardIdentity _identity;
    private readonly CancellationTokenSource _stopping = new();
    private readonly byte[] _routingTag;
    private readonly TaskCompletionSource _established = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private volatile bool _closed;
    private WireGuardSession? _current;
    private int _disposed;
    private long _handshakeStartedAt;
    private SocketException? _lastNetworkError;
    private long _lastSentAt;
    private HandshakeState? _pending;
    private long _pendingSentAt;
    private WireGuardSession? _previous;
    private IPacketReceiver? _receiver;
    private Task _receiving = Task.CompletedTask;
    private Task _timer = Task.CompletedTask;

    private WireGuardTunnel(IUdpConnection connection, WireGuardIdentity identity, byte[] routingTag)
    {
        _connection = connection;
        _identity = identity;
        _routingTag = routingTag;
    }

    public bool IsClosed => _closed;

    public static async ValueTask<WireGuardTunnel> OpenAsync(DeviceRegistration registration, IUdpConnector underlay, CancellationToken cancellationToken)
    {
        const string notEnrolled = "The device is not enrolled for WireGuard.";
        string encodedPrivateKey = registration.WireGuardPrivateKey ?? throw new InvalidOperationException(notEnrolled);
        string peerPublicKey = registration.WireGuardPeerPublicKey ?? throw new InvalidOperationException(notEnrolled);
        string endpointText = registration.WireGuardEndpoint ?? throw new InvalidOperationException(notEnrolled);

        DnsEndPoint endpoint = ParseEndpoint(endpointText) ?? throw new InvalidDataException($"The WireGuard endpoint {endpointText} is not host:port.");
        byte[] privateKey = Convert.FromBase64String(encodedPrivateKey);
        WireGuardIdentity identity = new(privateKey, WireGuardCrypto.GetPublicKey(privateKey), Convert.FromBase64String(peerPublicKey));
        byte[] routingTag = registration.ClientId is null ? new byte[RoutingTagLength] : Convert.FromBase64String(registration.ClientId);
        IUdpConnection connection = await underlay.ConnectAsync(endpoint, cancellationToken).ConfigureAwait(continueOnCapturedContext: false);
        WireGuardTunnel tunnel = new(connection, identity, routingTag);

        try
        {
            await tunnel.EstablishAsync(cancellationToken).ConfigureAwait(continueOnCapturedContext: false);

            return tunnel;
        }
        catch
        {
            await tunnel.DisposeAsync().ConfigureAwait(continueOnCapturedContext: false);

            throw;
        }
    }

    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposed, value: 1) != 0)
            return;

        _closed = true;
        await _stopping.CancelAsync().ConfigureAwait(continueOnCapturedContext: false);
        await _connection.DisposeAsync().ConfigureAwait(continueOnCapturedContext: false);
        await _receiving.ConfigureAwait(continueOnCapturedContext: false);
        await _timer.ConfigureAwait(continueOnCapturedContext: false);
        _current?.Dispose();
        _previous?.Dispose();
        _stopping.Dispose();
    }

    public void StartReceiving(IPacketReceiver receiver)
    {
        _receiver = receiver;
    }

    public async ValueTask TransmitAsync(ReadOnlyMemory<byte> packet, CancellationToken cancellationToken)
    {
        byte[] message;

        using (await _mutex.LockAsync(cancellationToken).ConfigureAwait(continueOnCapturedContext: false))
        {
            if (_closed)
                throw new IOException(message: "The WireGuard tunnel is closed.");

            // Without live keys the packet is dropped, as a router without a route would; TCP retransmits it after rekeying.
            if (_current is null)
                return;

            message = _current.Seal(packet.Span);
            _lastSentAt = Environment.TickCount64;
        }

        await SendAsync(message, cancellationToken).ConfigureAwait(continueOnCapturedContext: false);
    }

    private static bool IsTransient(SocketError error)
    {
        return error is SocketError.ConnectionRefused or SocketError.ConnectionReset or SocketError.HostUnreachable or SocketError.NetworkUnreachable;
    }

    // Accepts "host:port", "1.2.3.4:port" and "[ipv6]:port".
    private static DnsEndPoint? ParseEndpoint(string endpoint)
    {
        int separator = endpoint.LastIndexOf(value: ':');

        return separator <= 0 || !int.TryParse(endpoint.AsSpan(separator + 1), NumberStyles.None, CultureInfo.InvariantCulture, out int port)
            ? null
            : new DnsEndPoint(endpoint[..separator].Trim(trimChars: ['[', ']']), port);
    }

    private async ValueTask CloseAsync(Exception reason)
    {
        _closed = true;

        using (await _mutex.LockAsync().ConfigureAwait(continueOnCapturedContext: false))
        {
            if (!_established.Task.IsCompleted)
                _established.SetException(reason);
        }

        if (_receiver is not null)
            await _receiver.StopAsync(reason).ConfigureAwait(continueOnCapturedContext: false);
    }

    // Called with the mutex held.
    private async ValueTask CompleteHandshakeAsync(byte[] message, CancellationToken cancellationToken)
    {
        if (_pending is null)
            return;

        TransportKeys? keys = WireGuardHandshake.TryConsumeResponse(_identity, _pending, message);

        if (keys is null)
            return;

        _previous?.Dispose();
        _previous = _current;
        _current = new WireGuardSession(keys, Environment.TickCount64);
        _pending = null;

        // The responder only trusts the new keys after the initiator uses them, so confirm right away with a keepalive.
        byte[] keepalive = _current.Seal([]);

        _lastSentAt = Environment.TickCount64;
        await SendAsync(keepalive, cancellationToken).ConfigureAwait(continueOnCapturedContext: false);

        if (!_established.Task.IsCompleted)
            _established.SetResult();
    }

    private async ValueTask EstablishAsync(CancellationToken cancellationToken)
    {
        _receiving = ReceiveAsync(_stopping.Token);
        _timer = RunTimerAsync(_stopping.Token);

        using (await _mutex.LockAsync(cancellationToken).ConfigureAwait(continueOnCapturedContext: false))
        {
            _handshakeStartedAt = Environment.TickCount64;
            await InitiateAsync(cancellationToken).ConfigureAwait(continueOnCapturedContext: false);
        }

        try
        {
            await _established.Task.WaitAsync(HandshakeTimeout, cancellationToken).ConfigureAwait(continueOnCapturedContext: false);
        }
        catch (OperationCanceledException exception) when (_lastNetworkError is not null)
        {
            throw new IOException($"Cloudflare did not answer the WireGuard handshake; the network reported: {_lastNetworkError.Message}", exception);
        }
    }

    private async ValueTask HandleMessageAsync(byte[] message, CancellationToken cancellationToken)
    {
        if (message[0] == WireGuardHandshake.ResponseType)
        {
            using (await _mutex.LockAsync(cancellationToken).ConfigureAwait(continueOnCapturedContext: false))
                await CompleteHandshakeAsync(message, cancellationToken).ConfigureAwait(continueOnCapturedContext: false);

            return;
        }

        if (message[0] != WireGuardSession.DataType)
            return;

        byte[]? packet;

        using (await _mutex.LockAsync(cancellationToken).ConfigureAwait(continueOnCapturedContext: false))
        {
            uint receiverIndex = BinaryPrimitives.ReadUInt32LittleEndian(message.AsSpan(start: 4));
            WireGuardSession? session = _current?.LocalIndex == receiverIndex ? _current : _previous?.LocalIndex == receiverIndex ? _previous : null;

            packet = session?.Open(message);
        }

        // An empty plaintext is a keepalive; anything else is an IP packet for the stack.
        if (packet is { Length: > 0 } && _receiver is not null)
            await _receiver.ReceiveAsync(packet, cancellationToken).ConfigureAwait(continueOnCapturedContext: false);
    }

    // Called with the mutex held.
    private async ValueTask InitiateAsync(CancellationToken cancellationToken)
    {
        uint senderIndex = BinaryPrimitives.ReadUInt32LittleEndian(RandomNumberGenerator.GetBytes(count: 4));
        HandshakeInitiation initiation = WireGuardHandshake.CreateInitiation(_identity, senderIndex, DateTimeOffset.UtcNow);

        _pending = initiation.State;
        _pendingSentAt = Environment.TickCount64;
        await SendAsync(initiation.Message, cancellationToken).ConfigureAwait(continueOnCapturedContext: false);
    }

    private async Task ReceiveAsync(CancellationToken cancellationToken)
    {
        byte[] buffer = new byte[MaximumMessageLength];
        Exception reason = new IOException(message: "The WireGuard tunnel was closed.");

        try
        {
            while (!cancellationToken.IsCancellationRequested)
            {
                int length = await ReceiveDatagramAsync(buffer, cancellationToken).ConfigureAwait(continueOnCapturedContext: false);

                if (length < WireGuardSession.DataHeaderLength)
                    continue;

                byte[] message = buffer[..length];

                // Cloudflare echoes the routing tag; the reserved bytes must be zero again before the message is authenticated.
                message.AsSpan(start: 1, RoutingTagLength).Clear();
                await HandleMessageAsync(message, cancellationToken).ConfigureAwait(continueOnCapturedContext: false);
            }
        }
        catch (IOException exception)
        {
            reason = exception;
        }
        catch (OperationCanceledException exception)
        {
            reason = exception;
        }
        catch (ObjectDisposedException exception)
        {
            reason = exception;
        }

        await CloseAsync(reason).ConfigureAwait(continueOnCapturedContext: false);
    }

    // ICMP errors such as "port unreachable" surface on a connected UDP socket's next receive. They are transient for
    // WireGuard, which keeps retrying the handshake, so they are remembered for diagnostics instead of ending the tunnel.
    private async ValueTask<int> ReceiveDatagramAsync(byte[] buffer, CancellationToken cancellationToken)
    {
        try
        {
            return await _connection.ReceiveAsync(buffer, cancellationToken).ConfigureAwait(continueOnCapturedContext: false);
        }
        catch (SocketException exception) when (IsTransient(exception.SocketErrorCode))
        {
            _lastNetworkError = exception;

            return 0;
        }
    }

    private async Task RunTimerAsync(CancellationToken cancellationToken)
    {
        using PeriodicTimer ticker = new(TimerInterval);

        try
        {
            while (await ticker.WaitForNextTickAsync(cancellationToken).ConfigureAwait(continueOnCapturedContext: false))
            {
                using (await _mutex.LockAsync(cancellationToken).ConfigureAwait(continueOnCapturedContext: false))
                    await TickAsync(cancellationToken).ConfigureAwait(continueOnCapturedContext: false);
            }
        }
        catch (OperationCanceledException)
        {
            _closed = true;
        }
        catch (IOException exception)
        {
            await CloseAsync(exception).ConfigureAwait(continueOnCapturedContext: false);
        }
    }

    private async ValueTask SendAsync(byte[] message, CancellationToken cancellationToken)
    {
        _routingTag.AsSpan(start: 0, RoutingTagLength).CopyTo(message.AsSpan(start: 1));
        await _connection.SendAsync(message, cancellationToken).ConfigureAwait(continueOnCapturedContext: false);
    }

    // Called with the mutex held.
    private async ValueTask TickAsync(CancellationToken cancellationToken)
    {
        long now = Environment.TickCount64;

        if (_current is not null && now - _current.CreatedAt >= (long)RejectAfter.TotalMilliseconds)
        {
            _current.Dispose();
            _current = null;
        }

        bool waiting = _pending is not null;
        bool retryDue = waiting && now - _pendingSentAt >= (long)HandshakeRetry.TotalMilliseconds;
        bool rekeyDue = !waiting && (_current is null || now - _current.CreatedAt >= (long)RekeyAfter.TotalMilliseconds);

        if (_current is null && waiting && now - _handshakeStartedAt >= (long)HandshakeTimeout.TotalMilliseconds)
            throw new IOException(message: "Cloudflare did not answer the WireGuard handshake.");

        if (rekeyDue && _current is null)
            _handshakeStartedAt = now;

        if (retryDue || rekeyDue)
        {
            await InitiateAsync(cancellationToken).ConfigureAwait(continueOnCapturedContext: false);

            return;
        }

        if (_current is not null && now - _lastSentAt >= (long)KeepaliveInterval.TotalMilliseconds)
        {
            byte[] keepalive = _current.Seal([]);

            _lastSentAt = now;
            await SendAsync(keepalive, cancellationToken).ConfigureAwait(continueOnCapturedContext: false);
        }
    }
}
