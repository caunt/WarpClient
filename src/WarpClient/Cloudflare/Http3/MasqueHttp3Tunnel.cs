using Warp.Cloudflare.Registration;
using Warp.Networking;
using Warp.Quic;

namespace Warp.Cloudflare.Http3;

/// <summary>
/// WARP's MASQUE IP tunnel over HTTP/3: one extended CONNECT with Cloudflare's <c>cf-connect-ip</c> protocol, after which
/// every IP packet travels as an HTTP datagram in a QUIC DATAGRAM frame.
/// </summary>
/// <remarks>
/// Cloudflare deviates from RFC 9484: it neither advertises extended CONNECT nor assigns addresses or routes in-band, so the
/// client sends the request regardless and takes its addresses from the registration.
/// </remarks>
internal sealed class MasqueHttp3Tunnel : IPacketTunnel
{
    private const string Authority = "cloudflareaccess.com";
    private const ulong H3DatagramSetting = 0x33;
    private const ulong LegacyH3DatagramSetting = 0x276;
    private const ulong PacketContext = 0;
    private const string Protocol = "cf-connect-ip";
    private const string ServerName = "consumer-masque.cloudflareclient.com";
    private const string ZeroTrustServerName = "zt-masque.cloudflareclient.com";

    private readonly MasqueHttp3Connection _connection;
    private readonly byte[] _datagramPrefix;
    private readonly ulong _quarterStreamId;
    private readonly ManagedQuicStream _request;
    private readonly CancellationTokenSource _stopping = new();
    private volatile bool _closed;
    private int _disposed;
    private Task _receiving = Task.CompletedTask;
    private Task _watching = Task.CompletedTask;

    private MasqueHttp3Tunnel(MasqueHttp3Connection connection, ManagedQuicStream request)
    {
        _connection = connection;
        _request = request;
        _quarterStreamId = (ulong)request.Id / 4;

        // Each datagram names the request it belongs to by quarter stream ID, then the CONNECT-IP context; zero is IP packets.
        QuicWriter prefix = new();

        prefix.WriteVariableLengthInteger(_quarterStreamId);
        prefix.WriteVariableLengthInteger(PacketContext);
        _datagramPrefix = prefix.ToArray();
    }

    public bool IsClosed => _closed || _connection.IsClosed;

    public static async ValueTask<MasqueHttp3Tunnel> OpenAsync(DeviceRegistration registration, IUdpConnector underlay, CancellationToken cancellationToken)
    {
        // Cloudflare requires datagram support in SETTINGS, and its own client also sends the setting's draft code point.
        QuicWriter settings = new();

        settings.WriteVariableLengthInteger(H3DatagramSetting);
        settings.WriteVariableLengthInteger(value: 1);
        settings.WriteVariableLengthInteger(LegacyH3DatagramSetting);
        settings.WriteVariableLengthInteger(value: 1);

        string serverName = registration.IsZeroTrust ? ZeroTrustServerName : ServerName;

        MasqueHttp3Connection connection = await MasqueHttp3Connection.OpenAsync(registration, underlay, serverName, settings.ToArray(), datagrams: true, cancellationToken)
            .ConfigureAwait(continueOnCapturedContext: false);

        try
        {
            ManagedQuicStream request = await connection.OpenRequestStreamAsync(cancellationToken).ConfigureAwait(continueOnCapturedContext: false);
            MasqueHttp3Tunnel tunnel = new(connection, request);

            await tunnel.EstablishAsync(cancellationToken).ConfigureAwait(continueOnCapturedContext: false);

            return tunnel;
        }
        catch
        {
            await connection.DisposeAsync().ConfigureAwait(continueOnCapturedContext: false);

            throw;
        }
    }

    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposed, value: 1) != 0)
            return;

        _closed = true;
        await _stopping.CancelAsync().ConfigureAwait(continueOnCapturedContext: false);
        await _request.DisposeAsync().ConfigureAwait(continueOnCapturedContext: false);
        await _connection.DisposeAsync().ConfigureAwait(continueOnCapturedContext: false);
        await _receiving.ConfigureAwait(continueOnCapturedContext: false);
        await _watching.ConfigureAwait(continueOnCapturedContext: false);
        _stopping.Dispose();
    }

    public void StartReceiving(IPacketReceiver receiver)
    {
        _receiving = ReceiveAsync(receiver, _stopping.Token);
    }

    public async ValueTask TransmitAsync(ReadOnlyMemory<byte> packet, CancellationToken cancellationToken)
    {
        if (IsClosed)
            throw new IOException(message: "The MASQUE tunnel is closed.");

        byte[] datagram = [.. _datagramPrefix, .. packet.Span];

        // A packet too large for one QUIC datagram is dropped, as a router drops what exceeds its link.
        if (datagram.Length > _connection.Connection.MaximumDatagramPayloadSize)
            return;

        await _connection.Connection.SendDatagramAsync(datagram, cancellationToken).ConfigureAwait(continueOnCapturedContext: false);
    }

    private async ValueTask EstablishAsync(CancellationToken cancellationToken)
    {
        byte[] request = Http3Framing.CreateFrame(Http3Framing.HeadersFrame, QpackFieldSection.CreateExtendedConnectRequest(Protocol, Authority));

        await _request.WriteAsync(request, cancellationToken).ConfigureAwait(continueOnCapturedContext: false);

        int status = await Http3Framing.ReadResponseStatusAsync(_request, cancellationToken).ConfigureAwait(continueOnCapturedContext: false);

        if (status is < 200 or > 299)
            throw new IOException($"Cloudflare refused the {Protocol} tunnel with HTTP status {status}.");

        _watching = WatchRequestAsync(_stopping.Token);
    }

    private async Task ReceiveAsync(IPacketReceiver receiver, CancellationToken cancellationToken)
    {
        Exception reason = new IOException(message: "The MASQUE tunnel was closed.");

        try
        {
            while (!cancellationToken.IsCancellationRequested)
            {
                byte[] datagram = await _connection.Connection.ReceiveDatagramAsync(cancellationToken).ConfigureAwait(continueOnCapturedContext: false);

                bool readable = VariableLengthInteger.TryRead(datagram, out ulong quarterStreamId, out int streamLength)
                    & VariableLengthInteger.TryRead(datagram.AsSpan(streamLength), out ulong context, out int contextLength);

                // Datagrams for another request or another context carry nothing this tunnel understands.
                if (readable && quarterStreamId == _quarterStreamId && context == PacketContext)
                    await receiver.ReceiveAsync(datagram.AsMemory(streamLength + contextLength), cancellationToken).ConfigureAwait(continueOnCapturedContext: false);
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

        _closed = true;
        await receiver.StopAsync(reason).ConfigureAwait(continueOnCapturedContext: false);
    }

    // The tunnel lives exactly as long as its request stream; Cloudflare ends idle tunnels by closing it.
    private async Task WatchRequestAsync(CancellationToken cancellationToken)
    {
        byte[] buffer = new byte[1024];

        try
        {
            while (await _request.ReadAsync(buffer, cancellationToken).ConfigureAwait(continueOnCapturedContext: false) > 0)
                cancellationToken.ThrowIfCancellationRequested();
        }
        catch (IOException)
        {
            _closed = true;
        }
        catch (OperationCanceledException)
        {
            _closed = true;
        }

        _closed = true;
        await _stopping.CancelAsync().ConfigureAwait(continueOnCapturedContext: false);
    }
}
