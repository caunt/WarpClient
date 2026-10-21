using System.Buffers.Binary;
using System.Net;
using System.Net.Security;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

using Nito.AsyncEx;

using Warp.Cloudflare.Registration;
using Warp.Networking;

namespace Warp.Cloudflare.Tunnel;

/// <summary>
/// Cloudflare WARP's MASQUE IP tunnel over HTTP/2: one <c>CONNECT</c> stream whose body carries IP packets in DATAGRAM capsules.
/// </summary>
/// <remarks>
/// HTTP/2 over TCP is used instead of HTTP/3 because .NET does not expose QUIC datagrams yet and because it works on networks
/// that block UDP. The request mirrors the official client: <c>cf-connect-proto: cf-connect-ip</c> on a classic CONNECT to
/// <c>cloudflareaccess.com:443</c>. Authentication is mutual TLS with the enrolled device key, and the server is verified by
/// pinning the public key returned at enrollment rather than by host name.
/// </remarks>
internal sealed class MasqueTunnel : IPacketTransmitter, IAsyncDisposable
{
    private const byte AcknowledgeFlag = 0x1;
    private const int AuthorityHeaderIndex = 1;
    private const string ConnectAuthority = "cloudflareaccess.com:443";
    private const int ConnectionStream = 0;
    private const byte DataFrame = 0x0;
    private const int DefaultWindowSize = ushort.MaxValue;
    private const ushort EnablePushSetting = 0x2;
    private const byte EndHeadersFlag = 0x4;
    private const byte EndStreamFlag = 0x1;
    private const byte GoAwayFrame = 0x7;
    private const byte HeadersFrame = 0x1;
    private const ushort InitialWindowSizeSetting = 0x4;
    private const int MaximumFrameSize = 16384;
    private const int MethodHeaderIndex = 2;
    private const byte PaddedFlag = 0x8;
    private const byte PingFrame = 0x6;
    private const byte PriorityFlag = 0x20;
    private const int PriorityLength = 5;
    private const int ReceiveWindowSize = 16 * 1024 * 1024;
    private const byte ResetFrame = 0x3;
    private const string ServerName = "consumer-masque.cloudflareclient.com";
    private const int ServerPort = 443;
    private const int SettingLength = 6;
    private const byte SettingsFrame = 0x4;
    private const int SuccessStatus = 200;
    private const int TunnelStream = 1;
    private const int UserAgentHeaderIndex = 58;
    private const byte WindowUpdateFrame = 0x8;
    private const int WindowUpdateThreshold = 1024 * 1024;
    private const string ZeroTrustServerName = "zt-masque.cloudflareclient.com";
    private static readonly byte[] ConnectionPreface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"u8.ToArray();

    private readonly AsyncLock _writeMutex = new();
    private readonly CapsuleParser _capsuleParser = new();
    private readonly ClientIdentity _identity;
    private readonly CancellationTokenSource _stopping = new();
    private readonly SslStream _transport;
    private readonly byte[] _frameBuffer = new byte[MaximumFrameSize];
    private volatile bool _closed;
    private long _connectionSendWindow = DefaultWindowSize;
    private long _streamSendWindow = DefaultWindowSize;
    private int _peerInitialWindowSize = DefaultWindowSize;
    private Task _receiving = Task.CompletedTask;
    private int _unacknowledgedConnectionBytes;
    private int _unacknowledgedStreamBytes;

    private MasqueTunnel(Stream connection, string privateKey)
    {
        _identity = new ClientIdentity(privateKey);
        _transport = new SslStream(connection, leaveInnerStreamOpen: false);
    }

    public bool IsClosed => _closed;

    public static async ValueTask<MasqueTunnel> OpenAsync(DeviceRegistration registration, ITcpConnector underlay, CancellationToken cancellationToken)
    {
        byte[] pinnedKey = ReadServerKey(registration.ServerPublicKey);
        string?[] endpoints = [registration.EndpointIpv4, registration.EndpointIpv6];
        List<Exception> failures = [];

        foreach (string endpoint in endpoints.OfType<string>())
        {
            try
            {
                return await OpenAsync(endpoint, registration, pinnedKey, underlay, cancellationToken).ConfigureAwait(continueOnCapturedContext: false);
            }
            catch (IOException exception)
            {
                failures.Add(exception);
            }
            catch (AuthenticationException exception)
            {
                failures.Add(exception);
            }
        }

        throw new IOException(message: "None of Cloudflare's MASQUE endpoints accepted the tunnel.", new AggregateException(failures));
    }

    public async ValueTask DisposeAsync()
    {
        _closed = true;
        await _stopping.CancelAsync().ConfigureAwait(continueOnCapturedContext: false);
        await _transport.DisposeAsync().ConfigureAwait(continueOnCapturedContext: false);
        await _receiving.ConfigureAwait(continueOnCapturedContext: false);
        _identity.Dispose();
        _stopping.Dispose();
    }

    public void StartReceiving(IPacketReceiver receiver)
    {
        _receiving = ReceiveAsync(receiver, _stopping.Token);
    }

    public async ValueTask TransmitAsync(ReadOnlyMemory<byte> packet, CancellationToken cancellationToken)
    {
        int headerLength = VariableLengthInteger.GetLength(value: 0) + VariableLengthInteger.GetLength((ulong)packet.Length);
        byte[] capsule = new byte[headerLength + packet.Length];
        int written = VariableLengthInteger.Write(value: 0, capsule);

        written += VariableLengthInteger.Write((ulong)packet.Length, capsule.AsSpan(written));
        packet.Span.CopyTo(capsule.AsSpan(written));

        using (await _writeMutex.LockAsync(cancellationToken).ConfigureAwait(continueOnCapturedContext: false))
        {
            if (_closed)
                throw new IOException(message: "The MASQUE tunnel is closed.");

            bool fits = capsule.Length <= MaximumFrameSize && capsule.Length <= _connectionSendWindow && capsule.Length <= _streamSendWindow;

            // An exhausted flow-control window drops the packet, as a full router queue would; TCP retransmits it later.
            if (!fits)
                return;

            _connectionSendWindow -= capsule.Length;
            _streamSendWindow -= capsule.Length;
            await WriteFrameAsync(DataFrame, flags: 0, TunnelStream, capsule, cancellationToken).ConfigureAwait(continueOnCapturedContext: false);
            await _transport.FlushAsync(cancellationToken).ConfigureAwait(continueOnCapturedContext: false);
        }
    }

    private static async ValueTask<MasqueTunnel> OpenAsync(string endpoint, DeviceRegistration registration, byte[] pinnedKey, ITcpConnector underlay, CancellationToken cancellationToken)
    {
        Stream connection = await underlay.ConnectAsync(new DnsEndPoint(endpoint, ServerPort), cancellationToken).ConfigureAwait(continueOnCapturedContext: false);
        MasqueTunnel tunnel = new(connection, registration.PrivateKey);

        try
        {
            await tunnel.AuthenticateAsync(registration.IsZeroTrust ? ZeroTrustServerName : ServerName, pinnedKey, cancellationToken).ConfigureAwait(continueOnCapturedContext: false);
            await tunnel.HandshakeAsync(cancellationToken).ConfigureAwait(continueOnCapturedContext: false);

            return tunnel;
        }
        catch
        {
            await tunnel.DisposeAsync().ConfigureAwait(continueOnCapturedContext: false);

            throw;
        }
    }

    private static int? ReadInitialWindowSize(ReadOnlySpan<byte> settings)
    {
        int? initialWindowSize = null;

        for (int offset = 0; offset + SettingLength <= settings.Length; offset += SettingLength)
        {
            if (BinaryPrimitives.ReadUInt16BigEndian(settings[offset..]) == InitialWindowSizeSetting)
                initialWindowSize = BinaryPrimitives.ReadInt32BigEndian(settings[(offset + 2)..]);
        }

        return initialWindowSize;
    }

    private static byte[] ReadServerKey(string publicKey)
    {
        using ECDsa key = ECDsa.Create();

        // Enrollment normally returns PEM, but some responses carry the bare base64 SubjectPublicKeyInfo.
        if (publicKey.Contains(value: "-----BEGIN", StringComparison.Ordinal))
            key.ImportFromPem(publicKey);
        else
            key.ImportSubjectPublicKeyInfo(Convert.FromBase64String(publicKey), out _);

        return key.ExportSubjectPublicKeyInfo();
    }

    private async ValueTask AnswerPingAsync(Http2FrameHeader frame, CancellationToken cancellationToken)
    {
        byte[] opaqueData = _frameBuffer.AsSpan(start: 0, frame.Length).ToArray();

        using (await _writeMutex.LockAsync(cancellationToken).ConfigureAwait(continueOnCapturedContext: false))
        {
            await WriteFrameAsync(PingFrame, AcknowledgeFlag, ConnectionStream, opaqueData, cancellationToken).ConfigureAwait(continueOnCapturedContext: false);
            await _transport.FlushAsync(cancellationToken).ConfigureAwait(continueOnCapturedContext: false);
        }
    }

    private async ValueTask ApplySettingsAsync(Http2FrameHeader frame, CancellationToken cancellationToken)
    {
        int? initialWindowSize = ReadInitialWindowSize(_frameBuffer.AsSpan(start: 0, frame.Length));

        using (await _writeMutex.LockAsync(cancellationToken).ConfigureAwait(continueOnCapturedContext: false))
        {
            if (initialWindowSize is int windowSize)
            {
                _streamSendWindow += windowSize - _peerInitialWindowSize;
                _peerInitialWindowSize = windowSize;
            }

            await WriteFrameAsync(SettingsFrame, AcknowledgeFlag, ConnectionStream, ReadOnlyMemory<byte>.Empty, cancellationToken).ConfigureAwait(continueOnCapturedContext: false);
            await _transport.FlushAsync(cancellationToken).ConfigureAwait(continueOnCapturedContext: false);
        }
    }

    private async ValueTask ApplyWindowUpdateAsync(Http2FrameHeader frame, CancellationToken cancellationToken)
    {
        int increment = BinaryPrimitives.ReadInt32BigEndian(_frameBuffer) & int.MaxValue;

        using (await _writeMutex.LockAsync(cancellationToken).ConfigureAwait(continueOnCapturedContext: false))
        {
            if (frame.StreamIdentifier == ConnectionStream)
                _connectionSendWindow += increment;
            else if (frame.StreamIdentifier == TunnelStream)
                _streamSendWindow += increment;
        }
    }

    private async ValueTask AuthenticateAsync(string serverName, byte[] pinnedKey, CancellationToken cancellationToken)
    {
        SslClientAuthenticationOptions options = new()
        {
            TargetHost = serverName,
            ApplicationProtocols = [SslApplicationProtocol.Http2],
            ClientCertificates = [_identity.Certificate],
            RemoteCertificateValidationCallback = (sender, certificate, chain, errors) =>
                certificate is X509Certificate2 serverCertificate && serverCertificate.PublicKey.ExportSubjectPublicKeyInfo().AsSpan().SequenceEqual(pinnedKey),
        };

        await _transport.AuthenticateAsClientAsync(options, cancellationToken).ConfigureAwait(continueOnCapturedContext: false);
    }

    private async ValueTask CreditReceivedAsync(int length, bool tunnelData, CancellationToken cancellationToken)
    {
        _unacknowledgedConnectionBytes += length;

        if (tunnelData)
            _unacknowledgedStreamBytes += length;

        if (_unacknowledgedConnectionBytes < WindowUpdateThreshold && _unacknowledgedStreamBytes < WindowUpdateThreshold)
            return;

        using (await _writeMutex.LockAsync(cancellationToken).ConfigureAwait(continueOnCapturedContext: false))
        {
            await WriteWindowUpdateAsync(ConnectionStream, _unacknowledgedConnectionBytes, cancellationToken).ConfigureAwait(continueOnCapturedContext: false);
            await WriteWindowUpdateAsync(TunnelStream, _unacknowledgedStreamBytes, cancellationToken).ConfigureAwait(continueOnCapturedContext: false);
            await _transport.FlushAsync(cancellationToken).ConfigureAwait(continueOnCapturedContext: false);
        }

        _unacknowledgedConnectionBytes = 0;
        _unacknowledgedStreamBytes = 0;
    }

    private int DecodeStatus(Http2FrameHeader frame)
    {
        ReadOnlySpan<byte> block = _frameBuffer.AsSpan(start: 0, frame.Length);
        int padding = 0;

        if ((frame.Flags & PaddedFlag) != 0)
        {
            padding = block[index: 0];
            block = block[1..];
        }

        if ((frame.Flags & PriorityFlag) != 0)
            block = block[PriorityLength..];

        return ResponseStatusDecoder.Decode(block[..^padding]);
    }

    private ReadOnlySpan<byte> GetDataPayload(Http2FrameHeader frame)
    {
        ReadOnlySpan<byte> payload = _frameBuffer.AsSpan(start: 0, frame.Length);

        return (frame.Flags & PaddedFlag) != 0 ? payload[1..^payload[index: 0]] : payload;
    }

    private async ValueTask HandleControlFrameAsync(Http2FrameHeader frame, CancellationToken cancellationToken)
    {
        bool acknowledgment = (frame.Flags & AcknowledgeFlag) != 0;

        switch (frame.Type)
        {
            case SettingsFrame when !acknowledgment:
                {
                    await ApplySettingsAsync(frame, cancellationToken).ConfigureAwait(continueOnCapturedContext: false);

                    break;
                }
            case PingFrame when !acknowledgment:
                {
                    await AnswerPingAsync(frame, cancellationToken).ConfigureAwait(continueOnCapturedContext: false);

                    break;
                }
            case WindowUpdateFrame:
                {
                    await ApplyWindowUpdateAsync(frame, cancellationToken).ConfigureAwait(continueOnCapturedContext: false);

                    break;
                }
            case GoAwayFrame:
                throw new IOException(message: "Cloudflare closed the MASQUE connection.");
            case ResetFrame when frame.StreamIdentifier == TunnelStream:
                throw new IOException(message: "Cloudflare reset the MASQUE tunnel stream.");
            default:
                break;
        }
    }

    private async ValueTask HandleDataAsync(Http2FrameHeader frame, IPacketReceiver receiver, CancellationToken cancellationToken)
    {
        bool tunnelData = frame.StreamIdentifier == TunnelStream;
        IReadOnlyList<byte[]> packets = tunnelData ? _capsuleParser.Append(GetDataPayload(frame)) : [];

        foreach (byte[] packet in packets)
            await receiver.ReceiveAsync(packet, cancellationToken).ConfigureAwait(continueOnCapturedContext: false);

        await CreditReceivedAsync(frame.Length, tunnelData, cancellationToken).ConfigureAwait(continueOnCapturedContext: false);

        if (tunnelData && (frame.Flags & EndStreamFlag) != 0)
            throw new IOException(message: "Cloudflare ended the MASQUE tunnel stream.");
    }

    private async ValueTask HandshakeAsync(CancellationToken cancellationToken)
    {
        HeaderBlockEncoder headers = new();

        headers.AddIndexedName(MethodHeaderIndex, value: "CONNECT");
        headers.AddIndexedName(AuthorityHeaderIndex, ConnectAuthority);
        headers.AddIndexedName(UserAgentHeaderIndex, string.Empty);
        headers.AddLiteral(name: "cf-connect-proto", value: "cf-connect-ip");
        headers.AddLiteral(name: "pq-enabled", value: "false");

        byte[] settings = new byte[SettingLength * 2];
        byte[] windowIncrement = new byte[sizeof(uint)];

        BinaryPrimitives.WriteUInt16BigEndian(settings, EnablePushSetting);
        BinaryPrimitives.WriteUInt16BigEndian(settings.AsSpan(SettingLength), InitialWindowSizeSetting);
        BinaryPrimitives.WriteUInt32BigEndian(settings.AsSpan(SettingLength + 2), ReceiveWindowSize);
        BinaryPrimitives.WriteUInt32BigEndian(windowIncrement, ReceiveWindowSize - DefaultWindowSize);

        using (await _writeMutex.LockAsync(cancellationToken).ConfigureAwait(continueOnCapturedContext: false))
        {
            await _transport.WriteAsync(ConnectionPreface, cancellationToken).ConfigureAwait(continueOnCapturedContext: false);
            await WriteFrameAsync(SettingsFrame, flags: 0, ConnectionStream, settings, cancellationToken).ConfigureAwait(continueOnCapturedContext: false);
            await WriteFrameAsync(WindowUpdateFrame, flags: 0, ConnectionStream, windowIncrement, cancellationToken).ConfigureAwait(continueOnCapturedContext: false);
            await WriteFrameAsync(HeadersFrame, EndHeadersFlag, TunnelStream, headers.ToArray(), cancellationToken).ConfigureAwait(continueOnCapturedContext: false);
            await _transport.FlushAsync(cancellationToken).ConfigureAwait(continueOnCapturedContext: false);
        }

        int? status = null;

        while (status is null)
        {
            Http2FrameHeader frame = await ReadFrameAsync(cancellationToken).ConfigureAwait(continueOnCapturedContext: false);

            if (frame.Type == HeadersFrame && frame.StreamIdentifier == TunnelStream)
                status = DecodeStatus(frame);
            else
                await HandleControlFrameAsync(frame, cancellationToken).ConfigureAwait(continueOnCapturedContext: false);

            if (status is not null && (frame.Flags & EndStreamFlag) != 0)
                throw new IOException($"Cloudflare closed the MASQUE tunnel immediately with HTTP status {status}.");
        }

        if (status != SuccessStatus)
            throw new IOException($"Cloudflare refused the MASQUE tunnel with HTTP status {status}.");
    }

    private async ValueTask<Http2FrameHeader> ReadFrameAsync(CancellationToken cancellationToken)
    {
        await _transport.ReadExactlyAsync(_frameBuffer.AsMemory(start: 0, Http2FrameHeader.Size), cancellationToken).ConfigureAwait(continueOnCapturedContext: false);

        Http2FrameHeader frame = Http2FrameHeader.Read(_frameBuffer);

        if (frame.Length > MaximumFrameSize)
            throw new InvalidDataException(message: "Cloudflare sent an HTTP/2 frame larger than the negotiated maximum.");

        await _transport.ReadExactlyAsync(_frameBuffer.AsMemory(start: 0, frame.Length), cancellationToken).ConfigureAwait(continueOnCapturedContext: false);

        return frame;
    }

    private async Task ReceiveAsync(IPacketReceiver receiver, CancellationToken cancellationToken)
    {
        Exception reason = new IOException(message: "The MASQUE tunnel was closed.");

        try
        {
            while (!cancellationToken.IsCancellationRequested)
            {
                Http2FrameHeader frame = await ReadFrameAsync(cancellationToken).ConfigureAwait(continueOnCapturedContext: false);

                if (frame.Type == DataFrame)
                    await HandleDataAsync(frame, receiver, cancellationToken).ConfigureAwait(continueOnCapturedContext: false);
                else
                    await HandleControlFrameAsync(frame, cancellationToken).ConfigureAwait(continueOnCapturedContext: false);
            }
        }
        catch (IOException exception)
        {
            reason = exception;
        }
        catch (InvalidDataException exception)
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

    private async ValueTask WriteFrameAsync(byte type, byte flags, int streamIdentifier, ReadOnlyMemory<byte> payload, CancellationToken cancellationToken)
    {
        byte[] frame = new byte[Http2FrameHeader.Size + payload.Length];

        new Http2FrameHeader(payload.Length, type, flags, streamIdentifier).Write(frame);
        payload.Span.CopyTo(frame.AsSpan(Http2FrameHeader.Size));
        await _transport.WriteAsync(frame, cancellationToken).ConfigureAwait(continueOnCapturedContext: false);
    }

    private async ValueTask WriteWindowUpdateAsync(int streamIdentifier, int increment, CancellationToken cancellationToken)
    {
        if (increment == 0)
            return;

        byte[] payload = new byte[sizeof(uint)];

        BinaryPrimitives.WriteInt32BigEndian(payload, increment);
        await WriteFrameAsync(WindowUpdateFrame, flags: 0, streamIdentifier, payload, cancellationToken).ConfigureAwait(continueOnCapturedContext: false);
    }
}
