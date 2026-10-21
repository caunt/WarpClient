using System.Globalization;
using System.Net;
using System.Net.Quic;
using System.Net.Security;
using System.Net.Sockets;
using System.Runtime.Versioning;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;

using Warp.Cloudflare.Registration;
using Warp.Cloudflare.Tunnel;

namespace Warp.Cloudflare.Http3;

/// <summary>
/// WARP's MASQUE proxy mode: every TCP connection is one HTTP/3 <c>CONNECT host:port</c> stream on a shared QUIC
/// connection, so Cloudflare resolves names and terminates TCP itself. Only TCP is carried in this mode.
/// </summary>
/// <remarks>
/// Uses the same mutual TLS and server key pin as the IP tunnel, with the proxy SNI the server insists on. The official
/// client uses 20-byte QUIC connection IDs; .NET cannot choose them, so a rejected connection is retried on a fresh session.
/// </remarks>
[SupportedOSPlatform("linux")]
[SupportedOSPlatform("macos")]
[SupportedOSPlatform("windows")]
internal sealed class Http3ProxySession : IWarpSession
{
    private const int MaximumHeadersLength = 16384;
    private const long NoError = 0x100;
    private const long RequestCancelled = 0x10C;
    private const string ServerName = "consumer-masque-proxy.cloudflareclient.com";
    private const int ServerPort = 443;
    private const string ZeroTrustServerName = "zt-masque-proxy.cloudflareclient.com";
    private static readonly TimeSpan HandshakeTimeout = TimeSpan.FromSeconds(seconds: 10);
    private static readonly TimeSpan KeepAliveInterval = TimeSpan.FromSeconds(seconds: 10);

    private readonly QuicConnection _connection;
    private readonly ClientIdentity _identity;
    private readonly CancellationTokenSource _stopping = new();
    private volatile bool _closed;
    private QuicStream? _controlStream;
    private Task _draining = Task.CompletedTask;

    private Http3ProxySession(QuicConnection connection, ClientIdentity identity)
    {
        _connection = connection;
        _identity = identity;
    }

    public bool IsClosed => _closed;

    public static async ValueTask<Http3ProxySession> OpenAsync(DeviceRegistration registration, CancellationToken cancellationToken)
    {
        byte[] pinnedKey = MasqueTunnel.ReadServerKey(registration.ServerPublicKey);
        string?[] endpoints = [registration.EndpointIpv4, registration.EndpointIpv6];
        List<Exception> failures = [];

        foreach (string endpoint in endpoints.OfType<string>())
        {
            try
            {
                return await OpenAsync(IPAddress.Parse(endpoint), registration, pinnedKey, cancellationToken).ConfigureAwait(continueOnCapturedContext: false);
            }
            catch (QuicException exception)
            {
                failures.Add(exception);
            }
            catch (AuthenticationException exception)
            {
                failures.Add(exception);
            }
            catch (SocketException exception)
            {
                failures.Add(exception);
            }
        }

        throw new IOException(message: "None of Cloudflare's MASQUE endpoints accepted the HTTP/3 proxy connection.", new AggregateException(failures));
    }

    public async ValueTask<Stream> ConnectTcpAsync(DnsEndPoint remoteEndPoint, CancellationToken cancellationToken)
    {
        string authority = FormatAuthority(remoteEndPoint);
        QuicStream stream;

        try
        {
            stream = await _connection.OpenOutboundStreamAsync(QuicStreamType.Bidirectional, cancellationToken).ConfigureAwait(continueOnCapturedContext: false);
        }
        catch (QuicException)
        {
            _closed = true;

            throw;
        }

        try
        {
            byte[] request = Http3Framing.CreateFrame(Http3Framing.HeadersFrame, QpackFieldSection.CreateConnectRequest(authority));

            await stream.WriteAsync(request, cancellationToken).ConfigureAwait(continueOnCapturedContext: false);

            int status = await ReadStatusAsync(stream, cancellationToken).ConfigureAwait(continueOnCapturedContext: false);

            return status is < 200 or > 299
                ? throw new IOException($"Cloudflare refused CONNECT {authority} with HTTP status {status}.")
                : (Stream)new Http3DataStream(stream);
        }
        catch
        {
            await stream.DisposeAsync().ConfigureAwait(continueOnCapturedContext: false);

            throw;
        }
    }

    public ValueTask<IUdpConnection> ConnectUdpAsync(DnsEndPoint remoteEndPoint, CancellationToken cancellationToken)
    {
        throw new NotSupportedException(message: "Cloudflare's HTTP/3 proxy mode carries TCP only; use MasqueHttp2 or WireGuard for UDP.");
    }

    public async ValueTask DisposeAsync()
    {
        _closed = true;
        await _stopping.CancelAsync().ConfigureAwait(continueOnCapturedContext: false);

        if (_controlStream is not null)
            await _controlStream.DisposeAsync().ConfigureAwait(continueOnCapturedContext: false);

        await _connection.CloseAsync(NoError).ConfigureAwait(continueOnCapturedContext: false);
        await _connection.DisposeAsync().ConfigureAwait(continueOnCapturedContext: false);
        await _draining.ConfigureAwait(continueOnCapturedContext: false);
        _identity.Dispose();
        _stopping.Dispose();
    }

    private static string FormatAuthority(DnsEndPoint endPoint)
    {
        bool bracketed = IPAddress.TryParse(endPoint.Host, out IPAddress? address) && address.AddressFamily == AddressFamily.InterNetworkV6;
        string host = bracketed ? $"[{endPoint.Host}]" : endPoint.Host;

        return string.Create(CultureInfo.InvariantCulture, $"{host}:{endPoint.Port}");
    }

    private static async ValueTask<Http3ProxySession> OpenAsync(IPAddress address, DeviceRegistration registration, byte[] pinnedKey, CancellationToken cancellationToken)
    {
        ClientIdentity identity = new(registration.PrivateKey);

        QuicClientConnectionOptions options = new()
        {
            RemoteEndPoint = new IPEndPoint(address, ServerPort),
            DefaultStreamErrorCode = RequestCancelled,
            DefaultCloseErrorCode = NoError,
            MaxInboundBidirectionalStreams = 0,
            MaxInboundUnidirectionalStreams = 8,
            HandshakeTimeout = HandshakeTimeout,
            KeepAliveInterval = KeepAliveInterval,
            ClientAuthenticationOptions = new SslClientAuthenticationOptions
            {
                TargetHost = registration.IsZeroTrust ? ZeroTrustServerName : ServerName,
                ApplicationProtocols = [SslApplicationProtocol.Http3],
                ClientCertificates = [identity.Certificate],
                RemoteCertificateValidationCallback = (sender, certificate, chain, errors) =>
                    certificate is X509Certificate2 serverCertificate && serverCertificate.PublicKey.ExportSubjectPublicKeyInfo().AsSpan().SequenceEqual(pinnedKey),
            },
        };

        QuicConnection? connection = null;

        try
        {
            connection = await QuicConnection.ConnectAsync(options, cancellationToken).ConfigureAwait(continueOnCapturedContext: false);

            Http3ProxySession session = new(connection, identity);

            connection = null;
            await session.StartAsync(cancellationToken).ConfigureAwait(continueOnCapturedContext: false);

            return session;
        }
        catch
        {
            identity.Dispose();

            throw;
        }
        finally
        {
            if (connection is not null)
                await connection.DisposeAsync().ConfigureAwait(continueOnCapturedContext: false);
        }
    }

    private static async ValueTask<int> ReadStatusAsync(QuicStream stream, CancellationToken cancellationToken)
    {
        Http3FrameHeader? frame = await Http3Framing.ReadHeaderAsync(stream, cancellationToken).ConfigureAwait(continueOnCapturedContext: false);

        // Unknown and reserved frame types may precede the response headers and are skipped (RFC 9114 section 9).
        while (frame is Http3FrameHeader skipped && skipped.Type != Http3Framing.HeadersFrame)
        {
            await Http3Framing.SkipAsync(stream, skipped.Length, cancellationToken).ConfigureAwait(continueOnCapturedContext: false);
            frame = await Http3Framing.ReadHeaderAsync(stream, cancellationToken).ConfigureAwait(continueOnCapturedContext: false);
        }

        if (frame is not Http3FrameHeader headers || headers.Length > MaximumHeadersLength)
            throw new IOException(message: "Cloudflare ended the HTTP/3 stream without response headers.");

        byte[] section = new byte[headers.Length];

        await stream.ReadExactlyAsync(section, cancellationToken).ConfigureAwait(continueOnCapturedContext: false);

        return QpackFieldSection.DecodeStatus(section);
    }

    private async Task DrainAsync(QuicStream inbound, CancellationToken cancellationToken)
    {
        byte[] buffer = new byte[1024];

        await using (inbound.ConfigureAwait(continueOnCapturedContext: false))
        {
            try
            {
                int read = await inbound.ReadAsync(buffer, cancellationToken).ConfigureAwait(continueOnCapturedContext: false);

                while (read > 0)
                    read = await inbound.ReadAsync(buffer, cancellationToken).ConfigureAwait(continueOnCapturedContext: false);
            }
            catch (QuicException)
            {
                _closed = true;
            }
            catch (OperationCanceledException)
            {
                _closed = true;
            }
        }
    }

    // The server's control and QPACK streams must stay open and be read; their contents need no action here.
    private async Task DrainInboundStreamsAsync(CancellationToken cancellationToken)
    {
        List<Task> readers = [];

        try
        {
            while (!cancellationToken.IsCancellationRequested)
            {
                QuicStream inbound = await _connection.AcceptInboundStreamAsync(cancellationToken).ConfigureAwait(continueOnCapturedContext: false);

                readers.Add(DrainAsync(inbound, cancellationToken));
            }
        }
        catch (QuicException)
        {
            _closed = true;
        }
        catch (OperationCanceledException)
        {
            _closed = true;
        }
        catch (ObjectDisposedException)
        {
            _closed = true;
        }

        await Task.WhenAll(readers).ConfigureAwait(continueOnCapturedContext: false);
    }

    private async ValueTask StartAsync(CancellationToken cancellationToken)
    {
        // Every HTTP/3 endpoint opens a control stream whose first frame is SETTINGS; empty SETTINGS keep all defaults,
        // including a QPACK dynamic table capacity of zero.
        _controlStream = await _connection.OpenOutboundStreamAsync(QuicStreamType.Unidirectional, cancellationToken).ConfigureAwait(continueOnCapturedContext: false);

        byte[] preface = [(byte)Http3Framing.ControlStreamType, .. Http3Framing.CreateFrame(Http3Framing.SettingsFrame, [])];

        await _controlStream.WriteAsync(preface, cancellationToken).ConfigureAwait(continueOnCapturedContext: false);
        _draining = DrainInboundStreamsAsync(_stopping.Token);
    }
}
