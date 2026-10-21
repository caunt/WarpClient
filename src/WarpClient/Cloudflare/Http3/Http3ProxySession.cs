using System.Globalization;
using System.Net;
using System.Net.Sockets;

using Warp.Cloudflare.Registration;
using Warp.Quic;

namespace Warp.Cloudflare.Http3;

/// <summary>
/// WARP's MASQUE proxy mode: every TCP connection is one HTTP/3 <c>CONNECT address:port</c> stream on a shared QUIC
/// connection, and Cloudflare terminates TCP itself. Only TCP is carried in this mode.
/// </summary>
/// <remarks>
/// Uses the same mutual TLS and server key pin as the IP tunnel, with the proxy SNI the server insists on. Cloudflare
/// refuses host names with HTTP 403, so names are resolved first by DNS that also travels through the proxy.
/// </remarks>
internal sealed class Http3ProxySession : IWarpSession
{
    private const string ServerName = "consumer-masque-proxy.cloudflareclient.com";
    private const string ZeroTrustServerName = "zt-masque-proxy.cloudflareclient.com";
    private static readonly TimeSpan ResponseTimeout = TimeSpan.FromSeconds(seconds: 10);

    private readonly MasqueHttp3Connection _connection;
    private readonly ProxyDnsResolver _resolver;

    private Http3ProxySession(MasqueHttp3Connection connection)
    {
        _connection = connection;
        _resolver = new ProxyDnsResolver(connection);
    }

    public bool IsClosed => _connection.IsClosed;

    /// <summary>
    /// Opens a CONNECT stream to an address and waits for Cloudflare to accept it.
    /// </summary>
    public static async ValueTask<Stream> ConnectAsync(MasqueHttp3Connection connection, IPEndPoint remoteEndPoint, CancellationToken cancellationToken)
    {
        string host = remoteEndPoint.AddressFamily == AddressFamily.InterNetworkV6 ? $"[{remoteEndPoint.Address}]" : remoteEndPoint.Address.ToString();
        string authority = string.Create(CultureInfo.InvariantCulture, $"{host}:{remoteEndPoint.Port}");
        ManagedQuicStream stream = await connection.OpenRequestStreamAsync(cancellationToken).ConfigureAwait(continueOnCapturedContext: false);

        using CancellationTokenSource response = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);

        response.CancelAfter(ResponseTimeout);

        try
        {
            byte[] request = Http3Framing.CreateFrame(Http3Framing.HeadersFrame, QpackFieldSection.CreateConnectRequest(authority));

            await stream.WriteAsync(request, response.Token).ConfigureAwait(continueOnCapturedContext: false);

            int status = await Http3Framing.ReadResponseStatusAsync(stream, response.Token).ConfigureAwait(continueOnCapturedContext: false);

            return status is < 200 or > 299
                ? throw new IOException($"Cloudflare refused CONNECT {authority} with HTTP status {status}.")
                : (Stream)new Http3DataStream(stream);
        }
        catch (OperationCanceledException exception) when (!cancellationToken.IsCancellationRequested)
        {
            await stream.DisposeAsync().ConfigureAwait(continueOnCapturedContext: false);

            throw new IOException($"Cloudflare did not answer CONNECT {authority} within {ResponseTimeout.TotalSeconds} seconds.", exception);
        }
        catch
        {
            await stream.DisposeAsync().ConfigureAwait(continueOnCapturedContext: false);

            throw;
        }
    }

    public static async ValueTask<Http3ProxySession> OpenAsync(DeviceRegistration registration, IUdpConnector underlay, CancellationToken cancellationToken)
    {
        string serverName = registration.IsZeroTrust ? ZeroTrustServerName : ServerName;

        MasqueHttp3Connection connection = await MasqueHttp3Connection.OpenAsync(registration, underlay, serverName, [], datagrams: false, cancellationToken)
            .ConfigureAwait(continueOnCapturedContext: false);

        return new Http3ProxySession(connection);
    }

    public async ValueTask<Stream> ConnectTcpAsync(DnsEndPoint remoteEndPoint, CancellationToken cancellationToken)
    {
        IPAddress address = IPAddress.TryParse(remoteEndPoint.Host, out IPAddress? literal)
            ? literal
            : await _resolver.ResolveAsync(remoteEndPoint.Host, cancellationToken).ConfigureAwait(continueOnCapturedContext: false);

        return await ConnectAsync(_connection, new IPEndPoint(address, remoteEndPoint.Port), cancellationToken).ConfigureAwait(continueOnCapturedContext: false);
    }

    public ValueTask<IUdpConnection> ConnectUdpAsync(DnsEndPoint remoteEndPoint, CancellationToken cancellationToken)
    {
        throw new NotSupportedException(message: "Cloudflare's HTTP/3 proxy mode carries TCP only; use MasqueHttp2, MasqueHttp3 or WireGuard for UDP.");
    }

    public ValueTask DisposeAsync()
    {
        return _connection.DisposeAsync();
    }
}
