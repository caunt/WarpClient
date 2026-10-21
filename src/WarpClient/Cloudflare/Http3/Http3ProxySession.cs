using System.Globalization;
using System.Net;
using System.Net.Sockets;

using Warp.Cloudflare.Registration;
using Warp.Quic;

namespace Warp.Cloudflare.Http3;

/// <summary>
/// WARP's MASQUE proxy mode: every TCP connection is one HTTP/3 <c>CONNECT host:port</c> stream on a shared QUIC
/// connection, so Cloudflare resolves names and terminates TCP itself. Only TCP is carried in this mode.
/// </summary>
/// <remarks>
/// Uses the same mutual TLS and server key pin as the IP tunnel, with the proxy SNI the server insists on.
/// </remarks>
internal sealed class Http3ProxySession(MasqueHttp3Connection connection) : IWarpSession
{
    private const string ServerName = "consumer-masque-proxy.cloudflareclient.com";
    private const string ZeroTrustServerName = "zt-masque-proxy.cloudflareclient.com";

    public bool IsClosed => connection.IsClosed;

    public static async ValueTask<Http3ProxySession> OpenAsync(DeviceRegistration registration, IUdpConnector underlay, CancellationToken cancellationToken)
    {
        string serverName = registration.IsZeroTrust ? ZeroTrustServerName : ServerName;

        MasqueHttp3Connection connection = await MasqueHttp3Connection.OpenAsync(registration, underlay, serverName, [], datagrams: false, cancellationToken)
            .ConfigureAwait(continueOnCapturedContext: false);

        return new Http3ProxySession(connection);
    }

    public async ValueTask<Stream> ConnectTcpAsync(DnsEndPoint remoteEndPoint, CancellationToken cancellationToken)
    {
        string authority = FormatAuthority(remoteEndPoint);
        ManagedQuicStream stream = await connection.OpenRequestStreamAsync(cancellationToken).ConfigureAwait(continueOnCapturedContext: false);

        try
        {
            byte[] request = Http3Framing.CreateFrame(Http3Framing.HeadersFrame, QpackFieldSection.CreateConnectRequest(authority));

            await stream.WriteAsync(request, cancellationToken).ConfigureAwait(continueOnCapturedContext: false);

            int status = await Http3Framing.ReadResponseStatusAsync(stream, cancellationToken).ConfigureAwait(continueOnCapturedContext: false);

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
        throw new NotSupportedException(message: "Cloudflare's HTTP/3 proxy mode carries TCP only; use MasqueHttp2, MasqueHttp3 or WireGuard for UDP.");
    }

    public ValueTask DisposeAsync()
    {
        return connection.DisposeAsync();
    }

    private static string FormatAuthority(DnsEndPoint endPoint)
    {
        bool bracketed = IPAddress.TryParse(endPoint.Host, out IPAddress? address) && address.AddressFamily == AddressFamily.InterNetworkV6;
        string host = bracketed ? $"[{endPoint.Host}]" : endPoint.Host;

        return string.Create(CultureInfo.InvariantCulture, $"{host}:{endPoint.Port}");
    }
}
