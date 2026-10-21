using System.Globalization;
using System.Net;
using System.Net.Sockets;

namespace Warp;

/// <summary>
/// Connects directly unless the system proxy settings route the destination through an HTTP proxy, mirroring how
/// <see cref="HttpClient"/> picks its path. On Linux and macOS those settings come from the <c>HTTPS_PROXY</c>,
/// <c>ALL_PROXY</c> and <c>NO_PROXY</c> environment variables.
/// </summary>
public sealed class SystemProxyTcpConnector : ITcpConnector
{
    private readonly DirectTcpConnector _directConnector = new();

    /// <inheritdoc />
    public ValueTask<Stream> ConnectAsync(DnsEndPoint remoteEndPoint, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(remoteEndPoint);

        bool bracketed = IPAddress.TryParse(remoteEndPoint.Host, out IPAddress? address) && address.AddressFamily == AddressFamily.InterNetworkV6;
        string host = bracketed ? $"[{remoteEndPoint.Host}]" : remoteEndPoint.Host;
        Uri destination = new(string.Create(CultureInfo.InvariantCulture, $"https://{host}:{remoteEndPoint.Port}/"));
        IWebProxy proxy = HttpClient.DefaultProxy;
        Uri? proxyAddress = proxy.IsBypassed(destination) ? null : proxy.GetProxy(destination);

        if (proxyAddress is null)
            return _directConnector.ConnectAsync(remoteEndPoint, cancellationToken);

        HttpProxyTcpConnector proxyConnector = new(new DnsEndPoint(proxyAddress.Host, proxyAddress.Port), _directConnector);

        return proxyConnector.ConnectAsync(remoteEndPoint, cancellationToken);
    }
}
