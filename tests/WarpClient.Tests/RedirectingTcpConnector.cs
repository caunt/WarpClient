using System.Net;

namespace Warp.Tests;

/// <summary>
/// Sends every connection to one loopback port, standing in for Cloudflare's endpoints.
/// </summary>
internal sealed class RedirectingTcpConnector(int port) : ITcpConnector
{
    public ValueTask<Stream> ConnectAsync(DnsEndPoint remoteEndPoint, CancellationToken cancellationToken)
    {
        return new DirectTcpConnector().ConnectAsync(new DnsEndPoint(host: "127.0.0.1", port), cancellationToken);
    }
}
