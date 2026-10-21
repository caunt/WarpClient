using System.Net;

namespace Warp.Tests;

/// <summary>
/// Refuses the first connections, as a proxy does while its route to the endpoint is briefly down, then connects every
/// later one to a loopback port.
/// </summary>
internal sealed class FlakyTcpConnector(int refusals, int port) : ITcpConnector
{
    private int _attempts;

    public int Attempts => _attempts;

    public ValueTask<Stream> ConnectAsync(DnsEndPoint remoteEndPoint, CancellationToken cancellationToken)
    {
        return Interlocked.Increment(ref _attempts) <= refusals
            ? throw new IOException($"The proxy refused to connect to {remoteEndPoint.Host}:{remoteEndPoint.Port}: HTTP/1.1 502 Bad Gateway")
            : new DirectTcpConnector().ConnectAsync(new DnsEndPoint(host: "127.0.0.1", port), cancellationToken);
    }
}
