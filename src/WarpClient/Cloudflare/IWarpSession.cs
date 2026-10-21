using System.Net;

namespace Warp.Cloudflare;

/// <summary>
/// One live connection to Cloudflare, whichever transport carries it.
/// </summary>
internal interface IWarpSession : IAsyncDisposable
{
    bool IsClosed { get; }

    ValueTask<Stream> ConnectTcpAsync(DnsEndPoint remoteEndPoint, CancellationToken cancellationToken);

    ValueTask<IUdpConnection> ConnectUdpAsync(DnsEndPoint remoteEndPoint, CancellationToken cancellationToken);
}
