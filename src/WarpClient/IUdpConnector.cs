using System.Net;

namespace Warp;

/// <summary>
/// Opens UDP associations over one network path, such as the host's own sockets or a WARP tunnel, so callers never depend
/// on how datagrams reach the remote service.
/// </summary>
public interface IUdpConnector
{
    /// <summary>
    /// Binds a local port on the network path and associates it with the remote endpoint.
    /// </summary>
    /// <param name="remoteEndPoint">
    /// Host name or address and port of the remote service. Host names are resolved by the connector, so a tunnel can
    /// resolve them on its own side.
    /// </param>
    /// <param name="cancellationToken">Aborts the attempt, including any name resolution it needs.</param>
    /// <returns>A connection that sends to and receives from the remote endpoint only.</returns>
    ValueTask<IUdpConnection> ConnectAsync(DnsEndPoint remoteEndPoint, CancellationToken cancellationToken);
}
