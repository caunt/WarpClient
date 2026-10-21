using System.Net;

namespace Warp;

/// <summary>
/// Opens TCP connections over one network path, such as the host's own sockets or a WARP tunnel,
/// so callers never depend on how bytes reach the remote service.
/// </summary>
public interface ITcpConnector
{
    /// <summary>
    /// Establishes a connection to the remote service and returns the stream that carries its bytes.
    /// </summary>
    /// <param name="remoteEndPoint">
    /// Host name or address and port of the remote service. Host names are resolved by the connector,
    /// so a tunnel can resolve them on its own side instead of leaking lookups to the local resolver.
    /// </param>
    /// <param name="cancellationToken">Aborts the attempt before the connection is established.</param>
    /// <returns>A stream that owns the connection; disposing it closes the connection.</returns>
    ValueTask<Stream> ConnectAsync(DnsEndPoint remoteEndPoint, CancellationToken cancellationToken);
}
