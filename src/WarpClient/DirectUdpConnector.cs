using System.Net;
using System.Net.Sockets;

namespace Warp;

/// <summary>
/// Exchanges datagrams through the operating system's sockets without any tunnel, so traffic leaves from the host's own
/// network address.
/// </summary>
public sealed class DirectUdpConnector : IUdpConnector
{
    /// <inheritdoc />
    public async ValueTask<IUdpConnection> ConnectAsync(DnsEndPoint remoteEndPoint, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(remoteEndPoint);

        IPAddress[] addresses = await Dns.GetHostAddressesAsync(remoteEndPoint.Host, cancellationToken).ConfigureAwait(continueOnCapturedContext: false);

        if (addresses.Length == 0)
            throw new IOException($"{remoteEndPoint.Host} has no addresses.");

        IPEndPoint resolved = new(addresses[0], remoteEndPoint.Port);
        Socket? socket = new(resolved.AddressFamily, SocketType.Dgram, ProtocolType.Udp);

        try
        {
            await socket.ConnectAsync(resolved, cancellationToken).ConfigureAwait(continueOnCapturedContext: false);

            DirectUdpConnection connection = new(socket);

            // The connection owns the socket from here on, so the finally block must not dispose it.
            socket = null;

            return connection;
        }
        finally
        {
            socket?.Dispose();
        }
    }
}
