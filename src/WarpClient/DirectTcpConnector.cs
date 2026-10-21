using System.Net;
using System.Net.Sockets;

namespace Warp;

/// <summary>
/// Connects through the operating system's sockets without any tunnel, so traffic leaves from the host's own network address.
/// </summary>
public sealed class DirectTcpConnector : ITcpConnector
{
    /// <inheritdoc />
    public async ValueTask<Stream> ConnectAsync(DnsEndPoint remoteEndPoint, CancellationToken cancellationToken)
    {
        Socket? socket = new(SocketType.Stream, ProtocolType.Tcp) { NoDelay = true };

        try
        {
            await socket.ConnectAsync(remoteEndPoint, cancellationToken).ConfigureAwait(continueOnCapturedContext: false);

            NetworkStream stream = new(socket, ownsSocket: true);

            // The stream owns the socket from here on, so the finally block must not dispose it.
            socket = null;

            return stream;
        }
        finally
        {
            socket?.Dispose();
        }
    }
}
