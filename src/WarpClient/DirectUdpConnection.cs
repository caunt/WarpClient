using System.Net.Sockets;

namespace Warp;

internal sealed class DirectUdpConnection(Socket socket) : IUdpConnection
{
    public ValueTask DisposeAsync()
    {
        socket.Dispose();

        return ValueTask.CompletedTask;
    }

    public ValueTask<int> ReceiveAsync(Memory<byte> buffer, CancellationToken cancellationToken)
    {
        return socket.ReceiveAsync(buffer, SocketFlags.None, cancellationToken);
    }

    public async ValueTask SendAsync(ReadOnlyMemory<byte> datagram, CancellationToken cancellationToken)
    {
        int sent = await socket.SendAsync(datagram, SocketFlags.None, cancellationToken).ConfigureAwait(continueOnCapturedContext: false);

        if (sent != datagram.Length)
            throw new IOException(message: "The operating system sent only part of the datagram.");
    }
}
