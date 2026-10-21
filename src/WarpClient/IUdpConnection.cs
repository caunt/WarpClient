namespace Warp;

/// <summary>
/// Exchanges datagrams with one remote UDP endpoint over a particular network path, like a connected UDP socket.
/// </summary>
/// <remarks>
/// Datagrams may be lost, duplicated or reordered, exactly as with plain UDP. Disposing the connection releases its local port.
/// </remarks>
public interface IUdpConnection : IAsyncDisposable
{
    /// <summary>
    /// Waits for the next datagram from the remote endpoint and copies it into <paramref name="buffer"/>.
    /// </summary>
    /// <param name="buffer">Destination for the payload; a longer datagram is truncated to its length.</param>
    /// <param name="cancellationToken">Stops waiting, for example to implement a receive timeout.</param>
    /// <returns>The number of payload bytes copied into the buffer.</returns>
    ValueTask<int> ReceiveAsync(Memory<byte> buffer, CancellationToken cancellationToken);

    /// <summary>
    /// Sends one datagram to the remote endpoint.
    /// </summary>
    /// <param name="datagram">Payload carried by a single UDP packet; it should fit the path's MTU to avoid loss.</param>
    /// <param name="cancellationToken">Aborts the send before the datagram leaves.</param>
    /// <returns>A task that completes once the datagram has been handed to the network path.</returns>
    ValueTask SendAsync(ReadOnlyMemory<byte> datagram, CancellationToken cancellationToken);
}
