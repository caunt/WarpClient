namespace Warp.Tests;

/// <summary>
/// Wraps a UDP connection and deterministically drops every n-th datagram in each direction, to exercise loss recovery
/// over a loopback path that never loses anything.
/// </summary>
internal sealed class LossyUdpConnection(IUdpConnection inner, int dropEvery) : IUdpConnection
{
    private int _received;
    private int _sent;

    public static IUdpConnection Wrap(IUdpConnection inner, int dropEvery)
    {
        return new LossyUdpConnection(inner, dropEvery);
    }

    public ValueTask DisposeAsync()
    {
        return inner.DisposeAsync();
    }

    public async ValueTask<int> ReceiveAsync(Memory<byte> buffer, CancellationToken cancellationToken)
    {
        int length = await inner.ReceiveAsync(buffer, cancellationToken).ConfigureAwait(continueOnCapturedContext: false);

        // The offset keeps the first datagrams flowing, so the drops land inside the handshake and the transfer.
        while (Interlocked.Increment(ref _received) % dropEvery == 2)
            length = await inner.ReceiveAsync(buffer, cancellationToken).ConfigureAwait(continueOnCapturedContext: false);

        return length;
    }

    public ValueTask SendAsync(ReadOnlyMemory<byte> datagram, CancellationToken cancellationToken)
    {
        return Interlocked.Increment(ref _sent) % dropEvery == 1 ? ValueTask.CompletedTask : inner.SendAsync(datagram, cancellationToken);
    }
}
