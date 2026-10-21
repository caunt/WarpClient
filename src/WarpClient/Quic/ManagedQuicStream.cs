namespace Warp.Quic;

/// <summary>
/// One stream of a <see cref="ManagedQuicConnection"/> as an asynchronous <see cref="Stream"/>. Disposing it completes
/// writes and stops reading.
/// </summary>
internal sealed class ManagedQuicStream(ManagedQuicConnection connection, QuicStreamState state) : Stream
{
    private int _disposed;

    public override bool CanRead => state.CanReceive;

    public override bool CanSeek => false;

    public override bool CanWrite => state.CanSend;

    public long Id => state.Id;

    public override long Length => throw new NotSupportedException();

    public override long Position
    {
        get => throw new NotSupportedException();
        set => throw new NotSupportedException();
    }

    public ValueTask AbortAsync(ulong errorCode)
    {
        return connection.AbortAsync(state, errorCode);
    }

    public ValueTask CompleteWritesAsync(CancellationToken cancellationToken)
    {
        return connection.CompleteWritesAsync(state, cancellationToken);
    }

    public override async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposed, value: 1) == 0)
            await connection.ReleaseAsync(state).ConfigureAwait(continueOnCapturedContext: false);

        await base.DisposeAsync().ConfigureAwait(continueOnCapturedContext: false);
    }

    public override void Flush()
    {
        // Every write is handed to the connection immediately, so there is nothing buffered to flush.
    }

    public override Task FlushAsync(CancellationToken cancellationToken)
    {
        return Task.CompletedTask;
    }

    public override int Read(byte[] buffer, int offset, int count)
    {
        throw new NotSupportedException(message: "QUIC streams only support asynchronous reads.");
    }

    public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
    {
        return connection.ReadAsync(state, buffer, cancellationToken);
    }

    public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
    {
        return ReadAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();
    }

    public override long Seek(long offset, SeekOrigin origin)
    {
        throw new NotSupportedException();
    }

    public override void SetLength(long value)
    {
        throw new NotSupportedException();
    }

    public override void Write(byte[] buffer, int offset, int count)
    {
        throw new NotSupportedException(message: "QUIC streams only support asynchronous writes.");
    }

    public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
    {
        return connection.WriteAsync(state, buffer, cancellationToken);
    }

    public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
    {
        return WriteAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();
    }

    protected override void Dispose(bool disposing)
    {
        // Synchronous disposal cannot wait for the connection, so the stream is released by its timer shortly afterwards.
        if (disposing && Interlocked.Exchange(ref _disposed, value: 1) == 0)
            connection.RequestRelease(state);

        base.Dispose(disposing);
    }
}
