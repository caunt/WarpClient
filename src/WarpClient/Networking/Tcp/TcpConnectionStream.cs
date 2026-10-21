namespace Warp.Networking.Tcp;

/// <summary>
/// Presents a tunneled TCP connection as an asynchronous <see cref="Stream"/>.
/// </summary>
/// <remarks>
/// Synchronous reads and writes are not supported because they would have to block on tunnel I/O.
/// </remarks>
internal sealed class TcpConnectionStream(TcpConnection connection) : Stream
{
    public override bool CanRead => true;

    public override bool CanSeek => false;

    public override bool CanWrite => true;

    public override long Length => throw new NotSupportedException();

    public override long Position
    {
        get => throw new NotSupportedException();
        set => throw new NotSupportedException();
    }

    public override async ValueTask DisposeAsync()
    {
        await connection.CloseAsync().ConfigureAwait(continueOnCapturedContext: false);
        await base.DisposeAsync().ConfigureAwait(continueOnCapturedContext: false);
    }

    public override void Flush()
    {
        // Every write is handed to the tunnel immediately, so there is nothing buffered to flush.
    }

    public override Task FlushAsync(CancellationToken cancellationToken)
    {
        return Task.CompletedTask;
    }

    public override int Read(byte[] buffer, int offset, int count)
    {
        throw new NotSupportedException(message: "Tunneled connections only support asynchronous reads.");
    }

    public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
    {
        return connection.ReadAsync(buffer, cancellationToken);
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
        throw new NotSupportedException(message: "Tunneled connections only support asynchronous writes.");
    }

    public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
    {
        return connection.WriteAsync(buffer, cancellationToken);
    }

    public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
    {
        return WriteAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();
    }

    protected override void Dispose(bool disposing)
    {
        // Synchronous disposal cannot wait for the FIN handshake, so the connection's timer finishes closing in the background.
        if (disposing)
            connection.RequestClose();

        base.Dispose(disposing);
    }
}
