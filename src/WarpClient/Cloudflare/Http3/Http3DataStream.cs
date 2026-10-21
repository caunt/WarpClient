using Warp.Quic;

namespace Warp.Cloudflare.Http3;

/// <summary>
/// The byte stream of an established HTTP/3 <c>CONNECT</c>: writes become DATA frames, and reads return DATA payloads while
/// skipping any other frame the server interleaves.
/// </summary>
internal sealed class Http3DataStream(ManagedQuicStream stream) : Stream
{
    private bool _ended;
    private long _remaining;

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
        // Disposing the QUIC stream sends the FIN that ends the tunneled connection.
        await stream.DisposeAsync().ConfigureAwait(continueOnCapturedContext: false);
        await base.DisposeAsync().ConfigureAwait(continueOnCapturedContext: false);
    }

    public override void Flush()
    {
        // QUIC streams send as soon as they are written to, so there is nothing buffered here.
    }

    public override Task FlushAsync(CancellationToken cancellationToken)
    {
        return stream.FlushAsync(cancellationToken);
    }

    public override int Read(byte[] buffer, int offset, int count)
    {
        throw new NotSupportedException(message: "Tunneled connections only support asynchronous reads.");
    }

    public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
    {
        while (_remaining == 0)
        {
            if (_ended)
                return 0;

            Http3FrameHeader? frame = await Http3Framing.ReadHeaderAsync(stream, cancellationToken).ConfigureAwait(continueOnCapturedContext: false);

            if (frame is not Http3FrameHeader header)
            {
                _ended = true;

                return 0;
            }

            if (header.Type == Http3Framing.DataFrame)
                _remaining = header.Length;
            else
                await Http3Framing.SkipAsync(stream, header.Length, cancellationToken).ConfigureAwait(continueOnCapturedContext: false);
        }

        int length = (int)Math.Min(buffer.Length, _remaining);
        int read = await stream.ReadAsync(buffer[..length], cancellationToken).ConfigureAwait(continueOnCapturedContext: false);

        if (read == 0)
            throw new IOException(message: "The HTTP/3 stream ended inside a DATA frame.");

        _remaining -= read;

        return read;
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

    public override async ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
    {
        if (buffer.IsEmpty)
            return;

        await stream.WriteAsync(Http3Framing.CreateFrame(Http3Framing.DataFrame, buffer.Span), cancellationToken).ConfigureAwait(continueOnCapturedContext: false);
    }

    public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
    {
        return WriteAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing)
            stream.Dispose();

        base.Dispose(disposing);
    }
}
