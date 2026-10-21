using Warp.Quic;

namespace Warp.Cloudflare.Http3;

/// <summary>
/// HTTP/3 frame headers (RFC 9114 section 7.1): a variable-length type followed by a variable-length payload length.
/// </summary>
internal static class Http3Framing
{
    public const ulong ControlStreamType = 0x0;
    public const ulong DataFrame = 0x0;
    public const ulong HeadersFrame = 0x1;
    public const ulong SettingsFrame = 0x4;
    private const int MaximumHeadersLength = 16384;
    private const int MaximumIntegerLength = 8;

    public static byte[] CreateFrame(ulong type, ReadOnlySpan<byte> payload)
    {
        int typeLength = VariableLengthInteger.GetLength(type);
        int lengthLength = VariableLengthInteger.GetLength((ulong)payload.Length);
        byte[] frame = new byte[typeLength + lengthLength + payload.Length];
        int offset = VariableLengthInteger.Write(type, frame);

        offset += VariableLengthInteger.Write((ulong)payload.Length, frame.AsSpan(offset));
        payload.CopyTo(frame.AsSpan(offset));

        return frame;
    }

    /// <summary>
    /// Reads the next frame header, or returns <see langword="null"/> when the stream ends cleanly between frames.
    /// </summary>
    public static async ValueTask<Http3FrameHeader?> ReadHeaderAsync(Stream stream, CancellationToken cancellationToken)
    {
        ulong? type = await ReadIntegerAsync(stream, cancellationToken).ConfigureAwait(continueOnCapturedContext: false);

        if (type is not ulong frameType)
            return null;

        ulong length = await ReadIntegerAsync(stream, cancellationToken).ConfigureAwait(continueOnCapturedContext: false)
            ?? throw new IOException(message: "The HTTP/3 stream ended inside a frame header.");

        return length > int.MaxValue ? throw new InvalidDataException(message: "The HTTP/3 frame is too large.") : new Http3FrameHeader(frameType, (long)length);
    }

    /// <summary>
    /// Reads the response HEADERS of a request stream and returns its status, skipping frames that may precede it.
    /// </summary>
    public static async ValueTask<int> ReadResponseStatusAsync(Stream stream, CancellationToken cancellationToken)
    {
        Http3FrameHeader? frame = await ReadHeaderAsync(stream, cancellationToken).ConfigureAwait(continueOnCapturedContext: false);

        // Unknown and reserved frame types may precede the response headers and are skipped (RFC 9114 section 9).
        while (frame is Http3FrameHeader skipped && skipped.Type != HeadersFrame)
        {
            await SkipAsync(stream, skipped.Length, cancellationToken).ConfigureAwait(continueOnCapturedContext: false);
            frame = await ReadHeaderAsync(stream, cancellationToken).ConfigureAwait(continueOnCapturedContext: false);
        }

        if (frame is not Http3FrameHeader headers || headers.Length > MaximumHeadersLength)
            throw new IOException(message: "Cloudflare ended the HTTP/3 stream without response headers.");

        byte[] section = new byte[headers.Length];

        await stream.ReadExactlyAsync(section, cancellationToken).ConfigureAwait(continueOnCapturedContext: false);

        return QpackFieldSection.DecodeStatus(section);
    }

    public static async ValueTask SkipAsync(Stream stream, long length, CancellationToken cancellationToken)
    {
        byte[] scratch = new byte[Math.Min(length, val2: 4096)];

        while (length > 0)
        {
            int chunk = (int)Math.Min(length, scratch.Length);

            await stream.ReadExactlyAsync(scratch.AsMemory(start: 0, chunk), cancellationToken).ConfigureAwait(continueOnCapturedContext: false);
            length -= chunk;
        }
    }

    private static async ValueTask<ulong?> ReadIntegerAsync(Stream stream, CancellationToken cancellationToken)
    {
        byte[] buffer = new byte[MaximumIntegerLength];
        int first = await stream.ReadAsync(buffer.AsMemory(start: 0, length: 1), cancellationToken).ConfigureAwait(continueOnCapturedContext: false);

        if (first == 0)
            return null;

        int length = 1 << (buffer[0] >> 6);

        await stream.ReadExactlyAsync(buffer.AsMemory(start: 1, length - 1), cancellationToken).ConfigureAwait(continueOnCapturedContext: false);

        return VariableLengthInteger.TryRead(buffer.AsSpan(start: 0, length), out ulong value, out int read) && read == length
            ? value
            : throw new InvalidDataException(message: "The HTTP/3 stream carries a malformed integer.");
    }
}
