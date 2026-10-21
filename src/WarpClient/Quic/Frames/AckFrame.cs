using Warp.Quic.Buffers;

namespace Warp.Quic.Frames;

/// <summary>
/// A received ACK frame (RFC 9000 section 19.3): acknowledged packet number ranges, newest first, and the encoded delay.
/// </summary>
internal sealed record AckFrame(IReadOnlyList<LongRange> Ranges, long EncodedDelay)
{
    public static AckFrame Read(QuicReader reader, bool withCounts)
    {
        long largest = reader.ReadVariableLengthLong();
        long encodedDelay = reader.ReadVariableLengthLong();
        long rangeCount = reader.ReadVariableLengthLong();
        long smallest = largest - reader.ReadVariableLengthLong();
        List<LongRange> ranges = [new LongRange(smallest, largest + 1)];

        for (long index = 0; index < rangeCount && smallest >= 0; index++)
        {
            long high = smallest - reader.ReadVariableLengthLong() - 2;

            smallest = high - reader.ReadVariableLengthLong();
            ranges.Add(new LongRange(smallest, high + 1));
        }

        if (smallest < 0)
            throw new QuicTransportException(QuicTransportException.FrameEncodingError, message: "The server sent an acknowledgment range below zero.");

        // ECN counts are read past; this client does not mark packets.
        if (withCounts)
        {
            reader.SkipVariableLengthInteger();
            reader.SkipVariableLengthInteger();
            reader.SkipVariableLengthInteger();
        }

        return new AckFrame(ranges, encodedDelay);
    }
}
