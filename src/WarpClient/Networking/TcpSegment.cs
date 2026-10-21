using System.Buffers.Binary;

namespace Warp.Networking;

internal readonly record struct TcpSegment(
    ushort SourcePort,
    ushort DestinationPort,
    uint SequenceNumber,
    uint AcknowledgmentNumber,
    TcpControlBits ControlBits,
    ushort Window,
    int MaximumSegmentSize,
    ReadOnlyMemory<byte> Payload
)
{
    public const int HeaderLength = 20;
    private const byte EndOfOptions = 0;
    private const byte NoOperation = 1;
    private const byte MaximumSegmentSizeOption = 2;

    public static bool TryParse(ReadOnlyMemory<byte> segment, out TcpSegment parsed)
    {
        parsed = default;

        ReadOnlySpan<byte> span = segment.Span;

        if (span.Length < HeaderLength)
            return false;

        int headerLength = (span[index: 12] >> 4) * 4;

        if (headerLength < HeaderLength || headerLength > span.Length)
            return false;

        parsed = new TcpSegment(
            BinaryPrimitives.ReadUInt16BigEndian(span),
            BinaryPrimitives.ReadUInt16BigEndian(span[2..]),
            BinaryPrimitives.ReadUInt32BigEndian(span[4..]),
            BinaryPrimitives.ReadUInt32BigEndian(span[8..]),
            (TcpControlBits)(span[index: 13] & 0x3F),
            BinaryPrimitives.ReadUInt16BigEndian(span[14..]),
            ReadMaximumSegmentSize(span[HeaderLength..headerLength]),
            segment[headerLength..]
        );

        return true;
    }

    private static int ReadMaximumSegmentSize(ReadOnlySpan<byte> options)
    {
        int offset = 0;

        while (offset < options.Length)
        {
            byte kind = options[offset];

            if (kind == EndOfOptions)
                return 0;

            if (kind == NoOperation)
            {
                offset++;

                continue;
            }

            if (offset + 1 >= options.Length || options[offset + 1] < 2)
                return 0;

            int length = options[offset + 1];

            if (kind == MaximumSegmentSizeOption && length == 4 && offset + 4 <= options.Length)
                return BinaryPrimitives.ReadUInt16BigEndian(options[(offset + 2)..]);

            offset += length;
        }

        return 0;
    }
}
