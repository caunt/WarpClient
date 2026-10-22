using System.Buffers.Binary;

namespace Warp.Networking.Packets;

internal readonly record struct TcpSegment(
    ushort SourcePort,
    ushort DestinationPort,
    uint SequenceNumber,
    uint AcknowledgmentNumber,
    TcpControlBits ControlBits,
    ushort Window,
    int MaximumSegmentSize,
    ReadOnlyMemory<byte> Payload,
    int WindowScale = TcpSegment.AbsentWindowScale
)
{
    public const int HeaderLength = 20;
    public const int ChecksumOffset = 16;
    public const int AbsentWindowScale = -1;
    public const byte MaximumWindowScale = 14;
    private const byte EndOfOptions = 0;
    private const byte NoOperation = 1;
    private const byte MaximumSegmentSizeOption = 2;
    private const int MaximumSegmentSizeOptionLength = 4;
    private const byte WindowScaleOption = 3;
    private const int WindowScaleOptionLength = 3;

    public int EncodedLength => EncodedHeaderLength + Payload.Length;

    // The window scale option is padded with a leading no-operation so the header stays a multiple of four bytes.
    private int EncodedHeaderLength => HeaderLength + (MaximumSegmentSize > 0 ? MaximumSegmentSizeOptionLength : 0) + (WindowScale >= 0 ? WindowScaleOptionLength + 1 : 0);

    public static bool TryParse(ReadOnlyMemory<byte> segment, out TcpSegment parsed)
    {
        parsed = default;

        ReadOnlySpan<byte> span = segment.Span;

        if (span.Length < HeaderLength)
            return false;

        int headerLength = (span[index: 12] >> 4) * 4;

        if (headerLength < HeaderLength || headerLength > span.Length)
            return false;

        ReadOptions(span[HeaderLength..headerLength], out int maximumSegmentSize, out int windowScale);

        parsed = new TcpSegment(
            BinaryPrimitives.ReadUInt16BigEndian(span),
            BinaryPrimitives.ReadUInt16BigEndian(span[2..]),
            BinaryPrimitives.ReadUInt32BigEndian(span[4..]),
            BinaryPrimitives.ReadUInt32BigEndian(span[8..]),
            (TcpControlBits)(span[index: 13] & 0x3F),
            BinaryPrimitives.ReadUInt16BigEndian(span[14..]),
            maximumSegmentSize,
            segment[headerLength..],
            windowScale
        );

        return true;
    }

    // Writes everything except the checksum, which depends on the IP pseudo-header and is filled in by the caller.
    public void Write(Span<byte> destination)
    {
        int headerLength = EncodedHeaderLength;

        BinaryPrimitives.WriteUInt16BigEndian(destination, SourcePort);
        BinaryPrimitives.WriteUInt16BigEndian(destination[2..], DestinationPort);
        BinaryPrimitives.WriteUInt32BigEndian(destination[4..], SequenceNumber);
        BinaryPrimitives.WriteUInt32BigEndian(destination[8..], AcknowledgmentNumber);
        destination[index: 12] = (byte)((headerLength / 4) << 4);
        destination[index: 13] = (byte)ControlBits;
        BinaryPrimitives.WriteUInt16BigEndian(destination[14..], Window);

        int offset = HeaderLength;

        if (MaximumSegmentSize > 0)
        {
            destination[offset] = MaximumSegmentSizeOption;
            destination[offset + 1] = MaximumSegmentSizeOptionLength;
            BinaryPrimitives.WriteUInt16BigEndian(destination[(offset + 2)..], (ushort)MaximumSegmentSize);
            offset += MaximumSegmentSizeOptionLength;
        }

        if (WindowScale >= 0)
        {
            destination[offset] = NoOperation;
            destination[offset + 1] = WindowScaleOption;
            destination[offset + 2] = WindowScaleOptionLength;
            destination[offset + 3] = (byte)Math.Min(WindowScale, MaximumWindowScale);
        }

        Payload.Span.CopyTo(destination[headerLength..]);
    }

    private static void ReadOptions(ReadOnlySpan<byte> options, out int maximumSegmentSize, out int windowScale)
    {
        maximumSegmentSize = 0;
        windowScale = AbsentWindowScale;

        int offset = 0;

        while (offset < options.Length)
        {
            byte kind = options[offset];

            if (kind == EndOfOptions)
                return;

            if (kind == NoOperation)
            {
                offset++;

                continue;
            }

            if (offset + 1 >= options.Length || options[offset + 1] < 2)
                return;

            int length = options[offset + 1];
            bool complete = offset + length <= options.Length;

            if (kind == MaximumSegmentSizeOption && length == MaximumSegmentSizeOptionLength && complete)
                maximumSegmentSize = BinaryPrimitives.ReadUInt16BigEndian(options[(offset + 2)..]);
            else if (kind == WindowScaleOption && length == WindowScaleOptionLength && complete)
                windowScale = Math.Min(options[offset + 2], MaximumWindowScale);

            offset += length;
        }
    }
}
