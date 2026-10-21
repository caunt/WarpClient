using System.Text;

using Warp.Quic.Buffers;

namespace Warp.Quic.Frames;

/// <summary>
/// Encodes the QUIC frames this client sends (RFC 9000 section 19).
/// </summary>
internal static class FrameWriter
{
    // Type, the widest stream ID and offset, and a two-byte length; packets never exceed 16383 bytes.
    public const int MaximumStreamOverhead = 1 + 8 + 8 + 2;

    public static void WriteAck(QuicWriter writer, RangeSet received, long encodedDelay)
    {
        IReadOnlyList<LongRange> ranges = received.Ranges;
        LongRange newest = ranges[^1];

        writer.WriteVariableLengthInteger(FrameType.Ack);
        writer.WriteVariableLengthInteger((ulong)(newest.End - 1));
        writer.WriteVariableLengthInteger((ulong)encodedDelay);
        writer.WriteVariableLengthInteger((ulong)(ranges.Count - 1));
        writer.WriteVariableLengthInteger((ulong)(newest.End - 1 - newest.Start));

        for (int index = ranges.Count - 2; index >= 0; index--)
        {
            LongRange range = ranges[index];
            long previousSmallest = ranges[index + 1].Start;

            writer.WriteVariableLengthInteger((ulong)(previousSmallest - range.End - 1));
            writer.WriteVariableLengthInteger((ulong)(range.End - 1 - range.Start));
        }
    }

    public static void WriteConnectionClose(QuicWriter writer, CloseRequest request)
    {
        byte[] reason = Encoding.UTF8.GetBytes(request.Reason);

        writer.WriteVariableLengthInteger(request.Application ? FrameType.ApplicationClose : FrameType.ConnectionClose);
        writer.WriteVariableLengthInteger(request.Code);

        if (!request.Application)
            writer.WriteVariableLengthInteger(value: 0);

        writer.WriteVariableLengthInteger((ulong)reason.Length);
        writer.WriteBytes(reason);
    }

    public static void WriteCrypto(QuicWriter writer, long offset, ReadOnlySpan<byte> data)
    {
        writer.WriteVariableLengthInteger(FrameType.Crypto);
        writer.WriteVariableLengthInteger((ulong)offset);
        writer.WriteVariableLengthInteger((ulong)data.Length);
        writer.WriteBytes(data);
    }

    public static void WriteDatagram(QuicWriter writer, ReadOnlySpan<byte> data)
    {
        writer.WriteVariableLengthInteger(FrameType.DatagramWithLength);
        writer.WriteVariableLengthInteger((ulong)data.Length);
        writer.WriteBytes(data);
    }

    public static void WriteInteger(QuicWriter writer, ulong type, long value)
    {
        writer.WriteVariableLengthInteger(type);
        writer.WriteVariableLengthInteger((ulong)value);
    }

    public static void WriteMaximumStreamData(QuicWriter writer, long streamId, long limit)
    {
        writer.WriteVariableLengthInteger(FrameType.MaximumStreamData);
        writer.WriteVariableLengthInteger((ulong)streamId);
        writer.WriteVariableLengthInteger((ulong)limit);
    }

    public static void WriteResetStream(QuicWriter writer, long streamId, ulong errorCode, long finalSize)
    {
        writer.WriteVariableLengthInteger(FrameType.ResetStream);
        writer.WriteVariableLengthInteger((ulong)streamId);
        writer.WriteVariableLengthInteger(errorCode);
        writer.WriteVariableLengthInteger((ulong)finalSize);
    }

    public static void WriteStopSending(QuicWriter writer, long streamId, ulong errorCode)
    {
        writer.WriteVariableLengthInteger(FrameType.StopSending);
        writer.WriteVariableLengthInteger((ulong)streamId);
        writer.WriteVariableLengthInteger(errorCode);
    }

    public static void WriteStream(QuicWriter writer, long streamId, long offset, ReadOnlySpan<byte> data, bool fin)
    {
        ulong type = FrameType.Stream | FrameType.StreamLength | (offset > 0 ? FrameType.StreamOffset : 0) | (fin ? FrameType.StreamFin : 0);

        writer.WriteVariableLengthInteger(type);
        writer.WriteVariableLengthInteger((ulong)streamId);

        if (offset > 0)
            writer.WriteVariableLengthInteger((ulong)offset);

        writer.WriteVariableLengthInteger((ulong)data.Length);
        writer.WriteBytes(data);
    }
}
