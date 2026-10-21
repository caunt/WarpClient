using System.Buffers.Binary;

namespace Warp.Quic;

/// <summary>
/// Reads QUIC and TLS wire formats from a buffer, failing with <see cref="InvalidDataException"/> when the data runs out.
/// </summary>
internal sealed class QuicReader(ReadOnlyMemory<byte> data)
{
    public bool IsEnd => Offset >= data.Length;

    public int Offset { get; private set; }

    public int Remaining => data.Length - Offset;

    public byte ReadByte()
    {
        Ensure(length: 1);

        byte value = data.Span[Offset];

        Offset++;

        return value;
    }

    public ReadOnlyMemory<byte> ReadBytes(int length)
    {
        Ensure(length);

        ReadOnlyMemory<byte> slice = data.Slice(Offset, length);

        Offset += length;

        return slice;
    }

    public int ReadLength()
    {
        ulong value = ReadVariableLengthInteger();

        return value <= int.MaxValue ? (int)value : throw new InvalidDataException(message: "The message declares an impossible length.");
    }

    public ReadOnlyMemory<byte> ReadRemaining()
    {
        return ReadBytes(Remaining);
    }

    public ushort ReadUInt16()
    {
        return BinaryPrimitives.ReadUInt16BigEndian(ReadBytes(length: 2).Span);
    }

    public int ReadUInt24()
    {
        ReadOnlySpan<byte> bytes = ReadBytes(length: 3).Span;

        return (bytes[index: 0] << 16) | (bytes[index: 1] << 8) | bytes[index: 2];
    }

    public uint ReadUInt32()
    {
        return BinaryPrimitives.ReadUInt32BigEndian(ReadBytes(length: 4).Span);
    }

    public ulong ReadVariableLengthInteger()
    {
        if (!VariableLengthInteger.TryRead(data.Span[Offset..], out ulong value, out int length))
            throw new InvalidDataException(message: "The message ends inside a variable-length integer.");

        Offset += length;

        return value;
    }

    public long ReadVariableLengthLong()
    {
        return (long)ReadVariableLengthInteger();
    }

    public ReadOnlyMemory<byte> ReadVector16()
    {
        return ReadBytes(ReadUInt16());
    }

    public ReadOnlyMemory<byte> ReadVector24()
    {
        return ReadBytes(ReadUInt24());
    }

    public ReadOnlyMemory<byte> ReadVector8()
    {
        return ReadBytes(ReadByte());
    }

    public void Skip(int length)
    {
        Ensure(length);
        Offset += length;
    }

    public void SkipVariableLengthInteger()
    {
        if (ReadVariableLengthInteger() > (1UL << 62))
            throw new InvalidDataException(message: "The message carries an out-of-range integer.");
    }

    private void Ensure(int length)
    {
        if (length < 0 || length > Remaining)
            throw new InvalidDataException(message: "The message ends early.");
    }
}
