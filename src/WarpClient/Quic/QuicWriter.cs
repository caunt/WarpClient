using System.Buffers.Binary;

namespace Warp.Quic;

/// <summary>
/// Builds QUIC and TLS wire formats, including length-prefixed vectors whose length is filled in once their content is known.
/// </summary>
internal sealed class QuicWriter
{
    private byte[] _buffer = new byte[256];

    public int Length { get; private set; }

    public ReadOnlySpan<byte> WrittenSpan => _buffer.AsSpan(start: 0, Length);

    // Reserves a big-endian length prefix of the given width; EndVector fills it in.
    public int BeginVector(int prefixLength)
    {
        int position = Length;

        Ensure(prefixLength);
        _buffer.AsSpan(position, prefixLength).Clear();
        Length += prefixLength;

        return position;
    }

    public void EndVector(int position, int prefixLength)
    {
        int length = Length - position - prefixLength;

        for (int index = 0; index < prefixLength; index++)
            _buffer[position + index] = (byte)(length >> (8 * (prefixLength - 1 - index)));
    }

    public byte[] ToArray()
    {
        return WrittenSpan.ToArray();
    }

    public void WriteByte(byte value)
    {
        Ensure(additional: 1);
        _buffer[Length] = value;
        Length++;
    }

    public void WriteBytes(ReadOnlySpan<byte> bytes)
    {
        Ensure(bytes.Length);
        bytes.CopyTo(_buffer.AsSpan(Length));
        Length += bytes.Length;
    }

    public void WriteUInt16(ushort value)
    {
        Ensure(additional: 2);
        BinaryPrimitives.WriteUInt16BigEndian(_buffer.AsSpan(Length), value);
        Length += 2;
    }

    public void WriteUInt24(int value)
    {
        WriteByte((byte)(value >> 16));
        WriteByte((byte)(value >> 8));
        WriteByte((byte)value);
    }

    public void WriteUInt32(uint value)
    {
        Ensure(additional: 4);
        BinaryPrimitives.WriteUInt32BigEndian(_buffer.AsSpan(Length), value);
        Length += 4;
    }

    public void WriteVariableLengthInteger(ulong value)
    {
        Ensure(additional: 8);
        Length += VariableLengthInteger.Write(value, _buffer.AsSpan(Length));
    }

    public void WriteVector16(ReadOnlySpan<byte> bytes)
    {
        WriteUInt16((ushort)bytes.Length);
        WriteBytes(bytes);
    }

    public void WriteVector24(ReadOnlySpan<byte> bytes)
    {
        WriteUInt24(bytes.Length);
        WriteBytes(bytes);
    }

    public void WriteVector8(ReadOnlySpan<byte> bytes)
    {
        WriteByte((byte)bytes.Length);
        WriteBytes(bytes);
    }

    private void Ensure(int additional)
    {
        if (Length + additional > _buffer.Length)
            Array.Resize(ref _buffer, Math.Max(_buffer.Length * 2, Length + additional));
    }
}
