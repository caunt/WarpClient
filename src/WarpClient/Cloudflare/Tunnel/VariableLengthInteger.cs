using System.Buffers.Binary;

namespace Warp.Cloudflare.Tunnel;

/// <summary>
/// QUIC variable-length integers (RFC 9000 section 16), which also frame HTTP capsules.
/// </summary>
internal static class VariableLengthInteger
{
    public static int GetLength(ulong value)
    {
        return value switch
        {
            < 1UL << 6 => 1,
            < 1UL << 14 => 2,
            < 1UL << 30 => 4,
            _ => 8,
        };
    }

    public static bool TryRead(ReadOnlySpan<byte> source, out ulong value, out int length)
    {
        value = 0;
        length = 0;

        if (source.IsEmpty)
            return false;

        length = 1 << (source[index: 0] >> 6);

        if (source.Length < length)
            return false;

        value = length switch
        {
            1 => source[index: 0],
            2 => BinaryPrimitives.ReadUInt16BigEndian(source) & 0x3FFFUL,
            4 => BinaryPrimitives.ReadUInt32BigEndian(source) & 0x3FFF_FFFFUL,
            _ => BinaryPrimitives.ReadUInt64BigEndian(source) & 0x3FFF_FFFF_FFFF_FFFFUL,
        };

        return true;
    }

    public static int Write(ulong value, Span<byte> destination)
    {
        int length = GetLength(value);

        switch (length)
        {
            case 1:
                {
                    destination[index: 0] = (byte)value;

                    break;
                }
            case 2:
                {
                    BinaryPrimitives.WriteUInt16BigEndian(destination, (ushort)(value | 0x4000));

                    break;
                }
            case 4:
                {
                    BinaryPrimitives.WriteUInt32BigEndian(destination, (uint)value | 0x8000_0000);

                    break;
                }
            default:
                {
                    BinaryPrimitives.WriteUInt64BigEndian(destination, value | 0xC000_0000_0000_0000);

                    break;
                }
        }

        return length;
    }
}
