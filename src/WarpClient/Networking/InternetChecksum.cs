using System.Buffers.Binary;

namespace Warp.Networking;

internal static class InternetChecksum
{
    public static uint Accumulate(ReadOnlySpan<byte> data, uint sum)
    {
        int index = 0;

        for (; index + 1 < data.Length; index += 2)
            sum += BinaryPrimitives.ReadUInt16BigEndian(data[index..]);

        if (index < data.Length)
            sum += (uint)(data[index] << 8);

        return sum;
    }

    public static ushort Complete(uint sum)
    {
        while (sum > 0xFFFF)
            sum = (sum & 0xFFFF) + (sum >> 16);

        return (ushort)~sum;
    }
}
