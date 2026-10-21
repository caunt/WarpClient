using System.Buffers.Binary;

namespace Warp.Cloudflare.Tunnel;

internal readonly record struct Http2FrameHeader(int Length, byte Type, byte Flags, int StreamIdentifier)
{
    public const int Size = 9;

    public static Http2FrameHeader Read(ReadOnlySpan<byte> source)
    {
        int length = (source[index: 0] << 16) | (source[index: 1] << 8) | source[index: 2];
        int streamIdentifier = BinaryPrimitives.ReadInt32BigEndian(source[5..]) & int.MaxValue;

        return new Http2FrameHeader(length, source[index: 3], source[index: 4], streamIdentifier);
    }

    public void Write(Span<byte> destination)
    {
        destination[index: 0] = (byte)(Length >> 16);
        destination[index: 1] = (byte)(Length >> 8);
        destination[index: 2] = (byte)Length;
        destination[index: 3] = Type;
        destination[index: 4] = Flags;
        BinaryPrimitives.WriteInt32BigEndian(destination[5..], StreamIdentifier);
    }
}
