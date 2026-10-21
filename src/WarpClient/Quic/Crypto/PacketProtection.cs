using System.Buffers.Binary;

namespace Warp.Quic.Crypto;

/// <summary>
/// Applies and removes QUIC packet protection (RFC 9001 section 5.4): AEAD over the payload, then a mask over the header's
/// low bits and the packet number.
/// </summary>
internal static class PacketProtection
{
    public const int PacketNumberLength = 4;
    private const byte LongHeaderMask = 0x0F;
    private const byte ShortHeaderMask = 0x1F;

    // RFC 9000 appendix A.3: picks the packet number closest to the next expected one that has these low bits.
    public static long DecodePacketNumber(long largestReceived, long truncated, int bits)
    {
        long expected = largestReceived + 1;
        long window = 1L << bits;
        long halfWindow = window / 2;
        long candidate = (expected & ~(window - 1)) | truncated;

        return candidate <= expected - halfWindow && candidate < (1L << 62) - window
            ? candidate + window
            : candidate > expected + halfWindow && candidate >= window ? candidate - window : candidate;
    }

    // The header must already contain the packet number, written with PacketNumberLength bytes, at packetNumberOffset.
    public static byte[] Protect(PacketKeys keys, long packetNumber, ReadOnlySpan<byte> header, ReadOnlySpan<byte> payload)
    {
        byte[] ciphertext = keys.Seal(packetNumber, header, payload);
        byte[] packet = [.. header, .. ciphertext];
        int packetNumberOffset = header.Length - PacketNumberLength;
        byte[] mask = keys.CreateMask(packet.AsSpan(packetNumberOffset + PacketNumberLength, PacketKeys.SampleLength));

        packet[0] ^= (byte)(mask[0] & ((packet[0] & 0x80) != 0 ? LongHeaderMask : ShortHeaderMask));

        for (int index = 0; index < PacketNumberLength; index++)
            packet[packetNumberOffset + index] ^= mask[1 + index];

        return packet;
    }

    /// <summary>
    /// Removes header protection in place and recovers the full packet number, or returns <see langword="false"/> when the
    /// packet is too short to carry a sample.
    /// </summary>
    public static bool TryRemoveHeaderProtection(PacketKeys keys, Span<byte> packet, int packetNumberOffset, long largestReceived, out long packetNumber, out int headerLength)
    {
        packetNumber = -1;
        headerLength = 0;

        if (packet.Length < packetNumberOffset + PacketNumberLength + PacketKeys.SampleLength)
            return false;

        byte[] mask = keys.CreateMask(packet.Slice(packetNumberOffset + PacketNumberLength, PacketKeys.SampleLength));

        packet[index: 0] ^= (byte)(mask[0] & ((packet[index: 0] & 0x80) != 0 ? LongHeaderMask : ShortHeaderMask));

        int length = (packet[index: 0] & 0x03) + 1;
        long truncated = 0;

        for (int index = 0; index < length; index++)
        {
            packet[packetNumberOffset + index] ^= mask[1 + index];
            truncated = (truncated << 8) | packet[packetNumberOffset + index];
        }

        packetNumber = DecodePacketNumber(largestReceived, truncated, length * 8);
        headerLength = packetNumberOffset + length;

        return true;
    }

    public static void WritePacketNumber(Span<byte> destination, long packetNumber)
    {
        BinaryPrimitives.WriteUInt32BigEndian(destination, (uint)packetNumber);
    }
}
