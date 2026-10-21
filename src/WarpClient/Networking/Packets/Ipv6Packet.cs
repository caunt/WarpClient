using System.Buffers.Binary;
using System.Net;

namespace Warp.Networking.Packets;

/// <summary>
/// Fixed IPv6 headers (RFC 8200). Extension headers are never sent, and packets that carry them are not delivered.
/// </summary>
internal static class Ipv6Packet
{
    public const int HeaderLength = 40;
    private const int AddressLength = 16;
    private const byte HopLimit = 64;

    public static bool TryParse(ReadOnlySpan<byte> packet, out InternetDatagram datagram)
    {
        datagram = default;

        if (packet.Length < HeaderLength || packet[index: 0] >> 4 != 6)
            return false;

        int payloadLength = BinaryPrimitives.ReadUInt16BigEndian(packet[4..]);

        if (HeaderLength + payloadLength > packet.Length)
            return false;

        datagram = new InternetDatagram(
            new IPAddress(packet.Slice(start: 8, AddressLength)),
            new IPAddress(packet.Slice(start: 24, AddressLength)),
            packet[index: 6],
            HeaderLength,
            payloadLength
        );

        return true;
    }

    public static void WriteHeader(Span<byte> packet, IPAddress source, IPAddress destination, byte nextHeader, int payloadLength)
    {
        packet[index: 0] = 0x60;
        BinaryPrimitives.WriteUInt16BigEndian(packet[4..], (ushort)payloadLength);
        packet[index: 6] = nextHeader;
        packet[index: 7] = HopLimit;
        source.GetAddressBytes().CopyTo(packet[8..]);
        destination.GetAddressBytes().CopyTo(packet[24..]);
    }
}
