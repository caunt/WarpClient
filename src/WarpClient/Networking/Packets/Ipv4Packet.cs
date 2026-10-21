using System.Buffers.Binary;
using System.Net;

namespace Warp.Networking.Packets;

internal static class Ipv4Packet
{
    public const int HeaderLength = 20;
    private const ushort DoNotFragment = 0x4000;
    private const byte TimeToLive = 64;

    public static bool TryParse(ReadOnlySpan<byte> packet, out InternetDatagram datagram)
    {
        datagram = default;

        if (packet.Length < HeaderLength || packet[index: 0] >> 4 != 4)
            return false;

        int headerLength = (packet[index: 0] & 0x0F) * 4;
        int totalLength = BinaryPrimitives.ReadUInt16BigEndian(packet[2..]);
        bool fragmented = (BinaryPrimitives.ReadUInt16BigEndian(packet[6..]) & 0x3FFF) != 0;

        if (headerLength < HeaderLength || totalLength < headerLength || totalLength > packet.Length || fragmented)
            return false;

        datagram = new InternetDatagram(
            new IPAddress(packet.Slice(start: 12, length: 4)),
            new IPAddress(packet.Slice(start: 16, length: 4)),
            packet[index: 9],
            headerLength,
            totalLength - headerLength
        );

        return true;
    }

    public static void WriteHeader(Span<byte> packet, IPAddress source, IPAddress destination, ushort identification, byte protocol, int payloadLength)
    {
        packet[index: 0] = 0x45;
        BinaryPrimitives.WriteUInt16BigEndian(packet[2..], (ushort)(HeaderLength + payloadLength));
        BinaryPrimitives.WriteUInt16BigEndian(packet[4..], identification);
        BinaryPrimitives.WriteUInt16BigEndian(packet[6..], DoNotFragment);
        packet[index: 8] = TimeToLive;
        packet[index: 9] = protocol;
        source.GetAddressBytes().CopyTo(packet[12..]);
        destination.GetAddressBytes().CopyTo(packet[16..]);
        BinaryPrimitives.WriteUInt16BigEndian(packet[10..], InternetChecksum.Complete(InternetChecksum.Accumulate(packet[..HeaderLength], sum: 0)));
    }
}
