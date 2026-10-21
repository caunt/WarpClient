using System.Buffers.Binary;
using System.Net;

namespace Warp.Networking;

internal static class Ipv4Packet
{
    public const int HeaderLength = 20;
    public const byte TcpProtocol = 6;
    public const byte UdpProtocol = 17;
    private const ushort DoNotFragment = 0x4000;
    private const int MaximumSegmentSizeOptionLength = 4;
    private const byte TimeToLive = 64;
    private const int UdpHeaderLength = 8;

    public static byte[] CreateTcp(IPAddress source, IPAddress destination, ushort identification, in TcpSegment segment)
    {
        int optionsLength = segment.MaximumSegmentSize > 0 ? MaximumSegmentSizeOptionLength : 0;
        int headerLength = TcpSegment.HeaderLength + optionsLength;
        int tcpLength = headerLength + segment.Payload.Length;
        byte[] packet = new byte[HeaderLength + tcpLength];
        Span<byte> tcp = packet.AsSpan(HeaderLength);

        WriteHeader(packet, source, destination, identification, TcpProtocol, tcpLength);
        BinaryPrimitives.WriteUInt16BigEndian(tcp, segment.SourcePort);
        BinaryPrimitives.WriteUInt16BigEndian(tcp[2..], segment.DestinationPort);
        BinaryPrimitives.WriteUInt32BigEndian(tcp[4..], segment.SequenceNumber);
        BinaryPrimitives.WriteUInt32BigEndian(tcp[8..], segment.AcknowledgmentNumber);
        tcp[index: 12] = (byte)((headerLength / 4) << 4);
        tcp[index: 13] = (byte)segment.ControlBits;
        BinaryPrimitives.WriteUInt16BigEndian(tcp[14..], segment.Window);

        if (optionsLength > 0)
        {
            tcp[index: 20] = 2;
            tcp[index: 21] = MaximumSegmentSizeOptionLength;
            BinaryPrimitives.WriteUInt16BigEndian(tcp[22..], (ushort)segment.MaximumSegmentSize);
        }

        segment.Payload.Span.CopyTo(tcp[headerLength..]);
        BinaryPrimitives.WriteUInt16BigEndian(tcp[16..], ComputeTransportChecksum(packet, TcpProtocol, tcp));

        return packet;
    }

    public static byte[] CreateUdp(
        IPAddress source,
        IPAddress destination,
        ushort identification,
        ushort sourcePort,
        ushort destinationPort,
        ReadOnlySpan<byte> payload
    )
    {
        int udpLength = UdpHeaderLength + payload.Length;
        byte[] packet = new byte[HeaderLength + udpLength];
        Span<byte> udp = packet.AsSpan(HeaderLength);

        WriteHeader(packet, source, destination, identification, UdpProtocol, udpLength);
        BinaryPrimitives.WriteUInt16BigEndian(udp, sourcePort);
        BinaryPrimitives.WriteUInt16BigEndian(udp[2..], destinationPort);
        BinaryPrimitives.WriteUInt16BigEndian(udp[4..], (ushort)udpLength);
        payload.CopyTo(udp[UdpHeaderLength..]);

        ushort checksum = ComputeTransportChecksum(packet, UdpProtocol, udp);

        // An all-zero UDP checksum means "not computed", so a computed zero is sent as its one's complement twin.
        BinaryPrimitives.WriteUInt16BigEndian(udp[6..], checksum == 0 ? ushort.MaxValue : checksum);

        return packet;
    }

    public static bool TryParse(ReadOnlySpan<byte> packet, out Ipv4Datagram datagram)
    {
        datagram = default;

        if (packet.Length < HeaderLength || packet[index: 0] >> 4 != 4)
            return false;

        int headerLength = (packet[index: 0] & 0x0F) * 4;
        int totalLength = BinaryPrimitives.ReadUInt16BigEndian(packet[2..]);
        bool fragmented = (BinaryPrimitives.ReadUInt16BigEndian(packet[6..]) & 0x3FFF) != 0;

        if (headerLength < HeaderLength || totalLength < headerLength || totalLength > packet.Length || fragmented)
            return false;

        datagram = new Ipv4Datagram(
            new IPAddress(packet.Slice(start: 12, length: 4)),
            new IPAddress(packet.Slice(start: 16, length: 4)),
            packet[index: 9],
            headerLength,
            totalLength - headerLength
        );

        return true;
    }

    private static ushort ComputeTransportChecksum(ReadOnlySpan<byte> packet, byte protocol, ReadOnlySpan<byte> transport)
    {
        uint sum = InternetChecksum.Accumulate(packet.Slice(start: 12, length: 8), sum: 0);

        sum += protocol;
        sum += (uint)transport.Length;

        return InternetChecksum.Complete(InternetChecksum.Accumulate(transport, sum));
    }

    private static void WriteHeader(Span<byte> packet, IPAddress source, IPAddress destination, ushort identification, byte protocol, int payloadLength)
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
