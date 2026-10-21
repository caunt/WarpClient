using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;

namespace Warp.Networking.Packets;

/// <summary>
/// Builds and parses TCP and UDP packets over either IP version, so the stack above never branches on the address family.
/// </summary>
internal static class InternetPacket
{
    public const byte TcpProtocol = 6;
    public const byte UdpProtocol = 17;
    private const int UdpChecksumOffset = 6;
    private const int UdpHeaderLength = 8;

    // Sums the IPv4 (RFC 793) or IPv6 (RFC 8200 section 8.1) pseudo-header followed by the transport segment.
    public static ushort ComputeTransportChecksum(IPAddress source, IPAddress destination, byte protocol, ReadOnlySpan<byte> transport)
    {
        Span<byte> addresses = stackalloc byte[32];
        bool sourceWritten = source.TryWriteBytes(addresses, out int sourceLength);
        bool destinationWritten = destination.TryWriteBytes(addresses[sourceLength..], out int destinationLength);

        if (!sourceWritten || !destinationWritten)
            throw new ArgumentException(message: "The packet addresses could not be serialized.", nameof(source));

        uint sum = InternetChecksum.Accumulate(addresses[..(sourceLength + destinationLength)], sum: 0);

        sum += protocol;
        sum += (uint)(transport.Length >> 16) + (uint)(transport.Length & 0xFFFF);

        return InternetChecksum.Complete(InternetChecksum.Accumulate(transport, sum));
    }

    public static byte[] CreateTcp(IPAddress source, IPAddress destination, ushort identification, in TcpSegment segment)
    {
        int headerLength = GetHeaderLength(source.AddressFamily);
        byte[] packet = new byte[headerLength + segment.EncodedLength];
        Span<byte> transport = packet.AsSpan(headerLength);

        WriteHeader(packet, source, destination, identification, TcpProtocol, transport.Length);
        segment.Write(transport);
        BinaryPrimitives.WriteUInt16BigEndian(transport[TcpSegment.ChecksumOffset..], ComputeTransportChecksum(source, destination, TcpProtocol, transport));

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
        int headerLength = GetHeaderLength(source.AddressFamily);
        byte[] packet = new byte[headerLength + UdpHeaderLength + payload.Length];
        Span<byte> transport = packet.AsSpan(headerLength);

        WriteHeader(packet, source, destination, identification, UdpProtocol, transport.Length);
        BinaryPrimitives.WriteUInt16BigEndian(transport, sourcePort);
        BinaryPrimitives.WriteUInt16BigEndian(transport[2..], destinationPort);
        BinaryPrimitives.WriteUInt16BigEndian(transport[4..], (ushort)transport.Length);
        payload.CopyTo(transport[UdpHeaderLength..]);

        ushort checksum = ComputeTransportChecksum(source, destination, UdpProtocol, transport);

        // An all-zero UDP checksum means "not computed" (and is forbidden over IPv6), so a computed zero is sent as all ones.
        BinaryPrimitives.WriteUInt16BigEndian(transport[UdpChecksumOffset..], checksum == 0 ? ushort.MaxValue : checksum);

        return packet;
    }

    public static int GetHeaderLength(AddressFamily family)
    {
        return family == AddressFamily.InterNetworkV6 ? Ipv6Packet.HeaderLength : Ipv4Packet.HeaderLength;
    }

    public static bool TryParse(ReadOnlySpan<byte> packet, out InternetDatagram datagram)
    {
        datagram = default;

        return !packet.IsEmpty && (packet[index: 0] >> 4) switch
        {
            4 => Ipv4Packet.TryParse(packet, out datagram),
            6 => Ipv6Packet.TryParse(packet, out datagram),
            _ => false,
        };
    }

    private static void WriteHeader(Span<byte> packet, IPAddress source, IPAddress destination, ushort identification, byte protocol, int payloadLength)
    {
        if (source.AddressFamily == AddressFamily.InterNetworkV6)
            Ipv6Packet.WriteHeader(packet, source, destination, protocol, payloadLength);
        else
            Ipv4Packet.WriteHeader(packet, source, destination, identification, protocol, payloadLength);
    }
}
