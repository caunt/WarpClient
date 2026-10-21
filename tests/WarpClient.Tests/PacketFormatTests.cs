using System.Buffers.Binary;
using System.Net;

using Warp.Networking.Dns;
using Warp.Networking.Packets;
using Warp.Networking.Tcp;

namespace Warp.Tests;

/// <summary>
/// Covers the packets the userspace stack writes and parses: IPv4 and IPv6 headers, TCP segments, UDP datagrams and DNS
/// messages.
/// </summary>
public sealed class PacketFormatTests
{
    /// <summary>
    /// Gets local and remote address pairs for both IP versions carried by the tunnel.
    /// </summary>
    public static TheoryData<string, string> AddressPairs { get; } = new()
    {
        { "172.16.0.2", "34.160.111.145" },
        { "2606:4700:110:8898:27b1:6a68:2312:3043", "2606:4700:4700::1111" },
    };

    /// <summary>
    /// The ring buffer behind TCP send and receive queues must keep byte order when its contents wrap around.
    /// </summary>
    [Fact]
    public void ByteQueuePreservesOrderAcrossWrapAndGrowth()
    {
        ByteQueue queue = new();
        byte[] first = [.. Enumerable.Range(start: 0, count: 4000).Select(static index => (byte)index)];
        byte[] second = [.. Enumerable.Range(start: 0, count: 9000).Select(static index => (byte)(index * 7))];
        byte[] drained = new byte[3000];

        queue.Enqueue(first);

        int drainedLength = queue.Dequeue(drained);

        queue.Enqueue(second);

        byte[] remaining = new byte[queue.Count];
        int remainingLength = queue.Dequeue(remaining);

        Assert.Equal(first[..drainedLength], drained);
        Assert.Equal([.. first[drainedLength..], .. second], remaining[..remainingLength]);
        Assert.Equal(expected: 0, queue.Count);
    }

    /// <summary>
    /// A reply to a different query must never be accepted, or a stray datagram could poison the lookup.
    /// </summary>
    [Fact]
    public void DnsResponseWithForeignIdentifierIsIgnored()
    {
        byte[] response = DnsMessage.CreateQuery(identifier: 1, hostName: "example.com", DnsRecordType.Address);

        response[2] = 0x81;

        Assert.False(DnsMessage.TryReadFirstAddress(response, identifier: 2, DnsRecordType.Address, out IPAddress? address));
        Assert.Null(address);
    }

    /// <summary>
    /// Real answers often chain a CNAME before the A record and point back into the question with name compression.
    /// </summary>
    [Fact]
    public void DnsResponseYieldsAddressAfterCompressedCanonicalName()
    {
        byte[] query = DnsMessage.CreateQuery(identifier: 0x1234, hostName: "www.example.com", DnsRecordType.Address);
        byte[] canonicalName = [0xC0, 0x0C, 0x00, 0x05, 0x00, 0x01, 0, 0, 0, 60, 0x00, 0x02, 0xC0, 0x10];
        byte[] addressRecord = [0xC0, 0x10, 0x00, 0x01, 0x00, 0x01, 0, 0, 0, 60, 0x00, 0x04, 93, 184, 216, 34];
        byte[] response = [.. query, .. canonicalName, .. addressRecord];

        response[2] = 0x81;
        response[3] = 0x80;
        response[7] = 2;

        bool found = DnsMessage.TryReadFirstAddress(response, identifier: 0x1234, DnsRecordType.Address, out IPAddress? address);

        Assert.True(found);
        Assert.Equal(IPAddress.Parse(ipString: "93.184.216.34"), address);
    }

    /// <summary>
    /// AAAA answers carry 16-byte addresses and must not be confused with A records of the same name.
    /// </summary>
    [Fact]
    public void DnsResponseYieldsIpv6AddressForQuadARecord()
    {
        IPAddress expected = IPAddress.Parse(ipString: "2606:4700:4700::1111");
        byte[] query = DnsMessage.CreateQuery(identifier: 7, hostName: "one.one.one.one", DnsRecordType.Ipv6Address);
        byte[] ipv4Record = [0xC0, 0x0C, 0x00, 0x01, 0x00, 0x01, 0, 0, 0, 60, 0x00, 0x04, 1, 1, 1, 1];
        byte[] ipv6Record = [0xC0, 0x0C, 0x00, 0x1C, 0x00, 0x01, 0, 0, 0, 60, 0x00, 0x10, .. expected.GetAddressBytes()];
        byte[] response = [.. query, .. ipv4Record, .. ipv6Record];

        response[2] = 0x81;
        response[3] = 0x80;
        response[7] = 2;

        bool found = DnsMessage.TryReadFirstAddress(response, identifier: 7, DnsRecordType.Ipv6Address, out IPAddress? address);

        Assert.True(found);
        Assert.Equal(expected, address);
    }

    /// <summary>
    /// IPv4 headers carry their own checksum, which must verify independently of the transport checksum.
    /// </summary>
    [Fact]
    public void Ipv4HeaderChecksumVerifies()
    {
        byte[] packet = InternetPacket.CreateUdp(
            IPAddress.Parse(ipString: "172.16.0.2"),
            IPAddress.Parse(ipString: "1.1.1.1"),
            identification: 99,
            sourcePort: 1,
            destinationPort: 2,
            [0]
        );

        Assert.Equal(expected: 0, InternetChecksum.Complete(InternetChecksum.Accumulate(packet.AsSpan(start: 0, Ipv4Packet.HeaderLength), sum: 0)));
    }

    /// <summary>
    /// Fragments cannot be reassembled by the stack, so they must be refused rather than misread as whole packets.
    /// </summary>
    [Fact]
    public void Ipv4ParserRejectsFragments()
    {
        byte[] packet = InternetPacket.CreateUdp(
            IPAddress.Parse(ipString: "172.16.0.2"),
            IPAddress.Parse(ipString: "1.1.1.1"),
            identification: 1,
            sourcePort: 1,
            destinationPort: 2,
            [0]
        );

        BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(start: 6), value: 0x2000);

        Assert.False(InternetPacket.TryParse(packet, out InternetDatagram datagram));
        Assert.Equal(expected: default, datagram);
    }

    /// <summary>
    /// A TCP segment written into a packet of either IP version must parse back with its options and payload, carrying a
    /// transport checksum that verifies against the matching pseudo-header.
    /// </summary>
    /// <param name="localAddress">Tunnel address the packet is sent from.</param>
    /// <param name="remoteAddress">Address the packet is sent to.</param>
    [Theory]
    [MemberData(nameof(AddressPairs))]
    public void TcpSegmentSurvivesPacketRoundTripWithValidChecksums(string localAddress, string remoteAddress)
    {
        IPAddress local = IPAddress.Parse(localAddress);
        IPAddress remote = IPAddress.Parse(remoteAddress);
        byte[] payload = [1, 2, 3, 4, 5];

        TcpSegment segment = new(
            SourcePort: 50000,
            DestinationPort: 443,
            SequenceNumber: 0xFFFF_FFF0,
            AcknowledgmentNumber: 42,
            TcpControlBits.Synchronize | TcpControlBits.Acknowledgment,
            Window: 65535,
            MaximumSegmentSize: 1220,
            payload
        );

        byte[] packet = InternetPacket.CreateTcp(local, remote, identification: 7, segment);
        bool parsedPacket = InternetPacket.TryParse(packet, out InternetDatagram datagram);
        ReadOnlyMemory<byte> transport = packet.AsMemory(datagram.PayloadOffset, datagram.PayloadLength);
        bool parsedSegment = TcpSegment.TryParse(transport, out TcpSegment parsed);

        Assert.True(parsedPacket);
        Assert.True(parsedSegment);
        Assert.Equal(local, datagram.Source);
        Assert.Equal(remote, datagram.Destination);
        Assert.Equal(InternetPacket.TcpProtocol, datagram.Protocol);
        Assert.Equal(segment.SequenceNumber, parsed.SequenceNumber);
        Assert.Equal(segment.ControlBits, parsed.ControlBits);
        Assert.Equal(expected: 1220, parsed.MaximumSegmentSize);
        Assert.Equal(payload, parsed.Payload.ToArray());
        Assert.Equal(expected: 0, InternetPacket.ComputeTransportChecksum(local, remote, InternetPacket.TcpProtocol, transport.Span));
    }

    /// <summary>
    /// UDP datagrams over either IP version carry a pseudo-header checksum that the receiver must be able to verify.
    /// </summary>
    /// <param name="localAddress">Tunnel address the datagram is sent from.</param>
    /// <param name="remoteAddress">Address the datagram is sent to.</param>
    [Theory]
    [MemberData(nameof(AddressPairs))]
    public void UdpDatagramCarriesValidChecksum(string localAddress, string remoteAddress)
    {
        IPAddress local = IPAddress.Parse(localAddress);
        IPAddress remote = IPAddress.Parse(remoteAddress);
        byte[] payload = [9, 8, 7];
        byte[] packet = InternetPacket.CreateUdp(local, remote, identification: 1, sourcePort: 50001, destinationPort: 53, payload);
        bool parsed = InternetPacket.TryParse(packet, out InternetDatagram datagram);
        ReadOnlySpan<byte> udp = packet.AsSpan(datagram.PayloadOffset, datagram.PayloadLength);

        Assert.True(parsed);
        Assert.Equal(InternetPacket.UdpProtocol, datagram.Protocol);
        Assert.Equal(expected: 53, BinaryPrimitives.ReadUInt16BigEndian(udp[2..]));
        Assert.Equal(expected: 0, InternetPacket.ComputeTransportChecksum(local, remote, InternetPacket.UdpProtocol, udp));
    }
}
