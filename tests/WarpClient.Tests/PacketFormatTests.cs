using System.Buffers.Binary;
using System.Net;

using Warp.Networking;

namespace Warp.Tests;

/// <summary>
/// Covers the packets the userspace stack writes and parses: IPv4 headers, TCP segments, UDP datagrams and DNS messages.
/// </summary>
public sealed class PacketFormatTests
{
    private static readonly IPAddress Local = IPAddress.Parse(ipString: "172.16.0.2");
    private static readonly IPAddress Remote = IPAddress.Parse(ipString: "34.160.111.145");

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
        byte[] response = DnsMessage.CreateQuery(identifier: 1, hostName: "example.com");

        response[2] = 0x81;

        Assert.False(DnsMessage.TryReadFirstAddress(response, identifier: 2, out IPAddress? address));
        Assert.Null(address);
    }

    /// <summary>
    /// Real answers often chain a CNAME before the A record and point back into the question with name compression.
    /// </summary>
    [Fact]
    public void DnsResponseYieldsAddressAfterCompressedCanonicalName()
    {
        byte[] query = DnsMessage.CreateQuery(identifier: 0x1234, hostName: "www.example.com");
        byte[] canonicalName = [0xC0, 0x0C, 0x00, 0x05, 0x00, 0x01, 0, 0, 0, 60, 0x00, 0x02, 0xC0, 0x10];
        byte[] addressRecord = [0xC0, 0x10, 0x00, 0x01, 0x00, 0x01, 0, 0, 0, 60, 0x00, 0x04, 93, 184, 216, 34];
        byte[] response = [.. query, .. canonicalName, .. addressRecord];

        response[2] = 0x81;
        response[3] = 0x80;
        response[7] = 2;

        bool found = DnsMessage.TryReadFirstAddress(response, identifier: 0x1234, out IPAddress? address);

        Assert.True(found);
        Assert.Equal(IPAddress.Parse(ipString: "93.184.216.34"), address);
    }

    /// <summary>
    /// Fragments cannot be reassembled by the stack, so they must be refused rather than misread as whole packets.
    /// </summary>
    [Fact]
    public void Ipv4ParserRejectsFragments()
    {
        byte[] packet = Ipv4Packet.CreateUdp(Local, Remote, identification: 1, sourcePort: 1, destinationPort: 2, [0]);

        BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(start: 6), value: 0x2000);

        Assert.False(Ipv4Packet.TryParse(packet, out Ipv4Datagram datagram));
        Assert.Equal(expected: default, datagram);
    }

    /// <summary>
    /// A TCP segment written into an IPv4 packet must parse back with its options and payload, carrying valid checksums.
    /// </summary>
    [Fact]
    public void TcpSegmentSurvivesPacketRoundTripWithValidChecksums()
    {
        byte[] payload = [1, 2, 3, 4, 5];

        TcpSegment segment = new(
            SourcePort: 50000,
            DestinationPort: 443,
            SequenceNumber: 0xFFFF_FFF0,
            AcknowledgmentNumber: 42,
            TcpControlBits.Synchronize | TcpControlBits.Acknowledgment,
            Window: 65535,
            MaximumSegmentSize: 1240,
            payload
        );

        byte[] packet = Ipv4Packet.CreateTcp(Local, Remote, identification: 7, segment);
        bool parsedPacket = Ipv4Packet.TryParse(packet, out Ipv4Datagram datagram);
        ReadOnlyMemory<byte> transport = packet.AsMemory(datagram.PayloadOffset, datagram.PayloadLength);
        bool parsedSegment = TcpSegment.TryParse(transport, out TcpSegment parsed);

        Assert.True(parsedPacket);
        Assert.True(parsedSegment);
        Assert.Equal(Local, datagram.Source);
        Assert.Equal(Remote, datagram.Destination);
        Assert.Equal(Ipv4Packet.TcpProtocol, datagram.Protocol);
        Assert.Equal(segment.SequenceNumber, parsed.SequenceNumber);
        Assert.Equal(segment.ControlBits, parsed.ControlBits);
        Assert.Equal(expected: 1240, parsed.MaximumSegmentSize);
        Assert.Equal(payload, parsed.Payload.ToArray());
        Assert.Equal(expected: 0, InternetChecksum.Complete(InternetChecksum.Accumulate(packet.AsSpan(start: 0, Ipv4Packet.HeaderLength), sum: 0)));
        Assert.Equal(expected: 0, ComputePseudoHeaderChecksum(packet, Ipv4Packet.TcpProtocol, transport.Span));
    }

    /// <summary>
    /// UDP datagrams carry a pseudo-header checksum that the receiver must be able to verify.
    /// </summary>
    [Fact]
    public void UdpDatagramCarriesValidChecksum()
    {
        byte[] payload = [9, 8, 7];
        byte[] packet = Ipv4Packet.CreateUdp(Local, Remote, identification: 1, sourcePort: 50001, destinationPort: 53, payload);
        bool parsed = Ipv4Packet.TryParse(packet, out Ipv4Datagram datagram);
        ReadOnlySpan<byte> udp = packet.AsSpan(datagram.PayloadOffset, datagram.PayloadLength);

        Assert.True(parsed);
        Assert.Equal(Ipv4Packet.UdpProtocol, datagram.Protocol);
        Assert.Equal(expected: 53, BinaryPrimitives.ReadUInt16BigEndian(udp[2..]));
        Assert.Equal(expected: 0, ComputePseudoHeaderChecksum(packet, Ipv4Packet.UdpProtocol, udp));
    }

    private static ushort ComputePseudoHeaderChecksum(byte[] packet, byte protocol, ReadOnlySpan<byte> transport)
    {
        uint sum = InternetChecksum.Accumulate(packet.AsSpan(start: 12, length: 8), sum: 0) + protocol + (uint)transport.Length;

        return InternetChecksum.Complete(InternetChecksum.Accumulate(transport, sum));
    }
}
