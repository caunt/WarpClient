using Warp.Quic;
using Warp.Quic.Buffers;
using Warp.Quic.Crypto;

namespace Warp.Tests;

/// <summary>
/// Checks the managed QUIC building blocks against the test vectors of RFC 9000 and RFC 9001, and the stream buffers
/// against reordered and lost data.
/// </summary>
public sealed class QuicProtocolTests
{
    private static readonly byte[] ExampleConnectionId = Convert.FromHexString(s: "8394C8F03E515708");

    /// <summary>
    /// Protecting the client Initial of RFC 9001 appendix A.2 must give the published packet, which exercises AES-GCM,
    /// the nonce, the header as associated data and header protection together.
    /// </summary>
    [Fact]
    public void ClientInitialMatchesRfc9001Packet()
    {
        byte[] header = Convert.FromHexString(s: "C300000001088394C8F03E5157080000449E00000002");

        byte[] frames = Convert.FromHexString(
            "060040F1010000ED0303EBF8FA56F12939B9584A3896472EC40BB863CFD3E86804FE3A47F06A2B69484C00000413011302010000C000000010000E00000B6578"
            + "616D706C652E636F6DFF01000100000A00080006001D0017001800100007000504616C706E000500050100000000003300260024001D00209370B2C9CAA47FBA"
            + "BAF4559FEDBA753DE171FA71F50F1CE15D43E994EC74D748002B0003020304000D0010000E0403050306030203080408050806002D00020101001C0002400100"
            + "3900320408FFFFFFFFFFFFFFFF05048000FFFF07048000FFFF0801100104800075300901100F088394C8F03E51570806048000FFFF"
        );

        byte[] payload = new byte[1162];

        frames.CopyTo(payload, index: 0);

        byte[] packet = PacketProtection.Protect(PacketKeys.CreateInitial(ExampleConnectionId, label: "client in"), packetNumber: 2, header, payload);

        Assert.Equal(expected: 1200, packet.Length);
        Assert.Equal(expected: "C000000001088394C8F03E5157080000449E7B9AEC34D1B1C98DD7689FB8EC11D242B123DC9B", Convert.ToHexString(packet[..38]));
        Assert.Equal(expected: "E221AF44860018AB0856972E194CD934", Convert.ToHexString(packet[^16..]));
    }

    /// <summary>
    /// Initial secrets must match RFC 9001 appendix A.1, since both sides derive them from the client's connection ID.
    /// </summary>
    [Fact]
    public void InitialSecretsMatchRfc9001Vectors()
    {
        PacketKeys client = PacketKeys.CreateInitial(ExampleConnectionId, label: "client in");
        PacketKeys server = PacketKeys.CreateInitial(ExampleConnectionId, label: "server in");

        Assert.Equal(expected: "C00CF151CA5BE075ED0EBFB5C80323C42D6B7DB67881289AF4008F1F6C357AEA", Convert.ToHexString(client.Secret));
        Assert.Equal(expected: "3C199828FD139EFD216C155AD844CC81FB82FA8D7446FA7D78BE803ACDDA951B", Convert.ToHexString(server.Secret));
    }

    /// <summary>
    /// Truncated packet numbers must expand to the candidate nearest the next expected one (RFC 9000 appendix A.3).
    /// </summary>
    [Fact]
    public void PacketNumberDecodesNearExpected()
    {
        Assert.Equal(expected: 0xA82F9B32, PacketProtection.DecodePacketNumber(largestReceived: 0xA82F30EA, truncated: 0x9B32, bits: 16));
        Assert.Equal(expected: 256, PacketProtection.DecodePacketNumber(largestReceived: 255, truncated: 0, bits: 8));
    }

    /// <summary>
    /// Removing header protection from the RFC 9001 packet must restore the first byte and packet number, and the payload
    /// must then decrypt.
    /// </summary>
    [Fact]
    public void ProtectedPacketOpensAgain()
    {
        PacketKeys keys = PacketKeys.CreateInitial(ExampleConnectionId, label: "client in");
        byte[] header = Convert.FromHexString(s: "C300000001088394C8F03E5157080000449E00000002");
        byte[] payload = new byte[1162];

        payload[0] = 0x01;

        byte[] packet = PacketProtection.Protect(keys, packetNumber: 2, header, payload);
        bool unmasked = PacketProtection.TryRemoveHeaderProtection(keys, packet, packetNumberOffset: 18, largestReceived: 1, out long packetNumber, out int headerLength);
        byte[]? opened = keys.Open(packetNumber, packet.AsSpan(start: 0, headerLength), packet.AsSpan(headerLength));

        Assert.True(unmasked);
        Assert.Equal(expected: 2, packetNumber);
        Assert.Equal(header, packet[..headerLength]);
        Assert.Equal(payload, opened);
    }

    /// <summary>
    /// Out-of-order and overlapping stream data must come out once, in order.
    /// </summary>
    [Fact]
    public void ReassemblyBufferOrdersOverlappingData()
    {
        ReassemblyBuffer buffer = new();
        byte[] output = new byte[16];

        buffer.Insert(offset: 6, data: "ghij"u8);
        buffer.Insert(offset: 0, data: "abc"u8);
        buffer.Insert(offset: 2, data: "cdefg"u8);

        int read = buffer.Read(output);

        Assert.Equal(expected: "abcdefghij", System.Text.Encoding.ASCII.GetString(output, index: 0, read));
        Assert.Equal(expected: 10, buffer.ReadOffset);
    }

    /// <summary>
    /// A Retry packet is accepted only with the integrity tag of RFC 9001 appendix A.4 for the original connection ID.
    /// </summary>
    [Fact]
    public void RetryIntegrityMatchesRfc9001Vector()
    {
        byte[] retry = Convert.FromHexString(s: "FF000000010008F067A5502A4262B5746F6B656E04A265BA2EFF4D829058FB3F0F2496BA");
        byte[] tampered = [.. retry];

        tampered[20] ^= 0x01;

        Assert.True(RetryIntegrity.IsValid(ExampleConnectionId, retry));
        Assert.False(RetryIntegrity.IsValid(ExampleConnectionId, tampered));
    }

    /// <summary>
    /// Lost ranges must be sent again before new data, and the stream completes only once everything and the FIN are
    /// acknowledged.
    /// </summary>
    [Fact]
    public void SendBufferRetransmitsLostRangesFirst()
    {
        SendBuffer buffer = new();

        buffer.Write(data: "abcdefgh"u8);
        buffer.Finish();

        SendChunk? first = buffer.TakeChunk(maximumLength: 4, long.MaxValue);
        SendChunk? second = buffer.TakeChunk(maximumLength: 4, long.MaxValue);

        buffer.OnLost(offset: 0, length: 4, fin: false);
        buffer.OnAcknowledged(offset: 4, length: 4, fin: true);

        SendChunk? again = buffer.TakeChunk(maximumLength: 8, long.MaxValue);

        Assert.NotNull(first);
        Assert.NotNull(second);
        Assert.NotNull(again);
        Assert.True(second.Fin);
        Assert.Equal(expected: 0, again.Offset);
        Assert.Equal("abcd"u8.ToArray(), again.Data);
        Assert.False(buffer.IsFullyAcknowledged);

        buffer.OnAcknowledged(again.Offset, again.Data.Length, again.Fin);

        Assert.True(buffer.IsFullyAcknowledged);
        Assert.False(buffer.HasPendingData);
    }

    /// <summary>
    /// Transport parameters must survive an encode and decode round trip.
    /// </summary>
    [Fact]
    public void TransportParametersRoundTrip()
    {
        TransportParameters parameters = new()
        {
            MaximumIdleTimeout = 30000,
            InitialMaximumData = 1 << 24,
            InitialMaximumStreamDataBidirectionalLocal = 1 << 20,
            InitialMaximumStreamsUnidirectional = 16,
            MaximumDatagramFrameSize = 65535,
            InitialSourceConnectionId = ExampleConnectionId,
        };

        TransportParameters decoded = TransportParameters.Decode(parameters.Encode());

        Assert.Equal(parameters.MaximumIdleTimeout, decoded.MaximumIdleTimeout);
        Assert.Equal(parameters.InitialMaximumData, decoded.InitialMaximumData);
        Assert.Equal(parameters.InitialMaximumStreamDataBidirectionalLocal, decoded.InitialMaximumStreamDataBidirectionalLocal);
        Assert.Equal(parameters.InitialMaximumStreamsUnidirectional, decoded.InitialMaximumStreamsUnidirectional);
        Assert.Equal(parameters.MaximumDatagramFrameSize, decoded.MaximumDatagramFrameSize);
        Assert.Equal(ExampleConnectionId, decoded.InitialSourceConnectionId);
    }
}
