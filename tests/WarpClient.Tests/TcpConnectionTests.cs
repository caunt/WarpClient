using System.Net;
using System.Security.Cryptography;

using Warp.Networking;
using Warp.Networking.Packets;

namespace Warp.Tests;

/// <summary>
/// Drives the userspace TCP implementation against a scripted peer, covering the behaviour that keeps transfers through
/// a high-latency, lossy tunnel fast: window scaling, holding segments past a gap, fast retransmit and coalesced
/// acknowledgments.
/// </summary>
public sealed class TcpConnectionTests : IAsyncDisposable
{
    private const int FullSegment = ScriptedTcpPeer.MaximumSegmentSize;
    private static readonly IPAddress LocalAddress = IPAddress.Parse(ipString: "10.0.0.2");
    private static readonly IPAddress PeerAddress = IPAddress.Parse(ipString: "10.0.0.1");

    private UserspaceNetworkStack? _stack;

    /// <summary>
    /// When both ends offer window scaling, the stack advertises a receive window beyond the 64 KB a bare window field can express.
    /// </summary>
    [Fact]
    public async Task ConnectionAdvertisesScaledWindowWhenPeerOffersScaling()
    {
        (ScriptedTcpPeer peer, UserspaceNetworkStack stack) = CreateStack(windowScale: 7);

        Stream stream = await ConnectAsync(stack);

        TcpSegment synchronize = peer.Received[index: 0];
        TcpSegment acknowledgment = peer.Received[index: 1];

        Assert.NotNull(stream);
        Assert.True(synchronize.WindowScale > 0);
        Assert.Equal(ushort.MaxValue, synchronize.Window);
        Assert.True(acknowledgment.Window << synchronize.WindowScale > ushort.MaxValue);
    }

    /// <summary>
    /// A peer that does not offer window scaling must only ever see an unscaled window.
    /// </summary>
    [Fact]
    public async Task ConnectionKeepsWindowUnscaledWhenPeerDeclinesScaling()
    {
        (ScriptedTcpPeer peer, UserspaceNetworkStack stack) = CreateStack(TcpSegment.AbsentWindowScale);

        Stream stream = await ConnectAsync(stack);

        Assert.NotNull(stream);
        Assert.Equal(ushort.MaxValue, peer.Received[index: 1].Window);
    }

    /// <inheritdoc />
    public async ValueTask DisposeAsync()
    {
        // The scripted peer never acknowledges a FIN, so connections are aborted instead of closed gracefully.
        if (_stack is not null)
            await _stack.StopAsync(new IOException(message: "The test finished.")).ConfigureAwait(continueOnCapturedContext: false);
    }

    /// <summary>
    /// Full-size segments are acknowledged every second segment, and a lone one is still acknowledged by the timer.
    /// </summary>
    [Fact]
    public async Task FullSegmentsAreAcknowledgedInPairsAndLoneSegmentByTimer()
    {
        (ScriptedTcpPeer peer, UserspaceNetworkStack stack) = CreateStack(windowScale: 7);

        Assert.NotNull(await ConnectAsync(stack));

        byte[] payload = new byte[FullSegment];
        uint sequence = ScriptedTcpPeer.InitialSequence + 1;
        int transmitted = peer.Received.Count;

        await peer.SendAsync(sequence, peer.ClientFirstSequence, TcpControlBits.Acknowledgment, payload);

        Assert.Equal(transmitted, peer.Received.Count);

        await peer.SendAsync(sequence + FullSegment, peer.ClientFirstSequence, TcpControlBits.Acknowledgment, payload);

        Assert.Equal(transmitted + 1, peer.Received.Count);
        Assert.Equal(sequence + (FullSegment * 2), peer.Received[^1].AcknowledgmentNumber);

        await peer.SendAsync(sequence + (FullSegment * 2), peer.ClientFirstSequence, TcpControlBits.Acknowledgment, payload);
        await ScriptedTcpPeer.WaitForAsync(() => peer.Received.Count == transmitted + 2);

        Assert.Equal(sequence + (FullSegment * 3), peer.Received[^1].AcknowledgmentNumber);
    }

    /// <summary>
    /// Segments that arrive after a lost one are held and answered with duplicate acknowledgments, then delivered in order
    /// once the missing segment shows up, without the peer resending them.
    /// </summary>
    [Fact]
    public async Task SegmentsPastLostSegmentAreDeliveredOnceGapIsFilled()
    {
        (ScriptedTcpPeer peer, UserspaceNetworkStack stack) = CreateStack(windowScale: 7);

        Stream stream = await ConnectAsync(stack);

        byte[] data = new byte[FullSegment * 3];

        RandomNumberGenerator.Fill(data);

        uint first = ScriptedTcpPeer.InitialSequence + 1;
        int transmitted = peer.Received.Count;

        await peer.SendAsync(first + FullSegment, peer.ClientFirstSequence, TcpControlBits.Acknowledgment, data.AsMemory(FullSegment, FullSegment));
        await peer.SendAsync(first + (FullSegment * 2), peer.ClientFirstSequence, TcpControlBits.Acknowledgment, data.AsMemory(FullSegment * 2, FullSegment));

        IReadOnlyList<TcpSegment> duplicates = [.. peer.Received.Skip(transmitted)];

        Assert.Equal(expected: 2, duplicates.Count);
        Assert.All(duplicates, duplicate => Assert.Equal(first, duplicate.AcknowledgmentNumber));

        await peer.SendAsync(first, peer.ClientFirstSequence, TcpControlBits.Acknowledgment, data.AsMemory(start: 0, FullSegment));

        byte[] received = new byte[data.Length];

        using CancellationTokenSource timeout = new(TimeSpan.FromSeconds(seconds: 10));

        await stream.ReadExactlyAsync(received, timeout.Token);

        Assert.Equal(data, received);
        Assert.Equal(first + (uint)data.Length, peer.Received[^1].AcknowledgmentNumber);
    }

    /// <summary>
    /// Window scale and maximum segment size are both written to and read from a SYN.
    /// </summary>
    [Fact]
    public void TcpSegmentRoundTripsWindowScaleWithMaximumSegmentSize()
    {
        TcpSegment segment = new(
            SourcePort: 50000,
            DestinationPort: 443,
            SequenceNumber: 1,
            AcknowledgmentNumber: 0,
            TcpControlBits.Synchronize,
            Window: 65535,
            MaximumSegmentSize: 1240,
            ReadOnlyMemory<byte>.Empty,
            WindowScale: 7
        );

        byte[] packet = InternetPacket.CreateTcp(LocalAddress, PeerAddress, identification: 1, segment);
        bool parsedPacket = InternetPacket.TryParse(packet, out InternetDatagram datagram);
        bool parsedSegment = TcpSegment.TryParse(packet.AsMemory(datagram.PayloadOffset, datagram.PayloadLength), out TcpSegment parsed);

        Assert.True(parsedPacket);
        Assert.True(parsedSegment);
        Assert.Equal(expected: 1240, parsed.MaximumSegmentSize);
        Assert.Equal(expected: 7, parsed.WindowScale);
    }

    /// <summary>
    /// A segment without the option reports it as absent rather than as a shift of zero.
    /// </summary>
    [Fact]
    public void TcpSegmentWithoutWindowScaleReportsItAbsent()
    {
        TcpSegment segment = new(
            SourcePort: 50000,
            DestinationPort: 443,
            SequenceNumber: 1,
            AcknowledgmentNumber: 0,
            TcpControlBits.Synchronize,
            Window: 65535,
            MaximumSegmentSize: 1240,
            ReadOnlyMemory<byte>.Empty
        );

        byte[] packet = InternetPacket.CreateTcp(LocalAddress, PeerAddress, identification: 1, segment);
        bool parsedPacket = InternetPacket.TryParse(packet, out InternetDatagram datagram);
        bool parsedSegment = TcpSegment.TryParse(packet.AsMemory(datagram.PayloadOffset, datagram.PayloadLength), out TcpSegment parsed);

        Assert.True(parsedPacket);
        Assert.True(parsedSegment);
        Assert.Equal(TcpSegment.AbsentWindowScale, parsed.WindowScale);
    }

    /// <summary>
    /// Three duplicate acknowledgments resend only the first unacknowledged segment instead of waiting for the timeout and
    /// repeating the whole flight.
    /// </summary>
    [Fact]
    public async Task ThreeDuplicateAcknowledgmentsResendOnlyFirstUnacknowledgedSegment()
    {
        (ScriptedTcpPeer peer, UserspaceNetworkStack stack) = CreateStack(windowScale: 7);

        Stream stream = await ConnectAsync(stack);

        using CancellationTokenSource timeout = new(TimeSpan.FromSeconds(seconds: 10));

        await stream.WriteAsync(new byte[FullSegment * 3], timeout.Token);

        uint first = peer.ClientFirstSequence;
        uint peerNext = ScriptedTcpPeer.InitialSequence + 1;

        // The first acknowledgment announces the scaled window; only repeats of it count as duplicates.
        for (int repeat = 0; repeat < 4; repeat++)
            await peer.SendAsync(peerNext, first, TcpControlBits.Acknowledgment, ReadOnlyMemory<byte>.Empty);

        IReadOnlyList<TcpSegment> sent = [.. peer.Received.Where(static segment => !segment.Payload.IsEmpty)];

        Assert.Equal(expected: 4, sent.Count);
        Assert.Equal(first, sent[index: 3].SequenceNumber);
        Assert.Equal(FullSegment, sent[index: 3].Payload.Length);
    }

    private static async Task<Stream> ConnectAsync(UserspaceNetworkStack stack)
    {
        using CancellationTokenSource timeout = new(TimeSpan.FromSeconds(seconds: 10));

        return await stack.ConnectAsync(new IPEndPoint(PeerAddress, port: 443), timeout.Token).ConfigureAwait(continueOnCapturedContext: false);
    }

    private Harness CreateStack(int windowScale)
    {
        ScriptedTcpPeer peer = new(LocalAddress, PeerAddress, peerPort: 443, windowScale);
        UserspaceNetworkStack stack = new(peer, LocalAddress, localIpv6: null);

        peer.Stack = stack;
        _stack = stack;

        return new Harness(peer, stack);
    }

    private sealed record Harness(ScriptedTcpPeer Peer, UserspaceNetworkStack Stack);
}
