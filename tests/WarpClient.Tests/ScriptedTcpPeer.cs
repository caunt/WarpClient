using System.Collections.Concurrent;
using System.Net;

using Warp.Networking;
using Warp.Networking.Packets;

namespace Warp.Tests;

/// <summary>
/// Stands in for the remote end of the tunnel: it answers the SYN of the stack under test and then sends exactly the
/// segments a test scripts, while recording everything the stack transmits.
/// </summary>
internal sealed class ScriptedTcpPeer(IPAddress localAddress, IPAddress peerAddress, ushort peerPort, int windowScale) : IPacketTransmitter
{
    public const uint InitialSequence = 7000;
    public const int MaximumSegmentSize = 1240;

    private readonly ConcurrentQueue<TcpSegment> _received = new();
    private readonly ConcurrentQueue<Task> _replies = new();
    private ushort _clientPort;
    private int _identification;

    public uint ClientFirstSequence { get; private set; }

    public IReadOnlyList<TcpSegment> Received => [.. _received];

    public UserspaceNetworkStack? Stack { get; set; }

    public static async Task WaitForAsync(Func<bool> condition)
    {
        using CancellationTokenSource timeout = new(TimeSpan.FromSeconds(seconds: 10));

        while (!condition())
            await Task.Delay(TimeSpan.FromMilliseconds(milliseconds: 10), timeout.Token).ConfigureAwait(continueOnCapturedContext: false);
    }

    public async ValueTask SendAsync(uint sequence, uint acknowledgment, TcpControlBits controlBits, ReadOnlyMemory<byte> payload)
    {
        TcpSegment segment = new(peerPort, _clientPort, sequence, acknowledgment, controlBits, ushort.MaxValue, MaximumSegmentSize: 0, payload);

        await DeliverAsync(segment).ConfigureAwait(continueOnCapturedContext: false);
    }

    public ValueTask TransmitAsync(ReadOnlyMemory<byte> packet, CancellationToken cancellationToken)
    {
        bool parsedPacket = InternetPacket.TryParse(packet.Span, out InternetDatagram datagram);
        bool parsedSegment = TcpSegment.TryParse(packet.Slice(datagram.PayloadOffset, datagram.PayloadLength), out TcpSegment segment);

        if (!parsedPacket || !parsedSegment)
            return ValueTask.CompletedTask;

        _received.Enqueue(segment);

        // The stack holds its connection lock while it transmits, so the reply has to come from another task.
        if ((segment.ControlBits & TcpControlBits.Synchronize) != 0)
            _replies.Enqueue(Task.Run(() => AcceptAsync(segment).AsTask(), CancellationToken.None));

        return ValueTask.CompletedTask;
    }

    private async ValueTask AcceptAsync(TcpSegment synchronize)
    {
        _clientPort = synchronize.SourcePort;
        ClientFirstSequence = synchronize.SequenceNumber + 1;

        TcpSegment reply = new(
            peerPort,
            _clientPort,
            InitialSequence,
            ClientFirstSequence,
            TcpControlBits.Synchronize | TcpControlBits.Acknowledgment,
            ushort.MaxValue,
            MaximumSegmentSize,
            ReadOnlyMemory<byte>.Empty,
            windowScale
        );

        await DeliverAsync(reply).ConfigureAwait(continueOnCapturedContext: false);
    }

    private async ValueTask DeliverAsync(TcpSegment segment)
    {
        UserspaceNetworkStack stack = Stack ?? throw new InvalidOperationException(message: "The peer is not attached to a stack.");
        ushort identification = (ushort)Interlocked.Increment(ref _identification);
        byte[] packet = InternetPacket.CreateTcp(peerAddress, localAddress, identification, segment);

        await stack.ReceiveAsync(packet, CancellationToken.None).ConfigureAwait(continueOnCapturedContext: false);
    }
}
