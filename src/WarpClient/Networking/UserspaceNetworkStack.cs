using System.Buffers.Binary;
using System.Collections.Immutable;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;

using Nito.AsyncEx;

namespace Warp.Networking;

/// <summary>
/// Minimal IPv4 host that lives inside a packet tunnel: it owns one tunnel address, dispatches inbound packets to TCP
/// connections and pending UDP exchanges, and turns their output back into packets.
/// </summary>
internal sealed class UserspaceNetworkStack(IPacketTransmitter transmitter, IPAddress localAddress) : IPacketReceiver
{
    private const int EphemeralPortCount = 16384;
    private const int FirstEphemeralPort = 49152;
    private const int MaximumSegmentSize = MaximumTransmissionUnit - Ipv4Packet.HeaderLength - TcpSegment.HeaderLength;
    private const int MaximumTransmissionUnit = 1280;
    private const int UdpHeaderLength = 8;

    private readonly AsyncLock _mutex = new();
    private ImmutableDictionary<ConnectionKey, TcpConnection> _connections = [];
    private ImmutableDictionary<ushort, TunnelUdpConnection> _datagramConnections = [];
    private Exception? _failure;
    private int _identification;
    private int _portCursor = RandomNumberGenerator.GetInt32(EphemeralPortCount);

    public async ValueTask<Stream> ConnectAsync(IPEndPoint remoteEndPoint, CancellationToken cancellationToken)
    {
        if (remoteEndPoint.AddressFamily != AddressFamily.InterNetwork)
            throw new NotSupportedException(message: "The tunnel stack only carries IPv4 connections.");

        TcpConnection connection;

        using (await _mutex.LockAsync(cancellationToken).ConfigureAwait(continueOnCapturedContext: false))
        {
            ThrowIfStopped();

            ConnectionKey key = new(AllocatePort(), remoteEndPoint.Address, (ushort)remoteEndPoint.Port);

            connection = new TcpConnection(this, key, MaximumSegmentSize);
            _connections = _connections.Add(key, connection);
        }

        try
        {
            await connection.ConnectAsync(cancellationToken).ConfigureAwait(continueOnCapturedContext: false);
        }
        catch
        {
            await connection.AbortAsync(new OperationCanceledException(message: "The connection attempt was abandoned.")).ConfigureAwait(continueOnCapturedContext: false);
            await RemoveAsync(connection.Key).ConfigureAwait(continueOnCapturedContext: false);

            throw;
        }

        return new TcpConnectionStream(connection);
    }

    public async ValueTask<TunnelUdpConnection> ConnectDatagramAsync(IPEndPoint remoteEndPoint, CancellationToken cancellationToken)
    {
        if (remoteEndPoint.AddressFamily != AddressFamily.InterNetwork)
            throw new NotSupportedException(message: "The tunnel stack only carries IPv4 datagrams.");

        using (await _mutex.LockAsync(cancellationToken).ConfigureAwait(continueOnCapturedContext: false))
        {
            ThrowIfStopped();

            ushort port = AllocatePort();
            TunnelUdpConnection connection = new(this, port, remoteEndPoint);

            _datagramConnections = _datagramConnections.Add(port, connection);

            return connection;
        }
    }

    public async ValueTask ReceiveAsync(ReadOnlyMemory<byte> packet, CancellationToken cancellationToken)
    {
        if (!Ipv4Packet.TryParse(packet.Span, out Ipv4Datagram datagram) || !datagram.Destination.Equals(localAddress))
            return;

        ReadOnlyMemory<byte> payload = packet.Slice(datagram.PayloadOffset, datagram.PayloadLength);

        if (datagram.Protocol == Ipv4Packet.TcpProtocol)
            await ReceiveSegmentAsync(datagram.Source, payload, cancellationToken).ConfigureAwait(continueOnCapturedContext: false);
        else if (datagram.Protocol == Ipv4Packet.UdpProtocol)
            await ReceiveDatagramAsync(datagram.Source, payload, cancellationToken).ConfigureAwait(continueOnCapturedContext: false);
    }

    public async ValueTask RemoveAsync(ConnectionKey key)
    {
        using (await _mutex.LockAsync().ConfigureAwait(continueOnCapturedContext: false))
            _connections = _connections.Remove(key);
    }

    public async ValueTask RemoveDatagramAsync(ushort localPort)
    {
        using (await _mutex.LockAsync().ConfigureAwait(continueOnCapturedContext: false))
            _datagramConnections = _datagramConnections.Remove(localPort);
    }

    public async ValueTask SendDatagramAsync(ushort localPort, IPEndPoint remoteEndPoint, ReadOnlyMemory<byte> payload, CancellationToken cancellationToken)
    {
        byte[] packet = Ipv4Packet.CreateUdp(localAddress, remoteEndPoint.Address, NextIdentification(), localPort, (ushort)remoteEndPoint.Port, payload.Span);

        await transmitter.TransmitAsync(packet, cancellationToken).ConfigureAwait(continueOnCapturedContext: false);
    }

    public async ValueTask SendSegmentAsync(IPAddress remoteAddress, TcpSegment segment, CancellationToken cancellationToken)
    {
        byte[] packet = Ipv4Packet.CreateTcp(localAddress, remoteAddress, NextIdentification(), segment);

        await transmitter.TransmitAsync(packet, cancellationToken).ConfigureAwait(continueOnCapturedContext: false);
    }

    public async ValueTask StopAsync(Exception reason)
    {
        ImmutableDictionary<ConnectionKey, TcpConnection> stoppedConnections;
        ImmutableDictionary<ushort, TunnelUdpConnection> stoppedDatagramConnections;

        using (await _mutex.LockAsync().ConfigureAwait(continueOnCapturedContext: false))
        {
            _failure ??= reason;
            stoppedConnections = _connections;
            stoppedDatagramConnections = _datagramConnections;
            _connections = _connections.Clear();
            _datagramConnections = _datagramConnections.Clear();
        }

        foreach (TcpConnection connection in stoppedConnections.Values)
            await connection.AbortAsync(reason).ConfigureAwait(continueOnCapturedContext: false);

        foreach (TunnelUdpConnection connection in stoppedDatagramConnections.Values)
            connection.Fail(reason);
    }

    private ushort AllocatePort()
    {
        for (int attempt = 0; attempt < EphemeralPortCount; attempt++)
        {
            int offset = (_portCursor + attempt) % EphemeralPortCount;
            ushort candidate = (ushort)(FirstEphemeralPort + offset);
            bool used = _datagramConnections.ContainsKey(candidate) || _connections.Keys.Any(key => key.LocalPort == candidate);

            if (!used)
            {
                _portCursor = offset + 1;

                return candidate;
            }
        }

        throw new IOException(message: "The tunnel stack has no free local ports left.");
    }

    private ushort NextIdentification()
    {
        return (ushort)Interlocked.Increment(ref _identification);
    }

    private async ValueTask ReceiveDatagramAsync(IPAddress source, ReadOnlyMemory<byte> payload, CancellationToken cancellationToken)
    {
        if (payload.Length < UdpHeaderLength)
            return;

        ushort sourcePort = BinaryPrimitives.ReadUInt16BigEndian(payload.Span);
        ushort destinationPort = BinaryPrimitives.ReadUInt16BigEndian(payload.Span[2..]);
        TunnelUdpConnection? connection = null;

        using (await _mutex.LockAsync(cancellationToken).ConfigureAwait(continueOnCapturedContext: false))
        {
            if (_datagramConnections.TryGetValue(destinationPort, out TunnelUdpConnection? found))
                connection = found;
        }

        if (connection is not null && connection.Accepts(source, sourcePort))
            await connection.DeliverAsync(payload[UdpHeaderLength..].ToArray(), cancellationToken).ConfigureAwait(continueOnCapturedContext: false);
    }

    private async ValueTask ReceiveSegmentAsync(IPAddress source, ReadOnlyMemory<byte> payload, CancellationToken cancellationToken)
    {
        if (!TcpSegment.TryParse(payload, out TcpSegment segment))
            return;

        ConnectionKey key = new(segment.DestinationPort, source, segment.SourcePort);
        TcpConnection? connection = null;

        using (await _mutex.LockAsync(cancellationToken).ConfigureAwait(continueOnCapturedContext: false))
        {
            if (_connections.TryGetValue(key, out TcpConnection? found))
                connection = found;
        }

        if (connection is not null)
            await connection.HandleSegmentAsync(segment, cancellationToken).ConfigureAwait(continueOnCapturedContext: false);
        else if ((segment.ControlBits & TcpControlBits.Reset) == 0)
            await RejectSegmentAsync(source, segment, cancellationToken).ConfigureAwait(continueOnCapturedContext: false);
    }

    private async ValueTask RejectSegmentAsync(IPAddress source, TcpSegment segment, CancellationToken cancellationToken)
    {
        // Segments for connections that no longer exist get a reset, so the remote host stops retransmitting them.
        bool acknowledging = (segment.ControlBits & TcpControlBits.Acknowledgment) != 0;
        uint occupied = (uint)segment.Payload.Length + ((segment.ControlBits & (TcpControlBits.Synchronize | TcpControlBits.Finish)) != 0 ? 1u : 0u);

        TcpSegment reset = new(
            segment.DestinationPort,
            segment.SourcePort,
            acknowledging ? segment.AcknowledgmentNumber : 0,
            acknowledging ? 0 : segment.SequenceNumber + occupied,
            acknowledging ? TcpControlBits.Reset : TcpControlBits.Reset | TcpControlBits.Acknowledgment,
            Window: 0,
            MaximumSegmentSize: 0,
            ReadOnlyMemory<byte>.Empty
        );

        await SendSegmentAsync(source, reset, cancellationToken).ConfigureAwait(continueOnCapturedContext: false);
    }

    private void ThrowIfStopped()
    {
        if (_failure is not null)
            throw new IOException(message: "The tunnel is closed.", _failure);
    }
}
