namespace Warp.Quic.Frames;

/// <summary>
/// Unreliable QUIC datagrams (RFC 9221) waiting to be sent or read. Both queues are bounded and drop their oldest entry
/// rather than grow, since datagrams may be lost anyway.
/// </summary>
internal sealed class DatagramQueue(int capacity)
{
    private readonly LinkedList<byte[]> _incoming = new();
    private readonly LinkedList<byte[]> _outgoing = new();

    public void Enqueue(ReadOnlySpan<byte> datagram)
    {
        Add(_outgoing, datagram.ToArray());
    }

    public void OnReceived(ReadOnlySpan<byte> datagram)
    {
        Add(_incoming, datagram.ToArray());
    }

    public byte[]? TryReceive()
    {
        if (_incoming.First is not LinkedListNode<byte[]> first)
            return null;

        _incoming.RemoveFirst();

        return first.Value;
    }

    /// <summary>
    /// Writes as many queued datagrams as fit within <paramref name="limit"/>, and returns <see langword="true"/> when the
    /// next one would fit a packet of <paramref name="packetLimit"/> on its own, so whatever shares this packet should go
    /// now. Datagrams too large for any packet are dropped.
    /// </summary>
    public bool Write(QuicWriter payload, int limit, int packetLimit)
    {
        while (_outgoing.First?.Value is byte[] datagram)
        {
            int size = 1 + VariableLengthInteger.GetLength((ulong)datagram.Length) + datagram.Length;

            if (size > packetLimit)
            {
                _outgoing.RemoveFirst();

                continue;
            }

            if (payload.Length + size > limit)
                return payload.Length == 0;

            FrameWriter.WriteDatagram(payload, datagram);
            _outgoing.RemoveFirst();
        }

        return false;
    }

    private void Add(LinkedList<byte[]> queue, byte[] datagram)
    {
        if (queue.Count >= capacity)
            queue.RemoveFirst();

        queue.AddLast(new LinkedListNode<byte[]>(datagram));
    }
}
