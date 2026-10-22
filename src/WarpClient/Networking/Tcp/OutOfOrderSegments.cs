namespace Warp.Networking.Tcp;

/// <summary>
/// Holds payloads that arrived ahead of a gap in the byte stream, so the peer only has to resend the lost segment.
/// </summary>
internal sealed class OutOfOrderSegments
{
    private readonly List<Chunk> _chunks = [];

    public int BufferedBytes { get; private set; }

    public void Add(uint sequenceNumber, ReadOnlySpan<byte> payload)
    {
        int index = 0;

        while (index < _chunks.Count && IsBefore(_chunks[index].SequenceNumber, sequenceNumber))
            index++;

        bool duplicate = index < _chunks.Count && _chunks[index].SequenceNumber == sequenceNumber && _chunks[index].Payload.Length >= payload.Length;

        if (duplicate)
            return;

        _chunks.Insert(index, new Chunk(sequenceNumber, payload.ToArray()));
        BufferedBytes += payload.Length;
    }

    /// <summary>
    /// Moves every payload that now continues the stream into <paramref name="destination"/> and returns the next expected sequence number.
    /// </summary>
    public uint Drain(ByteQueue destination, uint receiveNext, int capacity)
    {
        while (_chunks.Count > 0)
        {
            Chunk first = _chunks[index: 0];
            int overlap = (int)(receiveNext - first.SequenceNumber);

            if (overlap < 0)
                break;

            if (overlap >= first.Payload.Length)
            {
                RemoveFirst();

                continue;
            }

            int length = Math.Min(first.Payload.Length - overlap, capacity - destination.Count);

            if (length <= 0)
                break;

            destination.Enqueue(first.Payload.AsSpan(overlap, length));
            receiveNext += (uint)length;

            if (overlap + length < first.Payload.Length)
                break;

            RemoveFirst();
        }

        return receiveNext;
    }

    private static bool IsBefore(uint first, uint second)
    {
        return (int)(first - second) < 0;
    }

    private void RemoveFirst()
    {
        BufferedBytes -= _chunks[index: 0].Payload.Length;
        _chunks.RemoveAt(index: 0);
    }

    private readonly record struct Chunk(uint SequenceNumber, byte[] Payload);
}
