using Warp.Networking.Tcp;

namespace Warp.Quic.Buffers;

/// <summary>
/// Puts stream or CRYPTO data that may arrive out of order and overlapping back into one contiguous byte sequence.
/// </summary>
internal sealed class ReassemblyBuffer
{
    private readonly SortedDictionary<long, byte[]> _chunks = [];
    private readonly ByteQueue _ready = new();

    public int AvailableLength => _ready.Count;

    public long ContiguousOffset => ReadOffset + _ready.Count;

    public long HighestOffset { get; private set; }

    public long ReadOffset { get; private set; }

    public void Insert(long offset, ReadOnlySpan<byte> data)
    {
        long end = offset + data.Length;

        HighestOffset = Math.Max(HighestOffset, end);

        if (data.IsEmpty || end <= ContiguousOffset)
            return;

        if (offset > ContiguousOffset)
        {
            if (!_chunks.TryGetValue(offset, out byte[]? existing) || existing.Length < data.Length)
                _chunks[offset] = data.ToArray();

            return;
        }

        _ready.Enqueue(data[(int)(ContiguousOffset - offset)..]);
        DrainChunks();
    }

    // Accounts for data that is dropped instead of buffered, such as on a stream whose reading was aborted.
    public void Observe(long end)
    {
        HighestOffset = Math.Max(HighestOffset, end);
    }

    public int Read(Span<byte> destination)
    {
        int read = _ready.Dequeue(destination);

        ReadOffset += read;

        return read;
    }

    private void DrainChunks()
    {
        while (_chunks.Count > 0)
        {
            KeyValuePair<long, byte[]> first = _chunks.First();

            if (first.Key > ContiguousOffset || !_chunks.Remove(first.Key))
                return;

            long end = first.Key + first.Value.Length;

            if (end > ContiguousOffset)
                _ready.Enqueue(first.Value.AsSpan((int)(ContiguousOffset - first.Key)));
        }
    }
}
