namespace Warp.Networking;

internal sealed class ByteQueue
{
    private byte[] _buffer = new byte[4096];
    private int _head;

    public int Count { get; private set; }

    public void CopyTo(int offset, Span<byte> destination)
    {
        int start = (_head + offset) % _buffer.Length;
        int firstLength = Math.Min(destination.Length, _buffer.Length - start);

        _buffer.AsSpan(start, firstLength).CopyTo(destination);
        _buffer.AsSpan(start: 0, destination.Length - firstLength).CopyTo(destination[firstLength..]);
    }

    public int Dequeue(Span<byte> destination)
    {
        int length = Math.Min(Count, destination.Length);

        CopyTo(offset: 0, destination[..length]);
        Discard(length);

        return length;
    }

    public void Discard(int length)
    {
        _head = (_head + length) % _buffer.Length;
        Count -= length;
    }

    public void Enqueue(ReadOnlySpan<byte> data)
    {
        EnsureCapacity(Count + data.Length);

        int tail = (_head + Count) % _buffer.Length;
        int firstLength = Math.Min(data.Length, _buffer.Length - tail);

        data[..firstLength].CopyTo(_buffer.AsSpan(tail));
        data[firstLength..].CopyTo(_buffer);
        Count += data.Length;
    }

    private void EnsureCapacity(int required)
    {
        if (required <= _buffer.Length)
            return;

        byte[] next = new byte[Math.Max(required, _buffer.Length * 2)];

        CopyTo(offset: 0, next.AsSpan(start: 0, Count));
        _buffer = next;
        _head = 0;
    }
}
