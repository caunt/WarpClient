using Warp.Networking.Tcp;

namespace Warp.Quic.Buffers;

/// <summary>
/// Outgoing bytes of a stream or CRYPTO flow, kept until acknowledged so lost ranges can be sent again.
/// </summary>
internal sealed class SendBuffer
{
    private readonly RangeSet _acknowledged = new();
    private readonly RangeSet _lost = new();
    private readonly ByteQueue _pending = new();
    private long _baseOffset;
    private bool _finAcknowledged;
    private bool _finLost;
    private bool _finSent;

    public int BufferedLength => _pending.Count;

    public bool FinRequested { get; private set; }

    public bool HasPendingData => !_lost.IsEmpty || NextOffset < WrittenOffset || FinPending;

    public bool IsFullyAcknowledged => FinRequested && _finAcknowledged && _baseOffset == WrittenOffset;

    public long NextOffset { get; private set; }

    public long WrittenOffset => _baseOffset + _pending.Count;

    private bool FinPending => FinRequested && NextOffset == WrittenOffset && !_finAcknowledged && (!_finSent || _finLost);

    public void Finish()
    {
        FinRequested = true;
    }

    public void OnAcknowledged(long offset, int length, bool fin)
    {
        if (fin)
            _finAcknowledged = true;

        _acknowledged.Add(offset, offset + length);
        _lost.Remove(offset, offset + length);

        while (!_acknowledged.IsEmpty && _acknowledged.Ranges[index: 0].Start <= _baseOffset)
        {
            LongRange first = _acknowledged.Ranges[index: 0];

            if (first.End > _baseOffset)
            {
                _pending.Discard((int)Math.Min(first.End - _baseOffset, _pending.Count));
                _baseOffset = first.End;
            }

            _acknowledged.Remove(first.Start, first.End);
        }
    }

    public void OnLost(long offset, int length, bool fin)
    {
        long start = Math.Max(offset, _baseOffset);
        long end = offset + length;

        if (end > start)
        {
            _lost.Add(start, end);

            foreach (LongRange acknowledged in _acknowledged.Ranges)
                _lost.Remove(acknowledged.Start, acknowledged.End);
        }

        if (fin && !_finAcknowledged)
            _finLost = true;
    }

    public SendChunk? TakeChunk(int maximumLength, long sendLimit)
    {
        if (maximumLength <= 0)
            return null;

        // Lost data goes first; its flow-control credit was spent when it was first sent.
        if (!_lost.IsEmpty)
        {
            LongRange range = _lost.Ranges[index: 0];
            int length = (int)Math.Min(range.End - range.Start, maximumLength);
            bool finAgain = _finLost && FinRequested && range.Start + length == WrittenOffset;

            _lost.Remove(range.Start, range.Start + length);

            if (finAgain)
                _finLost = false;

            return new SendChunk(range.Start, Copy(range.Start, length), finAgain, IsNewData: false);
        }

        long available = Math.Min(WrittenOffset, sendLimit) - NextOffset;

        if (available > 0)
        {
            int length = (int)Math.Min(available, maximumLength);
            long offset = NextOffset;

            NextOffset += length;

            bool fin = FinRequested && NextOffset == WrittenOffset;

            if (fin)
            {
                _finSent = true;
                _finLost = false;
            }

            return new SendChunk(offset, Copy(offset, length), fin, IsNewData: true);
        }

        if (!FinPending)
            return null;

        _finSent = true;
        _finLost = false;

        return new SendChunk(NextOffset, [], Fin: true, IsNewData: false);
    }

    public void Write(ReadOnlySpan<byte> data)
    {
        _pending.Enqueue(data);
    }

    private byte[] Copy(long offset, int length)
    {
        byte[] data = new byte[length];

        _pending.CopyTo((int)(offset - _baseOffset), data);

        return data;
    }
}
