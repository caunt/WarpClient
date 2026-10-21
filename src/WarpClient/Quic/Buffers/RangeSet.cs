namespace Warp.Quic.Buffers;

/// <summary>
/// A sorted set of disjoint half-open ranges, used for received packet numbers, acknowledged offsets and data to resend.
/// </summary>
internal sealed class RangeSet
{
    private readonly List<LongRange> _ranges = [];

    public int Count => _ranges.Count;

    public bool IsEmpty => _ranges.Count == 0;

    public IReadOnlyList<LongRange> Ranges => _ranges;

    public void Add(long start, long end)
    {
        if (start >= end)
            return;

        int index = 0;

        while (index < _ranges.Count && _ranges[index].End < start)
            index++;

        long mergedStart = start;
        long mergedEnd = end;

        while (index < _ranges.Count && _ranges[index].Start <= end)
        {
            mergedStart = Math.Min(mergedStart, _ranges[index].Start);
            mergedEnd = Math.Max(mergedEnd, _ranges[index].End);
            _ranges.RemoveAt(index);
        }

        _ranges.Insert(index, new LongRange(mergedStart, mergedEnd));
    }

    public bool Contains(long value)
    {
        foreach (LongRange range in _ranges)
        {
            if (value < range.Start)
                return false;

            if (value < range.End)
                return true;
        }

        return false;
    }

    // Keeps the newest ranges so acknowledgment frames stay small; peers re-acknowledge nothing older than that.
    public void KeepNewest(int count)
    {
        if (_ranges.Count > count)
            _ranges.RemoveRange(index: 0, _ranges.Count - count);
    }

    public void Remove(long start, long end)
    {
        for (int index = _ranges.Count - 1; index >= 0; index--)
        {
            LongRange range = _ranges[index];

            if (range.End <= start || range.Start >= end)
                continue;

            _ranges.RemoveAt(index);

            if (range.End > end)
                _ranges.Insert(index, new LongRange(end, range.End));

            if (range.Start < start)
                _ranges.Insert(index, new LongRange(range.Start, start));
        }
    }
}
