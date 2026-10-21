namespace Warp.Quic.Recovery;

/// <summary>
/// Round-trip estimation, probe timeouts and NewReno congestion control for one connection (RFC 9002), with times in
/// milliseconds.
/// </summary>
internal sealed class RecoveryState(int maximumDatagramSize)
{
    public const long Granularity = 1;
    private const long InitialRtt = 333;
    private const int LossReductionDivisor = 2;
    private const int MinimumWindowPackets = 2;

    private long _recoveryStartedAt = long.MinValue;

    public long BytesInFlight { get; private set; }

    public bool CanSend => BytesInFlight < CongestionWindow;

    public long CongestionWindow { get; private set; } = Math.Min(10L * maximumDatagramSize, Math.Max(val1: 14720, 2L * maximumDatagramSize));

    public bool HasRttSample { get; private set; }

    public long LatestRtt { get; private set; }

    public long LossDelay => Math.Max(Math.Max(SmoothedRtt, LatestRtt) * 9 / 8, Granularity);

    public long MinimumRtt { get; private set; }

    public int ProbeCount { get; set; }

    public long RttVariance { get; private set; } = InitialRtt / 2;

    public long SlowStartThreshold { get; private set; } = long.MaxValue;

    public long SmoothedRtt { get; private set; } = InitialRtt;

    public long GetProbeTimeout(long maximumAckDelay)
    {
        long timeout = SmoothedRtt + Math.Max(4 * RttVariance, Granularity) + maximumAckDelay;

        return timeout << Math.Min(ProbeCount, val2: 16);
    }

    public void OnPacketAcknowledged(SentPacket packet)
    {
        BytesInFlight = Math.Max(val1: 0, BytesInFlight - packet.Size);

        // Packets sent before the current recovery period began do not grow the window again.
        if (packet.SentAt <= _recoveryStartedAt)
            return;

        if (CongestionWindow < SlowStartThreshold)
            CongestionWindow += packet.Size;
        else
            CongestionWindow += (long)maximumDatagramSize * packet.Size / CongestionWindow;
    }

    public void OnPacketDiscarded(SentPacket packet)
    {
        BytesInFlight = Math.Max(val1: 0, BytesInFlight - packet.Size);
    }

    public void OnPacketSent(int size)
    {
        BytesInFlight += size;
    }

    public void OnPacketsLost(long lostBytes, long latestLostSentAt, long now)
    {
        BytesInFlight = Math.Max(val1: 0, BytesInFlight - lostBytes);

        if (latestLostSentAt <= _recoveryStartedAt)
            return;

        _recoveryStartedAt = now;
        SlowStartThreshold = Math.Max(CongestionWindow / LossReductionDivisor, (long)MinimumWindowPackets * maximumDatagramSize);
        CongestionWindow = SlowStartThreshold;
    }

    public void UpdateRtt(long latestRtt, long ackDelay)
    {
        LatestRtt = Math.Max(latestRtt, Granularity);

        if (!HasRttSample)
        {
            HasRttSample = true;
            MinimumRtt = LatestRtt;
            SmoothedRtt = LatestRtt;
            RttVariance = LatestRtt / 2;

            return;
        }

        MinimumRtt = Math.Min(MinimumRtt, LatestRtt);

        // The peer's reported delay is subtracted only when that cannot push the sample below the minimum seen.
        long adjusted = LatestRtt >= MinimumRtt + ackDelay ? LatestRtt - ackDelay : LatestRtt;

        RttVariance = ((3 * RttVariance) + Math.Abs(SmoothedRtt - adjusted)) / 4;
        SmoothedRtt = ((7 * SmoothedRtt) + adjusted) / 8;
    }
}
