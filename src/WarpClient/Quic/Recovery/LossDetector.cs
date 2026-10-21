using Warp.Quic.Buffers;

namespace Warp.Quic.Recovery;

/// <summary>
/// Detects lost packets by acknowledgment gaps and timers, and schedules probe packets when acknowledgments stop arriving
/// (RFC 9002 section 6).
/// </summary>
internal sealed class LossDetector(RecoveryState recovery, IReadOnlyList<PacketNumberSpace> spaces, ISentFrameHandler handler)
{
    private const int PacketThreshold = 3;
    private const int ProbePacketCount = 2;
    private const int RequeuedApplicationPackets = 2;

    private long _lastAckElicitingSentAt;

    public void Discard(PacketNumberSpace space)
    {
        Forget(space);
        space.IsDiscarded = true;
        space.AckPending = false;
        space.ProbesPending = 0;
        space.PingPending = false;
        recovery.ProbeCount = 0;
    }

    // Drops what is in flight without treating it as lost, as after a Retry or when keys are discarded.
    public void Forget(PacketNumberSpace space)
    {
        foreach (SentPacket packet in space.Sent.Values)
            recovery.OnPacketDiscarded(packet);

        space.Sent.Clear();
        space.LossTime = long.MaxValue;
    }

    public long GetDeadline(bool handshakeComplete, bool handshakeConfirmed, long maximumAckDelay)
    {
        long lossTime = long.MaxValue;

        foreach (PacketNumberSpace space in spaces)
            lossTime = Math.Min(lossTime, space.LossTime);

        return lossTime != long.MaxValue ? lossTime : GetProbeDeadline(handshakeComplete, handshakeConfirmed, maximumAckDelay, out PacketNumberSpace? _);
    }

    public void OnAckReceived(PacketNumberSpace space, IReadOnlyList<LongRange> ranges, long ackDelay, long now)
    {
        List<SentPacket> acknowledged = [];

        foreach (SentPacket packet in space.Sent.Values)
        {
            if (Contains(ranges, packet.Number))
                acknowledged.Add(packet);
        }

        long largest = ranges[index: 0].End - 1;

        space.LargestAcknowledged = Math.Max(space.LargestAcknowledged, largest);

        if (acknowledged.Count == 0)
            return;

        SentPacket newest = acknowledged[^1];

        // Only an acknowledgment that newly covers the largest packet number gives a usable round-trip sample.
        if (newest.Number == largest)
            recovery.UpdateRtt(now - newest.SentAt, ackDelay);

        foreach (SentPacket packet in acknowledged)
        {
            if (!space.Sent.Remove(packet.Number))
                continue;

            recovery.OnPacketAcknowledged(packet);

            foreach (SentFrame frame in packet.Frames)
                handler.OnAcknowledged(space, frame);
        }

        recovery.ProbeCount = 0;
        DetectLostPackets(space, now);
    }

    public void OnPacketSent(PacketNumberSpace space, SentPacket packet)
    {
        space.Sent.Add(packet.Number, packet);
        space.LastAckElicitingSentAt = packet.SentAt;
        _lastAckElicitingSentAt = packet.SentAt;
        recovery.OnPacketSent(packet.Size);
    }

    public void OnTimeout(long now, bool handshakeComplete, bool handshakeConfirmed, long maximumAckDelay)
    {
        bool lossTimerFired = false;

        foreach (PacketNumberSpace space in spaces)
        {
            if (space.LossTime > now)
                continue;

            DetectLostPackets(space, now);
            lossTimerFired = true;
        }

        if (lossTimerFired)
            return;

        long deadline = GetProbeDeadline(handshakeComplete, handshakeConfirmed, maximumAckDelay, out PacketNumberSpace? probeSpace);

        if (deadline > now || probeSpace is null)
            return;

        recovery.ProbeCount++;

        // Probes carry the oldest unacknowledged data again; with nothing to resend they carry a PING.
        int requeued = 0;

        foreach (SentPacket packet in probeSpace.Sent.Values)
        {
            if (probeSpace.Level == EncryptionLevel.Application && requeued >= RequeuedApplicationPackets)
                break;

            foreach (SentFrame frame in packet.Frames)
                handler.OnLost(probeSpace, frame);

            requeued++;
        }

        probeSpace.ProbesPending = ProbePacketCount;
    }

    private static bool Contains(IReadOnlyList<LongRange> ranges, long number)
    {
        foreach (LongRange range in ranges)
        {
            if (number >= range.Start && number < range.End)
                return true;
        }

        return false;
    }

    private void DetectLostPackets(PacketNumberSpace space, long now)
    {
        space.LossTime = long.MaxValue;

        if (space.LargestAcknowledged < 0)
            return;

        long lossDelay = recovery.LossDelay;
        List<SentPacket> lost = [];

        foreach (SentPacket packet in space.Sent.Values)
        {
            if (packet.Number > space.LargestAcknowledged)
                break;

            bool lostByTime = packet.SentAt <= now - lossDelay;
            bool lostByOrder = space.LargestAcknowledged >= packet.Number + PacketThreshold;

            if (lostByTime || lostByOrder)
                lost.Add(packet);
            else
                space.LossTime = Math.Min(space.LossTime, packet.SentAt + lossDelay);
        }

        if (lost.Count == 0)
            return;

        long lostBytes = 0;
        long latestSentAt = 0;

        foreach (SentPacket packet in lost)
        {
            if (!space.Sent.Remove(packet.Number))
                continue;

            lostBytes += packet.Size;
            latestSentAt = Math.Max(latestSentAt, packet.SentAt);

            foreach (SentFrame frame in packet.Frames)
                handler.OnLost(space, frame);
        }

        recovery.OnPacketsLost(lostBytes, latestSentAt, now);
    }

    private long GetProbeDeadline(bool handshakeComplete, bool handshakeConfirmed, long maximumAckDelay, out PacketNumberSpace? probeSpace)
    {
        probeSpace = null;

        long duration = recovery.GetProbeTimeout(maximumAckDelay: 0);
        bool anyInFlight = spaces.Any(space => !space.IsDiscarded && space.Sent.Count > 0);

        // Before the handshake completes the client keeps probing even with nothing in flight, so a server held back by
        // its anti-amplification limit can continue (RFC 9002 section 6.2.2.1).
        if (!anyInFlight)
        {
            if (handshakeComplete)
                return long.MaxValue;

            PacketNumberSpace handshake = spaces[(int)EncryptionLevel.Handshake];

            probeSpace = handshake.CanSend ? handshake : spaces[(int)EncryptionLevel.Initial];

            return _lastAckElicitingSentAt + duration;
        }

        long deadline = long.MaxValue;

        foreach (PacketNumberSpace space in spaces)
        {
            if (space.IsDiscarded || space.Sent.Count == 0)
                continue;

            bool application = space.Level == EncryptionLevel.Application;

            // Application data is probed only once the handshake is confirmed, unless nothing else is in flight.
            if (application && !handshakeConfirmed && probeSpace is not null)
                continue;

            long candidate = space.LastAckElicitingSentAt + (application ? recovery.GetProbeTimeout(maximumAckDelay) : duration);

            if (candidate < deadline)
            {
                deadline = candidate;
                probeSpace = space;
            }
        }

        return deadline;
    }
}
