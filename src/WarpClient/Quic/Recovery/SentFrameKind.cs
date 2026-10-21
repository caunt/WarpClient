namespace Warp.Quic.Recovery;

/// <summary>
/// Frames whose loss must be repaired. Acknowledgments, pings, padding and datagrams are never retransmitted.
/// </summary>
internal enum SentFrameKind
{
    None = 0,
    Crypto,
    Stream,
    MaximumData,
    MaximumStreamData,
    MaximumStreamsBidirectional,
    MaximumStreamsUnidirectional,
    StopSending,
    ResetStream,
    RetireConnectionId,
}
