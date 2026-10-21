namespace Warp.Quic.Recovery;

/// <summary>
/// An ack-eliciting packet waiting for acknowledgment, with the frames to repair if it is declared lost.
/// </summary>
internal sealed record SentPacket(long Number, long SentAt, int Size, IReadOnlyList<SentFrame> Frames);
