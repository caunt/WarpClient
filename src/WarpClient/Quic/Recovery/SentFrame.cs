namespace Warp.Quic.Recovery;

internal readonly record struct SentFrame(SentFrameKind Kind, long StreamId, long Offset, int Length, bool Fin);
