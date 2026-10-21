namespace Warp.Quic.Buffers;

/// <summary>
/// A half-open interval [Start, End) of packet numbers or stream offsets.
/// </summary>
internal readonly record struct LongRange(long Start, long End);
