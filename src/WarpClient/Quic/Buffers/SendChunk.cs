namespace Warp.Quic.Buffers;

internal sealed record SendChunk(long Offset, byte[] Data, bool Fin, bool IsNewData);
