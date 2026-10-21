namespace Warp.Quic;

internal sealed record CloseRequest(ulong Code, bool Application, string Reason);
