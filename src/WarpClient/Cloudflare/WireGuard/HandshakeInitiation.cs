namespace Warp.Cloudflare.WireGuard;

internal sealed record HandshakeInitiation(byte[] Message, HandshakeState State);
