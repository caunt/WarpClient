namespace Warp.Cloudflare.WireGuard;

/// <summary>
/// The device's static X25519 key pair and Cloudflare's static public key, which the handshake authenticates.
/// </summary>
internal sealed record WireGuardIdentity(byte[] PrivateKey, byte[] PublicKey, byte[] PeerPublicKey);
