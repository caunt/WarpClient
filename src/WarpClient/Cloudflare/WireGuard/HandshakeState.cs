namespace Warp.Cloudflare.WireGuard;

/// <summary>
/// What the initiator must remember between sending an initiation and processing the response.
/// </summary>
internal sealed record HandshakeState(byte[] ChainingKey, byte[] Hash, byte[] EphemeralPrivateKey, uint SenderIndex);
