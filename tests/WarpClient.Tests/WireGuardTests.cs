using Warp.Cloudflare.WireGuard;

namespace Warp.Tests;

/// <summary>
/// Covers the WireGuard building blocks that do not need a responder: the hash, replay protection and initiation layout.
/// The full handshake was verified against the independent noiseprotocol implementation over loopback UDP.
/// </summary>
public sealed class WireGuardTests
{
    /// <summary>
    /// BLAKE2s-256 must match the RFC 7693 appendix B test vector, since every WireGuard key derivation builds on it.
    /// </summary>
    [Fact]
    public void HashMatchesRfc7693Vector()
    {
        byte[] digest = WireGuardCrypto.Hash(first: "abc"u8, []);

        Assert.Equal(expected: "508C5E8C327C14E2E1A72BA34EEB452F37458B209ED63A294D999B4C86675982", Convert.ToHexString(digest));
    }

    /// <summary>
    /// An initiation must have WireGuard's fixed layout and a mac1 keyed by the responder's public key, computed while the
    /// reserved bytes are still zero.
    /// </summary>
    [Fact]
    public void InitiationCarriesMacOverZeroReservedBytes()
    {
        byte[] devicePrivateKey = WireGuardCrypto.GeneratePrivateKey();
        byte[] peerPublicKey = WireGuardCrypto.GetPublicKey(WireGuardCrypto.GeneratePrivateKey());
        WireGuardIdentity identity = new(devicePrivateKey, WireGuardCrypto.GetPublicKey(devicePrivateKey), peerPublicKey);

        HandshakeInitiation initiation = WireGuardHandshake.CreateInitiation(identity, senderIndex: 0x01020304, DateTimeOffset.UtcNow);
        byte[] message = initiation.Message;
        byte[] macKey = WireGuardCrypto.Hash(first: "mac1----"u8, peerPublicKey);

        Assert.Equal(WireGuardHandshake.InitiationLength, message.Length);
        Assert.Equal(WireGuardHandshake.InitiationType, message[0]);
        Assert.Equal([0, 0, 0], message[1..4]);
        Assert.Equal(WireGuardCrypto.Mac(macKey, message.AsSpan(start: 0, length: 116)), message[116..132]);
        Assert.Equal(expected: 0x01020304U, initiation.State.SenderIndex);
    }

    /// <summary>
    /// Counters may arrive out of order within the window, but duplicates and counters older than the window are replays.
    /// </summary>
    [Fact]
    public void ReplayWindowRejectsDuplicatesAndStaleCounters()
    {
        ReplayWindow window = new();

        Assert.True(window.TryAccept(counter: 0));
        Assert.True(window.TryAccept(counter: 5));
        Assert.True(window.TryAccept(counter: 3));
        Assert.False(window.TryAccept(counter: 3));
        Assert.True(window.TryAccept(counter: 100));
        Assert.False(window.TryAccept(counter: 5));
        Assert.True(window.TryAccept(counter: 99));
    }
}
