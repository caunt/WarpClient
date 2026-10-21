using System.Buffers.Binary;
using System.Security.Cryptography;

namespace Warp.Cloudflare.WireGuard;

/// <summary>
/// The initiator's half of the WireGuard handshake (whitepaper section 5.4), which is Noise IKpsk2 with WireGuard's
/// identifier as prologue and an all-zero pre-shared key.
/// </summary>
internal static class WireGuardHandshake
{
    public const int InitiationLength = 148;
    public const byte InitiationType = 1;
    public const int ResponseLength = 92;
    public const byte ResponseType = 2;
    private const int InitiationMacOffset = 116;
    private const int ResponseMacOffset = 60;
    private static readonly byte[] Construction = "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s"u8.ToArray();
    private static readonly byte[] Identifier = "WireGuard v1 zx2c4 Jason@zx2c4.com"u8.ToArray();
    private static readonly byte[] MacLabel = "mac1----"u8.ToArray();
    private static readonly byte[] PresharedKey = new byte[WireGuardCrypto.KeyLength];

    public static HandshakeInitiation CreateInitiation(WireGuardIdentity identity, uint senderIndex, DateTimeOffset now)
    {
        byte[] chainingKey = WireGuardCrypto.Hash(Construction, []);
        byte[] hash = WireGuardCrypto.Hash(WireGuardCrypto.Hash(chainingKey, Identifier), identity.PeerPublicKey);
        byte[] ephemeralPrivateKey = WireGuardCrypto.GeneratePrivateKey();
        byte[] ephemeralPublicKey = WireGuardCrypto.GetPublicKey(ephemeralPrivateKey);

        chainingKey = WireGuardCrypto.Derive(chainingKey, ephemeralPublicKey).First;
        hash = WireGuardCrypto.Hash(hash, ephemeralPublicKey);

        DerivedKeys ephemeralStatic = WireGuardCrypto.Derive(chainingKey, WireGuardCrypto.Agree(ephemeralPrivateKey, identity.PeerPublicKey));
        byte[] encryptedStatic = WireGuardCrypto.Seal(ephemeralStatic.Second, counter: 0, identity.PublicKey, hash);

        chainingKey = ephemeralStatic.First;
        hash = WireGuardCrypto.Hash(hash, encryptedStatic);

        DerivedKeys staticStatic = WireGuardCrypto.Derive(chainingKey, WireGuardCrypto.Agree(identity.PrivateKey, identity.PeerPublicKey));
        byte[] encryptedTimestamp = WireGuardCrypto.Seal(staticStatic.Second, counter: 0, WireGuardCrypto.CreateTimestamp(now), hash);

        chainingKey = staticStatic.First;
        hash = WireGuardCrypto.Hash(hash, encryptedTimestamp);

        byte[] message = new byte[InitiationLength];

        message[0] = InitiationType;
        BinaryPrimitives.WriteUInt32LittleEndian(message.AsSpan(start: 4), senderIndex);
        ephemeralPublicKey.CopyTo(message, index: 8);
        encryptedStatic.CopyTo(message, index: 40);
        encryptedTimestamp.CopyTo(message, index: 88);
        WireGuardCrypto.Mac(WireGuardCrypto.Hash(MacLabel, identity.PeerPublicKey), message.AsSpan(start: 0, InitiationMacOffset)).CopyTo(message, InitiationMacOffset);

        return new HandshakeInitiation(message, new HandshakeState(chainingKey, hash, ephemeralPrivateKey, senderIndex));
    }

    /// <summary>
    /// Validates a handshake response and derives the transport keys, or returns <see langword="null"/> when the response
    /// does not answer this initiation or fails authentication.
    /// </summary>
    public static TransportKeys? TryConsumeResponse(WireGuardIdentity identity, HandshakeState state, ReadOnlySpan<byte> message)
    {
        bool shaped = message.Length == ResponseLength && message[index: 0] == ResponseType;

        if (!shaped || BinaryPrimitives.ReadUInt32LittleEndian(message[8..]) != state.SenderIndex)
            return null;

        byte[] expectedMac = WireGuardCrypto.Mac(WireGuardCrypto.Hash(MacLabel, identity.PublicKey), message[..ResponseMacOffset]);

        if (!CryptographicOperations.FixedTimeEquals(expectedMac, message.Slice(ResponseMacOffset, WireGuardCrypto.MacLength)))
            return null;

        uint responderIndex = BinaryPrimitives.ReadUInt32LittleEndian(message[4..]);
        ReadOnlySpan<byte> ephemeralPublicKey = message.Slice(start: 12, WireGuardCrypto.KeyLength);
        byte[] chainingKey = WireGuardCrypto.Derive(state.ChainingKey, ephemeralPublicKey).First;
        byte[] hash = WireGuardCrypto.Hash(state.Hash, ephemeralPublicKey);

        chainingKey = WireGuardCrypto.Derive(chainingKey, WireGuardCrypto.Agree(state.EphemeralPrivateKey, ephemeralPublicKey)).First;
        chainingKey = WireGuardCrypto.Derive(chainingKey, WireGuardCrypto.Agree(identity.PrivateKey, ephemeralPublicKey)).First;

        DerivedKeys presharedKeys = WireGuardCrypto.Derive(chainingKey, PresharedKey);

        hash = WireGuardCrypto.Hash(hash, presharedKeys.Second);

        byte[]? nothing = WireGuardCrypto.Open(presharedKeys.Third, counter: 0, message.Slice(start: 44, WireGuardCrypto.TagLength), hash);

        if (nothing is not { Length: 0 })
            return null;

        DerivedKeys transport = WireGuardCrypto.Derive(presharedKeys.First, []);

        return new TransportKeys(transport.First, transport.Second, state.SenderIndex, responderIndex);
    }
}
