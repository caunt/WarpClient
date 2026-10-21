using System.Buffers.Binary;
using System.Security.Cryptography;

using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace Warp.Cloudflare.WireGuard;

/// <summary>
/// The primitives of WireGuard's Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s construction: BLAKE2s hashing, HMAC-based key
/// derivation, keyed BLAKE2s message authentication, ChaCha20-Poly1305 and X25519.
/// </summary>
internal static class WireGuardCrypto
{
    public const int KeyLength = 32;
    public const int MacLength = 16;
    public const int TagLength = 16;
    private const int HashBits = 256;
    private const int NonceLength = 12;
    // TAI64 labels start at 2^62, and TAI runs ten seconds ahead of the Unix epoch's UTC.
    private const ulong Tai64Base = 0x4000_0000_0000_000A;

    public static byte[] Agree(byte[] privateKey, ReadOnlySpan<byte> publicKey)
    {
        byte[] secret = new byte[KeyLength];

        new X25519PrivateKeyParameters(privateKey).GenerateSecret(new X25519PublicKeyParameters(publicKey.ToArray()), secret, off: 0);

        return secret;
    }

    public static byte[] CreateTimestamp(DateTimeOffset now)
    {
        byte[] timestamp = new byte[12];

        BinaryPrimitives.WriteUInt64BigEndian(timestamp, Tai64Base + (ulong)now.ToUnixTimeSeconds());
        BinaryPrimitives.WriteUInt32BigEndian(timestamp.AsSpan(start: 8), (uint)(now.Ticks % TimeSpan.TicksPerSecond * 100));

        return timestamp;
    }

    public static DerivedKeys Derive(ReadOnlySpan<byte> chainingKey, ReadOnlySpan<byte> input)
    {
        byte[] secret = Hmac(chainingKey, input);
        byte[] first = Hmac(secret, [0x1]);
        byte[] second = Hmac(secret, [.. first, 0x2]);
        byte[] third = Hmac(secret, [.. second, 0x3]);

        return new DerivedKeys(first, second, third);
    }

    public static byte[] GeneratePrivateKey()
    {
        return new X25519PrivateKeyParameters(new SecureRandom()).GetEncoded();
    }

    public static byte[] GetPublicKey(byte[] privateKey)
    {
        return new X25519PrivateKeyParameters(privateKey).GeneratePublicKey().GetEncoded();
    }

    public static byte[] Hash(ReadOnlySpan<byte> first, ReadOnlySpan<byte> second)
    {
        Blake2sDigest digest = new(HashBits);

        digest.BlockUpdate(first);
        digest.BlockUpdate(second);

        return Finish(digest, KeyLength);
    }

    public static byte[] Mac(ReadOnlySpan<byte> key, ReadOnlySpan<byte> input)
    {
        Blake2sDigest digest = new(key.ToArray(), MacLength, salt: null, personalization: null);

        digest.BlockUpdate(input);

        return Finish(digest, MacLength);
    }

    public static byte[]? Open(ReadOnlySpan<byte> key, ulong counter, ReadOnlySpan<byte> sealedData, ReadOnlySpan<byte> associatedData)
    {
        using ChaCha20Poly1305 cipher = new(key);

        return Open(cipher, counter, sealedData, associatedData);
    }

    public static byte[]? Open(ChaCha20Poly1305 cipher, ulong counter, ReadOnlySpan<byte> sealedData, ReadOnlySpan<byte> associatedData)
    {
        if (sealedData.Length < TagLength)
            return null;

        Span<byte> nonce = stackalloc byte[NonceLength];
        byte[] plaintext = new byte[sealedData.Length - TagLength];

        BinaryPrimitives.WriteUInt64LittleEndian(nonce[4..], counter);

        try
        {
            cipher.Decrypt(nonce, sealedData[..plaintext.Length], sealedData[plaintext.Length..], plaintext, associatedData);

            return plaintext;
        }
        catch (AuthenticationTagMismatchException)
        {
            return null;
        }
    }

    public static byte[] Seal(ReadOnlySpan<byte> key, ulong counter, ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> associatedData)
    {
        using ChaCha20Poly1305 cipher = new(key);

        return Seal(cipher, counter, plaintext, associatedData);
    }

    public static byte[] Seal(ChaCha20Poly1305 cipher, ulong counter, ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> associatedData)
    {
        Span<byte> nonce = stackalloc byte[NonceLength];
        byte[] output = new byte[plaintext.Length + TagLength];

        BinaryPrimitives.WriteUInt64LittleEndian(nonce[4..], counter);
        cipher.Encrypt(nonce, plaintext, output.AsSpan(start: 0, plaintext.Length), output.AsSpan(plaintext.Length), associatedData);

        return output;
    }

    private static byte[] Finish(Blake2sDigest digest, int length)
    {
        byte[] output = new byte[length];
        int written = digest.DoFinal(output.AsSpan());

        return written == length ? output : throw new CryptographicException(message: "BLAKE2s produced an unexpected length.");
    }

    private static byte[] Hmac(ReadOnlySpan<byte> key, ReadOnlySpan<byte> input)
    {
        HMac mac = new(new Blake2sDigest(HashBits));

        mac.Init(new KeyParameter(key.ToArray()));
        mac.BlockUpdate(input);

        byte[] output = new byte[KeyLength];
        int written = mac.DoFinal(output.AsSpan());

        return written == KeyLength ? output : throw new CryptographicException(message: "HMAC-BLAKE2s produced an unexpected length.");
    }
}
