using System.Security.Cryptography;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;

namespace Warp.Quic.Crypto;

/// <summary>
/// One direction's QUIC packet protection (RFC 9001 section 5): AES-128-GCM for the payload and AES-based header protection
/// for the first byte and packet number.
/// </summary>
internal sealed class PacketKeys
{
    public const int SampleLength = 16;
    public const int TagLength = 16;
    private const int KeyLength = 16;
    private const int NonceLength = 12;
    private static readonly byte[] InitialSalt = Convert.FromHexString(s: "38762CF7F55934B34D179AE6A4C80CADCCBB7F0A");

    private readonly IBlockCipher _headerCipher;
    private readonly byte[] _headerKey;
    private readonly byte[] _initializationVector;
    private readonly byte[] _key;

    private PacketKeys(byte[] secret, byte[] headerKey)
    {
        Secret = secret;
        _key = KeyDerivation.ExpandLabel(secret, label: "quic key", [], KeyLength);
        _initializationVector = KeyDerivation.ExpandLabel(secret, label: "quic iv", [], NonceLength);
        _headerKey = headerKey;
        _headerCipher = AesUtilities.CreateEngine();
        _headerCipher.Init(forEncryption: true, new KeyParameter(headerKey));
    }

    public byte[] Secret { get; }

    // Initial packets are protected with keys anyone can derive from the client's first destination connection ID.
    public static PacketKeys CreateInitial(ReadOnlySpan<byte> destinationConnectionId, string label)
    {
        byte[] initialSecret = KeyDerivation.Extract(InitialSalt, destinationConnectionId);

        return FromSecret(KeyDerivation.ExpandLabel(initialSecret, label, [], KeyDerivation.HashLength));
    }

    public static PacketKeys FromSecret(byte[] secret)
    {
        return new PacketKeys(secret, KeyDerivation.ExpandLabel(secret, label: "quic hp", [], KeyLength));
    }

    public byte[] CreateMask(ReadOnlySpan<byte> sample)
    {
        byte[] mask = new byte[SampleLength];
        int processed = _headerCipher.ProcessBlock(sample[..SampleLength].ToArray(), inOff: 0, mask, outOff: 0);

        return processed == SampleLength ? mask : throw new CryptographicException(message: "Header protection produced an unexpected length.");
    }

    // A key update (RFC 9001 section 6) replaces the packet protection keys but keeps the header protection key.
    public PacketKeys CreateNextGeneration()
    {
        return new PacketKeys(KeyDerivation.ExpandLabel(Secret, label: "quic ku", [], KeyDerivation.HashLength), _headerKey);
    }

    public byte[]? Open(long packetNumber, ReadOnlySpan<byte> header, ReadOnlySpan<byte> ciphertext)
    {
        if (ciphertext.Length < TagLength)
            return null;

        GcmBlockCipher cipher = CreateCipher(forEncryption: false, packetNumber, header);
        byte[] output = new byte[ciphertext.Length - TagLength];

        try
        {
            int written = cipher.ProcessBytes(ciphertext.ToArray(), inOff: 0, ciphertext.Length, output, outOff: 0);

            written += cipher.DoFinal(output, written);

            return written == output.Length ? output : null;
        }
        catch (InvalidCipherTextException)
        {
            return null;
        }
    }

    public byte[] Seal(long packetNumber, ReadOnlySpan<byte> header, ReadOnlySpan<byte> plaintext)
    {
        GcmBlockCipher cipher = CreateCipher(forEncryption: true, packetNumber, header);
        byte[] output = new byte[plaintext.Length + TagLength];
        int written = cipher.ProcessBytes(plaintext.ToArray(), inOff: 0, plaintext.Length, output, outOff: 0);

        written += cipher.DoFinal(output, written);

        return written == output.Length ? output : throw new CryptographicException(message: "AES-GCM produced an unexpected length.");
    }

    private GcmBlockCipher CreateCipher(bool forEncryption, long packetNumber, ReadOnlySpan<byte> header)
    {
        byte[] nonce = [.. _initializationVector];

        for (int index = 0; index < sizeof(long); index++)
            nonce[NonceLength - 1 - index] ^= (byte)(packetNumber >> (8 * index));

        GcmBlockCipher cipher = new(AesUtilities.CreateEngine());

        cipher.Init(forEncryption, new AeadParameters(new KeyParameter(_key), TagLength * 8, nonce, header.ToArray()));

        return cipher;
    }
}
