using System.Security.Cryptography;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;

using ManagedChaCha20Poly1305 = Org.BouncyCastle.Crypto.Modes.ChaCha20Poly1305;

namespace Warp.Cloudflare.WireGuard;

/// <summary>
/// ChaCha20-Poly1305 from the platform's crypto library when it offers one, otherwise BouncyCastle's managed implementation,
/// so WireGuard runs on every .NET platform.
/// </summary>
internal sealed class ChaChaPolyCipher : IDisposable
{
    private const int TagBits = 128;

    private readonly byte[] _key;
    private readonly ChaCha20Poly1305? _platform;

    public ChaChaPolyCipher(ReadOnlySpan<byte> key, bool preferPlatform = true)
    {
        _key = key.ToArray();
        _platform = preferPlatform && ChaCha20Poly1305.IsSupported ? new ChaCha20Poly1305(key) : null;
    }

    public bool IsManaged => _platform is null;

    public void Dispose()
    {
        _platform?.Dispose();
    }

    public void Encrypt(ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> plaintext, Span<byte> ciphertext, Span<byte> tag, ReadOnlySpan<byte> associatedData)
    {
        if (_platform is not null)
        {
            _platform.Encrypt(nonce, plaintext, ciphertext, tag, associatedData);

            return;
        }

        ManagedChaCha20Poly1305 cipher = CreateManaged(forEncryption: true, nonce, associatedData);
        byte[] output = new byte[plaintext.Length + tag.Length];
        int written = cipher.ProcessBytes(plaintext.ToArray(), inOff: 0, plaintext.Length, output, outOff: 0);

        written += cipher.DoFinal(output, written);

        if (written != output.Length)
            throw new CryptographicException(message: "ChaCha20-Poly1305 produced an unexpected length.");

        output.AsSpan(start: 0, plaintext.Length).CopyTo(ciphertext);
        output.AsSpan(plaintext.Length).CopyTo(tag);
    }

    public bool TryDecrypt(
        ReadOnlySpan<byte> nonce,
        ReadOnlySpan<byte> ciphertext,
        ReadOnlySpan<byte> tag,
        Span<byte> plaintext,
        ReadOnlySpan<byte> associatedData
    )
    {
        if (_platform is not null)
            return TryDecryptPlatform(_platform, nonce, ciphertext, tag, plaintext, associatedData);

        ManagedChaCha20Poly1305 cipher = CreateManaged(forEncryption: false, nonce, associatedData);
        byte[] input = [.. ciphertext, .. tag];
        byte[] output = new byte[ciphertext.Length];

        try
        {
            int written = cipher.ProcessBytes(input, inOff: 0, input.Length, output, outOff: 0);

            written += cipher.DoFinal(output, written);
            output.CopyTo(plaintext);

            return written == ciphertext.Length;
        }
        catch (InvalidCipherTextException)
        {
            return false;
        }
    }

    private static bool TryDecryptPlatform(
        ChaCha20Poly1305 platform,
        ReadOnlySpan<byte> nonce,
        ReadOnlySpan<byte> ciphertext,
        ReadOnlySpan<byte> tag,
        Span<byte> plaintext,
        ReadOnlySpan<byte> associatedData
    )
    {
        try
        {
            platform.Decrypt(nonce, ciphertext, tag, plaintext, associatedData);

            return true;
        }
        catch (AuthenticationTagMismatchException)
        {
            return false;
        }
    }

    private ManagedChaCha20Poly1305 CreateManaged(bool forEncryption, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> associatedData)
    {
        ManagedChaCha20Poly1305 cipher = new();

        cipher.Init(forEncryption, new AeadParameters(new KeyParameter(_key), TagBits, nonce.ToArray(), associatedData.ToArray()));

        return cipher;
    }
}
