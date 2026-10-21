using System.Security.Cryptography;
using System.Text;

using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Parameters;

namespace Warp.Quic.Crypto;

/// <summary>
/// SHA-256, HMAC, HKDF (RFC 5869) and TLS 1.3's HKDF-Expand-Label (RFC 8446 section 7.1), which derive every QUIC and TLS key.
/// </summary>
internal static class KeyDerivation
{
    public const int HashLength = 32;

    public static byte[] ExpandLabel(ReadOnlySpan<byte> secret, string label, ReadOnlySpan<byte> context, int length)
    {
        byte[] fullLabel = Encoding.ASCII.GetBytes("tls13 " + label);
        byte[] information = [(byte)(length >> 8), (byte)length, (byte)fullLabel.Length, .. fullLabel, (byte)context.Length, .. context];
        byte[] output = new byte[length];
        byte[] block = [];
        int offset = 0;
        byte counter = 1;

        while (offset < length)
        {
            block = Hmac(secret, [.. block, .. information, counter]);

            int chunk = Math.Min(block.Length, length - offset);

            block.AsSpan(start: 0, chunk).CopyTo(output.AsSpan(offset));
            offset += chunk;
            counter++;
        }

        return output;
    }

    public static byte[] Extract(ReadOnlySpan<byte> salt, ReadOnlySpan<byte> inputKeyMaterial)
    {
        return Hmac(salt.IsEmpty ? new byte[HashLength] : salt, inputKeyMaterial);
    }

    public static byte[] Hash(ReadOnlySpan<byte> data)
    {
        Sha256Digest digest = new();
        byte[] output = new byte[HashLength];

        digest.BlockUpdate(data);

        int written = digest.DoFinal(output.AsSpan());

        return written == HashLength ? output : throw new CryptographicException(message: "SHA-256 produced an unexpected length.");
    }

    public static byte[] Hmac(ReadOnlySpan<byte> key, ReadOnlySpan<byte> data)
    {
        HMac mac = new(new Sha256Digest());
        byte[] output = new byte[HashLength];

        mac.Init(new KeyParameter(key.ToArray()));
        mac.BlockUpdate(data);

        int written = mac.DoFinal(output.AsSpan());

        return written == HashLength ? output : throw new CryptographicException(message: "HMAC-SHA-256 produced an unexpected length.");
    }
}
