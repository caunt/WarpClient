using System.Security.Cryptography;

namespace Warp.Quic.Crypto;

/// <summary>
/// Reads a public key given as PEM or bare base64 into its DER SubjectPublicKeyInfo, without any native crypto.
/// </summary>
internal static class PublicKeyEncoding
{
    public static byte[] ReadSubjectPublicKeyInformation(string publicKey)
    {
        return !PemEncoding.TryFind(publicKey, out PemFields fields)
            ? Convert.FromBase64String(publicKey)
            : Convert.FromBase64String(publicKey[fields.Base64Data]);
    }
}
