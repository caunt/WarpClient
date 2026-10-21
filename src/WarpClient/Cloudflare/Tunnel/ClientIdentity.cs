using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Warp.Cloudflare.Tunnel;

/// <summary>
/// The enrolled P-256 key wrapped in a short-lived self-signed certificate, which is how the device proves itself in the
/// tunnel's TLS handshake. Cloudflare only checks that the certificate's key is the one enrolled for the device.
/// </summary>
internal sealed class ClientIdentity : IDisposable
{
    private readonly ECDsa _key;

    public ClientIdentity(string privateKey)
    {
        byte[] encodedKey = Convert.FromBase64String(privateKey);

        _key = ECDsa.Create();
        _key.ImportPkcs8PrivateKey(encodedKey, out int bytesRead);

        if (bytesRead != encodedKey.Length)
            throw new InvalidDataException(message: "The stored device key has trailing data.");

        CertificateRequest request = new(new X500DistinguishedName(string.Empty), _key, HashAlgorithmName.SHA256);
        DateTimeOffset now = DateTimeOffset.UtcNow;

        Certificate = request.CreateSelfSigned(now.AddHours(hours: -1), now.AddDays(days: 1));
    }

    public X509Certificate2 Certificate { get; }

    public void Dispose()
    {
        Certificate.Dispose();
        _key.Dispose();
    }
}
