using System.Security.Cryptography.X509Certificates;

namespace Warp.Tests;

/// <summary>
/// Records what a loopback TLS server saw of its client, so a test can check the client authenticated with its own key.
/// </summary>
internal sealed class ServerProbe
{
    public byte[]? ClientPublicKey { get; private set; }

    public Exception? ServerError { get; set; }

    // The test client presents a self-signed certificate, so the probe only requires one and records its key.
    public bool RecordClientCertificate(X509Certificate? certificate)
    {
        if (certificate is null)
            return false;

        using X509Certificate2 presented = X509CertificateLoader.LoadCertificate(certificate.GetRawCertData());

        ClientPublicKey = presented.PublicKey.ExportSubjectPublicKeyInfo();

        return true;
    }
}
