using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;

namespace Warp.Quic.Crypto;

/// <summary>
/// The device's P-256 key with a short-lived self-signed certificate, built and used entirely in managed code. The server only
/// checks that the certificate carries the key enrolled for the device.
/// </summary>
internal sealed class ClientCredential
{
    private const string SignatureAlgorithm = "SHA-256withECDSA";

    private readonly ECPrivateKeyParameters _privateKey;

    private ClientCredential(ECPrivateKeyParameters privateKey, byte[] certificate)
    {
        _privateKey = privateKey;
        Certificate = certificate;
    }

    public byte[] Certificate { get; }

    public static ClientCredential FromPkcs8(byte[] privateKey)
    {
        if (PrivateKeyFactory.CreateKey(privateKey) is not ECPrivateKeyParameters key || key.PublicKeyParamSet is null)
            throw new InvalidDataException(message: "The device key is not a named-curve elliptic curve key.");

        ECPublicKeyParameters publicKey = new(algorithm: "EC", key.Parameters.G.Multiply(key.D).Normalize(), key.PublicKeyParamSet);
        X509Name name = new(dirName: "CN=WarpClient");
        X509V3CertificateGenerator generator = new();
        DateTime now = DateTime.UtcNow;

        generator.SetSerialNumber(new BigInteger(sizeInBits: 64, new SecureRandom()));
        generator.SetIssuerDN(name);
        generator.SetSubjectDN(name);
        generator.SetNotBefore(now.AddHours(value: -1));
        generator.SetNotAfter(now.AddDays(value: 1));
        generator.SetPublicKey(publicKey);

        X509Certificate certificate = generator.Generate(new Asn1SignatureFactory(algorithm: "SHA256WITHECDSA", key));

        return new ClientCredential(key, certificate.GetEncoded());
    }

    public static bool Verify(AsymmetricKeyParameter publicKey, ReadOnlySpan<byte> content, byte[] signature)
    {
        ISigner verifier = SignerUtilities.GetSigner(SignatureAlgorithm);

        verifier.Init(forSigning: false, publicKey);
        verifier.BlockUpdate(content);

        return verifier.VerifySignature(signature);
    }

    public byte[] Sign(ReadOnlySpan<byte> content)
    {
        ISigner signer = SignerUtilities.GetSigner(SignatureAlgorithm);

        signer.Init(forSigning: true, _privateKey);
        signer.BlockUpdate(content);

        return signer.GenerateSignature();
    }
}
