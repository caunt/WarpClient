using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Agreement;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;

namespace Warp.Quic.Crypto;

/// <summary>
/// An ephemeral P-256 Diffie-Hellman key share for one TLS 1.3 handshake (RFC 8446 section 4.2.8.2).
/// </summary>
internal sealed class KeyExchange
{
    private const int CoordinateLength = 32;
    private const byte UncompressedPoint = 0x04;
    private static readonly ECNamedDomainParameters Domain = ECNamedDomainParameters.LookupOid(SecObjectIdentifiers.SecP256r1);

    private readonly ECPrivateKeyParameters _privateKey;

    public KeyExchange()
    {
        ECKeyPairGenerator generator = new();

        generator.Init(new ECKeyGenerationParameters(Domain, new SecureRandom()));

        AsymmetricCipherKeyPair pair = generator.GenerateKeyPair();

        if (pair.Private is not ECPrivateKeyParameters privateKey || pair.Public is not ECPublicKeyParameters publicKey)
            throw new InvalidOperationException(message: "The key generator produced a key of an unexpected type.");

        _privateKey = privateKey;
        PublicKey = publicKey.Q.GetEncoded(compressed: false);
    }

    public byte[] PublicKey { get; }

    public byte[] Agree(ReadOnlySpan<byte> peerKey)
    {
        bool wellFormed = peerKey.Length == 1 + (2 * CoordinateLength) && peerKey[index: 0] == UncompressedPoint;

        if (!wellFormed)
            throw new InvalidDataException(message: "The server's key share is not an uncompressed P-256 point.");

        ECPoint point = Domain.Curve.DecodePoint(peerKey.ToArray());

        // The parameters' constructor rejects points off the curve and the point at infinity.
        ECPublicKeyParameters peer = new(point, Domain);
        ECDHBasicAgreement agreement = new();

        agreement.Init(_privateKey);

        BigInteger secret = agreement.CalculateAgreement(peer);

        return BigIntegers.AsUnsignedByteArray(CoordinateLength, secret);
    }
}
