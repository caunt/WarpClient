using System.Net;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Text;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;

using Warp.Quic.Crypto;

namespace Warp.Quic.Tls;

/// <summary>
/// The client side of a TLS 1.3 handshake carried in QUIC CRYPTO frames (RFC 8446, RFC 9001), limited to one profile:
/// TLS_AES_128_GCM_SHA256, P-256 key exchange and ECDSA P-256 signatures. The server is trusted only by a pinned public key,
/// and the client authenticates with its own certificate when asked.
/// </summary>
/// <remarks>
/// Feed server handshake bytes in order per encryption level; partial messages are buffered until complete.
/// </remarks>
internal sealed class TlsClientHandshake(string serverName, string applicationProtocol, byte[] transportParameters, byte[] pinnedPublicKey, ClientCredential? credential)
{
    private const ushort ApplicationProtocolExtension = 16;
    private const byte CertificateRequestType = 13;
    private const byte CertificateType = 11;
    private const byte CertificateVerifyType = 15;
    private const ushort CipherSuite = 0x1301;
    private const byte ClientHelloType = 1;
    private const ushort EcdsaP256Sha256 = 0x0403;
    private const byte EncryptedExtensionsType = 8;
    private const byte FinishedType = 20;
    private const ushort KeyShareExtension = 51;
    private const ushort LegacyVersion = 0x0303;
    private const int MaximumMessageLength = 1 << 16;
    private const int MessageHeaderLength = 4;
    private const byte NewSessionTicketType = 4;
    private const ushort P256Group = 0x0017;
    private const int RandomLength = 32;
    private const byte ServerHelloType = 2;
    private const ushort ServerNameExtension = 0;
    private const ushort SignatureAlgorithmsExtension = 13;
    private const ushort SupportedGroupsExtension = 10;
    private const ushort SupportedVersionsExtension = 43;
    private const ushort TlsVersion = 0x0304;
    private const ushort TransportParametersExtension = 57;
    private static readonly byte[] ClientSignatureContext = CreateSignatureContext(label: "TLS 1.3, client CertificateVerify");
    private static readonly byte[] EmptyHash = KeyDerivation.Hash([]);
    private static readonly byte[] HelloRetryRandom = Convert.FromHexString(s: "CF21AD74E59A6111BE1D8C021E65B891C2A211167ABB8C5E079E09E2C8A8339C");
    private static readonly byte[] ServerSignatureContext = CreateSignatureContext(label: "TLS 1.3, server CertificateVerify");
    private static readonly byte[] ZeroSecret = new byte[KeyDerivation.HashLength];

    private readonly string _applicationProtocol = applicationProtocol;
    private readonly byte[][] _buffers = [[], [], []];
    private readonly ClientCredential? _credential = credential;
    private readonly KeyExchange _keyExchange = new();
    private readonly ECPublicKeyParameters _pinnedKey = PublicKeyFactory.CreateKey(pinnedPublicKey) as ECPublicKeyParameters
            ?? throw new ArgumentException(message: "The pinned server key must be an elliptic curve key.", nameof(pinnedPublicKey));
    private readonly string _serverName = serverName;
    private readonly QuicWriter _transcript = new();
    private readonly byte[] _transportParameters = transportParameters;
    private byte[] _certificateRequestContext = [];
    private bool _certificateRequested;
    private byte[] _clientHandshakeSecret = [];
    private byte[] _handshakeSecret = [];
    private byte[] _serverHandshakeSecret = [];
    private ECPublicKeyParameters? _serverKey;
    private byte[] _sharedSecret = [];
    private HandshakeStage _stage = HandshakeStage.WaitServerHello;

    public bool IsComplete => _stage == HandshakeStage.Connected;

    public byte[]? PeerTransportParameters { get; private set; }

    public byte[] CreateClientHello()
    {
        QuicWriter body = new();

        body.WriteUInt16(LegacyVersion);
        body.WriteBytes(RandomNumberGenerator.GetBytes(RandomLength));

        // QUIC forbids a legacy session ID and compression, so both are empty (RFC 9001 section 8.4).
        body.WriteVector8([]);
        body.WriteVector16([CipherSuite >> 8, CipherSuite & 0xFF]);
        body.WriteVector8([0]);

        int extensions = body.BeginVector(prefixLength: 2);

        // Server names are sent only as host names; an IP literal must not appear in SNI (RFC 6066 section 3).
        if (!IPAddress.TryParse(_serverName, out IPAddress? _))
        {
            byte[] hostName = Encoding.ASCII.GetBytes(_serverName);
            QuicWriter serverNames = new();

            serverNames.WriteByte(value: 0);
            serverNames.WriteVector16(hostName);
            WriteExtension(body, ServerNameExtension, Vector16(serverNames.WrittenSpan));
        }

        WriteExtension(body, SupportedGroupsExtension, [0, 2, P256Group >> 8, P256Group & 0xFF]);
        WriteExtension(body, SignatureAlgorithmsExtension, [0, 2, EcdsaP256Sha256 >> 8, EcdsaP256Sha256 & 0xFF]);
        WriteExtension(body, SupportedVersionsExtension, [2, TlsVersion >> 8, TlsVersion & 0xFF]);

        QuicWriter keyShare = new();

        keyShare.WriteUInt16(P256Group);
        keyShare.WriteVector16(_keyExchange.PublicKey);
        WriteExtension(body, KeyShareExtension, Vector16(keyShare.WrittenSpan));

        QuicWriter protocols = new();

        protocols.WriteVector8(Encoding.ASCII.GetBytes(_applicationProtocol));
        WriteExtension(body, ApplicationProtocolExtension, Vector16(protocols.WrittenSpan));
        WriteExtension(body, TransportParametersExtension, _transportParameters);
        body.EndVector(extensions, prefixLength: 2);

        byte[] message = CreateMessage(ClientHelloType, body.WrittenSpan);

        _transcript.WriteBytes(message);

        return message;
    }

    public TlsProgress Receive(EncryptionLevel level, ReadOnlySpan<byte> data)
    {
        TlsProgress progress = new();
        byte[] buffer = [.. _buffers[(int)level], .. data];
        int offset = 0;

        while (buffer.Length - offset >= MessageHeaderLength)
        {
            int length = (buffer[offset + 1] << 16) | (buffer[offset + 2] << 8) | buffer[offset + 3];

            if (length > MaximumMessageLength)
                throw new InvalidDataException(message: "The server sent an oversized TLS handshake message.");

            if (buffer.Length - offset - MessageHeaderLength < length)
                break;

            byte type = buffer[offset];
            ReadOnlyMemory<byte> message = buffer.AsMemory(offset, MessageHeaderLength + length);

            offset += MessageHeaderLength + length;
            Process(level, type, message, progress);
        }

        _buffers[(int)level] = buffer[offset..];

        return progress;
    }

    private static byte[] CreateMessage(byte type, ReadOnlySpan<byte> body)
    {
        QuicWriter writer = new();

        writer.WriteByte(type);
        writer.WriteVector24(body);

        return writer.ToArray();
    }

    private static byte[] CreateSignatureContext(string label)
    {
        // The signed content starts with 64 spaces so it can never be confused with another TLS version's signature input.
        return [.. Enumerable.Repeat((byte)0x20, count: 64), .. Encoding.ASCII.GetBytes(label), 0];
    }

    private static EncryptionLevel GetExpectedLevel(HandshakeStage stage)
    {
        return stage switch
        {
            HandshakeStage.WaitServerHello => EncryptionLevel.Initial,
            HandshakeStage.Connected => EncryptionLevel.Application,
            _ => EncryptionLevel.Handshake,
        };
    }

    private static byte[] Vector16(ReadOnlySpan<byte> content)
    {
        QuicWriter writer = new();

        writer.WriteVector16(content);

        return writer.ToArray();
    }

    private static void WriteExtension(QuicWriter writer, ushort type, ReadOnlySpan<byte> content)
    {
        writer.WriteUInt16(type);
        writer.WriteVector16(content);
    }

    private void Complete(TlsProgress progress)
    {
        byte[] serverFinishedHash = KeyDerivation.Hash(_transcript.WrittenSpan);
        byte[] derived = KeyDerivation.ExpandLabel(_handshakeSecret, label: "derived", EmptyHash, KeyDerivation.HashLength);
        byte[] masterSecret = KeyDerivation.Extract(derived, ZeroSecret);

        progress.ApplicationSecrets = new TrafficSecrets(
            KeyDerivation.ExpandLabel(masterSecret, label: "c ap traffic", serverFinishedHash, KeyDerivation.HashLength),
            KeyDerivation.ExpandLabel(masterSecret, label: "s ap traffic", serverFinishedHash, KeyDerivation.HashLength)
        );

        QuicWriter flight = new();

        if (_certificateRequested)
        {
            QuicWriter certificate = new();
            int list;

            certificate.WriteVector8(_certificateRequestContext);
            list = certificate.BeginVector(prefixLength: 3);

            if (_credential is not null)
            {
                certificate.WriteVector24(_credential.Certificate);
                certificate.WriteVector16([]);
            }

            certificate.EndVector(list, prefixLength: 3);
            WriteFlightMessage(flight, CertificateType, certificate.WrittenSpan);

            if (_credential is not null)
            {
                byte[] signature = _credential.Sign([.. ClientSignatureContext, .. KeyDerivation.Hash(_transcript.WrittenSpan)]);
                QuicWriter verify = new();

                verify.WriteUInt16(EcdsaP256Sha256);
                verify.WriteVector16(signature);
                WriteFlightMessage(flight, CertificateVerifyType, verify.WrittenSpan);
            }
        }

        byte[] finishedKey = KeyDerivation.ExpandLabel(_clientHandshakeSecret, label: "finished", [], KeyDerivation.HashLength);

        WriteFlightMessage(flight, FinishedType, KeyDerivation.Hmac(finishedKey, KeyDerivation.Hash(_transcript.WrittenSpan)));
        progress.HandshakeData = flight.ToArray();
        progress.Completed = true;
        _stage = HandshakeStage.Connected;
    }

    private void DeriveHandshakeSecrets(TlsProgress progress)
    {
        byte[] earlySecret = KeyDerivation.Extract(ZeroSecret, ZeroSecret);
        byte[] derived = KeyDerivation.ExpandLabel(earlySecret, label: "derived", EmptyHash, KeyDerivation.HashLength);
        byte[] helloHash = KeyDerivation.Hash(_transcript.WrittenSpan);

        _handshakeSecret = KeyDerivation.Extract(derived, _sharedSecret);
        _clientHandshakeSecret = KeyDerivation.ExpandLabel(_handshakeSecret, label: "c hs traffic", helloHash, KeyDerivation.HashLength);
        _serverHandshakeSecret = KeyDerivation.ExpandLabel(_handshakeSecret, label: "s hs traffic", helloHash, KeyDerivation.HashLength);
        progress.HandshakeSecrets = new TrafficSecrets(_clientHandshakeSecret, _serverHandshakeSecret);
    }

    private void Process(EncryptionLevel level, byte type, ReadOnlyMemory<byte> message, TlsProgress progress)
    {
        if (level != GetExpectedLevel(_stage))
            throw new InvalidDataException(message: "The server sent a TLS handshake message at the wrong encryption level.");

        QuicReader body = new(message[MessageHeaderLength..]);

        switch (_stage, type)
        {
            case (HandshakeStage.WaitServerHello, ServerHelloType):
                {
                    ProcessServerHello(body);
                    _transcript.WriteBytes(message.Span);
                    DeriveHandshakeSecrets(progress);
                    _stage = HandshakeStage.WaitEncryptedExtensions;

                    break;
                }
            case (HandshakeStage.WaitEncryptedExtensions, EncryptedExtensionsType):
                {
                    ProcessEncryptedExtensions(body);
                    _transcript.WriteBytes(message.Span);
                    _stage = HandshakeStage.WaitCertificateOrRequest;

                    break;
                }
            case (HandshakeStage.WaitCertificateOrRequest, CertificateRequestType):
                {
                    _certificateRequestContext = body.ReadVector8().ToArray();
                    body.Skip(body.ReadUInt16());
                    _certificateRequested = true;
                    _transcript.WriteBytes(message.Span);
                    _stage = HandshakeStage.WaitCertificate;

                    break;
                }
            case (HandshakeStage.WaitCertificateOrRequest or HandshakeStage.WaitCertificate, CertificateType):
                {
                    ProcessCertificate(body);
                    _transcript.WriteBytes(message.Span);
                    _stage = HandshakeStage.WaitCertificateVerify;

                    break;
                }
            case (HandshakeStage.WaitCertificateVerify, CertificateVerifyType):
                {
                    ProcessCertificateVerify(body);
                    _transcript.WriteBytes(message.Span);
                    _stage = HandshakeStage.WaitFinished;

                    break;
                }
            case (HandshakeStage.WaitFinished, FinishedType):
                {
                    ProcessFinished(body);
                    _transcript.WriteBytes(message.Span);
                    Complete(progress);

                    break;
                }
            case (HandshakeStage.Connected, NewSessionTicketType):
                // Session resumption is not used, so tickets are read and dropped.
                break;
            default:
                throw new InvalidDataException(message: "The server sent an unexpected TLS handshake message.");
        }
    }

    private void ProcessCertificate(QuicReader body)
    {
        ReadOnlyMemory<byte> context = body.ReadVector8();
        QuicReader list = new(body.ReadVector24());

        if (!context.IsEmpty || list.IsEnd)
            throw new AuthenticationException(message: "The server did not present a certificate.");

        byte[] encoded = list.ReadVector24().ToArray();

        X509Certificate certificate = new X509CertificateParser().ReadCertificate(encoded)
            ?? throw new AuthenticationException(message: "The server's certificate could not be parsed.");

        AsymmetricKeyParameter key = certificate.GetPublicKey();

        // The pin is the only trust anchor: the certificate must carry exactly the enrolled server key.
        if (key is not ECPublicKeyParameters serverKey || !serverKey.Q.Equals(_pinnedKey.Q))
            throw new AuthenticationException(message: "The server's certificate does not carry the pinned public key.");

        _serverKey = serverKey;
    }

    private void ProcessCertificateVerify(QuicReader body)
    {
        ushort algorithm = body.ReadUInt16();
        byte[] signature = body.ReadVector16().ToArray();

        if (algorithm != EcdsaP256Sha256 || _serverKey is null)
            throw new AuthenticationException(message: "The server signed the handshake with an algorithm this client did not offer.");

        byte[] content = [.. ServerSignatureContext, .. KeyDerivation.Hash(_transcript.WrittenSpan)];

        if (!ClientCredential.Verify(_serverKey, content, signature))
            throw new AuthenticationException(message: "The server's handshake signature does not verify against the pinned key.");
    }

    private void ProcessEncryptedExtensions(QuicReader body)
    {
        QuicReader extensions = new(body.ReadVector16());
        string? protocol = null;

        while (!extensions.IsEnd)
        {
            ushort type = extensions.ReadUInt16();
            ReadOnlyMemory<byte> content = extensions.ReadVector16();

            if (type == TransportParametersExtension)
            {
                PeerTransportParameters = content.ToArray();
            }
            else if (type == ApplicationProtocolExtension)
            {
                QuicReader protocols = new(content);
                QuicReader list = new(protocols.ReadVector16());

                protocol = Encoding.ASCII.GetString(list.ReadVector8().Span);
            }
        }

        if (protocol != _applicationProtocol)
            throw new AuthenticationException($"The server did not agree to the {_applicationProtocol} application protocol.");

        if (PeerTransportParameters is null)
            throw new AuthenticationException(message: "The server did not send QUIC transport parameters.");
    }

    private void ProcessFinished(QuicReader body)
    {
        byte[] finishedKey = KeyDerivation.ExpandLabel(_serverHandshakeSecret, label: "finished", [], KeyDerivation.HashLength);
        byte[] expected = KeyDerivation.Hmac(finishedKey, KeyDerivation.Hash(_transcript.WrittenSpan));

        if (!CryptographicOperations.FixedTimeEquals(expected, body.ReadRemaining().Span))
            throw new AuthenticationException(message: "The server's Finished message does not match the handshake.");
    }

    private void ProcessServerHello(QuicReader body)
    {
        ushort version = body.ReadUInt16();
        ReadOnlySpan<byte> random = body.ReadBytes(RandomLength).Span;

        if (random.SequenceEqual(HelloRetryRandom))
            throw new AuthenticationException(message: "The server asked to retry the TLS key exchange with a group this client does not offer.");

        ReadOnlyMemory<byte> sessionId = body.ReadVector8();
        ushort cipherSuite = body.ReadUInt16();
        byte compression = body.ReadByte();
        bool acceptable = version == LegacyVersion && sessionId.IsEmpty && cipherSuite == CipherSuite && compression == 0;

        if (!acceptable)
            throw new AuthenticationException(message: "The server chose TLS parameters this client did not offer.");

        QuicReader extensions = new(body.ReadVector16());
        ushort? selectedVersion = null;
        byte[]? serverShare = null;

        while (!extensions.IsEnd)
        {
            ushort type = extensions.ReadUInt16();
            QuicReader content = new(extensions.ReadVector16());

            if (type == SupportedVersionsExtension)
                selectedVersion = content.ReadUInt16();
            else if (type == KeyShareExtension && content.ReadUInt16() == P256Group)
                serverShare = content.ReadVector16().ToArray();
        }

        if (selectedVersion != TlsVersion || serverShare is null)
            throw new AuthenticationException(message: "The server did not negotiate TLS 1.3 with a P-256 key share.");

        _sharedSecret = _keyExchange.Agree(serverShare);
    }

    private void WriteFlightMessage(QuicWriter flight, byte type, ReadOnlySpan<byte> body)
    {
        byte[] message = CreateMessage(type, body);

        _transcript.WriteBytes(message);
        flight.WriteBytes(message);
    }
}
