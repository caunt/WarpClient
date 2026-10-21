namespace Warp.Quic.Tls;

/// <summary>
/// The next server message a TLS 1.3 client accepts (RFC 8446 section A.1); anything else ends the handshake.
/// </summary>
internal enum HandshakeStage
{
    WaitServerHello = 0,
    WaitEncryptedExtensions,
    WaitCertificateOrRequest,
    WaitCertificate,
    WaitCertificateVerify,
    WaitFinished,
    Connected,
}
