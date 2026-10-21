namespace Warp.Quic.Tls;

/// <summary>
/// What processing a run of server handshake data produced: new keys, client handshake messages to send and completion.
/// </summary>
internal sealed class TlsProgress
{
    public TrafficSecrets? ApplicationSecrets { get; set; }

    public bool Completed { get; set; }

    public byte[] HandshakeData { get; set; } = [];

    public TrafficSecrets? HandshakeSecrets { get; set; }
}
