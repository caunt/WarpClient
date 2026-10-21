namespace Warp.Quic.Tls;

/// <summary>
/// The pair of traffic secrets one TLS key schedule step produces, from which QUIC derives packet protection keys.
/// </summary>
internal sealed record TrafficSecrets(byte[] Client, byte[] Server);
