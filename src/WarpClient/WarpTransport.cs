namespace Warp;

/// <summary>
/// Selects the protocol that carries traffic between this device and Cloudflare. A device holds one tunnel key at a time,
/// so switching re-enrolls the device's key through Cloudflare's API on the next connection.
/// </summary>
public enum WarpTransport
{
    /// <summary>
    /// MASQUE IP tunnel over HTTP/2 on TCP port 443, authenticated by mutual TLS. Works on networks that block UDP and
    /// through HTTP proxies.
    /// </summary>
    MasqueHttp2 = 0,

    /// <summary>
    /// WireGuard over UDP port 2408, the classic WARP protocol. Needs outbound UDP; carries Cloudflare's per-device routing
    /// tag in every message header.
    /// </summary>
    WireGuard = 1,
}
