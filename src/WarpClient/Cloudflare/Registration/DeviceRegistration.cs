namespace Warp.Cloudflare.Registration;

/// <summary>
/// Everything needed to reopen the tunnel for an enrolled WARP device. Stored on disk because Cloudflare returns the access
/// token only once and rate-limits new registrations. Fields added after the first release have defaults, so older files
/// keep loading.
/// </summary>
/// <remarks>
/// <see cref="TunnelType"/> records which key Cloudflare currently holds for the device: <c>masque</c> (also assumed when
/// missing) for the P-256 key, or <c>wireguard</c> for the X25519 key.
/// </remarks>
internal sealed record DeviceRegistration(
    string DeviceId,
    string AccessToken,
    string PrivateKey,
    string ServerPublicKey,
    string? EndpointIpv4,
    string? EndpointIpv6,
    string AddressIpv4,
    string? AddressIpv6,
    string? LicenseKey = null,
    bool IsZeroTrust = false,
    string? TunnelType = null,
    string? WireGuardPrivateKey = null,
    string? WireGuardPeerPublicKey = null,
    string? WireGuardEndpoint = null,
    string? ClientId = null
)
{
    public const string MasqueTunnelType = "masque";
    public const string WireGuardTunnelType = "wireguard";

    public bool IsWireGuard => TunnelType == WireGuardTunnelType;
}
