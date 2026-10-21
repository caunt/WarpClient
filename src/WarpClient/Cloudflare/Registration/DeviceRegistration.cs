namespace Warp.Cloudflare.Registration;

/// <summary>
/// Everything needed to reopen the tunnel for an enrolled WARP device. Stored on disk because Cloudflare returns the access
/// token only once and rate-limits new registrations.
/// </summary>
internal sealed record DeviceRegistration(
    string DeviceId,
    string AccessToken,
    string PrivateKey,
    string ServerPublicKey,
    string? EndpointIpv4,
    string? EndpointIpv6,
    string AddressIpv4,
    string? AddressIpv6
);
