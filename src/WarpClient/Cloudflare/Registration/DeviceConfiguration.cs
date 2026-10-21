namespace Warp.Cloudflare.Registration;

internal sealed record DeviceConfiguration(IReadOnlyList<DevicePeer> Peers, DeviceInterface Interface, string? ClientId = null);
