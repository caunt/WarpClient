namespace Warp.Cloudflare.WireGuard;

internal sealed record TransportKeys(byte[] SendingKey, byte[] ReceivingKey, uint LocalIndex, uint RemoteIndex);
