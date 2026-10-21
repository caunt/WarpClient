using System.Text.Json.Serialization;

namespace Warp.Cloudflare.Registration;

internal sealed record InterfaceAddresses([property: JsonPropertyName("v4")] string Ipv4, [property: JsonPropertyName("v6")] string? Ipv6);
