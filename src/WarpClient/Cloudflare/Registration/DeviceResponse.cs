using System.Text.Json.Serialization;

namespace Warp.Cloudflare.Registration;

internal sealed record DeviceResponse(string Id, string? Token, [property: JsonPropertyName("config")] DeviceConfiguration Configuration);
