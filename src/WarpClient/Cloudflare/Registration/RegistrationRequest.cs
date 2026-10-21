using System.Text.Json.Serialization;

namespace Warp.Cloudflare.Registration;

internal sealed record RegistrationRequest(
    string Key,
    string InstallId,
    [property: JsonPropertyName("fcm_token")] string FirebaseToken,
    [property: JsonPropertyName("tos")] string TermsAcceptedAt,
    string Model,
    string SerialNumber,
    string OsVersion,
    string KeyType,
    string TunnelType,
    string Locale
);
