using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Warp.Cloudflare.Registration;

[JsonSerializable(typeof(RegistrationRequest))]
[JsonSerializable(typeof(EnrollmentRequest))]
[JsonSerializable(typeof(DeviceResponse))]
[JsonSerializable(typeof(DeviceRegistration))]
[JsonSerializable(typeof(AccountResponse))]
[JsonSerializable(typeof(LicenseRequest))]
internal sealed partial class RegistrationJsonContext : JsonSerializerContext
{
    /// <summary>
    /// Snake-case options that leave '+' unescaped. Cloudflare's registration API rejects the default <c>+</c> escape
    /// in base64 keys and timestamps with "Invalid registration request".
    /// </summary>
    public static RegistrationJsonContext Relaxed { get; } = new(
        new JsonSerializerOptions
        {
            Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
            PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower,
            WriteIndented = true,
        }
    );
}
