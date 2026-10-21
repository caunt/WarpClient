using System.Globalization;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text.Json.Serialization.Metadata;

namespace Warp.Cloudflare.Registration;

/// <summary>
/// Talks to Cloudflare's consumer device API the way the Android app does: register a device, then enroll a P-256 key that
/// switches it to the MASQUE tunnel.
/// </summary>
internal sealed class DeviceRegistrationClient(HttpClient httpClient)
{
    private const string ClientVersion = "a-6.38.9-5641";
    // Version strings of the Android app that wgcf mimics; the API accepts a wide range of them.
    private const string UserAgent = "1.1.1.1/6.38.9-5641 (Android 16.0.0)";
    private static readonly Uri ApiAddress = new(uriString: "https://api.cloudflareclient.com/v0a5641/");

    public async ValueTask<DeviceRegistration> RegisterAsync(CancellationToken cancellationToken)
    {
        RegistrationJsonContext json = RegistrationJsonContext.Relaxed;

        // The app's first registration carries a WireGuard key; enrollment below replaces it, so a random one is enough.
        RegistrationRequest registration = new(
            Convert.ToBase64String(RandomNumberGenerator.GetBytes(count: 32)),
            string.Empty,
            string.Empty,
            DateTimeOffset.UtcNow.ToString(format: "yyyy-MM-dd'T'HH:mm:ss.fff'+00:00'", CultureInfo.InvariantCulture),
            Model: "PC",
            Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(count: 8)),
            string.Empty,
            KeyType: "curve25519",
            TunnelType: "wireguard",
            Locale: "en_US"
        );

        DeviceResponse registered = await SendAsync(HttpMethod.Post, path: "reg", registration, json.RegistrationRequest, accessToken: null, cancellationToken)
            .ConfigureAwait(continueOnCapturedContext: false);

        string accessToken = registered.Token ?? throw new InvalidDataException(message: "Cloudflare's registration response has no access token.");

        using ECDsa key = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        EnrollmentRequest enrollment = new(Convert.ToBase64String(key.ExportSubjectPublicKeyInfo()), KeyType: "secp256r1", TunnelType: "masque");

        DeviceResponse enrolled = await SendAsync(HttpMethod.Patch, $"reg/{registered.Id}", enrollment, json.EnrollmentRequest, accessToken, cancellationToken)
            .ConfigureAwait(continueOnCapturedContext: false);

        if (enrolled.Configuration.Peers.Count == 0)
            throw new InvalidDataException(message: "Cloudflare's enrollment response has no tunnel endpoint.");

        DevicePeer peer = enrolled.Configuration.Peers[index: 0];
        InterfaceAddresses addresses = enrolled.Configuration.Interface.Addresses;

        return new DeviceRegistration(
            registered.Id,
            accessToken,
            Convert.ToBase64String(key.ExportPkcs8PrivateKey()),
            peer.PublicKey,
            ReadAddress(peer.Endpoint.Ipv4),
            ReadAddress(peer.Endpoint.Ipv6),
            addresses.Ipv4,
            addresses.Ipv6
        );
    }

    // Endpoints come back as "162.159.198.2:0" or "[2606:4700:103::2]:0"; only the address matters.
    private static string? ReadAddress(string? endpoint)
    {
        return endpoint is not null && IPEndPoint.TryParse(endpoint, out IPEndPoint? parsed) ? parsed.Address.ToString() : null;
    }

    private async ValueTask<DeviceResponse> SendAsync<TRequest>(
        HttpMethod method,
        string path,
        TRequest body,
        JsonTypeInfo<TRequest> bodyType,
        string? accessToken,
        CancellationToken cancellationToken
    )
    {
        using HttpRequestMessage request = new(method, new Uri(ApiAddress, path));

        request.Content = JsonContent.Create(body, bodyType);
        request.Headers.UserAgent.ParseAdd(UserAgent);
        request.Headers.Add(name: "CF-Client-Version", ClientVersion);

        if (accessToken is not null)
            request.Headers.Authorization = new AuthenticationHeaderValue(scheme: "Bearer", accessToken);

        using HttpResponseMessage response = await httpClient.SendAsync(request, cancellationToken).ConfigureAwait(continueOnCapturedContext: false);

        if (!response.IsSuccessStatusCode)
        {
            string details = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(continueOnCapturedContext: false);

            throw new HttpRequestException($"Cloudflare's device API answered {(int)response.StatusCode}: {details}", inner: null, response.StatusCode);
        }

        DeviceResponse? device = await response.Content.ReadFromJsonAsync(RegistrationJsonContext.Relaxed.DeviceResponse, cancellationToken)
            .ConfigureAwait(continueOnCapturedContext: false);

        return device ?? throw new InvalidDataException(message: "Cloudflare's device API returned an empty response.");
    }
}
