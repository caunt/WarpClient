using System.Text.Json;

namespace Warp.Cloudflare.Registration;

/// <summary>
/// Keeps the device registration in a JSON file readable only by its owner, registering a new device the first time and
/// binding the configured WARP+ license once.
/// </summary>
internal static class DeviceRegistrationStore
{
    public static async ValueTask<AccountResponse> GetAccountAsync(WarpClientOptions options, CancellationToken cancellationToken)
    {
        DeviceRegistration registration = await LoadOrRegisterAsync(options, cancellationToken).ConfigureAwait(continueOnCapturedContext: false);

        using SocketsHttpHandler handler = options.Underlay.CreateHttpMessageHandler();

        using HttpClient httpClient = new(handler, disposeHandler: false) { Timeout = options.ConnectTimeout };

        return await new DeviceRegistrationClient(httpClient).GetAccountAsync(registration, cancellationToken).ConfigureAwait(continueOnCapturedContext: false);
    }

    public static async ValueTask<DeviceRegistration> LoadOrRegisterAsync(WarpClientOptions options, CancellationToken cancellationToken)
    {
        using SocketsHttpHandler handler = options.Underlay.CreateHttpMessageHandler();

        using HttpClient httpClient = new(handler, disposeHandler: false) { Timeout = options.ConnectTimeout };

        DeviceRegistrationClient client = new(httpClient);
        bool exists = File.Exists(options.RegistrationPath);

        DeviceRegistration registration = exists
            ? await LoadAsync(options.RegistrationPath, cancellationToken).ConfigureAwait(continueOnCapturedContext: false)
            : await client.RegisterAsync(options.TeamToken, cancellationToken).ConfigureAwait(continueOnCapturedContext: false);

        bool licenseChanged = false;

        if (options.LicenseKey is string licenseKey && licenseKey != registration.LicenseKey)
        {
            AccountResponse account = await client.BindLicenseAsync(registration, licenseKey, cancellationToken).ConfigureAwait(continueOnCapturedContext: false);

            registration = registration with { LicenseKey = licenseKey };
            licenseChanged = account.AccountType is not null;
        }

        bool wantsWireGuard = options.Transport == WarpTransport.WireGuard;
        bool transportChanged = wantsWireGuard != registration.IsWireGuard;

        // Cloudflare holds one tunnel key per device, so changing transport re-enrolls the matching key.
        if (transportChanged)
        {
            registration = wantsWireGuard
                ? await client.EnrollWireGuardAsync(registration, cancellationToken).ConfigureAwait(continueOnCapturedContext: false)
                : await client.EnrollMasqueAsync(registration, cancellationToken).ConfigureAwait(continueOnCapturedContext: false);
        }

        if (!exists || licenseChanged || transportChanged)
            await SaveAsync(options.RegistrationPath, registration, cancellationToken).ConfigureAwait(continueOnCapturedContext: false);

        return registration;
    }

    private static async ValueTask<DeviceRegistration> LoadAsync(string path, CancellationToken cancellationToken)
    {
        using FileStream stream = File.OpenRead(path);

        DeviceRegistration? registration = await JsonSerializer.DeserializeAsync(stream, RegistrationJsonContext.Relaxed.DeviceRegistration, cancellationToken)
            .ConfigureAwait(continueOnCapturedContext: false);

        return registration ?? throw new InvalidDataException($"{path} does not contain a WARP device registration.");
    }

    private static async ValueTask SaveAsync(string path, DeviceRegistration registration, CancellationToken cancellationToken)
    {
        string? directory = Path.GetDirectoryName(Path.GetFullPath(path));

        if (directory is not null)
            new DirectoryInfo(directory).Create();

        // Truncating keeps an existing file's owner-only permissions; a new file is created with them.
        FileStreamOptions fileOptions = new() { Mode = FileMode.Create, Access = FileAccess.Write };

        // The file holds the device's private key and access token, so nobody else may read it.
        if (!OperatingSystem.IsWindows())
            fileOptions.UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;

        using FileStream stream = new(path, fileOptions);

        await JsonSerializer.SerializeAsync(stream, registration, RegistrationJsonContext.Relaxed.DeviceRegistration, cancellationToken)
            .ConfigureAwait(continueOnCapturedContext: false);
    }
}
