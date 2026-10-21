using System.Text.Json;

namespace Warp.Cloudflare.Registration;

/// <summary>
/// Keeps the device registration in a JSON file readable only by its owner, registering a new device the first time.
/// </summary>
internal static class DeviceRegistrationStore
{
    public static async ValueTask<DeviceRegistration> LoadOrRegisterAsync(string path, ITcpConnector underlay, CancellationToken cancellationToken)
    {
        if (File.Exists(path))
            return await LoadAsync(path, cancellationToken).ConfigureAwait(continueOnCapturedContext: false);

        using SocketsHttpHandler handler = underlay.CreateHttpMessageHandler();

        using HttpClient httpClient = new(handler, disposeHandler: false);

        DeviceRegistration registration = await new DeviceRegistrationClient(httpClient).RegisterAsync(cancellationToken).ConfigureAwait(continueOnCapturedContext: false);

        await SaveAsync(path, registration, cancellationToken).ConfigureAwait(continueOnCapturedContext: false);

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

        FileStreamOptions options = new() { Mode = FileMode.CreateNew, Access = FileAccess.Write };

        // The file holds the device's private key and access token, so nobody else may read it.
        if (!OperatingSystem.IsWindows())
            options.UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;

        using FileStream stream = new(path, options);

        await JsonSerializer.SerializeAsync(stream, registration, RegistrationJsonContext.Relaxed.DeviceRegistration, cancellationToken)
            .ConfigureAwait(continueOnCapturedContext: false);
    }
}
