namespace Warp;

/// <summary>
/// Chooses where the WARP device credentials are kept and which network path reaches Cloudflare. The defaults work
/// without any configuration.
/// </summary>
public sealed class WarpClientOptions
{
    /// <summary>
    /// Gets or sets the file that holds the device registration, including its private key. It is created with owner-only
    /// permissions on first use and reused afterwards, so one WARP device serves every run. Defaults to
    /// <c>WarpClient/registration.json</c> inside the user's application data folder.
    /// </summary>
    // Without DoNotVerify, Unix returns an empty string while ~/.config does not exist yet, which would put the private key
    // in the working directory.
    public string RegistrationPath { get; set; } = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData, Environment.SpecialFolderOption.DoNotVerify),
        path2: "WarpClient",
        path3: "registration.json"
    );

    /// <summary>
    /// Gets or sets the network path used for Cloudflare's registration API and for the tunnel's own TCP connection.
    /// Defaults to <see cref="SystemProxyTcpConnector"/>, which honours the system proxy like <see cref="HttpClient"/> does.
    /// </summary>
    public ITcpConnector Underlay { get; set; } = new SystemProxyTcpConnector();
}
