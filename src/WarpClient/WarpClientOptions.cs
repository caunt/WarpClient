using System.Collections.ObjectModel;

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

    /// <summary>
    /// Gets or sets a WARP+ license key you own, as shown in the 1.1.1.1 app. It is bound to the device once and remembered
    /// in the registration file; the license's account allows a limited number of devices.
    /// </summary>
    public string? LicenseKey { get; set; }

    /// <summary>
    /// Gets or sets the protocol that carries traffic to Cloudflare. Defaults to <see cref="WarpTransport.MasqueHttp2"/>,
    /// which works wherever HTTPS does; <see cref="WarpTransport.WireGuard"/> needs outbound UDP.
    /// </summary>
    public WarpTransport Transport { get; set; } = WarpTransport.MasqueHttp2;

    /// <summary>
    /// Gets or sets a Cloudflare Zero Trust enrollment token for your organization: the JWT issued by
    /// <c>https://&lt;team&gt;.cloudflareaccess.com/warp</c> after signing in, or by a service token. It is only used when a
    /// new device is registered, and it expires quickly, so register right after obtaining it.
    /// </summary>
    public string? TeamToken { get; set; }

    /// <summary>
    /// Gets or sets how long registration requests and opening a transport may take before failing with a
    /// <see cref="TimeoutException"/>, so an unreachable endpoint is reported instead of waited on. Defaults to 20 seconds.
    /// </summary>
    public TimeSpan ConnectTimeout { get; set; } = TimeSpan.FromSeconds(seconds: 20);

    /// <summary>
    /// Gets additional Cloudflare MASQUE endpoints (IP addresses or host names, port 443) that the MASQUE transports try after
    /// the addresses stored in the registration, for when the registered address is unreachable from your network. They must
    /// serve the same tunnel key; an address that fails the key check is skipped. Empty by default, and ignored by WireGuard.
    /// </summary>
    public Collection<string> FallbackEndpoints { get; } = [];

    /// <summary>
    /// Gets or sets the network path for the WireGuard transport's UDP datagrams. Defaults to the host's own sockets.
    /// </summary>
    public IUdpConnector UdpUnderlay { get; set; } = new DirectUdpConnector();
}
