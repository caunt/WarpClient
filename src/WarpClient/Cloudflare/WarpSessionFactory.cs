using System.Net.Quic;

using Warp.Cloudflare.Http3;
using Warp.Cloudflare.Registration;

namespace Warp.Cloudflare;

/// <summary>
/// Registers or loads the device, enrolls the key the chosen transport needs, and opens the matching session.
/// </summary>
internal static class WarpSessionFactory
{
    public static async ValueTask<IWarpSession> OpenAsync(WarpClientOptions options, CancellationToken cancellationToken)
    {
        DeviceRegistration registration = await DeviceRegistrationStore.LoadOrRegisterAsync(options, cancellationToken).ConfigureAwait(continueOnCapturedContext: false);

        return options.Transport != WarpTransport.MasqueHttp3
            ? await TunnelSession.OpenAsync(registration, options, cancellationToken).ConfigureAwait(continueOnCapturedContext: false)
            : !QuicConnection.IsSupported
            ? throw new PlatformNotSupportedException(message: "HTTP/3 needs QUIC support; on Linux install libmsquic.")
            : (IWarpSession)await Http3ProxySession.OpenAsync(registration, cancellationToken).ConfigureAwait(continueOnCapturedContext: false);
    }
}
