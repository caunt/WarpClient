using System.Globalization;
using System.Net.Quic;

using Warp.Cloudflare.Http3;
using Warp.Cloudflare.Registration;

namespace Warp.Cloudflare;

/// <summary>
/// Registers or loads the device, enrolls the key the chosen transport needs, and opens the matching session within the
/// configured connect timeout.
/// </summary>
internal static class WarpSessionFactory
{
    public static async ValueTask<IWarpSession> OpenAsync(WarpClientOptions options, CancellationToken cancellationToken)
    {
        using CancellationTokenSource timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);

        timeout.CancelAfter(options.ConnectTimeout);

        try
        {
            DeviceRegistration registration = await DeviceRegistrationStore.LoadOrRegisterAsync(options, timeout.Token).ConfigureAwait(continueOnCapturedContext: false);

            return options.Transport != WarpTransport.MasqueHttp3
                ? await TunnelSession.OpenAsync(registration, options, timeout.Token).ConfigureAwait(continueOnCapturedContext: false)
                : !QuicConnection.IsSupported
                ? throw new PlatformNotSupportedException(message: "HTTP/3 needs QUIC support; on Linux install libmsquic.")
                : (IWarpSession)await Http3ProxySession.OpenAsync(registration, timeout.Token).ConfigureAwait(continueOnCapturedContext: false);
        }
        catch (OperationCanceledException exception) when (!cancellationToken.IsCancellationRequested)
        {
            string message = string.Create(
                CultureInfo.InvariantCulture,
                $"Cloudflare did not complete the {options.Transport} connection within {options.ConnectTimeout.TotalSeconds} seconds."
            );

            throw new TimeoutException(message, exception);
        }
    }
}
