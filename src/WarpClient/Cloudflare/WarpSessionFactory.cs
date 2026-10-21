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
    // .NET loads libmsquic from the default library paths; Homebrew's folder on Apple Silicon is not one of them.
    private static string QuicSetupHint => OperatingSystem.IsMacOS()
        ? "HTTP/3 needs libmsquic: run 'brew install libmsquic' and start the app with DYLD_FALLBACK_LIBRARY_PATH=/opt/homebrew/lib."
        : OperatingSystem.IsWindows()
        ? "HTTP/3 needs QUIC, which Windows provides from Windows 11 and Windows Server 2022."
        : "HTTP/3 needs libmsquic: install the libmsquic package from packages.microsoft.com.";

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
                ? throw new PlatformNotSupportedException(QuicSetupHint)
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
