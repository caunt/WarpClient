using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;

using Warp.Cloudflare.Registration;
using Warp.Cloudflare.Tunnel;

namespace Warp.Tests;

/// <summary>
/// Covers how the HTTP/2 MASQUE tunnel reports networks that stop it before Cloudflare answers.
/// </summary>
public sealed class MasqueTunnelTests
{
    private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(seconds: 10);

    /// <summary>
    /// A connection closed during the TLS handshake, as middleboxes that route TLS by server name do, must be explained
    /// rather than surface as a bare end of stream.
    /// </summary>
    /// <returns>A task that completes when the explanation has been verified.</returns>
    [Fact]
    public async Task ClosedHandshakeExplainsServerNameRouting()
    {
        using CancellationTokenSource cancellation = new(Timeout);

        using ECDsa deviceKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        using ECDsa serverKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        TaskCompletionSource<int> port = new(TaskCreationOptions.RunContinuationsAsynchronously);
        Task closing = CloseEveryConnectionAsync(port, cancellation.Token);

        DeviceRegistration registration = new(
            DeviceId: "loopback",
            AccessToken: "unused",
            Convert.ToBase64String(deviceKey.ExportPkcs8PrivateKey()),
            serverKey.ExportSubjectPublicKeyInfoPem(),
            EndpointIpv4: "127.0.0.1",
            EndpointIpv6: null,
            AddressIpv4: "172.16.0.2",
            AddressIpv6: null
        );

        RedirectingTcpConnector underlay = new(await port.Task.ConfigureAwait(continueOnCapturedContext: true));

        IOException exception = await Assert.ThrowsAsync<IOException>(
            async () =>
            {
                MasqueTunnel tunnel = await MasqueTunnel.OpenAsync(registration, underlay, cancellation.Token).ConfigureAwait(continueOnCapturedContext: true);

                await tunnel.DisposeAsync().ConfigureAwait(continueOnCapturedContext: true);
            }
        ).ConfigureAwait(continueOnCapturedContext: true);

        AggregateException failures = Assert.IsType<AggregateException>(exception.InnerException);

        Assert.Contains(expectedSubstring: "route TLS by server name", failures.InnerExceptions[index: 0].Message, StringComparison.Ordinal);

        await cancellation.CancelAsync().ConfigureAwait(continueOnCapturedContext: true);
        await closing.ConfigureAwait(continueOnCapturedContext: true);
    }

    // Accepts connections and closes them at once, like a middlebox with nowhere to send them.
    private static async Task CloseEveryConnectionAsync(TaskCompletionSource<int> port, CancellationToken cancellationToken)
    {
        using TcpListener listener = new(IPAddress.Loopback, port: 0);

        listener.Start();
        port.SetResult(((IPEndPoint)listener.LocalEndpoint).Port);

        try
        {
            while (!cancellationToken.IsCancellationRequested)
            {
                using Socket accepted = await listener.AcceptSocketAsync(cancellationToken).ConfigureAwait(continueOnCapturedContext: true);
            }
        }
        catch (OperationCanceledException exception)
        {
            Assert.True(cancellationToken.IsCancellationRequested, exception.Message);
        }
    }
}
