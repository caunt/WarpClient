using System.Net;
using System.Security.Cryptography;
using System.Text.Json;

using Warp.Cloudflare.Registration;
using Warp.Cloudflare.Tunnel;

namespace Warp.Tests;

/// <summary>
/// Covers how <see cref="WarpClient"/> replaces a session that Cloudflare closed, including when the replacement cannot
/// be opened right away.
/// </summary>
public sealed class SessionRecoveryTests
{
    private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(seconds: 20);

    /// <summary>
    /// A reopen that fails must not leave the closed session behind: once the network is back, the next call opens a fresh session.
    /// </summary>
    /// <returns>A task that completes when the client has recovered.</returns>
    [Fact]
    public async Task ClientRecoversWhenReopeningClosedSessionFailsOnce()
    {
        using CancellationTokenSource cancellation = new(Timeout);

        using ECDsa deviceKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        using ECDsa serverKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        LoopbackMasqueServer server = new(serverKey);

        string path = Path.Combine(Path.GetTempPath(), $"{Guid.NewGuid():N}.registration");
        SwitchableTcpConnector underlay = new(server.Port);
        WarpClient client = new(new WarpClientOptions { RegistrationPath = path, Underlay = underlay });

        try
        {
            await WriteRegistrationAsync(path, deviceKey, serverKey, cancellation.Token).ConfigureAwait(continueOnCapturedContext: true);

            await client.OpenAsync(cancellation.Token).ConfigureAwait(continueOnCapturedContext: true);

            underlay.Reachable = false;
            server.CloseConnections();

            // The client notices the closed session on the next call, and that call cannot reach Cloudflare.
            bool reopenFailed = false;

            while (!reopenFailed)
            {
                try
                {
                    await client.OpenAsync(cancellation.Token).ConfigureAwait(continueOnCapturedContext: true);
                    await Task.Delay(TimeSpan.FromMilliseconds(milliseconds: 20), cancellation.Token).ConfigureAwait(continueOnCapturedContext: true);
                }
                catch (InvalidOperationException)
                {
                    reopenFailed = true;
                }
            }

            underlay.Reachable = true;

            await client.OpenAsync(cancellation.Token).ConfigureAwait(continueOnCapturedContext: true);
        }
        finally
        {
            await client.DisposeAsync().ConfigureAwait(continueOnCapturedContext: true);

            await server.DisposeAsync().ConfigureAwait(continueOnCapturedContext: true);
            File.Delete(path);
        }
    }

    /// <summary>
    /// Disposing a tunnel twice, as happens when a closed session is disposed again, must not throw.
    /// </summary>
    /// <returns>A task that completes when both disposals have returned.</returns>
    [Fact]
    public async Task TunnelCanBeDisposedTwice()
    {
        using CancellationTokenSource cancellation = new(Timeout);

        using ECDsa deviceKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        using ECDsa serverKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        LoopbackMasqueServer server = new(serverKey);

        try
        {
            DeviceRegistration registration = CreateRegistration(deviceKey, serverKey);
            MasqueTunnel tunnel = await MasqueTunnel.OpenAsync(registration, new RedirectingTcpConnector(server.Port), [], cancellation.Token).ConfigureAwait(continueOnCapturedContext: true);

            await tunnel.DisposeAsync().ConfigureAwait(continueOnCapturedContext: true);
            await tunnel.DisposeAsync().ConfigureAwait(continueOnCapturedContext: true);

            Assert.True(tunnel.IsClosed);
        }
        finally
        {
            await server.DisposeAsync().ConfigureAwait(continueOnCapturedContext: true);
        }
    }

    private static DeviceRegistration CreateRegistration(ECDsa deviceKey, ECDsa serverKey)
    {
        return new DeviceRegistration(
            DeviceId: "loopback",
            AccessToken: "unused",
            Convert.ToBase64String(deviceKey.ExportPkcs8PrivateKey()),
            serverKey.ExportSubjectPublicKeyInfoPem(),
            EndpointIpv4: "127.0.0.1",
            EndpointIpv6: null,
            AddressIpv4: "172.16.0.2",
            AddressIpv6: null
        );
    }

    private static async Task WriteRegistrationAsync(string path, ECDsa deviceKey, ECDsa serverKey, CancellationToken cancellationToken)
    {
        using FileStream stream = File.Create(path);

        await JsonSerializer.SerializeAsync(stream, CreateRegistration(deviceKey, serverKey), RegistrationJsonContext.Relaxed.DeviceRegistration, cancellationToken)
            .ConfigureAwait(continueOnCapturedContext: true);
    }

    // Reaches the loopback server while reachable and fails with a non-network error otherwise, as an underlay does while
    // its network is down. Anything but IOException or SocketException ends the endpoint loop at once instead of retrying.
    private sealed class SwitchableTcpConnector(int port) : ITcpConnector
    {
        private volatile bool _reachable = true;

        public bool Reachable
        {
            get => _reachable;
            set => _reachable = value;
        }

        public ValueTask<Stream> ConnectAsync(DnsEndPoint remoteEndPoint, CancellationToken cancellationToken)
        {
            return _reachable
                ? new RedirectingTcpConnector(port).ConnectAsync(remoteEndPoint, cancellationToken)
                : throw new InvalidOperationException(message: "The underlay network is down.");
        }
    }
}
