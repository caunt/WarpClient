using System.Net;
using System.Net.Quic;
using System.Net.Security;
using System.Runtime.Versioning;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

using Warp.Quic;
using Warp.Quic.Crypto;

namespace Warp.Tests;

/// <summary>
/// Runs the managed QUIC client against the platform's msquic server over loopback, the independent implementation
/// available in .NET. The tests pass without running where msquic is not installed.
/// </summary>
public sealed class QuicInteropTests
{
    private const string ApplicationProtocol = "h3";
    private const string ServerName = "localhost";
    private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(seconds: 30);

    /// <summary>
    /// The handshake must authenticate both sides, a server-opened stream must arrive, and a payload larger than every
    /// flow-control window must echo back intact.
    /// </summary>
    /// <returns>A task that completes when the exchange has been verified.</returns>
    [Fact]
    public Task ManagedClientEchoesThroughMsquicServer()
    {
        return VerifyEchoAsync(dropEvery: 0);
    }

    /// <summary>
    /// With every seventh datagram lost in each direction, the handshake and the echo must still complete through
    /// retransmission and probe timeouts.
    /// </summary>
    /// <returns>A task that completes when the exchange has been verified.</returns>
    [Fact]
    public Task ManagedClientRecoversFromPacketLoss()
    {
        return VerifyEchoAsync(dropEvery: 7);
    }

    /// <summary>
    /// A server whose certificate does not carry the pinned key must fail the handshake as an authentication error.
    /// </summary>
    /// <returns>A task that completes when the rejection has been verified.</returns>
    [Fact]
    public async Task ManagedClientRejectsUnpinnedServer()
    {
        if (!QuicListener.IsSupported)
            return;

        using CancellationTokenSource cancellation = new(Timeout);

        using ECDsa serverKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        using ECDsa otherKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        using ECDsa clientKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        using X509Certificate2 serverCertificate = CreateCertificate(serverKey);

        QuicListener listener = await QuicListener.ListenAsync(CreateListenerOptions(serverCertificate, new ServerProbe()), cancellation.Token)
            .ConfigureAwait(continueOnCapturedContext: true);

        await using (listener.ConfigureAwait(continueOnCapturedContext: true))
        {
            QuicClientOptions options = CreateClientOptions(otherKey.ExportSubjectPublicKeyInfo(), clientKey);
            int port = listener.LocalEndPoint.Port;

            AuthenticationException exception = await Assert.ThrowsAsync<AuthenticationException>(
                async () =>
                {
                    ManagedQuicConnection connection = await ConnectAsync(port, options, cancellation.Token).ConfigureAwait(continueOnCapturedContext: true);

                    await connection.DisposeAsync().ConfigureAwait(continueOnCapturedContext: true);
                }
            ).ConfigureAwait(continueOnCapturedContext: true);

            Assert.Contains(expectedSubstring: "pinned", exception.Message, StringComparison.Ordinal);
        }
    }

    private static async Task<ManagedQuicConnection> ConnectAsync(int port, QuicClientOptions options, CancellationToken cancellationToken, int dropEvery = 0)
    {
        IUdpConnection transport = await new DirectUdpConnector().ConnectAsync(new DnsEndPoint(host: "127.0.0.1", port), cancellationToken)
            .ConfigureAwait(continueOnCapturedContext: true);

        if (dropEvery > 0)
            transport = LossyUdpConnection.Wrap(transport, dropEvery);

        return await ManagedQuicConnection.ConnectAsync(transport, options, cancellationToken).ConfigureAwait(continueOnCapturedContext: true);
    }

    private static X509Certificate2 CreateCertificate(ECDsa key)
    {
        CertificateRequest request = new(subjectName: "CN=localhost", key, HashAlgorithmName.SHA256);
        DateTimeOffset now = DateTimeOffset.UtcNow;

        using X509Certificate2 ephemeral = request.CreateSelfSigned(now.AddHours(hours: -1), now.AddDays(days: 1));

        // msquic needs a certificate whose private key can be handed to its TLS library, which an ephemeral key cannot.
        return X509CertificateLoader.LoadPkcs12(ephemeral.Export(X509ContentType.Pfx), password: null);
    }

    private static QuicClientOptions CreateClientOptions(byte[] pinnedPublicKey, ECDsa clientKey)
    {
        return new QuicClientOptions
        {
            ServerName = ServerName,
            ApplicationProtocol = ApplicationProtocol,
            PinnedPublicKey = pinnedPublicKey,
            Credential = ClientCredential.FromPkcs8(clientKey.ExportPkcs8PrivateKey()),
            StreamReceiveWindow = 64 * 1024,
        };
    }

    [SupportedOSPlatform("linux")]
    [SupportedOSPlatform("macos")]
    [SupportedOSPlatform("windows")]
    private static QuicListenerOptions CreateListenerOptions(X509Certificate2 certificate, ServerProbe probe)
    {
        QuicServerConnectionOptions connectionOptions = new()
        {
            DefaultStreamErrorCode = 0x10C,
            DefaultCloseErrorCode = 0x100,
            MaxInboundBidirectionalStreams = 4,
            MaxInboundUnidirectionalStreams = 4,
            ServerAuthenticationOptions = new SslServerAuthenticationOptions
            {
                ApplicationProtocols = [new SslApplicationProtocol(ApplicationProtocol)],
                ServerCertificate = certificate,
                ClientCertificateRequired = true,
                RemoteCertificateValidationCallback = (sender, presented, chain, errors) => probe.RecordClientCertificate(presented),
            },
        };

        return new QuicListenerOptions
        {
            ListenEndPoint = new IPEndPoint(IPAddress.Loopback, port: 0),
            ApplicationProtocols = [new SslApplicationProtocol(ApplicationProtocol)],
            ConnectionOptionsCallback = (connection, hello, cancellationToken) => ValueTask.FromResult(connectionOptions),
        };
    }

    private static async Task<byte[]> ReadToEndAsync(Stream stream, CancellationToken cancellationToken)
    {
        using MemoryStream received = new();

        await stream.CopyToAsync(received, cancellationToken).ConfigureAwait(continueOnCapturedContext: true);

        return received.ToArray();
    }

    [SupportedOSPlatform("linux")]
    [SupportedOSPlatform("macos")]
    [SupportedOSPlatform("windows")]
    private static async Task RunEchoServerAsync(QuicListener listener, ServerProbe probe, CancellationToken cancellationToken)
    {
        QuicConnection connection = await listener.AcceptConnectionAsync(cancellationToken).ConfigureAwait(continueOnCapturedContext: true);

        await using (connection.ConfigureAwait(continueOnCapturedContext: true))
        {
            // A server-opened unidirectional stream first, the way an HTTP/3 server opens its control stream.
            QuicStream control = await connection.OpenOutboundStreamAsync(QuicStreamType.Unidirectional, cancellationToken).ConfigureAwait(continueOnCapturedContext: true);

            await using (control.ConfigureAwait(continueOnCapturedContext: true))
                await control.WriteAsync("hello"u8.ToArray(), completeWrites: true, cancellationToken).ConfigureAwait(continueOnCapturedContext: true);

            QuicStream stream = await connection.AcceptInboundStreamAsync(cancellationToken).ConfigureAwait(continueOnCapturedContext: true);

            await using (stream.ConfigureAwait(continueOnCapturedContext: true))
            {
                byte[] received = await ReadToEndAsync(stream, cancellationToken).ConfigureAwait(continueOnCapturedContext: true);

                await stream.WriteAsync(received, completeWrites: true, cancellationToken).ConfigureAwait(continueOnCapturedContext: true);

                // On a lossy path the client may close before its acknowledgment of the FIN arrives, which ends the wait too.
                try
                {
                    await stream.WritesClosed.WaitAsync(cancellationToken).ConfigureAwait(continueOnCapturedContext: true);
                }
                catch (QuicException exception)
                {
                    probe.ServerError = exception;
                }
            }
        }
    }

    private static async Task VerifyEchoAsync(int dropEvery)
    {
        if (!QuicListener.IsSupported)
            return;

        using CancellationTokenSource cancellation = new(Timeout);

        using ECDsa serverKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        using ECDsa clientKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        using X509Certificate2 serverCertificate = CreateCertificate(serverKey);

        ServerProbe probe = new();

        QuicListener listener = await QuicListener.ListenAsync(CreateListenerOptions(serverCertificate, probe), cancellation.Token)
            .ConfigureAwait(continueOnCapturedContext: true);

        await using (listener.ConfigureAwait(continueOnCapturedContext: true))
        {
            Task server = RunEchoServerAsync(listener, probe, cancellation.Token);
            QuicClientOptions options = CreateClientOptions(serverKey.ExportSubjectPublicKeyInfo(), clientKey);
            byte[] payload = RandomNumberGenerator.GetBytes(count: 300_000);
            int port = listener.LocalEndPoint.Port;

            ManagedQuicConnection connection = await ConnectAsync(port, options, cancellation.Token, dropEvery).ConfigureAwait(continueOnCapturedContext: true);

            await using (connection.ConfigureAwait(continueOnCapturedContext: true))
            {
                ManagedQuicStream control = await connection.AcceptInboundStreamAsync(cancellation.Token).ConfigureAwait(continueOnCapturedContext: true);
                byte[] greeting = await ReadToEndAsync(control, cancellation.Token).ConfigureAwait(continueOnCapturedContext: true);

                await control.DisposeAsync().ConfigureAwait(continueOnCapturedContext: true);

                ManagedQuicStream stream = await connection.OpenStreamAsync(bidirectional: true, cancellation.Token).ConfigureAwait(continueOnCapturedContext: true);

                await using (stream.ConfigureAwait(continueOnCapturedContext: true))
                {
                    await stream.WriteAsync(payload, cancellation.Token).ConfigureAwait(continueOnCapturedContext: true);
                    await stream.CompleteWritesAsync(cancellation.Token).ConfigureAwait(continueOnCapturedContext: true);

                    byte[] echoed = await ReadToEndAsync(stream, cancellation.Token).ConfigureAwait(continueOnCapturedContext: true);

                    Assert.Equal("hello"u8.ToArray(), greeting);
                    Assert.Equal(payload, echoed);
                }
            }

            await server.ConfigureAwait(continueOnCapturedContext: true);
        }

        Assert.Equal(clientKey.ExportSubjectPublicKeyInfo(), probe.ClientPublicKey);
    }
}
