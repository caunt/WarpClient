using System.Net;
using System.Security.Authentication;

using Warp.Cloudflare.Registration;
using Warp.Quic;
using Warp.Quic.Crypto;

namespace Warp.Cloudflare.Http3;

/// <summary>
/// An HTTP/3 connection to Cloudflare's MASQUE service over the managed QUIC client: mutual TLS with the device key, the
/// pinned server key, and the control streams both sides keep open for the life of the connection.
/// </summary>
internal sealed class MasqueHttp3Connection : IAsyncDisposable
{
    public const ulong RequestCancelled = 0x10C;
    private const string ApplicationProtocol = "h3";
    private const ulong NoError = 0x100;
    private const int ServerPort = 443;
    private static readonly TimeSpan HandshakeTimeout = TimeSpan.FromSeconds(seconds: 10);
    private static readonly TimeSpan KeepAliveInterval = TimeSpan.FromSeconds(seconds: 10);
    private readonly CancellationTokenSource _stopping = new();
    private volatile bool _closed;
    private ManagedQuicStream? _controlStream;
    private int _disposed;
    private Task _draining = Task.CompletedTask;

    private MasqueHttp3Connection(ManagedQuicConnection connection)
    {
        Connection = connection;
    }

    public ManagedQuicConnection Connection { get; }

    public bool IsClosed => _closed || Connection.IsClosed;

    /// <summary>
    /// Connects to the first of the device's MASQUE endpoints that completes the handshake, then sends the client's
    /// SETTINGS.
    /// </summary>
    public static async ValueTask<MasqueHttp3Connection> OpenAsync(
        DeviceRegistration registration,
        IUdpConnector underlay,
        string serverName,
        byte[] settings,
        bool datagrams,
        CancellationToken cancellationToken
    )
    {
        QuicClientOptions options = new()
        {
            ServerName = serverName,
            ApplicationProtocol = ApplicationProtocol,
            PinnedPublicKey = PublicKeyEncoding.ReadSubjectPublicKeyInformation(registration.ServerPublicKey),
            Credential = ClientCredential.FromPkcs8(Convert.FromBase64String(registration.PrivateKey)),
            DatagramsEnabled = datagrams,
            KeepAliveInterval = KeepAliveInterval,
            StreamErrorCode = RequestCancelled,
        };

        string?[] endpoints = [registration.EndpointIpv4, registration.EndpointIpv6];
        List<Exception> failures = [];

        foreach (string endpoint in endpoints.OfType<string>())
        {
            try
            {
                return await OpenAsync(new DnsEndPoint(endpoint, ServerPort), underlay, options, settings, cancellationToken).ConfigureAwait(continueOnCapturedContext: false);
            }
            catch (IOException exception)
            {
                failures.Add(exception);
            }
            catch (AuthenticationException exception)
            {
                failures.Add(exception);
            }
        }

        throw new IOException(message: "None of Cloudflare's MASQUE endpoints accepted the HTTP/3 connection.", new AggregateException(failures));
    }

    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposed, value: 1) != 0)
            return;

        _closed = true;
        await _stopping.CancelAsync().ConfigureAwait(continueOnCapturedContext: false);

        try
        {
            await Connection.CloseAsync(NoError, CancellationToken.None).ConfigureAwait(continueOnCapturedContext: false);
        }
        finally
        {
            await Connection.DisposeAsync().ConfigureAwait(continueOnCapturedContext: false);
            await _draining.ConfigureAwait(continueOnCapturedContext: false);
            _stopping.Dispose();
        }
    }

    public async ValueTask<ManagedQuicStream> OpenRequestStreamAsync(CancellationToken cancellationToken)
    {
        try
        {
            return await Connection.OpenStreamAsync(bidirectional: true, cancellationToken).ConfigureAwait(continueOnCapturedContext: false);
        }
        catch (IOException)
        {
            _closed = true;

            throw;
        }
    }

    private static async ValueTask<MasqueHttp3Connection> OpenAsync(DnsEndPoint endpoint, IUdpConnector underlay, QuicClientOptions options, byte[] settings, CancellationToken cancellationToken)
    {
        using CancellationTokenSource handshake = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);

        handshake.CancelAfter(HandshakeTimeout);

        ManagedQuicConnection connection;

        try
        {
            IUdpConnection transport = await underlay.ConnectAsync(endpoint, handshake.Token).ConfigureAwait(continueOnCapturedContext: false);

            connection = await ManagedQuicConnection.ConnectAsync(transport, options, handshake.Token).ConfigureAwait(continueOnCapturedContext: false);
        }
        catch (OperationCanceledException exception) when (!cancellationToken.IsCancellationRequested)
        {
            // An endpoint that never answers, as when UDP is blocked, moves on to the next one instead of using up the timeout.
            throw new IOException($"Cloudflare's MASQUE endpoint {endpoint.Host} did not answer the QUIC handshake.", exception);
        }

        MasqueHttp3Connection session = new(connection);

        try
        {
            await session.StartAsync(settings, cancellationToken).ConfigureAwait(continueOnCapturedContext: false);

            return session;
        }
        catch
        {
            await session.DisposeAsync().ConfigureAwait(continueOnCapturedContext: false);

            throw;
        }
    }


    private async Task DrainAsync(ManagedQuicStream inbound, CancellationToken cancellationToken)
    {
        byte[] buffer = new byte[1024];

        await using (inbound.ConfigureAwait(continueOnCapturedContext: false))
        {
            try
            {
                int read = await inbound.ReadAsync(buffer, cancellationToken).ConfigureAwait(continueOnCapturedContext: false);

                while (read > 0)
                    read = await inbound.ReadAsync(buffer, cancellationToken).ConfigureAwait(continueOnCapturedContext: false);
            }
            catch (IOException)
            {
                _closed = true;
            }
            catch (OperationCanceledException)
            {
                _closed = true;
            }
        }
    }

    // The server's control and QPACK streams must stay open and be read; their contents need no action here.
    private async Task DrainInboundStreamsAsync(CancellationToken cancellationToken)
    {
        List<Task> readers = [];

        try
        {
            while (!cancellationToken.IsCancellationRequested)
            {
                ManagedQuicStream inbound = await Connection.AcceptInboundStreamAsync(cancellationToken).ConfigureAwait(continueOnCapturedContext: false);

                readers.Add(DrainAsync(inbound, cancellationToken));
            }
        }
        catch (IOException)
        {
            _closed = true;
        }
        catch (OperationCanceledException)
        {
            _closed = true;
        }

        await Task.WhenAll(readers).ConfigureAwait(continueOnCapturedContext: false);
    }

    private async ValueTask StartAsync(byte[] settings, CancellationToken cancellationToken)
    {
        // Every HTTP/3 endpoint opens a control stream whose first frame is SETTINGS; settings left out keep their defaults,
        // including a QPACK dynamic table capacity of zero.
        _controlStream = await Connection.OpenStreamAsync(bidirectional: false, cancellationToken).ConfigureAwait(continueOnCapturedContext: false);

        byte[] preface = [(byte)Http3Framing.ControlStreamType, .. Http3Framing.CreateFrame(Http3Framing.SettingsFrame, settings)];

        await _controlStream.WriteAsync(preface, cancellationToken).ConfigureAwait(continueOnCapturedContext: false);
        _draining = DrainInboundStreamsAsync(_stopping.Token);
    }
}
