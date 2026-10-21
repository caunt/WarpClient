using System.Net;

using Nito.AsyncEx;

using Warp.Cloudflare;

namespace Warp;

/// <summary>
/// Sends TCP, UDP and HTTP traffic through Cloudflare WARP, so remote services see a Cloudflare address instead of the
/// host's own. Registration, tunnel setup, reconnection and DNS are handled internally.
/// </summary>
/// <remarks>
/// The first use registers a free WARP device unless <see cref="WarpClientOptions.RegistrationPath"/> already holds one,
/// which accepts Cloudflare's terms of service. Traffic travels through WARP's MASQUE tunnel over HTTP/2 on TCP port 443,
/// carrying IPv4 and IPv6 packets; host names are resolved by 1.1.1.1 inside the tunnel.
/// </remarks>
/// <remarks>
/// Prepares a client that opens its tunnel on first use. Prefer <see cref="CreateAsync"/> to surface connection
/// problems immediately.
/// </remarks>
/// <param name="options">Where the device registration is kept and how Cloudflare is reached; defaults apply when omitted.</param>
public sealed class WarpClient(WarpClientOptions? options = null) : ITcpConnector, IUdpConnector, IAsyncDisposable
{
    private readonly AsyncLock _mutex = new();
    private readonly WarpClientOptions _options = options ?? new WarpClientOptions();
    private bool _disposed;
    private TunnelSession? _session;

    /// <summary>
    /// Registers the device if needed and opens the tunnel before returning, so failures surface here instead of on first use.
    /// </summary>
    /// <param name="options">Where the device registration is kept and how Cloudflare is reached; defaults apply when omitted.</param>
    /// <param name="cancellationToken">Aborts registration and tunnel setup.</param>
    /// <returns>A client whose tunnel is already open.</returns>
    public static async ValueTask<WarpClient> CreateAsync(WarpClientOptions? options = null, CancellationToken cancellationToken = default)
    {
        WarpClient client = new(options);

        try
        {
            TunnelSession opened = await client.GetSessionAsync(cancellationToken).ConfigureAwait(continueOnCapturedContext: false);

            return opened.IsClosed ? throw new IOException(message: "The WARP tunnel closed right after opening.") : client;
        }
        catch
        {
            await client.DisposeAsync().ConfigureAwait(continueOnCapturedContext: false);

            throw;
        }
    }

    /// <inheritdoc />
    public async ValueTask<Stream> ConnectAsync(DnsEndPoint remoteEndPoint, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(remoteEndPoint);

        TunnelSession current = await GetSessionAsync(cancellationToken).ConfigureAwait(continueOnCapturedContext: false);
        IPAddress address = await current.ResolveAsync(remoteEndPoint.Host, cancellationToken).ConfigureAwait(continueOnCapturedContext: false);

        return await current.Stack.ConnectAsync(new IPEndPoint(address, remoteEndPoint.Port), cancellationToken).ConfigureAwait(continueOnCapturedContext: false);
    }

    /// <summary>
    /// Opens a TCP connection to a host through the tunnel; host names are resolved inside the tunnel.
    /// </summary>
    /// <param name="host">Host name or IPv4 address of the remote service.</param>
    /// <param name="port">TCP port of the remote service.</param>
    /// <param name="cancellationToken">Aborts the connection attempt.</param>
    /// <returns>A stream that owns the connection; disposing it closes the connection.</returns>
    public ValueTask<Stream> ConnectTcpAsync(string host, int port, CancellationToken cancellationToken = default)
    {
        return ConnectAsync(new DnsEndPoint(host, port), cancellationToken);
    }

    /// <summary>
    /// Opens a UDP association with a host through the tunnel; host names are resolved inside the tunnel.
    /// </summary>
    /// <param name="host">Host name or IPv4 address of the remote service.</param>
    /// <param name="port">UDP port of the remote service.</param>
    /// <param name="cancellationToken">Aborts the attempt, including name resolution.</param>
    /// <returns>A connection that exchanges datagrams with that endpoint only.</returns>
    public ValueTask<IUdpConnection> ConnectUdpAsync(string host, int port, CancellationToken cancellationToken = default)
    {
        return ((IUdpConnector)this).ConnectAsync(new DnsEndPoint(host, port), cancellationToken);
    }

    /// <summary>
    /// Creates an <see cref="HttpClient"/> whose every connection travels through the tunnel.
    /// </summary>
    /// <returns>A client that owns its handler; dispose it when done.</returns>
    public HttpClient CreateHttpClient()
    {
        SocketsHttpHandler? handler = CreateHttpMessageHandler();

        try
        {
            HttpClient client = new(handler, disposeHandler: true);

            // The client owns the handler from here on, so the finally block must not dispose it.
            handler = null;

            return client;
        }
        finally
        {
            handler?.Dispose();
        }
    }

    /// <summary>
    /// Creates a handler for <see cref="HttpClient"/> or <c>IHttpClientFactory</c> that opens its connections through the tunnel.
    /// </summary>
    /// <returns>A handler owned by the caller.</returns>
    public SocketsHttpHandler CreateHttpMessageHandler()
    {
        return TcpConnectorExtensions.CreateHttpMessageHandler(this);
    }

    /// <summary>
    /// Closes the tunnel and every connection still open through it.
    /// </summary>
    /// <returns>A task that completes once the tunnel is closed.</returns>
    public async ValueTask DisposeAsync()
    {
        using (await _mutex.LockAsync().ConfigureAwait(continueOnCapturedContext: false))
        {
            _disposed = true;

            if (_session is not null)
                await _session.DisposeAsync().ConfigureAwait(continueOnCapturedContext: false);

            _session = null;
        }
    }

    /// <inheritdoc />
    async ValueTask<IUdpConnection> IUdpConnector.ConnectAsync(DnsEndPoint remoteEndPoint, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(remoteEndPoint);

        TunnelSession current = await GetSessionAsync(cancellationToken).ConfigureAwait(continueOnCapturedContext: false);
        IPAddress address = await current.ResolveAsync(remoteEndPoint.Host, cancellationToken).ConfigureAwait(continueOnCapturedContext: false);

        return await current.Stack.ConnectDatagramAsync(new IPEndPoint(address, remoteEndPoint.Port), cancellationToken).ConfigureAwait(continueOnCapturedContext: false);
    }

    private async ValueTask<TunnelSession> GetSessionAsync(CancellationToken cancellationToken)
    {
        using (await _mutex.LockAsync(cancellationToken).ConfigureAwait(continueOnCapturedContext: false))
        {
            ObjectDisposedException.ThrowIf(_disposed, this);

            if (_session is { IsClosed: false })
                return _session;

            // Cloudflare drops idle tunnels after a few minutes, so a closed session is replaced instead of reported.
            if (_session is not null)
                await _session.DisposeAsync().ConfigureAwait(continueOnCapturedContext: false);

            _session = await TunnelSession.OpenAsync(_options, cancellationToken).ConfigureAwait(continueOnCapturedContext: false);

            return _session;
        }
    }
}
