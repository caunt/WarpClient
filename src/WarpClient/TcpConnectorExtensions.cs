namespace Warp;

/// <summary>
/// Adapts connectors to the HTTP stack, so <see cref="HttpClient"/> requests travel over the same network path as raw connections.
/// </summary>
public static class TcpConnectorExtensions
{
    /// <summary>
    /// Builds an HTTP handler that opens every connection through the connector. System proxy settings are ignored,
    /// because a proxy would otherwise become the destination the connector dials instead of the requested server.
    /// </summary>
    /// <param name="connector">Network path that every HTTP connection is opened through.</param>
    /// <returns>A handler owned by the caller, ready to pass to an <see cref="HttpClient"/>.</returns>
    public static SocketsHttpHandler CreateHttpMessageHandler(this ITcpConnector connector)
    {
        ArgumentNullException.ThrowIfNull(connector);

        return new SocketsHttpHandler
        {
            UseProxy = false,
            ConnectCallback = (context, cancellationToken) => connector.ConnectAsync(context.DnsEndPoint, cancellationToken),
        };
    }
}
