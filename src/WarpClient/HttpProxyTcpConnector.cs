using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace Warp;

/// <summary>
/// Opens TCP connections through an HTTP proxy's CONNECT method, for networks where raw outbound TCP is only allowed via
/// such a proxy.
/// </summary>
public sealed class HttpProxyTcpConnector : ITcpConnector
{
    private const int MaximumResponseHeadLength = 8192;
    private static readonly byte[] HeadTerminator = "\r\n\r\n"u8.ToArray();

    private readonly ITcpConnector _proxyConnector;
    private readonly DnsEndPoint _proxyEndPoint;

    /// <summary>
    /// Prepares a connector that tunnels every connection through the given proxy.
    /// </summary>
    /// <param name="proxyEndPoint">Host name or address and port where the proxy listens.</param>
    /// <param name="proxyConnector">Network path used to reach the proxy itself, usually a <see cref="DirectTcpConnector"/>.</param>
    public HttpProxyTcpConnector(DnsEndPoint proxyEndPoint, ITcpConnector proxyConnector)
    {
        ArgumentNullException.ThrowIfNull(proxyEndPoint);
        ArgumentNullException.ThrowIfNull(proxyConnector);

        this._proxyEndPoint = proxyEndPoint;
        this._proxyConnector = proxyConnector;
    }

    /// <inheritdoc />
    public async ValueTask<Stream> ConnectAsync(DnsEndPoint remoteEndPoint, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(remoteEndPoint);

        string authority = FormatAuthority(remoteEndPoint);
        Stream? connection = await _proxyConnector.ConnectAsync(_proxyEndPoint, cancellationToken).ConfigureAwait(continueOnCapturedContext: false);

        try
        {
            byte[] request = Encoding.ASCII.GetBytes($"CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n");

            await connection.WriteAsync(request, cancellationToken).ConfigureAwait(continueOnCapturedContext: false);

            string statusLine = await ReadStatusLineAsync(connection, cancellationToken).ConfigureAwait(continueOnCapturedContext: false);

            if (!IsSuccess(statusLine))
                throw new IOException($"The proxy refused to connect to {authority}: {statusLine}");

            Stream established = connection;

            connection = null;

            return established;
        }
        finally
        {
            if (connection is not null)
                await connection.DisposeAsync().ConfigureAwait(continueOnCapturedContext: false);
        }
    }

    private static string FormatAuthority(DnsEndPoint endPoint)
    {
        bool bracketed = IPAddress.TryParse(endPoint.Host, out IPAddress? address) && address.AddressFamily == AddressFamily.InterNetworkV6;
        string host = bracketed ? $"[{endPoint.Host}]" : endPoint.Host;

        return string.Create(CultureInfo.InvariantCulture, $"{host}:{endPoint.Port}");
    }

    private static bool IsSuccess(string statusLine)
    {
        string[] parts = statusLine.Split(separator: ' ', count: 3);

        return parts.Length >= 2 && parts[1].Length == 3 && parts[1][index: 0] == '2';
    }

    private static async ValueTask<string> ReadStatusLineAsync(Stream connection, CancellationToken cancellationToken)
    {
        // The head is read one byte at a time so that no tunneled bytes after it are consumed by accident.
        byte[] head = new byte[MaximumResponseHeadLength];
        int length = 0;

        while (!head.AsSpan(start: 0, length).EndsWith(HeadTerminator))
        {
            if (length == head.Length)
                throw new IOException(message: "The proxy response head is too long.");

            await connection.ReadExactlyAsync(head.AsMemory(length, length: 1), cancellationToken).ConfigureAwait(continueOnCapturedContext: false);
            length++;
        }

        string text = Encoding.ASCII.GetString(head, index: 0, length);

        return text[..text.IndexOf(value: "\r\n", StringComparison.Ordinal)];
    }
}
