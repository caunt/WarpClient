using System.Net;
using System.Net.Sockets;
using System.Text;

namespace Warp.Tests;

/// <summary>
/// Exercises the public connectors against loopback servers, the way consumers use them.
/// </summary>
public sealed class ConnectorTests
{
    private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(seconds: 10);

    /// <summary>
    /// The direct UDP connector must exchange datagrams with the endpoint it was opened for.
    /// </summary>
    /// <returns>A task that completes when the echo has been verified.</returns>
    [Fact]
    public async Task DirectUdpConnectorExchangesDatagrams()
    {
        using CancellationTokenSource cancellation = new(Timeout);

        using Socket server = new(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);

        server.Bind(new IPEndPoint(IPAddress.Loopback, port: 0));

        IPEndPoint serverEndPoint = Assert.IsType<IPEndPoint>(server.LocalEndPoint);

        IUdpConnection connection = await new DirectUdpConnector().ConnectAsync(new DnsEndPoint(host: "127.0.0.1", serverEndPoint.Port), cancellation.Token)
            .ConfigureAwait(continueOnCapturedContext: true);

        await using (connection.ConfigureAwait(continueOnCapturedContext: true))
        {
            byte[] request = [1, 2, 3];
            byte[] serverBuffer = new byte[16];
            byte[] reply = new byte[16];

            await connection.SendAsync(request, cancellation.Token).ConfigureAwait(continueOnCapturedContext: true);

            SocketReceiveFromResult received = await server.ReceiveFromAsync(serverBuffer, new IPEndPoint(IPAddress.Any, port: 0), cancellation.Token)
                .ConfigureAwait(continueOnCapturedContext: true);

            int sent = await server.SendToAsync(serverBuffer.AsMemory(start: 0, received.ReceivedBytes), received.RemoteEndPoint, cancellation.Token)
                .ConfigureAwait(continueOnCapturedContext: true);

            int replyLength = await connection.ReceiveAsync(reply, cancellation.Token).ConfigureAwait(continueOnCapturedContext: true);

            Assert.Equal(request.Length, sent);
            Assert.Equal(request, reply[..replyLength]);
        }
    }

    /// <summary>
    /// A proxy that refuses the destination must surface as an I/O error instead of an unusable stream.
    /// </summary>
    /// <returns>A task that completes when the refusal has been verified.</returns>
    [Fact]
    public async Task HttpProxyConnectorReportsRefusedConnect()
    {
        using CancellationTokenSource cancellation = new(Timeout);

        TaskCompletionSource<int> proxyPort = new(TaskCreationOptions.RunContinuationsAsynchronously);
        Task<string> proxyTask = RunConnectProxyAsync(statusLine: "HTTP/1.1 403 Forbidden", proxyPort, cancellation.Token);
        int port = await proxyPort.Task.ConfigureAwait(continueOnCapturedContext: true);
        HttpProxyTcpConnector connector = new(new DnsEndPoint(host: "localhost", port), new DirectTcpConnector());

        IOException failure = await Assert.ThrowsAsync<IOException>(
            async () =>
            {
                Stream unexpected = await connector.ConnectAsync(new DnsEndPoint(host: "example.com", port: 443), cancellation.Token)
                    .ConfigureAwait(continueOnCapturedContext: true);

                await unexpected.DisposeAsync().ConfigureAwait(continueOnCapturedContext: true);
            }
        ).ConfigureAwait(continueOnCapturedContext: true);

        string requestLine = await proxyTask.ConfigureAwait(continueOnCapturedContext: true);

        Assert.Contains(expectedSubstring: "403", failure.Message, StringComparison.Ordinal);
        Assert.Equal(expected: "CONNECT example.com:443 HTTP/1.1", requestLine);
    }

    /// <summary>
    /// The proxy connector must issue a CONNECT for the destination and then hand back a stream that is already tunneled.
    /// </summary>
    /// <returns>A task that completes when the exchange has been verified.</returns>
    [Fact]
    public async Task HttpProxyConnectorTunnelsThroughConnectProxy()
    {
        using CancellationTokenSource cancellation = new(Timeout);

        TaskCompletionSource<int> proxyPort = new(TaskCreationOptions.RunContinuationsAsynchronously);
        Task<string> proxyTask = RunConnectProxyAsync(statusLine: "HTTP/1.1 200 Connection established", proxyPort, cancellation.Token);
        int port = await proxyPort.Task.ConfigureAwait(continueOnCapturedContext: true);
        HttpProxyTcpConnector connector = new(new DnsEndPoint(host: "localhost", port), new DirectTcpConnector());

        Stream tunnel = await connector.ConnectAsync(new DnsEndPoint(host: "2606:4700::1111", port: 443), cancellation.Token)
            .ConfigureAwait(continueOnCapturedContext: true);

        await using (tunnel.ConfigureAwait(continueOnCapturedContext: true))
        {
            byte[] greeting = "hello"u8.ToArray();
            byte[] echoed = new byte[greeting.Length];

            await tunnel.WriteAsync(greeting, cancellation.Token).ConfigureAwait(continueOnCapturedContext: true);
            await tunnel.ReadExactlyAsync(echoed, cancellation.Token).ConfigureAwait(continueOnCapturedContext: true);

            Assert.Equal(greeting, echoed);
        }

        string requestLine = await proxyTask.ConfigureAwait(continueOnCapturedContext: true);

        Assert.Equal(expected: "CONNECT [2606:4700::1111]:443 HTTP/1.1", requestLine);
    }

    // Accepts one client, answers its CONNECT with the given status line, echoes one read if accepted and returns the request line.
    private static async Task<string> RunConnectProxyAsync(string statusLine, TaskCompletionSource<int> port, CancellationToken cancellationToken)
    {
        using TcpListener listener = new(IPAddress.Loopback, port: 0);

        listener.Start();
        port.SetResult(((IPEndPoint)listener.LocalEndpoint).Port);

        using TcpClient client = await listener.AcceptTcpClientAsync(cancellationToken).ConfigureAwait(continueOnCapturedContext: false);

        NetworkStream stream = client.GetStream();
        StringBuilder head = new();
        byte[] octet = new byte[1];

        while (!head.ToString().EndsWith(value: "\r\n\r\n", StringComparison.Ordinal))
        {
            await stream.ReadExactlyAsync(octet, cancellationToken).ConfigureAwait(continueOnCapturedContext: false);
            head = head.Append((char)octet[0]);
        }

        await stream.WriteAsync(Encoding.ASCII.GetBytes($"{statusLine}\r\n\r\n"), cancellationToken).ConfigureAwait(continueOnCapturedContext: false);

        byte[] payload = new byte[5];
        bool accepted = statusLine.Contains(value: " 200 ", StringComparison.Ordinal);
        int length = accepted ? await stream.ReadAsync(payload, cancellationToken).ConfigureAwait(continueOnCapturedContext: false) : 0;

        await stream.WriteAsync(payload.AsMemory(start: 0, length), cancellationToken).ConfigureAwait(continueOnCapturedContext: false);

        string text = head.ToString();

        return text[..text.IndexOf(value: "\r\n", StringComparison.Ordinal)];
    }
}
