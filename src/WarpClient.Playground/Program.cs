using System.Buffers.Binary;
using System.Diagnostics;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Runtime.CompilerServices;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Text;

using Warp;

// Every check talks only to ITcpConnector / IUdpConnector, so "--direct" swaps WARP for the host's own sockets and
// "--transport=http2|wireguard|http3" picks how WARP carries them; "--account" also prints the device's Cloudflare account.
// Each step prints as it starts and fails on its own timeout, so a stall always shows where it happened.
const string headerTerminator = "\r\n\r\n";
const uint stunMagicCookie = 0x2112A442;
TimeSpan stepTimeout = TimeSpan.FromSeconds(seconds: 30);
Uri publicAddressUri = new(uriString: "https://ifconfig.me/ip");
DnsEndPoint stunServer = new(host: "stun.cloudflare.com", port: 3478);
DnsEndPoint traceServer = new(host: "2606:4700:4700::1111", port: 443);
bool direct = args.Contains(value: "--direct");
bool showAccount = args.Contains(value: "--account");
string transportName = args.FirstOrDefault(static argument => argument.StartsWith(value: "--transport=", StringComparison.Ordinal))?[12..] ?? "http2";

WarpTransport transport = transportName switch
{
    "wireguard" => WarpTransport.WireGuard,
    "http3" => WarpTransport.MasqueHttp3,
    _ => WarpTransport.MasqueHttp2,
};

Console.WriteLine($"Path: {(direct ? "direct sockets" : $"WARP over {transport}")}");

WarpClient warpClient = new(new WarpClientOptions { Transport = transport });

await using ConfiguredAsyncDisposable warpClientDisposal = warpClient.ConfigureAwait(continueOnCapturedContext: false);

ITcpConnector tcpConnector = direct ? new DirectTcpConnector() : warpClient;
IUdpConnector udpConnector = direct ? new DirectUdpConnector() : warpClient;
int failures = 0;

if (!direct && showAccount)
{
    failures += await RunAsync(
        step: "Account",
        async cancellationToken =>
        {
            WarpAccount account = await warpClient.GetAccountAsync(cancellationToken).ConfigureAwait(continueOnCapturedContext: false);

            return $"{account.AccountType}, role {account.Role}, WARP+ {(account.IsWarpPlus ? "on" : "off")}";
        }
    ).ConfigureAwait(continueOnCapturedContext: false);
}

if (!direct)
{
    int tunnelFailure = await RunAsync(
        step: "Tunnel",
        async cancellationToken =>
        {
            await warpClient.OpenAsync(cancellationToken).ConfigureAwait(continueOnCapturedContext: false);

            return "open";
        }
    ).ConfigureAwait(continueOnCapturedContext: false);

    if (tunnelFailure > 0)
        return 1;
}

using SocketsHttpHandler httpHandler = tcpConnector.CreateHttpMessageHandler();

using HttpClient httpClient = new(httpHandler, disposeHandler: false);

failures += await RunAsync(step: "HTTP", cancellationToken => httpClient.GetStringAsync(publicAddressUri, cancellationToken)).ConfigureAwait(continueOnCapturedContext: false);

failures += await RunAsync(
    step: "TCP",
    async cancellationToken =>
    {
        Stream connection = await tcpConnector.ConnectAsync(new DnsEndPoint(publicAddressUri.Host, publicAddressUri.Port), cancellationToken)
            .ConfigureAwait(continueOnCapturedContext: false);

        SslStream sslStream = new(connection);

        await using (sslStream.ConfigureAwait(continueOnCapturedContext: false))
        {
            await sslStream.AuthenticateAsClientAsync(publicAddressUri.Host).ConfigureAwait(continueOnCapturedContext: false);

            byte[] request = Encoding.ASCII.GetBytes($"GET {publicAddressUri.PathAndQuery} HTTP/1.0\r\nHost: {publicAddressUri.Host}{headerTerminator}");

            await sslStream.WriteAsync(request, cancellationToken).ConfigureAwait(continueOnCapturedContext: false);

            using StreamReader reader = new(sslStream, Encoding.ASCII);

            string response = await reader.ReadToEndAsync(cancellationToken).ConfigureAwait(continueOnCapturedContext: false);

            return response[(response.IndexOf(headerTerminator, StringComparison.Ordinal) + headerTerminator.Length)..];
        }
    }
).ConfigureAwait(continueOnCapturedContext: false);

// A STUN binding request makes the server echo back the address our UDP datagram arrived from.
failures += await RunAsync(
    step: "UDP",
    async cancellationToken =>
    {
        IUdpConnection stunConnection = await udpConnector.ConnectAsync(stunServer, cancellationToken).ConfigureAwait(continueOnCapturedContext: false);

        await using (stunConnection.ConfigureAwait(continueOnCapturedContext: false))
        {
            byte[] bindingRequest = new byte[20];
            byte[] bindingResponse = new byte[512];

            BinaryPrimitives.WriteUInt16BigEndian(bindingRequest, value: 0x0001);
            BinaryPrimitives.WriteUInt32BigEndian(bindingRequest.AsSpan(start: 4), stunMagicCookie);
            RandomNumberGenerator.Fill(bindingRequest.AsSpan(start: 8));
            await stunConnection.SendAsync(bindingRequest, cancellationToken).ConfigureAwait(continueOnCapturedContext: false);

            int responseLength = await stunConnection.ReceiveAsync(bindingResponse, cancellationToken).ConfigureAwait(continueOnCapturedContext: false);

            return ReadMappedAddress(bindingResponse.AsSpan(start: 0, responseLength)).ToString();
        }
    }
).ConfigureAwait(continueOnCapturedContext: false);

// Cloudflare's trace page reports the address a request came from and whether it arrived through WARP.
failures += await RunAsync(
    step: "IPv6",
    async cancellationToken =>
    {
        Stream traceConnection = await tcpConnector.ConnectAsync(traceServer, cancellationToken).ConfigureAwait(continueOnCapturedContext: false);
        SslStream traceStream = new(traceConnection);

        await using (traceStream.ConfigureAwait(continueOnCapturedContext: false))
        {
            await traceStream.AuthenticateAsClientAsync(targetHost: "one.one.one.one").ConfigureAwait(continueOnCapturedContext: false);
            await traceStream.WriteAsync("GET /cdn-cgi/trace HTTP/1.0\r\nHost: one.one.one.one\r\n\r\n"u8.ToArray(), cancellationToken).ConfigureAwait(continueOnCapturedContext: false);

            using StreamReader traceReader = new(traceStream, Encoding.ASCII);

            string trace = await traceReader.ReadToEndAsync(cancellationToken).ConfigureAwait(continueOnCapturedContext: false);
            string[] traceLines = trace.Split(separator: '\n');
            string traceAddress = traceLines.FirstOrDefault(static line => line.StartsWith(value: "ip=", StringComparison.Ordinal)) ?? "ip=?";
            string traceWarp = traceLines.FirstOrDefault(static line => line.StartsWith(value: "warp=", StringComparison.Ordinal)) ?? "warp=?";

            return $"{traceAddress[3..]} ({traceWarp})";
        }
    }
).ConfigureAwait(continueOnCapturedContext: false);

return failures == 0 ? 0 : 1;

async Task<int> RunAsync(string step, Func<CancellationToken, Task<string>> check)
{
    long started = Stopwatch.GetTimestamp();

    Console.Write($"{step}... ");

    using CancellationTokenSource timeout = new(stepTimeout);

    try
    {
        string result = await check(timeout.Token).ConfigureAwait(continueOnCapturedContext: false);

        Console.WriteLine($"{result.Trim()} ({Stopwatch.GetElapsedTime(started).TotalSeconds:0.0}s)");

        return 0;
    }
    catch (Exception exception) when (IsReportable(exception))
    {
        TimeSpan elapsed = Stopwatch.GetElapsedTime(started);

        Console.WriteLine($"failed after {elapsed.TotalSeconds:0.0}s: {exception.GetType().Name}: {exception.Message}");

        return 1;
    }
}

// Failures a step reports and survives; anything else (a bug in the playground itself) still crashes loudly.
static bool IsReportable(Exception exception)
{
    return exception is IOException or TimeoutException or OperationCanceledException or HttpRequestException
        or NotSupportedException or InvalidDataException or AuthenticationException or SocketException;
}

static IPAddress ReadMappedAddress(ReadOnlySpan<byte> message)
{
    const ushort xorMappedAddress = 0x0020;
    Span<byte> cookie = stackalloc byte[4];
    int offset = 20;

    BinaryPrimitives.WriteUInt32BigEndian(cookie, stunMagicCookie);

    while (offset + 4 <= message.Length)
    {
        ushort type = BinaryPrimitives.ReadUInt16BigEndian(message[offset..]);
        int length = BinaryPrimitives.ReadUInt16BigEndian(message[(offset + 2)..]);
        ReadOnlySpan<byte> value = message.Slice(offset + 4, length);

        if (type == xorMappedAddress && value[index: 1] == 1)
        {
            byte[] address = value.Slice(start: 4, length: 4).ToArray();

            for (int index = 0; index < address.Length; index++)
                address[index] ^= cookie[index];

            return new IPAddress(address);
        }

        offset += 4 + ((length + 3) / 4 * 4);
    }

    throw new InvalidDataException(message: "The STUN response has no IPv4 XOR-MAPPED-ADDRESS.");
}
