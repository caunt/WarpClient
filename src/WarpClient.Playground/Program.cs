using System.Buffers.Binary;
using System.Net;
using System.Net.Security;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text;

using Warp;

// Every check below talks only to ITcpConnector / IUdpConnector, so "--direct" swaps WARP for the host's own sockets.
const string headerTerminator = "\r\n\r\n";
const uint stunMagicCookie = 0x2112A442;
Uri publicAddressUri = new(uriString: "https://ifconfig.me/ip");
DnsEndPoint stunServer = new(host: "stun.cloudflare.com", port: 3478);
bool direct = args.Contains(value: "--direct");

WarpClient warpClient = new();

await using ConfiguredAsyncDisposable warpClientDisposal = warpClient.ConfigureAwait(continueOnCapturedContext: false);

if (!direct)
{
    WarpAccount account = await warpClient.GetAccountAsync().ConfigureAwait(continueOnCapturedContext: false);

    Console.WriteLine($"Account: {account.AccountType}, role {account.Role}, WARP+ {(account.IsWarpPlus ? "on" : "off")}");
}

ITcpConnector tcpConnector = direct ? new DirectTcpConnector() : warpClient;
IUdpConnector udpConnector = direct ? new DirectUdpConnector() : warpClient;

using SocketsHttpHandler httpHandler = tcpConnector.CreateHttpMessageHandler();

using HttpClient httpClient = new(httpHandler, disposeHandler: false);

string httpClientAddress = await httpClient.GetStringAsync(publicAddressUri).ConfigureAwait(continueOnCapturedContext: false);
Console.WriteLine($"HTTP: {httpClientAddress}");

DnsEndPoint remoteEndPoint = new(publicAddressUri.Host, publicAddressUri.Port);

using Stream connection = await tcpConnector.ConnectAsync(remoteEndPoint, CancellationToken.None).ConfigureAwait(continueOnCapturedContext: false);

using SslStream sslStream = new(connection);

await sslStream.AuthenticateAsClientAsync(publicAddressUri.Host).ConfigureAwait(continueOnCapturedContext: false);

byte[] request = Encoding.ASCII.GetBytes($"GET {publicAddressUri.PathAndQuery} HTTP/1.0\r\nHost: {publicAddressUri.Host}{headerTerminator}");

await sslStream.WriteAsync(request).ConfigureAwait(continueOnCapturedContext: false);

using StreamReader reader = new(sslStream, Encoding.ASCII);

string response = await reader.ReadToEndAsync().ConfigureAwait(continueOnCapturedContext: false);
string rawHttpAddress = response[(response.IndexOf(headerTerminator, StringComparison.Ordinal) + headerTerminator.Length)..];
Console.WriteLine($"TCP: {rawHttpAddress}");

// A STUN binding request makes the server echo back the address our UDP datagram arrived from.
using CancellationTokenSource stunTimeout = new(TimeSpan.FromSeconds(seconds: 5));

IUdpConnection stunConnection = await udpConnector.ConnectAsync(stunServer, stunTimeout.Token).ConfigureAwait(continueOnCapturedContext: false);

await using (stunConnection.ConfigureAwait(continueOnCapturedContext: false))
{
    byte[] bindingRequest = new byte[20];
    byte[] bindingResponse = new byte[512];

    BinaryPrimitives.WriteUInt16BigEndian(bindingRequest, value: 0x0001);
    BinaryPrimitives.WriteUInt32BigEndian(bindingRequest.AsSpan(start: 4), stunMagicCookie);
    RandomNumberGenerator.Fill(bindingRequest.AsSpan(start: 8));
    await stunConnection.SendAsync(bindingRequest, stunTimeout.Token).ConfigureAwait(continueOnCapturedContext: false);

    int responseLength = await stunConnection.ReceiveAsync(bindingResponse, stunTimeout.Token).ConfigureAwait(continueOnCapturedContext: false);

    Console.WriteLine($"UDP: {ReadMappedAddress(bindingResponse.AsSpan(start: 0, responseLength))}");
}

// Cloudflare's trace page reports the address a request came from and whether it arrived through WARP.
DnsEndPoint traceEndPoint = new(host: "2606:4700:4700::1111", port: 443);
Stream traceConnection = await tcpConnector.ConnectAsync(traceEndPoint, CancellationToken.None).ConfigureAwait(continueOnCapturedContext: false);
SslStream traceStream = new(traceConnection);

await using (traceStream.ConfigureAwait(continueOnCapturedContext: false))
{
    await traceStream.AuthenticateAsClientAsync(targetHost: "one.one.one.one").ConfigureAwait(continueOnCapturedContext: false);
    await traceStream.WriteAsync("GET /cdn-cgi/trace HTTP/1.0\r\nHost: one.one.one.one\r\n\r\n"u8.ToArray()).ConfigureAwait(continueOnCapturedContext: false);

    using StreamReader traceReader = new(traceStream, Encoding.ASCII);

    string trace = await traceReader.ReadToEndAsync().ConfigureAwait(continueOnCapturedContext: false);
    string[] traceLines = trace.Split(separator: '\n');
    string traceAddress = traceLines.FirstOrDefault(static line => line.StartsWith(value: "ip=", StringComparison.Ordinal)) ?? "ip=?";
    string traceWarp = traceLines.FirstOrDefault(static line => line.StartsWith(value: "warp=", StringComparison.Ordinal)) ?? "warp=?";

    Console.WriteLine($"IPv6: {traceAddress[3..]} ({traceWarp})");
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
