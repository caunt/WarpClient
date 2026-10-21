using System.Net;
using System.Security.Cryptography;

namespace Warp.Networking;

/// <summary>
/// Resolves host names with plain DNS sent through the tunnel, so lookups never leak to the local resolver.
/// </summary>
internal sealed class TunnelDnsResolver(UserspaceNetworkStack stack)
{
    private const int MaximumResponseLength = 1232;
    private static readonly TimeSpan QueryTimeout = TimeSpan.FromSeconds(seconds: 3);
    private static readonly IPEndPoint[] Servers = [new(IPAddress.Parse(ipString: "1.1.1.1"), port: 53), new(IPAddress.Parse(ipString: "1.0.0.1"), port: 53)];

    public async ValueTask<IPAddress> ResolveAsync(string hostName, CancellationToken cancellationToken)
    {
        foreach (IPEndPoint server in Servers)
        {
            ushort identifier = (ushort)RandomNumberGenerator.GetInt32(ushort.MaxValue + 1);
            byte[] query = DnsMessage.CreateQuery(identifier, hostName);
            byte[]? response = await TryExchangeAsync(server, query, cancellationToken).ConfigureAwait(continueOnCapturedContext: false);

            if (response is not null && DnsMessage.TryReadFirstAddress(response, identifier, out IPAddress? address))
                return address;
        }

        throw new IOException($"The tunnel's DNS servers returned no IPv4 address for {hostName}.");
    }

    private async ValueTask<byte[]?> TryExchangeAsync(IPEndPoint server, byte[] query, CancellationToken cancellationToken)
    {
        TunnelUdpConnection connection = await stack.ConnectDatagramAsync(server, cancellationToken).ConfigureAwait(continueOnCapturedContext: false);

        await using (connection.ConfigureAwait(continueOnCapturedContext: false))
        {
            using CancellationTokenSource timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);

            timeout.CancelAfter(QueryTimeout);

            try
            {
                byte[] response = new byte[MaximumResponseLength];

                await connection.SendAsync(query, timeout.Token).ConfigureAwait(continueOnCapturedContext: false);

                int length = await connection.ReceiveAsync(response, timeout.Token).ConfigureAwait(continueOnCapturedContext: false);

                return response[..length];
            }
            catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
            {
                return null;
            }
        }
    }
}
