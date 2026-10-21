using System.Net;
using System.Security.Cryptography;

namespace Warp.Networking.Dns;

/// <summary>
/// Resolves host names with plain DNS sent through the tunnel, so lookups never leak to the local resolver. IPv4 answers
/// are preferred; AAAA records are used when a name has no IPv4 address and the tunnel carries IPv6.
/// </summary>
internal sealed class TunnelDnsResolver(UserspaceNetworkStack stack)
{
    private const int MaximumResponseLength = 1232;
    private static readonly TimeSpan QueryTimeout = TimeSpan.FromSeconds(seconds: 3);
    private static readonly IPEndPoint[] Servers = [new(IPAddress.Parse(ipString: "1.1.1.1"), port: 53), new(IPAddress.Parse(ipString: "1.0.0.1"), port: 53)];

    public async ValueTask<IPAddress> ResolveAsync(string hostName, CancellationToken cancellationToken)
    {
        IPAddress? address = await QueryAsync(hostName, DnsRecordType.Address, cancellationToken).ConfigureAwait(continueOnCapturedContext: false);

        if (address is null && stack.SupportsIpv6)
            address = await QueryAsync(hostName, DnsRecordType.Ipv6Address, cancellationToken).ConfigureAwait(continueOnCapturedContext: false);

        return address ?? throw new IOException($"The tunnel's DNS servers returned no address for {hostName}.");
    }

    private async ValueTask<IPAddress?> QueryAsync(string hostName, DnsRecordType recordType, CancellationToken cancellationToken)
    {
        foreach (IPEndPoint server in Servers)
        {
            ushort identifier = (ushort)RandomNumberGenerator.GetInt32(ushort.MaxValue + 1);
            byte[] query = DnsMessage.CreateQuery(identifier, hostName, recordType);
            byte[]? response = await TryExchangeAsync(server, query, cancellationToken).ConfigureAwait(continueOnCapturedContext: false);

            if (response is not null && DnsMessage.TryReadFirstAddress(response, identifier, recordType, out IPAddress? address))
                return address;

            // An answer without records is final; only a lost query is worth asking the next server.
            if (response is not null)
                return null;
        }

        return null;
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
