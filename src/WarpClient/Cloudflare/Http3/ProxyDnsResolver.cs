using System.Buffers.Binary;
using System.Net;
using System.Security.Cryptography;

using Warp.Networking.Dns;

namespace Warp.Cloudflare.Http3;

/// <summary>
/// Resolves host names for proxy mode with DNS over TCP (RFC 7766) to 1.1.1.1, carried in a CONNECT stream through the
/// proxy itself, so lookups never leak to the local resolver. IPv4 answers are preferred.
/// </summary>
internal sealed class ProxyDnsResolver(MasqueHttp3Connection connection)
{
    private const int LengthPrefix = 2;
    private static readonly TimeSpan QueryTimeout = TimeSpan.FromSeconds(seconds: 5);
    private static readonly IPEndPoint[] Servers = [new(IPAddress.Parse(ipString: "1.1.1.1"), port: 53), new(IPAddress.Parse(ipString: "1.0.0.1"), port: 53)];

    public async ValueTask<IPAddress> ResolveAsync(string hostName, CancellationToken cancellationToken)
    {
        List<Exception> failures = [];

        foreach (IPEndPoint server in Servers)
        {
            IPAddress? address;

            try
            {
                address = await ResolveWithAsync(server, hostName, cancellationToken).ConfigureAwait(continueOnCapturedContext: false);
            }
            catch (OperationCanceledException exception) when (!cancellationToken.IsCancellationRequested)
            {
                failures.Add(exception);

                continue;
            }
            catch (IOException exception)
            {
                failures.Add(exception);

                continue;
            }

            // An answer without records is final; only a server that cannot be reached is worth replacing.
            return address ?? throw new IOException($"Cloudflare's DNS returned no address for {hostName}.");
        }

        throw new IOException($"Cloudflare's DNS servers could not be reached through the proxy to resolve {hostName}.", new AggregateException(failures));
    }

    private static async ValueTask<IPAddress?> QueryAsync(Stream stream, string hostName, DnsRecordType recordType, CancellationToken cancellationToken)
    {
        ushort identifier = (ushort)RandomNumberGenerator.GetInt32(ushort.MaxValue + 1);
        byte[] query = DnsMessage.CreateQuery(identifier, hostName, recordType);
        byte[] framed = new byte[LengthPrefix + query.Length];

        BinaryPrimitives.WriteUInt16BigEndian(framed, (ushort)query.Length);
        query.CopyTo(framed, LengthPrefix);
        await stream.WriteAsync(framed, cancellationToken).ConfigureAwait(continueOnCapturedContext: false);

        byte[] prefix = new byte[LengthPrefix];

        await stream.ReadExactlyAsync(prefix, cancellationToken).ConfigureAwait(continueOnCapturedContext: false);

        byte[] response = new byte[BinaryPrimitives.ReadUInt16BigEndian(prefix)];

        await stream.ReadExactlyAsync(response, cancellationToken).ConfigureAwait(continueOnCapturedContext: false);

        return DnsMessage.TryReadFirstAddress(response, identifier, recordType, out IPAddress? address) ? address : null;
    }

    private async ValueTask<IPAddress?> ResolveWithAsync(IPEndPoint server, string hostName, CancellationToken cancellationToken)
    {
        using CancellationTokenSource timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);

        timeout.CancelAfter(QueryTimeout);

        Stream stream = await Http3ProxySession.ConnectAsync(connection, server, timeout.Token).ConfigureAwait(continueOnCapturedContext: false);

        await using (stream.ConfigureAwait(continueOnCapturedContext: false))
        {
            return await QueryAsync(stream, hostName, DnsRecordType.Address, timeout.Token).ConfigureAwait(continueOnCapturedContext: false)
                ?? await QueryAsync(stream, hostName, DnsRecordType.Ipv6Address, timeout.Token).ConfigureAwait(continueOnCapturedContext: false);
        }
    }
}
