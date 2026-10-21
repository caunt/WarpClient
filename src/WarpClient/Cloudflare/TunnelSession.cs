using System.Net;

using Warp.Cloudflare.Registration;
using Warp.Cloudflare.Tunnel;
using Warp.Cloudflare.WireGuard;
using Warp.Networking;
using Warp.Networking.Dns;

namespace Warp.Cloudflare;

/// <summary>
/// One open layer-3 tunnel (MASQUE over HTTP/2 or WireGuard) together with the network stack and resolver inside it.
/// </summary>
internal sealed class TunnelSession : IWarpSession
{
    private readonly TunnelDnsResolver _resolver;
    private readonly UserspaceNetworkStack _stack;
    private readonly IPacketTunnel _tunnel;

    private TunnelSession(IPacketTunnel tunnel, UserspaceNetworkStack stack)
    {
        _tunnel = tunnel;
        _stack = stack;
        _resolver = new TunnelDnsResolver(stack);
    }

    public bool IsClosed => _tunnel.IsClosed;

    public static async ValueTask<TunnelSession> OpenAsync(DeviceRegistration registration, WarpClientOptions options, CancellationToken cancellationToken)
    {
        IPacketTunnel tunnel = options.Transport == WarpTransport.WireGuard
            ? await WireGuardTunnel.OpenAsync(registration, options.UdpUnderlay, cancellationToken).ConfigureAwait(continueOnCapturedContext: false)
            : await MasqueTunnel.OpenAsync(registration, options.Underlay, cancellationToken).ConfigureAwait(continueOnCapturedContext: false);

        IPAddress? localIpv6 = registration.AddressIpv6 is null ? null : IPAddress.Parse(registration.AddressIpv6);
        UserspaceNetworkStack stack = new(tunnel, IPAddress.Parse(registration.AddressIpv4), localIpv6);

        tunnel.StartReceiving(stack);

        return new TunnelSession(tunnel, stack);
    }

    public async ValueTask<Stream> ConnectTcpAsync(DnsEndPoint remoteEndPoint, CancellationToken cancellationToken)
    {
        IPAddress address = await ResolveAsync(remoteEndPoint.Host, cancellationToken).ConfigureAwait(continueOnCapturedContext: false);

        return await _stack.ConnectAsync(new IPEndPoint(address, remoteEndPoint.Port), cancellationToken).ConfigureAwait(continueOnCapturedContext: false);
    }

    public async ValueTask<IUdpConnection> ConnectUdpAsync(DnsEndPoint remoteEndPoint, CancellationToken cancellationToken)
    {
        IPAddress address = await ResolveAsync(remoteEndPoint.Host, cancellationToken).ConfigureAwait(continueOnCapturedContext: false);

        return await _stack.ConnectDatagramAsync(new IPEndPoint(address, remoteEndPoint.Port), cancellationToken).ConfigureAwait(continueOnCapturedContext: false);
    }

    public ValueTask DisposeAsync()
    {
        return _tunnel.DisposeAsync();
    }

    private async ValueTask<IPAddress> ResolveAsync(string host, CancellationToken cancellationToken)
    {
        return IPAddress.TryParse(host, out IPAddress? address)
            ? address
            : await _resolver.ResolveAsync(host, cancellationToken).ConfigureAwait(continueOnCapturedContext: false);
    }
}
