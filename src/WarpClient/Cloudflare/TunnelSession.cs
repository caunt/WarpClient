using System.Net;

using Warp.Cloudflare.Registration;
using Warp.Cloudflare.Tunnel;
using Warp.Networking;
using Warp.Networking.Dns;

namespace Warp.Cloudflare;

/// <summary>
/// One open MASQUE tunnel together with the network stack and resolver that live inside it.
/// </summary>
internal sealed class TunnelSession : IAsyncDisposable
{
    private readonly MasqueTunnel _tunnel;

    private TunnelSession(MasqueTunnel tunnel, UserspaceNetworkStack stack)
    {
        this._tunnel = tunnel;
        Stack = stack;
        Resolver = new TunnelDnsResolver(stack);
    }

    public bool IsClosed => _tunnel.IsClosed;

    public TunnelDnsResolver Resolver { get; }

    public UserspaceNetworkStack Stack { get; }

    public static async ValueTask<TunnelSession> OpenAsync(WarpClientOptions options, CancellationToken cancellationToken)
    {
        DeviceRegistration registration = await DeviceRegistrationStore.LoadOrRegisterAsync(options.RegistrationPath, options.Underlay, cancellationToken)
            .ConfigureAwait(continueOnCapturedContext: false);

        MasqueTunnel tunnel = await MasqueTunnel.OpenAsync(registration, options.Underlay, cancellationToken).ConfigureAwait(continueOnCapturedContext: false);
        IPAddress? localIpv6 = registration.AddressIpv6 is null ? null : IPAddress.Parse(registration.AddressIpv6);
        UserspaceNetworkStack stack = new(tunnel, IPAddress.Parse(registration.AddressIpv4), localIpv6);

        tunnel.StartReceiving(stack);

        return new TunnelSession(tunnel, stack);
    }

    public ValueTask DisposeAsync()
    {
        return _tunnel.DisposeAsync();
    }

    public async ValueTask<IPAddress> ResolveAsync(string host, CancellationToken cancellationToken)
    {
        return IPAddress.TryParse(host, out IPAddress? address)
            ? address
            : await Resolver.ResolveAsync(host, cancellationToken).ConfigureAwait(continueOnCapturedContext: false);
    }
}
