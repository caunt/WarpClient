# WarpClient

A .NET library for sending TCP, UDP, and HTTP traffic through Cloudflare WARP. Remote services see a Cloudflare address while the calling code keeps using ordinary streams, datagrams, and `HttpClient` — no VPN, TUN device, or elevated privileges.

## Features

- Register a free WARP device on first use and reuse it afterwards.
- Open TCP streams, connected UDP associations, or `HttpClient` instances through the tunnel.
- Resolve host names inside the tunnel with 1.1.1.1, so lookups never leak to the local resolver.
- Run over HTTP/2 on TCP port 443, so it works on networks that block UDP; honours `HTTPS_PROXY`.
- Swap network paths behind `ITcpConnector` and `IUdpConnector`, with direct implementations included.

## Quick Start

```csharp
using Warp;

await using WarpClient warp = await WarpClient.CreateAsync();
using HttpClient client = warp.CreateHttpClient();

string address = await client.GetStringAsync("https://ifconfig.me/ip");
```

Raw TCP and UDP use the same client:

```csharp
await using Stream tcp = await warp.ConnectTcpAsync("example.com", 443);
await using IUdpConnection udp = await warp.ConnectUdpAsync("stun.cloudflare.com", 3478);
```

## Dependency Injection

Install `WarpClient.DependencyInjection` and register with your service collection:

```csharp
builder.Services.AddWarpClient();
builder.Services.AddHttpClient("warp").UseWarpClient();
```

`AddWarpClient` also exposes the shared client as `ITcpConnector` and `IUdpConnector`.

## Configuration

```csharp
WarpClientOptions options = new()
{
    RegistrationPath = "/var/lib/myapp/warp.json",
    Underlay = new DirectTcpConnector(),
};
```

- `RegistrationPath` holds the device's private key and access token. It defaults to `WarpClient/registration.json` in the user's application data folder and is created readable only by its owner.
- `Underlay` carries the registration API calls and the tunnel's own TCP connection. It defaults to `SystemProxyTcpConnector`, which connects directly unless the system proxy settings say otherwise.

## How It Works

1. A device is registered with Cloudflare's consumer API and an ECDSA P-256 key is enrolled for the MASQUE tunnel.
2. The client connects to Cloudflare's MASQUE endpoint with mutual TLS, pinning the server key returned at enrollment.
3. One HTTP/2 `CONNECT` stream (`cf-connect-proto: cf-connect-ip`) carries raw IPv4 packets in DATAGRAM capsules.
4. A small userspace IPv4 stack turns those packets into TCP connections and UDP datagrams.

The research behind this — registration API, WireGuard and MASQUE transports, and how community clients work — is in [`reports/`](reports/).

## Limitations

- Dual-stack inside the tunnel: IPv4 and IPv6 destinations, with A records preferred and AAAA used as a fallback.
- HTTP/2 transport only. HTTP/3 needs QUIC datagrams, which .NET does not expose yet.
- The TCP implementation favours simplicity: no congestion control, selective acknowledgments, or window scaling.
- Free WARP accounts only; Zero Trust enrollment and WARP+ licenses are not supported yet.
- Registering a device accepts Cloudflare's [terms of service](https://www.cloudflare.com/application/terms/).

## Credits

The wire protocol is undocumented; this library builds on reverse engineering by [usque](https://github.com/Diniboy1123/usque), [wgcf](https://github.com/ViRb3/wgcf), [warp-plus](https://github.com/bepass-org/warp-plus), [mihomo](https://github.com/MetaCubeX/mihomo), and [Xray-core](https://github.com/XTLS/Xray-core).
