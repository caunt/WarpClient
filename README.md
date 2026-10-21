# WarpClient

A .NET library for sending TCP, UDP, and HTTP traffic through Cloudflare WARP. Remote services see a Cloudflare address while the calling code keeps using ordinary streams, datagrams, and `HttpClient` — no VPN, TUN device, or elevated privileges.

## Features

- Register a free WARP device on first use and reuse it afterwards.
- Open TCP streams, connected UDP associations, or `HttpClient` instances through WARP, over IPv4 and IPv6.
- Choose the transport WARP offers: MASQUE over HTTP/2, WireGuard, or MASQUE proxy mode over HTTP/3.
- Resolve host names inside the tunnel with 1.1.1.1, so lookups never leak to the local resolver.
- Bind your own WARP+ license, enroll into your Cloudflare Zero Trust organization, and read account details.
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

## Transports

| `WarpTransport` | Carries | Runs over | Notes |
| --- | --- | --- | --- |
| `MasqueHttp2` (default) | TCP, UDP, IPv4, IPv6 | TCP 443 | Works wherever HTTPS does, including through HTTP proxies. |
| `WireGuard` | TCP, UDP, IPv4, IPv6 | UDP 2408 | The classic WARP protocol, with Cloudflare's per-device routing tag. |
| `MasqueHttp3` | TCP | UDP 443 (QUIC) | Proxy mode: one HTTP/3 `CONNECT` stream per connection; Cloudflare resolves names. Needs libmsquic on Linux and macOS (see below). |

```csharp
await using WarpClient warp = await WarpClient.CreateAsync(new WarpClientOptions { Transport = WarpTransport.WireGuard });
```

HTTP/3 uses .NET's QUIC support, which loads libmsquic: install the `libmsquic` package on Linux; on macOS run `brew install libmsquic` and start the app with `DYLD_FALLBACK_LIBRARY_PATH=/opt/homebrew/lib`, because .NET does not search Homebrew's folder.

A device holds one tunnel key at a time, so switching between WireGuard and MASQUE re-enrolls the device's key through Cloudflare's API on the next connection. Both keys stay in the registration file.

## Accounts

```csharp
WarpAccount account = await warp.GetAccountAsync();
Console.WriteLine($"{account.AccountType}, WARP+ {account.IsWarpPlus}");
```

- `LicenseKey` binds a WARP+ license you own (from the 1.1.1.1 app) once, and remembers it.
- `TeamToken` enrolls a new device into your Cloudflare Zero Trust organization. Use the token issued by `https://<team>.cloudflareaccess.com/warp` right away; it expires quickly.

## Dependency Injection

Install `WarpClient.DependencyInjection` and register with your service collection:

```csharp
builder.Services.AddWarpClient(options => options.Transport = WarpTransport.MasqueHttp2);
builder.Services.AddHttpClient("warp").UseWarpClient();
```

`AddWarpClient` also exposes the shared client as `ITcpConnector` and `IUdpConnector`.

## Configuration

```csharp
WarpClientOptions options = new()
{
    RegistrationPath = "/var/lib/myapp/warp.json",
    Underlay = new DirectTcpConnector(),
    UdpUnderlay = new DirectUdpConnector(),
};
```

- `ConnectTimeout` (20 seconds by default) bounds registration requests and opening a transport, so an unreachable endpoint fails with a `TimeoutException` instead of waiting.
- `RegistrationPath` holds the device's private keys and access token. It defaults to `WarpClient/registration.json` in the user's application data folder and is created readable only by its owner.
- `Underlay` carries the registration API calls and the HTTP/2 tunnel's TCP connection. It defaults to `SystemProxyTcpConnector`, which connects directly unless the system proxy settings say otherwise.
- `UdpUnderlay` carries WireGuard datagrams. HTTP/3 uses its own QUIC socket.

## How It Works

1. A device is registered with Cloudflare's device API, and the key its transport needs is enrolled: ECDSA P-256 for MASQUE, X25519 for WireGuard.
2. **MASQUE over HTTP/2** connects with mutual TLS, pinning the server key returned at enrollment. One `CONNECT` stream (`cf-connect-proto: cf-connect-ip`) carries raw IP packets in DATAGRAM capsules.
3. **WireGuard** runs the standard Noise IKpsk2 handshake and writes the registration's `client_id` into the reserved header bytes of every message.
4. With either IP tunnel, a small userspace IPv4/IPv6 stack turns packets into TCP connections and UDP datagrams, and DNS goes to 1.1.1.1 inside the tunnel.
5. **MASQUE over HTTP/3** skips the IP layer: each TCP connection is an HTTP/3 `CONNECT host:port` stream on a shared QUIC connection.

The research behind this — registration API, WireGuard and MASQUE transports, and how community clients work — is in [`reports/`](reports/).

## Verification

| Part | How it was verified |
| --- | --- |
| MASQUE over HTTP/2 | End to end against Cloudflare: HTTP, raw TCP, UDP (STUN), and IPv6. |
| Registration, account details, switching transports | Against Cloudflare's live device API. |
| WireGuard | End to end against Cloudflare on macOS: HTTP, raw TCP, UDP (STUN), and IPv6. Also against the independent [noiseprotocol](https://github.com/plizonczyk/noiseprotocol) implementation over loopback UDP. |
| MASQUE over HTTP/3 | QPACK and HTTP/3 framing unit tests; not yet against Cloudflare's endpoint. |
| WARP+ licenses, Zero Trust | Implemented from community research; not yet exercised. |

## Limitations

- MASQUE's IP tunnel over HTTP/3 (CONNECT-IP with QUIC datagrams) is not offered, because .NET does not expose QUIC datagrams yet.
- HTTP/3 proxy mode carries TCP only, and .NET picks the QUIC connection IDs; Cloudflare's own client uses 20-byte IDs.
- WireGuard does not answer cookie replies, which Cloudflare only sends under load.
- The TCP implementation favours simplicity: no congestion control, selective acknowledgments, or window scaling.
- Registering a device accepts Cloudflare's [terms of service](https://www.cloudflare.com/application/terms/).

## Credits

The wire protocols are undocumented; this library builds on reverse engineering by [usque](https://github.com/Diniboy1123/usque), [wgcf](https://github.com/ViRb3/wgcf), [warp-plus](https://github.com/bepass-org/warp-plus), [mihomo](https://github.com/MetaCubeX/mihomo), and [Xray-core](https://github.com/XTLS/Xray-core).
