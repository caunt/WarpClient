# WarpClient

A .NET library for sending TCP, UDP, and HTTP traffic through Cloudflare WARP. Remote services see a Cloudflare address while the calling code keeps using ordinary streams, datagrams, and `HttpClient` — no VPN, TUN device, or elevated privileges.

## Features

- Register a free WARP device on first use and reuse it afterwards.
- Open TCP streams, connected UDP associations, or `HttpClient` instances through WARP, over IPv4 and IPv6.
- Choose any transport WARP offers: MASQUE over HTTP/2 or HTTP/3, MASQUE proxy mode, or WireGuard.
- Fully managed on every platform: QUIC, TLS 1.3, WireGuard and the TCP/IP stack are implemented in C#, so nothing native such as libmsquic has to be installed.
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
| `MasqueHttp3` | TCP, UDP, IPv4, IPv6 | UDP 443 (QUIC) | The protocol of Cloudflare's own apps: IP packets travel as QUIC datagrams. |
| `MasqueHttp3Proxy` | TCP | UDP 443 (QUIC) | Proxy mode: one HTTP/3 `CONNECT` stream per connection, without an IP stack. |
| `WireGuard` | TCP, UDP, IPv4, IPv6 | UDP 2408 | The classic WARP protocol, with Cloudflare's per-device routing tag. |

```csharp
await using WarpClient warp = await WarpClient.CreateAsync(new WarpClientOptions { Transport = WarpTransport.WireGuard });
```

Both HTTP/3 transports run on WarpClient's own QUIC implementation rather than .NET's, which needs libmsquic and cannot send QUIC datagrams. Earlier releases named proxy mode `MasqueHttp3`; code compiled against them keeps getting proxy mode, while recompiled code that says `MasqueHttp3` now gets the IP tunnel, which carries UDP as well.

A device holds one tunnel key at a time, so switching between WireGuard and MASQUE re-enrolls the device's key through Cloudflare's API on the next connection. Both keys stay in the registration file.

## Accounts

```csharp
WarpAccount account = await warp.GetAccountAsync();
Console.WriteLine($"{account.AccountType}, WARP+ {account.IsWarpPlus}");
```

- `LicenseKey` binds a WARP+ license you own (from the 1.1.1.1 app) once, and remembers it.
- `TeamToken` enrolls a new device into your Cloudflare Zero Trust organization. Use the token issued by `https://<team>.cloudflareaccess.com/warp` right away; it expires quickly.

## Dependency Injection

Register with your service collection; the extensions ship in the same package:

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
- `UdpUnderlay` carries WireGuard and QUIC datagrams.

## How It Works

1. A device is registered with Cloudflare's device API, and the key its transport needs is enrolled: ECDSA P-256 for MASQUE, X25519 for WireGuard.
2. **MASQUE over HTTP/2** connects with mutual TLS, pinning the server key returned at enrollment. One `CONNECT` stream (`cf-connect-proto: cf-connect-ip`) carries raw IP packets in DATAGRAM capsules.
3. **WireGuard** runs the standard Noise IKpsk2 handshake and writes the registration's `client_id` into the reserved header bytes of every message.
4. **MASQUE over HTTP/3** opens one extended CONNECT with `:protocol cf-connect-ip`, after which every IP packet is an HTTP datagram in a QUIC DATAGRAM frame. QUIC v1 and its TLS 1.3 handshake (P-256, AES-128-GCM, the same server key pin and client certificate) are implemented in managed code on BouncyCastle.
5. With any IP tunnel, a small userspace IPv4/IPv6 stack turns packets into TCP connections and UDP datagrams, and DNS goes to 1.1.1.1 inside the tunnel.
6. **MASQUE proxy mode** skips the IP layer: each TCP connection is an HTTP/3 `CONNECT address:port` stream on a shared QUIC connection. Cloudflare refuses host names there, so they are resolved first with DNS over TCP to 1.1.1.1, carried by the proxy as well.

The research behind this — registration API, WireGuard and MASQUE transports, and how community clients work — is in [`reports/`](reports/).

## Verification

| Part | How it was verified |
| --- | --- |
| MASQUE over HTTP/2 | End to end against Cloudflare: HTTP, raw TCP, UDP (STUN), and IPv6. |
| Registration, account details, switching transports | Against Cloudflare's live device API. |
| WireGuard | End to end against Cloudflare on macOS: HTTP, raw TCP, UDP (STUN), and IPv6. Also against the independent [noiseprotocol](https://github.com/plizonczyk/noiseprotocol) implementation over loopback UDP. |
| QUIC and TLS 1.3 | RFC 9001 test vectors; against msquic over loopback with mutual TLS, flow control and a path dropping every seventh datagram. |
| MASQUE over HTTP/3 | End to end against Cloudflare on macOS: HTTP, raw TCP, UDP (STUN), and IPv6. Also against an [aioquic](https://github.com/aiortc/aioquic) stand-in over loopback. |
| MASQUE proxy mode | Against the aioquic stand-in over loopback, including DNS through the proxy. Against Cloudflare, the handshake succeeds and CONNECT by host name is refused with HTTP 403; connecting by resolved address is not yet confirmed. |
| WARP+ licenses, Zero Trust | Implemented from community research; not yet exercised. |

## Limitations

- HTTP/3 proxy mode carries TCP only.
- QUIC sends 1350-byte packets without path MTU discovery, and offers only the TLS profile Cloudflare uses: P-256 key exchange and ECDSA P-256 server keys.
- Some networks block every path to WARP: UDP is refused, Cloudflare's MASQUE addresses are filtered (162.159.198.2 times out from some countries), or a transparent proxy routes TLS by server name, which drops MASQUE because its server names have no DNS records. An HTTP proxy in `Underlay` (used by default from `HTTPS_PROXY`) avoids the last one.
- WireGuard does not answer cookie replies, which Cloudflare only sends under load.
- The TCP implementation favours simplicity: no congestion control or selective acknowledgments. It does scale windows, hold segments that arrive past a gap, fast-retransmit after three duplicate acknowledgments, and follow the measured round trip for its retransmission timeout.
- Registering a device accepts Cloudflare's [terms of service](https://www.cloudflare.com/application/terms/).

## Credits

The wire protocols are undocumented; this library builds on reverse engineering by [usque](https://github.com/Diniboy1123/usque), [wgcf](https://github.com/ViRb3/wgcf), [warp-plus](https://github.com/bepass-org/warp-plus), [mihomo](https://github.com/MetaCubeX/mihomo), and [Xray-core](https://github.com/XTLS/Xray-core).
