# Userspace WARP proxy architecture (SOCKS5/HTTP → userspace TCP/IP → WireGuard/MASQUE) and .NET implications

Research date: 2026-10-21. All code was read from GitHub at the commits and dates given. No tool was run and nothing connected to Cloudflare. Repo HEADs used:
- windtf/wireproxy `35cce290db` (2026-10-12; `pufferffish/wireproxy` now redirects here).
- bepass-org/warp-plus `f70ea7e4f1` (2025-11-17; last release v1.2.6, 2025-06-04).
- Diniboy1123/usque `6aa03fc97d` (2026-07-20, v4.2.1).
- WireGuard/wireguard-go `2631ce99a0` (2026-10-06).
- SagerNet/sing-box `testing` branch (pushed 2026-10-13; v1.14.3, 2026-10-09).
- XTLS/Xray-core `0f3d884786` (2026-10-16).

The shared pattern in all these tools is simple:
1. A local listener (SOCKS5/HTTP/port-forward) accepts a TCP connection.
2. The tool calls `DialContext(target)` on a userspace network stack, usually gVisor `tcpip` wrapped by `golang.zx2c4.com/wireguard/tun/netstack`.
3. That stack emits raw IP packets into a virtual `tun.Device`.
4. Either a wireguard-go `device.Device` encrypts the packets into WireGuard UDP datagrams, or a CONNECT-IP client sends them as HTTP/3 datagrams (MASQUE).
5. Return traffic goes the opposite way, and the tool copies bytes between the two `net.Conn`s.

The big change in 2026 is that Cloudflare's own client and usque now offer an **L4 mode**. It opens one HTTP/3 `CONNECT host:port` stream per proxied TCP connection, so no userspace TCP/IP stack is needed. Xray-core has also dropped gVisor for its own small stack.

---

## Q1. pufferffish/wireproxy (now windtf/wireproxy; formerly octeep/wireproxy)

### Takeaway
wireproxy is a thin wrapper around three pieces: the stock wireguard-go `device.Device`, the gVisor-based `tun/netstack` from wireguard-go, and the `things-go/go-socks5` library. It exposes SOCKS5, HTTP CONNECT/GET, transparent SNI, TCP client/server/STDIO tunnels and a UDP port-forwarder. It has no setting for the WireGuard `reserved` bytes, which some WARP setups need. SOCKS5 UDP ASSOCIATE now works implicitly through go-socks5, even though the README still lists it as TODO.

### Cited Findings
- **Repo identity.** The GitHub API resolves `pufferffish/wireproxy` to `windtf/wireproxy`, and `go.mod` declares `module github.com/windtf/wireproxy` (Go 1.26.0). Latest release is v1.1.3 (2026-07-16); latest commit is 2026-10-12. — [go.mod](https://github.com/windtf/wireproxy/blob/35cce290db/go.mod)
- **Dependencies:**
  - `golang.zx2c4.com/wireguard v0.0.0-20250521234502-f333402bd9cb`
  - `gvisor.dev/gvisor v0.0.0-20250503011706-39ed1f5ac29c` (indirect, via wireguard-go netstack)
  - `github.com/things-go/go-socks5 v0.1.3`
  - `go-ini`
  - `landlock-lsm/go-landlock` and `suah.dev/protect` (pledge/unveil sandboxing)
  - Source: [go.mod](https://github.com/windtf/wireproxy/blob/35cce290db/go.mod), [cmd/wireproxy/main.go](https://github.com/windtf/wireproxy/blob/35cce290db/cmd/wireproxy/main.go#L40-L120)
- **Core wiring (`StartWireguard`):**
  - Builds a UAPI/IPC text request (`private_key=`, `public_key=`, `endpoint=`, `allowed_ip=`, …). If a peer has no AllowedIPs it defaults to `0.0.0.0/0` and `::0/0`.
  - Calls `netstack.CreateNetTUN(DeviceAddr, DNS, MTU)`, then `device.NewDevice(tun, conn.NewDefaultBind(), logger)`, then `dev.IpcSet(...)` and `dev.Up()`.
  - Source: [wireguard.go](https://github.com/windtf/wireproxy/blob/35cce290db/wireguard.go#L26-L83)
- **Default MTU** is 1420 unless `MTU =` is set in `[Interface]`. — [config.go](https://github.com/windtf/wireproxy/blob/35cce290db/config.go#L620-L640)
- **The netstack itself** (wireguard-go `tun/netstack`):
  - Creates a gVisor stack with IPv4/IPv6, TCP/UDP/ICMPv4/ICMPv6 and `HandleLocal: true`, attached to a `channel.New(1024, mtu, "")` link endpoint.
  - Explicitly turns on TCP SACK ("TCP SACK is disabled by default").
  - Offers `DialContextTCP`, `DialUDP`, `ListenTCP`, `DialPing` (ICMP) and a built-in DNS client `LookupContextHost` that queries the configured DNS servers *through* the stack.
  - Source: [tun/netstack/tun.go](https://github.com/WireGuard/wireguard-go/blob/2631ce99a0/tun/netstack/tun.go#L55-L72) (file last changed 2025-05-05, "cleanup network stack at closing time")
- **SOCKS5 data flow:**
  - With no split-routing config, the server is built with `socks5.WithDial(vt.Tnet.DialContext)` and `socks5.WithResolver(vt)`. Every CONNECT is dialed inside the netstack, and FQDNs are resolved by wireproxy before dialing.
  - Buffers come from a 256 KiB pool (`bufferpool.NewPool(256 * 1024)`).
  - Optional username/password auth.
  - Source: [routine.go](https://github.com/windtf/wireproxy/blob/35cce290db/routine.go#L199-L235)
- **Split routing (new):**
  - `TunnelDomains` takes RE2 regexes; `LogDomains` logs routing decisions.
  - When set, the server uses `WithDialAndRequest(routedSocks5Dial)` with a `passthroughResolver` so the FQDN survives to the dial step. Matching hosts go to `Tnet.DialContext`; everything else goes to a normal `net.Dialer`.
  - Available in `[Socks5]`, `[http]` and `[SNI]`.
  - Source: [routine.go](https://github.com/windtf/wireproxy/blob/35cce290db/routine.go#L165-L235), [README](https://github.com/windtf/wireproxy/blob/35cce290db/README.md)
- **DNS handling:**
  - `LookupAddr` uses `net.DefaultResolver` (the host OS resolver) when `SystemDNS` is true, which happens when no `DNS =` is configured. Otherwise it uses `Tnet.LookupContextHost`, i.e. DNS over the tunnel.
  - `[Resolve] ResolveStrategy` = `ipv4` / `ipv6` / `auto`. `auto` means ipv4 if the interface has only a v4 address, else ipv6.
  - Results are shuffled and **only the first address is returned**.
  - Source: [routine.go](https://github.com/windtf/wireproxy/blob/35cce290db/routine.go#L66-L121), [wireguard.go](https://github.com/windtf/wireproxy/blob/35cce290db/wireguard.go#L85-L113)
- **Modes**, as listed in the README sample config:
  - `[TCPClientTunnel]`: local listen → `Tnet.DialTCP` to the target.
  - `[TCPServerTunnel]`: listen on a port *inside* the WireGuard network → forward to the local network.
  - `[STDIOTunnel]`: for ssh `ProxyCommand`.
  - `[Socks5]`, `[http]` (optionally HTTPS via `CertFile`/`KeyFile`), `[SNI]` (transparent TLS proxy routed by SNI).
  - `[UDPProxyTunnel]`: static UDP forward with `InactivityTimeout`.
  - Multiple peers routed by AllowedIPs; `WGConfig =` imports an existing wg-quick file.
  - Source: [README](https://github.com/windtf/wireproxy/blob/35cce290db/README.md)
- **HTTP proxy** handles only `CONNECT` and `GET`; other methods get 405. — [http.go](https://github.com/windtf/wireproxy/blob/35cce290db/http.go#L120-L130)
- **UDPProxyTunnel** keeps a per-source-address session map. Each session does `vt.Tnet.Dial("udp", conf.Target)`, and an inactivity reaper closes idle sessions. — [udp_proxy.go](https://github.com/windtf/wireproxy/blob/35cce290db/udp_proxy.go#L44-L147)
- **SOCKS5 UDP ASSOCIATE:**
  - PR #224 (merged 2026-09-17) bumped go-socks5 to v0.1.3. Before that, the UDP relay socket was bound to 0.0.0.0, which "could let anyone on the local network piggyback through the WireGuard tunnel". The PR says "UDP ASSOCIATE remains enabled."
  - Meanwhile the README "TODO" still says "UDP Support in SOCKS5". Issue #30 (UDP Support, 2022) and #221 (2026-08-29, "UDP support desparately needed") are both still open.
  - Source: [PR #224](https://github.com/windtf/wireproxy/pull/224), [README](https://github.com/windtf/wireproxy/blob/35cce290db/README.md), [issue #221](https://github.com/windtf/wireproxy/issues/221)
- **How go-socks5 routes UDP.** Its `handleAssociate` dials each UDP destination with `sf.dial`. If `sf.dial` is nil it falls back to `net.Dial`. — [things-go/go-socks5 handle.go](https://github.com/things-go/go-socks5/blob/master/handle.go#L181-L265)
- **Health checks:**
  - `-i/--info addr` starts an HTTP server.
  - `/metrics` returns the wireguard-go IPC dump (the same as `wg show`).
  - `/readyz` returns 200/503 based on ICMP pings to `CheckAlive` IPs, sent through the netstack every `CheckAliveInterval` seconds (default 5, with 2 s leeway).
  - Source: [README](https://github.com/windtf/wireproxy/blob/35cce290db/README.md), [routine.go `pingIPs`](https://github.com/windtf/wireproxy/blob/35cce290db/routine.go#L473-L580)
- **No reserved-bytes support.** The config parser has no `Reserved` key. Issue #72 "Make reserved field configurable" (opened 2023-06-11, still open) explains that "some backend (cloudflare warp) use this as client-id". A commenter asks for it so WARP works "in LA and HK". — [issue #72](https://github.com/windtf/wireproxy/issues/72), [config.go](https://github.com/windtf/wireproxy/blob/35cce290db/config.go)
- **AmneziaWG fork.** The README points users who need AmneziaWG to a separate fork, `artem-russkikh/wireproxy-awg`. — [README](https://github.com/windtf/wireproxy/blob/35cce290db/README.md)

### Inferences
- **Using wireproxy with WARP:** you generate a profile with wgcf, then point `WGConfig =` at it or paste `[Interface]`/`[Peer]` into the config. If Cloudflare requires the client-id/reserved bytes for that account or colo, wireproxy cannot connect. sing-box, Xray or warp-plus can, because they support reserved.
- **Possible UDP leak in split-routing mode.** In split-routing mode only `WithDialAndRequest` is set and `sf.dial` stays nil. go-socks5's UDP ASSOCIATE would then dial UDP **directly** via `net.Dial`, bypassing the tunnel. In legacy mode, UDP goes through `Tnet.DialContext`. This comes from reading the code and has not been tested.
- **DNS leak by default.** If `DNS =` is omitted, every hostname is resolved by the host OS resolver, so DNS queries leave outside the tunnel.
- **Weak IPv6/dual-stack behaviour.** The resolver returns a single address, there is no happy-eyeballs, and there is no fallback to the other address family.

### Gaps
- I did not find a maintainer statement about whether UDP ASSOCIATE through go-socks5 is officially supported. The README and the PR #224 description disagree.

---

## Q2. bepass-org/warp-plus

### Takeaway
warp-plus vendors a **forked wireguard-go** that adds `reserved` and `trick` (junk-packet obfuscation) UAPI keys. Its netstack uses the SagerNet gVisor fork. It puts its own "mixed" HTTP/SOCKS4/SOCKS5 proxy in front, which dials `tnet.Dial(network, host:port)`, so hostnames are resolved inside the tunnel. Modes are:
- plain WARP;
- generic `--wgconf`;
- `--gool` (warp-in-warp, which nests two netstacks through a local UDP forwarder);
- `--cfon` (Psiphon chained over the WARP SOCKS proxy);
- `--scan` (endpoint scanner).

The project has been quiet since late 2025.

### Cited Findings
- **Activity.** Last commit 2025-11-17 ("Upgrade Go toolchain support to 1.23+"); last release v1.2.6 (2025-06-04). — [repo](https://github.com/bepass-org/warp-plus/commits/master)
- **Dependencies:**
  - `github.com/sagernet/gvisor v0.0.0-20241123041152-536d05261cff`, `github.com/sagernet/sing v0.6.10`
  - Psiphon tunnel-core, `refraction-networking/utls`, `flynn/noise`
  - In-tree `wireguard/` fork; its netstack imports `github.com/sagernet/gvisor/pkg/tcpip/...`
  - Source: [go.mod](https://github.com/bepass-org/warp-plus/blob/f70ea7e4f1/go.mod), [wireguard/tun/netstack/tun.go](https://github.com/bepass-org/warp-plus/blob/f70ea7e4f1/wireguard/tun/netstack/tun.go#L27-L34)
- **Device setup (`establishWireguard`):**
  - Writes an IPC request that includes the non-standard `trick=%s` and `reserved=%d,%d,%d` lines, plus optional `fwmark`.
  - Creates `device.NewDevice(tunDev, conn.NewDefaultBind(), ...)`.
  - Then polls `IpcGet()` for `last_handshake_time_sec != 0` with a 15 s deadline.
  - Source: [app/wg.go](https://github.com/bepass-org/warp-plus/blob/f70ea7e4f1/app/wg.go#L53-L139)
- **Fork UAPI parsing.** It parses `trick` and `reserved` (3 bytes). The `t1`/`t2` tricks send 20–50 random junk packets (t2 uses a fake QUIC-like header) before handshakes and keepalives; `t0` disables them. — [wireguard/device/uapi.go](https://github.com/bepass-org/warp-plus/blob/f70ea7e4f1/wireguard/device/uapi.go#L389-L410), [wireguard/device/send.go](https://github.com/bepass-org/warp-plus/blob/f70ea7e4f1/wireguard/device/send.go#L96-L130)
- **MTU and liveness test:**
  - Hard-coded `singleMTU = 1330` and `doubleMTU = 1280` ("minimum mtu for IPv6, may cause frag reassembly somewhere"), used for the inner tunnel in gool.
  - After the handshake it runs a userspace HTTP HEAD connectivity test (`--test-url`, default `http://connectivity.cloudflareclient.com/cdn-cgi/trace`) over `tnet.DialContext`.
  - Source: [app/app.go](https://github.com/bepass-org/warp-plus/blob/f70ea7e4f1/app/app.go#L20-L35), [app/wg.go](https://github.com/bepass-org/warp-plus/blob/f70ea7e4f1/app/wg.go#L20-L50)
- **Gool (warp-in-warp):**
  - Brings up an outer netstack `tnet1` (MTU 1330).
  - `wiresocks.NewVtunUDPForwarder(127.0.0.1:0, endpoint, tnet1, 1330)` creates a local UDP port that relays into the outer tunnel.
  - A second WireGuard device (MTU 1280, trick `t0`) uses that local port as its peer endpoint, and gets its own netstack `tnet2`. The SOCKS proxy is served from `tnet2`.
  - Source: [app/app.go](https://github.com/bepass-org/warp-plus/blob/f70ea7e4f1/app/app.go#L240-L355)
- **Psiphon mode** starts the WARP proxy on `127.0.0.1:0`, then runs Psiphon, which uses that proxy as upstream, on the user bind address. — [app/app.go](https://github.com/bepass-org/warp-plus/blob/f70ea7e4f1/app/app.go#L360-L430)
- **CLI flags:**
  - `-b` bind (default 127.0.0.1:8086), `--dns` (default 1.1.1.1)
  - `--gool`, `--cfon --country`
  - `--scan --rtt`
  - `--reserved '1,2,3'`, `--wgconf`, `--fwmark`, `-4/-6`
  - Source: [README](https://github.com/bepass-org/warp-plus/blob/f70ea7e4f1/README.md)
- **Proxy path:**
  - `wiresocks.StartProxy` builds `mixed.NewProxy`, which accepts HTTP, SOCKS5/5h and SOCKS4/4a on one port, with a user handler.
  - `generalHandler` calls `vt.Tnet.Dial(req.Network, req.Destination)`. The destination may be a hostname, which is resolved by the netstack's built-in DNS client against `--dns` *inside* the tunnel.
  - It then copies in both directions with 64 KiB pooled buffers (`sing/common/buf`).
  - UDP flows get a 15 s idle read deadline.
  - Source: [wiresocks/proxy.go](https://github.com/bepass-org/warp-plus/blob/f70ea7e4f1/wiresocks/proxy.go#L33-L118), [proxy/README.md](https://github.com/bepass-org/warp-plus/blob/f70ea7e4f1/proxy/README.md)
- **SOCKS5 UDP ASSOCIATE.** It is implemented, but with a user handler set, the server "wait[s] for first packet so that target sender and receiver get known". It then hands one `ProxyRequest{Network:"udp", Destination: firstTarget}` to the handler, which does a single `Tnet.Dial("udp", target)`. — [proxy/pkg/socks5/server.go](https://github.com/bepass-org/warp-plus/blob/f70ea7e4f1/proxy/pkg/socks5/server.go#L303-L349)
- **Reported problems:**
  - "Unexplainably high memory usage" (~70 MB with `--scan --gool`, versus ≤30 MB for sing-box/xray), issue #177, opened 2024-06-29, open. — [issue #177](https://github.com/bepass-org/warp-plus/issues/177)
  - Issue search also shows open UDP issues: "UDP Connection Problem in gool mode" #265 and "Not support udp" #251. — [issues](https://github.com/bepass-org/warp-plus/issues?q=udp)

### Inferences
- warp-plus's UDP ASSOCIATE effectively pins each association to its **first** destination. That breaks clients that send to many peers from one association, such as DHT/BitTorrent or QUIC with connection migration. This is a limitation of the design, not just a bug.
- **Why warp-plus works where wireproxy does not.** It supports reserved bytes, and it runs the scanner and liveness test before exposing the proxy. Both matter for WARP specifically.
- In gool mode every packet goes through two gVisor stacks and two layers of WireGuard crypto. Together with the fixed 1330/1280 MTUs, this explains the extra CPU and memory.

### Gaps
- The scanner (`ipscanner/`) and the `warp/` registration code are out of scope and were not analyzed.
- Whether the t1/t2 "tricks" are still useful against current DPI was not researched.

---

## Q3. Diniboy1123/usque (MASQUE)

### Takeaway
usque's "full" modes (`socks`, `http-proxy`, `portfw`) reuse wireguard-go's gVisor `tun/netstack` **without** any WireGuard device. A pump loop (`MaintainTunnel`) moves raw IP packets between the netstack and a `connect-ip-go` (RFC 9484, `cf-connect-ip`) session carried over quic-go HTTP/3 datagrams.

Since June 2026 usque also has **L4 modes** (`l4-socks`, `l4-http-proxy`). These open one HTTP/3 `CONNECT host:port` request stream per TCP connection over a single shared QUIC connection, with no IP stack and no datagrams. This mirrors what Cloudflare's official client switched to.

### Cited Findings
- **Dependencies:** `github.com/Diniboy1123/connect-ip-go` (a fork), `quic-go v0.60.0`, `golang.zx2c4.com/wireguard v0.0.0-20260522210424-ecfc5a8d5446` (for netstack only), `gvisor.dev/gvisor v0.0.0-20260616165937`, `txthinking/socks5`, `songgao/water` (native TUN). — [go.mod](https://github.com/Diniboy1123/usque/blob/6aa03fc97d/go.mod)
- **Commands:** `register`, `enroll`, `nativetun`, `socks`, `http-proxy`, `l4-socks`, `l4-http-proxy`, `portfw`. — [README](https://github.com/Diniboy1123/usque/blob/6aa03fc97d/README.md)
- **Full SOCKS mode wiring:**
  - `netstack.CreateNetTUN(localAddresses, dnsAddrs, mtu)`.
  - `go api.MaintainTunnel(..., Device: api.NewNetstackAdapter(tunDev), MTU: mtu, ReconnectDelay, KeepalivePeriod, ...)`.
  - A SOCKS5 server whose dialer is the netstack `Net`.
  - Flags: `--mtu` default 1280, with a warning that a different MTU "is not supported. Packet loss and other issues may occur"; `--keepalive-period` 30 s; `--reconnect-delay` 1 s; `--always-reconnect`; `--initial-packet-size`; `-d` DNS (default Quad9 9.9.9.9/149.112.112.112/2620:fe::fe/2620:fe::9); `-l` local DNS; `--system-dns`.
  - Source: [cmd/socks.go](https://github.com/Diniboy1123/usque/blob/6aa03fc97d/cmd/socks.go#L171-L318)
- **The pump (`MaintainTunnel`):**
  - Reads packets from the device into pooled buffers with headroom for the datagram context ID.
  - Calls `ipConn.WritePacketBuffer(...)`. If that returns an ICMP packet (for example PTB/unreachable), the ICMP is written back into the device.
  - In the other direction, `ipConn.ReadPacketZeroCopy(true)` → `Device.WritePacket`.
  - If the tunnel is idle it waits for outbound activity before reconnecting, unless `AlwaysReconnect` is set.
  - Source: [api/tunnel.go](https://github.com/Diniboy1123/usque/blob/6aa03fc97d/api/tunnel.go#L216-L410)
- **Tunnel session setup.** QUIC is configured with `EnableDatagrams: true`. The tunnel is opened with `connectip.Dial(ctx, hconn, template, "cf-connect-ip", headers, true)`. The HTTP/2 fallback sets a `cf-connect-proto: cf-connect-ip` header. — [internal/utils.go](https://github.com/Diniboy1123/usque/blob/6aa03fc97d/internal/utils.go#L125-L140), [api/masque.go](https://github.com/Diniboy1123/usque/blob/6aa03fc97d/api/masque.go#L109-L210)
- **L4 mode (`api/l4proxy.go`)**, described in the source as "L4Proxy opens one HTTP/3 CONNECT stream for each proxied TCP connection":
  - `getOrCreateClientConn` lazily creates **one** cached `quic.Transport{ConnectionIDLength: 20}` connection plus an `http3.ClientConn`. The source notes that "without ConnectionIDLength set, backend occasionally throws PROTOCOL_VIOLATION".
  - Each `dial` does `OpenRequestStream`, then `SendRequestHeader(CONNECT https://host:port, Host=host:port)`, then `ReadResponse`, accepting any 2xx. The stream then becomes the `net.Conn`.
  - On a stale connection it reconnects once and retries. There are 2 attempts with a 15 s timeout each.
  - If `ResolveLocally` is false, the hostname is sent to Cloudflare. If true, a local `DNSResolver` turns it into an IP first.
  - QUIC config for L4 has `EnableDatagrams: false`.
  - Source: [api/l4proxy.go](https://github.com/Diniboy1123/usque/blob/6aa03fc97d/api/l4proxy.go#L41-L290), [cmd/l4_helpers.go](https://github.com/Diniboy1123/usque/blob/6aa03fc97d/cmd/l4_helpers.go#L160-L180)
- **L4 history:**
  - Added 2026-06-16 (`33396a876c`, "L4 SOCKS5 and HTTP Proxy modes").
  - HTTP/3 connection reuse added 2026-06-17 (`8b47f8f3c5`).
  - CID-length fix for PROTOCOL_VIOLATION added 2026-07-20 (`6aa03fc97d`).
  - Source: [commits for api/l4proxy.go](https://github.com/Diniboy1123/usque/commits/main/api/l4proxy.go)
- **L4 limitations, per the wiki:**
  - Historically both usque (gVisor) and the official client (smoltcp) used a userspace TCP/IP stack "because Cloudflare's MASQUE endpoints operated on L3 traffic". Cloudflare moved to L4.
  - L4 works only over HTTP/3/QUIC; there is no HTTP/2/TCP L4 yet.
  - Custom SNI is rejected. The SNI must be `consumer-masque-proxy.cloudflareclient.com`.
  - UDP through L4 fails because "Cloudflare does not appear to support this on their end".
  - Source: [usque wiki: L4 proxy mode](https://github.com/Diniboy1123/usque/wiki/L4-proxy-mode)
- **Cloudflare's own description** (blog post, 2026-03-05). The old proxy mode used "smoltcp, a Rust user-space TCP stack" to turn L4 into L3 for the WireGuard tunnel; smoltcp "is optimized for embedded systems, and does not support modern TCP features". The new proxy mode carries SOCKS5/HTTP proxy requests as HTTP/3 CONNECT directly in QUIC streams. Internal tests show about 2x download/upload throughput. It requires client 2025.8.779.0+ with Local proxy mode plus the MASQUE protocol. — [Cloudflare blog: faster SASE proxy mode via QUIC](https://blog.cloudflare.com/faster-sase-proxy-mode-quic/)
- **Performance claims:**
  - 833.60 Mbps down / 772.88 Mbps up in full SOCKS mode on a Ryzen 7 5700U at ~26% CPU.
  - quic-go supports only Reno congestion control, which gives "slow initial speeds", especially on high latency links.
  - Idle sessions get dropped by the server with `H3_NO_ERROR`, and the tool reconnects automatically.
  - Source: [README Performance / Known Issues](https://github.com/Diniboy1123/usque/blob/6aa03fc97d/README.md)
- **Issue #9 (2025-04).** A user got only ~150 Mbps on an arm64 OrangePi 5 Plus. The maintainer mentions a separate `usque-rs` (Rust) build and considering smoltcp. — [issue #9](https://github.com/Diniboy1123/usque/issues/9)
- **Exposure and auth defaults.**
  - Full SOCKS/HTTP binds `0.0.0.0` with no authentication by default, and only one user:pass is supported. Proxy users can reach the internal WARP network unfiltered.
  - `portfw` takes SSH-like `-L`/`-R` forwards, intended for WARP-to-WARP in Zero Trust.
  - Source: [README](https://github.com/Diniboy1123/usque/blob/6aa03fc97d/README.md)

### Inferences
- **The most important finding for WarpClient: for TCP-only proxying over MASQUE, no userspace TCP/IP stack is needed.** The client needs only:
  - QUIC with mTLS (client cert and ECDSA P-256 key from enrollment);
  - minimal HTTP/3 with a plain (non-extended) `CONNECT` request per TCP connection;
  - a duplex byte copy.
- A userspace stack is needed only for the L3 paths: WireGuard, or MASQUE CONNECT-IP, which you need for UDP/ICMP or when QUIC/UDP is blocked and HTTP/2 CONNECT-IP is the fallback.
- **Sizing the L4 data plane.** One QUIC connection multiplexes all streams. QUIC flow control and congestion control replace the inner TCP, so there is no TCP-over-QUIC "double congestion control" penalty. Expect the QUIC implementation's congestion controller (Reno in quic-go; CUBIC/BBR in msquic) to dominate throughput.

### Gaps
- Exact QUIC transport parameters and ALPN used for L4 were not fully extracted. The adjacent MASQUE wire-protocol researcher covers these.
- I found no public statement on whether Cloudflare's L4 endpoint accepts CONNECT over HTTP/2 now. The wiki (June 2026) says no.

---

## Q4. sing-box and Xray-core WireGuard (and MASQUE) outbounds

### Takeaway
- **sing-box** (≥1.11) models WireGuard as an "endpoint", which can be used both as an outbound and as an inbound. It runs a forked wireguard-go on top of sing-tun's gVisor "Go" stack (or a kernel TUN with `system: true`). Proxied TCP reaches it via the router as `Endpoint.DialContext(network, ip:port)`, and the endpoint's `stack.DialTCP` creates the in-tunnel socket.
- **Xray-core** uses wireguard-go with a kernel TUN when available, otherwise a userspace stack. Since **2026-10-15** that userspace stack is Xray's own lightweight TCP/IP stack instead of gVisor, for both WireGuard and its new MASQUE (CONNECT-IP) outbound. The reported results are faster, smaller and lower-CPU.

### Cited Findings
- **sing-box WireGuard outbound deprecation.** Deprecated in 1.11.0 and scheduled for removal in 1.13.0. Users must migrate to the `wireguard` endpoint. — [docs/configuration/outbound/wireguard.md](https://github.com/SagerNet/sing-box/blob/testing/docs/configuration/outbound/wireguard.md)
- **sing-box endpoint fields:**
  - `system` (kernel interface, needs privilege), `mtu` (default **1408**), `address`, `private_key`, `listen_port`.
  - `peers[].{address,port,public_key,pre_shared_key,allowed_ips,persistent_keepalive_interval,reserved}`.
  - `workers`, `on_demand` (1.15.0), UDP NAT fields `udp_mapping`/`udp_filtering`/`udp_nat_max` (1.14.0), and Dial Fields (so the WireGuard UDP can itself be detoured through another outbound).
  - Source: [docs/configuration/endpoint/wireguard.md](https://github.com/SagerNet/sing-box/blob/testing/docs/configuration/endpoint/wireguard.md)
- **sing-box implementation:**
  - `NewDevice` chooses `newStackDevice` (userspace) or `newSystemStackDevice`.
  - The userspace device is `tun.NewGo(tun.StackOptions{Tun: memoryTun, MTU, UDPTimeout, UDPMapping, ...})` from sing-tun.
  - `DialContext` calls `stack.DialTCP(ctx, bind, destination.AddrPort())`, which needs an IP, and sets TCP keepalive to 15 s/15 s. UDP uses `stack.DialUDP`.
  - Source: [transport/wireguard/device.go](https://github.com/SagerNet/sing-box/blob/testing/transport/wireguard/device.go#L46-L68), [device_stack.go](https://github.com/SagerNet/sing-box/blob/testing/transport/wireguard/device_stack.go#L51-L75)
- **sing-box reserved bytes.** They are written in the UDP bind's `Send` (`copy(buf[1:4], reserved)`), with per-endpoint overrides. Validation requires exactly 3 bytes. — [transport/wireguard/client_bind.go](https://github.com/SagerNet/sing-box/blob/testing/transport/wireguard/client_bind.go#L166-L190), [endpoint.go](https://github.com/SagerNet/sing-box/blob/testing/transport/wireguard/endpoint.go#L88-L96)
- **sing-box dependencies.** `sagernet/wireguard-go v0.0.8-0.20260929…`, `sagernet/sing-tun v0.9.7-0.20261013…`, `sagernet/gvisor v0.0.0-20260727.0-sing-box-mod.1`. — [go.mod](https://github.com/SagerNet/sing-box/blob/testing/go.mod)
- **Xray WireGuard client:**
  - If `!conf.NoKernelTun && KernelTunSupported()` it logs "Using kernel TUN" and calls `createKernelTun`. Otherwise it logs "Using built-in TCP/IP stack" and calls `CreateNetTUN(...)`.
  - Default in-tunnel DNS is 1.1.1.1/1.0.0.1/2606:4700:4700::1111/::1001.
  - `bind.reserved = conf.Reserved`.
  - Hostnames are resolved via `MakeResolveLocal` according to `domainStrategy`.
  - `Process()` → TCP: `h.tnet.DialContext(ctx, "tcp", target)`; UDP: `h.tnet.Dial("udp", target)`.
  - Source: [proxy/wireguard/client.go](https://github.com/XTLS/Xray-core/blob/0f3d884786/proxy/wireguard/client.go#L95-L270), [config.proto](https://github.com/XTLS/Xray-core/blob/0f3d884786/proxy/wireguard/config.proto)
- **Xray PR #7156 (merged 2026-10-15)**, "Use Xray-core's built-in lightweight TCP/IP stack instead of gVisor":
  - WireGuard and MASQUE, client and server, moved off gVisor, and "no Go file imports gVisor any more". The Linux amd64 binary shrank from 37.4 to 33.2 MB.
  - The stack had to add TCP connect, its own UDP ports, IP fragments both ways, ICMP too-big/unreachable, checksum verification, TCP timestamps, and loopback dropping.
  - Measured on a veth pair: 240 MB/s vs 143 MB/s (one stream), 234 vs 138 (eight streams), and 22 vs 37 CPU-s/GB.
  - Recovery after a 60 s outage: 0.6 s vs 46 s for gVisor.
  - Differences from gVisor: a fixed 1 MiB window (gVisor's grows from 512 KiB to 2 MiB), and "deadlines on these connections do nothing".
  - Source: [PR #7156](https://github.com/XTLS/Xray-core/pull/7156), [proxy/wireguard/netstack.go](https://github.com/XTLS/Xray-core/blob/0f3d884786/proxy/wireguard/netstack.go#L1-L78)
- **Xray PR #7130 (2026-10-11)**, the precursor, for the TUN inbound:
  - The stack has window scaling, SACK, a congestion window and an RTT-following retransmit timer.
  - With Linux offload: 380 MB/s vs 162 MB/s, and 2100 MB/s.
  - An idle TCP connection uses 14 KB of heap vs 28 KB.
  - Weakness: the fixed window means one connection over 100 ms RTT gets 1.6 MB/s vs 4.4 MB/s with gVisor.
  - Source: [Xray-core #7130](https://github.com/XTLS/Xray-core/issues/7130)
- **Size of the new stack.** `proxy/tun/tcp_lightweight.go` is 1261 lines and `proxy/tun/stack.go` is 624 lines (fetched 2026-10-21). — [proxy/tun](https://github.com/XTLS/Xray-core/tree/main/proxy/tun)
- **Xray MASQUE outbound:**
  - Added 2026-09-24 (PR #6807, "Add MASQUE outbound & transport (IETF CONNECT-IP, RFC 9484)").
  - The PR originally ran WireGuard's gVisor `CreateNetTUN` on the assigned address. TCP/UDP were handled as in the WireGuard outbound: domains resolved in-tunnel via `remoteDNS`, UDP FullCone, and one shared tunnel per outbound, rebuilt on the next connection after a drop.
  - XMUX was added on 2026-10-12 (#7121).
  - Source: [PR #6807](https://github.com/XTLS/Xray-core/pull/6807), [commits](https://github.com/XTLS/Xray-core/commits/main/proxy/masque/client.go)

### Inferences
- **How proxied TCP reaches the tunnel.** In both projects, an inbound (SOCKS/HTTP/mixed/TUN) terminates the client TCP. The router chooses the WireGuard or MASQUE outbound, which calls `stack.DialTCP(ip:port)` on the userspace stack. The two byte streams are spliced. Domains are resolved before the dial, by sing-box's DNS router or by Xray's `domainStrategy`/`remoteDNS`.
- **Xray's new stack is the best existing template for a managed (C#) port.** It is about 1.9k lines for TCP plus the stack core. It already handles the pain points relevant to a tunnel client (ICMP PTB, fragments, loopback filtering, timestamps), and it outperformed gVisor in its author's benchmarks.
- I did not verify whether Xray's MASQUE outbound speaks Cloudflare's `cf-connect-ip` variant (see Gaps).

### Gaps
- Grepping Xray's `proxy/masque/client.go` found no "warp"/"cloudflare"/"cf-connect" strings, so WARP compatibility of Xray MASQUE is unconfirmed.
- I did not read sing-tun's `tun.Go` internals (gVisor options such as buffer sizes or congestion control).

---

## Q5. tun2socks-style tools (comparison only)

### Takeaway
tun2socks runs the opposite direction: TUN → gVisor → SOCKS upstream. It is still useful as a reference for which gVisor TCP settings people tune. The only C# tun2socks found (VEthernet) relies on a **native lwIP** library, not a managed stack.

### Cited Findings
- **xjasonlyu/tun2socks** (pushed 2026-10-11):
  - Uses gVisor `tcp.NewForwarder(...)` with `maxConnAttempts = 2<<10`.
  - Enables keepalive: idle 60 s, interval 30 s, count 9.
  - Applies the send/receive buffer size ranges per endpoint.
  - Option defaults: `tcpCongestionControlAlgorithm = "reno"` ("reno" or "cubic"), `tcpModerateReceiveBufferEnabled = false` (receive-buffer auto-tuning off), and custom min/default/max buffer sizes, with the comment "We expect no packet loss, therefore we can bump buffers".
  - Source: [core/tcp.go](https://github.com/xjasonlyu/tun2socks/blob/main/core/tcp.go#L18-L110), [core/option/option.go](https://github.com/xjasonlyu/tun2socks/blob/main/core/option/option.go#L30-L90)
- **liulilittle/VEthernet** ("A implementation of tun2socks written in C#") ships `VEthernet/Net/LwIP/Netstack.cs` and a native `tun2socks/libtcpip.dll`. — [VEthernet repo tree](https://github.com/liulilittle/VEthernet)

### Inferences
- For a .NET project, VEthernet suggests one pragmatic route: P/Invoke into a native lwIP (or smoltcp/gVisor via cgo) shared library instead of writing TCP in C#. The cost is native packaging per RID.
- eycorsican/go-tun2socks was not examined. It is generally described as lwIP-based, but this was not verified in this session.

### Gaps
- No benchmark comparing lwIP-based and gVisor-based tun2socks was collected.

---

## Q6. Common pitfalls reported in issues

### Takeaway
The recurring problems are:
1. **MTU/PMTU blackholes** (gVisor not reacting to ICMP PTB; fixed-MTU guesses of 1280/1330/1408/1420).
2. **Poor single-connection throughput** from userspace TCP: small or fixed windows, Reno, no auto-tuning.
3. **DNS leaks** whenever the resolver falls back to the OS.
4. **Weak IPv6/dual-stack handling.**
5. **Fragile or missing SOCKS5 UDP.**
6. **Idle-disconnect and reconnect behaviour**, including slow recovery after outages.
7. **Memory growth.**

### Cited Findings
- **MTU/PMTU:**
  - usque #123 (2026-08-05): with MTU 1280 and the gVisor netstack, "any TCP payload larger than ~1250 bytes (in practice: every TLS handshake)" stalled. Title: "gVisor netstack does not respond to ICMP Packet Too Big". MTU 1000 worked.
  - The maintainer's fix: set QUIC `InitialPacketSize` to 1350 ("the value Cloudflare's client also uses") and keep MTU 1280.
  - Source: [usque #123](https://github.com/Diniboy1123/usque/issues/123)
- **Default MTUs differ per tool:**
  - warp-plus: 1330 single, 1280 nested. — [app.go](https://github.com/bepass-org/warp-plus/blob/f70ea7e4f1/app/app.go#L20-L21)
  - wireproxy: 1420. — [config.go](https://github.com/windtf/wireproxy/blob/35cce290db/config.go#L633)
  - sing-box: 1408. — [endpoint docs](https://github.com/SagerNet/sing-box/blob/testing/docs/configuration/endpoint/wireguard.md)
  - usque: 1280, and changing it is warned as unsupported. — [cmd/socks.go](https://github.com/Diniboy1123/usque/blob/6aa03fc97d/cmd/socks.go#L187-L193)
- **Throughput:**
  - wireproxy #55 (2023-01-20, open): a single connection through SOCKS was capped at ~3.2 MB/s, while multi-connection tests nearly saturated the link. A commenter blames the bandwidth-delay product and the lack of UDP/QUIC. — [wireproxy #55](https://github.com/windtf/wireproxy/issues/55)
  - Xray measured gVisor at 143 MB/s single-stream vs 240 MB/s for its own stack. — [PR #7156](https://github.com/XTLS/Xray-core/pull/7156)
  - Cloudflare called the smoltcp path a "performance ceiling". — [Cloudflare blog](https://blog.cloudflare.com/faster-sase-proxy-mode-quic/)
  - usque blames quic-go's Reno for slow ramp-up. — [README](https://github.com/Diniboy1123/usque/blob/6aa03fc97d/README.md)
- **SOCKS5 vs HTTP mode in usque.** A Windows user in usque #105 reports ~10 kB/s in SOCKS5 mode versus ~10 MB/s in HTTP mode. Others report "udp address … is not associated with tcp" and "martian packet dropped with loopback source address" since v3.0.1. PR #107 is under test. — [usque #105](https://github.com/Diniboy1123/usque/issues/105)
- **UDP:**
  - wireproxy lacked UDP for years: #30 from 2022, #221 from 2026. — [wireproxy #221](https://github.com/windtf/wireproxy/issues/221)
  - The wireproxy UDP ASSOCIATE relay was bound to all interfaces until 2026-09-17, which allowed LAN abuse. — [PR #224](https://github.com/windtf/wireproxy/pull/224)
  - warp-plus pins each association to its first destination. — [socks5/server.go](https://github.com/bepass-org/warp-plus/blob/f70ea7e4f1/proxy/pkg/socks5/server.go#L326-L349)
  - L4/CONNECT mode cannot do UDP at all against Cloudflare. — [usque wiki](https://github.com/Diniboy1123/usque/wiki/L4-proxy-mode)
- **DNS:**
  - wireproxy uses the OS resolver if no `DNS =` is set. — [routine.go](https://github.com/windtf/wireproxy/blob/35cce290db/routine.go#L66-L74)
  - usque's full modes resolve through the tunnel stack by default; L4 sends the hostname to Cloudflare unless `-l`. — [usque README DNS](https://github.com/Diniboy1123/usque/blob/6aa03fc97d/README.md), [api/l4proxy.go](https://github.com/Diniboy1123/usque/blob/6aa03fc97d/api/l4proxy.go#L146-L165)
  - warp-plus resolves in-tunnel to `--dns` (default 1.1.1.1). — [README](https://github.com/bepass-org/warp-plus/blob/f70ea7e4f1/README.md)
- **IPv6 / address selection:**
  - wireproxy #153: "Does Not Automatically Fallback to IPv6 When IPv4 Connection Fails" (closed 2024-12-31). The current code still returns a single address. — [wireproxy #153](https://github.com/windtf/wireproxy/issues/153), [routine.go](https://github.com/windtf/wireproxy/blob/35cce290db/routine.go#L78-L121)
  - usque #92: impossible to change IPv4/IPv6 priority after DNS resolution in `socks` (closed 2026-04-22). — [usque #92](https://github.com/Diniboy1123/usque/issues/92)
  - usque has no happy-eyeballs. — [README](https://github.com/Diniboy1123/usque/blob/6aa03fc97d/README.md)
- **Connection reuse and reconnects:**
  - usque L4 reuses one QUIC connection for all CONNECT streams and reconnects once on stream-open failure. — [api/l4proxy.go](https://github.com/Diniboy1123/usque/blob/6aa03fc97d/api/l4proxy.go#L167-L268)
  - The server drops idle tunnels with `H3_NO_ERROR`. — [README Known Issues](https://github.com/Diniboy1123/usque/blob/6aa03fc97d/README.md)
  - PROTOCOL_VIOLATION occurs unless the CID length is 20. — [api/l4proxy.go](https://github.com/Diniboy1123/usque/blob/6aa03fc97d/api/l4proxy.go#L238-L242)
  - After the link was down for 20–60 s, gVisor TCP needed 5.8–46 s to resume data, against 0.6 s for Xray's stack. — [PR #7156](https://github.com/XTLS/Xray-core/pull/7156)
- **Handshake and re-keying.** WireGuard rekeying is handled inside wireguard-go. Tools only wait for the first handshake (warp-plus polls `last_handshake_time_sec`) and keep `persistent_keepalive_interval`. — [app/wg.go](https://github.com/bepass-org/warp-plus/blob/f70ea7e4f1/app/wg.go#L53-L94)
- **Memory:**
  - warp-plus #177: ~70 MB and growing. — [issue #177](https://github.com/bepass-org/warp-plus/issues/177)
  - Xray: an idle TCP connection costs 28 KB in gVisor vs 14 KB in its own stack. — [Xray #7130](https://github.com/XTLS/Xray-core/issues/7130)
  - usque: full SOCKS mode "emulates an entire user-space network stack, so it can be resource hungry". — [README](https://github.com/Diniboy1123/usque/blob/6aa03fc97d/README.md)

### Inferences
- A new tool should:
  - derive the inner MTU from the outer path. For WARP, 1280 inner with 1350-byte QUIC initial packets for MASQUE matches the official client, per the usque maintainer.
  - clamp MSS on SYN, or answer PTB inside its own stack.
  - never silently fall back to the OS resolver.
  - implement happy-eyeballs across A/AAAA.
  - prefer L4 CONNECT streams for TCP whenever MASQUE/QUIC is reachable.

### Gaps
- No issue data was gathered on WireGuard handshake-retry storms or Cloudflare rate-limiting at the proxy layer. These are covered by other researchers.

---

## Q7. .NET building blocks for WarpClient (.NET 10) — separate section

### Takeaway
The pieces split into three groups:
- **Available in .NET 10:** ChaCha20-Poly1305 (BCL), ECDSA P-256 and X.509 for MASQUE mTLS, and QUIC streams via System.Net.Quic/msquic.
- **Missing from the .NET 10 BCL:**
  - X25519. `X25519DiffieHellman` is in .NET 11 and may also ship out-of-band.
  - BLAKE2s.
  - QUIC datagrams (planned for .NET 12).
  - Extended CONNECT over HTTP/3 in HttpClient, which CONNECT-IP needs.
  - Any usable managed userspace TCP/IP stack.
  - A maintained SOCKS5 server library.
- **Fastest viable path:** MASQUE **L4** — plain HTTP/3 CONNECT per TCP connection. It needs only QUIC bidirectional streams plus a minimal hand-written HTTP/3 layer. The WireGuard path needs NSec/BouncyCastle plus Blake2Fast for crypto, plus a hand-written or ported TCP/IP stack.

### Cited Findings
- **ChaCha20Poly1305** is in the BCL. Support: Windows 10 Build 20142+, Linux with OpenSSL 1.1.0+, macOS ✔, iOS/tvOS (from .NET 9, 13.0+), Android API 28+. Fixed 256-bit key, 96-bit nonce, 128-bit tag. Check `IsSupported` at runtime. — [Microsoft Learn: cross-platform cryptography](https://learn.microsoft.com/en-us/dotnet/standard/security/cross-platform-cryptography)
- **ECDSA/ECDH** on NIST P-256 is supported on every platform. That covers the MASQUE client key. The same doc page lists no X25519/Ed25519 support, and its "Hash" table contains no BLAKE2. — [Microsoft Learn: cross-platform cryptography](https://learn.microsoft.com/en-us/dotnet/standard/security/cross-platform-cryptography)
- **X25519 timeline:**
  - The `X25519DiffieHellman` API proposal (#126206) is api-approved with milestone **11.0.0**. The last checklist item was closed 2026-06-09 ("All platforms implemented"), covering Apple, Windows, OpenSSL, Android, `X25519DiffieHellmanOpenSsl` and `X25519DiffieHellmanCng`.
  - On 2026-06-20 vcsjones said "I think we should OOB this", meaning ship it out-of-band in Microsoft.Bcl.Cryptography for lower targets.
  - The older Curve25519/Ed25519 request #14741 is closed.
  - Source: [dotnet/runtime #126206](https://github.com/dotnet/runtime/issues/126206), [#14741](https://github.com/dotnet/runtime/issues/14741)
- **BLAKE2** request #80900 ("Add support to blake2 and blake3") is still open, opened 2023-01-20. — [dotnet/runtime #80900](https://github.com/dotnet/runtime/issues/80900)
- **Third-party crypto on NuGet:**
  - `NSec.Cryptography` latest 26.4.0 (published 2026-04-30); it wraps libsodium.
  - `BouncyCastle.Cryptography` latest 2.7.0 (published 2026-07-30); fully managed.
  - `Noise.NET` latest 1.0.0 (published 2018-05-30); the repo was last pushed 2020-12-26. It is .NET Standard 1.3 and supports the IK pattern with Psk2, ChaChaPoly, BLAKE2s and Curve25519.
  - Source: [NuGet NSec.Cryptography](https://www.nuget.org/packages/NSec.Cryptography), [NuGet BouncyCastle.Cryptography](https://www.nuget.org/packages/BouncyCastle.Cryptography), [Metalnem/noise](https://github.com/Metalnem/noise)
- **Existing C# WireGuard code:**
  - `Proxylity.WireGuardClient` 0.2.0 (MIT, repo pushed 2026-10-06, 15★): "Standalone, `UdpClient`-compatible WireGuard client". It implements "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s" and ChaCha20-Poly1305 transport with "automatic session re-keying" in pure managed code. It targets `net10.0` and depends on `NSec.Cryptography 26.4.0` and `SauceControl.Blake2Fast 2.0.0`. It sends and receives raw datagrams (IP packets) only; there is no TCP/IP stack. — [proxylity/wg-client](https://github.com/proxylity/wg-client), [NuGet](https://www.nuget.org/packages/Proxylity.WireGuardClient)
  - `WireGuard.Net` (Scartzz, 2024-11-08, net8.0, BouncyCastle 2.4.0 + Blake2Fast) is a student "Prototype … (dont use in production)" without the cookie-reply message. The author "tried … a prototype TCP/IP stack implementation", found it "not stable", and left it out of the repo. — [Scartzz/WireGuard.Net](https://github.com/Scartzz/WireGuard.Net)
  - `damob-byun/WireGuardNTSharp` is only a P/Invoke wrapper for the WireGuardNT kernel driver, not userspace. — [repo](https://github.com/damob-byun/WireGuardNTSharp)
- **GitHub search for C# "cloudflare warp"** found only config generators and wrappers around external tools (for example `dullassistan/WarpGenerator`, a .NET 8 WPF config generator). I found **no C# WARP client** that implements WireGuard/MASQUE plus a proxy. — [GitHub search](https://github.com/search?q=cloudflare+warp+language%3AC%23&type=repositories)
- **Userspace TCP/IP stacks in C#.** The GitHub "tcp/ip stack" and "userspace tcp" C# searches return only toy or archival projects, such as `netduino/Netduino.IP` (.NET Micro Framework, last pushed 2015). The only C# tun2socks (VEthernet) uses native lwIP. — [Netduino.IP](https://github.com/netduino/Netduino.IP), [VEthernet](https://github.com/liulilittle/VEthernet)
- **System.Net.Quic:**
  - Stable (not preview) since .NET 9 and built on MsQuic.
  - Windows 11/Server 2022+ ships msquic.dll. Linux requires the `libmsquic` package (2.2+). macOS is only "partially supported" via Homebrew `libmsquic` and `DYLD_FALLBACK_LIBRARY_PATH`, outside the test matrix.
  - Exposes bidirectional/unidirectional streams and `SslClientAuthenticationOptions`, so client certificates are possible.
  - Source: [Microsoft Learn: QUIC support in .NET](https://learn.microsoft.com/en-us/dotnet/fundamentals/networking/quic/quic-overview)
- **QUIC datagrams** (RFC 9221) are **not exposed**. #53533 "QUIC Datagram API" is open with milestone **12.0.0**; a duplicate proposal (#123418) was closed 2026-01-21 with "we will look into this internally". — [dotnet/runtime #53533](https://github.com/dotnet/runtime/issues/53533), [#123418](https://github.com/dotnet/runtime/issues/123418)
- **HttpClient and CONNECT:**
  - `SocketsHttpHandler` only uses HTTP/3 when `!request.IsExtendedConnectRequest`, where an extended CONNECT is `Method == CONNECT && headers.Protocol != null`. Extended CONNECT is therefore never sent over HTTP/3.
  - `Http3Connection.cs` contains no `EnableConnectProtocol` or datagram/H3_DATAGRAM handling (grep).
  - HTTP/2 extended CONNECT exists for WebSockets over HTTP/2 (#69669).
  - Plain (non-extended) CONNECT over HTTP/2 is still an open request (#88003, milestone Future).
  - Source: [HttpConnectionPool.cs](https://github.com/dotnet/runtime/blob/main/src/libraries/System.Net.Http/src/System/Net/Http/SocketsHttpHandler/ConnectionPool/HttpConnectionPool.cs#L424-L428), [HttpRequestMessage.cs](https://github.com/dotnet/runtime/blob/main/src/libraries/System.Net.Http/src/System/Net/Http/HttpRequestMessage.cs#L265), [dotnet/runtime #88003](https://github.com/dotnet/runtime/issues/88003), [#69669](https://github.com/dotnet/runtime/issues/69669)
- **SOCKS5 server libraries in C#** are tiny and unmaintained, for example `Abaddax/Socks5` (0★, 2026-03-25), `fexxef/SuperSocks5` (0★, UDP support claimed) and `AmazingTurtle/socks5serverv2` (2015). — [GitHub search](https://github.com/search?q=socks5+server+language%3AC%23&type=repositories)

### Inferences
- **Recommended .NET architecture for WarpClient (TCP-only):**
  - A hand-written SOCKS5 (RFC 1928 CONNECT; optional user/pass per RFC 1929) and HTTP CONNECT listener on `Socket`/`System.IO.Pipelines`.
  - Per connection, open a `QuicStream` on one shared `QuicConnection` to Cloudflare. Use ALPN `h3`, SNI `consumer-masque-proxy.cloudflareclient.com`, a client certificate from the enrolled P-256 key, and server-key pinning in `RemoteCertificateValidationCallback`.
  - Write a minimal HTTP/3 layer: the client control stream with SETTINGS, QPACK encoding of `:method CONNECT` and `:authority` (static table plus literals, no dynamic table), HEADERS/DATA framing, and a 2xx check. Then pump DATA frames to and from the socket.
  - This mirrors usque's `l4proxy.go` and avoids every TCP/IP-stack pitfall above.
  - HttpClient cannot be used here: it has no plain-CONNECT tunnel semantics for HTTP/3 (none found in source), and it disables HTTP/3 through proxies.
- **Risks on the L4 path:**
  - msquic/System.Net.Quic may not let you set the 20-byte connection-ID length that usque needed to avoid PROTOCOL_VIOLATION, or the 1350-byte initial packet size. Both need verification.
  - Linux requires the `libmsquic` package, and macOS support is unofficial.
- **Constraints on the L3 paths (WireGuard, or MASQUE CONNECT-IP for UDP):**
  - CONNECT-IP over HTTP/3 needs QUIC DATAGRAM frames, which System.Net.Quic will not expose before .NET 12. Options are a different QUIC stack (P/Invoke msquic directly, or quiche) or the HTTP/2 + capsule fallback.
  - For WireGuard, reuse or port Proxylity.WireGuardClient's managed Noise IKpsk2 (NSec + Blake2Fast). On .NET 11 you could swap NSec's X25519 for BCL `X25519DiffieHellman`.
  - Either L3 path also needs a userspace TCP/IP stack. No managed one exists, so the choices are to port Xray's ~1.9k-line lightweight Go stack (or smoltcp) to C#, or to P/Invoke a native lwIP/smoltcp.
  - WireGuard.Net's author tried a home-grown stack and found it unstable, which supports porting a proven stack rather than writing one from scratch.
- **XChaCha20-Poly1305 gap.** WireGuard's cookie-reply message uses XChaCha20-Poly1305 (per the WireGuard whitepaper; not re-verified here), and that is not in the BCL. NSec/libsodium or BouncyCastle would be needed for full under-load compliance. WireGuard.Net skipped cookie replies entirely.

### Gaps
- I did not confirm whether `X25519DiffieHellman` has actually shipped in a Microsoft.Bcl.Cryptography package usable from net10.0. Only the intent (2026-06-20) was found.
- I did not verify whether msquic exposes connection-ID length or initial-packet-size settings through `QuicClientConnectionOptions` in .NET 10.
- I did not test whether Cloudflare's endpoint accepts HTTP Datagrams as capsules on the request stream (RFC 9297) instead of QUIC DATAGRAM frames. If it does, CONNECT-IP over System.Net.Quic would become possible without the datagram API.
- I found no managed C# QPACK/HTTP/3 framing library outside the runtime's internal implementation. The runtime's `QPackEncoder` is internal and could be copied (MIT), but this was not investigated further.
