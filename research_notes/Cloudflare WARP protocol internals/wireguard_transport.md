# Cloudflare WARP WireGuard transport: wire format, Cloudflare quirks, and what third-party clients do

Research date: 2026-10-21. Sources are mostly read directly from source code with `gh api`. Commit prefixes and dates are given so that every constant can be checked. Repo moves seen during research: `peanut996/CloudflareWarpSpeedTest` now redirects to `puzige/CloudflareWarpSpeedTest`, and `pufferffish/wireproxy` redirects to `windtf/wireproxy`. `fscarmen/warp` returns "Repository access blocked (tos)" on GitHub, so it could not be read.

Main repos and the commits read:
- bepass-org/warp-plus at master `f70ea7e4f1` (2025-11-17), the last code commit. The repo is not archived, but code activity effectively stopped in 2025.
- CluvexStudio/Aether, created 2026-07-14, read at `a463ab71b5` (2026-09-12). This is the Rust WARP core that bepass-org/oblivion is built on as of Oct 2026.
- SagerNet/sing-box, `testing` branch. `transport/wireguard/client_bind.go` was last changed at `ba4146ea31` (2026-08-21).
- XTLS/Xray-core, `main` branch. `proxy/wireguard/bind.go` was last changed at `0f3d884786` (2026-10-16).
- puzige/CloudflareWarpSpeedTest at `4d00b536b9` (2026-08-14).
- ViRb3/wgcf at `de6bba7147` (v2.3.1, 2026-10-11).
- cloudflare/boringtun at `6dcc889a95` (2026-06-15).
- amnezia-vpn/amneziawg-go, README at `ce7cf1034d` (2026-07-31).

---

## 1. Is WARP plain WireGuard? The "reserved" bytes (client_id / routing id)

### Takeaway
WARP runs ordinary WireGuard: Noise_IKpsk2 with the standard prologue, the standard 148-byte initiation and 92-byte response, type values 1–4, a 1-byte type at offset 0, and an all-zero PSK. Cloudflare's change is to use header bytes 1..3, which the spec reserves and requires to be zero, as a 3-byte per-registration routing tag. That tag is the base64-decoded `config.client_id`. The client writes it into bytes 1..3 of every outgoing message after MAC1/MAC2 are computed, and must zero bytes 1..3 of every incoming message before parsing it, because the server sets the tag on its replies too. Leaving the tag out (all zeros) still gets a handshake response. In some PoPs (Hong Kong and Los Angeles, March 2023) transport data did not flow without the tag, and a wrong non-zero tag gets no response at all.

### Cited Findings
**What the standard handshake looks like toward WARP (taken from a working scanner)**
- warp-plus's endpoint "ping" builds a vanilla WireGuard initiation with `flynn/noise` and reaches WARP edges:
  - `noise.HandshakeIK`, `DH25519` / `ChaChaPoly` / `BLAKE2s`
  - prologue `"WireGuard v1 zx2c4 Jason@zx2c4.com"`
  - `PresharedKeyPlacement: 2`, with a 32-byte zero PSK when none is given
  - payload is the TAI64N timestamp
  - header written as `{0x01,0x00,0x00,0x00}`, so the reserved bytes are zero
  - sender index fixed at `28`
  - MAC1 = BLAKE2s-128 keyed with `BLAKE2s-256("mac1----" || server_pubkey)`; MAC2 is 16 zero bytes

  It accepts a reply if it is at least 60 bytes long, `response[0]==2` (only the first byte is checked), receiver index is 28, and `hs.ReadMessage(response[12:60])` decrypts — [warp-plus ipscanner/ping/warp.go @f70ea7e4f1](https://github.com/bepass-org/warp-plus/blob/f70ea7e4f1/ipscanner/ping/warp.go).
- CloudflareWarpSpeedTest checks for exactly 92 bytes, the standard WireGuard handshake-response size (`wireguardHandshakeRespBytes = 92`), and builds initiations with stock `wireguard-go` `device.CreateMessageInitiation` plus `CookieGenerator.AddMacs` — [task/warping.go @4d00b536b9](https://github.com/puzige/CloudflareWarpSpeedTest/blob/4d00b536b9/task/warping.go).
- Cloudflare's 2024 MASQUE post: "WireGuard was the perfect choice for the 1.1.1.1 with WARP service in 2019", and "WireGuard is not easily extended". Features such as FIPS cipher suites "would have to be added as proprietary extensions". This fits WARP-WireGuard staying close to stock, with only the header tweak — [Cloudflare blog, 2024-03-06](https://blog.cloudflare.com/zero-trust-warp-with-a-masque/).

**Where the tag comes from**
- warp-plus decodes the registration's `client_id` as standard base64 and uses the first 3 bytes: `clientID, _ := base64.StdEncoding.DecodeString(i.Config.ClientID)` → `Reserved: [3]byte{clientID[0], clientID[1], clientID[2]}` — [warp-plus app/app.go `generateWireguardConfig` @f70ea7e4f1](https://github.com/bepass-org/warp-plus/blob/f70ea7e4f1/app/app.go).
- wgcf's OpenAPI spec lists `client_id` as a required field of the device `config` object — [wgcf openapi-spec.yml @de6bba7147](https://github.com/ViRb3/wgcf/blob/de6bba7147/openapi-spec.yml). wgcf's generated profile has no `Reserved` line, because stock wg-quick has no such field — [wgcf wireguard/profile.go @833a541b9a, 2026-08-15](https://github.com/ViRb3/wgcf/blob/833a541b9a/wireguard/profile.go).
- Worked example: CloudflareWarpSpeedTest's default `reserved = [3]byte{60, 189, 175}` (hex `3c bd af`) is the decode of the 4-character `client_id` "PL2v". Its hard-coded initiation packet starts `01 3c bd af …` — [task/warping.go @4d00b536b9](https://github.com/puzige/CloudflareWarpSpeedTest/blob/4d00b536b9/task/warping.go). The decode was checked locally with `base64 -d`.
- The tag belongs to the registration, not the device. In Mar 2023 a private_key + reserved pair registered on a Tokyo VPS worked from a Hong Kong VPS, but mixing Tokyo's reserved with Hong Kong's private key did not. A tester summed it up: "reserved绑定客户端配置，不绑定客户端设备。warp-cli也是如此" ("reserved is bound to the client config, not the device; same for warp-cli") — [Xray-core #1730, 2023-03-04 comments](https://github.com/XTLS/Xray-core/issues/1730).
- Community scripts call it a routing id. The nftables workaround used with wg-quick, quoted in #1730, computes `routing_id = id[0]*16**4 + id[1]*16**2 + id[2]`. On output it rewrites `@th,72,24` (bits 72–95 of the transport header = 8-byte UDP header + 1 byte, i.e. WireGuard bytes 1..3) for traffic to `162.159.192.1:2408`. On input it zeroes the same field when it equals routing_id — [Xray-core #1730](https://github.com/XTLS/Xray-core/issues/1730).

**Ordering relative to MACs, and what the server sends back (black-box results, Xray #1730, 2023-03-03)**
- Writing the tag before MAC computation: no reply from WARP. Writing it after MAC computation: replies arrive. RPRX's conclusion: "WARP 接受 MAC 后改 reserved，因为有回包，而 MAC 前改 reserved 没有回包" ("WARP accepts reserved changed after the MAC, since there are replies; changing it before the MAC gets no replies"). He infers the server "检查后把它们置 0 再校验 MAC" (checks the value, sets it to 0, then verifies the MAC) — [Xray-core #1730](https://github.com/XTLS/Xray-core/issues/1730).
- Replies carry the tag too, so the client must zero bytes 1..3 before its own WireGuard stack verifies them. The final working Xray build (`c6a4d30`) did this, and Xray `main` has done it since commit `4c8ee0af50` "Set reserved to zero after Read()" (2023-03-03) — [Xray commit 4c8ee0a](https://github.com/XTLS/Xray-core/commit/4c8ee0af50); [Xray-core #1730](https://github.com/XTLS/Xray-core/issues/1730).
- Packet captures in #1730: with the correct reserved the server returns data; with a wrong value, nothing. A later test build that skipped the tag on types 1 and 2 got replies even with a wrong reserved, but was "不通" (did not pass traffic) — [Xray-core #1730](https://github.com/XTLS/Xray-core/issues/1730).
- RPRX notes that only handshake messages are MAC-protected over bytes 1..3. Transport data is sealed with no AEAD additional data (`keypair.send.Seal(header, nonce, packet, nil)`), so the tag on type-4 packets is not authenticated — [Xray-core #1730](https://github.com/XTLS/Xray-core/issues/1730).

**When the tag is required (historical, March 2023)**
- Singapore server: wg-quick and Xray worked without reserved. Hong Kong ("hkg"): neither worked without reserved, and both worked with the correct reserved — [Xray-core #1730 (IRN-Kawakaze, 2023-03-03)](https://github.com/XTLS/Xray-core/issues/1730).
- The issue opener (fscarmen) reported that Hong Kong and LA VPSes "不能通过 wgcf 来获取 warp 服务" (could not get WARP service via wgcf, i.e. without reserved), and that this was the motivation for the feature — [Xray-core #1730](https://github.com/XTLS/Xray-core/issues/1730).

**Which implementations write and strip the tag, and on which message types**

| Implementation | Config surface | Write rule (TX) | Strip rule (RX) | Added | Source |
|---|---|---|---|---|---|
| warp-plus (wireguard-go fork) | UAPI `reserved=a,b,c`; INI `Reserved = 1,2,3` or `random`; CLI `--reserved '1,2,3'` | `copy(buf[1:4], peer.reserved)` in `Peer.SendBuffers` when `len>3 && buf[0] in 1..4` and not a junk ("trick") packet | `packet[1],packet[2],packet[3] = 0,0,0` before reading the 32-bit LE type, for every received datagram | 2024-05-27 (`d707edac50`) | [device/peer.go](https://github.com/bepass-org/warp-plus/blob/f70ea7e4f1/wireguard/device/peer.go), [device/receive.go](https://github.com/bepass-org/warp-plus/blob/f70ea7e4f1/wireguard/device/receive.go), [device/uapi.go](https://github.com/bepass-org/warp-plus/blob/f70ea7e4f1/wireguard/device/uapi.go), [wiresocks/config.go](https://github.com/bepass-org/warp-plus/blob/f70ea7e4f1/wiresocks/config.go) |
| sing-box | `peers[].reserved: [0,0,0]` (endpoint); legacy outbound `reserved` | `ClientBind`: `copy(buf[1:4], reserved)` for every datagram with `len>3`, any type, with a per-endpoint override map (`SetReservedForEndpoint`) | `clear(b[1:4])` in `receive` | 2022-10-26 (`35886b88d7`); fixes 2024-12-05 (`8c3a98faa2`), 2025-04-25 (`787b5f1931`, Linux), 2026-02-24 (`d48236da94`) | [transport/wireguard/client_bind.go](https://github.com/SagerNet/sing-box/blob/testing/transport/wireguard/client_bind.go), [docs endpoint/wireguard.md](https://github.com/SagerNet/sing-box/blob/testing/docs/configuration/endpoint/wireguard.md) |
| Xray-core | `settings.reserved: [0,0,0]`; must be empty or exactly 3 bytes | `bind.Send`: `bufs[i][1..3] = reserved` for every datagram with `len>3`, any type | `bufs[0][1..3] = 0` after read | 2023-03-02 (`ccba465590`) + 2023-03-03 (`4c8ee0af50`) | [proxy/wireguard/bind.go](https://github.com/XTLS/Xray-core/blob/main/proxy/wireguard/bind.go), [infra/conf/wireguard.go](https://github.com/XTLS/Xray-core/blob/main/infra/conf/wireguard.go), [docs](https://github.com/XTLS/Xray-docs-next/blob/main/docs/en/config/outbounds/wireguard.md) |
| Aether (Rust, uses `boringtun = "0.7"`) | `client_id: [u8;3]` | `inject_client_id`: `pkt[1..4] = client_id` if `pkt[0] in 1..=4` | `strip_client_id`: `pkt[1..4] = 0` if `pkt[0] in 1..=4` | 2026 | [aether/src/wireguard.rs @a463ab71b5](https://github.com/CluvexStudio/Aether/blob/a463ab71b5/aether/src/wireguard.rs) |
| CloudflareWarpSpeedTest | `-reserved "[0, 0, 0]"`, plus `-pri`/`-pub` | `AddReserved(packet)` called after `AddMacs` | n/a (only checks reply length) | — | [task/warping.go](https://github.com/puzige/CloudflareWarpSpeedTest/blob/4d00b536b9/task/warping.go) |
| upstream cloudflare/boringtun | none | — | parses `u32::from_le_bytes(src[0..4])` as the type and matches `(HANDSHAKE_INIT, 148)` etc., so non-zero bytes 1..3 make the packet unparseable | — | [boringtun/src/noise/mod.rs @6dcc889a95](https://github.com/cloudflare/boringtun/blob/6dcc889a95/boringtun/src/noise/mod.rs) |

- The warp-plus INI parser accepts `Reserved = random` (3 random bytes) — [wiresocks/config.go `ParseReserved`](https://github.com/bepass-org/warp-plus/blob/f70ea7e4f1/wiresocks/config.go).
- Xray docs: "The three WireGuard reserved bytes. All three default to 0" — [Xray-docs-next outbounds/wireguard.md](https://github.com/XTLS/Xray-docs-next/blob/main/docs/en/config/outbounds/wireguard.md). sing-box docs: "WireGuard reserved field bytes" — [sing-box docs](https://github.com/SagerNet/sing-box/blob/testing/docs/configuration/endpoint/wireguard.md).

### Inferences
- Implementation recipe, inferred from all five implementations plus #1730:
  - (a) Build every message (types 1, 2, 3, 4) exactly as stock WireGuard, including MAC1/MAC2 over a header whose bytes 1..3 are zero.
  - (b) Just before `sendto`, overwrite bytes 1..3 with `base64decode(client_id)[0:3]`.
  - (c) On every datagram received from the peer, zero bytes 1..3 before dispatching on the type and before MAC verification.
  - Clients effectively send only types 1 and 4. Type 3 (cookie reply) comes from the server.
- Gating on `buf[0] ∈ 1..4` (warp-plus, Aether) is safer than tagging every datagram (sing-box, Xray) once junk/obfuscation packets share the socket. warp-plus deliberately skips its junk packets (`SendBuffers(…, trick=true)`).
- Stock kernel WireGuard / wg-quick and upstream boringtun cannot send the tag without packet mangling (nftables `@th,72,24`). They work only on PoPs or accounts where the zero tag is accepted, and only if the server then replies with zeros. wgcf + wg-quick working widely suggests the server echoes the client's tag (zero in, zero out), but no source states this outright.
- A zero tag looks like "no tag / route by key" (warp-plus's scanner gets valid type-2 replies with zeros). A wrong non-zero tag is dropped. RPRX compared this to REALITY short-ids, where all-zero is allowed and arbitrary values are rejected.
- Because type-4 packets are not authenticated over bytes 1..3, the tag works as unauthenticated routing metadata, probably used by the edge to steer packets to the right backend or session without a key lookup. This is consistent with "required at some PoPs only" (inference).

### Gaps
- No Cloudflare documentation of the field (name, semantics, which PoPs require it). Everything above is black-box community evidence.
- No 2025–2026 test confirming which PoPs still drop data traffic without the tag. All implementations still send it by default when known, so a new client should always send it.
- Whether Cloudflare's official clients use a private boringtun fork with tag support. Upstream boringtun has none.

---

## 2. Server public key, endpoint hostnames, IP ranges, UDP ports

### Takeaway
Consumer WARP uses one static server key, `bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=`, which the registration API returns in `peers[0].public_key`. The endpoint `engage.cloudflareclient.com` resolves to `162.159.192.1` / `2606:4700:d0::a29f:c001`. The IPv6 addresses embed the IPv4 address in their last 32 bits.

Cloudflare documents UDP 2408 as the default and 500, 1701, 4500 as fallbacks. The API also returns `ports: [2408, 500, 1701, 4500]`. Community scanners probe a fixed list of 54 ports and a handful of /24s: 162.159.192/195 and 188.114.96–99. For Zero Trust, Cloudflare documents 162.159.193.0/24 and 2606:4700:100::/48.

### Cited Findings
- **Server key**: `warpPublicKey = "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo="` (default for `-pub`) — [CloudflareWarpSpeedTest task/warping.go @4d00b536b9](https://github.com/puzige/CloudflareWarpSpeedTest/blob/4d00b536b9/task/warping.go). The same key appears in a 2023 Xray WARP config — [Xray-core #1730](https://github.com/XTLS/Xray-core/issues/1730). warp-plus reads it from the registration (`ident.Config.Peers[0].PublicKey`) rather than hard-coding it — [warp-plus app/app.go](https://github.com/bepass-org/warp-plus/blob/f70ea7e4f1/app/app.go).
- **Cloudflare firewall docs (page updated 2026-07-24)** — [Cloudflare One WARP firewall docs](https://developers.cloudflare.com/cloudflare-one/connections/connect-devices/warp/deployment/firewall/):
  - WireGuard: IPv4 `162.159.193.0/24`, IPv6 `2606:4700:100::/48`; default UDP 2408; fallback UDP 500, 1701, 4500.
  - MASQUE (context only): `162.159.197.0/24`, `2606:4700:102::/48`; UDP 443; fallbacks UDP 500, 1701, 4500, 4443, 8443, 8095 and TCP 443.
  - "The 162.159.192.0/24 range may appear before login. It serves the consumer WARP client and isn't required for Zero Trust."
  - `engage.cloudflareclient.com` is the outside-tunnel connectivity check and "resolves to the WARP ingress range or the `override_warp_endpoint`". `connectivity.cloudflareclient.com` (162.159.197.4 / 2606:4700:102::4) is the inside-tunnel check.
- **Registration API endpoint object**: `{host, v4, v6, ports}` with `ports` default `[2408, 500, 1701, 4500]`. wgcf uses `host` when present, otherwise `v4` (or `v6`) with port `ports[0]`, falling back to 2408 — [wgcf openapi-spec.yml + cloudflare/api.go `WireGuardEndpoint` @803310a27b (2026-09-18)](https://github.com/ViRb3/wgcf/blob/de6bba7147/cloudflare/api.go).
- **Hostname → IPs**: v2rayN hard-codes `{ "engage.cloudflareclient.com", ["162.159.192.1", "2606:4700:d0::a29f:c001"] }` — [v2rayN ServiceLib/Global.cs](https://github.com/2dust/v2rayN/blob/master/v2rayN/ServiceLib/Global.cs). The low 32 bits `a29f:c001` = 162.159.192.1 (checked locally).
- **warp-plus endpoint pool** (`warp/endpoint.go`, last changed 2025-02-26 `2a0296790c` "delete old endpoint range", which removed `162.159.193.0/24`): `162.159.192.0/24, 162.159.195.0/24, 188.114.96.0/24, 188.114.97.0/24, 188.114.98.0/24, 188.114.99.0/24, 2606:4700:d0::/64, 2606:4700:d1::/64` — [warp-plus warp/endpoint.go](https://github.com/bepass-org/warp-plus/blob/f70ea7e4f1/warp/endpoint.go); [commit 2a02967](https://github.com/bepass-org/warp-plus/commit/2a0296790c).
- **The 54-port list**, identical in warp-plus `WarpPorts()` and CloudflareWarpSpeedTest `ports`:
  `500, 854, 859, 864, 878, 880, 890, 891, 894, 903, 908, 928, 934, 939, 942, 943, 945, 946, 955, 968, 987, 988, 1002, 1010, 1014, 1018, 1070, 1074, 1180, 1387, 1701, 1843, 2371, 2408, 2506, 3138, 3476, 3581, 3854, 4177, 4198, 4233, 4500, 5279, 5956, 7103, 7152, 7156, 7281, 7559, 8319, 8742, 8854, 8886`
  — [warp-plus warp/endpoint.go](https://github.com/bepass-org/warp-plus/blob/f70ea7e4f1/warp/endpoint.go); [CloudflareWarpSpeedTest task/warping.go](https://github.com/puzige/CloudflareWarpSpeedTest/blob/4d00b536b9/task/warping.go).
- **CloudflareWarpSpeedTest ranges**: IPv4 `162.159.192.0/24, 162.159.193.0/24, 162.159.195.0/24, 162.159.204.0/24, 188.114.96.0/24, 188.114.97.0/24, 188.114.98.0/24, 188.114.99.0/24`; IPv6 `2606:4700:100::/48` — [task/warping.go](https://github.com/puzige/CloudflareWarpSpeedTest/blob/4d00b536b9/task/warping.go).
- **Aether (2026) constants**:
  - `WG_PREFIXES_V4` = the warp-plus v4 set plus `162.159.193.0/24`.
  - `WG_PREFIXES_V6` = `2606:4700:d0::/64, 2606:4700:d1::/64, 2606:4700:100::/48`.
  - Zero Trust prefixes = `162.159.193.0/24` and `2606:4700:100::/48`, which it prioritises.
  - `WG_PORTS` = the same 54 ports, reordered so 2408, 500, 1701, 4500 come first. A unit test asserts "the documented default wireguard port leads the sweep".
  - Seeds: `162.159.192.1, 162.159.195.1, 188.114.96.1, 188.114.97.1, 162.159.193.1`; v6 `2606:4700:d0::a29f:c001, 2606:4700:d1::a29f:c001, 2606:4700:d0::a29f:c301, 2606:4700:d0::bc72:6001`.

  — [aether/src/wireguard.rs @a463ab71b5](https://github.com/CluvexStudio/Aether/blob/a463ab71b5/aether/src/wireguard.rs). `a29f:c301` = 162.159.195.1 and `bc72:6001` = 188.114.96.1 (checked locally).
- Cloudflare's 2024 blog describes the Zero Trust WARP WireGuard tunnel as using port 2408, "still a non-standard port" — [Cloudflare blog 2024-03-06](https://blog.cloudflare.com/zero-trust-warp-with-a-masque/).

### Inferences
- The brief's "188.114.96.0/20" is not what any source uses. All code lists the four /24s 188.114.96–99, which together are 188.114.96.0/22. These sit in Cloudflare's general anycast space; Aether's `CDN_ANYCAST_POOL` in `consts.rs` also lists them.
- The 54-port list is community-observed, not documented. Only 2408/500/1701/4500 are official, and they are also what the API returns. 500/4500 are IKE/NAT-T and 1701 is L2TP, so they look like "VPN ports allowed through firewalls" choices.
- Range status disagrees: warp-plus dropped 162.159.193.0/24 in Feb 2025, but Cloudflare documents it (2026) as the Zero Trust WireGuard range, and Aether scans it first. A plausible reading is that 193 serves Zero Trust (Teams) registrations and is unreliable for consumer keys (inference).
- Reliable IPv6 seeds follow the pattern `2606:4700:d0::<IPv4-as-hex>` / `2606:4700:d1::…`.

### Gaps
- No authoritative list of which non-official ports are currently open. The 54-port list has not changed in the code bases since at least March 2024, the start of warp-plus's file history.
- Whether 162.159.204.0/24 (CloudflareWarpSpeedTest only) is a WARP range could not be confirmed.

---

## 3. Interface addresses, MTU, DNS, keepalive, AllowedIPs

### Takeaway
The registration gives a /32 IPv4 (`172.16.0.2`) and a /128 IPv6 inside `2606:4700:110::/48`. DNS is 1.1.1.1/1.0.0.1 plus 2606:4700:4700::1111/::1001, and AllowedIPs is `0.0.0.0/0, ::/0`. Clients disagree on MTU: wgcf 1280 (the official Android tun0 value), warp-plus 1330 single / 1280 nested, sing-box 1408 default, Xray 1420 default. Keepalive is optional in the protocol, but WARP-focused clients set 5–25 s.

### Cited Findings
- wgcf profile template (MTU line since the 2020 fix; addresses on one line since `9c45cd97cd` 2024-10-20; keepalive flag since `833a541b9a` 2026-08-15, v2.3.0 released 2026-09-18) — [wgcf wireguard/profile.go](https://github.com/ViRb3/wgcf/blob/833a541b9a/wireguard/profile.go); [CHANGELOG](https://github.com/ViRb3/wgcf/blob/de6bba7147/CHANGELOG.md):
  ```
  Address = {{ v4 }}/32, {{ v6 }}/128
  DNS = 1.1.1.1, 1.0.0.1, 2606:4700:4700::1111, 2606:4700:4700::1001
  MTU = 1280
  AllowedIPs = 0.0.0.0/0, ::/0
  PersistentKeepalive = N   (only with --keepalive; default 25)
  ```
- Example registration addresses: `"172.16.0.2/32"`, `"2606:4700:110:8bdf:6d2f:7eab:ce2b:ece0/128"` — [Xray-core #1730 config, 2023-03-02](https://github.com/XTLS/Xray-core/issues/1730).
- MTU history: wgcf issue #40 (2020-08-23). Without an MTU, "ping&dns would usually work but https browsing never does". ViRb3 measured Android tun0 under the 1.1.1.1 app at 1280 and Windows WireGuard's default at 1420, and set 1280 as the default. A 2025-09-10 comment complains 1280 is slow on 1 Gbps / 5G — [wgcf #40](https://github.com/ViRb3/wgcf/issues/40). The README says: "the generated profile will have a MTU of 1280, just like the official Android app" — [wgcf README](https://github.com/ViRb3/wgcf/blob/de6bba7147/README.md).
- warp-plus: `const singleMTU = 1330`; `const doubleMTU = 1280 // minimum mtu for IPv6, may cause frag reassembly somewhere` (inner tunnel in gool mode). DNS default `1.1.1.1` (`--dns`). Peers forced to `KeepAlive = 5` (outer / normal); inner gool peer `KeepAlive = 20`. `AllowedIPs 0.0.0.0/0, ::/0`. PSK = 64 hex zeros — [warp-plus app/app.go](https://github.com/bepass-org/warp-plus/blob/f70ea7e4f1/app/app.go); keepalive changed from 3 to 5 in `08088f2358` (2024-08-03) — [commit](https://github.com/bepass-org/warp-plus/commit/08088f2358).
- sing-box WireGuard endpoint: "`1408` will be used by default"; `persistent_keepalive_interval` "Disabled by default" — [sing-box docs endpoint/wireguard.md](https://github.com/SagerNet/sing-box/blob/testing/docs/configuration/endpoint/wireguard.md).
- Xray: `mtu` default 1420 (`config.Mtu = 1420` when 0); `remoteDNS` default `["1.1.1.1","1.0.0.1","2606:4700:4700::1111","2606:4700:4700::1001"]`; `allowedIPs` default `["0.0.0.0/0","::/0"]`; `keepAlive` default 0 — [infra/conf/wireguard.go](https://github.com/XTLS/Xray-core/blob/main/infra/conf/wireguard.go); [Xray docs](https://github.com/XTLS/Xray-docs-next/blob/main/docs/en/config/outbounds/wireguard.md). Xray's docs give the overhead as outer IP 20/40 + UDP 8 + type 4 + index 4 + nonce 8 + tag 16.
- Aether: `Some(keepalive.unwrap_or(25))` (25 s default) — [aether/src/wireguard.rs](https://github.com/CluvexStudio/Aether/blob/a463ab71b5/aether/src/wireguard.rs).

### Inferences
- WireGuard overhead is 32 bytes plus 8 (UDP) plus 20/40 (IPv4/IPv6). On a clean 1500 path that gives an inner MTU of 1440 over IPv4 or 1420 over IPv6. 1280 is the safe floor for IPv6 inside the tunnel and survives PPPoE, mobile and nested (WARP-in-WARP) paths. 1280–1330 is the defensible default for a third-party client, optionally with PMTU probing.
- The /32 + /128 addresses are point-to-point. A client needs no on-link routes, only default routes via the tunnel and an exclusion route for the endpoint IP.

### Gaps
- No Cloudflare documentation of WARP-WireGuard MTU, and no explicit server-side MSS clamping info.
- No source states whether the v4 inner address is always 172.16.0.2 for all accounts. It is commonly observed, but only confirmed here by one config example.

---

## 4. Endpoint scanners and optimizers: how they measure, and what they show

### Takeaway
Every scanner measures time from sending a WireGuard handshake initiation to receiving a valid handshake response. CloudflareWarpSpeedTest sends 10 initiations per IP:port, records loss and average RTT, and needs an exact 92-byte reply. warp-plus sends one initiation per random port, preceded by 20–50 junk packets, and decrypts the reply. Aether goes further: it checks the data plane by sending a DNS query through the tunnel after the handshake.

What the scanners reveal: WARP edges answer on many ports across a few /24s, ports and IPs are interchangeable, and a scanner can use a static or pre-recorded initiation.

### Cited Findings
- **CloudflareWarpSpeedTest** — [task/warping.go](https://github.com/puzige/CloudflareWarpSpeedTest/blob/4d00b536b9/task/warping.go):
  - Generates IP×port pairs across all 54 ports, shuffles them, and caps at `MaxScanCount = 5000` unless `-all`.
  - Per address, `PingTimes = 10` (default) sequential `handshake()` calls over one UDP "connection" with `udpConnectTimeout = 1000ms`.
  - Success requires `n == 92`. It records `Sent`, `Received`, and `Delay = totalDelay/recv`.
  - CLI filters exist for delay (`-tl`/`-tll`) and loss rate (`-tlr`) — [README](https://github.com/puzige/CloudflareWarpSpeedTest/blob/4d00b536b9/README.md).
  - With no `-pri`/`-pub`, it sends a hard-coded pre-built 148-byte initiation (`warpHandshakePacket` hex `013cbdaf…`, reserved 3c bd af). With `-pri`, it builds a fresh initiation using stock wireguard-go, `AddMacs`, then `AddReserved`.
- **warp-plus scanner** — [ipscanner/ping/warp.go](https://github.com/bepass-org/warp-plus/blob/f70ea7e4f1/ipscanner/ping/warp.go); [wiresocks/scanner.go](https://github.com/bepass-org/warp-plus/blob/f70ea7e4f1/wiresocks/scanner.go):
  - Picks a random port from the 54-port list for each IP.
  - Sends `randomInt(20,50)` random-content UDP packets of 40–100 bytes, spaced 80–150 ms. These parameters were raised from 8–15 packets and 20–250 ms in `0480583deb` on 2025-02-20 — [commit](https://github.com/bepass-org/warp-plus/commit/0480583deb).
  - Then sends the initiation, starts the RTT timer, and reads with a 5 s deadline. It validates the reply type and index and Noise-decrypts it.
  - `RunScan` uses the user's real key pair, the 1-minute overall timeout, `--rtt` max desirable RTT (default 1 s), and returns the first two good endpoints.
- **Aether** — [aether/src/wireguard.rs](https://github.com/CluvexStudio/Aether/blob/a463ab71b5/aether/src/wireguard.rs):
  - Has a separate `wg_prober.rs`.
  - After the handshake, `verify_dataplane` builds an IPv4/UDP DNS query from the tunnel address to `8.8.8.8:53`, encrypts it as a transport packet carrying the client_id, and waits for a reply. Timings: `DATAPLANE_PROBE_GAP` 600 ms, resend every 700 ms.
  - Health checks run every 3 s ± 0.5 s jitter.

### Inferences
- CloudflareWarpSpeedTest's default mode replays the same static initiation, with the same timestamp and ephemeral key, ten times per address. Stock WireGuard responders drop initiations whose TAI64N timestamp is not newer than the last one accepted, yet the tool counts 92-byte replies as success. If the tool still works, Cloudflare's edge does not enforce per-peer timestamp replay protection, at least not across anycast hosts or ports. This is an inference: there was no live test (connections were forbidden), and the source shows only that the tool expects replies.
- A handshake-only probe overstates quality. #1730 shows cases where the handshake succeeds but data does not flow (missing or wrong tag on type-4 packets). A third-party client should confirm the data plane, for example with a DNS query or `connectivity.cloudflareclient.com/cdn-cgi/trace` (warp-plus's default `--test-url` is `http://connectivity.cloudflareclient.com/cdn-cgi/trace`).
- warp-plus and the scanners both send junk first. In censored networks the "RTT" therefore includes surviving whatever DPI state the junk is meant to disrupt.

### Gaps
- No published comparison of loss or RTT by range or port. Scanner outputs are user-local and not aggregated anywhere I found.

---

## 5. Censorship, DPI and obfuscation in community tools

### Takeaway
WARP-WireGuard has a fixed, recognisable handshake: a 148-byte type-1 packet to a few well-known Cloudflare /24s on a small port set. It is blocked in Iran (2024) and intentionally by some ISPs, as Cloudflare itself acknowledges. Community clients respond with client-side-only measures the WARP server ignores:
- warp-plus "tricks": 20–50 random or QUIC-like junk packets before each handshake and keepalive.
- AmneziaWG-style Jc/Jmin/Jmax junk and I1–I5 "custom signature" packets (used by Aether's "noize" profiles, including IKEv2-shaped wrapping).
- Endpoint scanning.
- Chaining: WARP-in-WARP ("gool") and Psiphon over WARP ("cfon"). Oblivion/Aether in 2026 also offer Tor and MASQUE-carried WireGuard.

Header-changing AmneziaWG features (S1–S4, H1–H4, header protection) cannot be used against WARP because both ends must support them.

### Cited Findings
- **warp-plus "tricks"** — [wireguard/device/send.go](https://github.com/bepass-org/warp-plus/blob/f70ea7e4f1/wireguard/device/send.go); [app/app.go](https://github.com/bepass-org/warp-plus/blob/f70ea7e4f1/app/app.go):
  - `sendRandomPackets()` runs before every `SendHandshakeInitiation` and every `SendKeepalive` when `peer.trick` is not `""` and not `"t0"`.
  - It sends `randomInt(20,50)` packets of size `randomInt(len(hdr)+10, len(hdr)+120)`, spaced 80–150 ms, via `SendBuffers(…, trick=true)`, so they are not tagged.
  - Mode `"t1"`: pure random bytes.
  - Mode `"t2"`: an 18-byte prefix. First byte is one of `{0xDC,0xDE,0xD3,0xD9,0xD0,0xEC,0xEE,0xE3}`, followed by `00 00 00 01 08`, then 8 random bytes, then `00 00 44 D0`.
  - `runWarp` tries `t1`, then `t2` if the connection test fails. The inner gool tunnel uses `t0` (no tricks).
  - Tricks are always on for the outer tunnel (`peer.Trick = true`).
- History: tricks predate the 2024-03-14 rename to warp-plus. "wireguard: tweak trick" (2024-05-02, `dd5bac33b7`) had 8–15 packets of 40–100 bytes. "update parameters" (2025-02-20, `0480583deb`) set the current 20–50 packets, 80–150 ms — [commit dd5bac3](https://github.com/bepass-org/warp-plus/commit/dd5bac33b7); [commit 0480583](https://github.com/bepass-org/warp-plus/commit/0480583deb).
- **Gool (WARP-in-WARP)**: two identities (`primary`, `secondary`). The outer tunnel (MTU 1330) carries a UDP forwarder (`NewVtunUDPForwarder`) to the same endpoint. The inner tunnel (MTU 1280, keepalive 20) runs over it, which changes the exit location ("virtual NAT location"). **cfon**: WARP SOCKS on a random local port, with Psiphon chained over it (`--country` from 31 codes) — [warp-plus app/app.go](https://github.com/bepass-org/warp-plus/blob/f70ea7e4f1/app/app.go); [README](https://github.com/bepass-org/warp-plus/blob/f70ea7e4f1/README.md). The repo description reads "Warp+Psiphon, an anti censorship utility for iran" — [bepass-org repos](https://github.com/bepass-org/warp-plus).
- **Iran blocking (May 2024)**: warp-plus #124 "Is this the end? (For Iranian Users)". A reply says "The IRGFW has limited most of Cloudflare's IP addresses, including WARP ones. This is irrelevant to the wireguard protocol" — [warp-plus #124, 2024-05-24/25](https://github.com/bepass-org/warp-plus/issues/124). Issue #185 reports Iran's MCI mobile network not working at all (2024-07-11) — [warp-plus #185](https://github.com/bepass-org/warp-plus/issues/185).
- **Cloudflare acknowledges blocking**: "non-standard traffic can be blocked, sometimes intentionally… Some public Wi-Fi locations and ISPs don't know anything about WireGuard and block these ports… [other ISPs] know what WireGuard is and block it intentionally" — [Cloudflare blog 2024-03-06](https://blog.cloudflare.com/zero-trust-warp-with-a-masque/).
- **AmneziaWG** — [amneziawg-go README @ce7cf1034d](https://github.com/amnezia-vpn/amneziawg-go/blob/ce7cf1034d/README.md):
  - Client-only features (no server change needed): `Jc` junk packets (recommended 4–12) of random size `Jmin..Jmax`, sent "prior every handshake". `I1`–`I5` custom signature packets, also sent before every handshake, built from tags `<b 0x..>` (static bytes), `<r N>` (random bytes), `<rd N>` (random digits), `<rc N>` (random chars), `<t>` (timestamp).
  - Both-sides features: `S1`–`S4` paddings, `H1`–`H4` header type ranges, and AWG 3.0 "header protection" (2026-07-24, `457d920a1a`).
- **Aether "noize"** — [aether/src/aethernoize.rs @a463ab71b5](https://github.com/CluvexStudio/Aether/blob/a463ab71b5/aether/src/aethernoize.rs):
  - AmneziaWG-style profiles `off`, `light`, `balanced`, `aggressive`, `firewall`, `gfw`, with I1–I5 templates. For example, `gfw` I1 is `<b 16030100><c><rc 48-72>` (a TLS-record-like prefix) and I3 is `<b 474554202f20485454502f312e31>…` ("GET / HTTP/1.1").
  - Junk counts are split before the handshake / after I1 / after the handshake, with `jmin/jmax` from 48–384.
  - A `wrap_ikev2()` helper frames junk as an IKEv2 SA_INIT-like header (SPIs, `0x21 0x20 0x22 0x08`).
  - `send_keepalive_junk` is also called on keepalives (wireguard.rs).
- **Oblivion (Android, Oct 2026)** is "built on Aether, a user-space Warp core written in Rust that speaks MASQUE and WireGuard". It offers "Gool: WireGuard carried inside MASQUE and dialled from inside WARP", keeps "the older WARP-in-WARP… as Classic Gool", and adds TLS camouflage, a gateway finder, Psiphon and Tor bridges. Aether's description: "A Rust userspace WARP core for censored networks" — [bepass-org/oblivion README](https://github.com/bepass-org/oblivion/blob/master/README.md); [CluvexStudio/Aether](https://github.com/CluvexStudio/Aether).

### Inferences
- warp-plus's `t2` prefix appears to imitate a QUIC v1 long header: the first byte has form and fixed bits set with type 0-RTT or Handshake; then version `00000001`, DCID length 8, an 8-byte random DCID, a zero SCID length, a zero token length, and a 2-byte varint length `0x44D0` (= 1232). Junk would then look like QUIC to a classifier. This decoding is my own; the source has no comment.
- Why junk works against WARP: the WARP edge silently drops datagrams that are not valid WireGuard, so client-only junk is harmless. DPI that classifies a flow by its first packets, or that tracks state (as reported for Iran's and China's GFW), sees noise or QUIC/TLS/HTTP/IKE-looking packets first.
- The cost is real: warp-plus's 20–50 packets at 80–150 ms add roughly 1.6–7.5 s before every handshake (including rekeys every ~2 min) and every keepalive.
- Use of ports 500/4500 combined with IKEv2-shaped junk (Aether) aims to look like IPsec traffic on IPsec ports.
- MASQUE (UDP 443 / TCP 443) is the main censorship answer in 2026 tools. WireGuard is kept as a fallback, and as an inner layer carried over MASQUE in Oblivion's "Gool".

### Gaps
- I found no primary-source GitHub discussion specifically about Russian (TSPU) or Chinese blocking of WARP-WireGuard in the repos examined. The Aether profile name `gfw` implies China targeting but is not evidence of measured behaviour.
- No source shows which specific junk patterns currently get past Iran's filtering. Results are anecdotal and change quickly.

---

## 6. boringtun (Cloudflare's Rust userspace WireGuard) and its relation to WARP

### Takeaway
boringtun is Cloudflare's independent, permissively licensed Rust implementation of standard WireGuard, announced 2019-03-27. Its README says it ships in the 1.1.1.1 (WARP) iOS and Android apps and on "thousands of Cloudflare Linux servers". Upstream boringtun does not implement the WARP reserved-byte tag. Third-party Rust clients such as Aether use `boringtun = "0.7"` and add tagging in the UDP layer.

### Cited Findings
- "BoringTun is successfully deployed on millions of iOS and Android consumer devices as well as thousands of Cloudflare Linux servers". The iOS and Android links point to the "1.1.1.1: Faster Internet" app (`com.cloudflare.onedotonedotonedotone`) — [boringtun README @6dcc889a95](https://github.com/cloudflare/boringtun/blob/6dcc889a95/README.md).
- Announcement (2019-03-27): built because the kernel module was Linux-only, wireguard-go was too slow, and wireguard-rs was immature. Cloudflare wanted "a completely independent implementation under a permissive license". The blog itself does not mention WARP — [Cloudflare blog](https://blog.cloudflare.com/boringtun-userspace-wireguard-rust/).
- Upstream parsing reads the full 32-bit little-endian word as the message type (`u32::from_le_bytes(src[0..4])`) and matches `(HANDSHAKE_INIT, 148)` and similar pairs. It has no reserved/tag hook — [boringtun/src/noise/mod.rs](https://github.com/cloudflare/boringtun/blob/6dcc889a95/boringtun/src/noise/mod.rs).
- Repo state: last commit 2026-06-15 (NetBSD support). Library 0.7.1 was prepared 2026-05-01. The last GitHub Releases are `boringtun-0.5.2` and `boringtun-cli-0.5.2`, both 2022-07-20 — [cloudflare/boringtun commits/releases](https://github.com/cloudflare/boringtun).
- Aether depends on `boringtun = "0.7"` and wraps it with `inject_client_id` and `strip_client_id` on the UDP socket — [aether/Cargo.toml & src/wireguard.rs](https://github.com/CluvexStudio/Aether/blob/a463ab71b5/aether/src/wireguard.rs).

### Inferences
- Since Cloudflare's own apps use boringtun and the server needs the tag at some PoPs, Cloudflare's apps must add the tag somewhere: a private fork or a wrapper at the socket layer, as Aether does. A third-party Rust client should do the same. Strip on receive before calling `Tunn::decapsulate`, and tag after `Tunn::encapsulate` / `format_handshake_initiation`.
- boringtun being the server-side implementation behind WARP ingress is not established. "Cloudflare Linux servers" may refer to other uses.

### Gaps
- No public source confirms what the WARP edge runs server-side.
- No public source shows how the official clients set the tag.

---

## 7. Other observed differences: handshake, roaming, IPv6, rate limiting, NAT keepalive

### Takeaway
Apart from the tag, observed behaviour matches standard WireGuard:
- standard handshake sizes, a zero PSK, and standard timers in the forks;
- the same key and identity work from any IP, so the server roams naturally;
- registration provides dual-stack inner addresses;
- endpoints are interchangeable across the anycast /24s and the port list.

Community clients add aggressive keepalives (5–25 s), retry the handshake with fallback obfuscation modes, and check connectivity after the handshake. There is little public evidence on rate limiting.

### Cited Findings
- Same identity across machines: one private key + reserved pair used from different VPSes (Tokyo-registered, used in Hong Kong). The exit IP then showed Cloudflare Hong Kong, meaning the exit follows the ingress PoP, not the registration location — [Xray-core #1730, 2023-03-04](https://github.com/XTLS/Xray-core/issues/1730).
- warp-plus brings up the device, waits up to 15 s for `last_handshake_time_sec != 0` (`waitHandshake`), then runs an HTTP HEAD connectivity test through the tunnel (5 s deadline). If that fails it retries with the next trick mode (`t1` → `t2`) — [warp-plus app/wg.go & app.go](https://github.com/bepass-org/warp-plus/blob/f70ea7e4f1/app/wg.go).
- warp-plus also resolves domain endpoints itself, using the configured DNS (default 1.1.1.1), before passing an IP to wireguard-go (`iputils.ParseResolveAddressPort`) — [app/app.go](https://github.com/bepass-org/warp-plus/blob/f70ea7e4f1/app/app.go).
- sing-box "Resolve and race all WireGuard addresses on handshake" (2026-08-10, `1e2846a1a5`) — [sing-box commit history for client_bind.go](https://github.com/SagerNet/sing-box/commits/testing/transport/wireguard/client_bind.go).
- Gool mode with IPv6 endpoints was reported broken (warp-plus #165, 2024-06-12) — [warp-plus #165](https://github.com/bepass-org/warp-plus/issues/165).
- Xray docs recommend keepalive "only in special situations and only on the client" (default 0). warp-plus forces 5 s outer / 20 s inner. Aether defaults to 25 s. wgcf added an opt-in `--keepalive` (default 25 s) in 2026-09 — [Xray docs](https://github.com/XTLS/Xray-docs-next/blob/main/docs/en/config/outbounds/wireguard.md); [warp-plus app/app.go](https://github.com/bepass-org/warp-plus/blob/f70ea7e4f1/app/app.go); [Aether wireguard.rs](https://github.com/CluvexStudio/Aether/blob/a463ab71b5/aether/src/wireguard.rs); [wgcf README](https://github.com/ViRb3/wgcf/blob/de6bba7147/README.md).

### Inferences
- NAT keepalive: WARP sends no unsolicited traffic, so behind NAT/CGNAT an idle client loses inbound reachability unless it sends keepalives. 25 s is the standard WireGuard recommendation. warp-plus's 5 s is driven by censorship and NAT churn, and with tricks enabled every keepalive also triggers a junk burst.
- Anycast plus a stateless-looking edge (inferred from the scanner replay in §4 and reachability on dozens of ports) means a client can switch endpoint IP or port mid-session and re-handshake cheaply. Standard WireGuard roaming (the server learns the client's new source address from authenticated packets) presumably applies, but was not verified.
- IPv6 inside the tunnel works through the /128 the registration provides (`2606:4700:110:…`), with `::/0` in AllowedIPs. The outer transport can be IPv4 or IPv6 (2606:4700:d0::/64 and d1::/64 seeds); warp-plus exposes `-4`/`-6` to choose.

### Gaps
- Rate limiting of handshakes or data on WARP-WireGuard: no source found. The only rate-limiting discussions encountered concern the registration API, which is out of scope.
- Server-initiated rekey or handshake behaviour, cookie (type 3) usage under load, and session lifetime limits: no source found.
- Whether Cloudflare enforces TAI64N replay protection or a per-key session limit (e.g. the same key from two places at once): not documented. Community evidence is limited to the replay-based scanner in §4.
