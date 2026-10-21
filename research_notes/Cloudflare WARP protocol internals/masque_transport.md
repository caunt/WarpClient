# Cloudflare WARP MASQUE transport: wire protocol, authentication, community implementations (as of 2026-10-21)

Conventions used below:
- "usque@6aa03fc" = Diniboy1123/usque at commit `6aa03fc97d12848dce34eedbd187fb1077b5d1ea` (2026-07-20, tag v4.2.1), the latest commit on `main` as of 2026-10-21.
- "fork@66cba32" = Diniboy1123/connect-ip-go at `66cba32d7d33` (2026-06-13), the version pinned in usque's `go.mod`.
- Code was read directly (cloned with git, nothing executed). No Cloudflare endpoint was contacted.
- Most wire-level facts come from reverse engineering (usque, Xray-core, mihomo, yuhaiin). Cloudflare has not published a specification for `cf-connect-ip`. Treat these facts as observed behavior that could change server-side.

## 1. Which MASQUE protocol does WARP use, and what does the HTTP/3 Extended CONNECT handshake look like on the wire?

### Takeaway
WARP's L3 tunnel is a Cloudflare dialect of CONNECT-IP (RFC 9484) over HTTP/3. It uses a non-standard `:protocol` of `cf-connect-ip` and sends `:authority cloudflareaccess.com` with `:path /`. The default SNI is `consumer-masque.cloudflareclient.com` (consumer) or `zt-masque.cloudflareclient.com` (Zero Trust), and ALPN is `h3`. The client must also send the legacy `SETTINGS_H3_DATAGRAM_00` (0x276) setting. The server does not advertise `SETTINGS_ENABLE_CONNECT_PROTOCOL`, and its backend expects 20-byte client QUIC connection IDs. A newer L4 "proxy mode" uses a different SNI (`consumer-masque-proxy.cloudflareclient.com`) and opens one plain HTTP/3 `CONNECT host:port` stream per TCP flow.

### Cited Findings
**Request pseudo-headers (H3, L3 tunnel)**
- The official Linux client's qlog showed this HEADERS frame on stream 0: `:method CONNECT`, `:protocol cf-connect-ip`, `:scheme https`, `:authority cloudflareaccess.com`, `:path /`. The qlog is enabled with `warp-cli debug qlog enable` and written to `/var/lib/cloudflare-warp/qlogs/`. — [usque RESEARCH.md (last changed 2025-03-20)](https://github.com/Diniboy1123/usque/blob/6aa03fc97d12848dce34eedbd187fb1077b5d1ea/RESEARCH.md)
- usque hardcodes `ConnectURI = "https://cloudflareaccess.com"` and passes the request protocol `"cf-connect-ip"` to `connectip.Dial(..., "cf-connect-ip", additionalHeaders, true)`. — [usque@6aa03fc internal/consts.go L10](https://github.com/Diniboy1123/usque/blob/6aa03fc97d12848dce34eedbd187fb1077b5d1ea/internal/consts.go#L10); [api/masque.go L203](https://github.com/Diniboy1123/usque/blob/6aa03fc97d12848dce34eedbd187fb1077b5d1ea/api/masque.go#L203)
- Additional headers:
  - usque sends `User-Agent: ""`, i.e. an empty user-agent. — [api/masque.go L112](https://github.com/Diniboy1123/usque/blob/6aa03fc97d12848dce34eedbd187fb1077b5d1ea/api/masque.go#L112)
  - The fork's `Dial` adds `Capsule-Protocol: ?1`. — [fork@66cba32 client.go L40](https://github.com/Diniboy1123/connect-ip-go/blob/66cba32d7d33/client.go#L40)
  - A captured fixture of the full header set is `{":method":"CONNECT",":scheme":"https",":authority":"cloudflareaccess.com",":path":"/",":protocol":"cf-connect-ip","user-agent":"","capsule-protocol":"?1"}`. — [GeorgeXie2333/usque-app oracle/fixtures/h3-connect.json](https://github.com/GeorgeXie2333/usque-app/blob/HEAD/oracle/fixtures/h3-connect.json)
  - Xray-core's maintainers note that an explicit empty User-Agent "is what the official warp client does". — [XTLS/Xray-core PR #7121 (merged 2026-10-12)](https://github.com/XTLS/Xray-core/pull/7121)
- How the RFC-path search ended: the usque author first got HTTP 400 using the standard `connect-ip` value and got 200 after switching to `cf-connect-ip`. He tried RFC 9484 URI templates (`/.well-known/masque/ip/{target}/{ipproto}/`), but none were needed. "there is no mysterious endpoint". — [usque RESEARCH.md](https://github.com/Diniboy1123/usque/blob/6aa03fc97d12848dce34eedbd187fb1077b5d1ea/RESEARCH.md)
- The successful response is `200 OK` and carries a `Cf-Team` header. — [usque RESEARCH.md](https://github.com/Diniboy1123/usque/blob/6aa03fc97d12848dce34eedbd187fb1077b5d1ea/RESEARCH.md)
- Cloudflare's Dec 2024 blog illustrates CONNECT-IP with `:protocol = connect-ip` and path `/.well-known/masque/ip/*/*/`. That is a generic RFC example, not the values the client actually sends. — [Cloudflare blog, 2024-12-27](https://blog.cloudflare.com/masque-now-powers-1-1-1-1-and-warp-apps-dex-available-with-remote-captures/); contrasted with [usque RESEARCH.md](https://github.com/Diniboy1123/usque/blob/6aa03fc97d12848dce34eedbd187fb1077b5d1ea/RESEARCH.md)

**Deviations from RFC 9484 / 9220 that a client must tolerate**
1. Cloudflare's server does not advertise Extended CONNECT (`SETTINGS_ENABLE_CONNECT_PROTOCOL`). The fork added an `ignoreExtendedConnect` flag to skip that check.
2. The server does not send ROUTE_ADVERTISEMENT, and a route request "just hung forever". The fork added an "allow any route" option.
3. The server does require that it has received datagram support in SETTINGS (`settings.EnableDatagrams`).
   - Sources: [RESEARCH.md](https://github.com/Diniboy1123/usque/blob/6aa03fc97d12848dce34eedbd187fb1077b5d1ea/RESEARCH.md); [fork@66cba32 client.go L33-L37](https://github.com/Diniboy1123/connect-ip-go/blob/66cba32d7d33/client.go#L33); fork commit log (2026-04-08: "Ability to set requestProtocol manually", "Extend Dial to support additional HTTP headers", "Option to allow any route regardless of advertised state", "Extend Dial to support ignoring extended connect") — [Diniboy1123/connect-ip-go commits](https://github.com/Diniboy1123/connect-ip-go/commits/master)
   - The usque author's summary: "Technically if they stick with `connect-ip`, advertise `ExtendedConnect` and send out a wildcard route, they would be RFC compliant." — [RESEARCH.md](https://github.com/Diniboy1123/usque/blob/6aa03fc97d12848dce34eedbd187fb1077b5d1ea/RESEARCH.md)

**HTTP/3 SETTINGS sent by the client**
- usque sets `http3.Transport{EnableDatagrams: true, AdditionalSettings: {0x276: 1}, DisableCompression: true}`, i.e. the RFC 9297 H3_DATAGRAM setting plus the deprecated draft-00 `SETTINGS_H3_DATAGRAM_00 = 0x276`. The code comment says "official client still sends this out as well" and points to Cloudflare quiche's `frame.rs`. — [usque@6aa03fc api/masque.go L189-L199](https://github.com/Diniboy1123/usque/blob/6aa03fc97d12848dce34eedbd187fb1077b5d1ea/api/masque.go#L189)
- mihomo copies the same `0x276: 1` setting. — [MetaCubeX/mihomo transport/masque/masque.go (Alpha) L117](https://github.com/MetaCubeX/mihomo/blob/Alpha/transport/masque/masque.go)
- yuhaiin documents the same: "Cloudflare WARP uses `cf-connect-ip`, legacy HTTP/3 Datagram setting `0x276`, and a 20-byte client QUIC connection ID". — [yuhaiin docs/masque.md](https://github.com/yuhaiin/yuhaiin/blob/HEAD/docs/masque.md)
- Xray-core's WARP mode likewise uses "`cf-connect-ip` and the older datagram setting". — [XTLS/Xray-core PR #6878 (merged 2026-10-08)](https://github.com/XTLS/Xray-core/pull/6878)

**QUIC transport details**
- QUIC config: `EnableDatagrams: true` (RFC 9221 DATAGRAM frames) and `KeepAlivePeriod` (default 30 s). PMTU discovery stays on unless `--initial-packet-size` is set, which also disables PMTUD. PMTUD became the default in commit b297a1d (2026-04-09). — [usque@6aa03fc internal/utils.go L129-L141](https://github.com/Diniboy1123/usque/blob/6aa03fc97d12848dce34eedbd187fb1077b5d1ea/internal/utils.go#L129); [cmd/socks.go L309-L311](https://github.com/Diniboy1123/usque/blob/6aa03fc97d12848dce34eedbd187fb1077b5d1ea/cmd/socks.go#L309)
- **Connection ID length = 20 bytes.** Without it, "backend occasionally throws PROTOCOL_VIOLATION". The author measured 20–50% of 40 test connections failing with `http3: parsing frame failed: PROTOCOL_VIOLATION (remote)` and noted "in CF's case, the connection ID consistently seems to be 20". Fix: `quic.Transport{ConnectionIDLength: 20}`. — [usque commit 6aa03fc (2026-07-20)](https://github.com/Diniboy1123/usque/commit/6aa03fc97d12848dce34eedbd187fb1077b5d1ea); [api/masque.go L181-L183](https://github.com/Diniboy1123/usque/blob/6aa03fc97d12848dce34eedbd187fb1077b5d1ea/api/masque.go#L181)
  - usque also retries the H3 dial once when the error contains both "failed to read response" and "PROTOCOL_VIOLATION". — [api/masque.go](https://github.com/Diniboy1123/usque/blob/6aa03fc97d12848dce34eedbd187fb1077b5d1ea/api/masque.go)
- **Initial packet size:**
  - Early research observed a 1242-byte Initial from the official client and used `InitialPacketSize: 1242` (2025). — [RESEARCH.md](https://github.com/Diniboy1123/usque/blob/6aa03fc97d12848dce34eedbd187fb1077b5d1ea/RESEARCH.md)
  - On 2026-08-05 the maintainer wrote: "Bump the `InitialPacketSize` to 1350, that's the value Cloudflare's client also uses." — [usque issue #123](https://github.com/Diniboy1123/usque/issues/123)
  - Xray notes its H3 client "can't parrot chrome because that means a 1250-byte initial and zero-length connection ids, while masque needs room for 1280-byte packets from the start". — [Xray-core PR #7121](https://github.com/XTLS/Xray-core/pull/7121)
- **Keepalive and idle timeout:**
  - The official client "seems to send keepalives every 2-3 seconds" (maintainer observation, 2025-03-20). — [usque issue #6](https://github.com/Diniboy1123/usque/issues/6)
  - The server kills a connection after about 5 minutes of inactivity with `H3_NO_ERROR` (stream 0 canceled, error code 256 = 0x100). "Their official client suffers from the same issue. Their solution is simply to reconnect." — [usque issue #30 (2025-06-14)](https://github.com/Diniboy1123/usque/issues/30)
  - Xray keeps quic-go's 10 s keepalive for H3 and uses Chrome's 45 s PING interval for H2. — [Xray-core PR #7121](https://github.com/XTLS/Xray-core/pull/7121)
- **Official stack:** the official client "(at least on Linux and Android) is implemented in Rust with … quiche". On Android the tunnel lives in `libwarp_mobile.so` (BoringSSL), not in the roughly 280 MiB `libnativetunnel.so`. — [usque README](https://github.com/Diniboy1123/usque/blob/6aa03fc97d12848dce34eedbd187fb1077b5d1ea/README.md); [RESEARCH.md](https://github.com/Diniboy1123/usque/blob/6aa03fc97d12848dce34eedbd187fb1077b5d1ea/RESEARCH.md)

**TLS layer (SNI, ALPN, key exchange)**
- ALPN is `h3` (`NextProtos: []string{http3.NextProtoH3}`), and SNI defaults to `consumer-masque.cloudflareclient.com`. — [usque@6aa03fc api/masque.go L44](https://github.com/Diniboy1123/usque/blob/6aa03fc97d12848dce34eedbd187fb1077b5d1ea/api/masque.go#L44); [internal/consts.go L6](https://github.com/Diniboy1123/usque/blob/6aa03fc97d12848dce34eedbd187fb1077b5d1ea/internal/consts.go#L6)
- That SNI was first seen in the official client's QUIC Initial ClientHello sent to 162.159.198.1. — [RESEARCH.md](https://github.com/Diniboy1123/usque/blob/6aa03fc97d12848dce34eedbd187fb1077b5d1ea/RESEARCH.md)
- Zero Trust SNI is `zt-masque.cloudflareclient.com`. The README says "You should probably set SNI to `zt-masque.cloudflareclient.com` … The default `consumer-masque.cloudflareclient.com` also works, but discouraged." — [internal/consts.go L9](https://github.com/Diniboy1123/usque/blob/6aa03fc97d12848dce34eedbd187fb1077b5d1ea/internal/consts.go#L9); [README "ZeroTrust support"](https://github.com/Diniboy1123/usque/blob/6aa03fc97d12848dce34eedbd187fb1077b5d1ea/README.md#zerotrust-support)
- TLS 1.3 key exchange (FIPS):
  - The server accepts only `secp256r1` (classical) or `P256Kyber768Draft00` (PQ hybrid). Go's default ClientHello leads with an X25519MLKEM768/X25519 key share, so the server answers with a HelloRetryRequest that forces secp256r1. That costs one extra RTT, and usque accepts it deliberately. — [usque issue #81 (2026-04-10/11)](https://github.com/Diniboy1123/usque/issues/81); [api/masque.go L47-L56 comment](https://github.com/Diniboy1123/usque/blob/6aa03fc97d12848dce34eedbd187fb1077b5d1ea/api/masque.go#L47)
  - Cloudflare's PQ post confirms the FIPS boundary uses "FIPS-compliant ECDH using the P256 Elliptic curve" with "an early version of ML-KEM-768", i.e. P256Kyber768Draft00. — [Cloudflare blog "post-quantum-warp", 2025-09-24](https://blog.cloudflare.com/post-quantum-warp/)
- **L4 proxy mode (newer):**
  - SNI is `consumer-masque-proxy.cloudflareclient.com`. Each TCP flow is one HTTP/3 request stream with a classic `CONNECT` (no `:protocol`): `http.NewRequestWithContext(ctx, http.MethodConnect, "https://"+target, nil)` with `req.Host = target`. The same mTLS is used, and one QUIC connection is reused across flows (since v4.1.0, 2026-06-17). — [usque@6aa03fc internal/consts.go L7](https://github.com/Diniboy1123/usque/blob/6aa03fc97d12848dce34eedbd187fb1077b5d1ea/internal/consts.go#L7); [api/l4proxy.go L193-L198](https://github.com/Diniboy1123/usque/blob/6aa03fc97d12848dce34eedbd187fb1077b5d1ea/api/l4proxy.go#L193); [cmd/l4_helpers.go L105](https://github.com/Diniboy1123/usque/blob/6aa03fc97d12848dce34eedbd187fb1077b5d1ea/cmd/l4_helpers.go#L105)
  - mihomo uses the same `L4ConnectSNI`. — [mihomo transport/masque/l4proxy.go L18](https://github.com/MetaCubeX/mihomo/blob/Alpha/transport/masque/l4proxy.go)
  - Zero Trust L4 reportedly needs `zt-masque-proxy.cloudflareclient.com`; the consumer proxy SNI returns HTTP 403 for a ZT config (user report, 2026-08-12). — [usque issue #126](https://github.com/Diniboy1123/usque/issues/126)
  - Cloudflare's description: "By leveraging HTTP/3 (RFC 9114) with the CONNECT method, we can now keep traffic at Layer 4 … encapsulated directly into a QUIC stream". This requires client 2025.8.779.0 or later. — [Cloudflare blog "faster-sase-proxy-mode-quic", 2026-03-05](https://blog.cloudflare.com/faster-sase-proxy-mode-quic/)

### Inferences
- QUIC version: none of usque, mihomo or Xray pins a QUIC version, so quic-go's default (QUIC v1, RFC 9000) is evidently what Cloudflare accepts. This is inferred from working code, not documented.
- A compatible H3 client needs six things:
  1. QUIC v1 with DATAGRAM support (max_datagram_frame_size > 0).
  2. A 20-byte source CID.
  3. TLS 1.3 with ALPN `h3`, P-256 (or P256Kyber768Draft00) key share, and a client certificate.
  4. HTTP/3 SETTINGS with H3_DATAGRAM (0x33)=1 and 0x276=1.
  5. One Extended CONNECT on the first bidi stream (stream 0), with `:protocol cf-connect-ip`, `:authority cloudflareaccess.com`, `:path /`, `capsule-protocol: ?1` and an empty `user-agent`.
  6. No waiting for ADDRESS_ASSIGN or ROUTE_ADVERTISEMENT capsules.
- The Extended CONNECT is a session-establishment formality. Authorization is decided at the TLS layer (client cert), and the URI carries no target or ipproto variables.

### Gaps
- Not found in any public source:
  - Complete QUIC transport-parameter values of the official client (initial_max_data, idle timeout, max_datagram_frame_size) or of Cloudflare's server.
  - The full server SETTINGS frame contents.
  - Whether the server needs the H3_DATAGRAM (0x33) setting, 0x276, or both.
- No source documents whether QUIC v2 is accepted.
- The meaning of the `Cf-Team` response header for consumer accounts is undocumented.

## 2. How does the client authenticate (client certificate, enrollment, server pinning)?

### Takeaway
Authentication is mutual TLS. The device generates an ECDSA P-256 key pair and enrolls the public key with `PATCH /{api_version}/reg/{device_id}` using `key_type: "secp256r1"` and `tunnel_type: "masque"`. In every TLS handshake it presents a short-lived (24 h) self-signed certificate over that key. The client does not verify the server's hostname or chain. Instead it pins the server's ECDSA P-256 public key, which the registration API returns in `config.peers[0].public_key` (PEM SPKI). An unenrolled key or a device with `warp_enabled` off is rejected with TLS `access denied`.

### Cited Findings
**Enrollment API call**
- The official Android app sends this when switching to MASQUE: `PATCH https://api.cloudflareclient.com/v0a4616/reg/<id>`, with headers `Authorization: Bearer <token>`, `CF-Client-Version: a-6.81-4616` and `User-Agent: WARP for Android`, and body `{"key":"M...==","key_type":"secp256r1","tunnel_type":"masque"}`. The key is base64 DER SubjectPublicKeyInfo (`ecPublicKey`, `prime256v1`). — [usque RESEARCH.md](https://github.com/Diniboy1123/usque/blob/6aa03fc97d12848dce34eedbd187fb1077b5d1ea/RESEARCH.md)
- usque reproduces the call:
  - `EnrollKey` sends `PATCH {ApiUrl}/{ApiVersion}/reg/{deviceId}` with body `models.DeviceUpdate{Key: base64(pubKey), KeyType: "secp256r1", TunType: "masque", Name?}`.
  - Constants: `ApiVersion = "v0a4471"`, `CF-Client-Version: a-6.35-4471`.
  - The API error code `InvalidPublicKey` triggers an offer to regenerate the key.
  - Sources: [usque@6aa03fc api/cloudflare.go L136-L187](https://github.com/Diniboy1123/usque/blob/6aa03fc97d12848dce34eedbd187fb1077b5d1ea/api/cloudflare.go#L136); [internal/consts.go L5, L14-L15, L20-L21](https://github.com/Diniboy1123/usque/blob/6aa03fc97d12848dce34eedbd187fb1077b5d1ea/internal/consts.go#L5); [cmd/enroll.go](https://github.com/Diniboy1123/usque/blob/6aa03fc97d12848dce34eedbd187fb1077b5d1ea/cmd/enroll.go)
- usque's initial `register` posts a random 32-byte fake WireGuard key with `key_type: "curve25519"` and `tunnel_type: "wireguard"`, then calls `enroll` to switch the device to MASQUE. — [api/cloudflare.go L37-L69](https://github.com/Diniboy1123/usque/blob/6aa03fc97d12848dce34eedbd187fb1077b5d1ea/api/cloudflare.go#L37)

**Fields used from the enroll response (`models.AccountData`)**
- `config.peers[0].public_key` is the server's pinning key, stored in PEM.
- `config.peers[0].endpoint.v4` is returned as `"ip:0"`, and `.v6` as `"[ip]:0"`. usque strips the `:0` and the brackets.
- `config.interface.addresses.v4` and `.v6` are the tunnel IPs.
- `policy.tunnel_protocol` is also present in the response.
- Sources: [cmd/enroll.go L103-L118](https://github.com/Diniboy1123/usque/blob/6aa03fc97d12848dce34eedbd187fb1077b5d1ea/cmd/enroll.go#L103); [models/register.go](https://github.com/Diniboy1123/usque/blob/6aa03fc97d12848dce34eedbd187fb1077b5d1ea/models/register.go)

**Client certificate**
- usque's certificate: `x509.CreateCertificate` with `SerialNumber: 0`, `NotBefore: now`, `NotAfter: now+24h`, an empty subject, and self-signed with the enrolled P-256 key. The private key is stored as base64 SEC1 DER (`x509.MarshalECPrivateKey`). — [usque@6aa03fc internal/utils.go L77-L117](https://github.com/Diniboy1123/usque/blob/6aa03fc97d12848dce34eedbd187fb1077b5d1ea/internal/utils.go#L77); [config/config.go](https://github.com/Diniboy1123/usque/blob/6aa03fc97d12848dce34eedbd187fb1077b5d1ea/config/config.go)
- The official client does the same per connection. Dumping its client certificate showed "they generate a new certificate for every connection and each certificate is valid for 24 hours". — [RESEARCH.md "Extras"](https://github.com/Diniboy1123/usque/blob/6aa03fc97d12848dce34eedbd187fb1077b5d1ea/RESEARCH.md)
- Xray-core's version uses a random 128-bit serial, `NotBefore = now-1h` and `NotAfter = now+24h`. It parses the private key as PKCS#8 (PEM or base64) and supplies it through `GetClientCertificate`. — [XTLS/Xray-core transport/internet/masque/warp.go](https://github.com/XTLS/Xray-core/blob/main/transport/internet/masque/warp.go)

**Server-key pinning**
- usque sets `InsecureSkipVerify: true` because "SNI is usually not for the endpoint". A `VerifyPeerCertificate` callback then requires that the leaf's ECDSA public key `.Equal()` the configured `endpoint_pub_key`. `--insecure` disables the pin. — [usque@6aa03fc api/masque.go L36-L91](https://github.com/Diniboy1123/usque/blob/6aa03fc97d12848dce34eedbd187fb1077b5d1ea/api/masque.go#L36)
- Xray compares `leaf.RawSubjectPublicKeyInfo` byte-for-byte with `publicKey`, "so the sni can be anything". — [Xray-core warp.go](https://github.com/XTLS/Xray-core/blob/main/transport/internet/masque/warp.go); [PR #6878](https://github.com/XTLS/Xray-core/pull/6878)
- The consumer endpoint public key, as published in usque's README sample config and in the Xray PR example: `MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEIaU7MToJm9NKp8YfGxR6r+/h4mcG7SxI8tsW8OR1A5tv/zCzVbCRRh2t87/kxnP6lAy0lkr7qYwu+ox+k3dr6w==` (P-256 SPKI). — [usque README "Configuration"](https://github.com/Diniboy1123/usque/blob/6aa03fc97d12848dce34eedbd187fb1077b5d1ea/README.md#configuration); [Xray-core PR #6878](https://github.com/XTLS/Xray-core/pull/6878)
- Other keys differ:
  - The FedRAMP endpoints (CN `masque.devices.fed.cloudflare.com`) use a different key from consumer WARP and Zero Trust (user report). — [usque issue #81 comment, 2026-04-13](https://github.com/Diniboy1123/usque/issues/81)
  - HTTP/2 endpoints "may use a different TLS public key than the one used for QUIC". — [usque wiki: HTTP-2-support](https://github.com/Diniboy1123/usque/wiki/HTTP-2-support)

**Failure modes**
- An unenrolled or mismatched key makes the server abort with a TLS `access denied` alert. usque maps this to "login failed! Please double-check if your tls key and cert is enrolled". — [api/masque.go L131-L133](https://github.com/Diniboy1123/usque/blob/6aa03fc97d12848dce34eedbd187fb1077b5d1ea/api/masque.go#L131)
- "the device needs `warp_enabled` on, otherwise the endpoint answers with access denied". — [Xray-core PR #6878](https://github.com/XTLS/Xray-core/pull/6878)
- Adding a WARP+ license and then connecting over H2 to 162.159.198.2 produced the same "login failed" error. A commenter claimed .198.2 is for free WARP and suggested 162.159.197.2 or 162.159.199.2 for ZT/WARP+ (unverified user claim). — [usque issue #134 (2026-09-23)](https://github.com/Diniboy1123/usque/issues/134)
- `CRYPTO_ERROR 0x128 (remote): tls: handshake failure` was reported in Feb 2026. The maintainer replied that PQC had rolled out but "the old ECDSA based connections still work fine for me". — [usque issue #73](https://github.com/Diniboy1123/usque/issues/73)

### Inferences
- `0x128` = QUIC CRYPTO_ERROR base 0x100 + TLS alert 40 (`handshake_failure`). The `access denied` case is alert 49 (0x131).
- The per-connection 24 h certificate is not a security boundary, since whoever holds the private key can mint certificates. The key enrolled through the API is the real credential. The usque author makes the same point. — [RESEARCH.md](https://github.com/Diniboy1123/usque/blob/6aa03fc97d12848dce34eedbd187fb1077b5d1ea/RESEARCH.md)
- Enrollment replaces the device's key and tunnel type. A device is therefore effectively either in WireGuard mode (curve25519 key) or MASQUE mode (secp256r1 key) at a time. This is inferred from usque's "Enrolls a MASQUE private key and switches mode" and is not explicitly documented.

### Gaps
- Not found in public sources:
  - Whether the server checks certificate validity dates, serial number or subject.
  - Whether a non-self-signed or longer-lived certificate is accepted.
  - The exact Zero Trust endpoint public key.
- The precise current official API version string used by desktop clients (2026) for the PATCH call is not established. Only Android `v0a4616` (2025) and usque's `v0a4471` were seen; other researchers cover the registration API.

## 3. Endpoints, ports, and HTTP/2-over-TCP fallback

### Takeaway
Consumer MASQUE reaches the anycast range 162.159.198.0/24 (H3 to .1 and 2606:4700:103::1 on UDP 443; H2 to 162.159.198.2 on TCP 443). Zero Trust uses 162.159.197.0/24 and 2606:4700:102::/48, and FedRAMP uses 162.159.239.0/24 and 2606:4700:105::/48. UDP 443 is the default, with UDP fallbacks 500/1701/4500/4443/8443/8095 and TCP 443 for HTTP/2. The HTTP/2 fallback (GA in clients from May 2025) is a plain HTTP/2 `CONNECT` to `cloudflareaccess.com:443` with headers `cf-connect-proto: cf-connect-ip` and `pq-enabled`. Its stream body carries RFC 9297 DATAGRAM capsules (type 0x00) that contain raw IP packets without a context ID.

### Cited Findings
**Documented endpoint table (Cloudflare One firewall docs, current)**

| Tunnel | IPv4 | IPv6 | Default port | Fallback ports |
|---|---|---|---|---|
| MASQUE | 162.159.197.0/24 | 2606:4700:102::/48 | UDP 443 | UDP 500, 1701, 4500, 4443, 8443, 8095; TCP 443 ("required for HTTP/2 fallback") |
| MASQUE, FedRAMP High | 162.159.239.0/24 | 2606:4700:105::/48 | UDP 443 | same as standard MASQUE |
| WireGuard | 162.159.193.0/24 | 2606:4700:100::/48 | UDP 2408 | UDP 500, 1701, 4500 |

- The same page notes that "162.159.192.0/24 is used by the consumer WARP client and is not required for Zero Trust".
- Connectivity checks:
  - Outside the tunnel: `engage.cloudflareclient.com` (162.159.197.3, 2606:4700:102::3).
  - Inside the tunnel: `connectivity.cloudflareclient.com` (162.159.197.4, 2606:4700:102::4).
- Source: [Cloudflare One docs, WARP firewall](https://developers.cloudflare.com/cloudflare-one/connections/connect-devices/warp/deployment/firewall/)

**Consumer endpoints (from reverse engineering, not documented by Cloudflare)**
- `162.159.198.1` "seems to be the anycast IP all Warp clients use for the actual tunnel" (Linux client capture, research written early 2025). — [usque RESEARCH.md](https://github.com/Diniboy1123/usque/blob/6aa03fc97d12848dce34eedbd187fb1077b5d1ea/RESEARCH.md)
- The endpoint comes from the enroll response, with the port given as `:0` (see Q2).
- A user's config shows `"endpoint_v6": "2606:4700:103::1"` and an alternative v4 of `162.159.199.1` on port 8090. — [usque issue #41 (2025-08-14)](https://github.com/Diniboy1123/usque/issues/41)
- usque's `--connect-port/-P` (default 443) overrides the port. — [cmd/socks.go L302](https://github.com/Diniboy1123/usque/blob/6aa03fc97d12848dce34eedbd187fb1077b5d1ea/cmd/socks.go#L302)
- FedRAMP endpoints `162.159.239.1`/`.2` and `2606:4700:105::1`/`::2` have CN `masque.devices.fed.cloudflare.com` (user report). This matches the documented FedRAMP range. — [usque issue #81](https://github.com/Diniboy1123/usque/issues/81)
- The community repo `ircfspace/endpoint` (286 stars) maintains "Suggested Endpoints for Warp & Masque". — [ircfspace/endpoint](https://github.com/ircfspace/endpoint)
- The usque maintainer refuses to add endpoint scanning ("could … fulfil the definition of abuse"). — [usque issue #31](https://github.com/Diniboy1123/usque/issues/31)

**HTTP/2 fallback: history and availability**
- Release notes: "When using MASQUE, the connection will fall back to HTTP/2 (TCP) when we detect that HTTP/3 traffic is blocked. This allows for a much more reliable connection on some public WiFi networks." This text appears in the WARP client GA notes of 2025-05-12 (Linux/macOS) and 2025-05-14 (Windows), as quoted in search results; the changelog pages returned 404 to a direct fetch. — [Cloudflare WARP download/release notes page](https://developers.cloudflare.com/cloudflare-one/team-and-resources/devices/warp/download-warp/); [usque issue #32 quoting it (2025-06-19)](https://github.com/Diniboy1123/usque/issues/32)
- In June 2025 the fallback did not work on Linux/Android in the maintainer's tests: the client looped retrying H3.
- In August 2025 users got it working:
  - `warp-cli tunnel masque-options set h2-only` produced `Tunnel Protocol: MASQUE (HTTP/2)`, `Endpoints: 162.159.198.2, ::`, and the trace showed `http=http/2`, `kex=X25519MLKEM768`, `warp=on`.
  - Windows clients on a corporate network with QUIC fully blocked fell back to H2 automatically.
  - Source: [usque issue #32](https://github.com/Diniboy1123/usque/issues/32)
- usque added `--http2` in v2.0.0 (2026-04-09). The default H2 endpoint is hardcoded as `DefaultEndpointH2V4 = "162.159.198.2"`, and no default exists for IPv6. "Because endpoints cannot be reliably pulled from the API" they are configured manually as `endpoint_h2_v4`/`endpoint_h2_v6`. — [usque@6aa03fc config/endpoints.go L11](https://github.com/Diniboy1123/usque/blob/6aa03fc97d12848dce34eedbd187fb1077b5d1ea/config/endpoints.go#L11); [usque wiki HTTP-2-support](https://github.com/Diniboy1123/usque/wiki/HTTP-2-support); [releases](https://github.com/Diniboy1123/usque/releases)

**HTTP/2 wire format**
- **TLS:** the same client certificate and pin as H3, with `NextProtos = ["h2"]`. — [api/masque.go L234-L239](https://github.com/Diniboy1123/usque/blob/6aa03fc97d12848dce34eedbd187fb1077b5d1ea/api/masque.go#L234)
- yuhaiin notes the H2 mode "tolerates the empty ALPN response used by some Cloudflare WARP endpoints". — [yuhaiin docs/masque.md](https://github.com/yuhaiin/yuhaiin/blob/HEAD/docs/masque.md)
- **Request:** headers `cf-connect-proto: cf-connect-ip`, `pq-enabled: false` (usque: "TODO: support PQC") and `User-Agent: ""`. — [usque@6aa03fc api/masque.go L119-L125](https://github.com/Diniboy1123/usque/blob/6aa03fc97d12848dce34eedbd187fb1077b5d1ea/api/masque.go#L119)
- `DialH2` issues `http.NewRequestWithContext(ctx, http.MethodConnect, "https://cloudflareaccess.com", pipeReader)` with `req.Host = "cloudflareaccess.com:443"` and `ContentLength = -1` (streaming body). — [fork@66cba32 client_h2.go L19-L61](https://github.com/Diniboy1123/connect-ip-go/blob/66cba32d7d33/client_h2.go#L19); [fork commit 8d7bb0a "Support Cloudflare HTTP/2 protocol" (2026-04-10)](https://github.com/Diniboy1123/connect-ip-go/commit/8d7bb0a858a2674046a7cb5538749e4c826c3538)
- Xray describes it as "http/2 a plain connect with bare ip packets, like the warp client". — [Xray-core PR #6878](https://github.com/XTLS/Xray-core/pull/6878)
- **Framing:**
  - Each send is a capsule `varint(0x00 DATAGRAM) || varint(len) || raw IP packet`. On receive, capsules of other types are skipped, and the payload is treated as a raw IP packet (a context ID of 0 is prepended locally).
  - The fork rejects outgoing context IDs other than 0, and the H2 transport does not support control capsules (no ADDRESS_ASSIGN or ROUTE_ADVERTISEMENT).
  - Sources: [fork@66cba32 client_h2.go L17, L88-L141](https://github.com/Diniboy1123/connect-ip-go/blob/66cba32d7d33/client_h2.go#L88)
  - yuhaiin confirms: "Cloudflare H2 carries raw IPv4/IPv6 packets inside type-0 DATAGRAM capsules without an IP context ID." — [yuhaiin docs/masque.md](https://github.com/yuhaiin/yuhaiin/blob/HEAD/docs/masque.md)
- Captured H2 request fixture: `{"method":"CONNECT","uri":"https://cloudflareaccess.com/","http_version":"2","headers":{"user-agent":"","cf-connect-proto":"cf-connect-ip","pq-enabled":"false"},"capsule_datagram_type":0}`. — [GeorgeXie2333/usque-app oracle/fixtures/h2-connect.json](https://github.com/GeorgeXie2333/usque-app/blob/HEAD/oracle/fixtures/h2-connect.json)
- **Limitations:**
  - usque's L4 proxy modes are H3-only; "HTTP/2 support … is not available yet". — [usque wiki L4-proxy-mode](https://github.com/Diniboy1123/usque/wiki/L4-proxy-mode)
  - mihomo added H2 (`network: h2`) on 2026-04-10. — [mihomo commit 885244a9a0](https://github.com/MetaCubeX/mihomo/commit/885244a9a0)

### Inferences
- Go's HTTP/2 transport encodes a `CONNECT` without a `:protocol` pseudo-header as a classic RFC 9113 §8.5 CONNECT. The H2 request is therefore most likely `:method CONNECT`, `:authority cloudflareaccess.com:443` with no `:scheme`/`:path`, and the CONNECT-IP semantics come from the `cf-connect-proto` header rather than RFC 8441 Extended CONNECT. This is inferred from Go's behavior plus Xray's "plain connect" description; no packet capture confirming it was found.
- Omitting the context ID in H2 capsules violates RFC 9484 §6, which puts the Context ID inside every HTTP Datagram payload. An implementation must special-case H3 (context ID present) versus H2 (absent).
- The `pq-enabled` header suggests the official client signals PQ intent at the HTTP layer on H2, perhaps because TCP-path TLS terminators differ. This is speculative.

### Gaps
- The official consumer IPv4/IPv6 MASQUE ranges are not listed in Cloudflare docs (only ZT/FedRAMP are). 162.159.198.x and 2606:4700:103::x come from reverse engineering and user configs.
- The fallback-port order and timing used by the official client, and its H3 to H2 detection heuristic, were not found.
- Whether the H2 endpoint is advertised in any API field is unknown; usque says it "cannot be reliably pulled from the API".

## 4. How IP packets are carried: context IDs, datagram framing, address assignment, MTU

### Takeaway
Over H3, every IP packet is one QUIC DATAGRAM frame. The payload is the RFC 9297 Quarter-Stream-ID varint, then Context ID 0 (one byte `0x00`), then the full IPv4/IPv6 packet. Cloudflare sends no ADDRESS_ASSIGN or ROUTE_ADVERTISEMENT capsules. The client configures its inner addresses from the registration response, accepts traffic from and to any address, and simply starts sending. The inner MTU is fixed at 1280. Larger packets get a locally generated ICMP Packet Too Big. The official client's Initial/UDP payload size of about 1350 bytes leaves room for 1280-byte inner packets.

### Cited Findings
**Datagram framing (H3)**
- "Essentially the rest of the traffic is standard unreliable datagrams, exactly how they are defined by RFC 9221 … you take your raw IP packet and send it as datagrams." — [usque RESEARCH.md](https://github.com/Diniboy1123/usque/blob/6aa03fc97d12848dce34eedbd187fb1077b5d1ea/RESEARCH.md)
- usque reserves 1 byte of headroom before each packet because "CONNECT-IP context ID 0 is encoded as a one-byte QUIC varint". `WritePacketBuffer` copies `contextIDZero` into the headroom and sends `buf[offset-1 : offset+len]` as the HTTP datagram. quic-go's http3 layer prepends the quarter-stream-ID. — [usque@6aa03fc api/tunnel.go L158-L160, L233](https://github.com/Diniboy1123/usque/blob/6aa03fc97d12848dce34eedbd187fb1077b5d1ea/api/tunnel.go#L158); [fork@66cba32 conn.go L403-L430](https://github.com/Diniboy1123/connect-ip-go/blob/66cba32d7d33/conn.go#L403)

**Address and route assignment**
- "Cloudflare doesn't seem to follow the RFC and doesn't seem to advertise any routes. You can just start sending packets. And. It. Will. Just. Work." — [RESEARCH.md](https://github.com/Diniboy1123/usque/blob/6aa03fc97d12848dce34eedbd187fb1077b5d1ea/RESEARCH.md)
- usque reads with `ipConn.ReadPacketZeroCopy(true)`, i.e. `allowAny`, which skips destination filtering against advertised routes. — [api/tunnel.go](https://github.com/Diniboy1123/usque/blob/6aa03fc97d12848dce34eedbd187fb1077b5d1ea/api/tunnel.go); [fork conn.go](https://github.com/Diniboy1123/connect-ip-go/blob/66cba32d7d33/conn.go)
- Inner addresses come from registration: `config.interface.addresses.v4`/`.v6`, for example `172.16.0.2` and `2606:4700:110:…`. These are assigned to the TUN device (Linux netlink `AddrAdd`) or to the gVisor netstack. — [cmd/nativetun_linux.go L38-L66](https://github.com/Diniboy1123/usque/blob/6aa03fc97d12848dce34eedbd187fb1077b5d1ea/cmd/nativetun_linux.go#L38); [cmd/socks.go L133-L145](https://github.com/Diniboy1123/usque/blob/6aa03fc97d12848dce34eedbd187fb1077b5d1ea/cmd/socks.go#L133); [usque issue #41 config sample](https://github.com/Diniboy1123/usque/issues/41)
- Xray agrees: "`address` the addresses of the device, warp doesnt assign them inside the tunnel" (example `172.16.0.2/32`, `2606:4700:110:8a36::2/128`). — [Xray-core PR #6878](https://github.com/XTLS/Xray-core/pull/6878)
- yuhaiin's H3 client "advertises local IPv4/IPv6 routes and doesn't require Cloudflare to" send any. — [yuhaiin docs/masque.md](https://github.com/yuhaiin/yuhaiin/blob/HEAD/docs/masque.md)
- Zero Trust: "Assign a unique IP address to each device is enabled by default for devices with MASQUE enabled." — [Cloudflare One docs, device profile settings](https://developers.cloudflare.com/cloudflare-one/connections/connect-devices/warp/configure-warp/warp-settings/)

**MTU and ICMP Packet Too Big**
- usque defaults to `--mtu 1280` and warns "MTU is not the default 1280. This is not supported. Packet loss and other issues may occur." — [cmd/socks.go L310](https://github.com/Diniboy1123/usque/blob/6aa03fc97d12848dce34eedbd187fb1077b5d1ea/cmd/socks.go#L310); [cmd/nativetun.go L128-L130](https://github.com/Diniboy1123/usque/blob/6aa03fc97d12848dce34eedbd187fb1077b5d1ea/cmd/nativetun.go#L128)
- If an outbound packet does not fit in a QUIC datagram (`DatagramTooLargeError`), connect-ip-go builds an ICMP/ICMPv6 Packet Too Big with `minMTU = 1280` and returns it to the caller, which writes it back to the TUN. — [fork@66cba32 conn.go L57, L425](https://github.com/Diniboy1123/connect-ip-go/blob/66cba32d7d33/conn.go#L57); [api/tunnel.go](https://github.com/Diniboy1123/usque/blob/6aa03fc97d12848dce34eedbd187fb1077b5d1ea/api/tunnel.go)
- Reported stall (Aug 2026): with MTU 1280 and the gVisor netstack, TCP payloads above about 1250 bytes stalled (every TLS handshake) because "gVisor netstack does not respond to ICMP Packet Too Big". MTU 1000 fixed it. — [usque issue #123](https://github.com/Diniboy1123/usque/issues/123)
- The maintainer's fix was to raise `InitialPacketSize` to 1350, "the value Cloudflare's client also uses", and keep MTU 1280. — [usque issue #123](https://github.com/Diniboy1123/usque/issues/123)
- The fix is not merged on `main` yet: usque@6aa03fc still defaults `initial-packet-size` to 0, i.e. PMTUD starting from quic-go's default. — [cmd/socks.go L311](https://github.com/Diniboy1123/usque/blob/6aa03fc97d12848dce34eedbd187fb1077b5d1ea/cmd/socks.go#L311)
- Inbound inner packets can exceed the local MTU. yuhaiin found that "a peer's 1280-byte QUIC UDP payload (1308-byte IPv4 or 1328-byte IPv6 packet)" arrives through the tunnel, so receive buffers must not be capped at 1280 or a short-buffer error tears down the tunnel. Reproduced with live WARP credentials using DNS-over-QUIC. — [yuhaiin docs/masque.md (review 2026-10-18)](https://github.com/yuhaiin/yuhaiin/blob/HEAD/docs/masque.md)

**ICMP and IP-level behavior**
- connect-ip-go always allows ICMP. It validates IP headers and decrements TTL/hop limit per RFC 9484. — [fork conn.go](https://github.com/Diniboy1123/connect-ip-go/blob/66cba32d7d33/conn.go); [yuhaiin docs/masque.md](https://github.com/yuhaiin/yuhaiin/blob/HEAD/docs/masque.md)
- **UDP support:**
  - The L3 tunnel carries UDP; usque's `socks` mode supports UDP ASSOCIATE via gVisor. — [usque README](https://github.com/Diniboy1123/usque/blob/6aa03fc97d12848dce34eedbd187fb1077b5d1ea/README.md)
  - The L4 CONNECT mode does not: "Cloudflare does not appear to support this on their end". — [usque wiki L4-proxy-mode](https://github.com/Diniboy1123/usque/wiki/L4-proxy-mode)

### Inferences
- Rough H3 overhead per inner packet:
  - Short header: about 1 + 20 (DCID) + 1–4 (packet number).
  - DATAGRAM frame type and length: about 1–3.
  - Quarter-stream-ID 0: 1; Context ID: 1; AEAD tag: 16.
  - Total is about 41–46 bytes, so a 1280-byte inner packet needs a UDP payload of about 1321–1326 bytes. That fits a 1350-byte QUIC packet size but not quic-go's 1252-byte (IPv4) / 1232-byte (IPv6) conservative start, which explains the MTU-1280 stalls when PMTUD has not yet probed upward. Arithmetic inference, not measured.
- A compatible client should do five things:
  1. Use inner MTU 1280.
  2. Start with a QUIC max UDP payload of at least 1350, or rely on PMTUD while generating ICMP PTB for the local stack.
  3. Size receive buffers above 1280.
  4. Not wait for ADDRESS_ASSIGN.
  5. Not filter inbound packets by advertised routes.

### Gaps
- Not found in public sources:
  - Whether Cloudflare would honor client-sent ROUTE_ADVERTISEMENT or ADDRESS_REQUEST capsules.
  - Whether it ever sends capsules other than DATAGRAM.
  - Whether nonzero context IDs (e.g., for compression) are supported.
- The official client's exact `max_datagram_frame_size` and its PMTUD behavior are undocumented.

## 5. Diniboy1123/usque in depth, and other community MASQUE implementations

### Takeaway
usque (Go, about 1,490 stars, v1.0.0 2025-03-19 to v4.2.1 2026-07-20) is the reference open-source reimplementation. Most later projects (mihomo, yuhaiin, Xray-core, Rust ports) derive their WARP constants from it. It is built on quic-go plus the maintainer's patched fork of quic-go/connect-ip-go. It offers L3 modes (native TUN, gVisor-based SOCKS5/HTTP proxy, port forwarding), H3 and H2 transports, and since June 2026 L4 CONNECT-per-flow proxies. As of October 2026, WARP MASQUE is also supported by mihomo (since 2026-01-28) and Xray-core (since 2026-10-08), with several Rust and Go derivatives. sing-box 1.15 adds only a generic RFC 9484 client, and warp-plus has none.

### Cited Findings
**usque project facts**
- Repo created 2025-02-20. Latest commit and tag: 6aa03fc / v4.2.1 (2026-07-20); 35 open issues as of 2026-10-21. — [GitHub API: Diniboy1123/usque](https://github.com/Diniboy1123/usque); [releases](https://github.com/Diniboy1123/usque/releases)
- Release milestones:
  - v1.0.0 (2025-03-19).
  - v2.0.0 (2026-04-09): HTTP/2 + `--insecure`.
  - v3.0.0 (2026-04-22).
  - v4.0.0 (2026-06-16): L4 SOCKS5/HTTP proxy modes.
  - v4.1.0 (2026-06-17): reuse one HTTP/3 connection for L4.
  - v4.2.0 (2026-06-21): license key set/reset.
  - v4.2.1 (2026-07-20): ConnectionIDLength=20.
  - Sources: [releases](https://github.com/Diniboy1123/usque/releases); [commit log](https://github.com/Diniboy1123/usque/commits/main)

**Dependencies (go.mod, Go 1.26.3)**
- `github.com/quic-go/quic-go v0.60.0`
- `github.com/Diniboy1123/connect-ip-go v0.0.0-20260613064811-66cba32d7d33`
- `gvisor.dev/gvisor` and `golang.zx2c4.com/wireguard` (netstack TUN)
- `github.com/songgao/water` (TUN)
- `github.com/vishvananda/netlink`
- `github.com/txthinking/socks5`
- `github.com/yosida95/uritemplate/v3`
- `golang.org/x/net` (http2)
- `github.com/spf13/cobra`
- Source: [usque@6aa03fc go.mod](https://github.com/Diniboy1123/usque/blob/6aa03fc97d12848dce34eedbd187fb1077b5d1ea/go.mod)

**Why the connect-ip-go fork exists**
- "Because Cloudflare's implementation isn't exactly RFC 9484 compliant and it's not going to work without directly monkey patching the library." — [usque README](https://github.com/Diniboy1123/usque/blob/6aa03fc97d12848dce34eedbd187fb1077b5d1ea/README.md#why-did-you-fork-connect-ip-go)
- Fork changes (2026-04-08 to 2026-06-13):
  - configurable requestProtocol
  - additional headers
  - allow-any-route
  - ignore Extended CONNECT
  - `DialH2` with DATAGRAM-only capsules
  - zero-copy `WritePacketBuffer` / `ReadPacketZeroCopy`
  - Source: [Diniboy1123/connect-ip-go commits](https://github.com/Diniboy1123/connect-ip-go/commits/master)
- Upstream maintainer stance: the quic-go/connect-ip-go maintainer "has no plans to implement http/2, unless someone sponsors the project". — [usque issue #32](https://github.com/Diniboy1123/usque/issues/32)

**Code layout**
- `api/cloudflare.go`: register, enroll, account, license.
- `api/masque.go`: TLS config, pinning, and the H3/H2 `ConnectTunnel`.
- `api/tunnel.go`: `MaintainTunnel`, a reconnect supervisor with two pump goroutines, a `NetBuffer` pool, and netstack/water adapters.
- `api/l4proxy.go`: HTTP/3 CONNECT-per-flow.
- `api/hooks.go`: `--on-connect`/`--on-disconnect` executables with `USQUE_*` env vars.
- `internal/`: consts, key/cert generation, QUIC config, SOCKS5, DNS.
- `cmd/`: `register`, `enroll`, `socks`, `http-proxy`, `l4-socks`, `l4-http-proxy`, `portfw`, `nativetun` (Linux, and Windows since 2025-06-03), `account`, `version`.
- Source: [usque@6aa03fc tree](https://github.com/Diniboy1123/usque/tree/6aa03fc97d12848dce34eedbd187fb1077b5d1ea)

**Defaults**
- SOCKS `0.0.0.0:1080`, HTTP proxy `0.0.0.0:8000`, no authentication by default.
- DNS: `9.9.9.9, 149.112.112.112, 2620:fe::fe, 2620:fe::9`.
- Keepalive 30 s, MTU 1280, connect-port 443, reconnect delay 1 s.
- UDP relay idle timeout 60 s.
- `--always-reconnect` is off: by default the tunnel waits for outbound traffic before reconnecting.
- Sources: [cmd/socks.go L298-L320](https://github.com/Diniboy1123/usque/blob/6aa03fc97d12848dce34eedbd187fb1077b5d1ea/cmd/socks.go#L298); [README](https://github.com/Diniboy1123/usque/blob/6aa03fc97d12848dce34eedbd187fb1077b5d1ea/README.md)

**L4 modes**
- They "use direct HTTP/3 CONNECT streams, skip UDP/datagram handling, and avoid the extra user-space networking stack".
- Limitations: H3 only, no UDP, and no custom SNI ("backend rejects requests with an unexpected SNI", HTTP 403).
- The official client used smoltcp for proxy mode and has since replaced it.
- Sources: [usque wiki L4-proxy-mode](https://github.com/Diniboy1123/usque/wiki/L4-proxy-mode); [usque issue #110](https://github.com/Diniboy1123/usque/issues/110)
- Implementing L4 required "my own custom fork of quic-go"; the maintainer cites a growing maintenance burden. — [usque issue #77 (2026-06-13)](https://github.com/Diniboy1123/usque/issues/77)

**Known limitations (README "Known Issues")**
- Remote idle disconnects (`H3_NO_ERROR`).
- Limited API interaction.
- No WireGuard support.
- No DoH.
- Slow ramp-up because quic-go only has Reno congestion control (BBR is an open quic-go issue).
- Native TUN only on Linux (Windows was added later).
- Source: [usque README](https://github.com/Diniboy1123/usque/blob/6aa03fc97d12848dce34eedbd187fb1077b5d1ea/README.md#known-issues)

**Open issues (October 2026)**
- #105 / #133: UDP in SOCKS5.
- #109: a regression report (works on 3.0.1, not on 4.x).
- #117: SO_MARK.
- #126: ZT L4 SNI.
- #131: `--sni-address` exposed only in some modes.
- #130: WARP-in-WARP chaining.
- Source: [usque issues](https://github.com/Diniboy1123/usque/issues)

**Fingerprinting stance**
- The maintainer is not trying to be indistinguishable from the official client. usque "mimics a very old version of the official client where post quantum crypto wasn't even implemented". Cloudflare "know[s] about this project and haven't done any blocking attempts against it". uTLS was declined because of binary size. — [usque issue #81](https://github.com/Diniboy1123/usque/issues/81)

**Maintainer's other projects**
- [Diniboy1123/usque-rs](https://github.com/Diniboy1123/usque-rs): a Rust, quiche-based Linux native tunnel (created 2026-03-04, 37 stars). Files include `tls.rs`, `tunnel.rs`, `icmp.rs` and `tests/tunnel_mtu.rs`. — [GitHub API](https://github.com/Diniboy1123/usque-rs)
- He mentions a private Rust version with PQC. — [usque issue #81](https://github.com/Diniboy1123/usque/issues/81)
- [Diniboy1123/wasque](https://github.com/Diniboy1123/wasque): a container running the official client in SOCKS5 mode, used for testing. — [usque issue #32](https://github.com/Diniboy1123/usque/issues/32)

**Other implementations: proxy platforms**
- **mihomo (Clash.Meta), MetaCubeX/mihomo:**
  - `masque` outbound since 2026-01-28 ([e45c896185](https://github.com/MetaCubeX/mihomo/commit/e45c896185)).
  - `network: h2` on 2026-04-10 ([885244a9a0](https://github.com/MetaCubeX/mihomo/commit/885244a9a0)).
  - `network: h3-l4proxy` on 2026-06-17 ([8e2aba40fc](https://github.com/MetaCubeX/mihomo/commit/8e2aba40fc)).
  - The constants mirror usque (`consumer-masque.cloudflareclient.com`, `https://cloudflareaccess.com`, `0x276`, `cf-connect-ip`, `consumer-masque-proxy…`). — [mihomo transport/masque/ (Alpha)](https://github.com/MetaCubeX/mihomo/tree/Alpha/transport/masque)
- **Xray-core, XTLS/Xray-core:**
  - MASQUE inbound, a generic RFC 9484 CONNECT-IP server ([PR #6844, 2026-09-27](https://github.com/XTLS/Xray-core/pull/6844)).
  - WARP client support with H3 and H2, selected by `"alpn": ["h2"]` ([PR #6878, merged 2026-10-08](https://github.com/XTLS/Xray-core/pull/6878)).
  - Option to ignore `publicKey` when certificate-pin options are set, labeled "domain fronting for WARP" ([commit aa7aa9ad0a, 2026-10-10](https://github.com/XTLS/Xray-core/commit/aa7aa9ad0a)).
  - XMUX multi-tunnel and a default Chrome User-Agent ([PR #7121, 2026-10-12](https://github.com/XTLS/Xray-core/pull/7121)).
  - Code: [transport/internet/masque/](https://github.com/XTLS/Xray-core/tree/main/transport/internet/masque)
- **sing-box, SagerNet/sing-box:**
  - `masque-client` and `masque-server` endpoints "Since sing-box 1.15.0" (docs added 2026-10-11, commit b83089ecf6). It is a generic RFC 9484 client: default path `/.well-known/masque/ip/{target}/{ipproto}/`, HTTP versions 1/2/3 with fallback, MTU 1280. — [sing-box docs masque-client.md](https://github.com/SagerNet/sing-box/blob/HEAD/docs/configuration/endpoint/masque-client.md)
  - No `cf-connect-ip` or `cloudflareclient` strings were found by GitHub code search. Related issues: [#4000 feature request (2026-04-06)](https://github.com/SagerNet/sing-box/issues/4000), [#4561 "MASQUE over h2 is not work with Go 1.27"](https://github.com/SagerNet/sing-box/issues/4561).
- **yuhaiin:** WARP MASQUE over H3 with BBR (via `apernet/quic-go`) and over H2, using its own CONNECT-IP implementation. It was reviewed against usque 6aa03fc9 in an Oct 2026 review. — [yuhaiin docs/masque.md](https://github.com/yuhaiin/yuhaiin/blob/HEAD/docs/masque.md)

**Other implementations: derivatives found by GitHub code search for `cf-connect-ip` (2026-10-21; contents not audited)**
- Go: HynoR/uscf (usque fork), confeden/Nova and Nova-Android (`masque.go`, `masque_h2.go`), necronicle/z2k (`z2k-warpd` H2), ProjectClash/Clash and appshubcc/Bettbox (Clash.Meta `transport/masque`).
- Rust: GeorgeXie2333/usque-app (`usque-transport` h2.rs/h3.rs with Go "oracle" fixtures), CluvexStudio/Aether and several forks, Dushnilin/tachyon-core, Vincent-bin/masque-server (server side, with HTTP/2).
- Source: [GitHub code search "cf-connect-ip"](https://github.com/search?q=cf-connect-ip&type=code)

**Tooling and config generators (popular in Chinese and Iranian communities)**
- [byJoey/warp-masque-actions](https://github.com/byJoey/warp-masque-actions): about 1,074 stars; GitHub Actions that generate WARP MASQUE keys plus mihomo config.
- [KJGX66F/usque-custom-pro](https://github.com/KJGX66F/usque-custom-pro): about 1,518 stars; multi-client config converter.
- [6Kmfi6HP/warp-reg-gw](https://github.com/6Kmfi6HP/warp-reg-gw): registration plus QUIC endpoint scanning.
- [EdmundMad0309/warp-masque-bypass](https://github.com/EdmundMad0309/warp-masque-bypass): "MASQUE over HTTP/2 + SNI 伪装" for campus/corporate networks.
- Source: [GitHub repo search "warp masque"](https://github.com/search?q=warp+masque&type=repositories)

**warp-plus (bepass-org)**
- MASQUE support has been requested repeatedly: [#214 (2024-09-23)](https://github.com/bepass-org/warp-plus/issues/214), [#231](https://github.com/bepass-org/warp-plus/issues/231), [#268 (2025-05-27, open)](https://github.com/bepass-org/warp-plus/issues/268).
- Code search found no `masque` code, and the repo was last pushed 2025-12-15. — [bepass-org/warp-plus](https://github.com/bepass-org/warp-plus)

**Generic, non-WARP CONNECT-IP references**
- [google/quiche masque](https://github.com/google/quiche/tree/main/quiche/quic/masque): an RFC-compliant "toy" implementation.
- [ErikBcd/masquerade](https://github.com/ErikBcd/masquerade): Rust over quiche.
- Source: [usque issue #6](https://github.com/Diniboy1123/usque/issues/6)

### Inferences
- The ecosystem converged quickly in 2026. mihomo (Jan), usque H2 (Apr), usque/mihomo L4 (Jun) and Xray-core (Oct) all reuse the same reverse-engineered constants, so a Cloudflare-side change (for example, requiring PQ or validating SNI) would break all of them at once.
- Most third-party stacks are Go/quic-go and share quic-go's TLS/QUIC fingerprint, which differs from the official quiche/BoringSSL client.

### Gaps
- I did not audit the Rust derivatives (usque-rs, Aether, usque-app) line by line. Their PQ (P256Kyber768Draft00) support status is unverified.
- No public implementation of the official PQ key share was found in Go. Go's crypto/tls lacks P256Kyber768Draft00, per the maintainer in [usque issue #81](https://github.com/Diniboy1123/usque/issues/81).

## 6. Cloudflare announcements, rationale, current default protocol, and comparison with WireGuard

### Takeaway
Cloudflare announced MASQUE for Zero Trust WARP on 2024-03-06. The goals were to look like HTTPS, meet FIPS, be standards-based and get QUIC performance. On 2024-12-27 it made MASQUE the protocol of the consumer 1.1.1.1/WARP apps, with Auto/MASQUE/WireGuard selectable. Later additions: HTTP/2 TCP fallback (clients from May 2025), PQ key agreement (Sep 2025, P256Kyber768Draft00 inside the FIPS boundary) and QUIC-stream L4 proxy mode (Mar 2026). As of October 2026 the Zero Trust docs label MASQUE "(default)", and WireGuard remains selectable but is deprecated for proxy mode.

### Cited Findings
**Announcements**
- **2024-03-06, "Zero Trust WARP: tunneling with a MASQUE":**
  - "All customers want WARP traffic to look like HTTPS to avoid detection and blocking by firewalls", and "a significant number of customers also require FIPS-compliant encryption".
  - WireGuard "is not standards-based" and lacks advanced congestion control.
  - The first implementation "will use TLS 1.3 and FIPS compliant cipher suites".
  - The post cites WARP's WireGuard port 2408 and plans a Zero Trust beta in early Q2 2024.
  - Source: [Cloudflare blog](https://blog.cloudflare.com/zero-trust-warp-with-a-masque/)
- **2024-12-27, "MASQUE now powers 1.1.1.1 & WARP apps":**
  - "as of today, our cross-platform 1.1.1.1 & WARP apps now use MASQUE". All new installs on iOS, Android, macOS, Windows and Linux support it, and MASQUE is the preferred protocol over WireGuard.
  - Mobile setting: Advanced > Connection options > Tunnel protocol (Auto / MASQUE / WireGuard). Desktop: `warp-cli tunnel protocol set MASQUE|WireGuard`.
  - The post cites iCloud Private Relay and Microsoft Edge Secure Network as MASQUE at scale.
  - Source: [Cloudflare blog](https://blog.cloudflare.com/masque-now-powers-1-1-1-1-and-warp-apps-dex-available-with-remote-captures/)
- **2025-09-24, post-quantum WARP:**
  - PQ hybrid key agreement on MASQUE tunnels, on desktop 2025.5.893.0, iOS 1.11 and Android 2.4.2.
  - Consumer Phase 1 (PQ with downgrade allowed) is complete. Phase 2 (PQC-only) is planned for "summer of mid 2026".
  - MDM flag `enable_post_quantum`.
  - FIPS links use P256 ECDH with early ML-KEM-768. "MASQUE establishes a single very long-lived TLS connection".
  - Source: [Cloudflare blog](https://blog.cloudflare.com/post-quantum-warp/)
- **2026-03-05, faster SASE proxy mode:**
  - WireGuard is deprecated for local proxy mode, which now uses HTTP/3 CONNECT on QUIC streams.
  - "download and upload speeds doubled". Requires client 2025.8.779.0 or later.
  - Source: [Cloudflare blog](https://blog.cloudflare.com/faster-sase-proxy-mode-quic/)

**Current Zero Trust settings documentation**
- Device tunnel protocol: "MASQUE: (default) Establishes an HTTP/3 connection to Cloudflare". WireGuard "will encrypt traffic using a non-FIPs compliant cipher suite", whereas MASQUE uses TLS 1.3 with a FIPS 140-3 compliant suite.
- MASQUE minimum versions: Windows/macOS/Linux 2024.11.309.0, iOS 1.7, Android 2.0, ChromeOS 2.0.
- Source: [Cloudflare One docs, WARP settings](https://developers.cloudflare.com/cloudflare-one/connections/connect-devices/warp/configure-warp/warp-settings/)
- "Devices will use the MASQUE protocol in FedRAMP High environments." — [Cloudflare One docs, firewall](https://developers.cloudflare.com/cloudflare-one/connections/connect-devices/warp/deployment/firewall/)

**Comparison with WireGuard (from the sources above)**

| Aspect | WireGuard mode | MASQUE mode |
|---|---|---|
| Transport | UDP only. ZT: 162.159.193.0/24, UDP 2408 plus 500/1701/4500. Consumer: 162.159.192.0/24. | UDP 443 (H3) plus fallback UDP ports, and TCP 443 (H2). ZT: 162.159.197.0/24; consumer 162.159.198.x per reverse engineering. |
| Crypto | Fixed Noise suite, curve25519 key enrolled via API, not FIPS. | TLS 1.3, P-256 or P256Kyber768Draft00, FIPS 140-3. |
| Authentication | WireGuard static keys. | mTLS with an enrolled secp256r1 key; server key pinned. |
| Wire look | Distinctive WireGuard handshake. | Ordinary-looking QUIC/HTTP/3 or TLS/HTTP/2 with a Cloudflare SNI. |
| Kernel support | Kernel WireGuard possible, e.g. wgcf. | Userspace only. |
| Proxy mode | Deprecated. | QUIC-stream L4 proxy. |
| Idle behavior | Similar idle disconnects. | Similar idle disconnects. |

- Sources for the table: [CF firewall docs](https://developers.cloudflare.com/cloudflare-one/connections/connect-devices/warp/deployment/firewall/); [CF WARP settings](https://developers.cloudflare.com/cloudflare-one/connections/connect-devices/warp/configure-warp/warp-settings/); [usque README](https://github.com/Diniboy1123/usque/blob/6aa03fc97d12848dce34eedbd187fb1077b5d1ea/README.md#should-i-replace-wireguard-with-this); [usque issue #30](https://github.com/Diniboy1123/usque/issues/30)
- usque author's view: "MASQUE is userspace, and so is QUIC … making the implementation slower". It does offer "full blown TLS support … adjustable congestion control". Reasons to switch include "certain networks block WireGuard, but don't block QUIC" and reports that WARP+ no longer works over WireGuard for some users. — [usque README](https://github.com/Diniboy1123/usque/blob/6aa03fc97d12848dce34eedbd187fb1077b5d1ea/README.md#should-i-replace-wireguard-with-this)
- In a March 2026 Russian forum report, MASQUE dropped on laptop sleep or monitor-off while WireGuard did not. Users report that 2026 client versions reconnect almost instantly after wake. — [ntc.party WARP thread p.19](https://ntc.party/t/cloudflare-warp-%D0%BF%D0%B5%D1%80%D0%B2%D1%8B%D0%B9-%D1%81%D1%80%D0%B5%D0%B4%D0%B8-%D0%B2%D1%81%D0%B5%D1%85/15292?page=19)

### Inferences
- For consumer apps the documented default since 2024-12-27 is MASQUE, or "Auto" with MASQUE preferred. I found no later Cloudflare statement reverting it, so MASQUE is very likely still the consumer default as of Oct 2026.
- The PQ Phase 2 plan (PQC-only, mid-2026) is the largest compatibility risk for classical-only third-party clients like usque. As of the latest evidence (usque issue #73, Mar 2026; Xray PR #6878, Oct 2026), classical secp256r1 connections still worked for consumer accounts.

### Gaps
- No Cloudflare source dated 2026 explicitly states the consumer default (Auto vs MASQUE) or whether Phase 2 PQC-only enforcement happened for consumer endpoints.
- The changelog entries for the H2 fallback returned 404 to direct fetch. The text is confirmed only via search snippets and a user quote in usque issue #32.

## 7. Censorship-resistance observations

### Takeaway
MASQUE looks like generic HTTP/3 or HTTPS, and it has worked on networks that block WireGuard (train Wi-Fi, corporate networks via H2 fallback). It is still blockable in two ways:
1. Through the plaintext-derivable SNI in the QUIC Initial (`consumer-masque.cloudflareclient.com`). Russia's TSPU uses QUIC SNI filtering.
2. Through wholesale UDP/QUIC blocking (Iran, June 2025).

Russian users reported MASQUE being "heavily blocked" by some ISPs from about February 2026 and used zapret QUIC fakes or the TCP/H2 fallback to get around it. For the L3 tunnel the server does not validate SNI, so a custom SNI works. The L4 proxy mode rejects non-official SNIs with 403. Xray reports H3 and H2 WARP working in Iran (Oct 2026) with noise and fragmentation.

### Cited Findings
**What a censor can see and how it is blocked**
- usque README: "There is hardly a way to distinguish MASQUE traffic from other HTTP/3 traffic. However QUIC mandates TLS v1.3 so we send a ClientHello with `client-masque.cloudflareclient.com` in the SNI field. Some firewalls may block this. You can change the SNI by specifying `-s` flag to any domain … and the connection will still work." Note that the README says `client-masque`, while the code and the official client use `consumer-masque.cloudflareclient.com`; this looks like a README typo. — [usque README "Censorship circumvention"](https://github.com/Diniboy1123/usque/blob/6aa03fc97d12848dce34eedbd187fb1077b5d1ea/README.md#censorship-circumvention); [internal/consts.go L6](https://github.com/Diniboy1123/usque/blob/6aa03fc97d12848dce34eedbd187fb1077b5d1ea/internal/consts.go#L6)
- With custom SNI, the client pins the server key instead of verifying the hostname, so arbitrary SNI is safe for the L3 tunnel. Xray: "the server cert is checked against it so the sni can be anything". — [Xray-core PR #6878](https://github.com/XTLS/Xray-core/pull/6878)
- L4 proxy mode rejects unexpected SNI with 403. — [usque issue #110](https://github.com/Diniboy1123/usque/issues/110); [wiki L4-proxy-mode](https://github.com/Diniboy1123/usque/wiki/L4-proxy-mode)
- Observed bypasses:
  - "WireGuard was also blocked on the local train WiFi, but MASQUE wasn't." — [usque README "Why was this built?"](https://github.com/Diniboy1123/usque/blob/6aa03fc97d12848dce34eedbd187fb1077b5d1ea/README.md#why-was-this-built)
  - A corporate network with "quic … fully blocked": official Windows clients automatically fell back to HTTP/2 (Aug 2025). — [usque issue #32](https://github.com/Diniboy1123/usque/issues/32)
- **Russia, measurement:** a FOCI 2026 paper reports that Russia's TSPU moved from blocking all international QUIC to SNI-based QUIC filtering via packet dropping. The SNI in the QUIC Initial can be decrypted by middleboxes because Initial keys derive from public values. — [FOCI 2026 "On Russia's Early Introduction of QUIC SNI Censorship"](https://www.petsymposium.org/foci/2026/foci-2026-0010.php); [ntc.party discussion](https://ntc.party/t/on-russias-early-introduction-of-quic-sni-censorship-foci-2026/25670)
- **Russia, user reports (ntc.party, March 2026):**
  - "on my provider about 2 weeks ago masque also began to be heavily blocked" (March 4, 2026).
  - Others report "both Warp and usque work" when using zapret2 with a QUIC fake, or plain HTTP/2. The "lite option is to use tcp fallback".
  - One user runs usque in SOCKS5 mode with zapret on Linux.
  - Source: [ntc.party "CloudFlare Warp" thread p.19](https://ntc.party/t/cloudflare-warp-%D0%BF%D0%B5%D1%80%D0%B2%D1%8B%D0%B9-%D1%81%D1%80%D0%B5%D0%B4%D0%B8-%D0%B2%D1%81%D0%B5%D1%85/15292?page=19)
- **Iran:**
  - During the June 2025 blackout "virtually all UDP-based protocols were blocked" on major networks (WireGuard, QUIC, OpenVPN …). — [Lantern censorship corpus: HTTP/3 QUIC block](https://corpus.lantern.io/techniques/http3-quic-block/)
  - Xray's WARP MASQUE was "tested in iran on the real network with finalmask noise and fragment: http/3 and http/2 both connect and hold up" (Oct 2026). — [Xray-core PR #6878](https://github.com/XTLS/Xray-core/pull/6878)
- **Blocked port 443:** a user had UDP/443 blocked in their region but found alternative ports working with warp-cli. The example given was 162.159.199.1:8090, a port not in Cloudflare's documented list; this is unverified. — [usque issue #41](https://github.com/Diniboy1123/usque/issues/41)
- **Single working endpoint:** in one country only one Cloudflare endpoint worked for a ZT user, and swapping endpoint IPs was "hit or miss". — [usque issue #31](https://github.com/Diniboy1123/usque/issues/31)

**Fingerprinting**
- usque's Go TLS/QUIC fingerprint differs from the official quiche/BoringSSL client. The maintainer argues "the unique TLS fingerprint is probably useful against DPI as well which probably only has the fingerprint of the official client". This is opinion, not measurement. — [usque issue #81](https://github.com/Diniboy1123/usque/issues/81)
- Xray's H2 uses a uTLS Chrome fingerprint, and "utls fingerprints send the client cert now too, http/2 needs it". H3 cannot mimic Chrome because of the 20-byte CID and 1280-byte room requirements. — [Xray-core PR #6878](https://github.com/XTLS/Xray-core/pull/6878); [PR #7121](https://github.com/XTLS/Xray-core/pull/7121)

### Inferences
- Several features stand out to a censor even with a spoofed SNI: the destination (Cloudflare anycast 162.159.19x.x WARP ranges), the 20-byte client CIDs, the HelloRetryRequest to P-256, the TLS client-certificate exchange (encrypted in TLS 1.3, but it changes flight sizes), and a long-lived single QUIC flow carrying constant datagrams. IP-range blocking of 162.159.197–199.0/24 would defeat SNI tricks. Inferred, not measured.
- H2 over TCP 443 is the practical fallback in UDP-hostile networks (Iran blackouts, corporate). It inherits TCP-over-TCP performance problems, and per yuhaiin it uses the OS TCP congestion controller rather than QUIC BBR. — [yuhaiin docs/masque.md](https://github.com/yuhaiin/yuhaiin/blob/HEAD/docs/masque.md)

### Gaps
- No systematic measurement study specifically of WARP MASQUE blocking (China, Iran, Russia) was found. The evidence is forum and issue anecdotes plus general QUIC-censorship research.
- No reports on whether GFW (China) SNI-based QUIC censorship specifically targets `*.cloudflareclient.com` were found.
