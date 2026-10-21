# Cloudflare WARP device registration / enrollment API and account model (as implemented by community clients, state as of 2026-10-21)

Abbreviations used below:
- **wgcf@de6bba7**: ViRb3/wgcf at commit `de6bba7147dc965a1b8e4de113a709750697ccea` (2026-10-11, release v2.3.1).
- **usque@6aa03fc**: Diniboy1123/usque at `6aa03fc97d12848dce34eedbd187fb1077b5d1ea` (2026-07-20).
- **warp-plus@f70ea7e**: bepass-org/warp-plus at `f70ea7e4f193717c73f9a4357cbc98d6944b36bb` (2025-11-17).
- **wgcf-cli@1b43d47**: ArchiveNetwork/wgcf-cli at `1b43d47c348a003949e064786378c643872d9db1` (2024-10-12).
- **wgcf-mesh@8ddecda**: AnimMouse/wgcf-mesh at `8ddecda5690650798dba9c3c441aa8305223569a` (2026-10-16).
- Access notes: `fscarmen/warp` and `ALIILAPRO/warp-plus-cloudflare` return GitHub "Repository access blocked (reason: tos)" (blocked 2023-09-13 and 2023-01-23 respectively), so their code could not be read. `fscarmen/warp-sh` holds only READMEs.

---

## 1. Base URL and API version path; which versions repos use; how it changed over time

### Takeaway
Every consumer client uses `https://api.cloudflareclient.com/<ver>/…`. `<ver>` is `v0a<build>` for Android-app builds; some versions also use `v0i…`, which looks like iOS, or plain `v0`/`v1` for newer Zero Trust paths. The version path is not pinned. Repos in active use send anything from `v0a1922` (2021) to `v0a5641` (wgcf, 2026-09), and all of them reportedly work, so the server seems to accept a wide range of version strings. In 2026, the Zero Trust and Mesh registrations seen in the Linux client use a separate host and path family: `api.devices.cloudflare.com`, with `/v0/reg` and `/v1/accounts/{account_tag}/…`.

### Cited Findings
**Current constants per repo (newest first)**
- wgcf (2026-09-18 onward): `ApiUrl = "https://api.cloudflareclient.com"`, `ApiVersion = "v0a5641"`, `User-Agent: 1.1.1.1/6.38.9-5641 (Android 16.0.0)`, `CF-Client-Version: a-6.38.9-5641`. The spec header says "Cloudflare WARP Android API contract for version 6.38.9 (build 5641)". — [wgcf cloudflare/api.go@de6bba7](https://github.com/ViRb3/wgcf/blob/de6bba7147dc965a1b8e4de113a709750697ccea/cloudflare/api.go); [wgcf openapi-spec.yml@de6bba7](https://github.com/ViRb3/wgcf/blob/de6bba7147dc965a1b8e4de113a709750697ccea/openapi-spec.yml)
- The bump commit is `803310a` (2026-09-18), "fix: update api to v0a5641 and pin tls fingerprint, closes #626", shipped in v2.3.0. — [wgcf commit 803310a](https://github.com/ViRb3/wgcf/commit/803310a27bf040ac831b74cf3b4b993482f48647); [wgcf CHANGELOG](https://github.com/ViRb3/wgcf/blob/de6bba7147dc965a1b8e4de113a709750697ccea/CHANGELOG.md)
- **Historical:** wgcf used `ApiVersion = "v0a1922"`, `User-Agent: okhttp/3.12.1`, `CF-Client-Version: a-6.3-1922` from 2021-02-22 (commit `82e18f61`, "fix: update API to v0a1922") through 2025-08-22 (commit `8666a8be`). The very first API code (2020-07-28, `74663e89`) sent only `User-Agent: okhttp/3.12.1`. — [wgcf commit 82e18f61](https://github.com/ViRb3/wgcf/commit/82e18f61); [wgcf api.go@8666a8be](https://github.com/ViRb3/wgcf/blob/8666a8be/cloudflare/api.go)
- usque: `ApiVersion = "v0a4471"`, `User-Agent: "WARP for Android"`, `CF-Client-Version: "a-6.35-4471"`. These have not changed since the first public commit (2025-02-20) and were still the same on 2026-06-16. — [usque internal/consts.go@6aa03fc](https://github.com/Diniboy1123/usque/blob/6aa03fc97d12848dce34eedbd187fb1077b5d1ea/internal/consts.go)
- usque RESEARCH.md shows a captured Android-app request to `PATCH https://api.cloudflareclient.com/v0a4616/reg/<id>` with `CF-Client-Version: a-6.81-4616`. — [usque RESEARCH.md](https://github.com/Diniboy1123/usque/blob/6aa03fc97d12848dce34eedbd187fb1077b5d1ea/RESEARCH.md)
- warp-plus: `apiBase = "https://api.cloudflareclient.com/v0a4005"` with `User-Agent: okhttp/3.12.1` and `CF-Client-Version: a-6.30-3596`. The path build (4005) and the header build (3596) do not match. The API was rewritten 2024-05-21 (`bb5871fd`). — [warp-plus warp/api.go@f70ea7e](https://github.com/bepass-org/warp-plus/blob/f70ea7e4f193717c73f9a4357cbc98d6944b36bb/warp/api.go)
- wgcf-cli uses `https://api.cloudflareclient.com/v0a2158/...` with an invented `CF-Client-Version: a-7.21-0721` and `User-Agent: okhttp/0.7.21`. This has not changed since its initial commit on 2024-05-05. — [wgcf-cli utils/request.go@1b43d47](https://github.com/ArchiveNetwork/wgcf-cli/blob/1b43d47c348a003949e064786378c643872d9db1/utils/request.go)
- chise0713/warp-reg.sh (cited by the Xray docs) also posts to `/v0a2158/reg` with `CF-Client-Version: a-7.21-0721`. — [warp-reg.sh@8c93845](https://github.com/chise0713/warp-reg.sh/blob/8c93845d27a568992c9c62ae6d86a33d568d6050/warp-reg.sh)
- rany2/warp.sh (Teams-capable) uses `BASE_URL='https://api.cloudflareclient.com/v0a2483'`, `User-Agent: 1.1.1.1/6.81`, `CF-Client-Version: a-6.81-2410012252.0`. — [rany2/warp.sh@cad07da](https://github.com/rany2/warp.sh/blob/cad07dafa9ea93a3d7f122110ec52f43f77f9f42/warp.sh)
- WarpPlusKeyGenerator-NG (archived 2025-12-17) uses `https://api.cloudflareclient.com/v0a2223` with `CF-Client-Version: a-6.11-2223` and `User-Agent: okhttp/3.12.1`. — [WarpPlusKeyGenerator-NG main.py](https://github.com/0x24a/WarpPlusKeyGenerator-NG/blob/c9996c2c6fde7799006213f0332f8d6461bd4103/main.py)
- 6Kmfi6HP/warp-reg-gw (2026-07, MASQUE registrar) uses `v0a4471` + `a-6.35-4471` + `WARP for Android`, copying usque. — [warp-reg-gw registration.go](https://github.com/6Kmfi6HP/warp-reg-gw/blob/1c2edaefbf1233e8811b933c9a29298600093806/internal/registration/registration.go)

**Zero Trust / Mesh host and paths (2026)**
- wgcf-mesh worked out these from Linux `warp-svc` 2026.7.1377.0 on 2026-10-01:
  - The Zero Trust API host is `api.devices.cloudflare.com` (162.159.137.105 and 162.159.138.105). `zero-trust-client.cloudflareclient.com` resolves to the same IPs, and `api.cloudflareclient.com` also answers the same paths.
  - The paths are `POST /v1/accounts/{a}/warp_connector`, `POST /v0/reg` (team JWT), and `GET|PATCH|DELETE /v1/accounts/{a}/reg/{id}`.
  - The same `warp_connector` path under `/v0/` returns 404.

  — [wgcf-mesh API.md](https://github.com/AnimMouse/wgcf-mesh/blob/8ddecda5690650798dba9c3c441aa8305223569a/API.md); [wgcf-mesh HANDOFF.md](https://github.com/AnimMouse/wgcf-mesh/blob/8ddecda5690650798dba9c3c441aa8305223569a/HANDOFF.md)
- **Historical (2022):** a commenter in wgcf #56 pointed out that Cloudflare's firewall docs list `zero-trust-client.cloudflareclient.com` as the orchestration endpoint. Another commenter confirmed that `api.cloudflareclient.com` also worked for Teams registration. — [wgcf issue #56](https://github.com/ViRb3/wgcf/issues/56)

**Other endpoints in the current wgcf spec** (all under `/{apiVersion}/`):
- `client_config`
- `reg`
- `reg/{id}`
- `reg/{id}/account`
- `reg/{id}/account/devices`
- `reg/{id}/account/license`
- `reg/{id}/account/receipts`
- `reg/{id}/account/reg/{boundId}`
- `accounts/{accountId}/reg/{id}/auth`, used for a Gateway auth token
- `/notifications/v1/accounts/{accountId}/reg/{id}/ack`, outside the versioned prefix

— [wgcf openapi-spec.yml@de6bba7](https://github.com/ViRb3/wgcf/blob/de6bba7147dc965a1b8e4de113a709750697ccea/openapi-spec.yml)

### Inferences
- The server does not seem to enforce a strict match between the version path and the `CF-Client-Version` header. Several repos send mismatched or invented values and reportedly work: warp-plus (`v0a4005` with `a-6.30-3596`), wgcf-cli and warp-reg.sh (`a-7.21-0721`), and rany2 (`v0a2483` with `a-6.81-…`). warp-reg-gw's comment says the API "rejects clients whose version path and CF-Client-Version disagree", but these repos contradict it. Treat it as unverified folklore.
- The safest choice for a new implementation is to copy the newest Android build string set that wgcf ships (`v0a5641` / `a-6.38.9-5641` / `1.1.1.1/6.38.9-5641 (Android 16.0.0)`) together with its TLS fingerprint (Q7). In 2026 the fingerprint, not the version string, is what wgcf's maintainer found to matter.

### Gaps
- No official Cloudflare documentation of the consumer `/v0a…` API exists. Everything above is reverse-engineered.
- I found no source that tells `v0a…` (Android) apart from the `v0i…` (iOS) or `v0w`-style prefixes. I could not confirm those other prefixes from code in this pass.
- I could not see the exact date Cloudflare introduced `api.devices.cloudflare.com`.

---

## 2. Exact HTTP requests (method, path, headers, TLS), request and response JSON shapes

### Takeaway
Registration is an unauthenticated `POST /<ver>/reg` with a JSON body. Its centrepiece is `key`, the base64 public key, plus a `tos` timestamp; other fields are optional or can be empty strings. The response returns `id`, the device/registration UUID, and `token`, the bearer secret, which is **only returned here**. It also returns an `account` object and a `config` object with `client_id`, `interface.addresses.{v4,v6}`, `peers[0].{public_key, endpoint.{host,v4,v6,ports}}` and `services.http_proxy`. Every later call uses `Authorization: Bearer <token>` against `/<ver>/reg/<id>…`.

### Cited Findings
**Headers**
- wgcf (2026) sends:
  - `User-Agent: 1.1.1.1/6.38.9-5641 (Android 16.0.0)`
  - `CF-Client-Version: a-6.38.9-5641`
  - `Connection: Keep-Alive`
  - `Content-Type: application/json; charset=UTF-8` (rewritten from `application/json`)
  - No `Accept` header; it deletes it "to match the OkHttp request headers emitted by the Android client".
  - `Authorization: Bearer <token>` on authenticated calls.

  `/client_config` returns JSON labelled `text/plain`, which wgcf rewrites. — [wgcf cloudflare/api.go@de6bba7](https://github.com/ViRb3/wgcf/blob/de6bba7147dc965a1b8e4de113a709750697ccea/cloudflare/api.go)
- usque sends `User-Agent: WARP for Android`, `CF-Client-Version: a-6.35-4471`, `Content-Type: application/json; charset=UTF-8` and `Connection: Keep-Alive`. It adds `CF-Access-Jwt-Assertion: <jwt>` on `/reg` when a team JWT is given. — [usque internal/consts.go](https://github.com/Diniboy1123/usque/blob/6aa03fc97d12848dce34eedbd187fb1077b5d1ea/internal/consts.go); [usque api/cloudflare.go](https://github.com/Diniboy1123/usque/blob/6aa03fc97d12848dce34eedbd187fb1077b5d1ea/api/cloudflare.go)
- The wgcf OpenAPI spec declares an optional `Cf-Access-Jwt-Assertion` header parameter on `POST /{apiVersion}/reg`. — [wgcf openapi-spec.yml](https://github.com/ViRb3/wgcf/blob/de6bba7147dc965a1b8e4de113a709750697ccea/openapi-spec.yml)

**Register request: `POST /<ver>/reg`**
- wgcf body (2026):
  - `fcm_token: ""` and `install_id: ""`, with the comment "populated by Firebase in the Android app"
  - `key: <base64 Curve25519 public>`
  - `locale: "en_US"`
  - `model: <"PC" default>`
  - `tos: <time.RFC3339Nano>`
  - `serial_number: ""`
  - `os_version: "16.0.0"`
  - `key_type: "curve25519"`
  - `tunnel_type: "wireguard"`

  — [wgcf api.go `registrationRequest`](https://github.com/ViRb3/wgcf/blob/de6bba7147dc965a1b8e4de113a709750697ccea/cloudflare/api.go)
- Spec schema `Register_Request`:
  - Fields: `fcm_token`, `install_id`, `key`, `locale`, `model`, `referrer`, `tos`, `expired`, `serial_number`, `os_version`, `key_type`, `tunnel_type` (enum `wireguard|masque`).
  - Required: `fcm_token`, `install_id`, `key`, `locale`, `serial_number`.

  — [wgcf openapi-spec.yml](https://github.com/ViRb3/wgcf/blob/de6bba7147dc965a1b8e4de113a709750697ccea/openapi-spec.yml)
- usque body:
  - `key` is a **random 32 bytes base64**, not a real X25519 public key, "to mimic the Android app's registration process".
  - `install_id: ""`, `fcm_token: ""`
  - `tos` in the format `2006-01-02T15:04:05.000-07:00`
  - `model: "PC"`
  - `serial_number`: 16 random hex chars (8 bytes)
  - `os_version: ""`
  - `key_type: "curve25519"`, `tunnel_type: "wireguard"`
  - `locale: "en_US"`

  — [usque api/cloudflare.go](https://github.com/Diniboy1123/usque/blob/6aa03fc97d12848dce34eedbd187fb1077b5d1ea/api/cloudflare.go); [usque internal/utils.go](https://github.com/Diniboy1123/usque/blob/6aa03fc97d12848dce34eedbd187fb1077b5d1ea/internal/utils.go)
- warp-plus body: `install_id: ""`, `fcm_token: ""`, `tos: RFC3339Nano`, `key`, `type: "Android"`, `model: "PC"`, `locale: "en_US"`, `warp_enabled: true`. — [warp-plus warp/api.go](https://github.com/bepass-org/warp-plus/blob/f70ea7e4f193717c73f9a4357cbc98d6944b36bb/warp/api.go)
- wgcf-cli fakes Firebase identifiers:
  - `install_id` is 22 random chars from `[a-zA-Z0-9-_]`
  - `fcm_token` is `"<install_id>:APA91b<134 random chars>"`
  - `tos` is `UTC 2006-01-02T15:04:05.999Z`
  - `model: "Android"`
  - `serial_number` is the same value as `install_id`

  — [wgcf-cli cmd_register.go](https://github.com/ArchiveNetwork/wgcf-cli/blob/1b43d47c348a003949e064786378c643872d9db1/cmd/wgcf-cli/cmd_register.go)
- Minimal bodies are accepted. warp-reg.sh posts only `{"key": ..., "tos": ...}` (curl `--tlsv1.3`). WarpPlusKeyGenerator-NG posted `/reg` with **no body at all** and still received `id`, `token` and `account.license`; this is historical, about 2024. — [warp-reg.sh](https://github.com/chise0713/warp-reg.sh/blob/8c93845d27a568992c9c62ae6d86a33d568d6050/warp-reg.sh); [WarpPlusKeyGenerator-NG main.py](https://github.com/0x24a/WarpPlusKeyGenerator-NG/blob/c9996c2c6fde7799006213f0332f8d6461bd4103/main.py)

**Register response** (`Register_200_Response` = SourceDevice + extras)
- SourceDevice fields:
  - `id` (uuid)
  - `type`, `name`, `model`, `manufacturer`, `os_version`, `serial_number`
  - `key`
  - `fcm_token`, `install_id`
  - `locale`
  - `tos`
  - `created`, `updated`
  - `enabled`, `warp_enabled`, `waitlist_enabled`
  - `place`
  - `device_id`
- Extras:
  - `token` (uuid; required on `/reg`)
  - `account`, `config`, `policy`
  - `override_codes`, `alternate_networks[]`, `dex_tests[]`
  - `key_type`, `tunnel_type`

  `key_type`/`tunnel_type` are required on register, but v2.3.1 made them optional on GET because older accounts lack them (wgcf #629). — [wgcf openapi-spec.yml](https://github.com/ViRb3/wgcf/blob/de6bba7147dc965a1b8e4de113a709750697ccea/openapi-spec.yml); [wgcf issue #629](https://github.com/ViRb3/wgcf/issues/629)
- `config` schema: `client_id` (string) and `interface.addresses.{v4,v6}`. Peers have the form `peers[].{public_key, endpoint.{host,v4,v6,ports[]}}`, where `ports` defaults to `[2408, 500, 1701, 4500]`. There is also `services.http_proxy`. — [wgcf openapi-spec.yml](https://github.com/ViRb3/wgcf/blob/de6bba7147dc965a1b8e4de113a709750697ccea/openapi-spec.yml)
- Endpoint formats as seen by clients:
  - `endpoint.v4` looks like `162.159.193.5:0` and `endpoint.v6` like `[2606:4700:100::a29f:c105]:0`. The port is always 0; combine the address with `ports`.
  - `endpoint.host` is `engage.cloudflareclient.com:2408`.
  - usque likewise strips the `:0` and `[...]:0`.

  — [wgcf-mesh API.md](https://github.com/AnimMouse/wgcf-mesh/blob/8ddecda5690650798dba9c3c441aa8305223569a/API.md); [usque cmd/register.go](https://github.com/Diniboy1123/usque/blob/6aa03fc97d12848dce34eedbd187fb1077b5d1ea/cmd/register.go)
- wgcf builds the endpoint as follows: prefer `endpoint.host`; otherwise use `v4` (or `v6`), strip the port, and append `ports[0]` (default 2408). — [wgcf api.go `WireGuardEndpoint`](https://github.com/ViRb3/wgcf/blob/de6bba7147dc965a1b8e4de113a709750697ccea/cloudflare/api.go)
- An example consumer WireGuard output from warp-reg.sh: endpoint v4 `162.159.192.7`, v6 `[2606:4700:d0::a29f:c007]`, peer public key `bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=`, interface `172.16.0.2` / `2606:4700:110:…`. — [Xray-docs warp.md@59ab79c](https://github.com/XTLS/Xray-docs-next/blob/59ab79c7e09112475e7907bf745913ded7ca89a5/docs/en/document/level-2/warp.md)
- The Account object:
  - `id`, `account_type` (`free|limited|unlimited|team`), `license`
  - `created`, `updated`, `ttl`, `plus_expires_at`
  - `managed` (`api|not_api_managed`)
  - `premium_data`, `quota`, `usage`
  - `referral_count`, `referral_renewal_countdown`
  - `role` (`parent|child`)
  - `warp_plus`

  — [wgcf openapi-spec.yml](https://github.com/ViRb3/wgcf/blob/de6bba7147dc965a1b8e4de113a709750697ccea/openapi-spec.yml)
- The `policy` object in the device response:
  - Identity and mode: `organization`, `service_mode`/`service_mode_v2` (`1dot1|warp|posture_only|warp_tunnel_only|proxy`), `gateway_unique_id`, `unique_client_id`, `policy_id`.
  - Tunnel and endpoint overrides: `tunnel_protocol` (`wireguard|masque`), `post_quantum` (`disabled|enabled|enabled_with_downgrades`), `override_api_endpoint`, `override_warp_endpoint`, `override_doh_endpoint`.
  - Routing: `include`, `exclude`, `fallback_domains`, `always_exclude`, `always_include`.
  - Client behaviour: `switch_locked`, `auto_connect`, `allowed_to_leave`.
  - Service-token credentials: `auth_client_id`, `auth_client_secret`.

  — [wgcf openapi-spec.yml](https://github.com/ViRb3/wgcf/blob/de6bba7147dc965a1b8e4de113a709750697ccea/openapi-spec.yml)

**Post-registration calls (consumer API)**
- `GET /<ver>/reg/{id}` returns the full device and config. It takes an optional `?network=` query.
- `PATCH /<ver>/reg/{id}` updates the source device (`key`, `key_type`, `tunnel_type`, `fcm_token`, `name`, `os_version`, `manufacturer`, `model`, `device_id`) and returns 200 with the device or 204.
- `DELETE /<ver>/reg/{id}` returns 204.
- `GET /<ver>/reg/{id}/account`.
- `PUT /<ver>/reg/{id}/account` with `{"license": "..."}`.
- `GET /<ver>/reg/{id}/account/devices`.
- `PATCH /<ver>/reg/{id}/account/reg/{boundId}` with `{"name": ...}` or `{"active": bool}` returns the device array.
- `DELETE /<ver>/reg/{id}/account/reg/{boundId}`.
- `POST /<ver>/reg/{id}/account/license` returns `{"license": "..."}`, which resets or regenerates the license.
- `GET /<ver>/client_config`.

— [wgcf openapi-spec.yml](https://github.com/ViRb3/wgcf/blob/de6bba7147dc965a1b8e4de113a709750697ccea/openapi-spec.yml); [warp-plus warp/api.go](https://github.com/bepass-org/warp-plus/blob/f70ea7e4f193717c73f9a4357cbc98d6944b36bb/warp/api.go)

- usque additionally uses `DELETE /<ver>/reg/{id}/account` to unbind the license key. — [usque api/cloudflare.go](https://github.com/Diniboy1123/usque/blob/6aa03fc97d12848dce34eedbd187fb1077b5d1ea/api/cloudflare.go)
- The wgcf register flow is: `POST /reg` → save `private_key`, `device_id`, `access_token`, `license_key` → `PATCH /reg/{id}/account/reg/{id}` `{"name": <random 6-hex>}` → `GET /account` → `GET /account/devices`. HTTP 500 on the rename is tolerated as "server-side issue, but the operation still works". — [wgcf cmd/register/register.go](https://github.com/ViRb3/wgcf/blob/de6bba7147dc965a1b8e4de113a709750697ccea/cmd/register/register.go); [wgcf cmd/shared/shared.go](https://github.com/ViRb3/wgcf/blob/de6bba7147dc965a1b8e4de113a709750697ccea/cmd/shared/shared.go)
- The profile wgcf generates:
  - `Address = <v4>/32, <v6>/128`
  - `DNS = 1.1.1.1, 1.0.0.1, 2606:4700:4700::1111, 2606:4700:4700::1001`
  - `MTU = 1280` ("just like the official Android app")
  - `AllowedIPs = 0.0.0.0/0, ::/0`
  - optional `PersistentKeepalive` (added in v2.3.0)

  — [wgcf wireguard/profile.go](https://github.com/ViRb3/wgcf/blob/de6bba7147dc965a1b8e4de113a709750697ccea/wireguard/profile.go); [wgcf README](https://github.com/ViRb3/wgcf/blob/de6bba7147dc965a1b8e4de113a709750697ccea/README.md)
- The error body shape is `{"success": false, "errors": [{"code": N, "message": "..."}], ...}`. Known codes include 1001 (invalid public key), 2004 (bad device request), 2016 (unauthorized, 401), 2082 (invalid device OS for connector), 3004 (invalid `warp_connector_token`) and 3006 (missing key field). — [usque models/apierror.go](https://github.com/Diniboy1123/usque/blob/6aa03fc97d12848dce34eedbd187fb1077b5d1ea/models/apierror.go); [wgcf-mesh API.md](https://github.com/AnimMouse/wgcf-mesh/blob/8ddecda5690650798dba9c3c441aa8305223569a/API.md)

**TLS**: see Q7. In brief, wgcf pins a TLS 1.2-only, HTTP/1.1 ClientHello that imitates Android Conscrypt via uTLS. warp-plus uses uTLS with a padding extension and dials a fixed Cloudflare IP range.

### Inferences
- `token` is effectively the device's long-term secret. No refresh-token flow appears in any repo. Clients persist `{id, token, private key, license}`; wgcf names these `device_id`, `access_token`, `private_key` and `license_key`.
- `GET /reg/{id}` is the call for (re)fetching config. Clients that need fresh endpoints or addresses, such as for Zero Trust IPv6, re-read it, or re-PATCH the key (usque `enroll`).
- `fcm_token`, `install_id` and `serial_number` can be empty strings for consumer registration. wgcf (the most heavily used tool) sends them empty in 2026.

### Gaps
- No repo documents a full, verbatim raw `/reg` response from 2026 for consumer WireGuard. The schema above is from the wgcf OpenAPI spec, which is generated or curated from traffic.
- What `services.http_proxy`, `alternate_networks` and `override_codes` mean is not explained in any source I read.

---

## 3. Key types: WireGuard (Curve25519) vs MASQUE (ECDSA P-256), and switching an existing registration

### Takeaway
WireGuard registrations send `key` as a base64 32-byte X25519 public key with `key_type: "curve25519"` and `tunnel_type: "wireguard"`. MASQUE uses an ECDSA P-256 key: `key` is the base64 **SubjectPublicKeyInfo (PKIX DER)** public key, with `key_type: "secp256r1"` and `tunnel_type: "masque"`. Switching an existing device is a single authenticated `PATCH /<ver>/reg/{id}` carrying `{key, key_type, tunnel_type}`; the official Android app sends this when the user switches to MASQUE. For MASQUE, the response's `peers[0].public_key` is the edge's P-256 public key in PEM rather than a WireGuard key. The client authenticates to the MASQUE edge by mTLS, using a self-signed certificate made from the enrolled private key.

### Cited Findings
- The usque constants are `KeyTypeWg = "curve25519"`, `TunTypeWg = "wireguard"`, `KeyTypeMasque = "secp256r1"` and `TunTypeMasque = "masque"`. The MASQUE SNIs are `consumer-masque.cloudflareclient.com` (tunnel) and `consumer-masque-proxy.cloudflareclient.com` (L4 proxy mode). `zt-masque.cloudflareclient.com` is noted as unused, and the CONNECT authority is `https://cloudflareaccess.com`. — [usque internal/consts.go](https://github.com/Diniboy1123/usque/blob/6aa03fc97d12848dce34eedbd187fb1077b5d1ea/internal/consts.go)
- The usque registration flow has two steps:
  1. `POST /reg` with a random 32-byte "WireGuard-like" key and `curve25519`/`wireguard`.
  2. Generate an ECDSA P-256 key and `PATCH /reg/{id}` with `{"key": base64(x509.MarshalPKIXPublicKey(pub)), "key_type": "secp256r1", "tunnel_type": "masque", "name"?: ...}`, plus `Authorization: Bearer <token>`.

  usque stores the private key as base64 SEC1 DER (`x509.MarshalECPrivateKey`). — [usque api/cloudflare.go `EnrollKey`](https://github.com/Diniboy1123/usque/blob/6aa03fc97d12848dce34eedbd187fb1077b5d1ea/api/cloudflare.go); [usque cmd/register.go](https://github.com/Diniboy1123/usque/blob/6aa03fc97d12848dce34eedbd187fb1077b5d1ea/cmd/register.go); [usque internal/utils.go](https://github.com/Diniboy1123/usque/blob/6aa03fc97d12848dce34eedbd187fb1077b5d1ea/internal/utils.go)
- The captured app request is `PATCH /v0a4616/reg/<id>` with `{"key":"M…==","key_type":"secp256r1","tunnel_type":"masque"}`, and "The app sends this once you switch over to the MASQUE protocol". An ASN.1 decode showed `ecPublicKey` / `prime256v1`. — [usque RESEARCH.md](https://github.com/Diniboy1123/usque/blob/6aa03fc97d12848dce34eedbd187fb1077b5d1ea/RESEARCH.md)
- usque `enroll` re-PATCHes the stored or a regenerated key. It is used "if your account had WireGuard enabled and you want to switch to MASQUE" and when migrating devices. API error code 1001 (`InvalidPublicKey`) triggers a regenerate prompt. — [usque README](https://github.com/Diniboy1123/usque/blob/6aa03fc97d12848dce34eedbd187fb1077b5d1ea/README.md); [usque cmd/enroll.go](https://github.com/Diniboy1123/usque/blob/6aa03fc97d12848dce34eedbd187fb1077b5d1ea/cmd/enroll.go)
- In the MASQUE response, `peers[0].public_key` is a PEM `-----BEGIN PUBLIC KEY-----` P-256 key, stored as `endpoint_pub_key` and used to pin the edge certificate. The endpoints are `162.159.198.1` / `2606:4700:103::`, with `162.159.198.2` used for HTTP/2 mode. — [usque README (config section)](https://github.com/Diniboy1123/usque/blob/6aa03fc97d12848dce34eedbd187fb1077b5d1ea/README.md)
- warp-reg-gw (2026-07) does the same two steps and observes endpoint ports such as `[443,500,1701,4500,4443,8443,8095]`. It notes that "Some responses return base64 DER directly" instead of PEM, so a parser should accept both. — [warp-reg-gw registration.go](https://github.com/6Kmfi6HP/warp-reg-gw/blob/1c2edaefbf1233e8811b933c9a29298600093806/internal/registration/registration.go)
- Client authentication to the MASQUE edge:
  - The client presents a self-signed X.509 certificate signed by the enrolled P-256 key, and "Cloudflare only checks whether its public key is the one registered for this device".
  - The device must have `warp_enabled` on, "otherwise the endpoint returns access denied".
  - The official client generates a new certificate per connection, valid for 24 hours.

  — [Xray-docs warp.md (MASQUE section, added 2026-10-21, marked "written by AI")](https://github.com/XTLS/Xray-docs-next/blob/59ab79c7e09112475e7907bf745913ded7ca89a5/docs/en/document/level-2/warp.md); [usque RESEARCH.md](https://github.com/Diniboy1123/usque/blob/6aa03fc97d12848dce34eedbd187fb1077b5d1ea/RESEARCH.md)
- The Xray docs list per-account-type MASQUE edges: WARP `162.159.198.2` / `2606:4700:103::2`, WARP+ `162.159.199.2` / `2606:4700:104::2`, Zero Trust `162.159.197.2` / `2606:4700:102::2`, all with the same pinned key. These are labelled "tested", not official. — [Xray-docs warp.md](https://github.com/XTLS/Xray-docs-next/blob/59ab79c7e09112475e7907bf745913ded7ca89a5/docs/en/document/level-2/warp.md)
- In Zero Trust and Mesh, the official Linux client sends `tunnel_key_data: {key_type: "secp256r1", tunnel_type: "masque"}` on registration. It then rotates to a Curve25519 key in a second call if the device profile says WireGuard. The client also sends an `mtls_csr` field, null in the observed captures.

  For third-party clients: leave `tunnel_key_data` out and the server accepts a Curve25519 key directly. Sending `{key_type:"curve25519", tunnel_type:"wireguard"}` inside `tunnel_key_data` is rejected with `2004 bad device request`. A WireGuard config is returned even when the profile's `policy.tunnel_protocol` is `"masque"`. — [wgcf-mesh API.md](https://github.com/AnimMouse/wgcf-mesh/blob/8ddecda5690650798dba9c3c441aa8305223569a/API.md); [wgcf-mesh HANDOFF.md](https://github.com/AnimMouse/wgcf-mesh/blob/8ddecda5690650798dba9c3c441aa8305223569a/HANDOFF.md)
- wgcf explicitly declares MASQUE out of scope (2024-10-20). — [wgcf issue #426](https://github.com/ViRb3/wgcf/issues/426)

### Inferences
- A single registration has exactly one active key and tunnel type at a time. PATCHing a P-256 key presumably invalidates the WireGuard key, and vice versa. A client wanting both would need two registrations.
- For a MASQUE-only client, the Curve25519 key in the initial `/reg` is a throwaway; usque does not even generate a valid one. Registering directly with `key_type: "secp256r1"` and `tunnel_type: "masque"` in `/reg` may work, since the spec allows `tunnel_type` on the request, but no repo was seen doing it on the consumer API.

### Gaps
- No repo documented whether `POST /reg` directly with a P-256 key works on the consumer API.
- The exact MASQUE CSR (`mtls_csr`) semantics are unknown.

---

## 4. WARP+ license keys, device limits, account/quota queries; referral and key-generator tools and their status

### Takeaway
A license is bound with `PUT /<ver>/reg/{id}/account` `{"license": "<xxxxxxxx-xxxxxxxx-xxxxxxxx>"}`. That moves the device under the license's parent account; the device becomes `role: child` and shares its WARP+ status. Accounts are capped at **5 linked devices**; exceeding the cap returns a generic `400`. `GET …/account` returns `account_type`, `premium_data`, `quota`, `usage`, `referral_count` and so on. The "key generator" tools abused the referral program: register throwaway devices with `referrer = <target id>`, then shuffle licenses. Cloudflare ended the referral program on **2024-11-01**, so these tools are dead, archived or paused. In 2025–2026, community reports say WARP+ only works with keys from real 1.1.1.1 subscriptions, and over WireGuard often shows `warp=on` instead of `warp=plus`.

### Cited Findings
- The license format is three dash-separated parts (`xxxxxxxx-xxxxxxxx-xxxxxxxx`); wgcf has a validator `IsWarpLicenseKey`. — [usque cmd/account.go](https://github.com/Diniboy1123/usque/blob/6aa03fc97d12848dce34eedbd187fb1077b5d1ea/cmd/account.go); [wgcf util/credentials.go](https://github.com/ViRb3/wgcf/blob/de6bba7147dc965a1b8e4de113a709750697ccea/util/credentials.go)
- wgcf's update flow:
  1. `GET /reg/{id}/account` and compare `license`.
  2. If it differs, `PUT /reg/{id}/account` `{"license": key}` and save it.
  3. `GET /account/devices`.
  4. Optionally `PATCH /account/reg/{boundId}` `{"active": bool}` or `{"name": ...}`, or `DELETE` it.

  Per the help text, "there is a maximum limit of 5 active devices linked to the same account". — [wgcf cmd/update/update.go](https://github.com/ViRb3/wgcf/blob/de6bba7147dc965a1b8e4de113a709750697ccea/cmd/update/update.go); [wgcf api.go](https://github.com/ViRb3/wgcf/blob/de6bba7147dc965a1b8e4de113a709750697ccea/cloudflare/api.go)
- Exceeding 5 devices returns "a generic `400: bad request`". — [wgcf issue #76](https://github.com/ViRb3/wgcf/issues/76)
- Historical (2023-12, PR #355): the private key is no longer changed after updating the license; before that, wgcf re-keyed. — [wgcf issue #355](https://github.com/ViRb3/wgcf/issues/355); [wgcf commit 2fe51a19](https://github.com/ViRb3/wgcf/commit/2fe51a19)
- The wgcf README (2026):
  - "Only subscriptions purchased directly from the official 1.1.1.1 app are supported. Keys obtained by any other means, including referrals, will not work."
  - "There's a bug on Cloudflare's side that prevents existing accounts from getting Warp+ even after you bind a correct license key. If you have ever connected to Warp VPN, then your account is affected." The workaround is to register fresh and immediately `wgcf update --license-key`.

  — [wgcf README](https://github.com/ViRb3/wgcf/blob/de6bba7147dc965a1b8e4de113a709750697ccea/README.md); [wgcf issue #85](https://github.com/ViRb3/wgcf/issues/85)
- Since about early 2025, users report a WARP+ subscription showing `warp=on` over wgcf (WireGuard) while the official client shows `warp=plus`, which is attributed to MASQUE. Diniboy1123 (usque) tested and said the difference "doesn't seem to be cosmetic only" (2025-03-19). — [wgcf issue #459](https://github.com/ViRb3/wgcf/issues/459)
- Account semantics:
  - `account_type: limited` means WARP+ from referral data (finite `premium_data`/`quota`).
  - `unlimited` means a paid subscription. It shows `premium_data`/`quota` of 0 B, which the maintainer believes means "infinite".
  - `role: child` means the device is bound to another device's license.

  — [wgcf issue #326](https://github.com/ViRb3/wgcf/issues/326); [wgcf issue #304](https://github.com/ViRb3/wgcf/issues/304)
- usque exposes `account info` (`GET /account`), `account devices` (`GET /account/devices`), `account set <KEY>` (`PUT /account`) and `account reset` (`DELETE /reg/{id}/account`, "free up the license key to be used on another device"). — [usque cmd/account.go](https://github.com/Diniboy1123/usque/blob/6aa03fc97d12848dce34eedbd187fb1077b5d1ea/cmd/account.go); [usque api/cloudflare.go](https://github.com/Diniboy1123/usque/blob/6aa03fc97d12848dce34eedbd187fb1077b5d1ea/api/cloudflare.go)
- warp-plus binds the license during identity creation: register → `PUT /account` → `GET /account`. It also has `POST /reg/{id}/account/license` (`ResetAccountLicense`). — [warp-plus warp/account.go](https://github.com/bepass-org/warp-plus/blob/f70ea7e4f193717c73f9a4357cbc98d6944b36bb/warp/account.go); [warp-plus warp/api.go](https://github.com/bepass-org/warp-plus/blob/f70ea7e4f193717c73f9a4357cbc98d6944b36bb/warp/api.go)

**Referral-based generators (historical)**
- wgcf-cli `plus` ("Recharge your account indefinitely") loops every 500 ms. Each iteration does `POST /reg` with a fresh key, fake `install_id` and `fcm_token`, and `"referrer": "<target device id>"`. Each successful registration credited the referrer with data. On error it backs off for 30 s. — [wgcf-cli cmd_plus.go](https://github.com/ArchiveNetwork/wgcf-cli/blob/1b43d47c348a003949e064786378c643872d9db1/cmd/wgcf-cli/cmd_plus.go)
- The WarpPlusKeyGenerator-NG algorithm, which produced keys with "1.92EB quota":
  1. Register U1 and U2 with an empty body.
  2. `PATCH /reg/{U1}` `{"referrer": U2.id}`.
  3. `DELETE /reg/{U2}`.
  4. `PUT /reg/{U1}/account` `{"license": <base_key>}` (a pre-made high-quota key).
  5. `PUT /reg/{U1}/account` `{"license": U1.original_license}`.
  6. `GET /account` to read `license`, `account_type` and `referral_count`.
  7. `DELETE /reg/{U1}`.

  It backed off 30 s and grew the delay on errors. — [WarpPlusKeyGenerator-NG main.py](https://github.com/0x24a/WarpPlusKeyGenerator-NG/blob/c9996c2c6fde7799006213f0332f8d6461bd4103/main.py)
- Status of the key generators:
  - Issue #9 quotes Cloudflare support: "Cloudflare will conclude the referral program for WARP+ on November 1, 2024".
  - The project was paused 2025-03-09; the maintainer cites Cloudflare's "card validation system" blocking a Zero Trust team-based substitute.
  - The repo was archived 2025-12-17.

  — [WarpPlusKeyGenerator-NG issue #9](https://github.com/0x24a/WarpPlusKeyGenerator-NG/issues/9); [comment 2708741001](https://github.com/0x24a/WarpPlusKeyGenerator-NG/issues/9#issuecomment-2708741001); [README](https://github.com/0x24a/WarpPlusKeyGenerator-NG/blob/c9996c2c6fde7799006213f0332f8d6461bd4103/README.md)
- The fscarmen/warp-sh changelog:
  - 2024-07-25: added a self-hosted API (`warp.cloudflare.now.cc/?run=pluskey`) for "1920 PB WARP+ license".
  - 2024-09-14: "Remove the function of generating licenses … because cloning Warp+ licenses is officially prohibited".
  - 2026-01-02: "Remove deprecated WARP+ and Teams account types from installation and upgrade processes (warp a) following Cloudflare's adjustments".
  - 2026-04-10: "Removed the change License (warp a) function".

  — [fscarmen/warp-sh README_EN.md](https://github.com/fscarmen/warp-sh/blob/78e86a8691a07523618167b3e9db8fabe6a0e8d6/README_EN.md)
- Per a search summary, Wikipedia states that the WARP+ referral program is discontinued and that, as of Nov 2025, WARP+ (Unlimited) is a paid monthly subscription. I did not fetch or verify the page directly. — [Wikipedia: 1.1.1.1](https://en.wikipedia.org/wiki/1.1.1.1)

### Inferences
- Because the device count is capped per account (5) and children inherit plan status, a reimplementation should call `GET /account/devices` before binding a license, and offer `DELETE`/deactivate of stale bound devices.
- The referral-recharge approach (`referrer` in `/reg` or `PATCH /reg/{id}`) can be assumed non-functional for new data credit after 2024-11-01. Any "WARP+ key" circulating publicly is likely a cloned or shared subscription license, and community tools now refuse to support those.

### Gaps
- I found no primary Cloudflare source for the 5-device limit; it is stated by wgcf only.
- What `POST /account/license` does exactly (reset or regenerate the license string) is inferred from naming only.
- Whether `account_type` values changed after Nov 2025 (when WARP+ became subscription-only per Wikipedia) is not documented in code.

---

## 5. How Zero Trust / Teams enrollment differs

### Takeaway
Teams/Zero Trust registration is the same `POST /<ver>/reg` (or `POST /v0/reg` on `api.devices.cloudflare.com`), plus a header `CF-Access-Jwt-Assertion: <JWT>`. The JWT comes from `https://<team>.cloudflareaccess.com/warp` after SSO, or non-interactively by presenting a service token (`CF-Access-Client-Id`/`CF-Access-Client-Secret`). The response has `account.account_type = "team"`, an `account.organization`, an empty license, a populated `policy` (device profile), CGNAT-like addresses, and a `/v1/accounts/{account_tag}/reg/{id}` family for later calls. Mesh / WARP Connector nodes use a different body field (`warp_connector_token`) on `/v1/accounts/{a}/warp_connector`.

### Cited Findings
- **Historical (2021-09):** reverse engineering showed that "Teams login utilizes JWT token obtained from `<teamname>.cloudflareaccess.com/warp` to fetch Bearer token. After that, the flow is same as normal one." With `Cf-Access-Jwt-Assertion` on `/{ApiVersion}/reg`, the API "returns different scheme". In 2022-12 another user confirmed that "Only the single request to /reg is required". — [wgcf issue #56](https://github.com/ViRb3/wgcf/issues/56)
- usque `register --jwt <team-token>` steps:
  1. Visit `https://<team-domain>/warp` and authenticate.
  2. Extract the token from the success page; in the console: `document.querySelector("meta[http-equiv='refresh']").content.split("=")[2]`.

  usque sends the token in `CF-Access-Jwt-Assertion`. "ZeroTrust doesn't use licenses". IPv6 inside Zero Trust needs up-to-date addresses, refreshed via `enroll`. — [usque README](https://github.com/Diniboy1123/usque/blob/6aa03fc97d12848dce34eedbd187fb1077b5d1ea/README.md); [usque issue #12](https://github.com/Diniboy1123/usque/issues/12)
- rany2/warp.sh does Teams registration with `POST /v0a2483/reg` and `CF-Access-Jwt-Assertion`, using the body `{"key","install_id":"","fcm_token":"","model","serial_number":"","name","locale":"en_US"}`. It uses the same JWT-extraction one-liner, and the license is "N/A" for Teams. — [rany2/warp.sh](https://github.com/rany2/warp.sh/blob/cad07dafa9ea93a3d7f122110ec52f43f77f9f42/warp.sh)
- wgcf-cli `register -t <ZeroTrust token>` adds `Cf-Access-Jwt-Assertion`. — [wgcf-cli utils/request.go](https://github.com/ArchiveNetwork/wgcf-cli/blob/1b43d47c348a003949e064786378c643872d9db1/utils/request.go)
- The usque model notes Zero Trust differences: `account.managed` and `account.organization` are set only for Zero Trust, and `premium_data`, `quota`, `warp_plus`, `role` and `license` are absent. `warp_enabled`, `waitlist_enabled`, `tos`, `place`, `enabled` and `serial_number` are "not set for ZeroTier" (usque's name for Zero Trust). — [usque models/register.go](https://github.com/Diniboy1123/usque/blob/6aa03fc97d12848dce34eedbd187fb1077b5d1ea/models/register.go)
- The service-token flow (verified 2026-10-06):
  - Request `GET https://<team>.cloudflareaccess.com/warp` with `CF-Access-Client-Id: <id>.access` and `CF-Access-Client-Secret: <secret>`. It answers `302 Location: com.cloudflare.warp://<team>.cloudflareaccess.com/auth?token=<JWT>`.
  - The JWT is RS256 and valid for **60 s**. Its claims include `account_id`, `service_token_uuid`, `email: non_identity@<team>.cloudflareaccess.com` and `warp: true`.
  - Then `POST /v0/reg` with `Cf-Access-Jwt-Assertion`. The body has `type` (`linux` and `windows` accepted), `key` (Curve25519), optional `name`/`model`/`os_version`/`serial_number` (≤100 bytes each) and optional `tos`.
  - The response is wrapped in `{"result": {...}, "success": true}` with `account.account_type = "team"`.
  - Subsequent calls: `GET`/`PATCH`/`DELETE /v1/accounts/{account_id}/reg/{id}` with `Authorization: Bearer <result.token>`. DELETE returns 204, and the token then yields 401 `2016`.

  This mirrors the official client's `mdm.xml` keys `organization`, `auth_client_id` and `auth_client_secret`. — [wgcf-mesh API.md](https://github.com/AnimMouse/wgcf-mesh/blob/8ddecda5690650798dba9c3c441aa8305223569a/API.md)
- The Mesh / WARP Connector flow:
  - The token is base64 JSON `{"a": <32-hex account tag>, "t": <tunnel uuid>, "s": <secret>}`.
  - Register with `POST /v1/accounts/{a}/warp_connector` and body `{"type": "linux", "name", "key", "warp_connector_token": <token unchanged>}`. Only `type: "linux"` is accepted (`2082` otherwise).
  - The response includes `connector.routes`, `connector.nat_mode` and `connector.additional_interfaces`. Example addresses are `100.96.0.17` and `2606:4700:cf1:1000::11`. The peer key is the same `bmXOC+F1…` as consumer WARP, and `endpoint.host` is `engage.cloudflareclient.com:2408`.
  - No `CF-Client-Version` or User-Agent was required.

  — [wgcf-mesh API.md](https://github.com/AnimMouse/wgcf-mesh/blob/8ddecda5690650798dba9c3c441aa8305223569a/API.md); [wgcf-mesh HANDOFF.md](https://github.com/AnimMouse/wgcf-mesh/blob/8ddecda5690650798dba9c3c441aa8305223569a/HANDOFF.md)
- The wgcf spec has a Zero Trust-related `GET /{apiVersion}/accounts/{accountId}/reg/{id}/auth` that returns `{"token": ...}` (GatewayAuth). The `policy` object carries the device-profile settings: `organization`, `gateway_unique_id`, `tunnel_protocol`, `include`/`exclude`, `fallback_domains`, `auth_client_id`/`auth_client_secret`, `override_*_endpoint`, `post_quantum` and so on. — [wgcf openapi-spec.yml](https://github.com/ViRb3/wgcf/blob/de6bba7147dc965a1b8e4de113a709750697ccea/openapi-spec.yml)
- Cloudflare's official manual-deployment docs describe `warp-cli` Zero Trust enrollment via team name, browser login, then pasting `com.cloudflare.warp://<team>.cloudflareaccess.com/auth?token=…`. The command is `teams-enroll-token` in current docs and `registration token` in older ones. A 401 means the token expired. Per a search-result summary, tokens are short-lived. — [Cloudflare docs: Manual deployment](https://developers.cloudflare.com/cloudflare-one/connections/connect-devices/warp/deployment/manual-deployment); [Cloudflare docs: headless Linux](https://developers.cloudflare.com/cloudflare-one/tutorials/warp-on-headless-linux/)
- Zero Trust tunnels obtained this way have mixed reliability. One 2025-07 user reported that extracted Zero Trust WireGuard credentials stopped working when `warp-svc` stopped, and another said it works regardless; this is unresolved. There is a dedicated Zero Trust MASQUE edge, `162.159.197.2`, and SNI `zt-masque.cloudflareclient.com` appears in usque's constants. — [wgcf issue #56](https://github.com/ViRb3/wgcf/issues/56); [Xray-docs warp.md](https://github.com/XTLS/Xray-docs-next/blob/59ab79c7e09112475e7907bf745913ded7ca89a5/docs/en/document/level-2/warp.md); [usque internal/consts.go](https://github.com/Diniboy1123/usque/blob/6aa03fc97d12848dce34eedbd187fb1077b5d1ea/internal/consts.go)
- A Teams registration via usque `--jwt` on `v0a4471` returned **HTTP 500** in 2026-01. The issue is open and unresolved. — [usque issue #68](https://github.com/Diniboy1123/usque/issues/68)
- Per a search-result summary of APKMirror's 1.1.1.1 v6.38.7 release notes, logging into Cloudflare One (Zero Trust) from the consumer 1.1.1.1 app "will be disabled May 2026", with users pointed to a separate Cloudflare One Agent app. The page itself returned 403, so I could not verify it. This lines up with fscarmen removing "Teams account types … following Cloudflare's adjustments" in 2026-01. — [APKMirror (unverified)](https://www.apkmirror.com/?p=13566116); [fscarmen/warp-sh README_EN.md](https://github.com/fscarmen/warp-sh/blob/78e86a8691a07523618167b3e9db8fabe6a0e8d6/README_EN.md)

### Inferences
- In 2026, the most reliable third-party Zero Trust path appears to be the newer `api.devices.cloudflare.com` family: `POST /v0/reg` with a JWT obtained via service token, then `/v1/accounts/{a}/reg/{id}`. Using the consumer `/v0a…/reg` with a JWT is the older approach and showed a 500 in at least one 2026 report.
- Because the JWT expires in 60 s, a client must chain "get JWT → register" without user delay. The browser-extracted JWT approach is fragile.

### Gaps
- The Zero Trust `/v0/reg` response shape under the consumer `api.cloudflareclient.com/v0a…` path in 2026 is not documented, including whether it is wrapped in `result`.
- No source confirmed whether a Zero Trust registration can be switched to MASQUE by the same `PATCH` with `secp256r1`, though usque's README implies `enroll` works under Zero Trust.
- Cloudflare's own 2026 announcement about removing Zero Trust login from the 1.1.1.1 app could not be fetched.

---

## 6. How `config.client_id` is returned and used (WireGuard reserved bytes)

### Takeaway
`config.client_id` is a short base64 string (e.g. `I0q+`) that decodes to **3 bytes**. Cloudflare's WARP WireGuard edge expects those 3 bytes in the three "reserved" bytes of every WireGuard message header (bytes 1–3 after the 1-byte type). Stock WireGuard sends zeros there. Community clients such as Xray, sing-box, warp-plus, wireguard-go-reserved and warp-go put `client_id` into a `reserved: [b0, b1, b2]` setting. wgcf ignores it.

### Cited Findings
- wgcf-cli `ClientIDtoReserved` base64-decodes `client_id`, then emits `reserved_dec` (an int array) and `reserved_hex` (`0x…`). — [wgcf-cli utils/general.go](https://github.com/ArchiveNetwork/wgcf-cli/blob/1b43d47c348a003949e064786378c643872d9db1/utils/general.go)
- warp-reg.sh: `reserved_str = client_id`, `reserved_hex = base64 -d | xxd -p`, `reserved_dec = [b0, b1, b2]`. Example: `"reserved_dec": [35, 74, 190], "reserved_hex": "0x234abe", "reserved_str": "I0q+"`. — [warp-reg.sh](https://github.com/chise0713/warp-reg.sh/blob/8c93845d27a568992c9c62ae6d86a33d568d6050/warp-reg.sh); [Xray-docs warp.md](https://github.com/XTLS/Xray-docs-next/blob/59ab79c7e09112475e7907bf745913ded7ca89a5/docs/en/document/level-2/warp.md)
- rany2/warp.sh: "this is also referred to as 'reserved key' as the client ID is put in the reserved field in the WireGuard header". It outputs `CFClientIdB64`, `CFClientIdHex` and `CFClientIdDec`. — [rany2/warp.sh](https://github.com/rany2/warp.sh/blob/cad07dafa9ea93a3d7f122110ec52f43f77f9f42/warp.sh)
- The Xray WireGuard outbound `reserved` field is documented as "The three WireGuard reserved bytes… default to 0". The WARP guide pastes `client_id`-derived values into it. — [Xray-docs warp.md](https://github.com/XTLS/Xray-docs-next/blob/59ab79c7e09112475e7907bf745913ded7ca89a5/docs/en/document/level-2/warp.md)
- warp-plus parses a user-supplied `Reserved` (`"1,2,3"` or `"random"`) into `[3]byte` and writes `reserved=%d,%d,%d` into its wireguard-go IPC config. It does not auto-derive the value from `client_id`. — [warp-plus wiresocks/config.go](https://github.com/bepass-org/warp-plus/blob/f70ea7e4f193717c73f9a4357cbc98d6944b36bb/wiresocks/config.go); [warp-plus app/wg.go](https://github.com/bepass-org/warp-plus/blob/f70ea7e4f193717c73f9a4357cbc98d6944b36bb/app/wg.go)
- A Wireshark commit, "WireGuard: support Decode As and non-zero reserved", recognises "Cloudflare Warp traffic which may use non-zero bytes for load balancing purposes. This is an extension of the WireGuard protocol, it is not understood by official implementations which require the reserved bytes field to be zero." This is from a search-result excerpt. — [Wireshark commit 6920118 (osmocom mirror)](https://gitea.osmocom.org/osmith/wireshark/commit/69201185adfc0359abe08f6ed6befbea93c63f94)
- A forum capture showed `wg.reserved` as `000000` for official WireGuard (Wiresock) and `b91981` for the WARP client, which the poster called Cloudflare's client ID used for routing. The maintainer noted it was unknown "when and how this client ID is assigned". — [ntkernel forum](https://ntkernel.com/?p=12224)
- fscarmen 2023-06-30: "Use wireguard-go with reserved to replace kernel. Make Hong Kong, Los Angeles and other restricted areas use warp". On 2026-02-25: "Restore Reserved configuration for Warp usage". — [fscarmen/warp-sh README_EN.md](https://github.com/fscarmen/warp-sh/blob/78e86a8691a07523618167b3e9db8fabe6a0e8d6/README_EN.md)
- A 3x-ui bug fix shows the panel failing to store `config.client_id` at registration, which produced an empty reserved array. The fix stores it and re-reads it from the live config. — [3x-ui commit (search excerpt)](https://git.txlyre.website/txlyre/3x-ui/commit/3657ed55dcc3aacf55aa0f1a98f54f4778652c04?lang=de-DE)

### Inferences
- `client_id` is per-registration and returned in both `POST /reg` and `GET /reg/{id}`. A client should read it from the latest `GET /reg/{id}` in case it changes, for example after a key PATCH, though no source confirmed whether it does change.
- Whether reserved bytes are *required* appears region- or edge-dependent. fscarmen explicitly ties them to making WARP work in "restricted areas" such as Hong Kong and Los Angeles, while wgcf's kernel WireGuard profiles (zero reserved) still work for many users.
- The reserved bytes do not apply to MASQUE, where the device is identified by its mTLS key.

### Gaps
- No Cloudflare documentation exists for `client_id` semantics. "Load balancing / routing" comes from the Wireshark commit message and forum speculation.
- It is unconfirmed whether `client_id` is stable across key rotation, or whether a wrong or zero `reserved` leads to silent drops or handshake failure on today's edges.

---

## 7. Errors, rate limits, TLS fingerprinting, blocking, and community workarounds

### Takeaway
The dominant 2024–2026 failure is **HTTP 429 Too Many Requests on `/reg`**, partly from rapid repeated registration and, in 2026, demonstrably from **TLS ClientHello fingerprinting**. wgcf releases whose Go runtime changed the ClientHello went from roughly 90% to roughly 10% success until the fingerprint was restored and then pinned via uTLS to imitate Android Conscrypt. Older reports include `403` with Cloudflare error `1020` (fixed by forcing TLS 1.2) and `401` (account or IP blocked for abuse). warp-plus works around censorship by connecting to a hard-coded Cloudflare IP range with a custom padded uTLS hello and fallbacks.

### Cited Findings
**TLS fingerprinting and 429**
- wgcf #613 (2026-07-17):
  - `wgcf register` → `429 Too Many Requests` on v2.2.31, while v2.2.30 worked. One user measured about 90% vs about 10% success, alternating versions with a success/fail/success/fail pattern.
  - The maintainer suspected "TLS fingerprinting occurring here, perhaps due to the upgrade from Go 1.25 -> 1.26".
  - The fix was commit `b03439ea` (2026-07-22), "restore old tls fingerprint", released as v2.2.32.

  — [wgcf issue #613](https://github.com/ViRb3/wgcf/issues/613); [wgcf compare v2.2.31...v2.2.32](https://github.com/ViRb3/wgcf/compare/v2.2.31...v2.2.32)
- wgcf #626 (2026-09-10): v2.2.32 then started getting 429 on the first try, while some saw 2.2.31 working. The maintainer said "looks like something in the TLS fingerprint changed again". v2.3.0 (2026-09-18) moved to `v0a5641` and a pinned uTLS fingerprint; testers reported 5/5 and 40/40 successes back-to-back. — [wgcf issue #626](https://github.com/ViRb3/wgcf/issues/626)
- The current wgcf ClientHello (uTLS `HelloCustom`):
  - TLS 1.2 only (`MinVersion = MaxVersion = TLS1.2`).
  - Ciphers: `ECDHE_ECDSA_AES_256_GCM_SHA384`, `ECDHE_RSA_AES_256_GCM_SHA384`.
  - Extensions in order: SNI, ExtendedMasterSecret, RenegotiationInfo(never), SupportedCurves `[X25519, P-256, P-384]`, PointFormats `[uncompressed]`, SessionTicket, ALPN `["http/1.1"]`, StatusRequest, SignatureAlgorithms `[ecdsa_p256_sha256, pss_sha256, pkcs1_sha256, ecdsa_p384_sha384, pss_sha384, pkcs1_sha384, pss_sha512, pkcs1_sha512, pkcs1_sha1]`, BoringSSL-style padding.
  - Empty session ID on fresh connections ("Conscrypt leaves the session ID empty"), with a random 32-byte ID only when resuming a ticket.
  - HTTP/2 disabled (`ForceAttemptHTTP2: false`).
  - The connection deliberately avoids HTTP CONNECT proxies so the custom hello is always used.

  — [wgcf cloudflare/api.go@de6bba7](https://github.com/ViRb3/wgcf/blob/de6bba7147dc965a1b8e4de113a709750697ccea/cloudflare/api.go)
- **Historical (≤2025-08):** wgcf's comment read "Match app's TLS config or API will reject us with code 403 error 1020". The fix then was Go `crypto/tls` with `MinVersion = MaxVersion = TLS 1.2` and HTTP/2 off. — [wgcf api.go@8666a8be](https://github.com/ViRb3/wgcf/blob/8666a8be/cloudflare/api.go)
- Counter-evidence (2026): wgcf-mesh found that plain curl with no special headers worked against `api.devices.cloudflare.com` for Mesh and service-token registrations. It lists "whether the API ever starts requiring a client version header or rejecting old ones" as an open watch item. — [wgcf-mesh HANDOFF.md](https://github.com/AnimMouse/wgcf-mesh/blob/8ddecda5690650798dba9c3c441aa8305223569a/HANDOFF.md)
- warp-reg.sh uses curl `--tlsv1.3`, which contrasts with wgcf's TLS 1.2 requirement. wgcf-cli allows TLS 1.2–1.3. — [warp-reg.sh](https://github.com/chise0713/warp-reg.sh/blob/8c93845d27a568992c9c62ae6d86a33d568d6050/warp-reg.sh); [wgcf-cli utils/http_client.go](https://github.com/ArchiveNetwork/wgcf-cli/blob/1b43d47c348a003949e064786378c643872d9db1/utils/http_client.go)

**warp-plus anti-censorship dialer** (commit `94c33060`, 2025-06-03, "implement retries and multiple fprints")
- The dialer ignores DNS and connects to a random IP in `141.101.113.0/24`:443, keeping SNI `api.cloudflareclient.com`.
- It tries three fingerprints, each with 3 attempts at 250 ms intervals:
  1. A uTLS custom hello with GREASE, a TLS 1.2 maximum, and a fake extension `0x15` (padding) of **1200 zero bytes** placed first (named "SNICurve"); SNI is last.
  2. Go `utls.Client` with TLS 1.3 minimum.
  3. A third fallback.
- It uses its own root pool (`noql-net/certpool`).

— [warp-plus warp/tls.go](https://github.com/bepass-org/warp-plus/blob/f70ea7e4f193717c73f9a4357cbc98d6944b36bb/warp/tls.go)
- warp-plus users also hit `429 Too Many Requests` when creating the identity (2024-06). — [warp-plus issue #178](https://github.com/bepass-org/warp-plus/issues/178)

**Other errors and blocks**
- `401 Unauthorized`: the maintainer says this "probably means that your account or source IP address were blocked due to abuse". — [wgcf issue #403](https://github.com/ViRb3/wgcf/issues/403)
- `400 bad request` when the license device limit (5) is exceeded. — [wgcf issue #76](https://github.com/ViRb3/wgcf/issues/76)
- `500` on the device-rename PATCH is treated as a success by wgcf (`IsHttp500Error`). — [wgcf cmd/shared/shared.go](https://github.com/ViRb3/wgcf/blob/de6bba7147dc965a1b8e4de113a709750697ccea/cmd/shared/shared.go); [wgcf util/util.go](https://github.com/ViRb3/wgcf/blob/de6bba7147dc965a1b8e4de113a709750697ccea/util/util.go)
- API schema drift breaks strict clients:
  - wgcf #576 (2026-02): "no value given for required property model".
  - #519 (2025-08): "…required property usage" for WARP+.
  - #629 (2026-10): `key_type` missing on old accounts.

  The fixes made those fields optional. — [wgcf issue #629](https://github.com/ViRb3/wgcf/issues/629); [wgcf issues search](https://github.com/ViRb3/wgcf/issues?q=required+property)
- IPv6 pitfall: `api.cloudflareclient.com` has both A and AAAA records. On hosts with an IPv6 address but no IPv6 route, registration failed with `dial tcp [2606:4700::6810:1854]:443: network is unreachable`. usque #127 (2026-08) proposes preferring IPv4. — [usque issue #127](https://github.com/Diniboy1123/usque/issues/127)
- Rate-limit handling in tools:
  - usque: "In case of certain issues such as rate limiting, you may need to wait a bit and try again."
  - wgcf-cli `plus`: 30 s sleep.
  - WarpPlusKeyGenerator-NG: 30 s, growing by 30 s per failure.

  — [usque README](https://github.com/Diniboy1123/usque/blob/6aa03fc97d12848dce34eedbd187fb1077b5d1ea/README.md); [wgcf-cli cmd_plus.go](https://github.com/ArchiveNetwork/wgcf-cli/blob/1b43d47c348a003949e064786378c643872d9db1/cmd/wgcf-cli/cmd_plus.go); [WarpPlusKeyGenerator-NG main.py](https://github.com/0x24a/WarpPlusKeyGenerator-NG/blob/c9996c2c6fde7799006213f0332f8d6461bd4103/main.py)
- Network-level blocking of the tunnel, not the API:
  - Jio (India) reportedly blocked WARP UDP ports 2408/1701/500/4500 to `162.159.193.0/24` in 2022.
  - usque's author notes WireGuard was blocked on train Wi-Fi while MASQUE was not.
  - The Xray docs say the MASQUE edge rejects ECH, while ECH "is only useful for WARP API calls (the general edge supports ECH)".

  — [wgcf issue #56](https://github.com/ViRb3/wgcf/issues/56); [usque README](https://github.com/Diniboy1123/usque/blob/6aa03fc97d12848dce34eedbd187fb1077b5d1ea/README.md); [Xray-docs warp.md](https://github.com/XTLS/Xray-docs-next/blob/59ab79c7e09112475e7907bf745913ded7ca89a5/docs/en/document/level-2/warp.md)

### Inferences
- For a robust 2026 reimplementation of consumer registration:
  - Emulate the Android OkHttp/Conscrypt stack end to end: TLS 1.2-only ClientHello as in wgcf, HTTP/1.1, the `1.1.1.1/<ver>-<build> (Android X)` UA with a matching `CF-Client-Version`, `Content-Type: application/json; charset=UTF-8`, `Connection: Keep-Alive`, and no `Accept`.
  - Avoid rapid repeated `/reg` calls from one IP.
  - Cache `{id, token, keys}` and reuse them instead of re-registering.
  - Prefer IPv4 to the API, and handle 429 with exponential backoff.
- Fingerprint enforcement looks specific to the consumer `/v0a…/reg` path on `api.cloudflareclient.com`. The Zero Trust `api.devices.cloudflare.com` path accepted plain curl in Oct 2026. This rests on one repo's tests.

### Gaps
- Cloudflare has published no rate-limit numbers. Community reports say only "several in quick succession" triggers 429.
- I found no source for whether 429s are per-IP, per-ASN, or per-fingerprint, beyond the wgcf A/B tests that implicate the fingerprint.
- Error codes beyond those listed (1001, 1020, 2004, 2016, 2082, 3004, 3006) are not catalogued anywhere I found.
