# Repository Guidelines

## Project Structure & Module Organization

This repository is a .NET 10 solution for a Cloudflare WARP client library.

- `src/WarpClient/`: core library. Public API at the project root; `Cloudflare/Registration/` holds the device API, `Cloudflare/Tunnel/` MASQUE over HTTP/2, `Cloudflare/WireGuard/` WireGuard, `Cloudflare/Http3/` MASQUE proxy mode over HTTP/3, and `Networking/` the userspace IPv4/IPv6 stack (`Packets/`, `Tcp/`, `Dns/`).
- `src/WarpClient.DependencyInjection/`: service registration and `IHttpClientFactory` integration.
- `src/WarpClient.Playground/`: runs HTTP, TCP, UDP, and IPv6 checks through WARP (`--transport=http2|wireguard|http3` picks the transport, `--account` also prints the device account, `--direct` uses the host's sockets instead).
- `tests/WarpClient.Tests/`: xUnit tests for protocol framing, packet formats, and loopback connector behaviour.
- `reports/`, `research_notes/`: protocol research the implementation is based on.
- `WarpClient.slnx`: solution entry point.

## Build, Test, and Development Commands

- `dotnet build WarpClient.slnx`: builds all projects. Requires the .NET 10.0.4xx SDK or newer (NetAgents analyzers).
- `dotnet test WarpClient.slnx`: runs the xUnit suite; it only uses loopback sockets.
- `dotnet run --project src/WarpClient.Playground`: registers a WARP device on first run and prints the WARP egress addresses.

## Coding Style & Naming Conventions

`NetAgents.Analyzers` enforces the shared rules on every build and **rewrites source files** to apply its formatting and fixes, so review the diff after building. Builds fail on any remaining violation, and rules cannot be silenced through `NoWarn` or severity settings. Highlights:

- Full descriptive names; no abbreviations such as `ip`, `max`, `config`, or all-caps acronyms (`Ipv4`, `Tcp`, `Http`).
- Name literal arguments, consume every return value (no `_ =` discards), no null-forgiving operators, no boxing.
- One top-level type per file, at most 16 C# files per directory, XML documentation on public APIs.
- No `lock` or framework synchronization primitives; use `Nito.AsyncEx` (`AsyncLock`, `AsyncConditionVariable`).

## Testing Guidelines

Tests use xUnit in `tests/WarpClient.Tests`. Prefer behavioural tests against loopback servers for public connectors and focused round-trip tests for wire formats. Do not add tests that contact Cloudflare. WireGuard interoperability was checked manually against the Python noiseprotocol library acting as a loopback responder; repeat that after changing the handshake or transport framing. Name tests as `ScenarioConditionExpectedBehavior` without underscores (CA1707 is enforced), and use `TheoryData<T>` with `MemberData` instead of `InlineData`, which boxes values.

## Commit & Pull Request Guidelines

Use concise imperative commit messages, for example `Add UDP connector loopback tests`. Every push to `main` publishes both packages to NuGet with a date-based version (`yy.M.d.<time bucket>`), so keep `main` releasable.

## Security & Configuration Tips

The registration file contains the device private key and access token; never commit it or log its contents. Keep the server key pin in place — the tunnel's TLS is verified only by that pin.
