# ProxyCheck — Advanced Proxy Checker & Analyzer

**Fast proxy validation tool for HTTP, HTTPS, SOCKS4 and SOCKS5 proxies with latency, location, ASN, ISP, anonymity and connectivity analysis.**

Developed by **Diwas Khatri**.

```
┌───────────────────────────────────────────┐
│ ProxyCheck                                │
│ Advanced Proxy Analyzer                   │
├───────────────────────────────────────────┤
│  Paste proxies… / Upload .txt / Drop file │
│  Protocol: Auto · Timeout: 8s · Conc: 100 │
│              [ START CHECK ]              │
├───────────────────────────────────────────┤
│ Results  ·  dashboard  ·  charts  ·  export │
└───────────────────────────────────────────┘
```

## Features

- **Automatic format detection** — `ip:port`, `ip:port:user:pass`, `user:pass@ip:port`, `scheme://…`, bracketed and unbracketed IPv6; normalization, deduplication and malformed-line reporting (see [docs/PROXY_FORMATS.md](docs/PROXY_FORMATS.md))
- **High-performance async checking engine** — bounded concurrency with adaptive tuning, worker queue, per-proxy deadlines, bounded retries, cancellation that destroys in-flight sockets, pause/resume
- **Real protocol probing** — a proxy is classified by how it actually behaves (HTTP absolute-URI, SOCKS4/4a/5 handshakes), never by its input prefix
- **Latency analysis** — TCP connect, protocol handshake, first response and total time with descriptive buckets (<100 ms excellent … >1500 ms very slow)
- **Exit-IP + metadata** — observed exit IP, approximate geolocation (country/region/city/lat/lon/timezone), ASN, AS organization, ISP, reverse DNS; batched + cached lookups with a fallback provider; unavailable data is shown as *Unknown*, never invented
- **Anonymity classification** — transparent / anonymous / elite / unknown based on headers the test endpoint actually observed, always with an explanation
- **HTTPS/TLS tunnel test** — CONNECT or SOCKS tunnel + TLS handshake with certificate validation **always on** (never disabled to fake a "working" result)
- **Authentication detection** — 407 handling, credential testing, masked display (`user:********@1.2.3.4:8080`); passwords never reach the client, logs or exports unless you explicitly request a credential-preserving export
- **Real-time progress** — Server-Sent Events stream progress and results; automatic polling fallback; pause / resume / cancel / restart / recheck
- **Virtualized results table** — smoothly handles tens of thousands of rows; sortable, filterable, searchable
- **Dashboard & charts** — 12 live stat cards plus latency/protocol/country/alive-ratio charts (dependency-free SVG)
- **Exports** — TXT / CSV / JSON, filtered scopes (alive, dead, current filter…), optional credential preservation as an explicit, confirmed action
- **SSRF protection** — proxies pointing at loopback/private/link-local/CGNAT/reserved ranges and cloud-metadata endpoints are rejected before a socket opens, including hostname resolution rebinding (see [docs/SECURITY-IMPLEMENTATION.md](docs/SECURITY-IMPLEMENTATION.md))

## Architecture

```
Browser (vanilla ES modules, virtual table, SVG charts, SSE client)
   ↓
API server (zero-dependency Node.js)  ──  rate limiting, validation, security headers
   ↓
Job manager (bounded worker pool, adaptive concurrency, per-job event stream)
   ↓
Checking pipeline                     ──  parser → SSRF guard → connect →
   (per proxy)                            protocol probe → echo → HTTPS/TLS → anonymity
   ↓
Geo enrichment (batched provider + LRU cache + fallback)  ──  attached to results asynchronously
```

Details in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Installation

Requirements: **Node.js ≥ 18.13** (no other dependencies).

```bash
npm install   # no-op (zero runtime dependencies) — kept for convention
npm start     # production start on :3000
npm run dev   # development with auto-reload
```

Copy `.env.example` to `.env` to customize (all values have safe defaults).

Docker:

```bash
docker compose up --build
```

## Deployment

For a permanent public URL, deploy to Render (free tier works) in ~2 minutes — Blueprint included. See **[DEPLOY.md](DEPLOY.md)** for GitHub + Render step-by-step, environment variables, and platform notes. A GitHub Actions CI workflow (`.github/workflows/ci.yml`) runs lint + the full test suite on every push.

## Development

```bash
npm run dev        # start with --watch
npm test           # 81 unit + integration tests (fully offline, mock servers)
npm run bench      # controlled benchmark (100 → 10 000 proxies, local mocks)
npm run lint       # syntax/lint check across backend, frontend, tests
npm run lint:eslint # if eslint is installed
```

## Configuration

All configuration is environment-driven (see `.env.example`): server host/port, input limits (`MAX_PROXIES_PER_JOB`, `MAX_BODY_BYTES`), rate limits, checker defaults (concurrency/timeout/retries), `ALLOW_PRIVATE_PROXIES` (development only!), controlled echo targets, and geolocation provider settings.

## API

```
POST /api/check                start a job {text | proxies[], timeout, concurrency, retries, protocol}
GET  /api/jobs/:id             progress snapshot
GET  /api/jobs/:id/results     filtered + paged results
GET  /api/jobs/:id/events      Server-Sent Events stream (progress, results, geo, done)
GET  /api/jobs/:id/export      txt | csv | json download (filters apply)
POST /api/jobs/:id/cancel      cancel
POST /api/jobs/:id/pause       pause
POST /api/jobs/:id/resume      resume
POST /api/jobs/:id/recheck     {scope: all|failed|selected, keys?}
GET  /api/health               liveness + stats
GET  /api/config               limits & defaults for clients
```

Full reference with examples: [docs/API.md](docs/API.md).

## Proxy Formats

All of these are recognized and normalized automatically:

```text
1.2.3.4:8080
1.2.3.4:8080:username:password
username:password@1.2.3.4:8080
http://1.2.3.4:8080
https://1.2.3.4:8443
socks4://1.2.3.4:1080
socks5://1.2.3.4:1080
socks5://username:password@1.2.3.4:1080
[2001:db8::1]:8080
proxy.example.com:3128
```

Details and edge cases: [docs/PROXY_FORMATS.md](docs/PROXY_FORMATS.md).

## Performance

Design target: **1,000 proxies in ~3 minutes** with the default 8 s timeout and concurrency 100 — this is a design target, not a guarantee; real-world throughput depends on proxy latency and network conditions.

On the controlled local benchmark (mock proxies, see [docs/PERFORMANCE.md](docs/PERFORMANCE.md)) the pipeline sustains **~3,400 checks/s at 10,000 proxies** with ~0% errors and modest memory growth. The UI uses virtual scrolling so even 25,000-row tables stay smooth.

## Security

- Credentials are never logged, never serialized to clients, and never exported unless you explicitly confirm a credential-preserving export
- Strict SSRF guard on every proxy destination (IP literals and DNS results), cloud-metadata endpoints always blocked
- Controlled allowlisted test targets only — the server never contacts arbitrary user-supplied URLs
- Per-IP rate limiting, job limits per client, body size caps, bounded concurrency, job TTL + cleanup
- Strict CSP (no inline scripts), `nosniff`, `Referrer-Policy: no-referrer`, HSTS when behind HTTPS
- Uploaded files are treated as plain text only — nothing is ever executed

See [SECURITY.md](SECURITY.md) (policy) and [docs/SECURITY-IMPLEMENTATION.md](docs/SECURITY-IMPLEMENTATION.md) (implementation details).

## Accuracy

ProxyCheck is a **multi-stage validation engine designed for reliable proxy verification** — no tool can guarantee 100% accuracy.

- Validation accuracy depends on the target, timeout, network conditions, proxy behavior, and geolocation provider
- IP geolocation is approximate and may be inaccurate
- Proxy status is a point-in-time measurement — a proxy can become unavailable immediately after a check

Every result carries a confidence state: `Verified`, `Partially Verified`, `Failed` or `Unknown`, derived only from checks that actually ran.

## Screenshots

Run `npm start` and open `http://localhost:3000` — dark/light themes, live progress, dashboard charts, and the proxy detail panel.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Please read the [Code of Conduct](CODE_OF_CONDUCT.md).

## Roadmap

- Optional Redis-backed job queue for multi-instance deployments
- SOCKS-over-TLS and authenticated proxy-chain testing
- Pluggable geolocation providers (MaxMind GeoLite2 local database)
- Result persistence with database indexes for historical analysis

## Credits

ProxyCheck is developed by **Diwas Khatri**.

## License

[MIT](LICENSE) — Copyright (c) 2026 Diwas Khatri.
