# Architecture

ProxyCheck is a zero-runtime-dependency Node.js application with a vanilla-JS frontend. This document explains how the pieces fit together.

```
Frontend (public/)                     Backend (src/)
┌──────────────────────┐   HTTP/JSON   ┌────────────────────────────┐
│ index.html           │ ────────────▶ │ server/httpServer.js       │
│ ES modules           │               │  · routing, static files   │
│  main.js  (wiring)   │   SSE stream  │  · rate limiter            │
│  api.js   (REST+SSE) │ ◀──────────── │  · security headers        │
│  table.js (virtual)  │               │  · input validation        │
│  charts.js (SVG)     │               └─────────────┬──────────────┘
│  detail.js (drawer)  │                             │
│  exporter.js         │                             ▼
│  filters/dashboard   │               ┌────────────────────────────┐
└──────────────────────┘               │ jobs/manager.js            │
                                       │  · JobManager / Job        │
                                       │  · bounded worker pool     │
                                       │  · adaptive concurrency    │
                                       │  · pause/resume/cancel     │
                                       └─────────────┬──────────────┘
                                                     │ per-proxy task
                                       ┌─────────────▼──────────────┐
                                       │ checker/probe.js           │
                                       │  0. SSRF guard             │
                                       │  1. connect (+TLS transport)│
                                       │  2. protocol probe          │
                                       │     http │ socks5/4a/4      │
                                       │  3. echo target request     │
                                       │  4. HTTPS/TLS tunnel test   │
                                       │  5. anonymity classification│
                                       └─────────────┬──────────────┘
                                                     │ exit IP
                                       ┌─────────────▼──────────────┐
                                       │ geo/geoClient.js           │
                                       │  batched provider + LRU    │
                                       │  cache + per-IP fallback   │
                                       └────────────────────────────┘
```

## Modules

| Path | Responsibility |
| --- | --- |
| `src/config.js` | Centralized env-driven configuration (lazy getters so tests can retarget) |
| `src/logger.js` | Structured JSON logging with credential redaction |
| `src/errors.js` | Error taxonomy (`TIMEOUT`, `CONNECTION_REFUSED`, `DNS_ERROR`, `AUTH_FAILED`, `TLS_ERROR`, `INVALID_PROXY`, `UNSUPPORTED_PROTOCOL`, `TARGET_ERROR`, `NETWORK_ERROR`, `UNKNOWN_ERROR`) and retryability |
| `src/validation.js` | IP/hostname/port validation, address classification, SSRF guard + rebinding-safe `dns.lookup` |
| `src/parser.js` | Proxy line parsing, normalization, deduplication, credential masking |
| `src/checker/socks.js` | SOCKS4 / SOCKS4a / SOCKS5 handshake client with tunnel reuse |
| `src/checker/httpProxy.js` | Raw HTTP proxy client (absolute-URI requests, CONNECT tunneling, TLS transport, TLS upgrade) |
| `src/checker/echo.js` | Echo-response adapter (httpbin / ip-api / ipwho.is shapes) |
| `src/checker/anonymity.js` | Header-based anonymity classification with reasons |
| `src/checker/probe.js` | Per-proxy pipeline orchestration under a single deadline |
| `src/targets.js` | Controlled allowlist targets + direct reachability probe (observer IP detection) |
| `src/geo/geoClient.js` | Batched geolocation with rate limiting, LRU+TTL cache and fallback provider |
| `src/jobs/manager.js` | Job lifecycle, worker pool, adaptive concurrency, SSE event emission |
| `src/jobs/view.js` | Safe result serialization (credentials never leave the server) |
| `src/jobs/filters.js` | One filter/sort engine shared by results + exports |
| `src/jobs/exporter.js` | TXT/CSV/JSON formatting with explicit credential gating |
| `src/server/httpServer.js` | Routing, SSE, static files, rate limiting, security headers |
| `server.js` | Bootstrap + graceful shutdown |

## Checking pipeline (per proxy)

1. **Syntax & guard** — the destination host is validated; private/reserved/metadata addresses are rejected before any socket opens (`ALLOW_PRIVATE_PROXIES=true` relaxes private ranges for local development only; metadata endpoints are *always* blocked).
2. **Connect** — TCP connect to the proxy through a rebinding-safe lookup; optional TLS transport for `https://` proxies (cert validation on).
3. **Protocol probe** — requested protocol, or auto-detect (HTTP → SOCKS5 → SOCKS4). A proxy is only labeled with a protocol it actually spoke. 407 / SOCKS auth failures are conclusive: the protocol is known even though the check failed.
4. **Echo request** — an HTTP GET to a controlled allowlist echo target through the proxy yields the exit IP and (when the target echoes them) request headers for the anonymity classifier.
5. **HTTPS/TLS test** — CONNECT (HTTP) or a SOCKS tunnel to the TLS probe host, TLS handshake with certificate validation **always enabled**, TLS version recorded, exit IP cross-checked.
6. **Normalize** — result view is built server-side: masked input, rounded latencies, confidence (`verified | partial | failed`), descriptive latency bucket.

## Concurrency model

- A job is a queue of proxy tasks; `pump()` keeps `currentConcurrency` probes in flight — never more, never unlimited.
- **Adaptive tuning**: every 2 s the engine inspects the recent outcome window — high timeout rate reduces concurrency (backoff), a healthy queue grows it back toward the configured maximum; low free memory forces reduction.
- **Cancellation**: a per-job abort signal destroys every tracked socket; in-flight probes reject quickly and are discarded, so cancel is prompt even with long timeouts.
- **Backpressure**: results stream out as they complete; SSE batches per subscriber (250 ms) so slow clients cannot accumulate unbounded frames.

## Real-time updates

`GET /api/jobs/:id/events` is a Server-Sent Events stream (`snapshot`, `results`, `geo`, `status`, `done` + heartbeats). `Last-Event-ID` lets a reconnecting client catch up without duplicates. If SSE is unavailable (e.g. a restrictive proxy), the frontend automatically falls back to REST polling.

## Storage model

Jobs live in memory with a TTL (default 2 h) and are bounded per client IP. Results are stored once per job and streamed; nothing is written to disk. For multi-instance production deployments the job queue/store interfaces are isolated in `jobs/manager.js` so a Redis-backed implementation can be swapped in (see Roadmap).
