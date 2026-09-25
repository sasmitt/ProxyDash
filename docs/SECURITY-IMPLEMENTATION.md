# Security Implementation Notes

This document describes **how** the security requirements are implemented. For the reporting policy see [SECURITY.md](../SECURITY.md).

## SSRF protection (`src/validation.js`, `src/checker/probe.js`)

The checker makes outbound connections by design, so destinations are validated at two layers:

1. **Pre-connect guard** — `assertSafeProxyHost(host)` runs before any socket:
   - loopback `127.0.0.0/8`, `::1`
   - private ranges `10/8`, `172.16/12`, `192.168/16`, `fc00::/7`
   - link-local `169.254/16`, `fe80::/10`
   - CGNAT `100.64/10`, benchmarking `198.18/15`, documentation ranges, this-network `0/8`, reserved `240/4`, multicast
   - **cloud metadata endpoints** (`169.254.169.254`, `169.254.170.2`, `fd00:ec2::254`) are blocked **always**, even when `ALLOW_PRIVATE_PROXIES=true` is set for local testing
   - blocked hostnames (`localhost`, `metadata.google.internal`, …)
2. **Rebinding-safe lookup** — connections use a custom `dns.lookup` that validates every resolved address *inside the connect call*, eliminating the validate-then-connect TOCTOU window. IPv4-mapped IPv6 (`::ffff:127.0.0.1`) is normalized and re-checked.

`ALLOW_PRIVATE_PROXIES=true` relaxes only private/loopback ranges (for local development and the test suite) — never metadata endpoints. Guard blocks are surfaced as `INVALID_PROXY` with an "SSRF protection" message.

**Target allowlist** — the checker only ever contacts the configured echo targets and TLS probe host (`TARGET_ECHO_URLS`, `TARGET_TLS_HOST`). There is no API that accepts an arbitrary check URL.

## Credential handling

- Passwords exist **only** in server-side job records; serialized results rebuild inputs as `user:********@host:port`.
- The logger redacts keys matching `/pass|pwd|secret|token|credential|authorization/i` and truncates long values.
- Exports contain credentials only with `include=credentials&confirm=yes` — two explicit parameters, enforced server-side (`CONFIRM_REQUIRED` otherwise). Password fields are excluded from CSV/JSON unless that flag is set; TXT exports use the reconstructed original line.
- The credential-preserving recheck feature rebuilds input lines server-side; clients never see or send passwords.

## Input handling

- JSON body parsing with hard size cap (`MAX_BODY_BYTES`, default 10 MB) and content-type checking; 413 responses flush politely before the socket is dropped.
- Proxy lists: line length caps, control-character stripping for array inputs, malformed lines reported (never executed, never `eval`'d, treated purely as text).
- Uploads are plain text only; the frontend enforces a 20 MB file limit and the server enforces its own body cap. Nothing uploaded is ever executed.

## Rate limiting & abuse control

- Per-client token bucket for API requests (default 240/min) and a separate job-creation limit (default 20/10 min).
- Max concurrent active jobs per client (default 3); per-job proxy cap (default 25,000).
- Bounded engine concurrency (1–500) with adaptive reduction under timeout storms; memory guard.
- Job TTL (default 2 h) with periodic cleanup; hard-stop for zombie jobs.

## HTTP hardening

- `Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'` — no inline scripts, all frontend code is self-hosted modules.
- `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, `Permissions-Policy` lockdown.
- `Strict-Transport-Security` added when the request arrives over HTTPS (`X-Forwarded-Proto: https`).
- Static file server resolves and confines every path under `public/` (traversal attempts → 403/404).
- API 404s/405s and internal errors return structured JSON; stack traces stay in server logs.

## TLS policy

Certificate validation is **never** disabled — not for the proxy transport, not for tunnel tests. A self-signed/invalid certificate is an honest `TLS_ERROR` result. `TLS_EXTRA_CA` may *add* a trusted CA (private CAs); it can never turn validation off.

## Responsible use

The tool is for testing proxies you supply or are authorized to test. Features that would enable credential bypass, stealth scanning, or abuse of third-party systems are intentionally out of scope; test traffic is limited to the allowlisted controlled endpoints with modest rates.
