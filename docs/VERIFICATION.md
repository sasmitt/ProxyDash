# Verification Checklist (v1.0.0)

Results from the pre-release verification pass on 2026-09-25 (Node v20.20.2, Linux sandbox).

| # | Requirement | Status | Evidence |
| --- | --- | --- | --- |
| 1 | Complete application built | ✅ | Backend (18 modules) + frontend (14 modules) + docs + Docker |
| 2 | Linting | ✅ | `npm run lint` — 0 failures across all JS |
| 3 | Unit tests | ✅ | parser (14), validation (10), units (26) |
| 4 | Integration tests | ✅ | engine pipeline (16), HTTP API (12), SSRF pipeline (2), rate limits (2) — **81/81 pass** (`npm test`) |
| 5 | Controlled performance test | ✅ | `npm run bench` — 10,000 proxies in ~2.9 s (~3,450 checks/s), 0% errors, +23 MB RSS (local mocks only) |
| 6 | Errors fixed | ✅ | parser IPv6/auth-segment bugs, geo callback delivery bug, cancel counter leak, CONNECT framing — all found & fixed by the suite |
| 7 | Responsive UI | ✅ | CSS grid/auto-fit layout, mobile breakpoints at 720 px, horizontally scrollable table |
| 8 | Accessibility | ✅ | semantic landmarks, skip link, `aria-live` progress, labeled inputs, keyboard table + drawer, `aria-sort`, focus-visible, reduced-motion |
| 9 | Security review | ✅ | CSP without inline script, nosniff, no-referrer, traversal-guarded static server, rate limits, body caps |
| 10 | No credential leakage | ✅ | asserted in tests: logs redact, results serialize masked inputs, exports gated (`export credential gate` test) |
| 11 | SSRF protections | ✅ | unit tests for ranges/metadata/rebinding + pipeline test: loopback/private/metadata/localhost → `INVALID_PROXY` before any socket |
| 12 | Cancellation works | ✅ | `cancel destroys in-flight work quickly` — active→0 promptly with 20 s timeouts in flight |
| 13 | Large lists don't freeze the browser | ✅ | virtual table (windowed DOM), throttled aggregates; 25k-row cap per job |
| 14 | Exports | ✅ | TXT/CSV/JSON tests incl. CSV escaping, BOM, credential gate |
| 15 | Real-time progress | ✅ | SSE test: snapshot/results/done frames with Last-Event-ID resume; polling fallback in client |
| 16 | Duplicate removal | ✅ | parser + API tests (`duplicatesRemoved` counters) |
| 17 | Protocol detection | ✅ | behavior-based probing tests (HTTP vs SOCKS5 auto-detect) |
| 18 | Geolocation fallback | ✅ | batch → per-IP fallback → `Unknown` (never fabricated); cache verified |
| 19 | Failed proxies handled | ✅ | refused/timeout/auth/TLS paths produce categorized, retryable-aware results |
| 20 | README & docs updated | ✅ | README + docs/ (architecture, API, formats, performance, security) |

## Manual verification notes

- Live progress, pause/resume/cancel/restart and recheck exercised through the API suite; the UI wires the same endpoints.
- Dark/light theme persists via `localStorage`; `prefers-color-scheme` respected initially.
- Demo button loads clearly-labeled generated sample data so the full UI can be explored without any checks.
- In restricted networks the job start performs a direct target probe; if none are reachable the job continues in a clearly-flagged degraded mode (partial verification only).
