# Performance

## Design target

**1,000 proxies in ~3 minutes** with the default configuration (8 s timeout, concurrency 100, 1 retry). This is a design target, **not** a guarantee: real-world duration is dominated by proxy latency and network conditions, not by the engine.

## Optimizations

**Engine**
- Fully asynchronous I/O on raw sockets (`net`/`tls`) — no per-check HTTP agent overhead
- Bounded worker pool with adaptive concurrency (timeout-rate feedback + memory guard)
- Single per-proxy deadline shared across protocol strategies, retries and the TLS test
- Prompt cancellation — in-flight sockets are destroyed, not waited out
- Geolocation batched (up to 100 IPs/request), rate-limited, LRU+TTL cached across jobs

**Transport**
- Connection reuse where safe (SOCKS tunnel carries the HTTP request directly)
- Response bodies capped (256 KB) so pathological targets cannot balloon memory
- DNS resolved once per connect through a validating lookup (no double lookups)

**Frontend**
- Virtual scrolling: only visible rows exist in the DOM (handles 25,000 rows)
- Aggregations computed over plain arrays with throttled re-render (~280 ms)
- SSE batches results (250 ms) instead of per-result network events
- Dependency-free SVG charts — no framework hydration cost

## Controlled benchmark

`npm run bench` measures the **real engine** against **local mock proxies** — never third-party infrastructure. Reference numbers (2 vCPU sandbox, Node 20, concurrency 100, canned responses):

| Proxies | Duration | Checks/s | Avg latency | Errors | ΔRSS |
| ---: | ---: | ---: | ---: | ---: | ---: |
| 100 | ~0.10 s | ~970 | ~29 ms | 0% | ~6 MB |
| 500 | ~0.30 s | ~1,650 | ~47 ms | 0% | ~14 MB |
| 1,000 | ~0.42 s | ~2,400 | ~36 ms | 0% | ~9 MB |
| 5,000 | ~1.5 s | ~3,400 | ~28 ms | 0% | ~8 MB |
| 10,000 | ~2.9 s | ~3,450 | ~28 ms | 0% | ~23 MB |

> These are **synthetic, local** numbers that measure the pipeline itself (parsing, scheduling, sockets, serialization). A real public proxy check takes hundreds of milliseconds and depends entirely on the proxy — which is exactly why the checker is latency-bound, not CPU-bound, in production.

## Scaling notes

- Memory: a 25,000-proxy job holds its results in memory (~1–2 KB/result). `MAX_PROXIES_PER_JOB` and `JOB_TTL_MS` bound worst-case usage; lower them for constrained environments.
- CPU: the engine is I/O bound; two cores sustain thousands of concurrent checks. `MIN_CONCURRENCY`/`MAX_CONCURRENCY` let you pin the envelope.
- For multi-instance deployments, swap the in-memory job store for a Redis-backed queue (interfaces are isolated in `src/jobs/manager.js`).
