# Changelog

All notable changes to ProxyCheck are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project adheres to [Semantic Versioning](https://semver.org).

## [1.0.0] — 2026-09-25

First public release. Developed by Diwas Khatri.

### Added
- Multi-format proxy parser (`ip:port`, `ip:port:user:pass`, `user:pass@ip:port`, scheme URLs, IPv6, hostnames) with normalization, deduplication and invalid-line reporting
- Async checking engine: bounded adaptive concurrency, worker queue, per-proxy deadlines, bounded retries, prompt cancellation, pause/resume
- Real protocol probing for HTTP, HTTPS, SOCKS4, SOCKS4A and SOCKS5 (behavior-based, not prefix-based)
- Latency analysis (TCP / handshake / first response / total) with descriptive buckets
- Exit-IP detection, approximate geolocation, ASN/ISP/organization/reverse DNS via batched + cached provider with fallback; unknowns are shown honestly
- Anonymity classification (transparent / anonymous / elite / unknown) from actually observed headers, with reasons
- HTTPS/TLS tunnel test with certificate validation always enabled
- Authentication requirement/success/failure detection with masked credentials
- Real-time progress over Server-Sent Events with polling fallback; live dashboard with 12 stat cards and dependency-free SVG charts
- Virtualized, sortable, filterable results table and proxy detail panel with copy/export/recheck
- Exports: TXT / CSV / JSON with filter scopes; credential-preserving export behind an explicit confirmation
- SSRF protection (private/reserved/metadata blocking, rebinding-safe DNS), rate limiting, job limits, TTL cleanup, strict CSP
- REST API (`/api/check`, `/api/jobs/:id`, results, events, export, control, health, config)
- Documentation: README, Architecture, API, Proxy Formats, Performance, Security; CONTRIBUTING, Code of Conduct, Security policy, MIT License
- Test suite: 81 unit + integration tests, fully offline against mock proxies/targets; controlled local benchmark (100 → 10,000 proxies)
- Docker deployment (`Dockerfile`, `docker-compose.yml`) and `.env.example`
