# Contributing to ProxyCheck

Thanks for your interest in improving ProxyCheck! Developed by **Diwas Khatri**.

## Getting started

```bash
git clone <your-fork>
cd proxycheck
npm install        # zero runtime dependencies
npm run dev        # http://localhost:3000
npm test           # must pass before any PR
npm run lint       # syntax checks
```

## Ground rules

1. **No fabricated claims** — README/UI copy must not promise "100% accuracy" or invent providers, partnerships, or benchmarks. Uncertainty is a feature: show `Unknown`.
2. **Credentials are sacred** — never add a code path that logs, serializes or exports passwords outside the explicit `include=credentials&confirm=yes` export gate.
3. **SSRF guard stays** — don't weaken destination validation; if you need private targets for tests, use `ALLOW_PRIVATE_PROXIES=true` locally.
4. **Zero runtime dependencies** is a design goal — argue your case in an issue before adding one.
5. **Tests accompany changes** — new parser formats, engine behaviors and API endpoints need coverage. The suite is fully offline (mock servers in `tests/helpers/`).
6. **Modular code** — respect the module boundaries in `docs/ARCHITECTURE.md`; no mega-files.

## Style

- Plain Node.js (CommonJS) on the server, vanilla ES modules in the browser
- Clear names over comments; comment only the "why"
- Structured logging via `src/logger.js` — never `console.log` in library code
- All user-visible text must be honest about uncertainty (point-in-time status, approximate geolocation)

## Pull requests

1. Fork & branch (`feat/…` or `fix/…`)
2. Make your change with tests
3. `npm test && npm run lint` green
4. Update `CHANGELOG.md` and, when relevant, `docs/`
5. Open a PR describing what and why

## Reporting bugs

Open an issue with: what you did, what you expected, what happened, and the proxy format involved (mask credentials!). Security issues: see [SECURITY.md](SECURITY.md) — report privately.
