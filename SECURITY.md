# Security Policy

## Supported version

| Version | Supported |
| --- | --- |
| 1.0.x | yes |

## Reporting a vulnerability

Please report security issues privately to the developer, **Diwas Khatri**, via the contact channel through which you received this software. Do not open a public issue for anything you believe is exploitable.

Include: a description, steps to reproduce, affected component, and your assessment of impact. You will get an acknowledgement and a plan; please allow a reasonable window for a fix before any public disclosure.

## Scope notes

ProxyCheck is a network testing tool: it intentionally makes outbound connections to proxies supplied by its users and to a small allowlist of controlled test endpoints. Reports are in scope when they involve:

- Bypassing the SSRF guard (e.g. reaching cloud metadata, loopback or private ranges)
- Credential leakage (logs, results, exports, memory dumps aside)
- Denial of service through unbounded resource consumption
- Injection into the frontend (XSS), path traversal in the static server
- Rate-limit or job-limit bypass with resource exhaustion

Out of scope: the tool being *used* to test proxies you do not own, or weaknesses in the proxies themselves.

## Hardening defaults

- SSRF guard on every destination (including DNS results and metadata endpoints)
- Credential redaction in logs; masked results; explicit-gated credential export
- Body-size caps, per-IP rate limits, per-client job limits, job TTLs
- Strict CSP without inline script, `nosniff`, `no-referrer`
- Certificate validation never disabled
