# API Reference

Base URL: `http://localhost:3000` (or your deployment origin). All request/response bodies are JSON unless downloading an export.

## Start a check

```http
POST /api/check
Content-Type: application/json

{
  "text": "1.2.3.4:8080\n5.6.7.8:3128",
  "timeout": 8000,
  "concurrency": 100,
  "retries": 1,
  "protocol": "auto",
  "httpsTest": true
}
```

- `text` (string) **or** `proxies` (string array) — the raw proxy list; formats are auto-detected.
- `timeout` — per-proxy deadline in ms, clamped to 1 000–30 000 (default 8 000).
- `concurrency` — clamped to 1–500 (default 100).
- `retries` — clamped to 0–3 (default 1); only transient failures retry.
- `protocol` — `auto | http | https | socks4 | socks4a | socks5` (default `auto`).
- `httpsTest` — run the HTTPS/TLS tunnel test for alive proxies (default true).

**Response — 202**

```json
{
  "jobId": "job_9f2c10ab55de4c7a",
  "total": 2,
  "status": "queued",
  "totalLines": 3,
  "duplicatesRemoved": 1,
  "uniqueCount": 2,
  "invalidCount": 0,
  "invalid": []
}
```

Errors: `400 NO_VALID_PROXIES` (includes parse details), `413 TOO_MANY_PROXIES` / `BODY_TOO_LARGE`, `429 RATE_LIMITED` / `JOB_RATE_LIMITED` / `JOB_LIMIT`, `400 BAD_PARAM` for malformed options.

## Job snapshot

```http
GET /api/jobs/:id
```

```json
{
  "snapshot": {
    "id": "job_…", "status": "running", "total": 2, "checked": 1,
    "counts": { "alive": 1, "timeout": 0, "refused": 0, "auth": 0, "other": 0 },
    "dead": 0, "avgLatencyMs": 184, "etaMs": 900,
    "concurrency": { "configured": 100, "current": 100 },
    "duplicatesRemoved": 0, "invalidCount": 0,
    "observerIp": "198.51.100.7", "degraded": false,
    "createdAt": "2026-09-25T12:00:00.000Z", "expiresAt": "2026-09-25T14:00:00.000Z"
  },
  "resultsTotal": 1
}
```

## Results (filtered + paged)

```http
GET /api/jobs/:id/results?status=alive&protocol=socks5&speed=fast&limit=500&sort=latency&dir=asc
```

Filters: `status` (`alive|dead`), `protocol` (`http|https|socks4|socks4a|socks5`), `https` (`supported|failed`), `anonymity` (`transparent|anonymous|elite|unknown`), `auth` (`required|no|failed`), `speed` (`fast|moderate|slow`), `country`, `asn`, `isp`, `q` (free text over ip/host/exit-ip/country/city/asn/isp), `maxLatencyMs`. Sorting: `seq | latency | input | exitIp | country | checkedAt | httpStatus | protocol` with `dir=asc|desc`. Paging: `limit` (≤5000) and `offset`.

Each result:

```json
{
  "seq": 0, "i": 0,
  "input": "user:********@1.2.3.4:8080",
  "host": "1.2.3.4", "port": 8080, "hasAuth": true,
  "requestedProtocol": "auto", "protocol": "http",
  "status": "alive", "alive": true, "partial": false,
  "exitIp": "203.0.113.9",
  "geo": { "state": "ok", "country": "Germany", "countryCode": "DE", "region": "Hesse",
           "city": "Frankfurt", "latitude": 50.11, "longitude": 8.68,
           "timezone": "Europe/Berlin", "asn": "AS12345", "asOrg": "Example Network GmbH",
           "isp": "Example Network", "org": "Example", "reverse": "", "source": "ip-api" },
  "latency": { "tcpMs": 42, "handshakeMs": 0, "requestMs": 184, "totalMs": 226 },
  "bucket": "moderate",
  "httpStatus": 200,
  "https": { "supported": true, "tlsVersion": "TLSv1.3", "certValid": true, "error": null },
  "anonymity": { "level": "anonymous", "reason": "…", "evidence": ["via: …"] },
  "auth": { "required": false, "provided": true, "ok": true },
  "dns": "remote (resolved by proxy)",
  "errorCategory": null, "errorMessage": null,
  "confidence": "verified",
  "attempts": 1,
  "checkedAt": "2026-09-25T12:00:01.123Z"
}
```

Passwords are **never** included — inputs are rebuilt as masked labels.

## Live stream (SSE)

```http
GET /api/jobs/:id/events        (text/event-stream)
```

Events: `snapshot` (full progress), `results` (batches; `id:` carries the last `seq` for `Last-Event-ID` resume), `geo` (async geolocation updates), `status`, `done`. Heartbeat comments keep intermediaries from closing the stream. Reconnect replays everything after `Last-Event-ID`.

## Control

```http
POST /api/jobs/:id/cancel
POST /api/jobs/:id/pause
POST /api/jobs/:id/resume
POST /api/jobs/:id/recheck    {"scope": "all|failed|selected", "keys": [0,1]}
```

All return `{ "snapshot": { … } }` (recheck returns the **new** job reference: `{jobId, total, status, recheckedFrom}`).

## Export

```http
GET /api/jobs/:id/export?format=csv&status=alive&sort=latency
GET /api/jobs/:id/export?format=txt&scheme=true
GET /api/jobs/:id/export?format=txt&include=credentials&confirm=yes
```

- Formats: `txt` (default, `ip:port` lines), `csv` (full metadata, BOM + headers), `json` (documented payload).
- All results filters apply to exports too.
- **Credentials** are only included when `include=credentials&confirm=yes` are BOTH present. This is intentionally explicit; without it, exports can never contain passwords.

## Health & config

```http
GET /api/health   → { ok, status, version, uptimeSec, jobs, geo, targets }
GET /api/config   → defaults + limits (used by the frontend)
```

## Error format

```json
{ "error": { "code": "BAD_PARAM", "message": "\"timeout\" must be an integer." } }
```

Stack traces never reach the client — they are logged server-side with credentials redacted.
