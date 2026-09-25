# Deploying ProxyCheck

This guide gets ProxyCheck onto the internet with a permanent public URL using **GitHub** + **Render** (free tier works).

> **Why no Gunicorn?** Gunicorn is a WSGI server for *Python* apps. ProxyCheck is **Node.js** — it ships its own production HTTP server (`node server.js`) with a built-in async worker pool, so it needs no external application server. Deploying it is actually simpler than a Python app.

---

## Step 1 — Put the code on GitHub

### Option A: with git (recommended)

```bash
cd proxycheck
git init -b main
git config user.name "Your Name"
git config user.email "you@example.com"
git add -A
git commit -m "ProxyCheck 1.0.0 — initial release"

# create an empty repo named e.g. `proxycheck` on github.com first, then:
git remote add origin https://github.com/<your-username>/proxycheck.git
git push -u origin main
```

### Option B: no command line

1. Download `proxycheck-1.0.0.zip` (built alongside this file) and unzip it
2. Go to <https://github.com/new> → repo name `proxycheck` → **Create repository**
3. On the empty repo page click **"uploading an existing file"** and drag in **all files/folders from the unzipped project** (skip the zip itself)
4. Click **Commit changes**

GitHub Actions (`.github/workflows/ci.yml`) will automatically run lint + the 81-test suite + a smoke benchmark on every push.

---

## Step 2 — Deploy on Render

### Option A: Blueprint (one click)

1. Go to <https://dashboard.render.comBlueprints/new> (Dashboard → **New → Blueprint**)
2. Grant Render access to your repo if asked, select `proxycheck`
3. Render reads `render.yaml` (instance type, build/start commands, health check, env vars) → click **Apply**
4. Wait ~2 minutes → your app is live at `https://proxycheck-xxxx.onrender.com`

### Option B: manual Web Service

1. Dashboard → **New → Web Service** → connect your `proxycheck` repo
2. Settings:
   - **Runtime**: `Node`
   - **Build Command**: `npm install --omit=dev`
   - **Start Command**: `npm start`
   - **Health Check Path**: `/api/health`
3. Environment → add `NODE_ENV=production` (everything else has safe defaults; see the table below)
4. **Create Web Service**

### Option C: Docker

Same as Option B but **Runtime: Docker** — the included `Dockerfile` runs the app as a non-root user with a built-in healthcheck.

---

## Environment variables (all optional)

| Variable | Default | Notes |
| --- | --- | --- |
| `NODE_ENV` | `development` | set to `production` |
| `PORT` | `3000` | Render injects this automatically — don't override |
| `MAX_PROXIES_PER_JOB` | `25000` | `render.yaml` lowers it to 10000 for the free tier |
| `DEFAULT_CONCURRENCY` / `MAX_CONCURRENCY` | `100` / `500` | keep modest on small instances |
| `MAX_JOBS_PER_IP` | `3` | abuse control |
| `JOB_RATE_MAX` | `20` | jobs per 10 min per client |
| `ALLOW_PRIVATE_PROXIES` | `false` | **never** set to `true` on a public deployment |
| `GEO_ENABLED` | `true` | set `false` to disable geolocation lookups |
| `TARGET_ECHO_URLS` | httpbin / postman-echo | your controlled validation endpoints |

## Free-tier notes (read this)

- The service **sleeps after ~15 min without traffic**; the next request wakes it (~40–60 s cold start). `/api/health` responds instantly once awake.
- Jobs and results live **in memory** — they are cleared on restart, redeploy, or sleep/wake. Export results you want to keep.
- The free instance is fine for the default 1,000-proxy jobs; for sustained 25,000-proxy jobs, upgrade the instance or split lists into batches (Multi-batch is built in).
- Render terminates TLS for you; the app adds HSTS automatically when it sees `X-Forwarded-Proto: https`.

## Deploying somewhere else

Any platform that runs Node works with zero changes: Railway, Koyeb, Fly.io, Heroku (Procfile included), a plain VPS (`npm install && npm start`, put nginx/caddy in front for TLS).

## Post-deploy checklist

- [ ] `https://your-app.onrender.com/api/health` returns `{"ok":true,...}`
- [ ] `/` loads the UI (dark theme) and `/about.html` shows credits
- [ ] Start a small check (5–10 known-dead IPs like `93.184.216.34:8080`) — expect quick `CONNECTION_REFUSED`/`TIMEOUT` results, not hangs
- [ ] SSRF guard: `127.0.0.1:8080` must return `INVALID_PROXY — Blocked by SSRF protection`
