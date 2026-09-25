'use strict';
/**
 * Job manager: bounded-concurrency checking engine.
 *
 * - Workers pull from a queue; concurrency is bounded and adaptive.
 * - Pause / resume / cancel are supported; cancel destroys in-flight sockets.
 * - Results stream to subscribers (SSE) in completion order; geo enrichment
 *   is attached asynchronously via the shared GeoClient cache.
 * - Credentials never leave the server: serialized results use masked inputs.
 */
const crypto = require('crypto');
const os = require('os');
const { EventEmitter } = require('events');
const config = require('../config');
const logger = require('../logger');
const { parseProxyList, proxyKey } = require('../parser');
const { CheckError, RETRYABLE, ApiError } = require('../errors');
const { checkProxy } = require('../checker/probe');
const { latencyBucket, clamp, backoffMs, sleep } = require('../utils');
const { EMPTY_GEO } = require('../geo/geoClient');
const { probeEchoTargets } = require('../targets');
const { buildResultView } = require('./view');

function newJobId() {
  return `job_${crypto.randomBytes(8).toString('hex')}`;
}

class Signal {
  constructor() {
    this.aborted = false;
    this.listeners = new Set();
  }

  onAbort(fn) {
    if (this.aborted) fn();
    else this.listeners.add(fn);
  }

  abort() {
    if (this.aborted) return;
    this.aborted = true;
    for (const fn of this.listeners) { try { fn(); } catch { /* noop */ } }
    this.listeners.clear();
  }
}

class Job {
  constructor({ id, proxies, rawText, config: cfg, meta }) {
    this.id = id;
    this.proxies = proxies; // full parse output, incl. credentials (server-only)
    this.rawText = rawText; // original input, for credential-preserving export
    this.cfg = cfg;
    this.meta = meta || {};
    this.status = 'queued';
    this.signal = new Signal();
    this.results = []; // serialized result views, seq == index
    this.checked = 0;
    this.nextIndex = 0;
    this.active = 0;
    this.paused = false;
    this.cancelled = false;
    this.counts = { alive: 0, timeout: 0, refused: 0, auth: 0, other: 0 };
    this.latencySum = 0;
    this.createdAt = Date.now();
    this.startedAt = null;
    this.finishedAt = null;
    this.expiresAt = Date.now() + config.limits.jobTtlMs;
    this.currentConcurrency = cfg.concurrency;
    this.outcomes = []; // recent {latencyMs, category} for adaptation
    this.echo = null; // {working, clientIp, degraded}
    this.emitter = new EventEmitter();
    this.emitter.setMaxListeners(100);
    this._resultBatch = [];
    this._flushTimer = null;
    this._adaptTimer = null;
    this._geoPending = 0;
    this._doneEmitted = false;
  }

  /** Progress snapshot for the API/UI. */
  snapshot() {
    const elapsed = this.startedAt ? (this.finishedAt || Date.now()) - this.startedAt : 0;
    const rate = elapsed > 200 ? this.checked / (elapsed / 1000) : null;
    const remaining = this.total - this.checked;
    return {
      id: this.id,
      status: this.status,
      total: this.total,
      checked: this.checked,
      counts: { ...this.counts },
      dead: this.total ? this.checked - this.counts.alive : 0,
      avgLatencyMs: this.counts.alive ? Math.round(this.latencySum / this.counts.alive) : null,
      etaMs: rate && remaining > 0 && this.status === 'running' ? Math.round((remaining / rate) * 1000) : this.status === 'completed' ? 0 : null,
      concurrency: {
        configured: this.cfg.concurrency,
        current: this.currentConcurrency,
      },
      timeoutMs: this.cfg.timeoutMs,
      retries: this.cfg.retries,
      httpsTest: this.cfg.httpsTest,
      duplicatesRemoved: this.duplicatesRemoved,
      invalidCount: this.invalidCount,
      observerIp: this.echo && this.echo.clientIp ? this.echo.clientIp : null,
      degraded: Boolean(this.echo && this.echo.degraded),
      createdAt: new Date(this.createdAt).toISOString(),
      startedAt: this.startedAt ? new Date(this.startedAt).toISOString() : null,
      finishedAt: this.finishedAt ? new Date(this.finishedAt).toISOString() : null,
      expiresAt: new Date(this.expiresAt).toISOString(),
    };
  }

  get total() {
    return this.proxies.length;
  }
}

class JobManager {
  constructor(geoClient) {
    this.geo = geoClient;
    this.jobs = new Map();
    this.jobsByIp = new Map(); // client ip -> Set of active job ids
    this.cleanupTimer = setInterval(() => this.cleanup(), 60 * 1000);
    this.cleanupTimer.unref();
  }

  activeJobsFor(ip) {
    const set = this.jobsByIp.get(ip);
    if (!set) return 0;
    let n = 0;
    for (const id of set) {
      const j = this.jobs.get(id);
      if (j && (j.status === 'queued' || j.status === 'running' || j.status === 'paused')) n++;
    }
    return n;
  }

  /**
   * Create and start a job from raw text input.
   * @returns {{job: Job, parse: object}}
   */
  createJob(text, opts, clientMeta) {
    const parse = parseProxyList(text);
    if (parse.uniqueCount === 0) {
      const err = new ApiError(400, 'NO_VALID_PROXIES', 'No valid proxies were found in the input.');
      err.parse = { totalLines: parse.totalLines, invalid: parse.invalid.slice(0, config.limits.maxInvalidReported), invalidCount: parse.invalid.length };
      throw err;
    }
    if (parse.uniqueCount > config.limits.maxProxiesPerJob) {
      throw new ApiError(413, 'TOO_MANY_PROXIES', `Refusing to queue ${parse.uniqueCount} proxies; the limit is ${config.limits.maxProxiesPerJob}. Split the list into batches.`);
    }
    const active = this.activeJobsFor(clientMeta.ip);
    if (active >= config.limits.maxJobsPerIp) {
      throw new ApiError(429, 'JOB_LIMIT', `You already have ${active} active job(s). Wait for them to finish or cancel one.`);
    }

    const cfg = {
      concurrency: clamp(opts.concurrency | 0 || config.checker.defaultConcurrency, 1, config.checker.maxConcurrency),
      timeoutMs: clamp(opts.timeoutMs | 0 || config.checker.defaultTimeoutMs, config.checker.minTimeoutMs, config.checker.maxTimeoutMs),
      retries: clamp(opts.retries | 0, 0, config.checker.maxRetries),
      protocol: opts.protocol || 'auto',
      httpsTest: opts.httpsTest !== false && config.checker.httpsTest,
    };

    // If a specific protocol is requested, filter nothing — the probe uses it
    // as the only strategy. Annotate proxies for that here.
    const proxies = parse.proxies.map((p) => ({
      ...p,
      protocol: cfg.protocol === 'auto' ? p.protocol : cfg.protocol,
    }));

    const job = new Job({
      id: newJobId(),
      proxies,
      rawText: text,
      config: cfg,
      meta: { ip: clientMeta.ip, userAgent: clientMeta.userAgent },
    });
    job.duplicatesRemoved = parse.duplicateCount;
    job.invalidCount = parse.invalid.length;
    job.parse = parse;
    this.jobs.set(job.id, job);
    if (!this.jobsByIp.has(clientMeta.ip)) this.jobsByIp.set(clientMeta.ip, new Set());
    this.jobsByIp.get(clientMeta.ip).add(job.id);

    setImmediate(() => this.run(job));
    return { job, parse };
  }

  get(id) {
    return this.jobs.get(id);
  }

  getOr404(id) {
    const job = this.jobs.get(id);
    if (!job) throw new ApiError(404, 'JOB_NOT_FOUND', 'Job not found. It may have expired (jobs are kept for a limited time).');
    return job;
  }

  pause(id) {
    const job = this.getOr404(id);
    if (job.status === 'running' || job.status === 'queued') {
      job.paused = true;
      job.status = 'paused';
      this.emit(job, 'status', { status: job.status });
    }
    return job.snapshot();
  }

  resume(id) {
    const job = this.getOr404(id);
    if (job.status === 'paused') {
      job.paused = false;
      job.status = 'running';
      this.emit(job, 'status', { status: job.status });
      setImmediate(() => this.pump(job));
    }
    return job.snapshot();
  }

  cancel(id) {
    const job = this.getOr404(id);
    if (job.status === 'completed' || job.status === 'cancelled') return job.snapshot();
    job.cancelled = true;
    job.paused = false;
    job.signal.abort(); // destroys in-flight sockets
    job.active = 0; // in-flight tasks will discard themselves without recording
    job.status = 'cancelled';
    logger.info('job cancelled', { jobId: job.id });
    this.finalize(job);
    return job.snapshot();
  }

  emit(job, event, payload) {
    job.emitter.emit('event', { event, payload });
  }

  /** Main loop: keep `currentConcurrency` probes in flight. */
  pump(job) {
    if (job.status === 'cancelled' || job.status === 'completed' || job.status === 'failed') return;
    const conc = job.currentConcurrency;
    while (!job.paused && !job.cancelled && job.active < conc && job.nextIndex < job.total) {
      const i = job.nextIndex++;
      job.active++;
      this.runTask(job, i).catch((err) => {
        // Defensive: runTask should never reject.
        logger.error('task crashed', { jobId: job.id, error: err.message });
        job.active--;
        this.record(job, { status: 'dead', errorCategory: 'UNKNOWN_ERROR', errorMessage: 'Internal check error.' }, i, {});
      });
    }
    if (job.checked >= job.total && job.active === 0 && !job.cancelled) this.finalize(job);
  }

  async runTask(job, i) {
    const proxy = job.proxies[i];
    const deadlineCfg = {
      timeoutMs: job.cfg.timeoutMs,
      httpsTest: job.cfg.httpsTest,
      echoTargets: job.echo && job.echo.working.length ? job.echo.working : config.targets.echoUrls,
      tlsProbeHost: config.targets.tlsProbeHost,
      tlsProbePort: config.targets.tlsProbePort,
      allowPrivate: config.checker.allowPrivateProxies,
      clientIp: job.echo ? job.echo.clientIp : null,
      signal: job.signal,
    };

    let current = null;
    let attempt = 0;
    for (;;) {
      if (job.signal.aborted) return this.discard(job);
      try {
        current = await checkProxy(proxy, deadlineCfg);
        break;
      } catch (err) {
        current = {
          status: 'dead',
          alive: false,
          protocol: null,
          errorCategory: err && err.category ? err.category : 'UNKNOWN_ERROR',
          errorMessage: err && err.message ? err.message : 'check crashed',
        };
        break;
      }
    }

    // Bounded retries for transient failures only.
    let retriesUsed = 0;
    while (
      !job.signal.aborted &&
      retriesUsed < job.cfg.retries &&
      current && !current.alive &&
      (RETRYABLE.has(current.errorCategory) || current.errorCategory === 'TIMEOUT')
    ) {
      await sleep(backoffMs(retriesUsed));
      if (job.signal.aborted) return this.discard(job);
      retriesUsed++;
      try {
        current = await checkProxy(proxy, deadlineCfg);
      } catch {
        break;
      }
    }
    if (current) current.attempts = 1 + retriesUsed;
    if (job.signal.aborted) return this.discard(job);

    this.record(job, current, i, proxy);
    job.active--;
    setImmediate(() => this.pump(job));
  }

  /** Attach geo asynchronously and emit the serialized result. */
  record(job, raw, i, proxy) {
    if (job.status === 'cancelled') return;
    const seq = job.results.length;
    const result = buildResultView(raw, proxy, seq, i);
    job.results.push(result);
    job.checked++;

    if (result.alive) {
      job.counts.alive++;
      if (result.latency.totalMs != null) job.latencySum += result.latency.totalMs;
    } else if (result.errorCategory === 'TIMEOUT') job.counts.timeout++;
    else if (result.errorCategory === 'CONNECTION_REFUSED') job.counts.refused++;
    else if (result.errorCategory === 'AUTH_FAILED') job.counts.auth++;
    else job.counts.other++;

    job.outcomes.push({ latencyMs: result.latency.totalMs, category: result.errorCategory });
    if (job.outcomes.length > 120) job.outcomes.shift();

    this.emit(job, 'result', { seq, result });
    this.scheduleBatchFlush(job);

    if (result.alive && result.exitIp && this.geo && config.geo.enabled) {
      job._geoPending++;
      this.geo.lookup(result.exitIp, (geo) => {
        result.geo = geo || { ...EMPTY_GEO() };
        job._geoPending--;
        this.emit(job, 'geo', { seq, geo: result.geo });
      });
    }
  }

  discard(job) {
    // cancelled before completion — nothing to record
  }

  scheduleBatchFlush() {
    /* results are emitted individually; the SSE layer batches per subscriber */
  }

  /** Adaptive concurrency: react to timeout rate, backlog, and memory. */
  adapt(job) {
    if (job.status !== 'running') return;
    const recent = job.outcomes.slice(-80);
    if (recent.length < 10) return;
    const timeouts = recent.filter((o) => o.category === 'TIMEOUT').length;
    const rate = timeouts / recent.length;
    const min = config.checker.minConcurrency;
    const max = job.cfg.concurrency;
    let next = job.currentConcurrency;
    if (rate > config.checker.timeoutRateHigh) {
      next = Math.max(min, Math.floor(next * 0.8));
    } else if (rate < config.checker.timeoutRateLow && job.nextIndex < job.total && next < max) {
      next = Math.min(max, next + Math.max(1, Math.floor(max * 0.1)));
    }
    const freeMem = os.freemem();
    if (freeMem < 200 * 1024 * 1024) next = Math.max(min, Math.floor(next * 0.5));
    if (next !== job.currentConcurrency) {
      logger.debug('adaptive concurrency', { jobId: job.id, from: job.currentConcurrency, to: next, timeoutRate: Number(rate.toFixed(2)), freeMemMb: Math.round(freememMb()) });
      job.currentConcurrency = next;
    }
  }

  async run(job) {
    job.status = 'running';
    job.startedAt = Date.now();
    this.emit(job, 'status', { status: job.status });

    // Probe controlled targets directly (no proxy) to order them and learn
    // the observer IP used for transparency detection.
    try {
      const probeResult = await probeEchoTargets(config.targets.echoUrls, 3500);
      job.echo = {
        working: probeResult.working.length ? probeResult.working : config.targets.echoUrls,
        clientIp: probeResult.clientIp,
        degraded: probeResult.working.length === 0,
      };
    } catch {
      job.echo = { working: config.targets.echoUrls, clientIp: null, degraded: true };
    }
    if (job.echo.degraded) {
      logger.warn('no echo target reachable directly; checks continue through proxies only', { jobId: job.id });
    }
    if (job.signal.aborted) return this.finalize(job);

    this.emit(job, 'start', { echo: job.echo, total: job.total });
    this._adaptTimer = setInterval(() => this.adapt(job), config.checker.adaptIntervalMs);
    this._adaptTimer.unref();
    this.pump(job);
  }

  finalize(job) {
    if (job._doneEmitted) return;
    job._doneEmitted = true;
    if (job.status !== 'cancelled') {
      job.status = job.checked >= job.total ? 'completed' : job.status;
    }
    job.finishedAt = Date.now();
    if (job._adaptTimer) clearInterval(job._adaptTimer);
    const waitGeo = () => {
      if (job._geoPending <= 0 || Date.now() - job.finishedAt > 8000) {
        this.emit(job, 'done', { status: job.status, snapshot: job.snapshot() });
      } else {
        setTimeout(waitGeo, 250);
      }
    };
    waitGeo();
  }

  cleanup() {
    const now = Date.now();
    for (const [id, job] of this.jobs) {
      if (job.expiresAt < now && (job.status === 'completed' || job.status === 'cancelled' || job.status === 'failed')) {
        this.jobs.delete(id);
      } else if (job.expiresAt + 30 * 60 * 1000 < now) {
        // hard stop for zombie jobs
        if (job.status === 'running' || job.status === 'paused') this.cancel(id);
        this.jobs.delete(id);
      }
    }
  }

  stats() {
    let active = 0;
    let running = 0;
    for (const job of this.jobs.values()) {
      if (job.status === 'running' || job.status === 'paused' || job.status === 'queued') running++;
      active++;
    }
    return { jobs: active, running };
  }

  stop() {
    clearInterval(this.cleanupTimer);
    for (const job of this.jobs.values()) {
      if (job.status === 'running' || job.status === 'paused' || job.status === 'queued') this.cancel(job.id);
    }
  }
}

function freememMb() {
  return os.freemem() / (1024 * 1024);
}

module.exports = { JobManager, Job, Signal };
