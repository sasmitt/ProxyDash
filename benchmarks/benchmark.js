'use strict';
/**
 * Controlled performance benchmark.
 *
 * Runs the real checking engine against LOCAL mock proxies/targets only —
 * never against third-party infrastructure (see docs/PERFORMANCE.md).
 *
 * Usage: npm run bench [-- 100 500 1000 5000 10000]
 */
process.env.ALLOW_PRIVATE_PROXIES = 'true';
process.env.GEO_ENABLED = 'false'; // geo is benchmarked separately below
process.env.HTTPS_TEST = 'false';

const fs = require('fs');
const path = require('path');
const os = require('os');

const { createEchoServer, createHttpProxy, waitFor } = require('../tests/helpers/mockProxy');
const config = require('../src/config');
const { GeoClient } = require('../src/geo/geoClient');
const { JobManager } = require('../src/jobs/manager');

const SIZES = (process.argv[2] ? process.argv[2].split(',').map(Number) : [100, 500, 1000, 5000, 10000])
  .filter((n) => Number.isFinite(n) && n > 0);

function fmt(n) {
  return Number(n).toLocaleString('en-US', { maximumFractionDigits: 1 });
}

function rssMb() {
  return process.memoryUsage().rss / (1024 * 1024);
}

async function runOnce(manager, lines, concurrency) {
  const rssBefore = rssMb();
  const t0 = process.hrtime.bigint();
  const created = manager.createJob(lines.join('\n'), {
    concurrency,
    timeoutMs: 5000,
    retries: 0,
    httpsTest: false,
  }, { ip: 'benchmark' });
  const { job } = created;
  await waitFor(() => ['completed', 'failed'].includes(job.status), 10 * 60 * 1000, 50);
  const durMs = Number(process.hrtime.bigint() - t0) / 1e6;
  const alive = job.counts.alive;
  const latencies = job.results.map((r) => r.latency.totalMs).filter((x) => x != null);
  const avg = latencies.length ? latencies.reduce((a, b) => a + b, 0) / latencies.length : 0;
  return {
    total: job.total,
    durationMs: Math.round(durMs),
    avgLatencyMs: Math.round(avg),
    alive,
    errorRate: Number(((job.total - alive) / job.total) * 100).toFixed(2) + '%',
    checksPerSec: fmt((job.total / durMs) * 1000),
    rssDeltaMb: Number((rssMb() - rssBefore).toFixed(1)),
    rssTotalMb: Number(rssMb().toFixed(1)),
    duplicatesRemoved: job.duplicatesRemoved,
  };
}

async function main() {
  console.log('ProxyCheck benchmark — controlled local infrastructure\n');
  console.log(`node ${process.version}, cpus ${os.cpus().length}, rss ${fmt(rssMb())} MB\n`);

  const echo = createEchoServer();
  const echoPort = await echo.ready;
  process.env.TARGET_ECHO_URLS = `http://127.0.0.1:${echoPort}/echo`;

  const proxy = createHttpProxy({ canned: true }); // fast canned responses
  const proxyPort = await proxy.ready;

  const geo = new GeoClient();
  const manager = new JobManager(geo);

  const results = [];
  for (const size of SIZES) {
    const lines = Array.from({ length: size }, (_, i) => `u${i}:pw@127.0.0.1:${proxyPort}`);
    const row = await runOnce(manager, lines, config.checker.defaultConcurrency);
    results.push({ proxies: size, concurrency: config.checker.defaultConcurrency, ...row });
    console.log(
      `${String(size).padStart(6)} proxies → ${String(row.durationMs).padStart(7)} ms  |  ` +
      `${row.checksPerSec} checks/s  |  avg ${row.avgLatencyMs} ms  |  alive ${row.alive}  |  ` +
      `err ${row.errorRate}  |  Δrss ${row.rssDeltaMb} MB`,
    );
  }

  // geo batch throughput (separate, still local-only)
  const t0 = Date.now();
  const N = 500;
  await Promise.all(Array.from({ length: N }, (_, i) => new Promise((res) => geo.lookup(`93.184.${Math.floor(i / 256)}.${i % 256}`, res))));
  const geoMs = Date.now() - t0;
  console.log(`\ngeo enrichment: ${N} unique IPs in ${geoMs} ms (${fmt((N / geoMs) * 1000)} lookups/s, batched)`);

  const outDir = path.join(__dirname, 'results');
  fs.mkdirSync(outDir, { recursive: true });
  const file = path.join(outDir, `benchmark-${new Date().toISOString().replace(/[:T]/g, '-').slice(0, 19)}.json`);
  fs.writeFileSync(file, JSON.stringify({
    benchmark: 'ProxyCheck local pipeline benchmark',
    date: new Date().toISOString(),
    node: process.version,
    note: 'Synthetic workload against local mock proxies. Not comparable to real-world proxy checks.',
    results,
    geo: { ips: N, durationMs: geoMs },
  }, null, 2));
  console.log(`\nsaved → ${path.relative(process.cwd(), file)}`);

  manager.stop();
  geo.stop();
  await proxy.close();
  await echo.close();
  process.exit(0);
}

main().catch((err) => {
  console.error('benchmark failed:', err);
  process.exit(1);
});
