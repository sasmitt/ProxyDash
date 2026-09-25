/** Dashboard: 12 live stat cards. */

import { fmtMs, fmtNum } from './util.js';

export function renderStats(gridEl, results, snapshot) {
  let alive = 0; let dead = 0; let timeout = 0; let errors = 0;
  let latSum = 0; let fastest = null; let httpsOk = 0; let socks5 = 0;
  const countries = new Set(); const asns = new Set();
  for (const r of results) {
    if (r.alive) {
      alive++;
      if (r.latency.totalMs != null) {
        latSum += r.latency.totalMs;
        if (fastest === null || r.latency.totalMs < fastest.ms) fastest = { ms: r.latency.totalMs, host: r.input };
      }
      if (r.https && r.https.supported) httpsOk++;
      if (r.protocol === 'socks5') socks5++;
      if (r.geo && r.geo.country) countries.add(r.geo.country);
      if (r.geo && r.geo.asn) asns.add(r.geo.asn);
    } else {
      dead++;
      if (r.errorCategory === 'TIMEOUT') timeout++;
      else errors++;
    }
  }
  const checked = results.length;
  const total = snapshot ? snapshot.total : checked;
  const avg = alive ? Math.round(latSum / alive) : null;

  const cards = [
    ['Total proxies', fmtNum(total), ''],
    ['Checked', `${fmtNum(checked)}${total ? ` / ${fmtNum(total)}` : ''}`, ''],
    ['Alive', fmtNum(alive), 'ok'],
    ['Dead', fmtNum(dead), 'err'],
    ['Timeout', fmtNum(timeout), 'warn'],
    ['Errors', fmtNum(errors), errors ? 'err' : ''],
    ['Average latency', avg != null ? fmtMs(avg) : '—', 'acc'],
    ['Fastest proxy', fastest ? `<div class="v small" style="color:var(--ok)">${fmtMs(fastest.ms)}</div><div class="k mono" title="${fastest.host.replace(/"/g, '&quot;')}">${fastest.host.replace(/</g, '&lt;').slice(0, 34)}</div>` : '<div class="v">—</div>', ''],
    ['HTTPS supported', fmtNum(httpsOk), 'ok'],
    ['SOCKS5 count', fmtNum(socks5), 'acc'],
    ['Countries', fmtNum(countries.size), ''],
    ['ASNs', fmtNum(asns.size), ''],
  ];

  gridEl.innerHTML = cards.map(([k, v, cls]) => `
    <div class="stat ${cls}">
      <div class="k">${k}</div>
      ${String(v).startsWith('<div') ? v : `<div class="v">${v}</div>`}
    </div>`).join('');
}
