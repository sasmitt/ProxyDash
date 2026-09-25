/** Dependency-free SVG charts, throttled for live updates. */

const NS = 'http://www.w3.org/2000/svg';
const PALETTE = ['#38bdf8', '#34d399', '#a78bfa', '#fbbf24', '#f87171', '#22d3ee', '#f472b6', '#84cc16'];

function svgEl(tag, attrs = {}) {
  const el = document.createElementNS(NS, tag);
  for (const [k, v] of Object.entries(attrs)) el.setAttribute(k, v);
  return el;
}

function cssVar(name) {
  return getComputedStyle(document.documentElement).getPropertyValue(name).trim();
}

const LATENCY_BUCKETS = [
  { label: '<100ms', min: 0, max: 100 },
  { label: '100–300', min: 100, max: 300 },
  { label: '300–700', min: 300, max: 700 },
  { label: '700–1500', min: 700, max: 1500 },
  { label: '>1500ms', min: 1500, max: Infinity },
];

/** Horizontal bar chart of latency buckets. */
export function latencyHistogram(container, results) {
  container.textContent = '';
  const counts = LATENCY_BUCKETS.map(() => 0);
  for (const r of results) {
    if (!r.alive || r.latency.totalMs == null) continue;
    const b = LATENCY_BUCKETS.findIndex((x) => r.latency.totalMs >= x.min && r.latency.totalMs < x.max);
    if (b >= 0) counts[b]++;
  }
  const max = Math.max(...counts, 1);
  const W = 320; const rowH = 26; const labelW = 66; const barX = labelW + 6;
  const svg = svgEl('svg', { viewBox: `0 0 ${W} ${counts.length * rowH + 6}`, role: 'img', 'aria-label': 'Latency distribution' });
  counts.forEach((c, i) => {
    const y = i * rowH + 4;
    const txt = svgEl('text', { x: 0, y: y + 13, fill: cssVar('--muted'), 'font-size': 11.5 });
    txt.textContent = LATENCY_BUCKETS[i].label;
    svg.appendChild(txt);
    const track = svgEl('rect', { x: barX, y: y + 2, width: W - barX - 46, height: 16, rx: 4, fill: cssVar('--surface-3') });
    svg.appendChild(track);
    const w = Math.max((c / max) * (W - barX - 46), c ? 3 : 0);
    const bar = svgEl('rect', { x: barX, y: y + 2, width: w, height: 16, rx: 4, fill: PALETTE[i % PALETTE.length] });
    svg.appendChild(bar);
    const val = svgEl('text', { x: W - 40, y: y + 13, fill: cssVar('--text'), 'font-size': 11.5, 'text-anchor': 'end' });
    val.textContent = c.toLocaleString('en-US');
    svg.appendChild(val);
  });
  container.appendChild(svg);
}

/** Donut with center label. */
function donut(container, segments, centerLabel, centerValue) {
  container.textContent = '';
  const total = segments.reduce((s, x) => s + x.value, 0);
  const size = 130; const r = 48; const cx = size / 2; const cy = size / 2;
  const svg = svgEl('svg', { viewBox: `0 0 ${size + 140} ${size}`, role: 'img', 'aria-label': centerLabel });
  if (!total) {
    const t = svgEl('text', { x: size / 2, y: cy + 4, fill: cssVar('--faint'), 'font-size': 12, 'text-anchor': 'middle' });
    t.textContent = 'no data yet';
    svg.appendChild(t);
    container.appendChild(svg);
    return;
  }
  let angle = -Math.PI / 2;
  const stroke = 16;
  for (let i = 0; i < segments.length; i++) {
    const seg = segments[i];
    if (!seg.value) continue;
    const frac = seg.value / total;
    const a2 = angle + frac * Math.PI * 2;
    const large = frac > 0.5 ? 1 : 0;
    const x1 = cx + r * Math.cos(angle); const y1 = cy + r * Math.sin(angle);
    const x2 = cx + r * Math.cos(a2); const y2 = cy + r * Math.sin(a2);
    const path = svgEl('path', {
      d: `M ${x1} ${y1} A ${r} ${r} 0 ${large} 1 ${x2} ${y2}`,
      fill: 'none', stroke: seg.color, 'stroke-width': stroke, 'stroke-linecap': 'butt',
    });
    svg.appendChild(path);
    angle = a2;
  }
  const vt = svgEl('text', { x: cx, y: cy - 2, fill: cssVar('--text'), 'font-size': 20, 'font-weight': 700, 'text-anchor': 'middle' });
  vt.textContent = centerValue;
  svg.appendChild(vt);
  const lt = svgEl('text', { x: cx, y: cy + 15, fill: cssVar('--faint'), 'font-size': 10.5, 'text-anchor': 'middle' });
  lt.textContent = centerLabel;
  svg.appendChild(lt);

  // legend
  let ly = cy - ((segments.filter((s) => s.value).length - 1) * 18) / 2;
  for (const seg of segments) {
    if (!seg.value) continue;
    const dot = svgEl('rect', { x: size + 18, y: ly - 8, width: 10, height: 10, rx: 3, fill: seg.color });
    svg.appendChild(dot);
    const t = svgEl('text', { x: size + 34, y: ly + 1, fill: cssVar('--muted'), 'font-size': 12 });
    t.textContent = `${seg.label} (${seg.value.toLocaleString('en-US')})`;
    svg.appendChild(t);
    ly += 18;
  }
  container.appendChild(svg);
}

export function aliveDonut(container, results) {
  let alive = 0;
  let dead = 0;
  for (const r of results) r.alive ? alive++ : dead++;
  donut(container, [
    { label: 'Alive', value: alive, color: cssVar('--ok') },
    { label: 'Dead', value: dead, color: cssVar('--err') },
  ], 'alive / dead', `${total(alive, dead)} checked`);
}

function total(a, b) { return (a + b).toLocaleString('en-US'); }

export function protocolDonut(container, results) {
  const counts = new Map();
  for (const r of results) {
    const key = r.protocol || 'unprobed';
    counts.set(key, (counts.get(key) || 0) + 1);
  }
  const order = ['http', 'https', 'socks5', 'socks4a', 'socks4', 'unprobed'];
  const labels = { http: 'HTTP', https: 'HTTPS', socks5: 'SOCKS5', socks4a: 'SOCKS4A', socks4: 'SOCKS4', unprobed: 'Unprobed' };
  const segments = [...counts.entries()]
    .sort((a, b) => order.indexOf(a[0]) - order.indexOf(b[0]))
    .map(([k, v], i) => ({ label: labels[k] || k, value: v, color: k === 'unprobed' ? cssVar('--faint') : PALETTE[i % PALETTE.length] }));
  donut(container, segments, 'detected protocols', results.length.toLocaleString('en-US'));
}

/** Top-N countries, horizontal bars. */
export function countryBars(container, results, n = 8) {
  container.textContent = '';
  const counts = new Map();
  for (const r of results) {
    if (!r.alive || !r.geo || !r.geo.country) continue;
    const key = r.geo.country;
    const cur = counts.get(key) || { count: 0, cc: r.geo.countryCode || '' };
    cur.count++;
    counts.set(key, cur);
  }
  const top = [...counts.entries()].sort((a, b) => b[1].count - a[1].count).slice(0, n);
  if (!top.length) {
    const t = document.createElement('div');
    t.className = 'tbl-empty';
    t.style.padding = '18px';
    t.textContent = 'No geolocated alive proxies yet.';
    container.appendChild(t);
    return;
  }
  const max = top[0][1].count;
  const W = 320; const rowH = 26; const labelW = 92;
  const svg = svgEl('svg', { viewBox: `0 0 ${W} ${top.length * rowH + 4}`, role: 'img', 'aria-label': 'Top countries' });
  top.forEach(([country, info], i) => {
    const y = i * rowH + 3;
    const label = (info.cc ? `${info.cc} · ` : '') + (country.length > 12 ? country.slice(0, 11) + '…' : country);
    const txt = svgEl('text', { x: 0, y: y + 13, fill: cssVar('--muted'), 'font-size': 11.5 });
    txt.textContent = label;
    svg.appendChild(txt);
    const barX = labelW + 4;
    const track = svgEl('rect', { x: barX, y: y + 2, width: W - barX - 40, height: 16, rx: 4, fill: cssVar('--surface-3') });
    svg.appendChild(track);
    const w = Math.max((info.count / max) * (W - barX - 40), 3);
    svg.appendChild(svgEl('rect', { x: barX, y: y + 2, width: w, height: 16, rx: 4, fill: PALETTE[1] }));
    const val = svgEl('text', { x: W - 34, y: y + 13, fill: cssVar('--text'), 'font-size': 11.5, 'text-anchor': 'end' });
    val.textContent = info.count.toLocaleString('en-US');
    svg.appendChild(val);
  });
  container.appendChild(svg);
}
