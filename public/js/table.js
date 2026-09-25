/** High-performance virtualized results table. */

import { esc, fmtMs, latencyClass } from './util.js';

const ROW_H = 40;

function chip(cls, text) {
  return `<span class="chip ${cls}">${esc(text)}</span>`;
}

function httpsChip(r) {
  const h = r.https || {};
  if (h.supported === true) return chip('alive', 'YES');
  if (h.supported === false) return chip('dead', 'NO');
  return chip('neutral', '—');
}

function authChip(r) {
  if (r.auth.ok === false) return chip('dead', 'AUTH FAIL');
  if (r.auth.required) return r.auth.ok === true ? chip('warn', 'AUTH OK') : chip('warn', 'AUTH REQ');
  if (r.hasAuth) return chip('info', 'CREDS');
  return chip('neutral', 'NO AUTH');
}

function anonChip(level) {
  if (level === 'elite') return chip('alive', 'ELITE');
  if (level === 'anonymous') return chip('info', 'ANON');
  if (level === 'transparent') return chip('warn', 'TRANSPARENT');
  return chip('neutral', 'UNKNOWN');
}

function shortTime(iso) {
  if (!iso) return '—';
  const d = new Date(iso);
  const p = (n) => String(n).padStart(2, '0');
  return `${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`;
}

export function createTable({ scroller, spacer, emptyEl, headerEl, state }) {
  let rows = [];
  let onOpen = null;

  function visibleHtml(first, last) {
    const parts = [];
    for (let i = first; i <= last && i < rows.length; i++) {
      const r = rows[i];
      const sel = state.selected.has(r.seq);
      const lat = r.latency.totalMs;
      const latCls = latencyClass(lat);
      parts.push(`
<div class="tbl-row${sel ? ' selected' : ''}" data-seq="${r.seq}" tabindex="0" role="row"
     aria-label="proxy ${esc(r.input)}, ${r.status}" style="top:${i * ROW_H}px">
  <div class="cell"><input type="checkbox" class="row-checkbox" data-seq="${r.seq}" ${sel ? 'checked' : ''} aria-label="Select ${esc(r.input)}"></div>
  <div class="cell mono" title="${esc(r.input)}">${esc(r.input)}</div>
  <div class="cell">${r.protocol ? chip(r.protocol.startsWith('socks') ? 'info' : 'acc', r.protocol.toUpperCase()) : chip('neutral', '—')}</div>
  <div class="cell mono">${esc(r.exitIp || '—')}</div>
  <div class="cell" title="${esc((r.geo && (r.geo.country || '').toString()) || '')}">${esc((r.geo && r.geo.country) || 'Unknown')}</div>
  <div class="cell">${esc((r.geo && r.geo.city) || '—')}</div>
  <div class="cell mono" title="${esc((r.geo && r.geo.asn) || '')}">${esc((r.geo && r.geo.asn) || '—')}</div>
  <div class="cell" title="${esc((r.geo && r.geo.isp) || '')}">${esc((r.geo && r.geo.isp) || '—')}</div>
  <div class="cell mono ${latCls}">${lat != null ? fmtMs(lat) : '—'}</div>
  <div class="cell">${httpsChip(r)}</div>
  <div class="cell">${anonChip(r.anonymity.level)}</div>
  <div class="cell">${authChip(r)}</div>
  <div class="cell mono">${r.httpStatus || '—'}</div>
  <div class="cell mono">${shortTime(r.checkedAt)}</div>
</div>`);
    }
    return parts.join('');
  }

  function renderWindow() {
    if (!rows.length) {
      spacer.style.height = '0px';
      emptyEl.style.display = '';
      return;
    }
    emptyEl.style.display = 'none';
    spacer.style.height = `${rows.length * ROW_H}px`;
    const top = scroller.scrollTop;
    const h = scroller.clientHeight || 560;
    const first = Math.max(0, Math.floor(top / ROW_H) - 4);
    const last = Math.min(rows.length, Math.ceil((top + h) / ROW_H) + 4);
    // reuse a single container for the window
    let win = spacer.querySelector('.tbl-window');
    if (!win) {
      win = document.createElement('div');
      win.className = 'tbl-window';
      win.style.position = 'absolute';
      win.style.inset = '0';
      spacer.appendChild(win);
    }
    win.innerHTML = visibleHtml(first, last);
  }

  scroller.addEventListener('scroll', () => {
    window.requestAnimationFrame(renderWindow);
  });
  window.addEventListener('resize', () => renderWindow());

  spacer.addEventListener('click', (e) => {
    const cb = e.target.closest('.row-checkbox');
    if (cb) {
      const seq = Number(cb.dataset.seq);
      if (cb.checked) state.selected.add(seq);
      else state.selected.delete(seq);
      const rowEl = spacer.querySelector(`.tbl-row[data-seq="${seq}"]`);
      if (rowEl) rowEl.classList.toggle('selected', cb.checked);
      e.stopPropagation();
      renderWindow();
      return;
    }
    const row = e.target.closest('.tbl-row');
    if (row && onOpen) onOpen(Number(row.dataset.seq));
  });

  spacer.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' || e.key === ' ') {
      const row = e.target.closest('.tbl-row');
      if (row) {
        e.preventDefault();
        if (onOpen) onOpen(Number(row.dataset.seq));
      }
    }
  });

  return {
    setRows(newRows) {
      rows = newRows;
      renderWindow();
    },
    refresh() { renderWindow(); },
    get rows() { return rows; },
    onOpenRow(fn) { onOpen = fn; },
  };
}

export function updateSortHeader(headerEl, sort) {
  headerEl.querySelectorAll('.h-cell[data-sort]').forEach((el) => {
    if (el.dataset.sort === sort.key) {
      el.setAttribute('aria-sort', sort.dir === 'asc' ? 'ascending' : 'descending');
      el.textContent = el.textContent.replace(/[▲▼]\s*$/, '').trim() + (sort.dir === 'asc' ? ' ▲' : ' ▼');
    } else {
      el.removeAttribute('aria-sort');
      el.textContent = el.textContent.replace(/[▲▼]\s*$/, '').trim();
    }
  });
}
