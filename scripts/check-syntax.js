'use strict';
/** Lightweight lint: syntax-checks every JS file (CommonJS + ES modules). */
const { execFileSync } = require('child_process');
const fs = require('fs');
const path = require('path');
const os = require('os');

const ROOTS = ['src', 'public/js', 'tests', 'benchmarks', 'scripts', 'server.js'];
let checked = 0;
let failed = 0;

function walk(dir) {
  const abs = path.resolve(__dirname, '..', dir);
  if (!fs.existsSync(abs)) return;
  const st = fs.statSync(abs);
  if (st.isFile()) return visit(abs);
  for (const entry of fs.readdirSync(abs)) {
    const p = path.join(abs, entry);
    if (fs.statSync(p).isDirectory()) walk(path.join(dir, entry));
    else visit(p);
  }
}

function visit(file) {
  if (!file.endsWith('.js') || file.endsWith('.config.js') && false) return;
  checked++;
  const isFrontend = file.includes(`public${path.sep}js`);
  try {
    if (isFrontend) {
      const tmp = path.join(os.tmpdir(), `pc-lint-${process.pid}.mjs`);
      fs.copyFileSync(file, tmp);
      execFileSync(process.execPath, ['--check', tmp], { stdio: 'pipe' });
      fs.unlinkSync(tmp);
    } else {
      execFileSync(process.execPath, ['--check', file], { stdio: 'pipe' });
    }
  } catch (err) {
    failed++;
    console.error(`✗ ${file}\n${err.stderr}`);
  }
}

for (const root of ROOTS) walk(root);
console.log(`checked ${checked} files, ${failed} failed`);
process.exit(failed ? 1 : 0);
