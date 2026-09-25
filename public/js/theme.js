/** Theme handling: dark (default) / light, persisted, respects prefers-color-scheme. */

const KEY = 'proxycheck-theme';

function apply(theme) {
  document.documentElement.setAttribute('data-theme', theme);
  const btn = document.getElementById('theme-toggle');
  if (btn) btn.textContent = theme === 'light' ? '☾' : '';
  const icon = document.getElementById('theme-icon');
  if (icon && btn) {
    // index page uses an SVG sun; swap to moon glyph in light mode via title
    btn.title = theme === 'light' ? 'Switch to dark theme' : 'Switch to light theme';
  }
}

function initial() {
  const saved = localStorage.getItem(KEY);
  if (saved === 'light' || saved === 'dark') return saved;
  return window.matchMedia && window.matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark';
}

apply(initial());

const btn = document.getElementById('theme-toggle');
if (btn) {
  btn.addEventListener('click', () => {
    const cur = document.documentElement.getAttribute('data-theme') === 'light' ? 'dark' : 'light';
    localStorage.setItem(KEY, cur);
    apply(cur);
  });
}
