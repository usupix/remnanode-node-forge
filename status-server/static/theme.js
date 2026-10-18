(() => {
  'use strict';
  const root = document.documentElement;
  const preference = window.matchMedia('(prefers-color-scheme: dark)');
  let saved = null;
  try { saved = localStorage.getItem('meltun-status-theme'); } catch (_) {}
  let manual = saved === 'dark' || saved === 'light';
  function apply(theme) {
    root.dataset.theme = theme;
    const meta = document.querySelector('meta[name="theme-color"]');
    if (meta) meta.content = theme === 'dark' ? '#111a25' : '#f7f9fc';
    const button = document.getElementById('theme-toggle');
    if (button) {
      button.setAttribute('aria-pressed', String(theme === 'dark'));
      button.title = theme === 'dark' ? 'Включить светлую тему' : 'Включить тёмную тему';
    }
  }
  apply(manual ? saved : preference.matches ? 'dark' : 'light');
  preference.addEventListener('change', () => { if (!manual) apply(preference.matches ? 'dark' : 'light'); });
  document.addEventListener('DOMContentLoaded', () => {
    apply(root.dataset.theme);
    document.getElementById('theme-toggle').addEventListener('click', () => {
      const theme = root.dataset.theme === 'dark' ? 'light' : 'dark';
      manual = true;
      try { localStorage.setItem('meltun-status-theme', theme); } catch (_) {}
      apply(theme);
    });
  });
})();
