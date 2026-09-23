/* theme.js — the Auto / Day / Dusk choice. Loaded WITHOUT defer from <head>, before the
   stylesheet, so data-theme is on <html> before the first paint and a Dusk screen never flashes
   Day on load. No inline script anywhere (CSP default-src 'self').

   Auto  = no data-theme attribute: style.css follows the computer's light/dark setting.
   Day   = data-theme="day"  (forces the stone & sage day theme even under a dark OS).
   Dusk  = data-theme="dusk" (forces the cocoa dusk theme even under a light OS).
   The choice is a per-browser convenience kept in localStorage; when storage is unavailable
   (private window, blocked site data) the page simply follows the OS. charts.js watches the
   attribute and redraws its SVGs, so the charts change with the page. */
(function () {
  'use strict';

  var KEY = 'homesoc.theme';
  var MODES = ['auto', 'day', 'dusk'];
  var LABEL = { auto: 'Auto', day: 'Day', dusk: 'Dusk' };
  var HINT = {
    auto: 'Colour theme: Auto, following this computer\'s light or dark setting. Click for Day.',
    day: 'Colour theme: Day (light), whatever this computer is set to. Click for Dusk.',
    dusk: 'Colour theme: Dusk (dark), whatever this computer is set to. Click for Auto.'
  };
  /* Browser-chrome tint, matching --bg in each theme (tokens.json "theme-color"). */
  var CHROME = { day: '#e5e0d5', dusk: '#3a332d' };
  var root = document.documentElement;

  function read() {
    try {
      var v = window.localStorage.getItem(KEY);
      return v === 'day' || v === 'dusk' ? v : 'auto';
    } catch (e) {
      return 'auto';
    }
  }

  function save(mode) {
    try {
      if (mode === 'auto') window.localStorage.removeItem(KEY);
      else window.localStorage.setItem(KEY, mode);
    } catch (e) { /* storage blocked: the choice lasts for this page only */ }
  }

  function tintChrome(mode) {
    var metas = document.querySelectorAll('meta[name="theme-color"]');
    for (var i = 0; i < metas.length; i++) {
      var m = metas[i];
      if (!m.dataset.auto) m.dataset.auto = m.getAttribute('content') || '';
      m.setAttribute('content', mode === 'auto' ? m.dataset.auto : CHROME[mode]);
    }
  }

  function apply(mode) {
    if (mode === 'day' || mode === 'dusk') root.setAttribute('data-theme', mode);
    else root.removeAttribute('data-theme');
    tintChrome(mode);
  }

  function paint(button, mode) {
    if (!button) return;
    var slot = button.querySelector('.theme-mode');
    if (slot) slot.textContent = LABEL[mode];
    else button.textContent = 'Theme: ' + LABEL[mode];
    button.title = HINT[mode];
    button.setAttribute('aria-label', HINT[mode]);
    button.dataset.mode = mode;
  }

  apply(read());

  function wire() {
    var button = document.getElementById('theme-toggle');
    if (!button) return;
    paint(button, read());
    button.addEventListener('click', function () {
      var current = button.dataset.mode || read();
      var next = MODES[(MODES.indexOf(current) + 1) % MODES.length];
      save(next);
      apply(next);
      paint(button, next);
    });
    /* Another tab changed the theme: follow it, so a wall screen and a laptop agree. */
    window.addEventListener('storage', function (ev) {
      if (ev.key !== KEY && ev.key !== null) return;
      var mode = read();
      apply(mode);
      paint(button, mode);
    });
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', wire);
  else wire();

  window.HomeSOCTheme = { read: read, apply: apply, modes: MODES.slice() };
})();
