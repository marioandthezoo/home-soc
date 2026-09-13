/* sw.js — service worker for Home SOC Lens (SPEC B8/B10).

   It caches the static shell and nothing else. Authenticated responses — everything under
   /api/, and the two dashboard pages that sit inside this worker's scope — are passed straight
   through to the network and are never read from or written to the cache. That is not a
   convention here, it is the rule that keeps device data out of a phone's disk cache and keeps
   a stale token answer from ever being replayed.

   Served from the site root (/lens-sw.js) so its scope can be /lens; registered by lens.js. */
'use strict';

/* The version is substituted by the /lens-sw.js route from a fingerprint of the shell files
   themselves. A hard-coded constant meant an upgraded lens.js/lens.css was never invalidated:
   the navigation branch is network-first so the HTML was always fresh, but the static branch is
   cache-first, so the first open after an upgrade paired new markup with the previous script —
   exactly the combination that throws a runtime error on a phone nobody can debug. A changed
   asset now changes this string, which changes this file, which installs a new worker. */
var CACHE = 'homesoc-lens-shell-__SHELL_VERSION__';

/* The shell: markup with no device data in it, plus the assets that render it. */
var SHELL = [
  '/lens',
  '/static/lens.css',
  '/static/lens.js',
  '/static/manifest.webmanifest',
  '/static/lens-icon.svg',
  '/static/lens-icon-192.png',
  '/static/lens-icon-512.png',
  '/static/lens-icon-maskable-512.png'
];

/* Paths this worker is allowed to serve from the cache. Anything else in scope
   (/lens/pair, /lens/stickers, /api/lens/*) is network-only, always. */
function isShell(url) {
  return SHELL.indexOf(url.pathname) >= 0;
}

self.addEventListener('install', function (event) {
  event.waitUntil(
    caches.open(CACHE).then(function (cache) {
      /* One missing file must not fail the whole install, so they are added individually. */
      return Promise.all(SHELL.map(function (path) {
        return cache.add(new Request(path, { cache: 'reload' })).catch(function () { return null; });
      }));
    }).then(function () { return self.skipWaiting(); })
  );
});

self.addEventListener('activate', function (event) {
  event.waitUntil(
    caches.keys().then(function (keys) {
      return Promise.all(keys.map(function (key) {
        return key === CACHE ? null : caches.delete(key);
      }));
    }).then(function () { return self.clients.claim(); })
  );
});

self.addEventListener('fetch', function (event) {
  var request = event.request;
  if (request.method !== 'GET') { return; }

  var url;
  try { url = new URL(request.url); } catch (e) { return; }
  if (url.origin !== self.location.origin) { return; }
  if (url.pathname.indexOf('/api/') === 0) { return; }        /* never touch the API */
  if (request.headers.get('X-Lens-Token')) { return; }        /* belt and braces */
  if (!isShell(url)) { return; }                              /* pair/stickers stay network-only */

  if (request.mode === 'navigate') {
    /* The page itself: fresh when the network is there, cached when it is not. */
    event.respondWith(
      fetch(request).then(function (response) {
        if (response && response.ok && response.type === 'basic') {
          var copy = response.clone();
          caches.open(CACHE).then(function (cache) { cache.put('/lens', copy); });
        }
        return response;
      }).catch(function () {
        return caches.match('/lens').then(function (hit) {
          return hit || Response.error();
        });
      })
    );
    return;
  }

  /* Static assets: cache first (instant open), refreshed in the background. */
  event.respondWith(
    caches.match(request).then(function (hit) {
      var network = fetch(request).then(function (response) {
        if (response && response.ok && response.type === 'basic') {
          var copy = response.clone();
          caches.open(CACHE).then(function (cache) { cache.put(request, copy); });
        }
        return response;
      }).catch(function () { return hit || Response.error(); });
      return hit || network;
    })
  );
});
