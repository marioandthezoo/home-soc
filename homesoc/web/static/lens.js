/* lens.js — Home SOC Lens (SPEC addendum B8): viewfinder, identification, overlay card.

   Rules this file lives by:
   - CSP is default-src 'self': no inline handlers, no eval, no remote code. Every listener is
     attached here.
   - Nothing from the database is ever parsed as markup. Every node is built with
     document.createElement and filled with textContent, so a device nicknamed
     `<img src=x onerror=alert(1)>` is text, in every section, always.
   - The pairing token lives in localStorage and travels in the X-Lens-Token header. It is never
     put in a URL, so it cannot leak through history, referrers or the server's access log.
   - Decoding runs at ~5 fps from a downscaled canvas, not once per animation frame: a phone held
     up to a cupboard for two minutes should not get hot. */
(function () {
  'use strict';

  var BODY = document.body;
  var PAGE = BODY.dataset.page || '';
  var TOKEN_KEY = 'homesoc.lens.token';
  var CARD_KEY = 'homesoc.lens.card';
  var IGNORE_KEY = 'homesoc.lens.ignored';
  var DECODE_MS = 200;          /* ~5 fps */
  var GRAB_WIDTH = 480;         /* downscaled frame the detector sees */
  var REPEAT_MS = 3500;         /* ignore the same code again for this long */
  var SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'];

  /* The dashboard's plain words (DESIGN.md 8.2). They sit BESIDE the technical label, never in
     place of it: "Critical" stays on the badge and "Fix now" goes next to it. */
  var SEV_LABEL = { critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low', info: 'Info' };
  var SEV_WORD = {
    critical: 'Fix now', high: 'Fix this week', medium: 'Worth fixing',
    low: 'When you have time', info: 'Good to know'
  };
  var STATUS_WORD = {
    open: 'Needs attention', acknowledged: 'Seen, not fixed yet',
    resolved: 'Fixed', suppressed: 'Ignored (your choice)'
  };
  /* What an unnamed device is called: "Unnamed camera", never its address twice. Mirrors the
     server's KIND_NOUN (homesoc/web/lens.py). */
  var KIND_NOUN = {
    router: 'router', gateway: 'router', ap: 'access point', camera: 'camera', printer: 'printer',
    nas: 'NAS', storage: 'storage box', tv: 'TV', media: 'media player', phone: 'phone', mobile: 'phone',
    tablet: 'tablet', laptop: 'laptop', computer: 'computer', desktop: 'PC', pc: 'PC', server: 'server',
    speaker: 'speaker', audio: 'speaker', thermostat: 'thermostat', plug: 'smart plug', bulb: 'smart bulb',
    light: 'smart light', console: 'games console', iot: 'gadget'
  };

  /* Plain-English gloss for the ports people actually find at home. The API may supply its own
     (`gloss`), which always wins; this table is the floor, so a port is never bare digits. */
  var PORT_GLOSS = {
    21: 'FTP — file transfer with no encryption',
    22: 'SSH — encrypted remote shell',
    23: 'Telnet — remote control with no encryption',
    25: 'SMTP — mail delivery',
    53: 'DNS — name lookups',
    80: 'HTTP — a web page served without encryption',
    110: 'POP3 — mail pickup, usually unencrypted',
    111: 'RPC — legacy Unix service directory',
    135: 'RPC — Windows service directory',
    139: 'NetBIOS — legacy Windows file sharing',
    143: 'IMAP — mail access',
    161: 'SNMP — device management, often left on default passwords',
    443: 'HTTPS — an encrypted web page',
    445: 'SMB — Windows file sharing',
    515: 'LPD — legacy printing',
    554: 'RTSP — a live video stream',
    631: 'IPP — printing',
    993: 'IMAPS — encrypted mail access',
    1080: 'SOCKS — a proxy',
    1883: 'MQTT — smart-home messaging',
    3306: 'MySQL — a database',
    3389: 'RDP — Windows remote desktop',
    5000: 'HTTP — a web admin page',
    5353: 'mDNS — local name discovery',
    5900: 'VNC — remote desktop, often with no password',
    8080: 'HTTP — a web admin page served without encryption',
    8443: 'HTTPS — an encrypted web admin page',
    9100: 'JetDirect — raw printing with no authentication',
    62078: 'iOS device sync'
  };

  var KIND_ICON = {
    router: '⇄', gateway: '⇄', printer: '⎙', camera: '◉', phone: '▯', mobile: '▯',
    tablet: '▭', laptop: '▤', computer: '▤', desktop: '▤', tv: '▢', media: '▢',
    speaker: '♪', audio: '♪', nas: '▥', storage: '▥', console: '⎚', iot: '✦',
    thermostat: '✦', plug: '✦', light: '✦', server: '▦', ap: '⇄', unknown: '▣'
  };

  /* ------------------------------------------------------------------ tiny DOM kit */

  function el(tag, props) {
    var node = document.createElement(tag);
    props = props || {};
    if (props.className) { node.className = props.className; }
    if (props.text !== undefined && props.text !== null) { node.textContent = String(props.text); }
    if (props.attrs) {
      Object.keys(props.attrs).forEach(function (k) { node.setAttribute(k, String(props.attrs[k])); });
    }
    for (var i = 2; i < arguments.length; i++) {
      var child = arguments[i];
      if (child === null || child === undefined || child === false) { continue; }
      if (Array.isArray(child)) {
        child.forEach(function (c) { if (c) { node.appendChild(typeof c === 'string' ? document.createTextNode(c) : c); } });
      } else {
        node.appendChild(typeof child === 'string' ? document.createTextNode(child) : child);
      }
    }
    return node;
  }
  function $(id) { return document.getElementById(id); }
  function clear(node) { while (node && node.firstChild) { node.removeChild(node.firstChild); } }
  function show(node, on) { if (node) { node.hidden = !on; } }
  function text(node, value) { if (node) { node.textContent = value === null || value === undefined ? '' : String(value); } }
  function num(value) {
    var n = Number(value);
    return isFinite(n) ? n.toLocaleString() : '0';
  }
  function ago(iso) {
    if (!iso) { return 'never'; }
    var d = new Date(iso);
    if (isNaN(d.getTime())) { return String(iso); }
    var s = Math.round((Date.now() - d.getTime()) / 1000);
    var back = s >= 0;
    s = Math.abs(s);
    if (s < 60) { return back ? 'just now' : 'in under a minute'; }
    var n = s >= 86400 ? Math.floor(s / 86400) : s >= 3600 ? Math.floor(s / 3600) : Math.floor(s / 60);
    var unit = s >= 86400 ? 'day' : s >= 3600 ? 'hour' : 'min';
    var out = n + ' ' + (unit === 'min' || n === 1 ? unit : unit + 's');
    return back ? out + ' ago' : 'in ' + out;
  }
  function severity(value) {
    var s = String(value || 'info').toLowerCase();
    return SEVERITIES.indexOf(s) >= 0 ? s : 'info';
  }
  function sevRank(value) { return SEVERITIES.indexOf(severity(value)); }
  function badge(kind, label) {
    return el('span', { className: 'badge badge-' + String(kind || 'info').toLowerCase(), text: label === undefined ? kind : label });
  }
  /* The severity badge (technical label, solid fill) and its plain action word beside it. */
  function sevBadge(value, done) {
    var sev = severity(value);
    /* A finding that is already fixed (or ignored) keeps its severity label but loses the
       "Fix now" urge: telling someone to fix a thing they fixed is the kind of noise that
       teaches them to stop reading. */
    if (done) { return [badge(sev, SEV_LABEL[sev])]; }
    return [badge(sev, SEV_LABEL[sev]), el('span', { className: 'sev-word sev-word-' + sev, text: SEV_WORD[sev] })];
  }
  function isDone(status) {
    var st = String(status || '').toLowerCase();
    return st === 'resolved' || st === 'suppressed';
  }
  /* A finding's status as the dashboard's quiet pill, in words; the raw status stays in the
     row's technical details. */
  function statusBadge(value) {
    var st = String(value || '').toLowerCase();
    if (!STATUS_WORD[st]) { return null; }
    return el('span', { className: 'badge badge-status badge-' + st, text: STATUS_WORD[st] });
  }
  function looksLikeAddress(value) {
    var v = String(value || '');
    return /^\d{1,3}(\.\d{1,3}){3}$/.test(v) || /^[0-9a-f]{2}([:-][0-9a-f]{2}){5}$/i.test(v) || /^device \d+$/.test(v);
  }
  /* Devices are named, not numbered (DESIGN.md 8.1 #4): the server's device_label when it sends
     one, then the owner's nickname, then the hostname; an unnamed device reads "Unnamed camera"
     and its IP is shown second, muted, by the caller. */
  function deviceName(d) {
    d = d || {};
    var ids = [d.ip, d.mac].filter(Boolean).map(String);
    var picks = [d.device_label, d.nickname, d.display_name, d.hostname, d.name];
    for (var i = 0; i < picks.length; i++) {
      var v = picks[i];
      /* A label that embeds the address ("Unnamed camera (192.168.1.142)") is skipped too: the
         IP is printed on its own line, and the offline snapshot must never keep it. */
      var carriesId = ids.some(function (id) { return String(v).indexOf(id) >= 0; });
      if (v && !carriesId && !looksLikeAddress(v)) { return String(v); }
    }
    return 'Unnamed ' + (KIND_NOUN[String(d.kind || '').toLowerCase()] || 'device');
  }
  function kindIcon(kind) {
    var key = String(kind || '').toLowerCase();
    return KIND_ICON[key] || KIND_ICON.unknown;
  }
  function store(key, value) {
    try {
      if (value === null) { localStorage.removeItem(key); } else { localStorage.setItem(key, value); }
    } catch (e) { /* private mode / quota: Lens still works, it just forgets */ }
  }
  function load(key) {
    try { return localStorage.getItem(key); } catch (e) { return null; }
  }

  /* ------------------------------------------------------------------ transport */

  function token() { return load(TOKEN_KEY) || ''; }

  /* ----------------------------------------------------------- the offline card at rest

     B8 wants the last card back when Home SOC is unreachable, and the only place a phone can
     keep it is localStorage — on the phone's disk, readable by whoever holds the phone. The
     service worker already refuses to cache an authenticated response for exactly that reason,
     so what is kept here is held to the same standard:

     - a trimmed snapshot, not the payload: the name the owner sees, the flags, the headline, the
       severity counts and the open ports. No MAC, no vendor, no CVE list, no DNS history, no
       dependency map, no timeline;
     - it expires: a snapshot older than CARD_TTL_MS is deleted on read, not shown;
     - it belongs to a pairing: no token, no card. Revocation (the 401 path) and a phone that was
       never paired both wipe it, so a revoked phone in airplane mode shows the pairing notice,
       not the last device it looked at.

     A card written by an older lens.js (the full payload, no version) fails the version check
     and is deleted the first time it is read. */
  var CARD_VERSION = 2;
  var CARD_TTL_MS = 24 * 60 * 60 * 1000;
  var CARD_MAX_SERVICES = 40;

  function cardSnapshot(payload, now) {
    if (!payload || !payload.device) { return null; }
    var d = payload.device;
    var posture = payload.posture || {};
    var counts = posture.severity_counts || {};
    var keptCounts = {};
    SEVERITIES.forEach(function (sev) { if (Number(counts[sev])) { keptCounts[sev] = Number(counts[sev]); } });
    var services = (payload.services || []).filter(function (s) {
      return s && (!s.state || String(s.state) === 'open');
    }).slice(0, CARD_MAX_SERVICES).map(function (s) {
      return {
        port: Number(s.port) || 0,
        proto: s.proto ? String(s.proto) : 'tcp',
        label: s.label ? String(s.label) : (s.name ? String(s.name) : ''),
        gloss: s.gloss ? String(s.gloss) : '',
        risk: s.risk ? String(s.risk) : ''
      };
    });
    return {
      v: CARD_VERSION,
      saved_at: Number(now) || 0,
      device: {
        id: d.id,
        /* The one name the card was headed with, in place of the identifiers behind it. */
        name: deviceName(d),
        kind: d.kind ? String(d.kind) : '',
        online: Boolean(d.online),
        trusted: Boolean(d.trusted),
        last_seen: d.last_seen || ''
      },
      posture: {
        headline: posture.headline ? String(posture.headline) : '',
        severity_counts: keptCounts,
        score_contribution: Number(posture.score_contribution) || 0
      },
      services: services
    };
  }

  function saveCard(payload, now) {
    if (!token()) { store(CARD_KEY, null); return; }
    var snap = cardSnapshot(payload, now);
    store(CARD_KEY, snap ? JSON.stringify(snap) : null);
  }

  function readCachedCard(now) {
    var raw = load(CARD_KEY);
    if (!raw) { return null; }
    if (!token()) { store(CARD_KEY, null); return null; }
    var parsed = null;
    try { parsed = JSON.parse(raw); } catch (e) { parsed = null; }
    var saved = parsed ? Number(parsed.saved_at) : 0;
    var age = Number(now) - saved;
    /* A clock set backwards more than a minute is treated as expired rather than as "fresh
       forever". */
    if (!parsed || parsed.v !== CARD_VERSION || !parsed.device || !saved || !(age >= -60000 && age <= CARD_TTL_MS)) {
      store(CARD_KEY, null);
      return null;
    }
    return parsed;
  }

  /* Everything this phone kept because it was paired goes when the pairing does. */
  function forgetPairing() {
    store(TOKEN_KEY, null);
    store(CARD_KEY, null);
    store(IGNORE_KEY, null);
  }

  function request(path, options) {
    options = options || {};
    var headers = { 'Accept': 'application/json', 'X-Requested-With': 'fetch' };
    var tok = token();
    if (tok) { headers['X-Lens-Token'] = tok; }
    if (options.body !== undefined) { headers['Content-Type'] = 'application/json'; }
    return fetch(path, {
      method: options.method || (options.body !== undefined ? 'POST' : 'GET'),
      headers: headers,
      cache: 'no-store',
      credentials: 'same-origin',
      body: options.body === undefined ? undefined : JSON.stringify(options.body)
    }).then(function (resp) {
      return resp.json().catch(function () { return {}; }).then(function (data) {
        if (resp.ok) { return data; }
        var err = new Error(String(data.error || ('HTTP ' + resp.status)));
        err.status = resp.status;
        err.data = data;
        throw err;
      });
    });
  }

  /* ================================================================== the phone app */

  function lensApp() {
    var cam = $('cam');
    var grab = $('grab');
    var reticle = $('reticle');
    var hint = $('reticle-hint');
    var stateChip = $('scan-state');
    var notice = $('notice');
    var card = $('card');
    var cardBody = $('card-body');
    var picker = $('picker');
    var pickerList = $('picker-list');
    var pickerSearch = $('picker-search');
    var unknown = $('unknown');
    var unknownList = $('unknown-list');
    var fallback = $('fallback');
    var fallbackBody = $('fallback-body');
    var undoButton = $('undo-ignore');

    var detector = null;
    var stream = null;
    var timer = null;
    var scanning = false;
    var lastCode = '';
    var lastCodeAt = 0;
    /* Device id behind a card that came from the cache, so coming back online can refresh it. */
    var staleDeviceId = null;
    /* Last observed reachability of Home SOC itself, which navigator.onLine does not report. */
    var reachable = true;
    var pendingCode = '';
    /* Codes the user closed the "new code" sheet on. In memory only and short-lived, unlike the
       persistent IGNORE_KEY list: closing a sheet means "not now", never "never again". */
    var snoozed = {};
    var SNOOZE_MS = 60000;
    /* The control that opened a sheet, so focus can go back where it came from on close. */
    var returnFocus = null;
    var devices = [];
    var devicesAt = 0;
    var pickerMode = 'browse';

    /* ---------------------------------------------------------- status + notices */

    function state(message, kind) {
      text(stateChip, message);
      stateChip.className = 'state' + (kind ? ' is-' + kind : '');
    }

    /* ``why`` names the notice so a later event can retract only its own. The camera starting
       must not silently clear an "unreachable" notice the boot probe put up while it was
       still negotiating with the hardware. */
    function showNotice(title, body, steps, action, why) {
      notice.dataset.why = why || '';
      text($('notice-title'), title);
      text($('notice-body'), body);
      var list = $('notice-steps');
      clear(list);
      (steps || []).forEach(function (step) { list.appendChild(el('li', { text: step })); });
      show(list, (steps || []).length > 0);
      var button = $('notice-action');
      if (action) {
        text(button, action.label);
        button.dataset.action = action.name;
        show(button, true);
      } else {
        show(button, false);
      }
      notice.classList.toggle('is-bad', Boolean(action && action.bad));
      show(notice, true);
    }
    function hideNotice() { notice.dataset.why = ''; show(notice, false); }
    function hideNoticeIf(why) { if ((notice.dataset.why || '') === why) { hideNotice(); } }

    $('notice-action').addEventListener('click', function () {
      var what = this.dataset.action || '';
      hideNotice();
      if (what === 'camera') { startCamera(); }
      if (what === 'pick') { openPicker('pick'); }
      if (what === 'reload') { location.reload(); }
    });

    /* ---------------------------------------------------------- camera */

    /* Why the viewfinder is not doing anything, if it is not. Set once and kept: the #notice is
       dismissible (its own button sends the user to the picker), so it cannot be the only thing
       carrying the explanation, or closing the picker leaves a black rectangle with a 13px chip
       in the corner and no way back. B8: never leave the user staring at a camera that silently
       does nothing. */
    var degraded = null;   /* null | 'camera' | 'nobarcode' */

    function noVideo(on) {
      BODY.classList.toggle('no-video', Boolean(on));
      show(reticle, !on);
      show(hint, !on);
      /* The <video> is fixed, inset:0 and painted black, so leaving it up covers the calm
         no-video gradient the stylesheet defines and the user gets a void instead. */
      show(cam, !on);
    }

    /* A permanent, non-dismissible panel in the middle of the viewfinder. Unlike #notice it is
       never cleared by hideNotice(), and it always carries a way back to the camera. */
    function setDegraded(why, title, body, steps) {
      degraded = why || null;
      clear(fallbackBody);
      if (!why) { show(fallback, false); return; }
      fallbackBody.appendChild(el('h2', { className: 'fallback-title', text: title }));
      fallbackBody.appendChild(el('p', { className: 'fallback-body', text: body }));
      if (steps && steps.length) {
        var how = el('ol', { className: 'steps' });
        steps.forEach(function (step) { how.appendChild(el('li', { text: step })); });
        fallbackBody.appendChild(how);
      }
      var row = el('div', { className: 'fallback-row' });
      var pick = el('button', { className: 'btn btn-primary', text: 'Pick a device', attrs: { type: 'button' } });
      pick.addEventListener('click', function () { openPicker('pick'); });
      row.appendChild(pick);
      var retry = el('button', { className: 'btn', text: 'Try the camera again', attrs: { type: 'button' } });
      retry.addEventListener('click', function () { setDegraded(null); hideNoticeIf('camera'); hideNoticeIf('nobarcode'); startCamera(); });
      row.appendChild(retry);
      fallbackBody.appendChild(row);
      show(fallback, true);
    }

    /* Re-assert whatever the viewfinder's real state is. Every "back to the scan tab" path goes
       through here, so closing a sheet can never reveal a viewfinder with no explanation on it. */
    function reconcile() {
      show(fallback, Boolean(degraded) && card.hidden && picker.hidden && unknown.hidden);
      scanState();
    }

    function startCamera() {
      if (!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) {
        noVideo(true);
        state('camera unavailable', 'bad');
        setDegraded('camera', 'No camera here',
          'This page is not a secure origin, so the browser will not hand out the camera. Everything else in Lens works — pick the device from the list.');
        showNotice(
          'This page is not a secure context',
          'Chrome only hands out the camera over HTTPS. Everything else in Lens still works — pick the device from the list.',
          ['Open Home SOC on your computer.', 'Go to Lens → Pair a phone.', 'Start Home SOC with --tls and use the https address it prints.'],
          { label: 'Pick a device', name: 'pick' },
          'camera'
        );
        return;
      }
      state('starting camera…', 'busy');
      navigator.mediaDevices.getUserMedia({
        video: { facingMode: { ideal: 'environment' }, width: { ideal: 1280 }, height: { ideal: 720 } },
        audio: false
      }).then(function (media) {
        stream = media;
        cam.srcObject = media;
        noVideo(false);
        setDegraded(null);
        hideNoticeIf('camera');   /* clear only a previous camera complaint; leave the rest up */
        var play = cam.play();
        if (play && play.catch) { play.catch(function () { /* autoplay is muted+playsinline, so this is rare */ }); }
        startScanner();
      }).catch(function (err) {
        noVideo(true);
        var name = (err && err.name) || '';
        state('camera off', 'bad');
        if (name === 'NotAllowedError' || name === 'SecurityError') {
          /* Said once, in the permanent panel, which carries the steps and both ways forward.
             A dismissible notice repeating the same sentence above it was the message twice. */
          hideNoticeIf('camera');
          setDegraded('camera', 'Camera permission was declined',
            'Lens needs the rear camera to read barcodes and stickers. You can allow it and try again, or pick the device from the list.',
            ['Tap the padlock (or ⓘ) next to the address.', 'Set Camera to Allow.', 'Tap “Try the camera again”.']);
          return;
        }
        setDegraded('camera', 'The camera is not running',
          name === 'NotFoundError' || name === 'OverconstrainedError' || name === 'DevicesNotFoundError'
            ? 'This device has no camera Lens can use. The device list below is the same information, one tap away.'
            : 'The camera could not be started' + (name ? ' (' + name + ')' : '') + '. Another app may be holding it.');
        if (name === 'NotFoundError' || name === 'OverconstrainedError' || name === 'DevicesNotFoundError') {
          showNotice(
            'No camera on this device',
            'Lens works without one: the device list below is the same information, one tap away.',
            [],
            { label: 'Open the device list', name: 'pick' },
            'camera'
          );
        } else {
          showNotice(
            'The camera could not be started',
            'Another app may be holding it. ' + (name ? '(' + name + ')' : ''),
            [],
            { label: 'Try again', name: 'camera' },
            'camera'
          );
        }
      });
    }

    function startScanner() {
      if (!('BarcodeDetector' in window)) {
        /* Documented fallback (B8): never a camera that silently does nothing. The panel is
           permanent, so closing the picker does not leave a live camera feed with no reticle,
           no hint and no explanation on it. */
        show(reticle, false);
        show(hint, false);
        state('scanning unsupported', 'bad');
        /* The persistent panel is the whole explanation: it carries both actions and reconcile()
           re-asserts it whenever a sheet closes. Raising a notice as well would put the same
           sentence on screen twice, so it does not. */
        setDegraded('nobarcode', 'This browser cannot scan codes',
          'Automatic scanning needs the BarcodeDetector API, which Chrome on Android provides. The camera still shows what you are pointing at; the picker identifies any device in one tap.');
        $('btn-pick').classList.add('dock-primary');
        return;
      }
      var wanted = ['qr_code', 'code_128', 'code_39', 'code_93', 'codabar', 'data_matrix', 'ean_13', 'ean_8', 'itf', 'pdf417', 'upc_a', 'upc_e', 'aztec'];
      Promise.resolve(window.BarcodeDetector.getSupportedFormats ? window.BarcodeDetector.getSupportedFormats() : wanted)
        .then(function (supported) {
          var formats = wanted.filter(function (f) { return supported.indexOf(f) >= 0; });
          detector = formats.length ? new window.BarcodeDetector({ formats: formats }) : new window.BarcodeDetector();
          if (degraded === 'nobarcode') { setDegraded(null); }
          scanning = true;
          /* The camera finishes starting after the rest of the boot has run, so it must not
             shout over a card (or a notice) that is already on screen. Scanning still works
             offline — the decode is local — but the lookup afterwards will not, so say so
             rather than reporting a healthy "looking for a code…". */
          if (card.hidden && picker.hidden && unknown.hidden) { scanState(); }
          loop();
        })
        .catch(function () {
          detector = null;
          state('scanning unavailable', 'bad');
          setDegraded('nobarcode', 'Scanning could not start',
            'This browser would not start the barcode reader. The picker identifies any device in one tap.');
        });
    }

    function loop() {
      if (timer) { clearTimeout(timer); }
      timer = setTimeout(function () {
        decodeOnce().then(loop, loop);
      }, DECODE_MS);
    }

    function decodeOnce() {
      if (!detector || !scanning || document.hidden || !card.hidden || !picker.hidden || !unknown.hidden) {
        return Promise.resolve();
      }
      if (!cam.videoWidth || cam.readyState < 2) { return Promise.resolve(); }
      var scale = GRAB_WIDTH / cam.videoWidth;
      grab.width = GRAB_WIDTH;
      grab.height = Math.max(1, Math.round(cam.videoHeight * scale));
      var ctx = grab.getContext('2d', { willReadFrequently: true });
      ctx.drawImage(cam, 0, 0, grab.width, grab.height);
      return detector.detect(grab).then(function (hits) {
        if (!hits || !hits.length) { return; }
        var value = String(hits[0].rawValue || '').trim();
        if (value) { onCode(value); }
      }).catch(function () { /* a dropped frame is not an error worth showing */ });
    }

    function stopScanning() { scanning = false; if (timer) { clearTimeout(timer); timer = null; } }
    function resumeScanning() { if (detector) { scanning = true; loop(); } }

    /* ---------------------------------------------------------- identification */

    function ignored() {
      try { return JSON.parse(load(IGNORE_KEY) || '[]') || []; } catch (e) { return []; }
    }
    function ignore(code) {
      var list = ignored();
      if (list.indexOf(code) < 0) { list.push(code); }
      store(IGNORE_KEY, JSON.stringify(list.slice(-200)));
    }

    /* An ignored code is recoverable: show the undo next to the status chip until it is used
       or something else happens. */
    function offerUndo(code) {
      undoButton.dataset.code = code || '';
      show(undoButton, Boolean(code));
    }

    function unignore(code) {
      var list = ignored().filter(function (c) { return c !== code; });
      store(IGNORE_KEY, JSON.stringify(list));
      /* Undo it on the server too, so other paired phones stop skipping it as well. A read-only
         phone gets a 403 here, which is fine: the local list is what silenced it on this one. */
      request('/api/lens/tag/' + encodeURIComponent(code), { method: 'DELETE' }).catch(function () { });
      lastCode = '';
      lastCodeAt = 0;
      offerUndo('');
      state('code un-ignored');
      resumeScanning();
    }

    function onCode(code) {
      var now = Date.now();
      if (code === lastCode && now - lastCodeAt < REPEAT_MS) { return; }
      if (snoozed[code] && now - snoozed[code] < SNOOZE_MS) { return; }
      if (ignored().indexOf(code) >= 0) {
        /* Dropping it in silence made a mis-tap on "Not a device" permanent and invisible: the
           sticker was simply dead on this phone, with no way back short of clearing site data.
           Say so, and make the status chip the undo. */
        if (card.hidden && picker.hidden && unknown.hidden && notice.hidden) {
          state('code ignored', 'bad');
          offerUndo(code);
        }
        return;
      }
      offerUndo('');
      lastCode = code;
      lastCodeAt = now;
      reticle.classList.add('is-hit');
      setTimeout(function () { reticle.classList.remove('is-hit'); }, 600);
      if (navigator.vibrate) { try { navigator.vibrate(35); } catch (e) { /* ignore */ } }
      state('identifying…', 'busy');
      stopScanning();
      request('/api/lens/identify', { body: { code: code } })
        .then(function (match) { onMatch(code, match); })
        .catch(function (err) { onError(err, 'identify'); });
    }

    function payloadOf(match) {
      if (!match || typeof match !== 'object') { return null; }
      var candidates = [match.lens_device, match.payload, match.device_payload, match.data, match.device, match];
      for (var i = 0; i < candidates.length; i++) {
        var p = candidates[i];
        if (p && typeof p === 'object' && p.device && typeof p.device === 'object' && p.device.id) { return p; }
      }
      return null;
    }

    function onMatch(code, match) {
      var payload = payloadOf(match);
      var confidence = String((match && match.confidence) || 'unknown');
      if (payload) { renderCard(payload); return; }
      if (confidence === 'exact' && match.device_id) { openDevice(match.device_id); return; }
      openUnknown(code, (match && match.candidates) || []);
    }

    function openDevice(deviceId) {
      state('loading…', 'busy');
      stopScanning();
      return request('/api/lens/device/' + encodeURIComponent(deviceId) + '?hours=24')
        .then(function (payload) { renderCard(payload); })
        .catch(function (err) { onError(err, 'device'); });
    }

    function onError(err, where) {
      if (err && err.status === 401) {
        forgetPairing();
        state('not paired', 'bad');
        showNotice(
          'This phone is no longer paired',
          'Its access was withdrawn from the Home SOC computer, or it expired, so Lens cannot show anything until it is paired again.',
          ['Open Home SOC on your computer.', 'Go to Lens → Pair a phone.', 'Scan the QR code it shows with this phone.'],
          { label: 'Reload', name: 'reload', bad: true },
          'unpaired'
        );
        return;
      }
      if (err && err.status === 403) {
        state('not allowed', 'bad');
        showNotice('That action is not permitted', String(err.message || 'This phone is paired read-only.'), [], { label: 'Back', name: 'camera' }, 'forbidden');
        return;
      }
      if (err && err.status === 404 && where === 'device') {
        state('device not found', 'bad');
        showNotice('That device is no longer in the inventory', 'It may have been removed since the code was learned.', [], { label: 'Pick a device', name: 'pick' }, 'notfound');
        return;
      }
      /* The server answered, it just did not like the request (400 from a code it will not
         store, 429 from the claim limiter, 500, 503 "lens is unavailable on this install").
         Falling through to the offline path here told the user to go and check their Wi-Fi
         while Home SOC was running and telling them exactly what was wrong. The claim page has
         had this branch all along; the phone app was simply missing it. */
      if (err && err.status) {
        state('error ' + err.status, 'bad');
        showNotice(
          'Home SOC could not answer that',
          'It replied HTTP ' + err.status + ': ' + String((err && err.message) || 'no detail given') + '.',
          ['Check the Home SOC window (or data/logs) for the error.'],
          { label: 'Try again', name: 'camera', bad: true },
          'servererror'
        );
        resumeScanning();
        return;
      }
      /* No status means the request never arrived: offline, or the server went away. */
      reachable = false;
      var cached = cachedCard();
      if (cached) {
        state('offline', 'bad');
        staleDeviceId = cached.device.id;
        renderCard(cached, { stale: true });
        return;
      }
      state('offline', 'bad');
      unreachableNotice();
      resumeScanning();
    }

    /* Trimmed, time-limited and tied to the pairing: see readCachedCard. */
    function cachedCard() { return readCachedCard(Date.now()); }

    /* Is Home SOC actually reachable from here? ``navigator.onLine`` cannot answer that — it is
       true whenever the phone has *a* network, so a phone sitting on the home Wi-Fi with Home
       SOC shut down reports itself online and then fails on the first scan, and a shell opened
       from the service-worker cache reports online too.

       So the boot asks the cheapest authenticated endpoint there is (B7's /api/lens/health).
       Reachable: nothing changes, and the scan state stands. Unreachable: the last card comes
       back at once, marked stale (B8). Revoked or expired: onError's 401 path sends the user
       back to pairing now, instead of after a puzzling scan. */
    function online() { return reachable && navigator.onLine; }

    /* The viewfinder's status chip. Scanning still works with the server unreachable — the
       decode is local — so say "offline" rather than the healthy "looking for a code…" that
       would promise a lookup Lens cannot make. */
    function scanState() {
      /* A notice owns the status chip while it is up: the camera finishing its start-up must
         not report "looking for a code…" over the top of "this phone is no longer paired". */
      if (!notice.hidden) { return; }
      if (!detector) { state('scanning unsupported', 'bad'); }
      else if (online()) { state('looking for a code…'); }
      else { state('offline · scanning', 'bad'); }
    }

    function bootProbe() {
      return request('/api/lens/health')
        .then(function () { reachable = true; return true; })
        .catch(function (err) {
          /* Only the two answers the user can act on. Any other HTTP status means the server
             replied, so it is reachable; leave the viewfinder alone and let the real request
             report the real problem when there is one. */
          if (err && err.status === 401) { onError(err, 'health'); return false; }
          if (err && err.status) { return true; }
          goOffline();
          return false;
        });
    }

    /* The network went away (or was already away when the shell was opened from the service
       worker cache). B8: show the last card Lens saw, labelled stale, rather than a viewfinder
       that will silently fail on the next scan. Never over the top of something the user is
       already reading. */
    function goOffline() {
      reachable = false;
      /* An unpaired or revoked phone keeps its pairing notice: dropping off the network is no
         reason to show it a device card. */
      if (!token()) { state('not paired', 'bad'); return; }
      if (!card.hidden || !picker.hidden || !unknown.hidden) { state('offline', 'bad'); return; }
      var cached = cachedCard();
      if (cached) { staleDeviceId = cached.device.id; renderCard(cached, { stale: true }); return; }
      state('offline', 'bad');
      unreachableNotice();
    }

    function unreachableNotice() {
      showNotice(
        'Home SOC is not reachable',
        'The phone could not reach the dashboard, and there is nothing cached yet to show. ' +
          'The camera still works — scanning will resolve as soon as Home SOC answers again.',
        ['Check this phone is on the home Wi-Fi.', 'Check Home SOC is still running.'],
        { label: 'Try again', name: 'reload', bad: true },
        'offline'
      );
    }

    /* ---------------------------------------------------------- the card (B8 order) */

    function renderCard(payload, opts) {
      opts = opts || {};
      if (!payload || !payload.device) { return; }
      /* A fresh card is proof the server answered, so it also clears the offline state. */
      if (!opts.stale) { saveCard(payload, Date.now()); staleDeviceId = null; reachable = true; }
      stopScanning();
      hideNotice();
      clear(cardBody);

      var d = payload.device || {};
      var posture = payload.posture || {};
      var counts = posture.severity_counts || {};
      var name = deviceName(d);

      if (opts.stale) {
        cardBody.appendChild(el('p', {
          className: 'stale-strip',
          text: 'Offline — this is the last card Lens saw' + (d.last_seen ? ', ' + ago(d.last_seen) : '') + '. The numbers may have moved on.'
        }));
      } else if (payload.staleness && payload.staleness.stale) {
        /* The same honesty line the dashboard puts at the top of every page: the card is only as
           fresh as Home SOC's last look at the network. */
        var age = String(payload.staleness.age_text || '').trim();
        cardBody.appendChild(el('p', {
          className: 'stale-strip',
          text: 'Home SOC last checked your network ' + (age ? (/ago$/.test(age) ? age : age + ' ago') : 'a while ago') +
            ' — what you see may be out of date.'
        }));
      }

      /* header */
      /* Named, not numbered: the name leads and the address follows, muted. An unnamed device
         reads "Unnamed camera", so the IP line underneath is never a repeat of the title. */
      var meta = [d.ip, d.vendor, d.mac].filter(function (part) {
        return part && String(part) !== name;
      }).join(' · ');
      var flags = el('div', { className: 'dev-flags' },
        el('span', { className: 'flag ' + (d.online ? 'on' : 'off') }, el('span', { className: 'dot' }), el('span', { text: d.online ? 'Online' : 'Offline' })),
        el('span', { className: 'flag ' + (d.trusted ? 'trusted' : 'untrusted') }, el('span', { text: d.trusted ? 'Trusted' : 'Not trusted' })),
        d.kind ? el('span', { className: 'flag', text: String(d.kind) }) : null,
        d.last_seen ? el('span', { className: 'flag', text: 'Last seen ' + ago(d.last_seen) }) : null
      );
      cardBody.appendChild(el('div', { className: 'dev-head' },
        el('span', { className: 'dev-icon', text: kindIcon(d.kind), attrs: { 'aria-hidden': 'true' } }),
        el('div', { className: 'dev-id' },
          el('h2', { className: 'dev-name', text: name }),
          el('p', { className: 'dev-meta mono', text: meta }),
          flags)
      ));

      /* headline + severity strip */
      if (posture.headline) { cardBody.appendChild(el('p', { className: 'headline', text: String(posture.headline) })); }
      cardBody.appendChild(severityStrip(counts, posture));

      /* The cached card is a trimmed snapshot (readCachedCard): it has no findings, CVEs, DNS or
         dependency detail to show, and rendering those sections empty would claim "nothing open"
         about a device Lens simply did not keep the answer for. Say so instead. */
      if (opts.stale) {
        cardBody.appendChild(exposedSection(payload.services || []));
        cardBody.appendChild(el('p', {
          className: 'sec-empty',
          text: 'Things to fix, software flaws, websites looked up and history are shown only while Home SOC is reachable.'
        }));
        cardBody.appendChild(footer(payload, d, true));
        BODY.classList.add('card-open');
        show(card, true);
        cardBody.scrollTop = 0;
        card.focus();
        state('offline · cached', 'bad');
        return;
      }

      /* SPEC C7 calls this the single best use of the dependency map: point the phone at a box
         and learn what the house loses without it. The server has always computed it — and Lens
         paid for a full build_graph on every identification to do so — but renderCard never
         appended it, so the section the CHANGELOG tells users about did not exist on screen. */
      var blast = blastSection(payload.blast);
      if (blast) { cardBody.appendChild(blast); }

      /* ...and the relationships behind that consequence. The device page and /map have shown
         "Depends on" and "Depended on by" since the feature shipped; the phone — the surface
         where you are actually standing in front of the box — had only the headline. */
      (depsSections(payload.deps) || []).forEach(function (node) { cardBody.appendChild(node); });

      cardBody.appendChild(problemsSection(payload.findings || [], payload.actions || {}, d));
      cardBody.appendChild(exposedSection(payload.services || []));
      cardBody.appendChild(vulnSection(payload.vulns || []));
      cardBody.appendChild(dnsSection(payload.dns || {}));
      cardBody.appendChild(historySection(payload.timeline || []));
      cardBody.appendChild(footer(payload, d));

      BODY.classList.add('card-open');
      show(card, true);
      cardBody.scrollTop = 0;
      card.focus();
      state(opts.stale ? 'offline · cached' : name, opts.stale ? 'bad' : '');
    }

    function severityStrip(counts, posture) {
      var strip = el('div', { className: 'sev-strip' });
      var any = false;
      SEVERITIES.forEach(function (sev) {
        var n = Number(counts[sev] || 0);
        if (!n) { return; }
        any = true;
        strip.appendChild(el('span', { className: 'sev-chip sev-' + sev },
          el('b', { text: num(n) }), el('span', { text: sev }),
          el('span', { className: 'chip-word', text: SEV_WORD[sev] })));
      });
      if (!any) {
        strip.appendChild(el('span', { className: 'sev-chip is-clean', text: 'Nothing to fix' }));
      }
      if (posture && posture.score_contribution) {
        strip.appendChild(el('span', { className: 'sev-chip is-points', text: '−' + num(posture.score_contribution) + ' safety points' }));
      }
      return strip;
    }

    function section(title, count, open) {
      var head = el('summary', { className: 'sec-head' }, el('span', { className: 'sec-title', text: title }));
      if (count !== null && count !== undefined) { head.appendChild(el('span', { className: 'sec-count', text: num(count) })); }
      var node = el('details', { className: 'sec' }, head);
      if (open) { node.setAttribute('open', 'open'); }
      return node;
    }

    /* The four confidence levels ``blast_radius`` can report, each with the word for it. They
       are not synonyms: 'inferred' means the network's shape implies it, 'assumed' means
       nothing has confirmed it at all, and printing one for the other is the kind of small
       overstatement this whole feature is built to avoid. */
    var BLAST_CONF = {
      observed: 'Observed', mixed: 'Partly observed', inferred: 'Inferred', assumed: 'Assumed'
    };

    /* "If this fails" (SPEC C7). Three states the payload already distinguishes:
         - key absent or null: the topology package is not installed on this Home SOC, so there
           is nothing to say and no section is rendered at all;
         - both counts zero: nothing else is known to stop working, which is an answer;
         - populated: the headline, the counts, how it was established and the evidence line. */
    function blastSection(blast) {
      if (!blast || !blast.headline) { return null; }
      var offline = Number(blast.offline_count) || 0;
      var degraded = Number(blast.degraded_count) || 0;
      var sec = section('If this fails', offline + degraded, true);
      sec.appendChild(el('p', { className: 'blast-headline', text: String(blast.headline) }));

      if (offline || degraded) {
        var stats = el('div', { className: 'blast-stats' });
        if (offline) {
          stats.appendChild(el('span', { className: 'blast-stat is-offline' },
            el('b', { text: num(offline) }),
            el('span', { text: plural(offline, 'device') + ' unreachable' })));
        }
        if (degraded) {
          stats.appendChild(el('span', { className: 'blast-stat is-degraded' },
            el('b', { text: num(degraded) }),
            el('span', { text: plural(degraded, 'device') + ' degraded' })));
        }
        sec.appendChild(stats);
      } else {
        sec.appendChild(el('p', { className: 'sec-empty', text: 'Nothing else is known to stop working.' }));
      }

      var conf = String(blast.confidence || 'inferred');
      var row = el('p', { className: 'blast-evidence conf-' + conf },
        el('span', { className: 'blast-conf', text: BLAST_CONF[conf] || 'Inferred' }));
      row.appendChild(el('span', {
        text: ' ' + (blast.evidence ||
          'Nothing like this has actually been recorded — this follows from what Home SOC can see of the network.')
      }));
      sec.appendChild(row);

      /* The packet-visibility note, on the phone especially: a card headed "if this fails" is
         exactly where someone would otherwise read the map as a live traffic diagram. */
      if (blast.note) { sec.appendChild(el('p', { className: 'blast-note', text: String(blast.note) })); }
      return sec;
    }

    function plural(n, word) { return Number(n) === 1 ? word : word + 's'; }

    /* ------------------------------------------------------- Depends on / Depended on by */

    /* The three confidence levels an edge can carry (SPEC C2), each as a word. The left border
       repeats it — dashed for inferred, dotted for assumed, solid for observed, exactly as the
       blast evidence line already does — but the word is always there, so how strong a claim is
       never depends on a colour or a line style being noticed. */
    var DEP_CONF = { observed: 'Observed', inferred: 'Inferred', assumed: 'Assumed' };
    /* What the other end of the relationship actually is. Not decoration: "external service"
       and "device on this network" are the difference between a lookup and a neighbour. */
    var DEP_KIND = {
      device: 'device on this network',
      internet: 'the internet',
      resolver: 'DNS resolver',
      cloud: 'external service',
      cloud_blocked: 'blocked domain',
      service: 'service on a device'
    };

    function depRow(item, extraClass) {
      var conf = String((item && item.confidence) || 'inferred');
      if (!DEP_CONF[conf]) { conf = 'inferred'; }
      var kind = String((item && item.kind) || '');
      var row = el('div', { className: 'dep-row conf-' + conf + (extraClass ? ' ' + extraClass : '') });
      row.appendChild(el('div', { className: 'dep-label', text: String((item && item.label) || 'unknown') }));
      row.appendChild(el('div', { className: 'dep-meta' },
        el('span', { className: 'dep-conf', text: DEP_CONF[conf] }),
        el('span', { className: 'dep-kind', text: DEP_KIND[kind] || kind })));
      if (item && item.evidence) { row.appendChild(el('p', { className: 'dep-evidence', text: String(item.evidence) })); }
      return row;
    }

    function depMore(n, word) {
      return el('p', { className: 'dep-more', text: 'and ' + num(n) + ' more ' + plural(n, word) + ', not shown' });
    }

    /* Two sections, same pattern as the rest of the card, rendered straight after "If this
       fails". Three states, exactly as the blast section has:
         - deps absent or null: no topology package on this install, so nothing is rendered;
         - a list empty: said out loud ("Nothing is known to depend on this"), because absence of
           evidence is the honest answer here and hiding the section would read as a bug;
         - populated: one row per relationship, best-evidenced first, capped with a count.
       Blocked domains get their own group inside "Depends on" and are never rows of it: a
       lookup the filter refused is something the device asks for, not something it relies on. */
    function depsSections(deps) {
      if (!deps) { return null; }
      var up = deps.depends_on || [];
      var upMore = Number(deps.depends_on_more) || 0;
      var down = deps.depended_on_by || [];
      var downMore = Number(deps.depended_on_by_more) || 0;
      var blocked = deps.blocked || [];
      var blockedMore = Number(deps.blocked_more) || 0;

      var upSec = section('Depends on', up.length + upMore, true);
      if (up.length) {
        up.forEach(function (item) { upSec.appendChild(depRow(item)); });
        if (upMore) { upSec.appendChild(depMore(upMore, 'link')); }
      } else {
        upSec.appendChild(el('p', { className: 'sec-empty', text: 'Nothing this device relies on has been established.' }));
      }
      if (blocked.length) {
        upSec.appendChild(el('h4', { className: 'dep-sub', text: 'Asked for, but blocked' }));
        upSec.appendChild(el('p', {
          className: 'dep-sub-note',
          text: 'The DNS filter refused these lookups. This device keeps asking for them; it is not known to depend on them.'
        }));
        blocked.forEach(function (item) { upSec.appendChild(depRow(item, 'is-blocked')); });
        if (blockedMore) { upSec.appendChild(depMore(blockedMore, 'domain')); }
      }

      var downSec = section('Depended on by', down.length + downMore, true);
      if (down.length) {
        down.forEach(function (item) { downSec.appendChild(depRow(item)); });
        if (downMore) { downSec.appendChild(depMore(downMore, 'device')); }
      } else {
        downSec.appendChild(el('p', { className: 'sec-empty', text: 'Nothing is known to depend on this.' }));
      }
      if (deps.note) { downSec.appendChild(el('p', { className: 'blast-note dep-note', text: String(deps.note) })); }
      return [upSec, downSec];
    }

    function problemsSection(findings, actions, device) {
      var sorted = findings.slice().sort(function (a, b) { return sevRank(a.severity) - sevRank(b.severity); });
      /* The count is what still needs doing; fixed and ignored rows stay listed, marked as such. */
      var live = sorted.filter(function (f) { return !isDone(f.status); });
      var sec = section('Things to fix', live.length, live.length > 0);
      if (!sorted.length) {
        sec.appendChild(el('p', { className: 'sec-empty', text: 'Nothing open against this device.' }));
        return sec;
      }
      if (!live.length) {
        sec.appendChild(el('p', { className: 'sec-empty', text: 'Nothing open against this device. Earlier problems are listed below.' }));
      }
      sorted.forEach(function (f) {
        var row = el('div', { className: 'row is-stacked' },
          el('div', { className: 'row-head' }, sevBadge(f.severity, isDone(f.status)), statusBadge(f.status)),
          el('div', { className: 'row-main' },
            el('div', { className: 'row-title', text: f.title || f.finding_id || 'Finding' }),
            el('p', { className: 'row-sub', text: [f.detail, f.first_seen ? 'found ' + ago(f.first_seen) : ''].filter(Boolean).join(' · ') })));
        sec.appendChild(row);
        var steps = (f.remediation || []).filter(Boolean);
        if (steps.length) {
          var fix = el('details', { className: 'fix' },
            el('summary', { text: 'How to fix this — ' + steps.length + ' step' + (steps.length === 1 ? '' : 's') }));
          var list = el('ol', { className: 'fix-steps' });
          steps.forEach(function (step) { list.appendChild(el('li', { text: String(step) })); });
          fix.appendChild(list);
          sec.appendChild(fix);
        }
        /* Technical detail is one tap away, not deleted: the check's ID, the raw status and the
           references the fix steps came from. */
        var techBits = [
          f.finding_id ? 'Check: ' + f.finding_id : '',
          f.status ? 'Status: ' + f.status : '',
          'Severity: ' + severity(f.severity)
        ].filter(Boolean);
        var tech = el('details', { className: 'fix tech-details' },
          el('summary', { text: 'Technical details' }),
          el('p', { className: 'refs', text: techBits.join(' · ') }));
        (f.refs || []).forEach(function (ref) { tech.appendChild(el('p', { className: 'refs', text: String(ref) })); });
        sec.appendChild(tech);
        /* Outside the steps block on purpose: a finding with no remediation array is still an
           open finding the API will happily acknowledge, and burying the button inside "Fix it"
           meant the phone never offered it. Whether it can be acknowledged is a question about
           scope and status, not about whether anyone wrote fix steps for it. */
        if (actions.can_acknowledge && f.row_id && String(f.status) === 'open') {
          /* "Acknowledge" in the API; "I've seen this" on screen, as on the dashboard. */
          var ack = el('button', { className: 'btn btn-small', text: 'I’ve seen this', attrs: { type: 'button' } });
          ack.addEventListener('click', function () {
            ack.disabled = true;
            request('/api/lens/action', { body: { device_id: device.id, action: 'acknowledge', payload: { row_id: f.row_id } } })
              .then(function () { text(ack, 'Seen, not fixed yet'); })
              .catch(function (err) { ack.disabled = false; onError(err, 'action'); });
          });
          sec.appendChild(el('div', { className: 'row-actions' }, ack));
        }
      });
      return sec;
    }

    function exposedSection(services) {
      var open = services.filter(function (s) { return !s.state || String(s.state) === 'open'; });
      var sec = section('Open doors (ports)', open.length, open.length > 0);
      if (!open.length) {
        sec.appendChild(el('p', { className: 'sec-empty', text: 'No open ports were found on the last scan.' }));
        return sec;
      }
      open.forEach(function (s) {
        var port = Number(s.port);
        /* The API glosses every port in plain English; PORT_GLOSS is the offline floor. */
        var gloss = s.gloss || PORT_GLOSS[port] || (s.name ? String(s.name) + ' — service on this port' : 'an unrecognised service');
        var label = s.label || s.name || '';
        sec.appendChild(el('div', { className: 'row is-stacked' },
          s.risk ? el('div', { className: 'row-head' }, sevBadge(s.risk)) : null,
          el('div', { className: 'row-main' },
            el('div', { className: 'row-title', text: port + '/' + (s.proto || 'tcp') + (label ? ' ' + label : '') }),
            el('p', { className: 'row-sub', text: gloss }))));
      });
      return sec;
    }

    /* EPSS is a worldwide forecast for the flaw, not a forecast for this home: it estimates the
       chance the flaw is exploited anywhere in the next 30 days and says nothing about whether
       this household is targeted. So the wording is built here from the number, and never
       borrowed from a server string that might say "attack". */
    function epssText(v) {
      var raw = v && v.epss !== null && v.epss !== undefined && v.epss !== '' ? Number(v.epss) : NaN;
      var pct = isFinite(raw) && raw >= 0 && raw <= 1 ? raw * 100
        : (v && v.epss_pct !== null && v.epss_pct !== undefined && v.epss_pct !== '' ? Number(v.epss_pct) : NaN);
      if (!isFinite(pct) || pct < 0) { return ''; }
      var shown = pct < 1 ? 'Less than 1%' : (pct < 10 ? pct.toFixed(1) : String(Math.round(pct))) + '%';
      return shown + ' chance this flaw is exploited somewhere in the next 30 days (EPSS)';
    }

    function vulnSection(vulns) {
      var sec = section('Known software flaws (CVEs)', vulns.length, false);
      if (!vulns.length) {
        sec.appendChild(el('p', { className: 'sec-empty', text: 'No CVEs matched the software this device is running.' }));
        return sec;
      }
      var anyEpss = false;
      vulns.slice().sort(function (a, b) {
        return (b.kev ? 1 : 0) - (a.kev ? 1 : 0) || (Number(b.cvss) || 0) - (Number(a.cvss) || 0);
      }).forEach(function (v) {
        var epss = epssText(v);
        if (epss) { anyEpss = true; }
        var sub = [
          v.cvss ? 'CVSS ' + v.cvss + ' of 10' : '',
          epss,
          v.service ? 'via ' + v.service : ''
        ].filter(Boolean).join(' · ');
        var head = el('div', { className: 'row-main' },
          el('div', { className: 'row-title', text: [v.cve || 'CVE', v.title && v.title !== v.cve ? '— ' + v.title : ''].filter(Boolean).join(' ') }),
          el('p', { className: 'row-sub', text: sub }));
        if (v.kev_note) { head.appendChild(el('p', { className: 'row-sub', text: String(v.kev_note) })); }
        if (v.remediation) { head.appendChild(el('p', { className: 'row-sub', text: String(v.remediation) })); }
        /* KEV means CISA has seen the flaw exploited somewhere, which outranks every score, so it
           reads "Fix now" whatever the CVSS says. */
        var tag = v.kev
          ? el('div', { className: 'row-head' }, badge('kev', 'KEV · exploited'), el('span', { className: 'sev-word sev-word-critical', text: SEV_WORD.critical }))
          : (v.severity ? el('div', { className: 'row-head' }, sevBadge(v.severity)) : null);
        sec.appendChild(el('div', { className: 'row is-stacked' }, tag, head));
      });
      if (anyEpss) {
        sec.appendChild(el('p', {
          className: 'sec-note',
          text: 'EPSS is a worldwide forecast for the flaw itself. It does not say whether this home is being targeted.'
        }));
      }
      return sec;
    }

    function bars(rows, className, max) {
      var wrap = el('div');
      rows.forEach(function (row) {
        var count = Number(row.count) || 0;
        var pct = max > 0 ? Math.max(3, Math.round((count / max) * 100)) : 0;
        var fill = el('span', { className: 'bar-fill' });
        fill.style.width = pct + '%';
        wrap.appendChild(el('div', { className: 'bar-row ' + className },
          el('span', { className: 'bar-name', text: String(row.domain || row.name || '') }),
          el('span', { className: 'bar-count', text: num(count) + (row.reason ? ' · ' + row.reason : '') }),
          el('span', { className: 'bar-track' }, fill)));
      });
      return wrap;
    }

    function dnsSection(dns) {
      var total = Number(dns.total) || 0;
      var blocked = Number(dns.blocked) || 0;
      var rate = dns.block_rate !== undefined && dns.block_rate !== null
        ? Number(dns.block_rate) : (total ? blocked / total : 0);
      var pct = Math.round((rate <= 1 ? rate * 100 : rate));
      var threats = dns.threats || [];
      /* DNS lookups, not traffic: Home SOC sees which names a device asks its resolver for, not
         what it then sends or to whom, so the section says "looked up", never "talking to". */
      var sec = section('Websites it looked up (DNS)', total ? num(total) : null, true);

      /* Strictly false, not falsy: the API reports null when it cannot tell whether the
         resolver is on, and "unknown" must not be rendered as "off". In that case the note
         says so and the figures below are shown for what they are. */
      if (dns.enabled === false) {
        sec.appendChild(el('p', {
          className: 'sec-empty',
          text: dns.note || 'Web blocking (the Home SOC DNS resolver) is off, so Lens cannot see which websites this device looks up. Turn it on to find out.'
        }));
        return sec;
      }
      sec.appendChild(el('div', { className: 'dns-hero' },
        el('span', { className: 'dns-num' + (threats.length ? ' is-hot' : ''), text: pct + '%' }),
        el('span', { className: 'dns-hero-text' },
          el('b', { text: num(blocked) + ' of ' + num(total) + ' lookups blocked' }),
          el('span', { text: 'in the last ' + (dns.window_hours || 24) + ' hours' + (threats.length ? ' · ' + num(threats.length) + ' known-bad website' + (threats.length === 1 ? '' : 's') : '') }))));

      if (dns.note) { sec.appendChild(el('p', { className: 'dns-note', text: String(dns.note) })); }

      if (threats.length) {
        var maxT = Math.max.apply(null, threats.map(function (t) { return Number(t.count) || 0; }).concat([1]));
        sec.appendChild(el('div', { className: 'dns-group' },
          el('h4', { text: 'Known-bad websites' }), bars(threats, 'threat', maxT)));
      }
      var allowed = dns.top_allowed || [];
      if (allowed.length) {
        var maxA = Math.max.apply(null, allowed.map(function (a) { return Number(a.count) || 0; }).concat([1]));
        sec.appendChild(el('div', { className: 'dns-group' },
          el('h4', { text: 'Most looked up' }), bars(allowed.slice(0, 8), 'allowed', maxA)));
      }
      var blockedRows = dns.top_blocked || [];
      if (blockedRows.length) {
        var maxB = Math.max.apply(null, blockedRows.map(function (b) { return Number(b.count) || 0; }).concat([1]));
        sec.appendChild(el('div', { className: 'dns-group' },
          el('h4', { text: 'Blocked by web blocking' }), bars(blockedRows.slice(0, 8), 'blocked', maxB)));
      }
      if (!allowed.length && !blockedRows.length && !threats.length && !dns.note) {
        /* With a note the API has already explained the silence; two sentences saying the
           same thing is worse than one. */
        sec.appendChild(el('p', { className: 'sec-empty', text: 'No lookups from this device in the window.' }));
      }
      return sec;
    }

    function historySection(timeline) {
      var sec = section('What happened', timeline.length, false);
      if (!timeline.length) {
        sec.appendChild(el('p', { className: 'sec-empty', text: 'Nothing recorded for this device yet.' }));
        return sec;
      }
      var list = el('ul', { className: 'timeline' });
      timeline.slice(0, 20).forEach(function (item) {
        list.appendChild(el('li', {},
          el('span', { className: 'tl-when', text: ago(item.ts) }),
          el('span', { className: 'tl-title', text: String(item.title || item.kind || '') })));
      });
      sec.appendChild(list);
      return sec;
    }

    function footer(payload, device, stale) {
      var actions = payload.actions || {};
      var foot = el('div', { className: 'card-foot' });
      var scanAgain = el('button', { className: 'btn btn-primary', text: 'Scan again', attrs: { type: 'button' } });
      scanAgain.addEventListener('click', dismissCard);
      foot.appendChild(scanAgain);
      var pick = el('button', { className: 'btn', text: 'Pick manually', attrs: { type: 'button' } });
      pick.addEventListener('click', function () { dismissCard(); openPicker('pick'); });
      foot.appendChild(pick);

      function action(label, name, body) {
        var button = el('button', { className: 'btn', text: label, attrs: { type: 'button' } });
        button.addEventListener('click', function () {
          button.disabled = true;
          text(button, label + '…');
          request('/api/lens/action', { body: Object.assign({ device_id: device.id, action: name }, body || {}) })
            .then(function () { text(button, 'Done'); openDevice(device.id); })
            .catch(function (err) { button.disabled = false; text(button, label); onError(err, 'action'); });
        });
        foot.appendChild(button);
      }
      if (actions.can_rescan) { action('Check it again now', 'rescan'); }
      /* "Do you know it?" in the dashboard's words; the API action is still set_trusted. */
      if (actions.can_set_trusted) { action(device.trusted ? 'Not sure it’s ours' : 'Yes, it’s ours', 'set_trusted', { payload: { trusted: !device.trusted } }); }
      if (!stale && !actions.can_rescan && !actions.can_acknowledge && !actions.can_set_trusted) {
        foot.appendChild(el('p', { className: 'foot-note', text: 'This phone can look but not change anything (paired read-only). To recheck a device or mark things as seen from here, turn on [lens] allow_actions.' }));
      }
      return foot;
    }

    function dismissCard() {
      /* Dismissing is the user saying "show me again", so the repeat guard is cleared:
         pointing at the same sticker a second time must work immediately. */
      lastCode = '';
      lastCodeAt = 0;
      show(card, false);
      BODY.classList.remove('card-open');
      clear(cardBody);
      staleDeviceId = null;
      reconcile();
      resumeScanning();
    }

    /* ---------------------------------------------------------- picker + unknown sheet */

    function deviceRow(item, onPick) {
      var name = deviceName(item);
      /* Same rule as the card header: the name leads, the address follows it, muted. */
      var why = [item.ip, item.why || item.vendor].filter(function (part) {
        return part && String(part) !== name;
      }).join(' · ');
      var button = el('button', { className: 'device-btn', attrs: { type: 'button' } },
        el('span', { className: 'dev-icon', text: kindIcon(item.kind), attrs: { 'aria-hidden': 'true' } }),
        el('span', {},
          el('span', { className: 'device-name', text: name }),
          el('span', { className: 'device-why', text: why })));
      if (item.online) {
        button.appendChild(el('span', { className: 'device-badges' }, el('span', { className: 'flag on' }, el('span', { className: 'dot' }), el('span', { text: 'Online' }))));
      }
      button.addEventListener('click', function () { onPick(item); });
      return el('li', { className: 'device-item' }, button);
    }

    function fetchDevices() {
      if (devices.length && Date.now() - devicesAt < 20000) { return Promise.resolve(devices); }
      return request('/api/lens/devices').then(function (data) {
        devices = (data && (data.devices || data.candidates || data.items)) || [];
        devicesAt = Date.now();
        return devices;
      });
    }

    function renderPicker(list, filterValue) {
      clear(pickerList);
      var needle = String(filterValue || '').toLowerCase();
      var shown = list.filter(function (item) {
        if (!needle) { return true; }
        return [deviceName(item), item.name, item.ip, item.vendor, item.kind, item.hostname].filter(Boolean).join(' ').toLowerCase().indexOf(needle) >= 0;
      });
      shown.forEach(function (item) {
        pickerList.appendChild(deviceRow(item, function (picked) {
          closePicker();
          openDevice(picked.device_id || picked.id);
        }));
      });
      show($('picker-empty'), shown.length === 0);
    }

    function openPicker(mode) {
      pickerMode = mode || 'browse';
      stopScanning();
      returnFocus = document.activeElement && document.activeElement.focus ? document.activeElement : null;
      /* A pane that covers the whole screen is not modal unless it says so: without this the dock
         underneath stays focusable, so a keyboard or TalkBack user swipes past the last device
         onto three invisible buttons and can re-enter openPicker while it is already open. */
      BODY.classList.add('pane-open');
      show(picker, true);
      show(fallback, false);
      picker.focus();
      text($('picker-title'), pickerMode === 'pick' ? 'Which device is this?' : 'Devices');
      text($('picker-sub'), pickerMode === 'pick'
        ? 'Best guesses first: online devices, then anything with open problems.'
        : 'Everything Home SOC can see on the network. Tap one to open its card.');
      setTab(pickerMode === 'pick' ? null : 'devices');
      clear(pickerList);
      fetchDevices().then(function (list) { renderPicker(list, pickerSearch.value); })
        .catch(function (err) { closePicker(); onError(err, 'devices'); });
    }

    function closePicker() {
      show(picker, false);
      BODY.classList.remove('pane-open');
      setTab('scan');
      /* reconcile(), not just scanState(): the camera or the scanner may still be unavailable,
         and the user got here through the very button that dismissed the notice explaining it. */
      reconcile();
      if (returnFocus && document.contains(returnFocus)) { returnFocus.focus(); }
      returnFocus = null;
      resumeScanning();
    }

    function openUnknown(code, candidates) {
      pendingCode = code;
      returnFocus = document.activeElement && document.activeElement.focus ? document.activeElement : null;
      text($('unknown-code'), code.length > 200 ? code.slice(0, 200) + '…' : code);
      clear(unknownList);
      resetIgnore();
      BODY.classList.add('sheet-open');
      show(unknown, true);
      show(fallback, false);
      unknown.focus();
      state('new code', 'bad');
      var render = function (list) {
        clear(unknownList);
        list.forEach(function (item) {
          unknownList.appendChild(deviceRow(item, function (picked) {
            var deviceId = picked.device_id || picked.id;
            if (BODY.dataset.tagLearning !== '1') {
              closeUnknown();
              openDevice(deviceId);
              return;
            }
            request('/api/lens/learn', { body: { code: pendingCode, device_id: deviceId } })
              .then(function () { closeUnknown(); openDevice(deviceId); })
              .catch(function (err) { closeUnknown(); onError(err, 'learn'); });
          }));
        });
      };
      if (candidates && candidates.length) { render(candidates); }
      else { fetchDevices().then(render).catch(function (err) { closeUnknown(); onError(err, 'devices'); }); }
    }

    function closeUnknown() {
      /* "Close" has to stick. Without this the repeat guard expires 3.5 s later and the same code
         re-opens the sheet, so a phone still held up to a factory barcode loops for ever and the
         only control that stops it is the permanent, irreversible ignore. */
      if (pendingCode) { snoozed[pendingCode] = Date.now(); }
      show(unknown, false);
      BODY.classList.remove('sheet-open');
      pendingCode = '';
      resetIgnore();
      reconcile();
      if (returnFocus && document.contains(returnFocus)) { returnFocus.focus(); }
      returnFocus = null;
      resumeScanning();
    }

    /* ---------------------------------------------------------- wiring */

    function setTab(which) {
      var scanTab = $('tab-scan');
      var devTab = $('tab-devices');
      scanTab.classList.toggle('is-on', which === 'scan');
      scanTab.setAttribute('aria-pressed', which === 'scan' ? 'true' : 'false');
      devTab.classList.toggle('is-on', which === 'devices');
      devTab.setAttribute('aria-pressed', which === 'devices' ? 'true' : 'false');
    }

    $('tab-scan').addEventListener('click', function () { closePicker(); dismissCard(); });
    $('tab-devices').addEventListener('click', function () { openPicker('browse'); });
    $('btn-pick').addEventListener('click', function () { openPicker('pick'); });
    $('picker-close').addEventListener('click', closePicker);
    $('unknown-close').addEventListener('click', closeUnknown);
    /* Two taps, because this one is permanent, is the only full-width control on the sheet, and
       sits directly under the device list where a mis-tap is easy. */
    function resetIgnore() {
      var button = $('unknown-ignore');
      text(button, 'Not a device — ignore this code');
      button.classList.remove('is-bad');
      button.dataset.armed = '';
    }
    $('unknown-ignore').addEventListener('click', function () {
      var code = pendingCode;
      if (this.dataset.armed !== '1') {
        this.dataset.armed = '1';
        text(this, 'Ignore permanently — tap again');
        this.classList.add('is-bad');
        return;
      }
      if (code) {
        ignore(code);
        /* device_id: null records the code as "not a device" server-side, so no other paired
           phone is asked about it either. A failure here is not worth a modal: the local
           ignore list already stops this phone asking again. */
        if (BODY.dataset.tagLearning === '1') {
          request('/api/lens/learn', { body: { code: code, device_id: null } }).catch(function () { });
        }
      }
      closeUnknown();
      if (code) { state('code ignored', 'bad'); offerUndo(code); }
    });
    undoButton.addEventListener('click', function () {
      var code = this.dataset.code || '';
      offerUndo('');
      if (code) { unignore(code); }
    });
    $('card-handle').addEventListener('click', dismissCard);
    pickerSearch.addEventListener('input', function () { renderPicker(devices, this.value); });

    /* Tap the viewfinder or swipe the card down to dismiss it (B8). The scrim is
       pointer-events:none, so the tap lands on the video underneath it. */
    cam.addEventListener('click', function () { if (!card.hidden) { dismissCard(); } });
    var touchStart = 0;
    card.addEventListener('touchstart', function (ev) { touchStart = ev.touches[0].clientY; }, { passive: true });
    card.addEventListener('touchend', function (ev) {
      var dy = ev.changedTouches[0].clientY - touchStart;
      if (dy > 90 && cardBody.scrollTop <= 2) { dismissCard(); }
    }, { passive: true });
    window.addEventListener('pagehide', function () {
      /* Hand the camera back when the page goes away: a phone that keeps the torch-adjacent
         hardware warm in the background is a phone with a flat battery. */
      stopScanning();
      if (stream) { stream.getTracks().forEach(function (track) { track.stop(); }); stream = null; }
    });
    document.addEventListener('visibilitychange', function () {
      if (document.hidden) { stopScanning(); } else if (card.hidden && picker.hidden && unknown.hidden) { resumeScanning(); }
    });
    window.addEventListener('online', function () {
      reachable = true;
      /* A card that came out of the cache is replaced with the real thing rather than left
         sitting there labelled stale once the network is back. */
      if (staleDeviceId !== null && !card.hidden) { openDevice(staleDeviceId); return; }
      if (card.hidden) { state('back online'); resumeScanning(); }
    });
    window.addEventListener('offline', goOffline);

    /* Boot. No token means this phone has never been paired: say so instead of 401-ing later. */
    if (!token()) {
      /* Nothing a previous pairing left behind outlives it. */
      forgetPairing();
      state('not paired', 'bad');
      showNotice(
        'This phone is not paired yet',
        'Lens has to be paired with Home SOC once before it can show anything.',
        ['Open Home SOC on your computer.', 'Go to Lens → Pair a phone.', 'Scan the QR code with this phone.'],
        null,
        'unpaired'
      );
    }
    startCamera();
    if (token()) { bootProbe(); }
  }

  /* ================================================================== claim page */

  function claimApp() {
    var title = $('claim-title');
    var body = $('claim-body');
    var steps = $('claim-steps');
    var go = $('claim-go');
    var retry = $('claim-retry');
    var spinner = $('claim-spinner');

    function fail(headline, detail, how) {
      show(spinner, false);
      text(title, headline);
      text(body, detail);
      clear(steps);
      (how || []).forEach(function (step) { steps.appendChild(el('li', { text: step })); });
      show(steps, (how || []).length > 0);
      show(retry, true);
    }

    var match = /[#&]c=([^&]+)/.exec(location.hash || '');
    var code = match ? decodeURIComponent(match[1]) : '';
    /* Drop the code out of the address bar as soon as it is read: it is single-use, and the
       fragment would otherwise sit in the phone's history and in any shared screenshot. */
    if (match && window.history && history.replaceState) {
      history.replaceState(null, '', location.pathname);
    }
    if (!code) {
      fail('No pairing code in this link',
        'Open Home SOC on your computer, go to Lens → Pair a phone, and scan the QR code it shows.',
        ['The code is valid for five minutes.', 'Each code can be used once.']);
      return;
    }
    request('/api/lens/claim', { body: { code: code } }).then(function (data) {
      var tok = data && (data.token || data.lens_token);
      if (!tok) { throw new Error('the server did not return a token'); }
      /* A new pairing starts clean: the last card belonged to whichever token was here before. */
      forgetPairing();
      store(TOKEN_KEY, tok);
      show(spinner, false);
      text(title, 'This phone is paired');
      var until = String(data.expires_at || '').slice(0, 10);
      text(body, 'Paired as “' + String(data.label || 'phone') + '”'
        + (until ? ', valid until ' + until : '')
        + '. You can un-pair this phone any time from the Home SOC computer. Opening Lens…');
      show(go, true);
      setTimeout(function () { location.replace('/lens'); }, 900);
    }).catch(function (err) {
      var status = err && err.status;
      if (status === 429) {
        fail('Too many attempts', 'Pairing is rate-limited to ten attempts an hour from one address. Try again later.', []);
      } else if (status === 400 || status === 401 || status === 404) {
        fail('That pairing code did not work',
          String((err && err.message) || 'It was already used, or it expired.'),
          ['Reload the pairing page on your computer to get a fresh code.', 'Scan the new QR code within five minutes.']);
      } else if (status) {
        fail('Home SOC refused the pairing',
          'It answered HTTP ' + status + ': ' + String((err && err.message) || 'no detail given') + '.',
          ['Check the Home SOC window (or data/logs) for the error.', 'Then reload the pairing page and try again.']);
      } else {
        fail('Could not reach Home SOC',
          'The phone could not talk to the dashboard. Check it is on the home Wi-Fi and that Home SOC is running.',
          []);
      }
    });
    retry.addEventListener('click', function () { location.href = '/lens'; });
  }

  /* ================================================================== boot */

  if (PAGE === 'lens') {
    lensApp();
  } else if (PAGE === 'lens-claim') {
    claimApp();
  } else if (PAGE === 'lens-stickers') {
    var print = $('btn-print');
    if (print) { print.addEventListener('click', function () { window.print(); }); }
  }

  /* The service worker caches the shell only — never an authenticated API response. It is
     served from the site root so it can own the /lens scope without being able to touch
     anything under /static beyond the files it explicitly caches. */
  if ((PAGE === 'lens' || PAGE === 'lens-claim') && 'serviceWorker' in navigator) {
    window.addEventListener('load', function () {
      navigator.serviceWorker.register('/lens-sw.js', { scope: '/lens' }).catch(function () {
        /* No worker (plain HTTP, or registration refused) just means no offline shell. */
      });
    });
  }
})();
