/* app.js — Home SOC dashboard behaviour. Vanilla JS, no inline handlers (CSP default-src 'self').
   Responsibilities: polling /api/summary, table filtering, row expand, JSON POST helper
   (sets X-Requested-With: fetch + X-Token), and per-page renderers that build DOM with
   textContent only so nothing from the database is ever interpreted as HTML. */
(function () {
  'use strict';

  var body = document.body;
  var PAGE = body.dataset.page || '';
  var REFRESH = Math.max(3, parseInt(body.dataset.refresh || '15', 10) || 15) * 1000;

  function $(sel, root) { return (root || document).querySelector(sel); }
  function $$(sel, root) { return Array.prototype.slice.call((root || document).querySelectorAll(sel)); }

  /* ---------- fetch helpers ---------- */
  /* Auth is the HttpOnly cookie set by /login?token=...; the token is never read from the URL
     or re-sent as a header, so it cannot leak through history, referrers or proxy logs. */
  function headers(json) {
    var h = { 'X-Requested-With': 'fetch', 'Accept': 'application/json' };
    if (json) h['Content-Type'] = 'application/json';
    return h;
  }
  function getJSON(url) {
    return fetch(url, { headers: headers(false), credentials: 'same-origin' }).then(function (r) {
      if (r.status === 401) { location.href = '/login'; throw new Error('unauthorized'); }
      if (!r.ok) throw new Error('HTTP ' + r.status);
      return r.json();
    });
  }
  function postJSON(url, data, method) {
    return fetch(url, { method: method || 'POST', headers: headers(true), credentials: 'same-origin', body: JSON.stringify(data || {}) })
      .then(function (r) {
        return r.json().catch(function () { return {}; }).then(function (j) {
          if (!r.ok) { var e = new Error(j.error || ('HTTP ' + r.status)); e.status = r.status; e.body = j; throw e; }
          return j;
        });
      });
  }
  window.HomeSOC = { getJSON: getJSON, postJSON: postJSON };

  /* ---------- DOM helpers ---------- */
  function el(tag, props) {
    var e = document.createElement(tag);
    props = props || {};
    if (props.className) e.className = props.className;
    if (props.text !== undefined && props.text !== null) e.textContent = String(props.text);
    if (props.title) e.title = props.title;
    if (props.href) e.href = props.href;
    if (props.attrs) Object.keys(props.attrs).forEach(function (k) { e.setAttribute(k, props.attrs[k]); });
    if (props.data) Object.keys(props.data).forEach(function (k) { e.dataset[k] = props.data[k]; });
    for (var i = 2; i < arguments.length; i++) {
      var ch = arguments[i];
      if (ch === null || ch === undefined) continue;
      if (Array.isArray(ch)) ch.forEach(function (c) { if (c) e.appendChild(typeof c === 'string' ? document.createTextNode(c) : c); });
      else e.appendChild(typeof ch === 'string' ? document.createTextNode(ch) : ch);
    }
    return e;
  }
  /* Plain words BESIDE the technical ones (the same lists as app.py SEV_WORDS / STATUS_WORDS). */
  var SEV_WORDS = { critical: 'Fix now', high: 'Fix this week', medium: 'Worth fixing', low: 'When you have time', info: 'Good to know' };
  var STATUS_WORDS = { open: 'Needs attention', acknowledged: 'Seen, not fixed yet', resolved: 'Fixed', suppressed: 'Ignored (your choice)' };
  function scoreWord(score) {
    var v = Number(score);
    if (score === null || score === undefined || isNaN(v)) return '';
    return v >= 80 ? 'Good' : v >= 50 ? 'Fair' : 'Needs work';
  }
  function plural(n, one, many) { return n === 1 ? one : many; }
  function humanAge(seconds) {
    var s = Math.max(0, Math.floor(seconds));
    if (s < 60) return 'just now';
    var units = [[86400, 'day'], [3600, 'hour'], [60, 'minute']];
    for (var i = 0; i < units.length; i++) {
      if (s >= units[i][0]) { var n = Math.floor(s / units[i][0]); return n + ' ' + units[i][1] + (n === 1 ? '' : 's') + ' ago'; }
    }
    return 'just now';
  }
  function badge(kind, text) { return el('span', { className: 'badge badge-' + String(kind || '').toLowerCase().replace(/_/g, '-'), text: text === undefined ? kind : text }); }
  function clear(node) { if (node) node.textContent = ''; }
  function fmtNum(n) { return (n === null || n === undefined) ? '0' : Number(n).toLocaleString(); }
  function fmtTs(iso) {
    if (!iso) return '—';
    var d = new Date(iso);
    if (isNaN(d.getTime())) return String(iso);
    return d.toLocaleString(undefined, { month: 'short', day: '2-digit', hour: '2-digit', minute: '2-digit', second: '2-digit' });
  }
  function ago(iso) {
    if (!iso) return 'never';
    var d = new Date(iso);
    if (isNaN(d.getTime())) return String(iso);
    var s = Math.round((Date.now() - d.getTime()) / 1000);
    if (s >= 0) return humanAge(s);
    var ahead = humanAge(-s);   /* words, like the server's |ago: "in 3 hours" */
    return ahead === 'just now' ? 'in a moment' : 'in ' + ahead.replace(/ ago$/, '');
  }
  function hourLabel(key) { return key && key.length >= 13 ? key.slice(11, 13) + 'h' : String(key || ''); }

  var toastTimer = null;
  function toast(msg, kind) {
    var t = $('#toast');
    if (!t) return;
    t.textContent = msg;
    t.className = 'toast ' + (kind || '');
    t.hidden = false;
    clearTimeout(toastTimer);
    toastTimer = setTimeout(function () { t.hidden = true; }, 4500);
  }

  /* ---------- generic behaviours ---------- */
  function applyFilters(table) {
    var controls = $$('[data-filter]').filter(function (c) { return $(c.dataset.filter) === table; });
    var text = '', keys = {};
    controls.forEach(function (c) {
      if (c.dataset.filterKey) { if (c.value) keys[c.dataset.filterKey] = c.value.toLowerCase(); }
      else text = (c.value || '').trim().toLowerCase();
    });
    var shown = 0;
    $$('tbody > tr', table).forEach(function (tr) {
      if (tr.classList.contains('detail-row')) return;
      var ok = true;
      Object.keys(keys).forEach(function (k) { if (String(tr.dataset[k] || '').toLowerCase() !== keys[k]) ok = false; });
      if (ok && text) ok = tr.textContent.toLowerCase().indexOf(text) !== -1;
      tr.hidden = !ok;
      if (!ok && tr.nextElementSibling && tr.nextElementSibling.classList.contains('detail-row')) setRowOpen(tr, false);
      if (ok) shown++;
    });
    var counter = $('[data-filter-count="' + (table.id || '') + '"]');
    if (counter) counter.textContent = shown + ' shown';
  }
  function initFilters() {
    $$('[data-filter]').forEach(function (c) {
      var table = $(c.dataset.filter);
      if (!table) return;
      c.addEventListener('input', function () { applyFilters(table); });
      c.addEventListener('change', function () { applyFilters(table); });
    });
    /* Filter forms no longer submit on "change": in a select, every arrow key fires it, so a
       keyboard user could only ever pick the next option and lost the page and their focus each
       time (WCAG 3.2.2). The forms' own Search / Apply buttons submit them. */
  }
  /* Expandable rows (findings, devices, flaws, startup programs). Each carries a real
     <button class="row-toggle" aria-expanded aria-controls> so the keyboard can open it; a mouse
     click anywhere else on the row still works. A row a template did not give a button gets one
     here, so no expandable row is ever mouse-only. */
  function setRowOpen(tr, open) {
    var next = tr.nextElementSibling;
    if (!next || !next.classList.contains('detail-row')) return;
    next.hidden = !open;
    $$('.row-toggle', tr).forEach(function (b) { b.setAttribute('aria-expanded', open ? 'true' : 'false'); });
  }
  function initRowExpand() {
    $$('tr.expandable').forEach(function (tr, i) {
      var next = tr.nextElementSibling;
      if (!next || !next.classList.contains('detail-row')) return;
      if (!next.id) next.id = 'row-detail-' + i;
      if (!$('.row-toggle', tr)) {
        var cell = tr.cells[0];
        if (!cell) return;
        var b = el('button', { className: 'row-toggle row-toggle-icon', attrs: { type: 'button' } },
          el('span', { className: 'visually-hidden', text: 'Details: ' + (cell.textContent || '').trim().slice(0, 80) }));
        cell.insertBefore(b, cell.firstChild);
      }
      $$('.row-toggle', tr).forEach(function (b) {
        b.setAttribute('aria-controls', next.id);
        b.setAttribute('aria-expanded', next.hidden ? 'false' : 'true');
      });
    });
    document.addEventListener('click', function (ev) {
      var tr = ev.target.closest('tr.expandable');
      if (!tr) return;
      var own = ev.target.closest('.row-toggle');
      if (!own && ev.target.closest('a, button, input, select, textarea, summary, abbr.term')) return;
      var next = tr.nextElementSibling;
      if (next && next.classList.contains('detail-row')) setRowOpen(tr, next.hidden);
    });
  }
  function initForms() {
    $$('form[data-post]').forEach(function (form) {
      form.addEventListener('submit', function (ev) {
        ev.preventDefault();
        var data = {};
        $$('input, select, textarea', form).forEach(function (inp) {
          if (!inp.name) return;
          data[inp.name] = inp.type === 'checkbox' ? inp.checked : inp.value;
        });
        var btn = $('button[type=submit]', form);
        if (btn) btn.disabled = true;
        postJSON(form.dataset.post, data, form.dataset.method || 'POST').then(function (res) {
          toast(form.dataset.success || 'Saved', 'ok');
          if (form.dataset.reload !== undefined) setTimeout(function () { location.reload(); }, 400);
          form.dispatchEvent(new CustomEvent('homesoc:saved', { detail: res }));
        }).catch(function (e) { toast(e.message, 'err'); }).then(function () { if (btn) btn.disabled = false; });
      });
    });
  }

  /* ---------- action buttons (event delegation) ---------- */
  var actions = {
    scan: function (b) {
      return postJSON('/api/scan', { kind: b.dataset.kind }).then(function (r) {
        toast('Started ' + r.kind + ' scan (' + (r.jobs || []).join(', ') + ') via ' + r.mode, 'ok');
        if (PAGE === 'scans') setTimeout(refreshScans, 1500);
      });
    },
    'finding-status': function (b) {
      var id = b.dataset.id, status = b.dataset.status;
      return postJSON('/api/findings/' + id + '/status', { status: status }).then(function () {
        var row = $('tr[data-id="' + id + '"]');
        if (row) {
          row.dataset.status = status;
          var sb = $('.status-badge', row);
          if (sb) {
            sb.className = 'badge status-badge badge-' + status;
            /* A person pressed "I've fixed it": that is "Marked fixed" until a later check
               confirms it. Only Home SOC's own check earns the plain "Fixed". */
            sb.textContent = status === 'resolved' ? 'Marked fixed' : (STATUS_WORDS[status] || status);
            sb.dataset.status = status;
            sb.title = 'Status: ' + status + (status === 'resolved' ? '. You marked this fixed; Home SOC has not confirmed it.' : '');
            var tw = sb.parentNode && $('.tech-word', sb.parentNode);
            if (tw) tw.textContent = status;
          }
        }
        toast(status === 'resolved' ? 'Marked fixed (resolved)' : 'Marked "' + (STATUS_WORDS[status] || status) + '" (' + status + ')', 'ok');
        refreshSummary();
      });
    },
    'findings-ack-shown': function (b) {
      var table = $('#findings-table');
      if (!table) return Promise.resolve();
      var ids = $$('tbody > tr.expandable', table).filter(function (tr) { return !tr.hidden && tr.dataset.status === 'open'; }).map(function (tr) { return tr.dataset.id; });
      if (!ids.length) { toast('Nothing shown needs attention', 'ok'); return Promise.resolve(); }
      if (!window.confirm('Mark all ' + ids.length + ' shown ' + plural(ids.length, 'item', 'items') + ' as "Seen, not fixed yet" (acknowledged)? They stay on the list until they are fixed.')) return Promise.resolve();
      var done = 0;
      return ids.reduce(function (p, id) {
        return p.then(function () { return postJSON('/api/findings/' + id + '/status', { status: 'acknowledged' }).then(function () { done++; }); });
      }, Promise.resolve()).then(function () {
        toast('Marked ' + done + ' as seen (acknowledged)', 'ok');
        setTimeout(function () { location.reload(); }, 400);
      });
    },
    'device-trusted': function (b) {
      var id = b.dataset.id, next = b.dataset.trusted !== '1';
      return postJSON('/api/devices/' + id, { trusted: next }).then(function () {
        b.dataset.trusted = next ? '1' : '0';
        /* The template may give plain labels ("Yes, it's ours" / "Not sure"); the technical
           word stays in the tooltip. */
        b.textContent = next ? (b.dataset.labelOn || 'Trusted') : (b.dataset.labelOff || 'Untrusted');
        b.classList.toggle('btn-ok', next);
        toast(next ? "Marked as yours (trusted)" : "Marked as not sure (untrusted)", 'ok');
      });
    },
    'device-scan': function (b) {
      return postJSON('/api/devices/' + b.dataset.id + '/scan').then(function () { toast('Device scan started', 'ok'); });
    },
    defender: function (b) {
      /* The action shells out to MpCmdRun and can take a quarter of an hour, so the server answers
         202 immediately and we poll /api/defender/status until it reports the action finished. */
      return postJSON('/api/defender/' + b.dataset.op).then(function (r) {
        toast('Defender: ' + b.dataset.op + ' ' + (r.status || 'started') + ' — this can take several minutes', 'ok');
        pollDefender(b.dataset.op);
      });
    },
    print: function () { window.print(); return Promise.resolve(); },
    'dns-override': function (b) {
      if (b.dataset.op === 'allow') {
        var bad = /^(malicious|suspicious)$/i.test(b.dataset.reputation || '');
        var q = bad
          ? 'Security services have flagged ' + b.dataset.domain + ' as ' + b.dataset.reputation.toLowerCase() + '.\n\nAlways allow it anyway? Every device on your network will be able to reach it.'
          : 'Always allow ' + b.dataset.domain + '? Web blocking will stop blocking it for every device.';
        if (!window.confirm(q)) return Promise.resolve();
      }
      return postJSON('/api/dns/override', { domain: b.dataset.domain, action: b.dataset.op, note: b.dataset.note || 'from dashboard' }).then(function (r) {
        toast(r.domain + ' → ' + (r.action === 'allow' ? 'always allowed' : r.action === 'deny' ? 'always blocked' : r.action), 'ok');
        if (b.dataset.reload !== undefined) setTimeout(function () { location.reload(); }, 400);
      });
    },
    'dns-override-delete': function (b) {
      return postJSON('/api/dns/override/' + encodeURIComponent(b.dataset.domain), {}, 'DELETE').then(function () {
        var tr = b.closest('tr');
        if (tr) tr.remove();
        toast('Override removed', 'ok');
      });
    },
    'notify-test': function () {
      return postJSON('/api/notify/test').then(function (r) {
        var parts = Object.keys(r.channels || {}).map(function (k) { return k + ': ' + (r.channels[k] ? 'ok' : 'failed'); });
        toast(parts.length ? parts.join(' · ') : 'No channels configured', 'ok');
      });
    },
    'settings-save': function () { return saveSettings(); },
    'settings-clear': function (b) {
      var key = b.dataset.key;
      return postJSON('/api/settings/clear', { keys: [key] }).then(function (r) {
        toast((r.cleared && r.cleared.length ? key + ' now follows config.toml' : 'Nothing to clear') +
              (r.restart_required ? ' — restart Home SOC to apply' : ''), 'ok');
        setTimeout(function () { location.reload(); }, 900);
      });
    },
    toggle: function (b) {
      var t = $(b.dataset.target);
      if (t) {
        t.hidden = !t.hidden;
        b.setAttribute('aria-expanded', t.hidden ? 'false' : 'true');
        /* Optional second label, e.g. "show all 6" <-> "hide". */
        if (b.dataset.labelAlt) {
          var previous = b.textContent;
          b.textContent = b.dataset.labelAlt;
          b.dataset.labelAlt = previous;
        }
      }
      return Promise.resolve();
    }
  };
  function initActions() {
    document.addEventListener('click', function (ev) {
      var b = ev.target.closest('[data-action]');
      if (!b || !actions[b.dataset.action]) return;
      ev.preventDefault();
      b.disabled = true;
      actions[b.dataset.action](b).catch(function (e) { toast(e.message || 'Request failed', 'err'); }).then(function () { b.disabled = false; });
    });
  }

  /* ---------- summary polling (header chips + overview) ---------- */
  function bind(name, value) { $$('[data-bind="' + name + '"]').forEach(function (n) { n.textContent = value; }); }
  function openTotal(counts) {
    var o = (counts && counts.open) || {};
    return Object.keys(o).reduce(function (a, k) { return a + (o[k] || 0); }, 0);
  }
  function setText(sel, text) { var n = $(sel); if (n) n.textContent = text; }
  function scoreIsPartial(s) {
    return (s.overdue_checks || []).some(function (o) { return o && o.never; });
  }
  function renderHeader(s) {
    /* Never checked: no score to show. "100/100 · Good" on an empty database would read as a
       clean bill of health when Home SOC has not looked at anything yet. */
    var never = !!(s.staleness && s.staleness.never);
    bind('score', never ? '–' : s.score); bind('grade', never ? '–' : s.grade);
    /* "Safety 10/100 · Needs work"; the letter grade lives in the tooltip. */
    var chip = $('#chip-score');
    if (chip) {
      chip.className = never ? 'chip' : 'chip grade-' + s.grade;
      chip.title = never
        ? "No safety score yet: Home SOC hasn't checked your network."
        : 'Safety score ' + s.score + ' out of 100 (grade ' + s.grade + '). Higher is safer.';
    }
    /* A score from a device check alone is not "Good": nothing has looked at the devices' open
       doors, their software or this computer yet, so there was nothing to lose points on. */
    var partial = !never && scoreIsPartial(s);
    var word = never ? 'not checked yet' : (partial ? 'not fully checked yet' : scoreWord(s.score));
    setText('#chip-score-word', word ? '· ' + word : '');
    if (chip && partial) chip.title = 'Safety score ' + s.score + ' out of 100 — but some of Home SOC\'s checks have not run yet, so it only counts what has been looked at.';
    /* "33 to fix · 2 urgent": everything still open, and how many of those are critical. */
    var open = (s.counts && s.counts.open) || {};
    var total = openTotal(s.counts), urgent = open.critical || 0;
    var oc = $('#chip-open');
    if (oc) {
      oc.classList.toggle('is-urgent', urgent > 0);
      oc.title = total + ' ' + plural(total, 'finding needs', 'findings need') + ' attention; ' +
        urgent + ' ' + plural(urgent, 'is', 'are') + ' critical ("Fix now").';
    }
    setText('#chip-open-total', total ? fmtNum(total) : 'Nothing');
    setText('#chip-open-text', (!total && never) ? 'found yet' : 'to fix');
    setText('#chip-urgent', total ? (urgent ? ' · ' + fmtNum(urgent) + ' urgent' : ' · none urgent') : '');
    bind('open-total', total);
    bind('devices-online', s.devices.online); bind('devices-total', s.devices.total);
    bind('dns-total', fmtNum(s.dns.total24h)); bind('dns-blocked', fmtNum(s.dns.blocked24h));
    bind('dns-pct', s.dns.blocked_pct); bind('dns-clients', s.dns.clients24h);
    var dot = $('#dot-dns');
    if (dot) dot.className = 'dot ' + (s.dns.running ? 'on' : (s.dns.enabled ? 'off' : ''));
    setText('#chip-dns-state', s.dns.running ? 'running' : (s.dns.enabled ? 'not running' : 'off'));
    /* "Blocked 1,204 · last 24 h": a rolling 24 hours, so never "today". */
    var dc = $('#chip-dns');
    if (dc) {
      dc.classList.toggle('is-off', !s.dns.running);
      clear(dc);
      if (s.dns.running) {
        dc.appendChild(document.createTextNode('Blocked '));
        dc.appendChild(el('b', { text: fmtNum(s.dns.blocked24h) }));
        dc.appendChild(document.createTextNode(' · last 24 h'));
        dc.title = fmtNum(s.dns.blocked24h) + ' look-ups blocked in the last 24 hours, out of ' + fmtNum(s.dns.total24h) + ' (web blocking, the DNS filter)';
      } else {
        dc.appendChild(document.createTextNode('Blocking: '));
        dc.appendChild(el('span', { className: 'chip-word', text: s.dns.enabled ? 'not running' : 'off' }));
        dc.title = s.dns.enabled
          ? 'Web blocking is switched on but not running, so nothing is being filtered right now'
          : 'Web blocking (the DNS filter) is switched off';
      }
    }
    /* The time this SCREEN refreshed. The network check time is a separate line. */
    var lr = $('#last-refresh');
    if (lr) lr.textContent = 'Screen refreshed ' + new Date().toLocaleTimeString([], { hour: 'numeric', minute: '2-digit' });
    renderStaleness(s);
    renderScoreBreakdown(s.score_breakdown, !!(s.staleness && s.staleness.never));
  }
  /* The honesty banner and the sidebar "Network last checked" line, kept current while a wall
     screen stays up for days. Prefers the server's own verdict (summary.staleness); without one
     it works it out from the newest discovery start and the schedule the page was rendered
     with, by the same rule: older than 3 schedules, or 24 hours. */
  function renderStaleness(s) {
    var line = $('#network-check'), banner = $('#stale-banner');
    if (!line && !banner) return;
    var st = s && s.staleness, stale = false, text = '', never = false;
    if (st && typeof st === 'object') {
      stale = !!st.stale; never = !!st.never;
      var t0 = st.last_check ? new Date(st.last_check).getTime() : NaN;
      text = isNaN(t0) ? (st.age_text || '') : humanAge((Date.now() - t0) / 1000);
    } else {
      var last = s && s.last_scans && s.last_scans.discovery;
      var minutes = parseInt((line && line.dataset.scheduleMinutes) || '10', 10) || 10;
      if (!last) { never = true; }
      else {
        var age = (Date.now() - new Date(last).getTime()) / 1000;
        if (isNaN(age)) return;
        text = humanAge(age);
        stale = age > Math.min(3 * minutes, 24 * 60) * 60;
      }
    }
    if (line) {
      line.textContent = never ? 'Network not checked yet' : (text ? 'Network last checked ' + text : 'Network check time unknown');
      line.classList.toggle('is-stale', stale);
    }
    if (banner) {
      banner.hidden = !stale;
      var bt = $('#stale-text', banner);
      if (bt && stale) {
        clear(bt);
        bt.appendChild(document.createTextNode('Home SOC last checked your network '));
        bt.appendChild(el('b', { text: text || 'a while ago' }));
        bt.appendChild(document.createTextNode(' — what you see may be out of date.'));
      }
    }
  }
  /* "Fix these first": the open findings costing the score the most, from
     findings.score.score_breakdown via /api/summary. Rendered on the Overview (where the
     server also renders it, so it survives a broken poll) and on the Summary page. */
  function renderScoreBreakdown(items, never) {
    var list = $('#score-breakdown');
    if (!list) return;
    items = Array.isArray(items) ? items : [];
    clear(list);
    var note = $('#score-breakdown-note');
    if (note) note.hidden = !items.length;
    if (!items.length) {
      list.appendChild(el('li', {
        className: 'empty',
        text: never
          ? "Nothing yet: Home SOC hasn't checked your network."
          : 'Nothing is costing you points. Everything found is fixed, marked as seen, or ignored.'
      }));
      return;
    }
    /* Same shape as the server-rendered list: plain headline (technical title in the tooltip),
       then where it is and the action word, then "×N" and "+N points". */
    items.forEach(function (b) {
      var sev = String(b.severity || 'info');
      var word = b.severity_word || SEV_WORDS[sev] || '';
      var meta = el('span', { className: 'muted small' });
      var hasLink = b.link_device_id !== undefined && b.link_device_id !== null && b.device_label;
      if (hasLink) meta.appendChild(el('a', { text: b.device_label, href: '/devices/' + encodeURIComponent(b.link_device_id) }));
      else if (b.where_text) meta.appendChild(document.createTextNode(b.where_text));
      if (hasLink || b.where_text) meta.appendChild(document.createTextNode(' · '));
      meta.appendChild(document.createTextNode(word));
      var title = el('span', { className: 'cost-title' },
        el('a', {
          text: b.plain_title || b.title || b.finding_id,
          title: (b.finding_id || '') + ' — ' + (b.title || ''),
          href: '/findings?status=open&q=' + encodeURIComponent(b.finding_id || '')
        }),
        el('br', {}), meta);
      var row = el('li', { className: 'cost' },
        el('span', { className: 'tl-dot sev-dot-' + sev, title: sev + (word ? ' · ' + word : '') }),
        title);
      row.appendChild(b.count > 1
        ? el('span', { className: 'cost-count', text: '×' + b.count, title: b.count + ' problems of this type are open' })
        : el('span', {}));
      var gain = (b.gain === undefined || b.gain === null ? b.penalty : b.gain);
      row.appendChild(el('span', {
        className: 'cost-gain',
        text: b.gain_text || ('+' + gain + ' ' + plural(Number(gain), 'point', 'points')),
        title: 'The safety score would rise by about this much once every problem of this type is fixed'
      }));
      list.appendChild(row);
    });
  }
  function renderOverview(s) {
    var C = window.Charts;
    if (!C) return;
    var g = $('#chart-gauge');
    var neverChecked = !!(s.staleness && s.staleness.never);
    var partialScore = !neverChecked && scoreIsPartial(s);
    if (g) C.gauge(g, s.score, neverChecked
      ? { unknown: true, label: 'not checked yet', title: "No safety score yet: Home SOC hasn't checked your network" }
      : { label: partialScore ? 'not fully checked' : (scoreWord(s.score) || ('grade ' + s.grade)),
          title: 'Safety score ' + s.score + ' out of 100, grade ' + s.grade + (partialScore ? ' — some checks have not run yet' : '') });
    var tr = $('#chart-trend');
    if (tr) C.sparkline(tr, (s.trend || []).map(function (p) { return p[1]; }), { title: '30-day score trend', emptyText: 'Trend appears after the first hourly score sample' });
    var d = $('#chart-severity');
    if (d) {
      var open = (s.counts && s.counts.open) || {};
      var slices = ['critical', 'high', 'medium', 'low', 'info'].map(function (k) { return { label: k, value: open[k] || 0, word: SEV_WORDS[k] }; });
      C.donut(d, slices, { centerText: openTotal(s.counts), centerSub: 'to fix', legendAll: slices, title: 'Open findings by severity' });
    }
    var jc = $('#jobs-chips');
    if (jc) {
      clear(jc);
      if (!s.jobs.length) jc.appendChild(el('span', { className: 'muted', text: 'No jobs recorded yet.' }));
      s.jobs.forEach(function (j) {
        var st = (j.last_status || 'never').toLowerCase();
        jc.appendChild(el('span', { className: 'chip chip-job', title: 'last run ' + fmtTs(j.last_run) + (j.last_error ? ' — ' + j.last_error : '') },
          el('span', { className: 'job-status ' + (st === 'ok' ? 'ok' : st === 'error' || st === 'failed' ? 'error' : st === 'running' ? 'running' : '') }),
          el('b', { text: j.name }), el('span', { text: st + ' · ' + ago(j.last_run) })));
      });
    }
    var fb = $('#feeds-body');
    if (fb) {
      clear(fb);
      if (!s.feeds.length) fb.appendChild(el('tr', {}, el('td', { className: 'empty', text: 'No feeds recorded yet.', attrs: { colspan: 5 } })));
      s.feeds.forEach(function (f) {
        fb.appendChild(el('tr', {},
          el('td', { className: 'mono', text: f.name }),
          el('td', {}, badge(f.status || 'never')),
          el('td', { className: 'num', text: fmtNum(f.entries) }),
          el('td', { text: ago(f.last_updated), title: fmtTs(f.last_updated) }),
          el('td', { className: 'muted small wrap', text: f.error || '' })));
      });
    }
    var ev = $('#events-list');
    if (ev) { clear(ev); s.events.slice(0, parseInt(ev.dataset.limit || '20', 10) || 20).forEach(function (e) { ev.appendChild(eventItem(e, ev.classList.contains('events-plain'))); }); if (!s.events.length) ev.appendChild(el('li', { className: 'empty events-empty', text: 'Nothing yet. Anything Home SOC does — a check, a threat-list download, a problem changing state — shows up here.' })); }
    getJSON('/api/dns/series?hours=24').then(function (series) {
      var c = $('#chart-dns');
      if (c) C.bar(c, { values: series.map(function (p) { return p.total; }), overlay: series.map(function (p) { return p.blocked; }), labels: series.map(function (p) { return hourLabel(p.hour); }), title: 'Look-ups per hour, with the blocked share drawn over each bar', height: 130, emptyText: 'No website look-ups in the last 24 hours' });
    }).catch(function () {});
  }
  /* plain: the Home page's calm version. The source moves to the tooltip, and only warnings and
     errors carry a badge; the full technical list (source, level, data) is on System health. */
  function eventItem(e, plain) {
    if (plain) {
      var lvl = (e.level || 'info').toLowerCase();
      var msg = el('span', { className: 'e-msg', title: (e.source || 'Home SOC') + ': ' + (e.message || '') });
      if (lvl !== 'info' && lvl !== 'debug') { msg.appendChild(badge('level-' + lvl, e.level)); msg.appendChild(document.createTextNode(' ')); }
      msg.appendChild(document.createTextNode(e.plain || e.message || ''));
      if (e.repeats > 1) { msg.appendChild(document.createTextNode(' ')); msg.appendChild(el('span', { className: 'muted small', text: '×' + e.repeats, title: 'Happened ' + e.repeats + ' times in a row' })); }
      return el('li', {}, el('span', { className: 'e-ts', text: ago(e.ts), title: fmtTs(e.ts) }), msg);
    }
    var li = el('li', {},
      el('span', { className: 'e-ts', text: fmtTs(e.ts), title: e.ts }),
      el('span', { className: 'e-src', text: e.source }),
      el('span', { className: 'e-msg' }, badge('level-' + (e.level || 'info').toLowerCase(), e.level), ' ', e.message));
    if (e.data && typeof e.data === 'object' && Object.keys(e.data).length) {
      var pre = el('pre', { text: JSON.stringify(e.data, null, 2) });
      pre.hidden = true;
      var btn = el('button', { className: 'btn btn-sm', text: 'data' });
      btn.addEventListener('click', function () { pre.hidden = !pre.hidden; });
      $('.e-msg', li).appendChild(document.createTextNode(' '));
      $('.e-msg', li).appendChild(btn);
      $('.e-msg', li).appendChild(pre);
    }
    return li;
  }
  var lastSummary = null;
  function refreshSummary() {
    return getJSON('/api/summary').then(function (s) {
      lastSummary = s;
      renderHeader(s);
      if (PAGE === 'overview') renderOverview(s);
    }).catch(function () {});
  }

  /* ---------- DNS page ---------- */
  /* Why a look-up was allowed or blocked, in words (the same words as dns.html's reason_words);
     the stored reason stays beside it as the technical word. */
  var DNS_WORDS = null;
  function dnsWords() {
    if (DNS_WORDS) return DNS_WORDS;
    DNS_WORDS = { lists: {}, threat: [] };
    var seed = $('#dns-words');
    if (seed) { try { DNS_WORDS = JSON.parse(seed.textContent) || DNS_WORDS; } catch (e) { /* keep the empty words */ } }
    return DNS_WORDS;
  }
  function reasonWords(reason) {
    var r = String(reason || ''), w = dnsWords();
    if (r.indexOf('list:') === 0) {
      var name = r.slice(5), what = (w.lists && w.lists[name]) || '';
      return (w.threat || []).indexOf(name) >= 0
        ? 'On a threat list: ' + (what || 'dangerous sites').toLowerCase()
        : 'On a blocklist: ' + (what || 'blocked sites').toLowerCase();
    }
    if (r === 'override:deny') return 'You chose to always block it';
    if (r === 'override:allow') return 'You chose to always allow it';
    if (r === 'reputation') return 'Security services flagged it as dangerous';
    if (r === 'default') return 'Allowed (not on any list)';
    if (r === 'cache') return 'Answered from memory';
    return r || '';
  }
  var QTYPE_WORDS = { A: 'Address', AAAA: 'Address', HTTPS: 'Service details', SVCB: 'Service details', PTR: 'Name for an address',
                      CNAME: 'Alias', MX: 'Mail server', TXT: 'Text record', SRV: 'Service location', NS: 'Name server', SOA: 'Zone details' };
  var RESULT_WORDS = { allow: 'Allowed', block: 'Blocked', cache: 'From memory', error: 'Failed' };
  /* "live" only while the resolver runs and the newest row is recent. */
  function logFreshness(rowsData) {
    var n = $('#log-freshness');
    if (!n) return;
    var running = n.dataset.running === '1';
    var newest = rowsData.length ? new Date(rowsData[0].ts).getTime() : NaN;
    var age = isNaN(newest) ? null : (Date.now() - newest) / 1000;
    var text;
    if (running && age !== null && age < 15 * 60) text = '(live, newest first)';
    else {
      text = '(newest first' + (running ? '' : ' — web blocking is not running');
      if (age !== null && age >= 15 * 60) text += '; last look-up ' + humanAge(age);
      text += ')';
    }
    n.textContent = text;
  }
  function refreshDnsLog() {
    var tb = $('#log-body');
    if (!tb) return;
    var client = ($('#log-client') || {}).value || '', action = ($('#log-action') || {}).value || '';
    getJSON('/api/dns/log?limit=60&client=' + encodeURIComponent(client) + '&action=' + encodeURIComponent(action)).then(function (rowsData) {
      clear(tb);
      logFreshness(rowsData);
      if (!rowsData.length) tb.appendChild(el('tr', {}, el('td', { className: 'empty', text: 'No look-ups logged yet.', attrs: { colspan: 8 } })));
      rowsData.forEach(function (q) {
        var qt = String(q.qtype || ''), act = String(q.action || '');
        var why = reasonWords(q.reason);
        tb.appendChild(el('tr', {},
          el('td', { text: ago(q.ts), title: fmtTs(q.ts) }),
          clientCell(q),
          el('td', { className: 'wrap', text: q.qname }),
          el('td', { title: 'Record type ' + qt }, QTYPE_WORDS[qt] ? QTYPE_WORDS[qt] + ' ' : '', el('span', { className: 'tech-word', text: qt })),
          el('td', {}, badge(act, RESULT_WORDS[act] || act)),
          el('td', { className: 'wrap small' }, why && why !== q.reason ? why + ' ' : '', q.reason ? el('span', { className: 'tech-word', text: q.reason }) : null),
          el('td', { className: 'num', text: q.ms === null || q.ms === undefined ? '' : Number(q.ms).toFixed(1) + ' ms' }),
          el('td', {},
            el('button', { className: 'btn btn-sm btn-ok', text: 'Allow…', title: 'Always allow this site for every device (asks you to confirm)', data: { action: 'dns-override', domain: q.qname, op: 'allow', note: 'quick action', reputation: q.reputation || q.verdict || '' } }), ' ',
            el('button', { className: 'btn btn-sm btn-danger', text: 'Block', title: 'Always block this site for every device', data: { action: 'dns-override', domain: q.qname, op: 'deny', note: 'quick action' } }))));
      });
    }).catch(function () {});
  }
  /* A device named, not numbered: its name first and the address muted beside it. */
  function clientCell(q) {
    var name = q.device_label || q.client_label || '';
    if (!name || name === q.client) return el('td', { className: 'mono', text: q.client });
    return el('td', {}, el('span', { text: name }), el('span', { className: 'device-ip', text: q.client }));
  }
  function initDns() {
    var c = $('#chart-dns-hours');
    if (c && window.Charts) {
      getJSON('/api/dns/series?hours=24').then(function (series) {
        window.Charts.bar(c, { values: series.map(function (p) { return p.total; }), overlay: series.map(function (p) { return p.blocked; }), labels: series.map(function (p) { return hourLabel(p.hour); }), title: 'Look-ups per hour, with the blocked share drawn over each bar', height: 150, emptyText: 'No website look-ups in the last 24 hours' });
      }).catch(function () {});
    }
    ['#log-client', '#log-action'].forEach(function (sel) { var n = $(sel); if (n) { n.addEventListener('change', refreshDnsLog); n.addEventListener('input', refreshDnsLog); } });
    refreshDnsLog();
    setInterval(refreshDnsLog, REFRESH);
    var bar = $('#vt-budget-bar');
    if (bar) { var pct = Math.min(100, parseFloat(bar.dataset.pct || '0')); bar.style.width = pct + '%'; }
  }

  /* ---------- telemetry page ---------- */
  function renderMetrics(data) {
    var grid = $('#metrics-grid');
    if (!grid || !window.Charts) return;
    clear(grid);
    if (!data.names.length) {
      /* Say why it is empty. "The scheduler hasn't run its first job" is only true when the
         metrics table is truly empty; otherwise the window is simply shorter than the data's age. */
      var h = Number(data.hours) || 168;
      var windowWords = h % 24 === 0 && h >= 48 ? (h / 24) + ' days' : h + ' hours';
      var box = el('div', { className: 'chart-empty' });
      if (data.last_ts) {
        box.appendChild(el('span', { text: 'No measurements in the last ' + windowWords + ' — Home SOC last recorded one ' + ago(data.last_ts) + '.' }));
        var sel = $('#metrics-hours');
        if (sel && h < 720) {
          var more = el('button', { className: 'btn btn-sm', text: 'Show 30 days', attrs: { type: 'button' } });
          more.addEventListener('click', function () { sel.value = '720'; refreshMetrics(); });
          box.appendChild(more);
        }
      } else {
        box.appendChild(el('span', { text: 'No measurements recorded yet — they appear once the scheduler runs its first job.' }));
      }
      grid.appendChild(box);
      return;
    }
    data.names.forEach(function (name) {
      var pts = data.series[name] || [];
      var values = pts.map(function (p) { return p[1]; });
      var last = values[values.length - 1], min = Math.min.apply(null, values), max = Math.max.apply(null, values);
      var card = el('div', { className: 'metric' },
        el('div', { className: 'm-name', text: name, title: name }),
        el('div', { className: 'm-val', text: window.Charts.fmt(last) }),
        el('div', { className: 'm-range', text: pts.length + ' samples · min ' + window.Charts.fmt(min) + ' · max ' + window.Charts.fmt(max) + ' · last ' + ago(pts.length ? pts[pts.length - 1][0] : null) }));
      var chart = el('div', { className: 'chart' });
      card.appendChild(chart);
      grid.appendChild(card);
      window.Charts.sparkline(chart, values, { height: 48, title: name });
    });
  }
  function refreshMetrics() {
    var hours = ($('#metrics-hours') || {}).value || '168';
    return getJSON('/api/telemetry/metrics?hours=' + encodeURIComponent(hours)).then(renderMetrics).catch(function () {});
  }
  function refreshEvents() {
    var tb = $('#events-body');
    if (!tb) return;
    var level = ($('#events-level') || {}).value || '';
    getJSON('/api/telemetry/events?limit=150&level=' + encodeURIComponent(level)).then(function (events) {
      clear(tb);
      if (!events.length) tb.appendChild(el('li', { className: 'muted', text: 'No events yet.' }));
      events.forEach(function (e) { tb.appendChild(eventItem(e)); });
    }).catch(function () {});
  }
  function refreshJobs() {
    var tb = $('#jobs-body');
    if (!tb) return;
    getJSON('/api/telemetry/jobs').then(function (jobs) {
      clear(tb);
      if (!jobs.length) tb.appendChild(el('tr', {}, el('td', { className: 'empty', text: 'No jobs recorded yet.', attrs: { colspan: 8 } })));
      jobs.forEach(function (j) {
        tb.appendChild(el('tr', {},
          el('td', { className: 'mono', text: j.name }),
          el('td', {}, badge(j.last_status || 'never')),
          el('td', { text: ago(j.last_run), title: fmtTs(j.last_run) }),
          el('td', { className: 'num', text: j.last_duration_sec === null || j.last_duration_sec === undefined ? '' : Number(j.last_duration_sec).toFixed(1) + 's' }),
          el('td', { text: j.next_run ? ago(j.next_run) : '', title: fmtTs(j.next_run) }),
          el('td', { className: 'num', text: fmtNum(j.runs) }),
          el('td', { className: 'num', text: fmtNum(j.failures) }),
          el('td', { className: 'muted small wrap', text: j.last_error || '' })));
      });
    }).catch(function () {});
  }
  function initTelemetry() {
    var hs = $('#metrics-hours');
    if (hs) hs.addEventListener('change', refreshMetrics);
    var lv = $('#events-level');
    if (lv) lv.addEventListener('change', refreshEvents);
    refreshMetrics(); refreshEvents(); refreshJobs();
    setInterval(function () { refreshMetrics(); refreshEvents(); refreshJobs(); refreshScans(); }, REFRESH);
  }

  /* ---------- scans ---------- */
  /* A check's result, in the same words as _macros.html run_result. */
  var RUN_WORDS = { ok: 'Finished', error: 'Failed', partial: 'Partly finished', aborted: 'Stopped', running: 'Running now' };
  function refreshScans() {
    var tb = $('#scans-body');
    if (!tb) return;
    getJSON('/api/scans?limit=100').then(function (scans) {
      clear(tb);
      if (!scans.length) tb.appendChild(el('tr', {}, el('td', { className: 'empty', text: 'No scans yet.', attrs: { colspan: 6 } })));
      scans.forEach(function (s) {
        var summary = typeof s.summary === 'object' && s.summary ? Object.keys(s.summary).map(function (k) { return k + '=' + (typeof s.summary[k] === 'object' ? JSON.stringify(s.summary[k]) : s.summary[k]); }).join('  ') : (s.summary || '');
        var st = String(s.status || '').toLowerCase();
        tb.appendChild(el('tr', {},
          el('td', { className: 'mono', text: s.kind }),
          el('td', {}, el('span', { className: 'status-chip' }, badge(st, RUN_WORDS[st] || st || 'unknown'),
            RUN_WORDS[st] ? ' ' : null, RUN_WORDS[st] ? el('span', { className: 'tech-word', text: st }) : null)),
          el('td', { className: 'nowrap', text: fmtTs(s.started_at), title: s.started_at }),
          el('td', { className: 'num', text: s.duration_sec === null || s.duration_sec === undefined ? '' : s.duration_sec + 's' }),
          el('td', { className: 'muted small wrap', text: summary }),
          el('td', { className: 'small wrap error', text: s.error || '' })));
      });
    }).catch(function () {});
  }

  /* ---------- settings ---------- */
  function saveSettings() {
    var form = $('#settings-form');
    if (!form) return Promise.resolve();
    var data = {};
    $$('[name]', form).forEach(function (inp) {
      if (inp.type === 'checkbox') data[inp.name] = inp.checked;
      else if (inp.dataset.type === 'secret' && !inp.value) return;
      else data[inp.name] = inp.value;
    });
    return postJSON('/api/settings', data).then(function (r) {
      toast('Saved ' + r.saved.length + ' setting(s)' + (r.restart_required ? ' — restart Home SOC to apply' : ''), 'ok');
    }).catch(function (e) {
      var errs = e.body && e.body.errors ? Object.keys(e.body.errors).map(function (k) { return k + ': ' + e.body.errors[k]; }).join('; ') : e.message;
      toast('Not saved: ' + errs, 'err');
    });
  }
  function initSettings() {
    var form = $('#settings-form');
    if (form) form.addEventListener('submit', function (ev) { ev.preventDefault(); saveSettings(); });
  }

  /* ---------- defender status polling ---------- */
  /* The action shells out to MpCmdRun and can take a quarter of an hour, so the server answers 202
     immediately; we poll /api/defender/status instead of holding a request open. */
  var defenderTimers = {};
  function pollDefender(op) {
    if (defenderTimers[op]) return;
    var tries = 0;
    defenderTimers[op] = setInterval(function () {
      tries++;
      getJSON('/api/defender/status').then(function (s) {
        var job = (s.actions || {})[op] || {};
        if (job.running && tries < 240) return;
        clearInterval(defenderTimers[op]); delete defenderTimers[op];
        if (!job.running && job.finished_at) {
          toast('Defender ' + op + (job.ok ? ' finished' : ' failed' + (job.error ? ': ' + job.error : '')), job.ok ? 'ok' : 'err');
        }
      }).catch(function () { clearInterval(defenderTimers[op]); delete defenderTimers[op]; });
    }, 5000);
  }

  /* ---------- activity feed ---------- */
  var GLYPH = { finding: '▲', resolved: '✔', device: '▣', scan: '◎', feed: '⇩', dns: '⊘', threat: '☢', notify: '✉', system: '⚙' };
  var feedState = { newest: null, total: 0, paused: false, timer: null };

  var runSeq = 0;
  function feedItemNode(it, isNew) {
    var ref = it.ref || {};
    var repeats = Number(ref.count || 0);
    /* The severity's action word leads the title for medium and above, and is read out
       (visually hidden) for low and info — the same markup as feed.html — so colour is never
       the only signal. */
    var sv = String(it.severity || '').toLowerCase(), word = SEV_WORDS[sv] || '';
    var title = el('span', { className: 'tl-title' });
    if (word && (sv === 'critical' || sv === 'high' || sv === 'medium')) {
      title.appendChild(el('span', { className: 'tl-sev sev-word sev-word-' + sv, text: word, title: 'Severity: ' + sv }));
      title.appendChild(document.createTextNode(' · '));
    } else if (word) {
      title.appendChild(el('span', { className: 'visually-hidden', text: word + ' (' + sv + '): ' }));
    }
    title.appendChild(document.createTextNode(it.title || ''));
    var body = el('span', { className: 'tl-body' }, title);
    if (repeats > 1) {
      /* build_feed folded a run of identical events into this row; keep every one reachable. */
      var members = Array.isArray(ref.collapsed) ? ref.collapsed : [];
      var id = 'run-js-' + (runSeq++);
      title.appendChild(el('span', {
        className: 'tl-x', text: '×' + repeats,
        title: repeats + ' identical events between ' + fmtTs(ref.from) + ' and ' + fmtTs(ref.to)
      }));
      if (it.detail) body.appendChild(el('span', { className: 'tl-detail muted small', text: it.detail }));
      body.appendChild(el('button', {
        className: 'btn btn-sm tl-showall', text: 'show all ' + repeats,
        attrs: { type: 'button' }, data: { action: 'toggle', target: '#' + id, labelAlt: 'hide' }
      }));
      var runs = el('ol', { className: 'tl-runs', attrs: { id: id } });
      members.forEach(function (m) {
        var li = el('li', {}, el('span', { className: 'mono', text: fmtTs(m.ts) }), ' ', el('span', { className: 'muted small', text: ago(m.ts) }));
        if (m.link) { li.appendChild(document.createTextNode(' ')); li.appendChild(el('a', { className: 'link', href: m.link, text: 'open →' })); }
        runs.appendChild(li);
      });
      if (repeats > members.length) {
        runs.appendChild(el('li', { className: 'muted small', text: '…and ' + (repeats - members.length) + ' more.' }));
      }
      runs.hidden = true;
      body.appendChild(runs);
    } else if (it.detail) {
      body.appendChild(el('span', { className: 'tl-detail muted small', text: it.detail }));
    }
    if (it.link) body.appendChild(el('a', { className: 'tl-link link', href: it.link, text: 'open →' }));
    return el('li', { className: 'tl-item sev-' + it.severity + (isNew ? ' tl-new' : ''), data: { ts: it.ts, kind: it.kind, title: it.title } },
      el('span', { className: 'tl-glyph', text: GLYPH[it.icon] || '•', title: it.kind }),
      el('span', { className: 'tl-dot sev-dot-' + it.severity, title: sv + (word ? ' · ' + word : '') }),
      el('span', { className: 'tl-when', text: ago(it.ts), title: it.ts }),
      body);
  }
  function feedQuery(extra) {
    var p = new URLSearchParams(location.search);
    Object.keys(extra).forEach(function (k) {
      if (extra[k] === null || extra[k] === undefined || extra[k] === '') p.delete(k); else p.set(k, extra[k]);
    });
    return p.toString();
  }
  /* Identity key for a row. Read from data-title, not from the rendered title, because a
     collapsed row's title also carries its "xN" badge. */
  function feedKeys(list) {
    var seen = {};
    $$('.tl-item', list).forEach(function (n) {
      seen[n.dataset.ts + '|' + n.dataset.kind + '|' + (n.dataset.title || '')] = 1;
    });
    return seen;
  }
  function feedCount() { return $$('#feed-timeline .tl-item').length; }
  function feedStatus() {
    var n = $('#feed-status');
    if (n) n.textContent = feedCount() + ' of ' + feedState.total + ' shown';
    var more = $('#feed-more');
    if (more) more.hidden = feedCount() >= feedState.total;
  }
  function feedPoll() {
    var list = $('#feed-timeline');
    if (feedState.paused || !list || !feedState.newest) return;
    getJSON('/api/feed?' + feedQuery({ since: feedState.newest, offset: null, limit: 50 })).then(function (data) {
      var seen = feedKeys(list);
      var fresh = (data.items || []).filter(function (it) { return !seen[it.ts + '|' + it.kind + '|' + it.title]; });
      if (!fresh.length) return;
      var blank = $('.empty', list);
      if (blank) blank.remove();
      fresh.slice().reverse().forEach(function (it) { list.insertBefore(feedItemNode(it, true), list.firstChild); });
      if (fresh[0].ts > feedState.newest) feedState.newest = fresh[0].ts;
      feedState.total += fresh.length;
      feedStatus();
    }).catch(function () {});
  }
  function feedMore(btn) {
    var offset = parseInt(btn.dataset.offset || '0', 10) || 0;
    return getJSON('/api/feed?' + feedQuery({ offset: offset, since: null })).then(function (data) {
      var list = $('#feed-timeline');
      if (!list) return;
      var items = data.items || [];
      items.forEach(function (it) { list.appendChild(feedItemNode(it, false)); });
      feedState.total = data.total || feedState.total;
      btn.dataset.offset = String(offset + items.length);
      if (!items.length) btn.hidden = true;
      feedStatus();
    });
  }
  function initFeed() {
    var seed = $('#feed-state');
    if (seed) {
      try {
        var s = JSON.parse(seed.textContent);
        feedState.newest = s.newest || null;
        feedState.total = s.total || 0;
      } catch (e) { /* the server-rendered rows still stand on their own */ }
    }
    var pause = $('#feed-pause');
    if (pause) {
      pause.addEventListener('click', function () {
        feedState.paused = !feedState.paused;
        pause.dataset.paused = feedState.paused ? '1' : '0';
        pause.textContent = feedState.paused ? 'Resume auto-refresh' : 'Pause auto-refresh';
      });
    }
    var more = $('#feed-more');
    if (more) {
      more.addEventListener('click', function () {
        more.disabled = true;
        feedMore(more).catch(function (e) { toast(e.message || 'Could not load more', 'err'); }).then(function () { more.disabled = false; });
      });
    }
    feedStatus();
    feedState.timer = setInterval(feedPoll, Math.max(REFRESH, 5000));
  }

  /* ---------- summary page ---------- */
  function paginateTable(table, button) {
    if (!table || !button) return;
    var size = parseInt(table.dataset.pageSize || '25', 10) || 25;
    var all = $$('tbody > tr', table);
    var shown = size;
    function apply() {
      all.forEach(function (tr, i) { tr.hidden = i >= shown; });
      button.hidden = shown >= all.length;
      button.textContent = 'Show ' + Math.min(size, Math.max(0, all.length - shown)) + ' more of ' + all.length;
    }
    button.addEventListener('click', function () { shown += size; apply(); });
    apply();
  }
  function initSummary() {
    var seed = $('#summary-data'), C = window.Charts;
    if (!seed || !C) return;
    var data;
    try { data = JSON.parse(seed.textContent); } catch (e) { return; }
    var trend = data.trend || [];
    C.line($('#chart-summary-trend'), {
      series: [{ name: 'safety score', values: trend.map(function (p) { return p[1]; }), token: '--accent' }],
      labels: trend.map(function (p) { return p[0]; }),
      height: 170,
      title: 'Safety score over the window',
      emptyText: 'The trend appears once an hourly score sample has been recorded'
    });
    var bysev = data.by_severity || {};
    C.groupedBar($('#chart-found-remediated'), {
      groups: (data.severities || []).map(function (sv) {
        /* "Critical", not "critical": the axis reads like every other severity mention. */
        return {
          label: String(sv).charAt(0).toUpperCase() + String(sv).slice(1),
          values: [(bysev.open || {})[sv] || 0, (bysev.acknowledged || {})[sv] || 0, (bysev.resolved || {})[sv] || 0]
        };
      }),
      /* Status series in the status tokens, never in severity colours (from across a room the
         old chart read as "lots of High/Medium"). */
      series: [{ name: 'open (needs attention)', token: '--status-open' }, { name: 'acknowledged (seen)', token: '--status-ack' }, { name: 'resolved (fixed)', token: '--status-resolved' }],
      height: 190,
      title: 'Findings by severity and status',
      emptyText: 'Nothing has been found yet'
    });
    paginateTable($('#remediated-table'), $('#remediated-more'));
  }

  /* ---------- overview initial data ---------- */
  function initOverview() {
    var seed = $('#initial-summary');
    if (seed) {
      try { var s = JSON.parse(seed.textContent); lastSummary = s; renderHeader(s); renderOverview(s); } catch (e) { /* fall back to polling */ }
    }
  }

  /* ---------- boot ---------- */
  function boot() {
    initFilters(); initRowExpand(); initForms(); initActions();
    $$('table[data-filterable]').forEach(applyFilters);
    if (PAGE === 'overview') initOverview();
    if (PAGE === 'feed') initFeed();
    if (PAGE === 'summary') initSummary();
    if (PAGE === 'dns') initDns();
    if (PAGE === 'telemetry') initTelemetry();
    if (PAGE === 'scans') { refreshScans(); setInterval(refreshScans, REFRESH); }
    if (PAGE === 'settings') initSettings();
    if (PAGE !== 'login' && PAGE !== '404') {
      if (PAGE !== 'overview') refreshSummary();
      setInterval(refreshSummary, REFRESH);
    }
  }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', boot); else boot();
})();
