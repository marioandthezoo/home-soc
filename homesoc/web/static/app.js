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
    var neg = s < 0; s = Math.abs(s);
    var out = s >= 86400 ? Math.floor(s / 86400) + 'd' : s >= 3600 ? Math.floor(s / 3600) + 'h' : s >= 60 ? Math.floor(s / 60) + 'm' : s + 's';
    return neg ? 'in ' + out : out + ' ago';
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
      if (!ok && tr.nextElementSibling && tr.nextElementSibling.classList.contains('detail-row')) tr.nextElementSibling.hidden = true;
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
    $$('form[data-submit-on-change]').forEach(function (f) {
      $$('select', f).forEach(function (s) { s.addEventListener('change', function () { f.submit(); }); });
    });
  }
  function initRowExpand() {
    document.addEventListener('click', function (ev) {
      var tr = ev.target.closest('tr.expandable');
      if (!tr || ev.target.closest('a, button, input, select, textarea')) return;
      var next = tr.nextElementSibling;
      if (next && next.classList.contains('detail-row')) next.hidden = !next.hidden;
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
          if (sb) { sb.className = 'badge status-badge badge-' + status; sb.textContent = status; }
        }
        toast('Finding marked ' + status, 'ok');
        refreshSummary();
      });
    },
    'findings-ack-shown': function (b) {
      var table = $('#findings-table');
      if (!table) return Promise.resolve();
      var ids = $$('tbody > tr.expandable', table).filter(function (tr) { return !tr.hidden && tr.dataset.status === 'open'; }).map(function (tr) { return tr.dataset.id; });
      if (!ids.length) { toast('No open findings shown', 'ok'); return Promise.resolve(); }
      if (!window.confirm('Acknowledge ' + ids.length + ' open finding(s) currently shown?')) return Promise.resolve();
      var done = 0;
      return ids.reduce(function (p, id) {
        return p.then(function () { return postJSON('/api/findings/' + id + '/status', { status: 'acknowledged' }).then(function () { done++; }); });
      }, Promise.resolve()).then(function () {
        toast('Acknowledged ' + done + ' finding(s)', 'ok');
        setTimeout(function () { location.reload(); }, 400);
      });
    },
    'device-trusted': function (b) {
      var id = b.dataset.id, next = b.dataset.trusted !== '1';
      return postJSON('/api/devices/' + id, { trusted: next }).then(function () {
        b.dataset.trusted = next ? '1' : '0';
        b.textContent = next ? 'Trusted' : 'Untrusted';
        b.classList.toggle('btn-ok', next);
        toast('Device ' + (next ? 'trusted' : 'untrusted'), 'ok');
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
      return postJSON('/api/dns/override', { domain: b.dataset.domain, action: b.dataset.op, note: b.dataset.note || 'from dashboard' }).then(function (r) {
        toast(r.domain + ' → ' + r.action, 'ok');
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
  function renderHeader(s) {
    bind('score', s.score); bind('grade', s.grade);
    var chip = $('#chip-score');
    if (chip) chip.className = 'chip grade-' + s.grade;
    bind('open-total', openTotal(s.counts));
    bind('devices-online', s.devices.online); bind('devices-total', s.devices.total);
    bind('dns-total', fmtNum(s.dns.total24h)); bind('dns-blocked', fmtNum(s.dns.blocked24h));
    bind('dns-pct', s.dns.blocked_pct); bind('dns-clients', s.dns.clients24h);
    var dot = $('#dot-dns');
    if (dot) dot.className = 'dot ' + (s.dns.running ? 'on' : (s.dns.enabled ? 'off' : ''));
    var st = $('#chip-dns-state');
    if (st) st.textContent = s.dns.running ? 'running' : (s.dns.enabled ? 'enabled, not running' : 'off');
    var lr = $('#last-refresh');
    if (lr) lr.textContent = 'updated ' + new Date().toLocaleTimeString();
    renderScoreBreakdown(s.score_breakdown);
  }
  /* "Fix these first": the open findings costing the score the most, from
     findings.score.score_breakdown via /api/summary. Rendered on the Overview (where the
     server also renders it, so it survives a broken poll) and on the Summary page. */
  function renderScoreBreakdown(items) {
    var list = $('#score-breakdown');
    if (!list) return;
    items = Array.isArray(items) ? items : [];
    clear(list);
    var note = $('#score-breakdown-note');
    if (note) note.hidden = !items.length;
    if (!items.length) {
      list.appendChild(el('li', {
        className: 'empty',
        text: 'Nothing is costing you points. Either everything found is fixed, acknowledged or suppressed, or no scan has run yet.'
      }));
      return;
    }
    items.forEach(function (b) {
      var sev = String(b.severity || 'info');
      var row = el('li', { className: 'cost' },
        el('span', { className: 'tl-dot sev-dot-' + sev, title: sev }),
        el('a', {
          className: 'cost-title',
          text: b.title || b.finding_id,
          title: (b.finding_id || '') + ' — ' + (b.title || ''),
          href: '/findings?status=open&q=' + encodeURIComponent(b.finding_id || '')
        }));
      row.appendChild(b.count > 1
        ? el('span', { className: 'cost-count', text: '×' + b.count, title: b.count + ' findings of this type are open' })
        : el('span', {}));
      row.appendChild(el('span', {
        className: 'cost-gain',
        text: '+' + (b.gain === undefined || b.gain === null ? b.penalty : b.gain),
        title: 'the score would rise by about this much once every finding of this type is cleared'
      }));
      list.appendChild(row);
    });
  }
  function renderOverview(s) {
    var C = window.Charts;
    if (!C) return;
    var g = $('#chart-gauge');
    if (g) C.gauge(g, s.score, { label: 'grade ' + s.grade, title: 'Security score ' + s.score });
    var tr = $('#chart-trend');
    if (tr) C.sparkline(tr, (s.trend || []).map(function (p) { return p[1]; }), { title: '30-day score trend', emptyText: 'Trend appears after the first hourly score sample' });
    var d = $('#chart-severity');
    if (d) {
      var open = (s.counts && s.counts.open) || {};
      var slices = ['critical', 'high', 'medium', 'low', 'info'].map(function (k) { return { label: k, value: open[k] || 0 }; });
      C.donut(d, slices, { centerText: openTotal(s.counts), centerSub: 'open', legendAll: slices, title: 'Open findings by severity' });
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
    if (ev) { clear(ev); s.events.forEach(function (e) { ev.appendChild(eventItem(e)); }); if (!s.events.length) ev.appendChild(el('li', { className: 'muted', text: 'No events yet.' })); }
    getJSON('/api/dns/series?hours=24').then(function (series) {
      var c = $('#chart-dns');
      if (c) C.bar(c, { values: series.map(function (p) { return p.total; }), overlay: series.map(function (p) { return p.blocked; }), labels: series.map(function (p) { return hourLabel(p.hour); }), title: 'DNS queries per hour (blocked in red)', height: 130, emptyText: 'No DNS queries yet' });
    }).catch(function () {});
  }
  function eventItem(e) {
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
  function refreshDnsLog() {
    var tb = $('#log-body');
    if (!tb) return;
    var client = ($('#log-client') || {}).value || '', action = ($('#log-action') || {}).value || '';
    getJSON('/api/dns/log?limit=60&client=' + encodeURIComponent(client) + '&action=' + encodeURIComponent(action)).then(function (rowsData) {
      clear(tb);
      if (!rowsData.length) tb.appendChild(el('tr', {}, el('td', { className: 'empty', text: 'No queries logged yet.', attrs: { colspan: 8 } })));
      rowsData.forEach(function (q) {
        tb.appendChild(el('tr', {},
          el('td', { text: fmtTs(q.ts), title: q.ts }),
          el('td', { text: q.client }),
          el('td', { className: 'wrap', text: q.qname }),
          el('td', { text: q.qtype }),
          el('td', {}, badge(q.action)),
          el('td', { className: 'muted', text: q.reason || '' }),
          el('td', { className: 'num', text: q.ms === null || q.ms === undefined ? '' : Number(q.ms).toFixed(1) }),
          el('td', {},
            el('button', { className: 'btn btn-sm btn-ok', text: 'allow', data: { action: 'dns-override', domain: q.qname, op: 'allow', note: 'quick action' } }), ' ',
            el('button', { className: 'btn btn-sm btn-danger', text: 'block', data: { action: 'dns-override', domain: q.qname, op: 'deny', note: 'quick action' } }))));
      });
    }).catch(function () {});
  }
  function initDns() {
    var c = $('#chart-dns-hours');
    if (c && window.Charts) {
      getJSON('/api/dns/series?hours=24').then(function (series) {
        window.Charts.bar(c, { values: series.map(function (p) { return p.total; }), overlay: series.map(function (p) { return p.blocked; }), labels: series.map(function (p) { return hourLabel(p.hour); }), title: 'DNS queries per hour', height: 150, emptyText: 'No DNS queries yet' });
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
    if (!data.names.length) { grid.appendChild(el('div', { className: 'chart-empty', text: 'No metrics recorded yet — they appear once the scheduler runs its first job.' })); return; }
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
  function refreshScans() {
    var tb = $('#scans-body');
    if (!tb) return;
    getJSON('/api/scans?limit=100').then(function (scans) {
      clear(tb);
      if (!scans.length) tb.appendChild(el('tr', {}, el('td', { className: 'empty', text: 'No scans yet.', attrs: { colspan: 6 } })));
      scans.forEach(function (s) {
        var summary = typeof s.summary === 'object' && s.summary ? Object.keys(s.summary).map(function (k) { return k + '=' + (typeof s.summary[k] === 'object' ? JSON.stringify(s.summary[k]) : s.summary[k]); }).join('  ') : (s.summary || '');
        tb.appendChild(el('tr', {},
          el('td', { className: 'mono', text: s.kind }),
          el('td', {}, badge(s.status)),
          el('td', { text: fmtTs(s.started_at), title: s.started_at }),
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
    var title = el('span', { className: 'tl-title', text: it.title });
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
      el('span', { className: 'tl-dot sev-dot-' + it.severity, title: it.severity }),
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
    var col = C.colors();
    var trend = data.trend || [];
    C.line($('#chart-summary-trend'), {
      series: [{ name: 'score', values: trend.map(function (p) { return p[1]; }), color: col.accent }],
      labels: trend.map(function (p) { return p[0]; }),
      height: 170,
      title: 'Security score over the window',
      emptyText: 'The trend appears once an hourly score sample has been recorded'
    });
    var bysev = data.by_severity || {};
    C.groupedBar($('#chart-found-remediated'), {
      groups: (data.severities || []).map(function (sv) {
        return {
          label: sv,
          values: [(bysev.open || {})[sv] || 0, (bysev.acknowledged || {})[sv] || 0, (bysev.resolved || {})[sv] || 0]
        };
      }),
      series: [{ name: 'open', color: col.high }, { name: 'acknowledged', color: col.medium }, { name: 'resolved', color: col.low }],
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
