/* charts.js — dependency-free SVG charts for the Home SOC dashboard.
   Colors are read from CSS variables at draw time so both themes work; every chart is
   re-drawn automatically when the color scheme flips. No inline styles (CSP default-src 'self').

   SIZING RULE — read before adding a chart.
   Axis charts (bar, groupedBar, line, sparkline) size their viewBox to the container's own
   pixel width at draw time, so one user unit is one CSS pixel: a 10-unit label renders as 10px
   whether the card is 230px or 900px wide, and the SVG can never be wider than its card. They
   are redrawn by a ResizeObserver when that width changes.
   Aspect-locked charts (gauge, donut) keep a fixed viewBox and are pinned to a fixed CSS size
   in style.css. Never give an SVG a width/height that its parent has not agreed to. */
(function (global) {
  'use strict';

  var NS = 'http://www.w3.org/2000/svg';
  var registry = new Map(); // container -> draw()

  /* Below MIN_WIDTH the axes stop making sense, so the chart is drawn at MIN_WIDTH and scaled
     down instead (labels shrink, nothing overflows). Above MIN_WIDTH the viewBox matches the
     container exactly and one user unit is one CSS pixel. */
  var MIN_WIDTH = 180;
  var MAX_WIDTH = 1400;

  function cssVar(name, fallback) {
    var v = getComputedStyle(document.documentElement).getPropertyValue(name).trim();
    return v || fallback;
  }

  function colors() {
    var c = {
      fg: cssVar('--fg', '#e6e8ef'),
      muted: cssVar('--muted', '#8b91a3'),
      grid: cssVar('--line', '#262a36'),
      panel: cssVar('--panel', '#171a23'),
      accent: cssVar('--accent', '#3e63dd'),
      critical: cssVar('--sev-critical', '#e5484d'),
      high: cssVar('--sev-high', '#f76b15'),
      medium: cssVar('--sev-medium', '#ffb224'),
      low: cssVar('--sev-low', '#46a758'),
      info: cssVar('--sev-info', '#3e63dd')
    };
    c.palette = [c.accent, c.low, c.medium, c.high, c.critical, '#8e4ec6', '#12a594', '#e93d82', '#ad7f58'];
    return c;
  }

  function node(name, attrs, text) {
    var e = document.createElementNS(NS, name);
    if (attrs) {
      Object.keys(attrs).forEach(function (k) {
        if (attrs[k] !== null && attrs[k] !== undefined) e.setAttribute(k, attrs[k]);
      });
    }
    if (text !== undefined && text !== null) e.textContent = String(text);
    return e;
  }

  function svg(w, h, label, cls) {
    var s = node('svg', { viewBox: '0 0 ' + w + ' ' + h, preserveAspectRatio: 'xMidYMid meet', 'class': cls || 'chart-svg', role: 'img' });
    if (label) s.appendChild(node('title', null, label));
    return s;
  }

  /* The container's laid-out width, which becomes the chart's user-unit width. Falls back to a
     sensible default when there is no layout yet (first paint, a hidden tab, jsdom). */
  function boxWidth(container) {
    var w = 0;
    if (container) {
      try { w = Math.round(container.getBoundingClientRect().width); } catch (e) { w = 0; }
      if (!w) w = container.clientWidth || 0;
    }
    if (!w) return 600;
    return Math.max(MIN_WIDTH, Math.min(MAX_WIDTH, w));
  }

  /* Approximate rendered width of `text` at `size` px in the UI font — good enough to decide
     how many axis labels fit and whether one needs truncating. */
  function textWidth(text, size) {
    return String(text === null || text === undefined ? '' : text).length * size * 0.56;
  }

  function fitText(text, size, available) {
    text = String(text === null || text === undefined ? '' : text);
    if (textWidth(text, size) <= available) return text;
    var keep = Math.max(1, Math.floor(available / (size * 0.56)) - 1);
    return text.slice(0, keep) + '…';
  }

  function fmt(n) {
    if (n === null || n === undefined || isNaN(n)) return '–';
    var a = Math.abs(n);
    if (a >= 1e6) return (n / 1e6).toFixed(1).replace(/\.0$/, '') + 'M';
    if (a >= 1e4) return (n / 1e3).toFixed(1).replace(/\.0$/, '') + 'k';
    if (a >= 100 || Number.isInteger(n)) return String(Math.round(n));
    return n.toFixed(a >= 10 ? 1 : 2);
  }

  function niceMax(v) {
    if (v <= 0) return 1;
    var p = Math.pow(10, Math.floor(Math.log10(v)));
    var m = v / p;
    var n = m <= 1 ? 1 : m <= 2 ? 2 : m <= 5 ? 5 : 10;
    return n * p;
  }

  /* Redraw a width-driven chart when its card resizes (window resize, sidebar collapse,
     a filter row wrapping). Guarded on the width actually changing so the observer can never
     feed itself: drawing changes the container's height, never its width. */
  var observer = null;
  if (global.ResizeObserver) {
    observer = new global.ResizeObserver(function (entries) {
      for (var i = 0; i < entries.length; i++) {
        var container = entries[i].target;
        var draw = registry.get(container);
        if (!draw) continue;
        var w = boxWidth(container);
        if (w === container.__chartWidth) continue;
        render(container, draw);
      }
    });
  }

  function render(container, draw) {
    container.__chartWidth = boxWidth(container);
    container.textContent = '';
    var out = draw();
    if (out) container.appendChild(out);
  }

  function mount(container, draw) {
    if (!container) return;
    var known = registry.has(container);
    registry.set(container, draw);
    render(container, draw);
    if (observer && !known) {
      try { observer.observe(container); } catch (e) { /* detached node: nothing to observe */ }
    }
  }

  function empty(text) {
    var d = document.createElement('div');
    d.className = 'chart-empty';
    d.textContent = text || 'No data yet';
    return d;
  }

  /* ---- bar chart: values (+ optional overlay, e.g. blocked over total) ---- */
  function bar(container, opts) {
    mount(container, function () {
      var c = colors();
      var values = opts.values || [];
      var overlay = opts.overlay || null;
      var labels = opts.labels || [];
      if (!values.length) return empty(opts.emptyText);
      var W = boxWidth(container), H = opts.height || 150, padL = 36, padR = 6, padT = 8, padB = 20;
      var s = svg(W, H, opts.title);
      var max = niceMax(Math.max.apply(null, values.concat([1])));
      var innerW = W - padL - padR, innerH = H - padT - padB;
      var n = values.length, slot = innerW / n, bw = Math.max(2, slot * 0.7);
      [0, 0.5, 1].forEach(function (f) {
        var y = padT + innerH - innerH * f;
        s.appendChild(node('line', { x1: padL, x2: W - padR, y1: y, y2: y, stroke: c.grid, 'stroke-width': 1 }));
        s.appendChild(node('text', { x: padL - 5, y: y + 4, 'text-anchor': 'end', 'font-size': 10, fill: c.muted }, fmt(max * f)));
      });
      /* Only label as many ticks as actually fit, so "14:00" never collides with "15:00". */
      var widest = labels.reduce(function (a, l) { return Math.max(a, textWidth(l, 10)); }, 24);
      var every = Math.max(1, Math.ceil(n / Math.max(2, Math.floor(innerW / (widest + 8)))));
      values.forEach(function (v, i) {
        var x = padL + i * slot + (slot - bw) / 2;
        var h = innerH * (v / max);
        var g = node('g');
        var tip = (labels[i] !== undefined ? labels[i] + ': ' : '') + fmt(v) + (overlay ? ' (' + fmt(overlay[i] || 0) + ' ' + (opts.overlayLabel || 'blocked') + ')' : '');
        g.appendChild(node('title', null, tip));
        g.appendChild(node('rect', { x: x, y: padT + innerH - h, width: bw, height: h, rx: 2, fill: opts.color || c.accent, opacity: overlay ? 0.55 : 1 }));
        if (overlay) {
          var oh = innerH * ((overlay[i] || 0) / max);
          g.appendChild(node('rect', { x: x, y: padT + innerH - oh, width: bw, height: oh, rx: 2, fill: opts.overlayColor || c.critical }));
        }
        s.appendChild(g);
        if (labels[i] !== undefined && i % every === 0) {
          s.appendChild(node('text', { x: x + bw / 2, y: H - 6, 'text-anchor': 'middle', 'font-size': 10, fill: c.muted }, labels[i]));
        }
      });
      return s;
    });
  }

  /* ---- grouped bar chart: one cluster of bars per group (found / remediated / open) ----
     opts = { groups: [{label, values: [n, ...]}], series: [{name, color}], height, title, emptyText } */
  function groupedBar(container, opts) {
    mount(container, function () {
      var c = colors();
      var groups = opts.groups || [];
      var series = opts.series || [];
      var any = groups.some(function (g) { return (g.values || []).some(function (v) { return v > 0; }); });
      if (!groups.length || !series.length || !any) return empty(opts.emptyText);
      var W = boxWidth(container), padL = 36, padR = 8, padT = 10;
      /* Lay the legend out first: it may need two rows on a narrow card, and the plot area
         has to give up the height rather than let the swatches spill past the SVG. */
      var legend = layoutLegend(series, W - padL - padR, c);
      var legendBand = legend.rows * 16, padB = 14 + legendBand + 6;
      var H = Math.max(opts.height || 190, padT + 60 + padB);
      var s = svg(W, H, opts.title);
      var flat = [];
      groups.forEach(function (g) { flat = flat.concat(g.values || []); });
      var max = niceMax(Math.max.apply(null, flat.concat([1])));
      var innerW = W - padL - padR, innerH = H - padT - padB;
      /* counts are whole numbers: skip the half-way tick when it would read "0.50" */
      (max >= 2 ? [0, 0.5, 1] : [0, 1]).forEach(function (f) {
        var y = padT + innerH - innerH * f;
        s.appendChild(node('line', { x1: padL, x2: W - padR, y1: y, y2: y, stroke: c.grid, 'stroke-width': 1 }));
        s.appendChild(node('text', { x: padL - 5, y: y + 4, 'text-anchor': 'end', 'font-size': 10, fill: c.muted }, fmt(Math.round(max * f))));
      });
      var slot = innerW / groups.length, inner = slot * 0.78, bw = Math.max(3, inner / series.length - 2);
      groups.forEach(function (g, gi) {
        var x0 = padL + gi * slot + (slot - inner) / 2;
        (g.values || []).forEach(function (v, si) {
          var x = x0 + si * (inner / series.length);
          var h = innerH * ((v || 0) / max);
          var rect = node('rect', {
            x: x.toFixed(1), y: (padT + innerH - h).toFixed(1), width: bw.toFixed(1), height: Math.max(0, h).toFixed(1),
            rx: 2, fill: (series[si] && series[si].color) || c.palette[si % c.palette.length]
          });
          rect.appendChild(node('title', null, g.label + ' · ' + ((series[si] && series[si].name) || '') + ': ' + fmt(v || 0)));
          s.appendChild(rect);
        });
        var label = node('text', { x: (x0 + inner / 2).toFixed(1), y: (H - padB + 11).toFixed(1), 'text-anchor': 'middle', 'font-size': 10, fill: c.muted }, fitText(g.label, 10, slot - 2));
        label.appendChild(node('title', null, g.label));
        s.appendChild(label);
      });
      legend.items.forEach(function (it) {
        var y = H - legendBand + it.row * 16 + 11;
        s.appendChild(node('rect', { x: (padL + it.x).toFixed(1), y: (y - 8).toFixed(1), width: 9, height: 9, rx: 2, fill: it.color }));
        s.appendChild(node('text', { x: (padL + it.x + 13).toFixed(1), y: y.toFixed(1), 'font-size': 10, fill: c.muted }, it.name));
      });
      return s;
    });
  }

  /* Legend rows for groupedBar: [{name, color, x, row}] plus the row count, wrapped to `width`. */
  function layoutLegend(series, width, c) {
    var items = [], x = 0, row = 0;
    series.forEach(function (sr, si) {
      var name = String(sr.name || '');
      var w = 13 + textWidth(name, 10) + 12;
      if (x > 0 && x + w > width) { x = 0; row += 1; }
      items.push({ name: name, color: sr.color || c.palette[si % c.palette.length], x: x, row: row });
      x += w;
    });
    return { items: items, rows: row + 1 };
  }

  /* ---- line chart: one or more series of numbers (index-spaced) ---- */
  function line(container, opts) {
    mount(container, function () {
      var c = colors();
      var series = (opts.series || []).filter(function (sr) { return sr.values && sr.values.length; });
      if (!series.length) return empty(opts.emptyText);
      var W = boxWidth(container), H = opts.height || 150, padL = 40, padR = 8, padT = 8, padB = opts.labels ? 20 : 8;
      var s = svg(W, H, opts.title);
      var all = [];
      series.forEach(function (sr) { all = all.concat(sr.values); });
      var max = niceMax(Math.max.apply(null, all)), min = Math.min.apply(null, all.concat([0]));
      if (max === min) max = min + 1;
      var innerW = W - padL - padR, innerH = H - padT - padB;
      var len = Math.max.apply(null, series.map(function (sr) { return sr.values.length; }));
      var xs = function (i) { return padL + (len < 2 ? innerW / 2 : innerW * i / (len - 1)); };
      var ys = function (v) { return padT + innerH - innerH * (v - min) / (max - min); };
      [0, 0.5, 1].forEach(function (f) {
        var v = min + (max - min) * f, y = ys(v);
        s.appendChild(node('line', { x1: padL, x2: W - padR, y1: y, y2: y, stroke: c.grid }));
        s.appendChild(node('text', { x: padL - 5, y: y + 4, 'text-anchor': 'end', 'font-size': 10, fill: c.muted }, fmt(v)));
      });
      series.forEach(function (sr, si) {
        var color = sr.color || c.palette[si % c.palette.length];
        var pts = sr.values.map(function (v, i) { return xs(i).toFixed(1) + ',' + ys(v).toFixed(1); });
        if (sr.values.length === 1) {
          s.appendChild(node('circle', { cx: xs(0), cy: ys(sr.values[0]), r: 3, fill: color }));
        } else {
          s.appendChild(node('polyline', { points: pts.join(' '), fill: 'none', stroke: color, 'stroke-width': 2, 'stroke-linejoin': 'round' }));
        }
        var last = sr.values[sr.values.length - 1];
        var dot = node('circle', { cx: xs(sr.values.length - 1), cy: ys(last), r: 3, fill: color });
        dot.appendChild(node('title', null, (sr.name ? sr.name + ': ' : '') + fmt(last)));
        s.appendChild(dot);
      });
      if (opts.labels && opts.labels.length) {
        var room = (innerW - 12) / 2;
        s.appendChild(node('text', { x: padL, y: H - 5, 'font-size': 10, fill: c.muted }, fitText(opts.labels[0], 10, room)));
        if (opts.labels.length > 1) {
          s.appendChild(node('text', { x: W - padR, y: H - 5, 'text-anchor': 'end', 'font-size': 10, fill: c.muted }, fitText(opts.labels[opts.labels.length - 1], 10, room)));
        }
      }
      return s;
    });
  }

  /* ---- sparkline: tiny area+line, no axes ---- */
  function sparkline(container, values, opts) {
    opts = opts || {};
    mount(container, function () {
      var c = colors();
      values = (values || []).filter(function (v) { return typeof v === 'number' && !isNaN(v); });
      if (values.length < 1) return empty(opts.emptyText || 'No history yet');
      var W = boxWidth(container), H = opts.height || 40, pad = 3;
      var s = svg(W, H, opts.title);
      var max = Math.max.apply(null, values), min = Math.min.apply(null, values);
      if (max === min) { max += 1; min -= 1; }
      var n = values.length;
      var xs = function (i) { return n < 2 ? W / 2 : pad + (W - 2 * pad) * i / (n - 1); };
      var ys = function (v) { return pad + (H - 2 * pad) * (1 - (v - min) / (max - min)); };
      var color = opts.color || c.accent;
      var pts = values.map(function (v, i) { return xs(i).toFixed(1) + ',' + ys(v).toFixed(1); });
      if (n > 1) {
        s.appendChild(node('polygon', { points: [xs(0) + ',' + (H - pad)].concat(pts, [xs(n - 1) + ',' + (H - pad)]).join(' '), fill: color, opacity: 0.15 }));
        s.appendChild(node('polyline', { points: pts.join(' '), fill: 'none', stroke: color, 'stroke-width': 1.6 }));
      }
      var dot = node('circle', { cx: xs(n - 1), cy: ys(values[n - 1]), r: 2.5, fill: color });
      dot.appendChild(node('title', null, fmt(values[n - 1])));
      s.appendChild(dot);
      return s;
    });
  }

  /* ---- donut with legend ---- */
  function donut(container, slices, opts) {
    opts = opts || {};
    mount(container, function () {
      var c = colors();
      slices = (slices || []).filter(function (sl) { return sl.value > 0; });
      var total = slices.reduce(function (a, sl) { return a + sl.value; }, 0);
      var wrap = document.createElement('div');
      wrap.className = 'chart-wrap';
      var size = 120, r = 46, cx = size / 2, cy = size / 2, C = 2 * Math.PI * r;
      /* Its own class: `.chart-svg` alone would also match the 10x10 legend swatches below,
         and any rule sizing the ring would blow them up to the same size. */
      var s = svg(size, size, opts.title, 'chart-svg chart-ring');
      s.appendChild(node('circle', { cx: cx, cy: cy, r: r, fill: 'none', stroke: c.grid, 'stroke-width': 14 }));
      var offset = 0;
      slices.forEach(function (sl, i) {
        var len = C * sl.value / total;
        var circ = node('circle', {
          cx: cx, cy: cy, r: r, fill: 'none', stroke: sl.color || c[sl.label] || c.palette[i % c.palette.length],
          'stroke-width': 14, 'stroke-dasharray': len.toFixed(2) + ' ' + (C - len).toFixed(2),
          'stroke-dashoffset': (-offset + C / 4).toFixed(2)
        });
        circ.appendChild(node('title', null, sl.label + ': ' + fmt(sl.value)));
        s.appendChild(circ);
        offset += len;
      });
      s.appendChild(node('text', { x: cx, y: cy + 2, 'text-anchor': 'middle', 'font-size': 22, 'font-weight': 700, fill: c.fg }, opts.centerText !== undefined ? opts.centerText : fmt(total)));
      s.appendChild(node('text', { x: cx, y: cy + 18, 'text-anchor': 'middle', 'font-size': 10, fill: c.muted }, opts.centerSub || ''));
      wrap.appendChild(s);
      var ul = document.createElement('ul');
      ul.className = 'legend';
      (opts.legendAll || slices).forEach(function (sl, i) {
        var li = document.createElement('li');
        var sw = document.createElement('span');
        sw.className = 'sw';
        var swSvg = svg(10, 10, null, 'legend-swatch');
        swSvg.appendChild(node('rect', { width: 10, height: 10, rx: 2, fill: sl.color || c[sl.label] || c.palette[i % c.palette.length] }));
        sw.appendChild(swSvg);
        var lb = document.createElement('span');
        lb.className = 'lb';
        lb.textContent = sl.label;
        lb.title = sl.label;
        var lv = document.createElement('span');
        lv.className = 'lv';
        lv.textContent = fmt(sl.value);
        li.appendChild(sw); li.appendChild(lb); li.appendChild(lv);
        ul.appendChild(li);
      });
      wrap.appendChild(ul);
      return wrap;
    });
  }

  /* ---- gauge: half ring, colored by value ---- */
  function gauge(container, value, opts) {
    opts = opts || {};
    mount(container, function () {
      var c = colors();
      var max = opts.max || 100;
      var v = Math.max(0, Math.min(max, Number(value) || 0));
      var W = 200, H = 115, cx = 100, cy = 100, r = 78, sw = 16;
      var s = svg(W, H, opts.title || ('Score ' + v), 'chart-svg chart-dial');
      var arc = function (frac) {
        var a = Math.PI * (1 - frac);
        return { x: cx + r * Math.cos(a), y: cy - r * Math.sin(a) };
      };
      var d = function (frac) {
        var e = arc(frac);
        return 'M ' + (cx - r) + ' ' + cy + ' A ' + r + ' ' + r + ' 0 ' + (frac > 0.5 ? 1 : 0) + ' 1 ' + e.x.toFixed(2) + ' ' + e.y.toFixed(2);
      };
      var frac = v / max;
      var color = frac >= 0.8 ? c.low : frac >= 0.6 ? c.medium : frac >= 0.4 ? c.high : c.critical;
      s.appendChild(node('path', { d: d(1), fill: 'none', stroke: c.grid, 'stroke-width': sw, 'stroke-linecap': 'round' }));
      if (frac > 0.001) s.appendChild(node('path', { d: d(frac), fill: 'none', stroke: color, 'stroke-width': sw, 'stroke-linecap': 'round' }));
      s.appendChild(node('text', { x: cx, y: cy - 8, 'text-anchor': 'middle', 'font-size': 34, 'font-weight': 700, fill: c.fg }, Math.round(v)));
      s.appendChild(node('text', { x: cx, y: cy + 10, 'text-anchor': 'middle', 'font-size': 12, fill: color, 'font-weight': 600 }, opts.label || ''));
      return s;
    });
  }

  function redrawAll() {
    registry.forEach(function (draw, container) {
      if (!document.body.contains(container)) {
        registry.delete(container);
        if (observer) { try { observer.unobserve(container); } catch (e) { /* already gone */ } }
        return;
      }
      render(container, draw);
    });
  }

  if (global.matchMedia) {
    var mq = global.matchMedia('(prefers-color-scheme: dark)');
    if (mq.addEventListener) mq.addEventListener('change', redrawAll);
    else if (mq.addListener) mq.addListener(redrawAll);
  }

  global.Charts = { bar: bar, groupedBar: groupedBar, line: line, sparkline: sparkline, donut: donut, gauge: gauge, colors: colors, redrawAll: redrawAll, fmt: fmt };
})(window);
