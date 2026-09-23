/* graph.js — the dependency map (SPEC addendum C7). Hand-rolled SVG, no libraries, no CDN,
   following the static/charts.js precedent: elements built with createElementNS, colours read
   from CSS classes so both themes work, and every piece of text set with textContent so nothing
   out of the database can ever be parsed as markup.

   THE RULE THIS FILE EXISTS TO KEEP. Home SOC has no packet visibility, so it cannot know that
   two devices on the LAN talk to each other. This renderer therefore draws *exactly* the edges
   it was given and nothing else: no "probably prints to", no implied fan-out from a provider to
   everything that might use it. If an edge is not in the payload it is not on the screen, and
   every edge that is on the screen is drawn in the style of the confidence it arrived with.

   LAYOUT IS DETERMINISTIC. Positions are a pure function of the payload: fixed geometry, a
   stable initial ordering (criticality, then label, then id) and a fixed number of barycentre
   passes whose sorts are stable. The same data draws the same picture on every machine, at
   every window size — the container scrolls, the layout never reflows. */
(function (global) {
  'use strict';

  var NS = 'http://www.w3.org/2000/svg';

  /* ---- geometry (user units == CSS pixels; the canvas scrolls rather than reflowing) ---- */
  var PAD_X = 10, PAD_Y = 24;
  var GAP = 34;                 // between a column's labels and the next column's nodes
                                // (wide enough to hold a bundle's trunk without crossing them)
  /* Widest a label may be before it is truncated (the tooltip keeps the full text).
     104 cut five of the map's own nouns mid-word for the whole scene — "Home SOC DNS fi…",
     "Living room spe…", "15 blocked doma…", "9 external serv…" — including the two the page
     asks the reader to read. The columns are laid out from the widest label each one actually
     needs, and the infrastructure and external columns already reserve MAX_SUBLABEL, so
     raising this to 126 costs width in the devices column alone. */
  var MAX_LABEL = 126;
  var MAX_SUBLABEL = 124;       // the second line gets more room: C2.5's "no confirmed consumers"
                                // is 22 characters and must never be the half that gets cut off
  var OFFLINE_SUFFIX = ' (offline)';
  var LABEL_SIZE = 11.5;
  var ROW_MAX = 34, ROW_MIN = 24, ROW_BUDGET = 620;
  var R_MIN = 8, R_MAX = 16;
  var BUNDLE_MIN = 5;           // edges into one node before they are routed as a bus
  var CORNER = 8, LANE = 7;
  var BARYCENTRE_PASSES = 4;

  /* Plain column names (DESIGN §8.3). The technical names stay in each heading's tooltip. */
  var COLUMN_TITLES = ['The internet', 'Your router', 'Shared services', 'Your devices', 'Outside services'];
  var COLUMN_TECH = ['internet', 'default gateway', 'infrastructure', 'devices', 'external services'];
  /* A duplicated service label ("AirPlay" offered by two speakers) gets its host appended, so
     the two rows can be told apart without a tooltip; it may use this much more room. */
  var MAX_LABEL_WIDE = 290;
  /* What a link means, in words. Never "connection": Home SOC cannot see devices talking to
     each other (SPEC_TOPOLOGY C1); these are the reasons it believes one relies on another. The
     edge_type token stays in the tooltip for the owner. */
  var EDGE_WORDS = {
    gateway: 'reaches the internet through it', internet: 'the way out to the internet',
    dns: 'asks it to look up website names', cloud: 'looks up this online service',
    uses: 'uses a service it announces', hosted_by: 'runs on it',
    cloud_blocked: 'looked it up and web blocking refused'
  };
  var SEV_LETTER = { critical: 'C', high: 'H', medium: 'M', low: 'L', info: 'i' };
  var KIND_WORD = {
    device: 'device', internet: 'the internet', resolver: 'DNS resolver',
    cloud: 'external service', provider: 'offered service', hub: 'hub'
  };
  /* The same words with the article they need mid-sentence, so the panel does not say
     "This is device" or "This is external service". */
  var KIND_PHRASE = {
    device: 'a device', internet: 'the internet', resolver: 'the DNS resolver',
    cloud: 'an external service', provider: 'a service offered by a device', hub: 'a hub'
  };
  var CONF_WORD = {
    observed: 'observed — Home SOC saw it happen',
    inferred: 'inferred from the shape of the network',
    assumed: 'assumed; nothing has confirmed it'
  };
  /* The four values blast.confidence can take, each with the word for it and the sentence to
     print when there is no evidence line. 'assumed' is not a synonym for 'inferred': inferred
     means the network's shape implies it, assumed means nothing has confirmed it at all. */
  var CONF_LABEL = {
    observed: 'Observed', mixed: 'Partly observed', inferred: 'Inferred', assumed: 'Assumed'
  };
  var CONF_FALLBACK = {
    observed: 'Recorded, but the detail was not carried with this answer.',
    mixed: 'Part of this was recorded and part follows from the shape of the network.',
    inferred: 'Nothing like this has actually been recorded. This follows from the shape of the network, not from a failure Home SOC has watched.',
    assumed: 'Nothing has confirmed this. It is the default Home SOC falls back to when it has no route data at all — setting network.gateway would replace it with something better.'
  };
  var COLLAPSED_ID = 'cloud:__collapsed__';
  var BLOCKED_ID = 'cloud:__collapsed_blocked__';

  var state = {
    raw: null,          // the payload as served
    view: null,         // the payload after cloud collapsing
    layout: null,
    selected: null,     // node id in blast-radius mode
    blast: null,        // blast payload for the selected device
    blastPending: false, // a blast request is in flight for the selected device
    cloudOpen: false,
    rovingId: null,     // the one node that is currently in the page's tab order
    blastCache: {}
  };

  /* ---- tiny DOM helpers ---- */
  function svgEl(name, attrs, text) {
    var e = document.createElementNS(NS, name);
    if (attrs) {
      Object.keys(attrs).forEach(function (k) {
        if (attrs[k] !== null && attrs[k] !== undefined) e.setAttribute(k, attrs[k]);
      });
    }
    if (text !== undefined && text !== null) e.textContent = String(text);
    return e;
  }
  function el(tag, cls, text) {
    var e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text !== undefined && text !== null) e.textContent = String(text);
    return e;
  }
  function $(sel) { return document.querySelector(sel); }
  function clear(node) { while (node && node.firstChild) node.removeChild(node.firstChild); }
  function textWidth(text, size) { return String(text == null ? '' : text).length * size * 0.55; }
  function fitText(text, size, available) {
    text = String(text == null ? '' : text);
    if (textWidth(text, size) <= available) return text;
    var keep = Math.max(1, Math.floor(available / (size * 0.55)) - 1);
    return text.slice(0, keep) + '…';
  }
  function plural(n, one, many) { return n === 1 ? one : (many || one + 's'); }

  /* The drawn label, and the width the layout must reserve for it. One function, used by the
     column-width pass, the invisible hit rect and the <text> itself, so the three can never
     disagree — they used to, and the offline suffix was the proof: it was subtracted from the
     name's budget but never added to the column's reserve, so "Nintendo Switch (offline)"
     both lost its name to an ellipsis AND had nowhere to go if it had kept it. The suffix now
     carries its own room. */
  function drawnLabel(n) {
    var name = fitText(n.__shown || n.label, LABEL_SIZE, n.__shown ? MAX_LABEL_WIDE : MAX_LABEL);
    return n.online ? name : name + OFFLINE_SUFFIX;
  }
  function labelWidth(n) { return textWidth(drawnLabel(n), LABEL_SIZE); }

  /* =====================================================================
     the view: collapsing the cloud column into one node until it is opened
     ===================================================================== */

  function isCloud(node) { return node.kind === 'cloud'; }
  function isBlockedEdge(e) { return e.edge_type === 'cloud_blocked'; }
  /* A cloud node every one of whose edges was refused. The collapsed groups carry `blocked`
     already; an expanded column's individual domains have to be worked out from their edges. */
  function isBlockedOnly(node, edges) {
    if (!isCloud(node)) { return false; }
    var any = false, allBlocked = true;
    edges.forEach(function (e) {
      if (e.dst !== node.id) { return; }
      any = true;
      if (!isBlockedEdge(e)) { allBlocked = false; }
    });
    return any && allBlocked;
  }

  /* A domain every one of whose lookups was refused by the DNS filter is not something anything
     depends on — the device asked, and was told no. It is collapsed separately and drawn
     separately so it can never be read as a dependency (SPEC C2 rule 4). */
  function blockedCloudIds(nodes, edges) {
    var seen = {}, blocked = {};
    nodes.forEach(function (n) { if (isCloud(n)) { seen[n.id] = true; blocked[n.id] = true; } });
    edges.forEach(function (e) {
      if (seen[e.dst] && !isBlockedEdge(e)) blocked[e.dst] = false;
      if (seen[e.src] && !isBlockedEdge(e)) blocked[e.src] = false;
    });
    return blocked;
  }

  function buildView(raw, cloudOpen) {
    var nodes = raw.nodes.slice();
    var edges = raw.edges.slice();
    var blocked = blockedCloudIds(nodes, edges);
    var cloudIds = {}, cloudCount = 0, blockedCount = 0;
    nodes.forEach(function (n) {
      if (!isCloud(n)) return;
      cloudIds[n.id] = true;
      if (blocked[n.id]) blockedCount += 1; else cloudCount += 1;
    });
    var total = cloudCount + blockedCount;
    if (cloudOpen || total === 0) {
      return { nodes: nodes, edges: edges, cloudCount: total, blockedCount: blockedCount };
    }

    var kept = nodes.filter(function (n) { return !isCloud(n); });
    function group(id, count, label, sublabel, isBlocked) {
      if (!count) return;
      kept.push({
        id: id, kind: 'cloud', collapsed: true, blocked: isBlocked, members: count,
        label: label, sublabel: sublabel, device_id: null, criticality: 0, severity: null, online: true
      });
    }
    /* Both sublabels are short enough to survive MAX_SUBLABEL intact. They used to run to 40
       and 58 characters and drew as "reached, and grouped — o…" / "asked for and refused by…",
       so the one pair of nodes the page asks the reader to read was the one pair they could
       not finish. The full sentences are still on the node's tooltip, its accessible name and
       the side panel, where there is room for them. */
    group(COLLAPSED_ID, cloudCount, cloudCount + ' external ' + plural(cloudCount, 'service'),
          'reached — open to list', false);
    group(BLOCKED_ID, blockedCount, blockedCount + ' blocked ' + plural(blockedCount, 'domain'),
          'asked for, then refused', true);

    /* One edge per (other end, direction, confidence, blocked-or-not), carrying how many it
       stands for, so the collapsed node never suggests more or fewer relationships than were
       actually recorded. */
    var merged = {}, out = [];
    edges.forEach(function (e) {
      var srcCloud = cloudIds[e.src], dstCloud = cloudIds[e.dst];
      if (!srcCloud && !dstCloud) { out.push(e); return; }
      var cloudEnd = srcCloud ? e.src : e.dst;
      var groupId = blocked[cloudEnd] ? BLOCKED_ID : COLLAPSED_ID;
      var other = srcCloud ? e.dst : e.src;
      var key = other + '|' + (srcCloud ? 'in' : 'out') + '|' + e.confidence + '|' + groupId;
      if (merged[key]) {
        merged[key].observed_count += (e.observed_count || 0);
        merged[key].__n += 1;
        return;
      }
      var copy = {
        src: srcCloud ? groupId : e.src,
        dst: dstCloud ? groupId : e.dst,
        edge_type: e.edge_type, protocol: e.protocol, confidence: e.confidence,
        evidence: e.evidence, observed_count: e.observed_count || 0, __n: 1
      };
      merged[key] = copy;
      out.push(copy);
    });
    out.forEach(function (e) {
      if (e.__n > 1) {
        e.evidence = e.__n + (isBlockedEdge(e) ? ' blocked domains' : ' external services') +
          ', ' + e.observed_count + ' ' + plural(e.observed_count, 'lookup') + ' in total';
      }
    });
    return { nodes: kept, edges: out, cloudCount: total, blockedCount: blockedCount };
  }

  /* =====================================================================
     layout
     ===================================================================== */

  function columnOf(node, ctx) {
    if (node.kind === 'internet') return 0;
    if (node.kind === 'cloud') return 4;
    if (ctx.gateways[node.id]) return 1;
    if (node.kind === 'resolver' || node.kind === 'provider' || node.__hub) return 2;
    /* A device other *devices* depend on is infrastructure. Hosting a provider does not count:
       every printer and speaker hosts one, and treating that as infrastructure would empty the
       device column into the middle of the picture. */
    if (ctx.serves[node.id] > 0) return 2;
    return 3;
  }

  function layout(view) {
    var nodes = view.nodes, edges = view.edges;
    var byId = {};
    /* A hub arrives as kind 'provider' with an id ending ':hub' (infer._support_nodes); the
       engine has no 'hub' node kind and api.MAP_NODE_KINDS does not list one. Marking it here,
       before anything reads it, is what makes columnOf(), shape(), nodeTitle() and the C2.6
       hub note work — all four used to branch on a kind no payload has ever carried. */
    nodes.forEach(function (n) { byId[n.id] = n; n.__hub = n.kind === 'provider' && /:hub$/.test(String(n.id)); });
    /* Two speakers both offering "AirPlay" drew two identical rows whose difference lived only
       in the tooltip. A duplicated service label carries its host's name on the map itself. */
    var providerLabels = {};
    nodes.forEach(function (n) {
      n.__shown = null;
      if (n.kind === 'provider') providerLabels[n.label] = (providerLabels[n.label] || 0) + 1;
    });
    nodes.forEach(function (n) {
      if (n.kind !== 'provider' || providerLabels[n.label] < 2) return;
      var host = n.device_id != null ? byId['device:' + n.device_id] : null;
      if (!host) {
        edges.forEach(function (e) { if (!host && e.src === n.id && e.edge_type === 'hosted_by') host = byId[e.dst] || null; });
      }
      if (host && host.label) n.__shown = n.label + ' · ' + host.label;
    });

    var indegree = {}, serves = {}, gateways = {}, neighbours = {}, askedBy = {}, blockedOnly = {};
    nodes.forEach(function (n) { indegree[n.id] = 0; serves[n.id] = 0; askedBy[n.id] = 0; neighbours[n.id] = []; });
    nodes.forEach(function (n) { blockedOnly[n.id] = !!n.blocked || isBlockedOnly(n, edges); });
    edges.forEach(function (e) {
      if (!(e.dst in indegree) || !(e.src in indegree)) return;
      indegree[e.dst] += 1;
      if (isBlockedEdge(e)) askedBy[e.dst] += (e.__n || 1);
      /* `cloud_blocked` is excluded for the same reason graph.py keeps it out of
         DEPENDENCY_EDGE_TYPES: the device asked and was told no, which is the opposite of
         something it relies on (C2.4). Counting it here made a blocked domain's tooltip and
         screen-reader name read "7 devices depend on it · asked for and refused by the DNS
         filter — not a dependency", a sentence that contradicts itself, and for a screen-reader
         user the false half was the only thing said about the node. */
      if (e.edge_type !== 'hosted_by' && !isBlockedEdge(e) && byId[e.src] && byId[e.src].kind === 'device') serves[e.dst] += 1;
      neighbours[e.src].push(e.dst);
      neighbours[e.dst].push(e.src);
      if (e.edge_type === 'gateway') gateways[e.dst] = true;
    });
    /* Fallback when no edge is typed 'gateway': the device the internet node hangs off is it. */
    if (!Object.keys(gateways).length) {
      nodes.forEach(function (n) {
        if (n.kind !== 'internet') return;
        (neighbours[n.id] || []).forEach(function (other) {
          if (byId[other] && byId[other].kind === 'device') gateways[other] = true;
        });
      });
    }
    var ctx = { indegree: indegree, serves: serves, gateways: gateways };

    var columns = [[], [], [], [], []];
    nodes.forEach(function (n) {
      n.__col = columnOf(n, ctx);
      n.__indegree = indegree[n.id] || 0;
      columns[n.__col].push(n);
    });
    // deterministic seed order, then stable barycentre passes to cut crossings
    columns.forEach(function (col) {
      col.sort(function (a, b) {
        return (b.criticality || b.depended_on_by || 0) - (a.criticality || a.depended_on_by || 0) ||
               String(a.label).localeCompare(String(b.label)) ||
               String(a.id).localeCompare(String(b.id));
      });
    });
    var rank = {};
    function reindex() {
      columns.forEach(function (col) { col.forEach(function (n, i) { rank[n.id] = col.length < 2 ? 0.5 : i / (col.length - 1); }); });
    }
    function sortColumn(col) {
      if (col.length < 3) return;
      var bary = {};
      col.forEach(function (n, i) {
        var ns = neighbours[n.id] || [];
        var sum = 0, count = 0;
        ns.forEach(function (other) { if (other in rank) { sum += rank[other]; count += 1; } });
        bary[n.id] = count ? sum / count : i / (col.length - 1);
      });
      col.sort(function (a, b) { return bary[a.id] - bary[b.id]; });     // stable: ties keep order
    }
    /* Alternating sweeps, finishing right-to-left. The last sweep is what decides the picture,
       and going right-to-left last is what puts each offered service beside the device hosting
       it: the infrastructure column is ordered *after* the device column it hangs off, instead
       of being re-shuffled by a device pass that ran later. */
    reindex();
    for (var pass = 0; pass < BARYCENTRE_PASSES; pass++) {
      for (var c = 0; c < columns.length; c++) { sortColumn(columns[c]); reindex(); }
      for (var b = columns.length - 1; b >= 0; b--) { sortColumn(columns[b]); reindex(); }
    }

    // column x positions from the widest label each column actually needs
    var maxRows = 1;
    columns.forEach(function (col) { maxRows = Math.max(maxRows, col.length); });
    var rowStep = Math.max(ROW_MIN, Math.min(ROW_MAX, ROW_BUDGET / maxRows));
    /* Size is "how much hangs off this". The engine's own criticality when it set one, else the
       number of edges that actually point at the node — never a guess beyond either. */
    var maxCrit = 1;
    nodes.forEach(function (n) {
      /* A node nothing depends on is drawn at the minimum radius, and a wholly-blocked domain is
         one of those however many times it was refused: the legend says bigger means more
         depends on it, so sizing a blocked domain by its refusal count said the opposite. */
      n.__weight = (n.blocked || isBlockedOnly(n, edges))
        ? 0
        : Math.max(n.criticality || 0, n.depended_on_by != null ? n.depended_on_by : (indegree[n.id] || 0));
      maxCrit = Math.max(maxCrit, n.__weight);
    });

    var x = PAD_X, colX = [], colLabelW = [];
    columns.forEach(function (col, c) {
      var widest = 0, radius = R_MIN;
      col.forEach(function (n) {
        n.__r = R_MIN + (R_MAX - R_MIN) * Math.sqrt(Math.min(1, n.__weight / maxCrit));
        radius = Math.max(radius, n.__r);
        widest = Math.max(widest, labelWidth(n));
        if (n.sublabel || n.__hub) widest = Math.max(widest, Math.min(MAX_SUBLABEL, textWidth(n.sublabel || '', 9)));
      });
      colX[c] = x + radius;
      colLabelW[c] = widest;
      if (col.length) x = colX[c] + radius + 8 + widest + GAP;
    });
    var height = PAD_Y * 2 + 18 + maxRows * rowStep;
    var width = Math.max(x - GAP + PAD_X, 360);

    columns.forEach(function (col, c) {
      var top = PAD_Y + 18 + (maxRows - col.length) * rowStep / 2;
      col.forEach(function (n, i) {
        n.__x = colX[c];
        n.__y = top + i * rowStep + rowStep / 2;
        n.__row = i;
      });
    });
    return {
      nodes: nodes, edges: edges, byId: byId, columns: columns, colX: colX, colLabelW: colLabelW,
      width: width, height: height, rowStep: rowStep, indegree: indegree, serves: serves,
      gateways: gateways, askedBy: askedBy, blockedOnly: blockedOnly
    };
  }

  /* =====================================================================
     drawing
     ===================================================================== */

  function edgePath(e, lay, bundleX) {
    var a = lay.byId[e.src], b = lay.byId[e.dst];
    if (!a || !b) return null;
    var dir = a.__x >= b.__x ? -1 : 1;                 // travelling left or right
    var sx = a.__x + dir * (a.__r + 2), sy = a.__y;
    var tx = b.__x - dir * (b.__r + 5), ty = b.__y;
    if (bundleX === null || bundleX === undefined) {
      var dx = Math.max(24, Math.abs(tx - sx) * 0.45);
      return 'M' + sx.toFixed(1) + ' ' + sy.toFixed(1) +
             ' C' + (sx + dir * dx).toFixed(1) + ' ' + sy.toFixed(1) +
             ' ' + (tx - dir * dx).toFixed(1) + ' ' + ty.toFixed(1) +
             ' ' + tx.toFixed(1) + ' ' + ty.toFixed(1);
    }
    /* Bus routing: a horizontal run out of the source, one shared vertical trunk, a horizontal
       run into the target. Eighteen devices reaching one gateway then read as a comb instead of
       eighteen overlapping curves — every edge still its own element, still individually
       hoverable, highlightable and styled by its own confidence. */
    var down = ty >= sy ? 1 : -1;
    var vy1 = sy + down * CORNER, vy2 = ty - down * CORNER;
    if (Math.abs(ty - sy) < 2 * CORNER + 1) {
      return 'M' + sx.toFixed(1) + ' ' + sy.toFixed(1) + ' L' + tx.toFixed(1) + ' ' + ty.toFixed(1);
    }
    return 'M' + sx.toFixed(1) + ' ' + sy.toFixed(1) +
           ' L' + (bundleX - dir * CORNER).toFixed(1) + ' ' + sy.toFixed(1) +
           ' Q' + bundleX.toFixed(1) + ' ' + sy.toFixed(1) + ' ' + bundleX.toFixed(1) + ' ' + vy1.toFixed(1) +
           ' L' + bundleX.toFixed(1) + ' ' + vy2.toFixed(1) +
           ' Q' + bundleX.toFixed(1) + ' ' + ty.toFixed(1) + ' ' + (bundleX + dir * CORNER).toFixed(1) + ' ' + ty.toFixed(1) +
           ' L' + tx.toFixed(1) + ' ' + ty.toFixed(1);
  }

  /* Where each bundle's shared vertical trunk goes.

     In the gap between two columns — never over a column's labels, which is the whole reason the
     gap is as wide as it is. Groups that would land on the same line are fanned out in fixed
     lanes, in sorted key order, so the picture is the same every time. */
  function bundleTargets(lay) {
    var groups = {};
    lay.edges.forEach(function (e) {
      var key = e.dst + '|' + e.edge_type + '|' + e.confidence;
      var src = lay.byId[e.src], dst = lay.byId[e.dst];
      if (!src || !dst) return;
      if (!groups[key]) groups[key] = { n: 0, srcCol: src.__col, right: src.__x < dst.__x };
      groups[key].n += 1;
    });
    var trunks = {}, lanes = {};
    Object.keys(groups).sort().forEach(function (key) {
      var g = groups[key];
      if (g.n < BUNDLE_MIN) return;
      var c = g.srcCol;
      var base = g.right
        ? lay.colX[c] + R_MAX + 8 + lay.colLabelW[c] + GAP / 2   // gap after this column's labels
        : lay.colX[c] - R_MAX - GAP / 2;                          // gap before this column's nodes
      var slot = (lanes[base] = (lanes[base] || 0) + 1);
      trunks[key] = base + (slot - 1) * LANE * (g.right ? 1 : -1);
    });
    return trunks;
  }

  function shape(node) {
    var r = node.__r, k = node.kind;
    if (k === 'internet' || k === 'cloud') {
      return svgEl('rect', { x: -r, y: -r * 0.78, width: r * 2, height: r * 1.56, rx: 4, 'class': 'map-shape' });
    }
    if (k === 'resolver') {
      return svgEl('path', { d: 'M0 ' + (-r * 1.15) + 'L' + r * 1.15 + ' 0L0 ' + r * 1.15 + 'L' + (-r * 1.15) + ' 0Z', 'class': 'map-shape' });
    }
    if (k === 'provider' || node.__hub) {
      /* A hub arrives as kind 'provider' with an id ending ':hub' — the engine has no 'hub'
         kind and api.MAP_NODE_KINDS does not list one, so branching on kind === 'hub' drew
         every hub as an ordinary service pentagon and left the C2.6 note permanently hidden. */
      var sides = node.__hub ? 6 : 5, pts = [];
      for (var i = 0; i < sides; i++) {
        var a = -Math.PI / 2 + i * 2 * Math.PI / sides;
        pts.push((r * 1.12 * Math.cos(a)).toFixed(1) + ',' + (r * 1.12 * Math.sin(a)).toFixed(1));
      }
      return svgEl('polygon', { points: pts.join(' '), 'class': 'map-shape' });
    }
    return svgEl('circle', { r: r, 'class': 'map-shape' });
  }

  function nodeTitle(node, lay) {
    var bits = [node.__shown || node.label, (node.__hub ? KIND_WORD.hub : KIND_WORD[node.kind]) || node.kind];
    if (node.severity) bits.push('worst open finding: ' + node.severity);
    if (!node.online) bits.push('offline — not seen at the last network check');
    /* `serves`, not `__weight`: the weight that sizes a node counts every inbound edge, and a
       device's own offered services point at it with `hosted_by`. Reading that as dependents
       told a hover and a screen reader that "2 devices depend on" a printer nothing has ever
       been seen printing to — an invented relationship, in the one place the map must not
       invent. `serves` counts only edges that come from an actual device and are not hosted_by. */
    var dependents = (lay.serves && lay.serves[node.id]) || 0;
    var asked = (lay.askedBy && lay.askedBy[node.id]) || 0;
    if (node.blocked || (lay.blockedOnly && lay.blockedOnly[node.id])) {
      /* Never "N devices depend on it" for a refused lookup: they asked, and were told no. */
      if (asked) bits.push('asked for by ' + asked + ' ' + plural(asked, 'device') + ' and refused — not a dependency');
    } else if (node.kind === 'provider' && !(lay.indegree[node.id] > 0)) bits.push('no confirmed consumers');
    else if (dependents) bits.push(dependents + ' ' + plural(dependents, 'device') + ' ' +
                                   plural(dependents, 'depends', 'depend') + ' on it');
    if (node.sublabel) bits.push(node.sublabel);
    return bits.join(' · ');
  }

  function draw() {
    var canvas = $('#map-canvas');
    if (!canvas) return;
    var view = buildView(state.raw, state.cloudOpen);
    state.view = view;
    var lay = layout(view);
    state.layout = lay;

    // The viewBox carries the real geometry; width/height are left to CSS so the drawing scales
    // into whatever the panel is. Fixed pixel attributes here made the graph overflow its
    // container by ~90px at 1440px wide and clipped the external-services column off the right
    // edge. map.css gives it width:100% with a min-width, so it shrinks to fit and only starts
    // scrolling once shrinking further would make the labels unreadable.
    var svg = svgEl('svg', {
      viewBox: '0 0 ' + Math.round(lay.width) + ' ' + Math.round(lay.height),
      'data-layout-width': Math.round(lay.width), 'data-layout-height': Math.round(lay.height),
      preserveAspectRatio: 'xMidYMid meet',
      'class': 'map-svg', role: 'group',
      'aria-label': 'Dependency map: ' + lay.nodes.length + ' nodes, ' + lay.edges.length + ' links'
    });

    // column headings, so the left-to-right order is stated and not just implied
    lay.columns.forEach(function (col, c) {
      if (!col.length) return;
      var heading = svgEl('text', { x: lay.colX[c] - R_MAX, y: PAD_Y, 'class': 'map-col-title' }, COLUMN_TITLES[c]);
      heading.appendChild(svgEl('title', null, COLUMN_TITLES[c] + ' (' + COLUMN_TECH[c] + ')'));
      svg.appendChild(heading);
    });

    var gEdges = svgEl('g', { 'class': 'map-edges' });
    var gNodes = svgEl('g', { 'class': 'map-nodes' });
    svg.appendChild(gEdges);
    svg.appendChild(gNodes);

    var trunks = bundleTargets(lay);
    lay.edges.forEach(function (e, i) {
      var key = e.dst + '|' + e.edge_type + '|' + e.confidence;
      var d = edgePath(e, lay, key in trunks ? trunks[key] : null);
      if (!d) return;
      var path = svgEl('path', {
        d: d, 'class': 'map-edge conf-' + (e.confidence || 'assumed') + (isBlockedEdge(e) ? ' is-blocked' : ''),
        'data-src': e.src, 'data-dst': e.dst, 'data-edge': i
      });
      var a = lay.byId[e.src], b = lay.byId[e.dst];
      path.appendChild(svgEl('title', null,
        (a.__shown || a.label) + ' → ' + (b.__shown || b.label) + ' · ' +
        (isBlockedEdge(e) ? 'asked for, blocked — not a dependency' : (EDGE_WORDS[e.edge_type] || 'relies on it')) +
        ' · ' + (CONF_WORD[e.confidence] || e.confidence) + (e.evidence ? ' — ' + e.evidence : '') +
        ' [' + (e.edge_type || 'link') + (e.protocol ? ' · ' + e.protocol : '') + ']'));
      gEdges.appendChild(path);
    });

    lay.nodes.forEach(function (n) {
      var orphan = n.kind === 'provider' && !(n.depended_on_by || lay.indegree[n.id] || 0);
      var cls = 'map-node kind-' + n.kind + (n.severity ? ' sev-' + n.severity : ' sev-none') +
                (n.online ? '' : ' is-offline') + (orphan ? ' is-orphan' : '') + (n.blocked ? ' is-blocked' : '');
      var g = svgEl('g', {
        'class': cls, transform: 'translate(' + n.__x.toFixed(1) + ' ' + n.__y.toFixed(1) + ')',
        /* Roving tabindex: the graph is ONE stop in the page's tab order, and the arrow keys move
           inside it. Making all thirty-odd nodes tab stops would be "focusable" and unusable. */
        tabindex: n.id === state.rovingId ? '0' : '-1', role: 'button', 'data-id': n.id,
        'aria-label': nodeTitle(n, lay) + '. Press Enter for what stops working without it.'
      });
      /* An invisible hit area covering the shape AND its label: the label is the part a person
         aims at, and without this the edge that terminates on the node wins the click. */
      var labelW = labelWidth(n);
      g.appendChild(svgEl('rect', {
        x: -n.__r - 6, y: -Math.max(11, lay.rowStep / 2 - 1), width: n.__r * 2 + 20 + labelW,
        height: Math.max(22, lay.rowStep - 2), 'class': 'map-hit'
      }));
      g.appendChild(svgEl('circle', { r: n.__r + 5, 'class': 'map-focus-ring' }));
      /* A second, dashed ring drawn only while the node has keyboard focus, so focus differs
         from the blast-radius rings in shape as well as colour (map.css). */
      g.appendChild(svgEl('circle', { r: n.__r + 9, 'class': 'map-focus-outer' }));
      g.appendChild(shape(n));
      var letter = n.severity ? (SEV_LETTER[n.severity] || '') : '';
      if (letter) {
        g.appendChild(svgEl('text', { x: 0, y: Math.min(4, n.__r * 0.36), 'class': 'map-node-letter', 'font-size': Math.max(9, Math.min(12, n.__r * 0.95)) }, letter));
      }
      /* C2.5's statement lives on the provider node, and it has to be readable *on the map*.
         Two things used to stop it: the full sublabel ("on MacBook Air — no confirmed
         consumers") is far wider than MAX_LABEL so it truncated to "on MacBook Air — no …",
         and the second line was only drawn when rowStep >= 28, which an expanded cloud column
         never reaches — so every provider rendered as a bare "Printing" with nothing under it.
         An orphan provider now gets the fixed short phrase, which fits, and gets it regardless
         of row height. The host device name stays in the tooltip, where there is room. */
      var orphanText = orphan ? 'no confirmed consumers' : null;
      var subText = orphanText || n.sublabel;
      var twoLine = subText && (n.kind === 'provider' || n.collapsed) && (orphanText || lay.rowStep >= 28);
      /* map.html's legend tells the reader the word "offline" is in the node's own label. It
         was only ever in the tooltip and the accessible name, so a reader who checked the
         legend found it false — on a page whose whole premise is that it does not overstate
         what it knows. Now it is in the drawn label too. */
      /* The suffix is never the half that gets cut: "Nintendo Switch…" would leave the
         legend's claim about the word "offline" false for exactly the long names most likely
         to be truncated. drawnLabel() gives it its own room and the column reserves for it. */
      /* A plate in the canvas colour behind the label (and its second line), drawn above the
         edges: a link that passes a label goes behind it instead of striking through the words.
         The width follows the drawn font (12.5px against the 11.5px the layout measures). */
      var plateW = Math.max(labelW * 12.5 / LABEL_SIZE,
                            twoLine ? textWidth(fitText(subText, 9, MAX_SUBLABEL), 10.5) : 0) + 8;
      var plateH = Math.min(twoLine ? 26 : 17, lay.rowStep - 1);
      g.appendChild(svgEl('rect', {
        x: n.__r + 4, y: twoLine ? -Math.min(13, plateH / 2) : -plateH / 2 - 0.5,
        width: plateW, height: plateH, rx: 3, 'class': 'map-label-plate'
      }));
      g.appendChild(svgEl('text', { x: n.__r + 8, y: twoLine ? -1 : 4, 'class': 'map-label' },
                          drawnLabel(n)));
      if (twoLine) {
        g.appendChild(svgEl('text', { x: n.__r + 8, y: 10, 'class': 'map-sublabel' },
                            fitText(subText, 9, MAX_SUBLABEL)));
      }
      g.appendChild(svgEl('title', null, nodeTitle(n, lay)));
      gNodes.appendChild(g);
    });

    /* Keep the roving stop on a node that still exists (collapsing the cloud column removes
       some), otherwise put it on the first node of the first column. */
    if (!lay.byId[state.rovingId]) {
      state.rovingId = lay.nodes.length ? lay.columns.reduce(function (found, col) {
        return found || (col.length ? col[0].id : null);
      }, null) : null;
    }
    for (var gi = 0; gi < gNodes.childNodes.length; gi++) {
      var child = gNodes.childNodes[gi];
      child.setAttribute('tabindex', child.getAttribute('data-id') === state.rovingId ? '0' : '-1');
    }
    clear(canvas);
    canvas.appendChild(svg);
    applyHighlight();
    updateCloudButton(view.cloudCount, view.blockedCount);
    updateHubNote(lay);
  }

  function updateCloudButton(count, blockedCount) {
    var btn = $('#map-cloud-toggle');
    if (!btn) return;
    if (!count) { btn.hidden = true; return; }
    btn.hidden = false;
    var what = count + ' external ' + plural(count, 'service') +
               (blockedCount ? ' (' + blockedCount + ' blocked)' : '');
    btn.textContent = (state.cloudOpen ? 'Collapse ' : 'Show ') + what;
    btn.setAttribute('aria-expanded', state.cloudOpen ? 'true' : 'false');
  }

  /* SPEC C2.6: a hub's Zigbee/Z-Wave/Thread/Bluetooth children are not on the IP network, so
     Home SOC cannot see them at all. Say it on the page rather than let the map imply the hub
     stands alone. */
  function updateHubNote(lay) {
    var note = $('#map-hubnote');
    if (!note) return;
    var hubs = lay.nodes.filter(function (n) { return n.__hub; });
    if (!hubs.length) { note.hidden = true; return; }
    note.hidden = false;
    /* Name the *device*, not the hub node: the node's own label is "Hub (Zigbee / Z-Wave /
       Thread)", which made the sentence read "Hub (Zigbee / Z-Wave / Thread) is a hub". */
    function hostOf(n) {
      var host = n.device_id != null && lay.byId['device:' + n.device_id];
      return (host && host.label) || n.label;
    }
    note.textContent = hubs.length === 1
      ? hostOf(hubs[0]) + ' is a hub. Whatever it controls over Zigbee, Z-Wave, Thread or Bluetooth is not on the IP network, so Home SOC cannot see it — not even how many there are.'
      : hubs.length + ' hubs are on this map. Whatever they control over Zigbee, Z-Wave, Thread or Bluetooth is not on the IP network, so Home SOC cannot see those devices — not even how many there are.';
  }

  /* =====================================================================
     blast-radius mode
     ===================================================================== */

  function affectedSet() {
    if (!state.selected) return null;
    var set = {};
    set[state.selected] = 'source';
    var blast = state.blast;
    if (blast) {
      (blast.offline || []).forEach(function (d) { if (d && d.device_id != null) set['device:' + d.device_id] = 'offline'; });
      (blast.degraded || []).forEach(function (d) { if (d && d.device_id != null) set['device:' + d.device_id] = 'degraded'; });
      var mapEdges = (state.layout ? state.layout.edges : []);
      /* A service dies with the box hosting it — but only when that box actually stops.
         A host that is merely *degraded* keeps running and keeps offering what it offers:
         the printer still prints when the router dies, which is exactly why the panel's
         "what the house loses" does not list printing. Marking every provider whose host was
         anywhere in the radius put thirteen "lost" rings on the map against one line of text.
         Only the node that failed, and anything the payload calls unreachable, take their
         services with them. */
      mapEdges.forEach(function (e) {
        if (e.edge_type !== 'hosted_by') return;
        var host = set[e.dst];
        if (host === 'source' || host === 'offline') set[e.src] = 'lost';
      });
      /* Nodes that are not devices, and so are not in any of the three counts. The counts
         cover devices — the panel says so in words — but the picture must not leave a node
         dim while the text beside it lists that very node under "what the house loses".
         Both cases below are read off the graph, never off the prose:
           - the internet is reached only over an `internet` edge. If the node failing carries
             one, the internet goes out of reach with it, and so does every external endpoint
             on the far side of it;
           - anything else with an `internet` edge (the resolver forwards upstream over one)
             keeps running on the LAN and loses what it was reaching for: degraded, the same
             word the panel uses for the devices in the same position.
         Domains the filter refused are deliberately left out: nothing depends on them, which
         is the whole reason they are drawn at all, so they stay dim rather than joining a
         list of things the house loses. */
      var carriesInternet = mapEdges.some(function (e) {
        return e.edge_type === 'internet' && e.src === state.selected;
      });
      if (carriesInternet) {
        set.internet = 'lost';
        mapEdges.forEach(function (e) {
          if (e.edge_type === 'internet' && e.src !== state.selected && !set[e.src]) {
            set[e.src] = 'degraded';
          }
        });
        (state.layout ? state.layout.nodes : []).forEach(function (n) {
          if (n.kind !== 'cloud' || set[n.id]) return;
          if (n.blocked || (state.layout.blockedOnly && state.layout.blockedOnly[n.id])) return;
          set[n.id] = 'lost';
        });
      }
      return set;
    }
    // no blast radius for this node (it is not a device): highlight only its recorded links
    (state.layout ? state.layout.edges : []).forEach(function (e) {
      if (e.src === state.selected) set[e.dst] = 'linked';
      if (e.dst === state.selected) set[e.src] = 'linked';
    });
    return set;
  }

  /* What blast-radius mode has decided about a node, in words. The ring says "in the radius";
     only this says which way, so a reader who cannot tell two ring colours apart — or is
     reading with a screen reader, where there are no rings at all — loses nothing. */
  var BLAST_WORD = {
    source: 'the device this radius is for',
    offline: 'in the blast radius — becomes unreachable',
    degraded: 'in the blast radius — keeps working, loses a service',
    lost: 'in the blast radius — stops working',
    linked: 'in the blast radius',
    dim: 'not in the blast radius'
  };

  function blastBaseTitle(g) {
    var t = g.querySelector('title');
    var base = (t && t.textContent) || '';
    g.setAttribute('data-title', base);
    return base;
  }

  function setNodeTitle(g, text) {
    var t = g.querySelector('title');
    if (t) t.textContent = text;
    g.setAttribute('aria-label', text + '. Press Enter for what stops working without it.');
  }

  function applyHighlight() {
    var canvas = $('#map-canvas');
    if (!canvas) return;
    var set = affectedSet();
    var nodes = canvas.querySelectorAll('.map-node');
    var edges = canvas.querySelectorAll('.map-edge');
    var i;
    for (i = 0; i < nodes.length; i++) {
      var id = nodes[i].getAttribute('data-id');
      nodes[i].classList.remove('is-affected', 'is-dim', 'is-source', 'is-degraded', 'is-lost');
      /* C7: severity and confidence must not be conveyed by colour alone, and neither may
         this. The ring is one treatment for everything in the radius; which *kind* of harm
         it is is a word, on the node itself and in the panel's lists. */
      var base = nodes[i].getAttribute('data-title') || '';
      if (!base) { base = blastBaseTitle(nodes[i]); }
      if (!set) { setNodeTitle(nodes[i], base); continue; }
      var word = id === state.selected ? BLAST_WORD.source : BLAST_WORD[set[id]] || BLAST_WORD.dim;
      setNodeTitle(nodes[i], base + ' · ' + word);
      if (id === state.selected) nodes[i].classList.add('is-source', 'is-affected');
      else if (set[id] === 'degraded') nodes[i].classList.add('is-affected', 'is-degraded');
      else if (set[id] === 'lost') nodes[i].classList.add('is-affected', 'is-lost');
      else if (set[id]) nodes[i].classList.add('is-affected');
      else nodes[i].classList.add('is-dim');
    }
    for (i = 0; i < edges.length; i++) {
      edges[i].classList.remove('is-affected', 'is-dim');
      if (!set) continue;
      var s = edges[i].getAttribute('data-src'), d = edges[i].getAttribute('data-dst');
      if (set[s] && set[d]) edges[i].classList.add('is-affected');
      else edges[i].classList.add('is-dim');
    }
    var exit = $('#map-exit');
    if (exit) exit.hidden = !state.selected;
    if (canvas) canvas.classList.toggle('is-blast', !!state.selected);
  }

  function statTile(n, word, hint) {
    var d = el('div', 'map-stat');
    d.appendChild(el('b', null, n));
    d.appendChild(el('span', null, word));
    if (hint) d.appendChild(el('span', 'muted small', hint));
    return d;
  }

  function deviceList(title, items, emptyText) {
    var wrap = document.createDocumentFragment();
    wrap.appendChild(el('h3', null, title));
    if (!items || !items.length) {
      wrap.appendChild(el('p', 'muted small', emptyText));
      return wrap;
    }
    var ul = el('ul', 'map-list');
    items.forEach(function (d) {
      var li = el('li');
      if (d.device_id != null) {
        var a = el('a', null, d.device_label || d.label || ('device ' + d.device_id));
        a.href = '/devices/' + encodeURIComponent(d.device_id);
        li.appendChild(a);
      } else {
        li.appendChild(el('span', null, d.label || String(d)));
      }
      if (d.why) li.appendChild(el('span', 'muted small', ' — ' + d.why));
      ul.appendChild(li);
    });
    wrap.appendChild(ul);
    return wrap;
  }

  function renderPanel() {
    var body = $('#map-panel-body'), title = $('#map-panel-title');
    if (!body || !title) return;
    if (!state.selected) { restoreIdlePanel(); return; }
    var node = state.layout.byId[state.selected];
    if (!node) { restoreIdlePanel(); return; }
    clear(body);
    title.textContent = node.label;

    var kind = el('p', 'map-panel-kind');
    kind.appendChild(el('span', 'badge badge-kind', KIND_WORD[node.kind] || node.kind));
    if (node.severity) kind.appendChild(el('span', 'badge badge-' + node.severity, node.severity));
    /* "Seen at last check", never a live "online": the map is built from Home SOC's last
       network check, which may be hours or days old (the banner says when). */
    var seen = el('span', 'badge badge-' + (node.online ? 'online' : 'offline'),
                  node.online ? 'seen at last check' : 'not seen at last check');
    seen.title = node.online ? "Seen at Home SOC's last network check (online)" : "Not seen at Home SOC's last network check (offline)";
    kind.appendChild(seen);
    body.appendChild(kind);

    var blast = state.blast;
    if (blast) {
      body.appendChild(el('p', 'map-headline', blast.headline || 'No headline was produced for this device.'));
      var stats = el('div', 'map-stats');
      var counts = blast.counts || {};
      stats.appendChild(statTile(counts.offline != null ? counts.offline : (blast.offline || []).length, 'unreachable', 'lose their only path'));
      stats.appendChild(statTile(counts.degraded != null ? counts.degraded : (blast.degraded || []).length, 'degraded', 'keep working, lose a service'));
      /* Not "unaffected": Home SOC cannot see devices using each other, so all it can say is
         that nothing it recorded depends on this one. */
      stats.appendChild(statTile(counts.unaffected != null ? counts.unaffected : (blast.unaffected || []).length,
                                 'not known to be affected', 'nothing recorded depends on it'));
      body.appendChild(stats);
      /* The three tiles count devices and nothing else. Without this line "0 unaffected" sat
         beside a picture with four dim nodes in it, and the reader had to guess which of the
         two was wrong. The map rings every node in the radius, device or not; the counts are
         the device half of the same answer. */
      body.appendChild(el('p', 'muted small map-stats-note',
        'These three count devices. The internet, the resolver and the services on the map are '
        + 'ringed in the picture, and named below, but they are not devices and are not counted here.'));

      /* Every level the legend explains gets its own word and its own fallback sentence.
         'assumed' — the weakest of the three, and reachable on any install that leaves
         network.gateway at "auto" — used to print as "Inferred", beside a sentence saying
         "this follows from the shape of the network", which is the definition of *inferred*. */
      var conf = blast.confidence || 'inferred';
      var ev = el('div', 'map-evidence conf-box-' + conf);
      ev.appendChild(el('b', null, CONF_LABEL[conf] || 'Inferred'));
      ev.appendChild(el('span', null, ' ' + (blast.evidence || CONF_FALLBACK[conf] || CONF_FALLBACK.inferred)));
      if (blast.resolution) ev.appendChild(el('span', 'muted small', ' ' + blast.resolution));
      body.appendChild(ev);

      if ((blast.services_lost || []).length) {
        body.appendChild(el('h3', null, 'What the house loses'));
        var ul = el('ul', 'map-list');
        blast.services_lost.forEach(function (s) { ul.appendChild(el('li', null, String(s))); });
        body.appendChild(ul);
      }
      body.appendChild(deviceList('Unreachable', blast.offline, 'Nothing becomes unreachable.'));
      body.appendChild(deviceList('Degraded', blast.degraded, 'Nothing is degraded.'));
    } else if (node.collapsed) {
      body.appendChild(el('p', 'map-headline', node.blocked
        ? node.members + ' domains devices here asked for and the DNS filter refused. They are on the map because the lookup happened, not because anything depends on them.'
        : node.members + ' external services are grouped here. Open the column to see each one.'));
      body.appendChild(el('p', 'muted small', 'These come from DNS lookups Home SOC answered itself. A device that does not use this resolver contributes nothing here, so silence is not evidence that it talks to nobody.'));
    } else if (state.blastPending) {
      body.appendChild(el('p', 'map-headline', 'Working out what stops working without ' + node.label + '…'));
    } else if (node.kind === 'device') {
      /* The request failed or came back empty. Say so rather than leaving the panel looking
         like an answer: the links below are evidence, but they are not the blast radius. */
      body.appendChild(el('p', 'map-headline',
        'Home SOC could not work out a blast radius for this device just now. What follows is the ' +
        'evidence the map is drawn from, not an answer to what stops working without it.'));
    } else {
      body.appendChild(el('p', 'map-headline', 'Home SOC works out a blast radius for devices it can watch fail. ' +
        'This is ' + (KIND_PHRASE[node.kind] || KIND_WORD[node.kind] || node.kind) +
        ', so the panel shows its recorded links instead.'));
    }

    // the links themselves, always — this is the evidence the picture is drawn from
    var dependsOn = [], dependents = [];
    state.layout.edges.forEach(function (e) {
      var other;
      if (e.src === state.selected) { other = state.layout.byId[e.dst]; if (other) dependsOn.push({ node: other, edge: e }); }
      if (e.dst === state.selected) { other = state.layout.byId[e.src]; if (other) dependents.push({ node: other, edge: e }); }
    });
    body.appendChild(linkList('Depends on', dependsOn,
      'Nothing recorded. Home SOC has seen no lookups, advertisements or mappings from this device.'));
    body.appendChild(linkList('Depended on by', dependents,
      node.kind === 'provider'
        ? 'No confirmed consumers. It offers this service, but nothing has been observed using it — and Home SOC will not guess who might.'
        : 'Nothing recorded depends on this.'));

    if (node.device_id != null) {
      var more = el('p', 'push-down');
      var a = el('a', 'link', 'Open this device →');
      a.href = '/devices/' + encodeURIComponent(node.device_id);
      more.appendChild(a);
      body.appendChild(more);
    }
  }

  function linkList(heading, items, emptyText) {
    var frag = document.createDocumentFragment();
    frag.appendChild(el('h3', null, heading));
    if (!items.length) { frag.appendChild(el('p', 'muted small', emptyText)); return frag; }
    var ul = el('ul', 'map-list map-links');
    items.sort(function (a, b) { return String(a.node.label).localeCompare(String(b.node.label)); });
    items.forEach(function (it) {
      var li = el('li');
      li.appendChild(el('span', 'map-link-name', it.node.__shown || it.node.label));
      li.appendChild(el('span', 'map-conf conf-tag-' + it.edge.confidence, CONF_LABEL[it.edge.confidence] || it.edge.confidence));
      var detail = (EDGE_WORDS[it.edge.edge_type] || 'relies on it') + (it.edge.evidence ? ' — ' + it.edge.evidence : '');
      var span = el('span', 'muted small', detail);
      span.title = 'Technical: ' + (it.edge.edge_type || 'link') + (it.edge.protocol ? ' · ' + it.edge.protocol : '') +
                   ' · ' + it.edge.confidence;
      li.appendChild(span);
      ul.appendChild(li);
    });
    frag.appendChild(ul);
    return frag;
  }

  var idlePanel = null;
  function restoreIdlePanel() {
    var body = $('#map-panel-body'), title = $('#map-panel-title');
    if (!body || !title) return;
    title.textContent = 'Blast radius';
    clear(body);
    if (idlePanel) body.appendChild(idlePanel.cloneNode(true));
  }

  function select(id) {
    if (state.selected === id) { exitBlast(); return; }
    state.selected = id;
    state.blast = null;
    var node = state.layout.byId[id];
    var willLoad = !!(node && node.kind === 'device' && node.device_id != null);
    state.blastPending = willLoad;   // set before the first paint, so the panel can say so
    applyHighlight();
    renderPanel();
    if (!willLoad) return;
    loadBlast(node.device_id).then(function (blast) {
      if (state.selected !== id) return;   // the user moved on while it was in flight
      state.blast = blast;
      state.blastPending = false;
      applyHighlight();
      renderPanel();
    });
  }

  function exitBlast() {
    state.selected = null;
    state.blast = null;
    state.blastPending = false;
    applyHighlight();
    restoreIdlePanel();
  }

  function loadBlast(deviceId) {
    var key = String(deviceId);
    if (state.blastCache[key]) return Promise.resolve(state.blastCache[key]);
    var embedded = state.raw.blast && state.raw.blast[key];
    if (embedded) { state.blastCache[key] = embedded; return Promise.resolve(embedded); }
    var get = (global.HomeSOC && global.HomeSOC.getJSON) || function (url) {
      return fetch(url, { headers: { 'X-Requested-With': 'fetch', Accept: 'application/json' }, credentials: 'same-origin' })
        .then(function (r) { if (!r.ok) throw new Error('HTTP ' + r.status); return r.json(); });
    };
    return get('/api/map/blast/' + encodeURIComponent(deviceId)).then(function (blast) {
      if (blast && blast.counts === undefined) {
        blast.counts = {
          offline: (blast.offline || []).length,
          degraded: (blast.degraded || []).length,
          unaffected: (blast.unaffected || []).length
        };
      }
      state.blastCache[key] = blast;
      return blast;
    }).catch(function () { return null; });
  }

  /* =====================================================================
     interaction
     ===================================================================== */

  function nodeFromEvent(ev) {
    var t = ev.target;
    while (t && t !== document && !(t.classList && t.classList.contains('map-node'))) t = t.parentNode;
    return t && t.classList && t.classList.contains('map-node') ? t : null;
  }

  function move(fromId, dx, dy) {
    var lay = state.layout, node = lay.byId[fromId];
    if (!node) return null;
    var col = lay.columns[node.__col];
    if (dy) {
      var next = col[node.__row + (dy > 0 ? 1 : -1)];
      return next ? next.id : null;
    }
    for (var c = node.__col + (dx > 0 ? 1 : -1); c >= 0 && c < lay.columns.length; c += (dx > 0 ? 1 : -1)) {
      var target = lay.columns[c];
      if (!target.length) continue;
      var best = target[0], bestD = Infinity;
      target.forEach(function (n) {
        var d = Math.abs(n.__y - node.__y);
        if (d < bestD) { bestD = d; best = n; }
      });
      return best.id;
    }
    return null;
  }

  function nodeElement(id) {
    return document.querySelector('.map-node[data-id="' + (global.CSS && CSS.escape ? CSS.escape(id) : id.replace(/"/g, '\\"')) + '"]');
  }

  function setRoving(id) {
    if (!id || id === state.rovingId) { state.rovingId = id || state.rovingId; return; }
    var previous = nodeElement(state.rovingId);
    if (previous) previous.setAttribute('tabindex', '-1');
    var next = nodeElement(id);
    if (next) next.setAttribute('tabindex', '0');
    state.rovingId = id;
  }

  function focusNode(id) {
    var g = nodeElement(id);
    if (g && g.focus) { setRoving(id); g.focus(); return true; }
    return false;
  }

  function bind() {
    var canvas = $('#map-canvas');
    if (!canvas) return;
    canvas.addEventListener('focusin', function (ev) {
      var g = nodeFromEvent(ev);
      if (g) setRoving(g.getAttribute('data-id'));
    });
    canvas.addEventListener('click', function (ev) {
      var g = nodeFromEvent(ev);
      if (!g) return;
      var id = g.getAttribute('data-id');
      if (id === COLLAPSED_ID || id === BLOCKED_ID) { toggleCloud(); return; }
      select(id);
    });
    canvas.addEventListener('keydown', function (ev) {
      var g = nodeFromEvent(ev);
      if (ev.key === 'Escape') { exitBlast(); return; }
      if (!g) return;
      var id = g.getAttribute('data-id'), next = null;
      if (ev.key === 'ArrowDown') next = move(id, 0, 1);
      else if (ev.key === 'ArrowUp') next = move(id, 0, -1);
      else if (ev.key === 'ArrowRight') next = move(id, 1, 0);
      else if (ev.key === 'ArrowLeft') next = move(id, -1, 0);
      else if (ev.key === 'Enter' || ev.key === ' ' || ev.key === 'Spacebar') {
        ev.preventDefault();
        if (id === COLLAPSED_ID || id === BLOCKED_ID) toggleCloud(); else select(id);
        return;
      } else return;
      ev.preventDefault();
      if (next) focusNode(next);
    });
    document.addEventListener('keydown', function (ev) {
      if (ev.key === 'Escape' && state.selected) exitBlast();
    });
    var exit = $('#map-exit');
    if (exit) exit.addEventListener('click', exitBlast);
    var cloud = $('#map-cloud-toggle');
    if (cloud) cloud.addEventListener('click', toggleCloud);
    /* No submit-on-change for the window picker: an arrow key in a select fires "change", so a
       keyboard user could only ever reach the next option before the page reloaded under them
       (WCAG 3.2.2). The form's own Apply button submits it. */
  }

  function toggleCloud() {
    state.cloudOpen = !state.cloudOpen;
    var keep = state.selected;
    draw();
    if (keep && state.layout.byId[keep]) { renderPanel(); } else { exitBlast(); }
  }

  function boot() {
    if (!document.body || document.body.dataset.page !== 'map') return;
    var seed = $('#initial-map');
    if (!seed) return;
    try { state.raw = JSON.parse(seed.textContent); } catch (e) { return; }
    /* Devices are named, not numbered: when the server supplies device_label ("Unnamed camera")
       and the node's own label is only its address, show the name and keep the IP in the
       tooltip. */
    if (state.raw && Array.isArray(state.raw.nodes)) {
      state.raw.nodes.forEach(function (n) {
        if (n && n.device_label && n.device_label !== n.label && (!n.label || n.label === n.device_ip || /^[0-9.]+$|^[0-9a-f:]+$/i.test(String(n.label)))) {
          if (n.device_ip && !n.sublabel) n.sublabel = n.device_ip;
          else if (n.device_ip && String(n.sublabel).indexOf(n.device_ip) < 0) n.sublabel = n.device_ip + ' · ' + n.sublabel;
          n.label = n.device_label;
        }
      });
    }
    if (!state.raw || !state.raw.nodes || !state.raw.nodes.length) return;
    var body = $('#map-panel-body');
    if (body) { idlePanel = document.createDocumentFragment(); while (body.firstChild) idlePanel.appendChild(body.firstChild); restoreIdlePanel(); }
    draw();
    bind();
  }

  global.HomeSOCMap = { draw: draw, select: select, exit: exitBlast, state: state };
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', boot);
  else boot();
})(window);
