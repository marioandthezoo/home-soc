# Home SOC — Spec Addendum A: Activity Feed and Remediation Summary

Normative extension of `docs/SPEC.md`. Same rules apply (no external assets, CSP `default-src 'self'`, token auth,
escape everything, offline-capable, deps limited to flask/requests/dnslib + stdlib).

## A1. Purpose

Two new first-class pages complete the product loop:

- **Feed** (`/feed`) — one reverse-chronological stream of everything the agent observed and did, so the user can scroll
  through "what happened on my network" without knowing which table to look in.
- **Summary** (`/summary`) — the answer to "what has been found, and what has been fixed", including how long remediation
  took and what is still outstanding, exportable as a shareable report.

Both pages are linked from the sidebar in `base.html`, directly under Overview.

## A2. Activity feed

### A2.1 Data source — `homesoc/web/feed.py` (new module, owned by the web package)

```python
@dataclass(frozen=True)
class FeedItem:
    ts: str            # UTC ISO-8601, "...Z"
    kind: str          # see table below
    severity: str      # critical|high|medium|low|info
    title: str         # short, already human-readable, NEVER contains raw HTML
    detail: str        # one or two sentences; may be ""
    link: str | None   # in-app URL, e.g. "/findings?focus=42" or "/devices/7"
    icon: str          # short ascii token the template maps to a glyph: finding|resolved|device|scan|feed|dns|threat|notify|system
    ref: dict          # small dict of ids for the UI (finding_row_id, device_id, scan_id, domain, ...)

def build_feed(conn, *, since: str | None = None, until: str | None = None, kinds: set[str] | None = None,
               severities: set[str] | None = None, q: str | None = None, limit: int = 200,
               offset: int = 0) -> tuple[list[FeedItem], int]:
    """Merge every source below into one ordered stream. Returns (items, total_matching)."""

def feed_kinds() -> list[dict]      # [{"kind": "finding_new", "label": "New finding", "icon": "finding"}, ...] for the filter UI
def feed_counts(conn, hours: int = 24) -> dict[str, int]    # kind -> count, for the header chips
```

Sources merged by `build_feed` (each becomes one or more `FeedItem`s). Every query must be bounded by `limit + offset`
and use the indexed timestamp column; the merge is a heap-merge in Python, never a UNION over unbounded scans.

| kind | source | severity | title example |
|---|---|---|---|
| `finding_new` | `finding_events.event='created'` join `findings` | finding severity | New finding: Telnet is open on printer (192.168.1.74) |
| `finding_reopened` | `event='reopened'` | finding severity | Reopened: SMBv1 is enabled |
| `finding_resolved` | `event='resolved'` | info | Remediated: Windows Firewall re-enabled (open 3 days) |
| `finding_auto_resolved` | `event='auto_resolved'` | info | Fixed and verified: Telnet is no longer open on 192.168.1.74 |
| `finding_ack` | `event='acknowledged'` | info | Acknowledged: New device joined (Living-Room-TV) |
| `finding_suppressed` | `event='suppressed'` | info | Suppressed: Printer exposes port 9100 |
| `device_new` | `devices.first_seen` | medium | New device joined the network: tablet.lan (192.168.1.130, Apple) |
| `device_offline` | `device_sightings` gap → derived at query time from `devices.online=0 AND last_seen` | info | Device went offline: laptop.lan |
| `scan` | `scans` finished rows | info, or medium when `status='error'` | Full scan finished: 20 devices, 6 services, 27 findings (4m 12s) |
| `feed_update` | `feeds.last_updated` changes (use `events` rows written by the updater, source `feeds`) | info | Blocklist updated: hagezi_pro (224,113 domains) |
| `dns_block` | `dns_queries` where `action='block'`, **aggregated** per (client, registrable domain, hour) | medium when reason is a threat list, else info | Blocked 12 requests to doubleclick.net from 192.168.1.108 |
| `dns_threat` | `dns_queries` where reason starts with `threat:` or `reputation:` | high | Blocked a known-malicious domain: <domain> requested by 192.168.1.97 |
| `av_threat` | `events` rows with source `defender` and level `warning`/`error` | high | Microsoft Defender quarantined Trojan:Win32/Wacatac.B!ml |
| `notification` | `notifications` | info | Alert sent to ntfy (2 new high findings) |
| `system` | `events` where level in (`warning`,`error`) and source not `defender` | medium/high | Feed update failed: openphish (timeout) |

Aggregation rule for `dns_block`: group by client + registrable domain + hour bucket; `title` says the count; `ref`
carries `{"client":..., "domain":..., "hour":...}` so the UI can link to `/dns?client=..&q=domain`.

### A2.2 Page `/feed`

Header: chips with 24 h counts per kind (clickable = filter). Controls: kind multi-select, minimum severity,
time window (1 h / 24 h / 7 d / 30 d / all), free-text search, and a "pause auto-refresh" toggle.
Body: a vertical timeline grouped by day (`Today`, `Yesterday`, then `YYYY-MM-DD`), each row showing relative time
(`4m ago`), icon, severity dot, title, detail, and a link when `link` is set. Infinite "Load more" button using `offset`.
Auto-refresh: `app.js` polls `/api/feed?since=<newest ts>` every `web.refresh_seconds` and prepends new items with a
subtle highlight; the toggle stops polling. Empty state explains that the feed fills as scans run.

### A2.3 API

- `GET /api/feed?since&until&kinds=a,b&severity=high&q=&limit=200&offset=0` →
  `{"items": [FeedItem...], "total": int, "counts": {kind: n}, "generated_at": "...Z"}`
- `GET /api/feed/kinds` → `{"kinds": [{"kind","label","icon"}...]}`
- `GET /feed.rss` → RSS 2.0 of the last 100 items (`Content-Type: application/rss+xml`), for users who want it in a
  reader. Item guid = `homesoc:<kind>:<ts>:<hash>`; description is escaped plain text; honours the same token auth.

## A3. Remediation summary

### A3.1 Data source — `homesoc/web/summary.py` (new module, owned by the web package)

```python
def build_summary(conn, *, days: int = 30) -> dict:
    """Everything found and everything remediated, in one dict (see shape below)."""
def remediation_report_markdown(conn, *, days: int = 30) -> str
def remediation_report_json(conn, *, days: int = 30) -> dict     # same as build_summary + schema_version
```

`build_summary` shape:
```python
{
  "generated_at": "...Z", "window_days": 30,
  "score": {"current": 72, "grade": "C", "trend": [["2026-08-06", 41], ...]},
  "totals": {"found_all_time": 143, "open": 27, "acknowledged": 4, "resolved": 108, "suppressed": 4,
             "remediation_rate": 0.79,          # resolved / (resolved + open), 0..1
             "found_in_window": 61, "resolved_in_window": 52},
  "by_severity": {"open": {"critical": 1, ...}, "resolved": {...}},
  "by_category":  [{"category": "Windows Defender", "found": 14, "open": 3, "resolved": 11}, ...],
  "by_subject":   [{"subject_type": "host"|"device"|"wan"|"dns"|"soc", "found": n, "open": n, "resolved": n}, ...],
  "time_to_remediate": {"median_hours": 18.4, "p90_hours": 96.0, "fastest": {...}, "slowest": {...}},
  "remediated": [ {"finding_id","title","severity","subject","device_name","first_seen","resolved_at",
                   "hours_open": 18.4, "how": "auto"|"manual", "occurrences": n} ...],   # newest first, window-limited
  "open_worklist": [ {"finding_id","title","severity","subject","device_name","first_seen","age_days",
                      "occurrences","remediation": ["step 1", ...], "refs": [...]} ...],  # severity desc, then age desc
  "top_devices":  [{"device_id","name","ip","open","resolved"}...],
  "coverage": {"devices_total": n, "devices_online": n, "services_seen": n, "cves_matched": n, "kev_matches": n,
               "last_scans": {"discovery": ts, "services": ts, "host": ts, "exposure": ts, "files": ts},
               "feeds_current": n, "feeds_total": n, "feeds_stale": ["openphish", ...],
               "dns": {"enabled": bool, "queries_24h": n, "blocked_24h": n, "block_rate": 0.31, "clients_24h": n}},
  "defender": {"available": bool, "av_enabled": bool, "rtp": bool, "signature_age_days": n,
               "last_quick_scan": ts|None, "last_full_scan": ts|None, "threats_30d": n},
  "notes": ["Secure Boot could not be checked without administrator rights", ...]   # from host_checks needs_admin
}
```

Rules:
- "Found" counts every findings row ever created (`findings` table is append-mostly; a reopened finding counts once).
- "Remediated" = status `resolved`. `how` is `auto` when the newest `finding_events` row for it is `auto_resolved`
  (the agent re-scanned and the problem was gone — the strongest evidence), else `manual`.
- `hours_open` = `resolved_at - first_seen`. Medians computed on resolved findings inside the window only.
- `open_worklist` pulls `remediation` and `refs` from `homesoc.findings.catalog` so the page is directly actionable.
- Must return a complete, valid dict on an empty database (zeros, empty lists, `None`s) — never raise.

### A3.2 Page `/summary`

Sections, in order:
1. **Header cards** — Security score + grade; Found (all time); Remediated; Still open; Remediation rate; Median time to fix.
2. **Score trend** — line chart over the window (`charts.js`).
3. **Found vs remediated** — a grouped bar chart per severity (found / remediated / open), plus the category table.
4. **Remediated** — table: finding, severity, device, opened, fixed, time open, how (badge `verified by rescan` for auto,
   `marked fixed` for manual). Newest first, paginated client-side.
5. **Still open — what to do next** — the worklist as expandable cards: severity badge, title, affected subject, age,
   the numbered remediation steps from the catalog, reference links, and Acknowledge / Resolve buttons that POST to the
   existing `/api/findings/<id>/status`.
6. **Coverage** — what was scanned and when, feed freshness, DNS filtering stats, Defender status; explicit
   "not checked (needs administrator)" list from `notes`.
7. **Export** — buttons: Download JSON, Download Markdown, Print (uses a print stylesheet; no new endpoint).

### A3.3 API

- `GET /api/summary/report?days=30` → the `build_summary` dict.
- `GET /api/summary/report.md?days=30` → `text/markdown; charset=utf-8`, `Content-Disposition: attachment;
  filename="homesoc-report-<YYYY-MM-DD>.md"`.
- `GET /api/summary/report.json?days=30` → same as the dict, as an attachment.

The Markdown report is a genuine standalone document: title, generated date, score, an executive paragraph
("Home SOC has found N issues on your network; M are fixed, K still need attention"), the found/remediated tables,
the open worklist **with full remediation steps**, and the coverage section. It must be readable by someone who has
never seen the dashboard.

## A4. CLI additions (`homesoc/cli.py`)

```
python -m homesoc report [--days 30] [--format md|json] [--out PATH]   # writes the same report; prints to stdout when --out is absent
python -m homesoc feed [--limit 50] [--kinds a,b] [--since 24h]        # plain-text activity feed for the terminal
```
`report` with no `--out` and `--format md` is the default. Both commands work with the dashboard stopped.

## A5. Tests (`tests/test_feed_summary.py`, owned by the web package)

Offline, fixture-driven, must pass on an empty database and on a seeded one:
- `build_feed` merges all sources, orders strictly by `ts` descending, respects `limit`/`offset`/`since`/`kinds`/
  `severities`/`q`, and aggregates `dns_block` per client+domain+hour.
- Feed items never contain unescaped HTML: seed a device whose hostname is `<img src=x onerror=alert(1)>` and assert the
  rendered `/feed` page escapes it.
- `/api/feed`, `/api/feed/kinds`, `/feed.rss` return the documented shapes; RSS parses with `xml.etree.ElementTree`.
- `build_summary` on an empty DB returns the full key set with zeros; on a seeded DB the arithmetic is exact
  (found/open/resolved counts, remediation rate, median hours, `how` = auto vs manual).
- `/summary` renders; the Markdown report contains the open worklist's remediation steps; the JSON report round-trips.
- `python -m homesoc report --format json` exits 0 and prints valid JSON (subprocess test, marked slow but offline).
