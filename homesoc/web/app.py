"""Flask app factory for the Home SOC dashboard (SPEC section 15).

Pages are server-rendered Jinja; ``static/app.js`` only enhances them (polling, charts,
POST buttons). Security posture: optional token auth, a CSRF header on every mutating
request, and a ``default-src 'self'`` CSP, which is why there are no inline scripts,
styles or event handlers anywhere in the templates.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import socket
import sqlite3
from typing import Any
from urllib.parse import urlencode
from xml.etree import ElementTree as ET

from flask import Flask, Response, abort, g, jsonify, make_response, redirect, render_template, request
from markupsafe import Markup, escape

from homesoc.web import api
from homesoc.web import feed as feedmod
from homesoc.web import summary as summarymod

logger = logging.getLogger(__name__)

COOKIE_NAME = "homesoc_token"
CSRF_HEADER = "X-Requested-With"
CSRF_VALUE = "fetch"
MUTATING = frozenset({"POST", "PUT", "PATCH", "DELETE"})
FEED_WINDOWS: tuple[tuple[str, str, int], ...] = (
    ("1h", "Last hour", 1),
    ("24h", "Last 24 hours", 24),
    ("7d", "Last 7 days", 24 * 7),
    ("30d", "Last 30 days", 24 * 30),
    ("all", "All time", 0),
)
NAV: list[tuple[str, str, str]] = [
    ("overview", "/", "Overview"),
    ("feed", "/feed", "Activity feed"),
    ("summary", "/summary", "Summary"),
    ("findings", "/findings", "Findings"),
    ("devices", "/devices", "Devices"),
    ("vulns", "/vulns", "Vulnerabilities"),
    ("host", "/host", "Host posture"),
    ("dns", "/dns", "DNS filter"),
    ("telemetry", "/telemetry", "Telemetry"),
    ("scans", "/scans", "Scans"),
    ("settings", "/settings", "Settings"),
]


def create_app(cfg: Any, conn: sqlite3.Connection, scheduler: Any = None, dns_server: Any = None) -> Flask:
    app = Flask(__name__)
    app.config["JSON_SORT_KEYS"] = False
    token = str(api.cfg_get(cfg, "web.token", "") or "")
    app.config["HOMESOC_TRUSTED_HOSTS"] = trusted_hosts(str(api.cfg_get(cfg, "web.host", "127.0.0.1") or "127.0.0.1"))
    app.extensions["homesoc"] = api.WebContext(cfg=cfg, conn=conn, scheduler=scheduler, dns_server=dns_server, token=token)
    app.register_blueprint(api.bp)
    _register_security(app)
    _register_template_helpers(app)
    _register_pages(app)
    _register_feed_routes(app)
    _register_errors(app)
    return app


# --------------------------------------------------------------------------- security


def trusted_hosts(bind_host: str) -> frozenset[str]:
    """Host header values the dashboard answers to.

    A page on attacker.example that DNS-rebinds its own name to 127.0.0.1:8787 becomes same-origin
    with the dashboard in the browser; the only thing that still tells it apart is the Host header,
    so anything outside this allowlist is refused with 400. SPEC-GAP: the spec has no such list;
    loopback, the bind address, this PC's LAN address and hostname cover every legitimate URL.
    """
    hosts = {"127.0.0.1", "localhost", "::1", "[::1]"}
    if bind_host and bind_host not in ("0.0.0.0", "::", "[::]"):
        hosts.add(bind_host)
    name = ""
    try:
        from homesoc import util  # type: ignore

        hosts.add(util.default_interface_ip())
        name = util.local_hostname()
    except Exception:  # pragma: no cover - core package absent
        pass
    if not name:
        try:
            name = socket.gethostname()
        except OSError:  # pragma: no cover - no hostname configured
            name = ""
    if name:
        hosts.add(name)
        hosts.add(f"{name}.local")
        # Every address this machine answers on, so a second NIC (Wi-Fi + Ethernet, or a VPN)
        # does not lock the owner out of their own dashboard. Resolved once, at startup.
        try:
            for info in socket.getaddrinfo(name, None):
                addr = info[4][0]
                if addr:
                    hosts.add(addr.split("%", 1)[0])  # drop any IPv6 zone index
        except OSError:
            logger.debug("could not enumerate local addresses for %r", name)
    return frozenset(h.lower() for h in hosts if h)


def _host_header_name() -> str:
    host = request.host or ""
    if host.startswith("["):  # [::1]:8787
        return host.split("]", 1)[0] + "]"
    return host.rsplit(":", 1)[0] if host.count(":") == 1 else host


def _presented_token(*, allow_query: bool) -> str | None:
    query = request.args.get("token") if allow_query else None
    return query or request.headers.get("X-Token") or request.cookies.get(COOKIE_NAME)


def _token_ok(expected: str, *, allow_query: bool = False) -> bool:
    got = _presented_token(allow_query=allow_query)
    return bool(got) and hmac.compare_digest(got.encode(), expected.encode())


def _register_security(app: Flask) -> None:
    @app.before_request
    def _auth_and_csrf() -> Response | None:
        c: api.WebContext = app.extensions["homesoc"]
        path = request.path
        allowed_hosts: frozenset[str] = app.config.get("HOMESOC_TRUSTED_HOSTS") or frozenset()
        if allowed_hosts and _host_header_name().lower() not in allowed_hosts:
            logger.warning("refused request with unexpected Host header %r", request.host)
            return jsonify({"ok": False, "error": "bad host header"}), 400  # type: ignore[return-value]
        # SPEC-GAP: static assets and the login page are reachable without the token so the
        # login page can be styled; everything else is rejected with 401.
        if c.token and not (path == "/login" or path.startswith("/static/")):
            query_token = request.args.get("token")
            if query_token and request.method == "GET" and hmac.compare_digest(query_token.encode(), c.token.encode()):
                # ?token= is only meant for /login; turn it into the cookie and strip it from the
                # URL so the secret does not stay in the address bar, history and referrers.
                args = [(k, v) for k, v in request.args.items(multi=True) if k != "token"]
                target = path + (("?" + urlencode(args)) if args else "")
                resp = make_response(redirect(target))
                _set_token_cookie(resp, query_token)
                return resp
            if not _token_ok(c.token):
                if path.startswith("/api/"):
                    return jsonify({"ok": False, "error": "unauthorized"}), 401  # type: ignore[return-value]
                return make_response(render_template("login.html", page="login", page_title="Sign in", error=None), 401)
        if request.method in MUTATING:
            if request.headers.get(CSRF_HEADER, "") != CSRF_VALUE:
                return jsonify({"ok": False, "error": f"missing {CSRF_HEADER}: {CSRF_VALUE} header"}), 403  # type: ignore[return-value]
        g.homesoc = c
        return None

    @app.after_request
    def _headers(resp: Response) -> Response:
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Content-Security-Policy"] = "default-src 'self'; frame-ancestors 'none'"
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["Referrer-Policy"] = "no-referrer"
        if request.path.startswith("/api/"):
            resp.headers["Cache-Control"] = "no-store"
        return resp


def _set_token_cookie(resp: Response, token: str) -> None:
    resp.set_cookie(COOKIE_NAME, token, httponly=True, samesite="Strict", secure=request.is_secure, max_age=30 * 86400)


# --------------------------------------------------------------------------- templates


def _badge(kind: str, text: Any = None, extra: str = "") -> Markup:
    text = kind if text is None else text
    kind = str(kind or "").lower().replace("_", "-")
    return Markup(f'<span class="badge badge-{escape(kind)}{(" " + escape(extra)) if extra else ""}">{escape(text)}</span>')


def _register_template_helpers(app: Flask) -> None:
    @app.template_filter("ago")
    def _ago(value: Any) -> str:
        dt = api.parse_ts(value)
        if dt is None:
            return "never"
        secs = int((api.utcnow() - dt).total_seconds())
        if secs < 0:
            return "in " + _span(-secs)
        return _span(secs) + " ago"

    @app.template_filter("ts")
    def _ts(value: Any) -> str:
        dt = api.parse_ts(value)
        return dt.strftime("%Y-%m-%d %H:%M UTC") if dt else "—"

    @app.template_filter("pretty")
    def _pretty(value: Any) -> str:
        if value in (None, ""):
            return ""
        if isinstance(value, str):
            value = api.loads(value, value)
        return value if isinstance(value, str) else json.dumps(value, indent=2, sort_keys=True, default=str)

    @app.template_filter("num")
    def _num(value: Any) -> str:
        try:
            return f"{int(value):,}"
        except (TypeError, ValueError):
            return "0"

    @app.template_filter("hours")
    def _hours(value: Any) -> str:
        if not isinstance(value, (int, float)):
            return "—"
        if value < 1:
            return f"{int(value * 60)} min"
        if value < 48:
            return f"{value:.1f} h"
        return f"{value / 24:.1f} days"

    app.jinja_env.globals.update(
        badge=_badge,
        sev=lambda s: _badge(s, s),
        nav=NAV,
        severities=api.SEVERITIES,
        statuses=api.STATUSES,
        icon_glyph=ICON_GLYPH,
    )


# Ascii/unicode glyphs for feed.FeedItem.icon — no image assets, CSP-safe.
ICON_GLYPH: dict[str, str] = {
    "finding": "▲",
    "resolved": "✔",
    "device": "▣",
    "scan": "◎",
    "feed": "⇩",
    "dns": "⊘",
    "threat": "☢",
    "notify": "✉",
    "system": "⚙",
}


def _span(secs: int) -> str:
    for unit, size in (("d", 86400), ("h", 3600), ("m", 60)):
        if secs >= size:
            return f"{secs // size}{unit}"
    return f"{secs}s"


# --------------------------------------------------------------------------- pages


def _page(template: str, page: str, title: str, **data: Any) -> str:
    c: api.WebContext = g.homesoc
    base = {
        "page": page,
        "page_title": title,
        "app_name": str(api.cfg_get(c.cfg, "general.name", "Home SOC")),
        "refresh": int(api.cfg_get(c.cfg, "web.refresh_seconds", 15) or 15),
        "dns_enabled": api._bool(api.cfg_get(c.cfg, "dns.enabled", False)),
        "has_scheduler": c.scheduler is not None,
    }
    return render_template(template, **base, **data)


def _register_pages(app: Flask) -> None:
    @app.get("/login")
    def login():
        c: api.WebContext = app.extensions["homesoc"]
        if not c.token:
            return redirect("/")
        presented = request.args.get("token")
        if presented and hmac.compare_digest(presented.encode(), c.token.encode()):
            resp = make_response(redirect("/"))
            _set_token_cookie(resp, presented)
            return resp
        error = "Wrong token." if presented else None
        return make_response(render_template("login.html", page="login", page_title="Sign in", error=error), 401 if presented else 200)

    @app.get("/logout")
    def logout():
        resp = make_response(redirect("/login"))
        resp.delete_cookie(COOKIE_NAME)
        return resp

    @app.get("/")
    def overview():
        c: api.WebContext = g.homesoc
        return _page("overview.html", "overview", "Overview", summary=api.summary(c))

    @app.get("/feed")
    def feed_page():
        c: api.WebContext = g.homesoc
        f = _feed_filters()
        items, total = feedmod.build_feed(c.conn, **_feed_kwargs(f))
        return _page(
            "feed.html",
            "feed",
            "Activity feed",
            items=items,
            total=total,
            filters=f,
            kinds=feedmod.feed_kinds(),
            counts=feedmod.feed_counts(c.conn, 24),
            windows=FEED_WINDOWS,
            groups=_group_by_day(items),
        )

    @app.get("/summary")
    def summary_page():
        c: api.WebContext = g.homesoc
        days = _int_arg("days", 30, 1, 3650)
        data = summarymod.build_summary(c.conn, days=days)
        return _page("summary.html", "summary", "Security summary", data=data, days=days)

    @app.get("/findings")
    def findings():
        c: api.WebContext = g.homesoc
        f = {k: (request.args.get(k) or "") for k in ("status", "severity", "category", "q")}
        items = api.findings_list(c.conn, status=f["status"] or None, severity=f["severity"] or None, q=f["q"][:200] or None, category=f["category"] or None)
        categories = sorted(set(api.CATEGORY_BY_PREFIX.values()) | {i["category"] for i in items})
        return _page("findings.html", "findings", "Findings", findings=items, filters=f, categories=categories, counts=api.finding_counts(c.conn))

    @app.get("/devices")
    def devices():
        c: api.WebContext = g.homesoc
        return _page("devices.html", "devices", "Devices", devices=api.devices_list(c.conn), counts=api.device_counts(c.conn))

    @app.get("/devices/<int:device_id>")
    def device_detail(device_id: int):
        c: api.WebContext = g.homesoc
        d = api.device_detail(c.conn, device_id)
        if d is None:
            abort(404)
        return _page("device_detail.html", "devices", d["display_name"], device=d)

    @app.get("/vulns")
    def vulns():
        c: api.WebContext = g.homesoc
        f = {"kev": request.args.get("kev") or "", "q": request.args.get("q") or "", "min_cvss": request.args.get("min_cvss") or ""}
        try:
            min_cvss = float(f["min_cvss"]) if f["min_cvss"] else None
        except ValueError:
            min_cvss = None
        items = api.vulns_list(c.conn, kev=api._bool(f["kev"]), q=f["q"][:200] or None, min_cvss=min_cvss)
        return _page("vulns.html", "vulns", "Vulnerabilities", vulns=items, filters=f)

    @app.get("/host")
    def host():
        c: api.WebContext = g.homesoc
        data = api.host_data(c.conn)
        groups: dict[str, list[dict]] = {}
        for chk in data["checks"]:
            groups.setdefault(chk["group"], []).append(chk)
        return _page("host.html", "host", "Host posture", host=data, groups=groups)

    @app.get("/dns")
    def dns():
        c: api.WebContext = g.homesoc
        return _page(
            "dns.html",
            "dns",
            "DNS filter",
            dns=api.dns_summary(c),
            top_blocked=api.dns_top(c.conn, "blocked"),
            top_clients=api.dns_top(c.conn, "clients"),
            lists=api.dns_lists(c),
            overrides=api.dns_overrides(c.conn),
            reputation=api.dns_reputation(c.conn, 100),
        )

    @app.get("/telemetry")
    def telemetry():
        c: api.WebContext = g.homesoc
        return _page("telemetry.html", "telemetry", "Telemetry", jobs=api.telemetry_jobs(c), scans=api.scans_list(c.conn, 50), metric_names=api.telemetry_metrics(c.conn)["names"])

    @app.get("/scans")
    def scans():
        c: api.WebContext = g.homesoc
        return _page("scans.html", "scans", "Scans", scans=api.scans_list(c.conn), last=api.last_scans(c.conn), kinds=api.SCAN_KINDS)

    @app.get("/settings")
    def settings():
        c: api.WebContext = g.homesoc
        items = api.settings_get(c)
        sections: dict[str, list[dict]] = {}
        for it in items:
            sections.setdefault(it["section"], []).append(it)
        return _page("settings.html", "settings", "Settings", sections=sections)


# ------------------------------------------------------------------ feed / summary plumbing


def _int_arg(name: str, default: int, lo: int, hi: int) -> int:
    try:
        return max(lo, min(int(request.args.get(name, default)), hi))
    except (TypeError, ValueError):
        return default


def _feed_filters() -> dict:
    """Parse the feed query string once, for both the page and ``/api/feed``."""
    window = request.args.get("window") or "24h"
    if window not in {w for w, _, _ in FEED_WINDOWS}:
        window = "24h"
    kinds = [k for k in (request.args.get("kinds") or "").split(",") if k in feedmod.KINDS]
    severity = request.args.get("severity") or ""
    if severity not in api.SEVERITIES:
        severity = ""
    return {
        "window": window,
        "kinds": kinds,
        "severity": severity,
        "q": (request.args.get("q") or "").strip()[:200],
        "limit": _int_arg("limit", 200, 1, feedmod.MAX_LIMIT),
        "offset": _int_arg("offset", 0, 0, feedmod.MAX_OFFSET),
        "since": (request.args.get("since") or "").strip()[:40],
        "until": (request.args.get("until") or "").strip()[:40],
    }


def _feed_kwargs(f: dict) -> dict:
    """Filters -> ``build_feed`` keyword arguments (minimum severity expands to a set)."""
    hours = {w: h for w, _, h in FEED_WINDOWS}.get(f["window"], 24)
    since = f["since"] or (api.cutoff_iso(hours) if hours else None)
    severities = None
    if f["severity"]:
        cut = api.SEVERITIES.index(f["severity"])
        severities = set(api.SEVERITIES[: cut + 1])
    return {
        "since": since,
        "until": f["until"] or None,
        "kinds": set(f["kinds"]) or None,
        "severities": severities,
        "q": f["q"] or None,
        "limit": f["limit"],
        "offset": f["offset"],
    }


def _group_by_day(items: list) -> list[tuple[str, list]]:
    """[(label, items)] with 'Today' / 'Yesterday' / 'YYYY-MM-DD' labels, order preserved."""
    today = api.utcnow().date()
    groups: list[tuple[str, list]] = []
    for item in items:
        dt = api.parse_ts(item.ts)
        day = dt.date() if dt else today
        delta = (today - day).days
        label = "Today" if delta == 0 else "Yesterday" if delta == 1 else day.isoformat()
        if groups and groups[-1][0] == label:
            groups[-1][1].append(item)
        else:
            groups.append((label, [item]))
    return groups


def _rss(items: list, app_name: str) -> str:
    """RSS 2.0 of the newest items. ElementTree escapes every value, so hostnames and domains
    from the network can never break out of the document."""
    rss = ET.Element("rss", {"version": "2.0"})
    channel = ET.SubElement(rss, "channel")
    ET.SubElement(channel, "title").text = f"{app_name} activity"
    ET.SubElement(channel, "link").text = request.url_root.rstrip("/") + "/feed"
    ET.SubElement(channel, "description").text = "Everything Home SOC observed and did on this network."
    ET.SubElement(channel, "lastBuildDate").text = api.now_iso()
    for item in items:
        node = ET.SubElement(channel, "item")
        ET.SubElement(node, "title").text = item.title
        ET.SubElement(node, "link").text = request.url_root.rstrip("/") + (item.link or "/feed")
        ET.SubElement(node, "description").text = item.detail or item.title
        ET.SubElement(node, "category").text = item.kind
        ET.SubElement(node, "pubDate").text = item.ts
        digest = hashlib.sha256(f"{item.kind}|{item.ts}|{item.title}".encode("utf-8")).hexdigest()[:16]
        guid = ET.SubElement(node, "guid", {"isPermaLink": "false"})
        guid.text = f"homesoc:{item.kind}:{item.ts}:{digest}"
    return '<?xml version="1.0" encoding="utf-8"?>\n' + ET.tostring(rss, encoding="unicode")


def _register_feed_routes(app: Flask) -> None:
    @app.get("/api/feed")
    def api_feed():
        c: api.WebContext = g.homesoc
        f = _feed_filters()
        items, total = feedmod.build_feed(c.conn, **_feed_kwargs(f))
        return jsonify(
            {
                "items": [i.as_dict() for i in items],
                "total": total,
                "counts": feedmod.feed_counts(c.conn, 24),
                "generated_at": api.now_iso(),
            }
        )

    @app.get("/api/feed/kinds")
    def api_feed_kinds():
        return jsonify({"kinds": feedmod.feed_kinds()})

    @app.get("/feed.rss")
    def feed_rss():
        c: api.WebContext = g.homesoc
        items, _ = feedmod.build_feed(c.conn, limit=100)
        body = _rss(items, str(api.cfg_get(c.cfg, "general.name", "Home SOC")))
        return Response(body, mimetype="application/rss+xml")

    @app.get("/api/summary/report")
    def api_summary_report():
        c: api.WebContext = g.homesoc
        return jsonify(summarymod.remediation_report_json(c.conn, days=_int_arg("days", 30, 1, 3650)))

    @app.get("/api/summary/report.json")
    def api_summary_report_json():
        c: api.WebContext = g.homesoc
        data = summarymod.remediation_report_json(c.conn, days=_int_arg("days", 30, 1, 3650))
        return Response(
            json.dumps(data, indent=2, default=str),
            mimetype="application/json",
            headers={"Content-Disposition": f'attachment; filename="{_report_name("json")}"'},
        )

    @app.get("/api/summary/report.md")
    def api_summary_report_md():
        c: api.WebContext = g.homesoc
        body = summarymod.remediation_report_markdown(c.conn, days=_int_arg("days", 30, 1, 3650))
        return Response(
            body,
            mimetype="text/markdown",
            headers={
                "Content-Type": "text/markdown; charset=utf-8",
                "Content-Disposition": f'attachment; filename="{_report_name("md")}"',
            },
        )


def _report_name(ext: str) -> str:
    return f"homesoc-report-{api.utcnow().strftime('%Y-%m-%d')}.{ext}"


# --------------------------------------------------------------------------- errors


def _register_errors(app: Flask) -> None:
    @app.errorhandler(404)
    def _not_found(_err):
        if request.path.startswith("/api/"):
            return jsonify({"ok": False, "error": "not found"}), 404
        return make_response(render_template("login.html", page="404", page_title="Not found", error="Page not found.", not_found=True), 404)

    @app.errorhandler(405)
    def _bad_method(_err):
        return jsonify({"ok": False, "error": "method not allowed"}), 405

    @app.errorhandler(500)
    def _server_error(err):
        logger.exception("unhandled error: %s", err)
        return jsonify({"ok": False, "error": "internal error"}), 500
