"""Flask app factory for the Home SOC dashboard (SPEC section 15).

Pages are server-rendered Jinja; ``static/app.js`` only enhances them (polling, charts,
POST buttons). Security posture: optional token auth, a CSRF header on every mutating
request, and a ``default-src 'self'`` CSP, which is why there are no inline scripts,
styles or event handlers anywhere in the templates.
"""

from __future__ import annotations

import hashlib
import importlib
import json
import logging
import re
import socket
import sqlite3
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlencode
from xml.etree import ElementTree as ET

from flask import (Flask, Response, abort, g, jsonify, make_response, redirect, render_template,
                   request, send_from_directory)
from markupsafe import Markup, escape

from homesoc import db
from homesoc.web import api
from homesoc.web import feed as feedmod
from homesoc.web import summary as summarymod

logger = logging.getLogger(__name__)

COOKIE_NAME = api.DASHBOARD_COOKIE
SECURE_COOKIE_NAME = api.DASHBOARD_COOKIE_SECURE
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
    ("map", "/map", "Dependency map"),
    ("vulns", "/vulns", "Vulnerabilities"),
    ("host", "/host", "Host posture"),
    ("dns", "/dns", "DNS filter"),
    ("telemetry", "/telemetry", "Telemetry"),
    ("scans", "/scans", "Scans"),
    ("settings", "/settings", "Settings"),
]

# Lens (SPEC addendum B). Paths that authenticate themselves rather than through the dashboard
# token: the two phone pages are shells with no device data in them (everything they show is
# fetched with X-Lens-Token afterwards), and /api/lens/* checks that header itself. /lens/pair
# and /lens/stickers are deliberately absent — they show real inventory, so they stay behind the
# dashboard token like every other page.
LENS_SHELL_PATHS: frozenset[str] = frozenset({"/lens", "/lens/claim", "/lens-sw.js"})
LENS_API_PREFIX = "/api/lens/"
LENS_DEFAULTS: dict[str, Any] = {
    "enabled": False,
    "require_https": True,
    "tag_learning": True,
    "allow_actions": False,
    "token_ttl_days": 90,
    "max_tokens": 10,
}
# Label geometry for /lens/stickers (SPEC B9). Millimetres, because that is what @page understands.
STICKER_FORMATS: dict[str, dict[str, Any]] = {
    "avery": {"label": "Avery 5160 (2.625 × 1 in)", "cols": 3, "rows": 10, "page": "letter"},
    "40mm": {"label": "40 mm square", "cols": 4, "rows": 6, "page": "a4"},
}


def create_app(cfg: Any, conn: sqlite3.Connection, scheduler: Any = None, dns_server: Any = None) -> Flask:
    app = Flask(__name__)
    app.config["JSON_SORT_KEYS"] = False
    token = str(api.cfg_get(cfg, "web.token", "") or "")
    app.config["HOMESOC_TRUSTED_HOSTS"] = trusted_hosts(str(api.cfg_get(cfg, "web.host", "127.0.0.1") or "127.0.0.1"))
    app.extensions["homesoc"] = api.WebContext(cfg=cfg, conn=conn, scheduler=scheduler, dns_server=dns_server, token=token)
    app.register_blueprint(api.bp)
    api.sessions_sync_token(conn, token)
    _warn_weak_token(token)
    api.warn_shadowed_overrides(conn)
    _expire_pairing_codes_when_lens_is_off(cfg, conn)
    _register_lens_blueprints(app)
    _register_security(app)
    _register_template_helpers(app)
    _register_pages(app)
    _register_lens_pages(app)
    _register_feed_routes(app)
    _register_errors(app)
    return app


#: Shorter than this, a hand-picked token falls to guessing even at the rate-limited pace.
MIN_TOKEN_LENGTH = 16


def _warn_weak_token(token: str) -> None:
    if token and len(token) < MIN_TOKEN_LENGTH:
        logger.warning(
            "web.token is only %d characters long. Anyone who can reach the dashboard can guess a short "
            "token; replace it with a long random one (python -m homesoc init writes one).", len(token)
        )


def _expire_pairing_codes_when_lens_is_off(cfg: Any, conn: sqlite3.Connection) -> None:
    """SPEC B10: outstanding pairing codes die when ``lens.enabled`` goes false.

    ``config.set_override`` has the same hook, but nothing in the product calls it for a
    ``lens.*`` key — none of them are in the dashboard's EDITABLE_SETTINGS allowlist, so the
    only way to turn Lens off is editing config.toml and restarting. Doing it here as well means
    the control actually runs on the path the owner really takes, instead of being exercised
    only by its own tests: whichever way Lens is switched off, a code left on a screen is dead
    by the time anything could serve it.
    """
    if api._bool(api.cfg_get(cfg, "lens.enabled", False)):
        return
    try:
        cleared = int(db.lens_clear_pairing_codes(conn) or 0)
    except (AttributeError, sqlite3.Error):  # pre-Lens database, or core db without the helper
        return
    if cleared:
        logger.info("lens is disabled: invalidated %d outstanding pairing code(s)", cleared)


def _register_lens_blueprints(app: Flask) -> None:
    """Attach the Lens API blueprints when their packages are installed.

    ``homesoc.web.lens``/``lens_auth`` are owned by other packages and may not exist (Lens is an
    optional addendum), so this is a best-effort import: Home SOC must start either way.
    """
    for name in ("homesoc.web.lens_auth", "homesoc.web.lens"):
        try:
            module = importlib.import_module(name)
        except ImportError:
            continue
        except Exception:  # pragma: no cover - a broken optional module must not kill the app
            logger.exception("could not import %s", name)
            continue
        blueprint = getattr(module, "bp", None)
        if blueprint is not None and getattr(blueprint, "name", "") not in app.blueprints:
            app.register_blueprint(blueprint)


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


def _client_ip() -> str:
    return str(request.remote_addr or "unknown")[:45]


def _token_ok(c: api.WebContext) -> bool:
    """The request carries the dashboard credential: ``X-Token`` (scripts) or a session cookie.

    The cookie holds a session id, never the token (see api.session_create), so the raw token is
    only ever accepted from a header a browser does not attach on its own. A wrong ``X-Token`` is
    a guess and is counted; a session cookie is checked even while its address is locked out.
    """
    header = request.headers.get("X-Token")
    if header:
        return api.check_token_guess(c.conn, c.token, header, _client_ip())
    sid = api.presented_session()
    state = api.session_check(c.conn, sid)
    if state == "renewed":
        g.homesoc_renew_session = sid
    return state is not None


#: GET pages that change state: showing the pairing page mints a code (and voids the previous
#: one), showing a sticker sheet mints sticker tags, and /logout ends the session and clears the
#: cookie. Another site must not be able to trigger any of them, not even with a top-level link.
STATE_CHANGING_PAGES: frozenset[str] = frozenset({"/lens/pair", "/lens/stickers", "/logout"})

_CROSS_SITE_HTML = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Open this from Home SOC</title>
<link rel="stylesheet" href="/static/style.css">
</head><body data-page="login" data-refresh="0"><main class="main"><div class="card login">
<h1>Open this from Home SOC</h1>
<p>Another website tried to open this Home SOC page, so it was not shown. If that was you,
open Home SOC directly and use its menu.</p>
<p><a href="/">Go to the dashboard</a></p>
</div></main></body></html>
"""


def _foreign_request() -> bool:
    """True when the browser says another site (or another port on this host) made this request.

    ``Sec-Fetch-Site`` is sent by every current browser and cannot be set by page script. Where it
    is missing (an old browser, curl, a feed reader), an ``Origin`` header that is not this exact
    origin is used instead; a request with neither is not a browser cross-site request.
    """
    site = (request.headers.get("Sec-Fetch-Site") or "").lower()
    if site:
        return site not in ("same-origin", "none")
    origin = request.headers.get("Origin")
    if origin is None:
        return False
    return origin != f"{request.scheme}://{request.host}"


#: Desktop pages whose state-changing half is a plain HTML form POST (a browser cannot add the
#: X-Requested-With header to one). Minting a pairing code or sticker codes only ever happens on
#: that POST, never on GET, so loading the page (or an <img> of it) changes nothing.
FORM_POST_PAGES: frozenset[str] = frozenset({"/lens/pair", "/lens/stickers"})


def _same_origin_form() -> bool:
    """True only when the browser positively says this form POST came from this very origin.

    Unlike :func:`_foreign_request`, a request that carries neither ``Sec-Fetch-Site`` nor
    ``Origin`` is refused: every browser sends ``Origin`` on a POST, so its absence means
    something that is not a same-origin form.
    """
    site = (request.headers.get("Sec-Fetch-Site") or "").lower()
    if site:
        return site == "same-origin"
    origin = request.headers.get("Origin")
    return origin is not None and origin == f"{request.scheme}://{request.host}"


def _cross_site_refusal(path: str) -> Response | None:
    """Refuse what another website can make the owner's browser do here.

    Cookies are ``SameSite=Strict``, but with no ``web.token`` (a documented choice on a
    single-user PC) there is no cookie to withhold, so a page on any site could fire requests at
    ``http://127.0.0.1:8787`` from the owner's browser: loop the heaviest API aggregates, or load
    the two pages that change state on GET. What stays allowed from elsewhere is a plain link or
    bookmark to an ordinary page, and static assets.
    """
    if not _foreign_request() or path.startswith("/static/"):
        return None
    navigate = (request.headers.get("Sec-Fetch-Mode") or "navigate").lower() == "navigate"
    if request.method in ("GET", "HEAD") and navigate and path not in STATE_CHANGING_PAGES and not path.startswith("/api/"):
        return None
    logger.warning("refused a cross-site %s %s", request.method, path)
    if path.startswith("/api/"):
        return jsonify({"ok": False, "error": "cross-site request refused"}), 403  # type: ignore[return-value]
    resp = make_response(_CROSS_SITE_HTML, 403)
    resp.headers["Content-Type"] = "text/html; charset=utf-8"
    return resp


#: What a phone consumes. ``/lens/pair`` and ``/lens/stickers`` are deliberately not here:
#: they are desktop pages behind the dashboard token, and the pairing page's whole job is to
#: explain the HTTPS problem — refusing to serve it would hide the instructions for fixing it.
LENS_PHONE_PATHS: frozenset[str] = LENS_SHELL_PATHS

#: The refusal a phone sees. Written out rather than templated because it must survive a
#: half-installed build, and it borrows lens.css (a same-origin stylesheet, so CSP is happy
#: and no style attribute is needed) to look like the app the reader was expecting.
_HTTPS_REQUIRED_HTML = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<meta name="color-scheme" content="dark">
<meta name="theme-color" content="#0b0d13">
<title>Lens needs HTTPS</title>
<link rel="stylesheet" href="/static/lens.css">
</head><body class="lens no-video">
<div class="scrim"></div>
<header class="topbar"><span class="brand"><span class="brand-mark">&#9678;</span> Lens</span>
<span class="state is-bad">needs HTTPS</span></header>
<div class="notice is-bad">
  <h1 class="notice-title">Lens needs HTTPS</h1>
  <p class="notice-body">Home SOC is serving this address over plain HTTP, so Lens is switched
  off here. Phone browsers only grant camera access to a secure origin, and a pairing token
  travelling in clear text over the network would not stay a secret for long.</p>
  <ol class="steps">
    <li>On the computer running Home SOC, stop it.</li>
    <li>Start it again with <code>python -m homesoc serve --tls --host 0.0.0.0 --port 8443</code>.</li>
    <li>Open <code>/lens/pair</code> there and scan the new code with this phone.</li>
    <li>Or follow the Tailscale route in <code>docs/LENS_SETUP.md</code>, which needs no
    certificate warning at all.</li>
  </ol>
  <p class="notice-body">Setting <code>[lens] require_https = false</code> lifts this refusal,
  but it does not make plain HTTP safe: this phone's token, and everything Lens shows, would then
  cross the Wi-Fi in clear text for anyone on it to read and reuse — and the camera still will not
  start without a secure origin. Pairing a new phone is refused over plain HTTP either way.</p>
</div>
</body></html>
"""


def _lens_https_refusal(cfg: Any, path: str) -> Response | None:
    """SPEC B10: Lens over plain HTTP from anywhere but this machine is refused.

    ``request.is_secure`` is the transport the client really used; the peer address is the
    security-meaningful exemption (a ``Host: localhost`` header is attacker-supplied, a
    loopback peer is not). A loopback browser on plain HTTP is already a secure context as
    far as ``getUserMedia`` is concerned, so nothing is lost by letting it through.
    """
    if request.is_secure:
        return None
    if not (path in LENS_PHONE_PATHS or path.startswith(LENS_API_PREFIX)):
        return None
    if not lens_enabled(cfg) or not api._bool(api.cfg_get(cfg, "lens.require_https", True)):
        return None
    if _is_loopback(str(request.remote_addr or "")):
        return None
    logger.warning("refused plain-HTTP Lens request for %s from a non-loopback address", path)
    if path.startswith(LENS_API_PREFIX):
        return jsonify({  # type: ignore[return-value]
            "ok": False, "code": "https_required",
            "error": "Lens refuses to work over plain HTTP. Restart Home SOC with --tls. Setting "
                     "lens.require_https = false lifts this refusal but sends this phone's token "
                     "and everything Lens shows across the network in clear text, and the camera "
                     "still will not start.",
        }), 403
    resp = make_response(_HTTPS_REQUIRED_HTML, 403)
    resp.headers["Content-Type"] = "text/html; charset=utf-8"
    return resp


def _register_security(app: Flask) -> None:
    @app.before_request
    def _auth_and_csrf() -> Response | None:
        c: api.WebContext = app.extensions["homesoc"]
        path = request.path
        refusal = _lens_https_refusal(c.cfg, path)
        if refusal is not None:
            return refusal
        allowed_hosts: frozenset[str] = app.config.get("HOMESOC_TRUSTED_HOSTS") or frozenset()
        if allowed_hosts and _host_header_name().lower() not in allowed_hosts:
            logger.warning("refused request with unexpected Host header %r", request.host)
            return jsonify({"ok": False, "error": "bad host header"}), 400  # type: ignore[return-value]
        foreign = _cross_site_refusal(path)
        if foreign is not None:
            return foreign
        # SPEC-GAP: static assets and the login page are reachable without the token so the
        # login page can be styled; everything else is rejected with 401.
        if c.token and not (path == "/login" or path.startswith("/static/") or _lens_self_authenticating(c.cfg, path)):
            # A ?token= on a navigation that another website started is never evaluated: such a
            # page could otherwise fire hidden iframes with wrong tokens, each counted as a failed
            # guess from the owner's own address, and lock the owner out of signing in.
            query_token = None if _foreign_request() else request.args.get("token")
            if query_token and request.method == "GET" and api.check_token_guess(c.conn, c.token, query_token, _client_ip()):
                # ?token= is only meant for /login; turn it into a session and strip it from the
                # URL so the secret does not stay in the address bar, history and referrers.
                args = [(k, v) for k, v in request.args.items(multi=True) if k != "token"]
                target = path + (("?" + urlencode(args)) if args else "")
                return _signed_in(c, redirect(target))
            if not _token_ok(c):
                if path.startswith("/api/"):
                    return jsonify({"ok": False, "error": "unauthorized"}), 401  # type: ignore[return-value]
                return _login_page(None, 401)
        form_post = request.method == "POST" and path in FORM_POST_PAGES and _same_origin_form()
        if request.method in MUTATING and not (path == "/login" and request.method == "POST") and not form_post:
            # POST /login is a plain form post (a browser cannot add the header to one). It only
            # ever compares a token, the guess limiter counts it, and a cross-site post of it was
            # refused just above. The Lens minting forms (FORM_POST_PAGES) are accepted without
            # the header only when the browser itself vouches that they are same-origin.
            if request.headers.get(CSRF_HEADER, "") != CSRF_VALUE:
                return jsonify({"ok": False, "error": f"missing {CSRF_HEADER}: {CSRF_VALUE} header"}), 403  # type: ignore[return-value]
        g.homesoc = c
        return None

    @app.after_request
    def _headers(resp: Response) -> Response:
        renew = g.pop("homesoc_renew_session", None)
        if renew and "Set-Cookie" not in resp.headers:
            _set_session_cookie(resp, renew)  # the session was extended; so is the cookie
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Content-Security-Policy"] = "default-src 'self'; frame-ancestors 'none'"
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["Referrer-Policy"] = "no-referrer"
        path = request.path
        if path.startswith("/api/"):
            resp.headers["Cache-Control"] = "no-store"
        if resp.status_code == 401 and path.startswith(LENS_API_PREFIX) and request.headers.get("X-Lens-Token"):
            # A phone presented a token that is revoked or expired: have the browser wipe what
            # Lens kept on it (the cached device card), even if an old lens.js is still running.
            resp.headers["Clear-Site-Data"] = '"storage"'

        elif path in ("/lens/pair", "/lens/stickers"):
            # A pairing code and the printed sticker tokens are both one-shot secrets; keeping
            # them out of the browser (and the service worker) cache is free.
            resp.headers["Cache-Control"] = "no-store"
        return resp


def _set_session_cookie(resp: Response, sid: str) -> None:
    """The session cookie. Under TLS it is ``__Host-`` prefixed: Secure, host-only and Path=/,
    so neither a plain-HTTP page nor a sibling host can plant or overwrite it."""
    name = SECURE_COOKIE_NAME if request.is_secure else COOKIE_NAME
    resp.set_cookie(name, sid, httponly=True, samesite="Strict", secure=request.is_secure,
                    max_age=api.SESSION_TTL_SECONDS, path="/")


def _clear_session_cookies(resp: Response) -> None:
    resp.delete_cookie(COOKIE_NAME, path="/", samesite="Strict")
    if request.is_secure:
        resp.delete_cookie(SECURE_COOKIE_NAME, path="/", secure=True, samesite="Strict")


def _signed_in(c: api.WebContext, target: Any) -> Response:
    """``target`` with a fresh session attached, after the right token was presented."""
    resp = make_response(target)
    api.token_guess_reset(_client_ip())
    api.session_revoke(c.conn, api.presented_session())  # never carry a session over a sign-in
    _set_session_cookie(resp, api.session_create(c.conn))
    return resp


def _login_page(error: str | None, status: int) -> Response:
    retry = api.token_guess_retry_after(_client_ip())
    if retry:
        error = f"Too many wrong tokens. Try again in about {max(1, retry // 60)} minute(s)."
        status = 429
    return make_response(render_template("login.html", page="login", page_title="Sign in", error=error), status)


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
    @app.route("/login", methods=["GET", "POST"])
    def login():
        """Sign in. POST (the token in the form body) keeps it out of URLs; ``GET ?token=`` stays
        for the links the CLI and docs print, and is answered with a redirect straight away."""
        c: api.WebContext = app.extensions["homesoc"]
        if not c.token:
            return redirect("/")
        presented = request.form.get("token") if request.method == "POST" else request.args.get("token")
        if request.method != "POST" and _foreign_request():
            # Another site linked here with a ?token=: not the owner's link, and counting it as a
            # wrong guess from the owner's address would let that site lock the owner out.
            presented = None
        if presented and api.check_token_guess(c.conn, c.token, presented, _client_ip()):
            return _signed_in(c, redirect("/"))
        if presented:
            return _login_page("Wrong token.", 401)
        return _login_page(None, 200)

    @app.route("/logout", methods=["GET", "POST"])
    def logout():
        c: api.WebContext = app.extensions["homesoc"]
        api.session_revoke(c.conn, api.presented_session())  # dead on the server, not just forgotten here
        resp = make_response(redirect("/login"))
        _clear_session_cookies(resp)
        return resp

    @app.get("/")
    def overview():
        c: api.WebContext = g.homesoc
        graph = map_view(c.conn, c.cfg)
        return _page("overview.html", "overview", "Overview", summary=api.summary(c),
                     load_bearing=load_bearing(graph, 3), topology_available=graph["available"])

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
        graph = map_view(c.conn, c.cfg)
        return _page("device_detail.html", "devices", d["display_name"], device=d,
                     dep=device_dependencies(c.conn, c.cfg, device_id, graph))

    @app.get("/map")
    def map_page():
        """The dependency map (SPEC addendum C7).

        The graph is handed to the page as JSON rather than fetched, so the first paint needs no
        round trip and the page still draws if the API half is ever absent. Blast radii are
        embedded too — but only when nothing has registered ``/api/map/blast``, since fetching one
        per click beats shipping one per device.
        """
        c: api.WebContext = g.homesoc
        default_hours = api._int_or_none(api.cfg_get(c.cfg, "topology.window_hours", api.DEFAULT_MAP_HOURS)) or api.DEFAULT_MAP_HOURS
        hours = _int_arg("hours", default_hours, 1, api.MAX_MAP_HOURS)
        cloud_arg = request.args.get("cloud")
        cloud = api._bool(api.cfg_get(c.cfg, "topology.include_cloud", True)) if cloud_arg is None else api._bool(cloud_arg)
        graph = map_view(c.conn, c.cfg, hours=hours, cloud=cloud)
        if graph["available"] and not _has_blast_api(app):
            graph["blast"] = {
                str(n["device_id"]): blast
                for n in graph["nodes"]
                if n.get("device_id") is not None
                for blast in [map_blast(c.conn, c.cfg, int(n["device_id"]), graph.get("_engine_graph"))]
                if blast is not None
            }
        return _page(
            "map.html", "map", "Dependency map",
            mapdata={k: v for k, v in graph.items() if not k.startswith("_")},
            available=graph["available"],
            reason=graph["reason"],
            note=api.MAP_NOTE,
            doc=TOPOLOGY_DOC,
            legend=graph["legend"]["confidence"],
            hours=graph.get("window_hours", hours),
            cloud=cloud,
            load_bearing=load_bearing(graph, 3),
        )

    @app.get("/docs/<name>")
    def docs_page(name: str):
        """Serve the one document the map's honesty note links to, as plain text.

        Allowlisted by exact name — no path joining of anything the caller sent — so this cannot
        be walked into a file-read primitive.
        """
        filename = DOC_PAGES.get(name)
        if filename is None:
            abort(404)
        path = Path(__file__).resolve().parents[2] / "docs" / filename
        try:
            text = path.read_text(encoding="utf-8")
        except OSError:
            text = DOC_MISSING
        resp = make_response(text)
        resp.headers["Content-Type"] = "text/plain; charset=utf-8"
        return resp

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


# --------------------------------------------------------------------------- topology (addendum C)
#
# The page half of dependencies and blast radius. The graph itself comes from
# ``homesoc.topology`` through ``api.map_graph``/``map_blast``/``map_criticality`` — the same
# normalisation the JSON API serves, so the picture and the API can never disagree about what was
# observed and what was inferred, and an edge this layer would have to invent simply is not there.
#
# The one thing every surface below keeps straight: Home SOC has no packet visibility. It cannot
# know that the laptop is talking to the NAS, so the note below is rendered on every one of these
# surfaces, never collapsed, and never as small print.

TOPOLOGY_DOC = "/docs/TOPOLOGY.md"
#: Why there is no picture, in the user's words. Never "None": an empty map means either "this has
#: not run yet" or "there is nothing to draw", and those need different next steps.
TOPOLOGY_EMPTY = (
    "There is nothing on the dependency graph yet. It is built by the topology job, which runs "
    "after discovery — run a scan, or start Home SOC with the scheduler attached."
)


def map_view(conn: sqlite3.Connection, cfg: Any, *, hours: int | None = None, cloud: bool | None = None) -> dict[str, Any]:
    """The ``/api/map`` payload for a page, or one that explains why there is no picture.

    Always returns a dict with ``nodes``/``edges``/``legend``/``note`` so the template never has
    to guard every field: ``available`` says whether there is a graph, ``reason`` is the sentence
    to print instead of one.
    """
    hours = api.DEFAULT_MAP_HOURS if hours is None else hours
    include_cloud = api._bool(api.cfg_get(cfg, "topology.include_cloud", True)) if cloud is None else bool(cloud)
    empty: dict[str, Any] = {
        "nodes": [], "edges": [], "legend": api.map_legend(), "note": api.MAP_NOTE,
        "window_hours": hours, "include_cloud": include_cloud, "criticality": [],
        "available": False, "reason": TOPOLOGY_EMPTY, "_engine_graph": None,
    }
    # The engine's own (nodes, edges), kept so the ranking below — and the blast radius on
    # /devices/<id> — reuse this build instead of each starting another. One page used to run
    # the whole dependency graph two or three times, which on a week of DNS is most of its time.
    built: list[Any] = []
    try:
        graph = api.map_graph(conn, hours=hours, include_cloud=include_cloud, engine_out=built)
    except api.TopologyUnavailable as exc:
        empty["reason"] = str(exc) or api.TOPOLOGY_MISSING
        return empty
    except Exception:  # pragma: no cover - a broken engine explains itself instead of 500-ing
        logger.exception("building the dependency graph failed")
        empty["reason"] = "The dependency graph could not be built. The details are in the event log."
        return empty
    engine_graph = built[0] if built else None
    # The engine drops the cloud column from a handed-in graph, so this build can be reused
    # whichever way ``include_cloud`` went: the ranking is identical either way (external
    # endpoints are sinks, so nothing depends on them) and the page pays for one build.
    edges_for_ranking = engine_graph[1] if engine_graph else None
    try:
        graph["criticality"] = api.map_criticality(conn, 10, engine_edges=edges_for_ranking)
    except (api.TopologyUnavailable, Exception):  # ranking is a bonus; the graph stands without it
        graph["criticality"] = []
    graph["available"] = bool(graph.get("nodes"))
    graph["reason"] = "" if graph["available"] else TOPOLOGY_EMPTY
    # Underscored, and stripped before the payload is serialised for the page: these are the
    # engine's own dataclasses, useful only to the engine and not JSON at all.
    graph["_engine_graph"] = engine_graph if include_cloud else None
    return graph


def map_blast(conn: sqlite3.Connection, cfg: Any, device_id: int, engine_graph: Any = None) -> dict[str, Any] | None:
    """One device's blast radius, or None when the engine cannot produce it.

    ``engine_graph`` is the ``(nodes, edges)`` the page already built. ``blast_radius`` wants the
    cloud-inclusive graph, which is what ``map_view`` stores, so passing it is safe only when
    that build included cloud — ``map_view`` sets the key to None otherwise.
    """
    try:
        return api.map_blast(conn, int(device_id), cfg=cfg, engine_graph=engine_graph)
    except api.TopologyUnavailable as exc:
        logger.debug("no blast radius for device %s: %s", device_id, exc)
        return None
    except Exception:  # pragma: no cover
        logger.exception("blast radius failed for device %s", device_id)
        return None


def device_dependencies(conn: sqlite3.Connection, cfg: Any, device_id: int, graph: dict[str, Any]) -> dict[str, Any]:
    """The "Depends on / Depended on by / If this fails" slice for one device (SPEC C7)."""
    node_id = f"device:{int(device_id)}"
    by_id = {str(n.get("id")): n for n in graph.get("nodes") or []}
    me = by_id.get(node_id)

    def side(edge: dict[str, Any], end: str) -> dict[str, Any]:
        other = by_id.get(str(edge.get(end))) or {"id": edge.get(end), "label": edge.get(end), "kind": "unknown"}
        row = {k: other.get(k) for k in ("id", "label", "kind", "device_id", "online")}
        row.update({k: edge.get(k) for k in ("edge_type", "protocol", "confidence", "evidence", "observed_count")})
        return row

    edges = graph.get("edges") or []
    return {
        "available": bool(graph.get("available")) and me is not None,
        "reason": graph.get("reason") or "This device is not on the dependency graph yet.",
        "node": me,
        "depends_on": [side(e, "dst") for e in edges if e.get("src") == node_id],
        "dependents": [side(e, "src") for e in edges if e.get("dst") == node_id],
        "blast": map_blast(conn, cfg, device_id, graph.get("_engine_graph")) if graph.get("available") else None,
        "note": api.MAP_NOTE,
        "doc": TOPOLOGY_DOC,
    }


def load_bearing(graph: dict[str, Any], limit: int = 3) -> list[dict[str, Any]]:
    """Top devices by criticality for the overview card and the map's idle panel (SPEC C7)."""
    ranked = [dict(r) for r in (graph.get("criticality") or []) if r.get("device_id") is not None]
    if not ranked:
        # No ranking from the engine: fall back to the nodes' own criticality rather than an
        # empty card, ordered the same way the API would have ordered it.
        ranked = [
            {"device_id": n["device_id"], "label": n["label"], "dependents": n.get("depended_on_by", n.get("criticality", 0)),
             "weight": n.get("criticality", 0), "why": ""}
            for n in (graph.get("nodes") or [])
            if n.get("device_id") is not None and (n.get("depended_on_by") or n.get("criticality"))
        ]
        ranked.sort(key=lambda r: (-int(r.get("weight") or 0), -int(r.get("dependents") or 0), str(r.get("label") or "").lower()))
    return ranked[:limit]


def _has_blast_api(app: Flask) -> bool:
    """True when ``/api/map/blast/<id>`` is registered.

    When it is, the map fetches one blast radius per click. When it is not — an install without
    that half of the API — the page carries the ones it needs, so /map works either way.
    """
    return any(str(rule.rule).startswith("/api/map/blast") for rule in app.url_map.iter_rules())


#: The one document the map's note links to. Served as plain text because Home SOC ships no
#: Markdown renderer and will not grow a dependency for one page. Allowlisted by exact name, so
#: this can never be walked into a file-read primitive.
DOC_PAGES: dict[str, str] = {"TOPOLOGY.md": "TOPOLOGY.md"}
DOC_MISSING = """Home SOC — why the dependency map is not a traffic diagram
=========================================================

docs/TOPOLOGY.md is not installed next to this copy of Home SOC, so here is the short version.

Home SOC watches a home network from one ordinary machine on it. It is not the router, it is not
a managed switch mirroring a port, and it has no packet capture. Traffic between two devices on
the LAN — your laptop opening a file on the NAS, your phone printing — never reaches it. It
therefore cannot know those conversations happened, and it will not draw an arrow saying they did.

What it can honestly say:

  observed  It saw the thing itself: a DNS lookup arriving from that device at its own resolver,
            a service the device advertised over mDNS, or a set of devices that went offline in
            the same discovery cycle.
  inferred  It follows from how the network is shaped: every device on the gateway's own subnet
            reaches the internet through it.
  assumed   A reasonable default nothing has confirmed, such as a LAN device being reachable
            through the gateway when there is no route data at all.

So a printer advertising _printer._tcp appears as something that offers printing, with no
confirmed consumers — not with a line to every device in the house that might plausibly print.
A hub's Zigbee, Z-Wave, Thread or Bluetooth children are not on the IP network and are invisible
here; the map never pretends to know how many there are.

What would make this map dramatically better: a managed switch's bridge table over SNMP, conntrack
from an OpenWrt or pfSense router, a passive listener on a spare machine, or a reader for UPnP
port mappings, SSDP advertisements and the DHCP lease file — none of which Home SOC has today. Running the resolver
on a spare Raspberry Pi would also remove DNS as a single point of failure and make every device's
lookups visible, which is most of the missing evidence.
"""


# --------------------------------------------------------------------------- lens (addendum B)


@dataclass(frozen=True)
class Check:
    """One row of the /lens/pair preflight (SPEC B4.1): what was tested, and how to fix it."""

    key: str
    title: str
    level: str  # "ok" | "warn" | "fail"
    detail: str
    fix: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return self.level == "ok"


def lens_config(cfg: Any) -> dict[str, Any]:
    """The ``[lens]`` section with SPEC B3 defaults, read structurally like every other section."""
    out: dict[str, Any] = {}
    for key, default in LENS_DEFAULTS.items():
        value = api.cfg_get(cfg, f"lens.{key}", default)
        out[key] = api._bool(value) if isinstance(default, bool) else value
    for key in ("token_ttl_days", "max_tokens"):
        try:
            out[key] = int(out[key])
        except (TypeError, ValueError):
            out[key] = LENS_DEFAULTS[key]
    return out


def lens_enabled(cfg: Any) -> bool:
    return bool(api._bool(api.cfg_get(cfg, "lens.enabled", False)))


def _lens_self_authenticating(cfg: Any, path: str) -> bool:
    if not lens_enabled(cfg):
        return False  # master switch off: these paths 404 anyway, so never widen auth for them
    return path in LENS_SHELL_PATHS or path.startswith(LENS_API_PREFIX)


def _require_lens() -> dict[str, Any]:
    """Every Lens page is a 404 while ``lens.enabled`` is false (SPEC B3/B10)."""
    c: api.WebContext = g.homesoc
    if not lens_enabled(c.cfg):
        abort(404)
    return lens_config(c.cfg)


def _lens_helper(candidates: tuple[tuple[str, str], ...]) -> Any | None:
    """First importable callable from ``candidates``.

    The Lens transport (``homesoc.web.tls``/``lens_auth``) and identification
    (``homesoc.web.lens``) modules are owned by other packages and are optional, so the pages
    degrade to an explanation rather than a traceback when they are not installed.
    """
    for module_name, attr in candidates:
        try:
            module = importlib.import_module(module_name)
        except ImportError:
            continue
        except Exception:  # pragma: no cover - broken optional module
            logger.exception("could not import %s", module_name)
            continue
        fn = getattr(module, attr, None)
        if callable(fn):
            return fn
    return None


_QR_RENDERERS: tuple[tuple[str, str], ...] = (("homesoc.web.qr", "to_svg"), ("homesoc.web.qr", "svg"))
_QR_ENCODERS: tuple[tuple[str, str], ...] = (
    ("homesoc.web.qr", "encode"),
    ("homesoc.web.qr", "matrix"),
    ("homesoc.web.qr", "make"),
)
_PAIRING_MINTERS: tuple[tuple[str, str], ...] = (
    ("homesoc.web.lens_auth", "mint_pairing_code"),
    ("homesoc.web.lens_auth", "new_pairing_code"),
    ("homesoc.web.lens_auth", "create_pairing_code"),
    ("homesoc.web.lens", "mint_pairing_code"),
    ("homesoc.web.lens", "new_pairing_code"),
)
_STICKER_MINTERS: tuple[tuple[str, str], ...] = (("homesoc.web.lens", "mint_sticker_codes"),)
_STICKER_LOOKUPS: tuple[tuple[str, str], ...] = (("homesoc.web.lens", "existing_sticker_codes"),)


def qr_svg(payload: str, *, css_class: str = "qr") -> Markup | None:
    """Inline SVG for ``payload`` from the hand-rolled encoder, or None when it is unavailable.

    Only markup that actually starts with ``<svg`` is trusted into the page; anything else is
    dropped rather than interpolated, so a future renderer change cannot become an injection.
    """
    render = _lens_helper(_QR_RENDERERS)
    if render is None:
        return None
    svg: Any = None
    for args in ((payload,), None):
        try:
            if args is None:
                encode = _lens_helper(_QR_ENCODERS)
                if encode is None:
                    return None
                svg = render(encode(payload))
            else:
                svg = render(*args)
            break
        except TypeError:
            continue
        except Exception:  # pragma: no cover - encoder failure must not break the page
            logger.exception("QR rendering failed")
            return None
    text = str(svg or "").strip()
    if not text.startswith("<svg"):
        return None
    if css_class and 'class="' not in text.split(">", 1)[0]:
        text = text.replace("<svg", f'<svg class="{escape(css_class)}"', 1)
    return Markup(text)


def _as_pairing(value: Any) -> dict[str, Any] | None:
    """Normalise whatever the pairing minter returns into ``{code, expires_at}``."""
    if value is None:
        return None
    if isinstance(value, str):
        return {"code": value, "expires_at": None}
    if isinstance(value, dict):
        code = value.get("code") or value.get("pairing_code")
        return {"code": str(code), "expires_at": value.get("expires_at")} if code else None
    if isinstance(value, (tuple, list)) and value:
        return {"code": str(value[0]), "expires_at": value[1] if len(value) > 1 else None}
    code = getattr(value, "code", None)
    return {"code": str(code), "expires_at": getattr(value, "expires_at", None)} if code else None


def mint_pairing_code(conn: sqlite3.Connection, cfg: Any) -> dict[str, Any] | None:
    fn = _lens_helper(_PAIRING_MINTERS)
    if fn is None:
        return None
    for args in ((conn,), (conn, cfg)):
        try:
            return _as_pairing(fn(*args))
        except TypeError:
            continue
        except Exception:
            logger.exception("could not mint a Lens pairing code")
            return None
    return None


def mint_sticker_codes(conn: sqlite3.Connection, device_ids: list[int]) -> dict[int, str]:
    """Idempotent sticker tokens per device (SPEC B9); empty when the Lens package is absent."""
    fn = _lens_helper(_STICKER_MINTERS)
    if fn is None or not device_ids:
        return {}
    try:
        minted = fn(conn, device_ids)
    except Exception:
        logger.exception("could not mint Lens sticker codes")
        return {}
    out: dict[int, str] = {}
    for key, value in dict(minted or {}).items():
        try:
            out[int(key)] = str(value)
        except (TypeError, ValueError):
            continue
    return out


def existing_sticker_codes(conn: sqlite3.Connection, device_ids: list[int]) -> dict[int, str]:
    """Sticker codes that already exist for ``device_ids``. Read-only: never mints anything."""
    fn = _lens_helper(_STICKER_LOOKUPS)
    if fn is None or not device_ids:
        return {}
    try:
        found = fn(conn, device_ids)
    except Exception:
        logger.exception("could not read Lens sticker codes")
        return {}
    out: dict[int, str] = {}
    for key, value in dict(found or {}).items():
        try:
            out[int(key)] = str(value)
        except (TypeError, ValueError):
            continue
    return out


def cert_state() -> dict[str, Any]:
    """What ``homesoc.web.tls`` can tell us about the certificate, without ever raising."""
    try:
        tls = importlib.import_module("homesoc.web.tls")
    except ImportError:
        return {"status": "no-module", "error": "the Lens TLS helper is not installed"}
    except Exception as exc:  # pragma: no cover - broken optional module
        return {"status": "error", "error": str(exc)}
    try:
        cert, _key = tls.cert_paths()
    except Exception as exc:
        return {"status": "error", "error": str(exc)}
    try:
        if not cert.exists():
            return {"status": "missing", "path": str(cert)}
        info = dict(tls.cert_info(cert) or {})
        info["status"] = "ok"
        info["path"] = str(cert)
        return info
    except Exception as exc:
        # TlsUnavailable (no `cryptography`) lands here with the message the user needs.
        return {"status": "unavailable", "error": str(exc), "path": str(cert)}


#: Settings key written by ``cli.record_bind_state`` at every start: ``host:port``.
BIND_SETTING = "lens.bind"


def effective_bind(cfg: Any, conn: sqlite3.Connection | None) -> tuple[str, int]:
    """Where the server is *actually* listening, which is not always what config says.

    ``serve --host 0.0.0.0 --port 8443`` — the invocation SPEC B3 documents — overrides
    ``config.toml`` for the life of the process, so a preflight that reads ``web.host``
    alone tells a user to edit config and restart a server that is already reachable
    (and, the other way round, mints a pairing URL for an address nothing answers on).

    The recorded bind is the only trustworthy source: the serving process wrote it itself.
    The ``Host`` header deliberately is *not* consulted — it is attacker-influencable, and
    ``trusted_hosts`` already accepts this machine's LAN address on a loopback-only socket,
    so believing it would report "reachable from your phone" when nothing is listening there.
    """
    host = str(api.cfg_get(cfg, "web.host", "127.0.0.1") or "127.0.0.1")
    port = int(api.cfg_get(cfg, "web.port", 8787) or 8787)
    if conn is not None:
        try:
            raw = str(db.get_setting(conn, BIND_SETTING, "") or "")
        except sqlite3.Error:
            raw = ""
        if raw and ":" in raw:
            bound_host, _, bound_port = raw.rpartition(":")
            if bound_host:
                host = bound_host
            if bound_port.isdigit():
                port = int(bound_port)
    return host, port


def _lan_host(cfg: Any, conn: sqlite3.Connection | None = None) -> str:
    """The address a phone should dial. The bind host when it is a real one, else this PC's."""
    host, _port = effective_bind(cfg, conn)
    if host not in ("0.0.0.0", "::", "[::]", "127.0.0.1", "localhost", "::1"):
        return host
    try:
        from homesoc import util  # type: ignore

        found = str(util.default_interface_ip() or "")
    except Exception:
        found = ""
    if not found or found.startswith("127."):
        try:
            found = socket.gethostbyname(socket.gethostname())
        except OSError:
            found = ""
    return found or "127.0.0.1"


#: Bind addresses that mean "every interface". A socket listens on them; nothing dials them.
WILDCARD_HOSTS: frozenset[str] = frozenset({"0.0.0.0", "::", "[::]", "*"})


def _is_loopback(host: str) -> bool:
    return host.lower() in ("127.0.0.1", "localhost", "::1", "[::1]") or host.startswith("127.")


def _is_dialable(host: str) -> bool:
    """Can a phone actually put this in its address bar and reach Home SOC?

    Loopback reaches only this PC, and a wildcard bind is not an address at all — a QR code
    containing ``https://0.0.0.0:8443/...`` is a dead link, which is exactly what the pairing
    screen used to mint whenever the owner followed SPEC B3's own ``--host 0.0.0.0``.
    """
    return bool(host) and not _is_loopback(host) and host.lower() not in WILDCARD_HOSTS


def lens_preflight(cfg: Any, conn: sqlite3.Connection, lens: dict[str, Any]) -> list[Check]:
    """SPEC B4.1: refuse to hand out a pairing code until the phone can actually use it."""
    checks: list[Check] = []
    # The address the server is really on, not just the one config asks for: `serve --host`
    # wins over config.toml for the life of the process (see app.effective_bind).
    bind, _bind_port = effective_bind(cfg, conn)
    lan = _lan_host(cfg, conn)
    if _is_loopback(bind):
        checks.append(
            Check(
                "host",
                "Reachable from your phone",
                "fail",
                f"Home SOC is bound to {bind}, which only this computer can reach.",
                [
                    'Set [web] host = "0.0.0.0" in config.toml (or Settings → web.host).',
                    "Restart Home SOC so the new binding takes effect "
                    "(or start it once with: python -m homesoc serve --tls --host 0.0.0.0 --port 8443).",
                    "Run scripts/enable-lens.ps1 as administrator to open the port on the Private firewall profile.",
                ],
            )
        )
    else:
        checks.append(Check("host", "Reachable from your phone", "ok", f"Listening on {bind}; phones should use {lan}.", []))

    cert = cert_state()
    status = cert.get("status")
    if status == "ok":
        days = cert.get("days_left")
        detail = f"Self-signed certificate in place, fingerprint below." + (f" Expires in {days} days." if isinstance(days, int) else "")
        level = "warn" if isinstance(days, int) and days < 14 else "ok"
        fix = ["python -m homesoc lens cert --regenerate"] if level == "warn" else []
        checks.append(Check("cert", "HTTPS certificate", level, detail, fix))
    elif status == "missing":
        checks.append(
            Check("cert", "HTTPS certificate", "fail", "No certificate has been generated yet.", [f"python -m homesoc lens cert --regenerate --hosts {lan}", "Restart with: python -m homesoc serve --tls --host 0.0.0.0 --port 8443"])
        )
    else:
        checks.append(
            Check(
                "cert",
                "HTTPS certificate",
                "fail",
                str(cert.get("error") or "The certificate helper is unavailable."),
                ["pip install cryptography", "python -m homesoc lens cert --regenerate", "Or put Home SOC behind Tailscale Serve — see docs/LENS_SETUP.md."],
            )
        )

    sans = [str(s) for s in (cert.get("sans") or [])]
    if status == "ok" and sans and lan not in sans:
        checks.append(
            Check("sans", "Certificate covers this address", "warn", f"The certificate does not list {lan}; the phone will warn every visit.", [f"python -m homesoc lens cert --regenerate --hosts {lan}"])
        )

    if request.is_secure:
        checks.append(Check("https", "Served over HTTPS", "ok", "This page arrived over HTTPS, so the phone camera will be allowed to start.", []))
    elif not _is_loopback(bind):
        # Blocking whatever `require_https` says. That flag decides whether Lens will *serve* an
        # already-paired phone over plain HTTP; it has no business deciding whether Home SOC will
        # *issue a credential* over one. Minting here would put an 8-character pairing code and
        # the 90-day bearer token it buys onto the Wi-Fi in clear text, where copying them is the
        # whole attack — and the camera would not start either way.
        detail = ("This page arrived over plain HTTP while Home SOC is listening on the network. The pairing "
                  "code and the phone's long-lived token would cross the network in clear text and can simply "
                  "be copied by anyone on the same Wi-Fi. Chrome would also refuse the camera on this origin.")
        if not lens["require_https"]:
            detail += (" lens.require_https is false, which lifts the refusal to serve a phone that is already "
                       "paired; it does not make it safe to hand out a new token here.")
        checks.append(
            Check(
                "https",
                "Served over HTTPS",
                "fail",
                detail,
                ["Stop Home SOC.", "Start it again with: python -m homesoc serve --tls --host 0.0.0.0 --port 8443", "Re-open this page at https://" + lan + ":8443/lens/pair"],
            )
        )
    else:
        # Loopback plain HTTP: a secure context as far as the browser is concerned, and nothing
        # leaves this machine — but the phone still cannot reach it, which the host check says.
        checks.append(Check("https", "Served over HTTPS", "warn", "This page is plain HTTP on the loopback address. Nothing leaves this computer, but a phone cannot reach it either.", ['Serve with --tls and open this page at the LAN address.']))

    paired = _paired_count(conn)
    if paired is None:
        checks.append(Check("tokens", "Paired phones", "warn", "The lens_tokens table does not exist yet, so pairing cannot be recorded.", ["Restart Home SOC once so the database migration runs."]))
    elif paired >= lens["max_tokens"]:
        checks.append(Check("tokens", "Paired phones", "fail", f"{paired} of {lens['max_tokens']} slots are in use.", ["python -m homesoc lens tokens", "python -m homesoc lens revoke <id>"]))
    else:
        checks.append(Check("tokens", "Paired phones", "ok", f"{paired} of {lens['max_tokens']} slots in use.", []))
    return checks


def _paired_count(conn: sqlite3.Connection) -> int | None:
    try:
        return int(api.scalar(conn, "SELECT count(*) FROM lens_tokens WHERE revoked_at IS NULL"))
    except sqlite3.Error:
        return None


def _tagged_device_ids(conn: sqlite3.Connection, kinds: tuple[str, ...] = ()) -> set[int] | None:
    """Device ids that already carry a tag, optionally only of the given kinds."""
    sql = "SELECT DISTINCT device_id FROM lens_tags WHERE device_id IS NOT NULL"
    params: tuple[Any, ...] = ()
    if kinds:
        sql += " AND kind IN (%s)" % ",".join("?" for _ in kinds)
        params = tuple(kinds)
    try:
        found = api.rows(conn, sql, params)
    except sqlite3.Error:
        return None
    return {int(r["device_id"]) for r in found if r.get("device_id") is not None}


def _register_lens_pages(app: Flask) -> None:
    @app.get("/lens")
    def lens_page():
        lens = _require_lens()
        c: api.WebContext = g.homesoc
        return render_template(
            "lens.html",
            page="lens",
            page_title="Lens",
            app_name=str(api.cfg_get(c.cfg, "general.name", "Home SOC")),
            lens=lens,
            mode="scan",
        )

    @app.get("/lens/claim")
    def lens_claim_page():
        lens = _require_lens()
        c: api.WebContext = g.homesoc
        return render_template(
            "lens_claim.html",
            page="lens-claim",
            page_title="Pair this phone",
            app_name=str(api.cfg_get(c.cfg, "general.name", "Home SOC")),
            lens=lens,
            mode="claim",
        )

    @app.get("/lens-sw.js")
    def lens_service_worker():
        """Served from the root so the worker may claim the ``/lens`` scope.

        A worker at /static/sw.js is scoped to /static/ and could never control /lens, and
        widening that with Service-Worker-Allowed would let it control every static asset.
        """
        _require_lens()
        worker = _service_worker_source(app.static_folder or "static")
        if worker is None:  # pragma: no cover - only when static/sw.js is missing
            resp = make_response(send_from_directory(app.static_folder or "static", "sw.js", mimetype="text/javascript"))
        else:
            resp = make_response(worker)
            resp.headers["Content-Type"] = "text/javascript; charset=utf-8"
        resp.headers["Cache-Control"] = "no-cache"
        return resp

    @app.route("/lens/pair", methods=["GET", "POST"])
    def lens_pair_page():
        """GET explains and checks; only the page's own "Show a pairing code" form (a same-origin
        POST) mints a code. Minting voids the previous code, so a GET that minted let any web
        page break pairing with an <img> tag."""
        lens = _require_lens()
        c: api.WebContext = g.homesoc
        checks = lens_preflight(c.cfg, c.conn, lens)
        blocked = [chk for chk in checks if chk.level == "fail"]
        _bind, port = effective_bind(c.cfg, c.conn)
        # Never the bind host verbatim: it is routinely 0.0.0.0 (SPEC B3's own serve line) or
        # loopback, and neither is something a phone can dial. _lan_host resolves both to this
        # PC's LAN address, which is what the preflight above already tells the owner to use.
        lan = _lan_host(c.cfg, c.conn)
        scheme = "https" if (request.is_secure or lens["require_https"]) else "http"
        reached_over_lan = bool(request.host) and _is_dialable(_host_header_name())
        if reached_over_lan:
            # The owner reached this page over the LAN, so that address demonstrably works.
            base = f"{scheme}://{request.host}"
        else:
            base = f"{scheme}://{lan}:{port}"
        # Belt and braces over the preflight's blocking HTTPS check: a pairing code is a
        # credential, and one is never minted into a plain-HTTP URL that leaves this machine —
        # whatever lens.require_https says. require_https stays an escape hatch for serving a
        # phone that is already paired, never for issuing the token in the first place.
        claim_host = _host_header_name() if reached_over_lan else lan
        insecure_claim = scheme == "http" and not _is_loopback(claim_host)
        can_mint = not (blocked or insecure_claim)
        pairing = mint_pairing_code(c.conn, c.cfg) if (can_mint and request.method == "POST") else None
        claim_url = f"{base}/lens/claim#c={pairing['code']}" if pairing else ""
        cert = cert_state()
        return render_template(
            "lens_pair.html",
            page="lens-pair",
            page_title="Pair a phone",
            app_name=str(api.cfg_get(c.cfg, "general.name", "Home SOC")),
            lens=lens,
            checks=checks,
            blocked=blocked,
            pairing=pairing,
            can_mint=can_mint,
            minted=request.method == "POST",
            claim_url=claim_url,
            qr=qr_svg(claim_url) if claim_url else None,
            fingerprint=_fingerprint_groups(cert.get("fingerprint")),
            cert=cert,
            base=base,
            ttl_days=lens["token_ttl_days"],
        )

    @app.route("/lens/stickers", methods=["GET", "POST"])
    def lens_stickers_page():
        """GET shows the sheet with the codes that already exist; only the page's own
        "Create codes" form (a same-origin POST) mints the missing ones."""
        lens = _require_lens()
        c: api.WebContext = g.homesoc
        params = request.values
        size = params.get("size") if params.get("size") in STICKER_FORMATS else "avery"
        which = "all" if params.get("which") == "all" else "untagged"
        show_names = params.get("names", "1") != "0"
        devices = api.devices_list(c.conn)
        # SPEC B9: the default sheet is "all devices without a tag" — any tag, learned or
        # sticker. Minting happens after this filter, so once a device has been on a sheet it
        # drops off the default the next time; that is why the template's empty state points
        # at "All devices", which reprints the very same codes (minting is idempotent).
        tagged = _tagged_device_ids(c.conn)
        if which == "untagged" and tagged is not None:
            devices = [d for d in devices if int(d["id"]) not in tagged]
        devices = devices[:120]
        ids = [int(d["id"]) for d in devices]
        minting_now = request.method == "POST"
        codes = mint_sticker_codes(c.conn, ids) if minting_now else existing_sticker_codes(c.conn, ids)
        installed = _lens_helper(_STICKER_MINTERS) is not None
        labels = [
            {"device": d, "code": codes.get(int(d["id"]), ""), "qr": qr_svg(codes[int(d["id"])], css_class="qr") if codes.get(int(d["id"])) else None}
            for d in devices
        ]
        fmt = STICKER_FORMATS[str(size)]
        per_page = int(fmt["cols"]) * int(fmt["rows"])
        pages = [labels[i : i + per_page] for i in range(0, len(labels), per_page)] or [[]]
        return render_template(
            "lens_stickers.html",
            page="lens-stickers",
            page_title="Sticker sheet",
            app_name=str(api.cfg_get(c.cfg, "general.name", "Home SOC")),
            lens=lens,
            size=size,
            formats=STICKER_FORMATS,
            which=which,
            show_names=show_names,
            labels=labels,
            pages=pages,
            minting=installed,
            minted=minting_now,
            missing=sum(1 for i in ids if i not in codes),
        )


#: Files whose contents decide whether a cached Lens shell is stale.
_SHELL_SOURCES: tuple[str, ...] = ("sw.js", "lens.js", "lens.css", "manifest.webmanifest")
_SHELL_WORKER: dict[str, str] = {}


def shell_version(static_folder: str) -> str:
    """Short fingerprint of the Lens shell assets, used as the service worker's cache name.

    The worker caches ``lens.js``/``lens.css`` cache-first. With a hard-coded cache name nothing
    ever invalidated them, and since ``/lens-sw.js`` was byte-identical across an upgrade no new
    worker installed either — so the first open after a Lens change served the new HTML against
    the previous script. Deriving the name from the files themselves makes an upgraded asset a
    different worker, which is a different cache, which is a fresh fetch. No build step, no
    version query strings to keep in sync.
    """
    digest = hashlib.sha256()
    root = Path(static_folder)
    for name in _SHELL_SOURCES:
        try:
            digest.update(name.encode("utf-8"))
            digest.update((root / name).read_bytes())
        except OSError:  # a missing shell file must not stop Lens serving the worker
            digest.update(b"?")
    try:
        digest.update((Path(__file__).parent / "templates" / "lens.html").read_bytes())
    except OSError:
        digest.update(b"?")
    return digest.hexdigest()[:12]


def _service_worker_source(static_folder: str) -> str | None:
    """``static/sw.js`` with its cache name stamped, or ``None`` when it cannot be read."""
    cached = _SHELL_WORKER.get(static_folder)
    if cached is not None:
        return cached
    try:
        source = (Path(static_folder) / "sw.js").read_text(encoding="utf-8")
    except OSError:
        return None
    stamped = source.replace("__SHELL_VERSION__", shell_version(static_folder))
    _SHELL_WORKER[static_folder] = stamped
    return stamped


def _fingerprint_groups(value: Any) -> list[str]:
    """SHA-256 fingerprint split into readable groups of four bytes for the pairing screen."""
    text = str(value or "").replace(" ", "").upper()
    if not text:
        return []
    parts = text.split(":") if ":" in text else [text[i : i + 2] for i in range(0, len(text), 2)]
    return [":".join(parts[i : i + 4]) for i in range(0, len(parts), 4)]


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


#: Everything outside the XML 1.0 ``Char`` production. ElementTree escapes markup but writes these
#: through unchanged, and one of them anywhere makes every RSS reader reject the whole document.
_XML_INVALID = re.compile("[\x00-\x08\x0b\x0c\x0e-\x1f\ud800-\udfff\ufffe\uffff]")


def _xml_text(value: Any) -> str:
    return _XML_INVALID.sub("", "" if value is None else str(value))


def _rss(items: list, app_name: str) -> str:
    """RSS 2.0 of the newest items. ElementTree escapes every value, so hostnames and domains
    from the network can never break out of the document, and :func:`_xml_text` drops the
    control characters a device can put in its mDNS name, which would otherwise leave the
    document malformed for every reader."""
    rss = ET.Element("rss", {"version": "2.0"})
    channel = ET.SubElement(rss, "channel")
    ET.SubElement(channel, "title").text = _xml_text(f"{app_name} activity")
    ET.SubElement(channel, "link").text = _xml_text(request.url_root.rstrip("/") + "/feed")
    ET.SubElement(channel, "description").text = "Everything Home SOC observed and did on this network."
    ET.SubElement(channel, "lastBuildDate").text = api.now_iso()
    for item in items:
        node = ET.SubElement(channel, "item")
        ET.SubElement(node, "title").text = _xml_text(item.title)
        ET.SubElement(node, "link").text = _xml_text(request.url_root.rstrip("/") + (item.link or "/feed"))
        ET.SubElement(node, "description").text = _xml_text(item.detail or item.title)
        ET.SubElement(node, "category").text = _xml_text(item.kind)
        ET.SubElement(node, "pubDate").text = _xml_text(item.ts)
        digest = hashlib.sha256(f"{item.kind}|{item.ts}|{item.title}".encode("utf-8", "replace")).hexdigest()[:16]
        guid = ET.SubElement(node, "guid", {"isPermaLink": "false"})
        guid.text = _xml_text(f"homesoc:{item.kind}:{item.ts}:{digest}")
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
