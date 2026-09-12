"""Domain reputation: VirusTotal (keyed, budgeted) + URLhaus (keyless), async worker, NET-DNS-004.

Design constraints from SPEC §12: lookups must never block a DNS answer (hence the worker queue),
the VirusTotal free tier is 4 req/min and 500/day (hence the token bucket and the persisted daily
counter shared with ``scanners.files``), and only *newly seen* registrable domains are looked up so a
chatty LAN does not burn the budget on google.com.
"""
from __future__ import annotations

import ipaddress
import json
import logging
import queue
import re
import sqlite3
import threading
import time
import datetime as dt
from dataclasses import dataclass, field
from typing import Callable
from urllib.parse import quote

from homesoc.dnsfilter import (
    apply_findings,
    cfg_get,
    db_one,
    db_write,
    get_setting,
    make_draft,
    set_setting,
    utcnow_iso,
)

logger = logging.getLogger(__name__)

VT_URL = "https://www.virustotal.com/api/v3/domains/{domain}"
URLHAUS_URL = "https://urlhaus-api.abuse.ch/v1/host/"
HTTP_TIMEOUT = 10.0
VT_PER_MINUTE = 4
VERDICTS = ("malicious", "suspicious", "clean", "unknown")
FINDING_DEDUPE_HOURS = 24
SEEN_WINDOW_HOURS = 24
# A lookup that produced no verdict (budget spent, offline) is retried after this long, not 24 h.
NO_VERDICT_RETRY_HOURS = 1
QUEUE_MAX = 5000
# Hostname grammar (same as policy._DOMAIN_RE): DNS labels may legally contain '/', '?', '#' or '%',
# which must never reach the VirusTotal URL path or the URLhaus form field.
_HOSTNAME_RE = re.compile(r"^(?=.{1,253}$)[a-z0-9_](?:[a-z0-9_-]{0,62}[a-z0-9_])?(?:\.[a-z0-9_](?:[a-z0-9_-]{0,62}[a-z0-9_])?)+$")

# Second-level public suffixes where the registrable domain has three labels.
_TWO_LEVEL_SUFFIXES = frozenset(
    {
        "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk", "net.uk", "ltd.uk", "plc.uk", "com.au", "net.au", "org.au",
        "edu.au", "gov.au", "co.nz", "net.nz", "org.nz", "co.jp", "ne.jp", "or.jp", "ac.jp", "go.jp", "com.br",
        "net.br", "org.br", "gov.br", "com.mx", "org.mx", "gob.mx", "co.za", "org.za", "com.ar", "com.co", "com.pe",
        "com.ve", "com.ec", "com.uy", "com.cn", "net.cn", "org.cn", "gov.cn", "com.tw", "com.hk", "co.kr", "or.kr",
        "co.in", "net.in", "org.in", "com.sg", "com.my", "co.id", "com.ph", "com.vn", "com.tr", "co.il", "com.eg",
        "com.sa", "com.pk", "com.ng", "co.ke", "com.ua", "com.pl", "co.th", "com.bd", "com.np", "com.lk",
    }
)

# ~200 well-known domains that are never worth a reputation lookup (SPEC: "top-1k well-known list").
WELL_KNOWN: frozenset[str] = frozenset(
    """
    google.com googleapis.com gstatic.com googleusercontent.com googlevideo.com youtube.com ytimg.com
    ggpht.com gvt1.com gvt2.com google-analytics.com googletagmanager.com doubleclick.net googlesyndication.com
    googleadservices.com android.com goo.gl gmail.com googleapis.cn firebaseio.com crashlytics.com
    microsoft.com microsoftonline.com live.com office.com office365.com office.net outlook.com hotmail.com
    windows.com windowsupdate.com msftconnecttest.com msftncsi.com msn.com bing.com azure.com azureedge.net
    azure.net windows.net msedge.net skype.com xbox.com xboxlive.com onedrive.com sharepoint.com visualstudio.com
    microsoftstore.com msauth.net msecnd.net trafficmanager.net aka.ms mp.microsoft.com
    apple.com icloud.com icloud-content.com mzstatic.com apple-dns.net aaplimg.com itunes.com cdn-apple.com
    apple.news push.apple.com akadns.net akamai.net akamaiedge.net akamaihd.net akamaized.net edgesuite.net
    edgekey.net cloudfront.net amazonaws.com amazon.com amazon.co.uk amazon.de amazon.ca amazon.com.au
    amazon.in amazon.co.jp amazon.fr amazon.it amazon.es media-amazon.com ssl-images-amazon.com a2z.com
    amazonvideo.com primevideo.com alexa.com images-amazon.com amazontrust.com awsstatic.com
    facebook.com fbcdn.net fb.com instagram.com cdninstagram.com whatsapp.com whatsapp.net messenger.com
    meta.com oculus.com twitter.com twimg.com x.com t.co linkedin.com licdn.com reddit.com redd.it
    redditstatic.com redditmedia.com pinterest.com pinimg.com tumblr.com snapchat.com sc-cdn.net tiktok.com
    tiktokcdn.com tiktokv.com byteoversea.com discord.com discordapp.com discord.gg discordapp.net telegram.org
    signal.org slack.com slack-edge.com zoom.us teams.microsoft.com webex.com
    netflix.com nflxvideo.net nflximg.net nflxext.com nflxso.net hulu.com disneyplus.com disney.com bamgrid.com
    spotify.com scdn.co spotifycdn.com twitch.tv ttvnw.net jtvnw.net roku.com sonos.com plex.tv hbomax.com
    paramountplus.com peacocktv.com pandora.com soundcloud.com vimeo.com vimeocdn.com dailymotion.com
    cloudflare.com cloudflare-dns.com cloudflareinsights.com cloudflare.net one.one.one.one quad9.net
    fastly.net fastlylb.net jsdelivr.net unpkg.com cdnjs.com bootstrapcdn.com jquery.com gstatic.cn
    github.com githubusercontent.com github.io githubassets.com gitlab.com bitbucket.org atlassian.com
    atlassian.net npmjs.org npmjs.com pypi.org pythonhosted.org python.org nodejs.org rubygems.org
    docker.com docker.io ubuntu.com canonical.com debian.org fedoraproject.org redhat.com centos.org
    archlinux.org kernel.org mozilla.org mozilla.net mozilla.com firefox.com cdn.mozilla.net
    wikipedia.org wikimedia.org wiktionary.org stackoverflow.com stackexchange.com medium.com
    wordpress.com wordpress.org wp.com gravatar.com squarespace.com wix.com shopify.com shopifycdn.com
    ebay.com ebaystatic.com paypal.com paypalobjects.com stripe.com walmart.com target.com bestbuy.com
    costco.com homedepot.com etsy.com aliexpress.com alibaba.com alicdn.com
    nytimes.com washingtonpost.com cnn.com bbc.co.uk bbc.com theguardian.com reuters.com bloomberg.com
    wsj.com forbes.com yahoo.com yimg.com aol.com att.com verizon.com t-mobile.com comcast.net
    xfinity.com spectrum.net cox.net
    adobe.com adobe.io typekit.net dropbox.com dropboxapi.com box.com salesforce.com force.com hubspot.com
    zendesk.com intercom.io mailchimp.com sendgrid.net cloudflare-ipfs.com
    nvidia.com intel.com amd.com dell.com lenovo.com hp.com logitech.com samsung.com lg.com sony.com
    playstation.com playstation.net nintendo.com nintendo.net steampowered.com steamcommunity.com
    steamstatic.com epicgames.com unrealengine.com ea.com origin.com blizzard.com battle.net riotgames.com
    ubisoft.com minecraft.net mojang.com
    ntp.org pool.ntp.org time.windows.com time.apple.com time.google.com nist.gov letsencrypt.org
    digicert.com globalsign.com sectigo.com godaddy.com identrust.com ocsp.apple.com pki.goog
    duckduckgo.com brave.com opera.com vivaldi.com protonmail.com proton.me tutanota.com
    grammarly.com grammarly.io notion.so figma.com canva.com trello.com asana.com
    """.split()
)


# ---- helpers ------------------------------------------------------------------------------------
def registrable_domain(name: str) -> str:
    """``cdn3.assets.example.co.uk`` → ``example.co.uk``; IP literals and single labels come back unchanged."""
    n = name.strip().rstrip(".").lower()
    if not n:
        return n
    try:
        ipaddress.ip_address(n)
        return n
    except ValueError:
        pass
    labels = n.split(".")
    if len(labels) <= 2:
        return n
    if ".".join(labels[-2:]) in _TWO_LEVEL_SUFFIXES and len(labels) >= 3:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def is_well_known(name: str) -> bool:
    return registrable_domain(name) in WELL_KNOWN


def worst_verdict(*verdicts: str) -> str:
    for v in VERDICTS:  # ordered worst → best
        if v in verdicts:
            return v
    return "unknown"


# ---- budget -------------------------------------------------------------------------------------
class Budget:
    """Daily counter persisted in settings ``vt.budget.<YYYY-MM-DD>`` + 4/min token bucket.

    Persisting the daily count matters because the process restarts often on a laptop; without it
    a few restarts would blow past the free-tier quota and VirusTotal would start returning 429s.
    """

    SETTING_PREFIX = "vt.budget."

    def __init__(self, conn: sqlite3.Connection | None, daily_limit: int, per_minute: int = VT_PER_MINUTE) -> None:
        self.conn = conn
        self.daily_limit = max(0, int(daily_limit))
        self.per_minute = max(1, int(per_minute))
        self._tokens = float(self.per_minute)
        self._last_refill = time.monotonic()
        self._lock = threading.Lock()
        self._date = self._today()
        self._used = self._load_used(self._date)

    @staticmethod
    def _today() -> str:
        return dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%d")

    def _load_used(self, date: str) -> int:
        if self.conn is None:
            return 0
        try:
            return int(get_setting(self.conn, self.SETTING_PREFIX + date, "0") or 0)
        except (ValueError, sqlite3.Error):
            return 0

    def _persist(self) -> None:
        if self.conn is None:
            return
        try:
            set_setting(self.conn, self.SETTING_PREFIX + self._date, str(self._used))
        except sqlite3.Error:
            logger.debug("could not persist VT budget", exc_info=True)

    def _roll_day(self) -> None:
        today = self._today()
        if today != self._date:
            self._date = today
            self._used = self._load_used(today)

    def _refill(self, now: float) -> None:
        elapsed = max(0.0, now - self._last_refill)  # injected clocks may start below monotonic()
        self._last_refill = now
        self._tokens = min(float(self.per_minute), self._tokens + elapsed * self.per_minute / 60.0)

    def try_acquire(self, *, now: float | None = None) -> bool:
        """Consume one request slot if both the minute bucket and the daily quota allow it."""
        now = time.monotonic() if now is None else now
        with self._lock:
            self._roll_day()
            self._refill(now)
            if self._used >= self.daily_limit or self._tokens < 1.0:
                return False
            self._tokens -= 1.0
            self._used += 1
            self._persist()
            return True

    def used_today(self) -> int:
        with self._lock:
            self._roll_day()
            return self._used

    def remaining_today(self) -> int:
        return max(0, self.daily_limit - self.used_today())

    def status(self) -> dict:
        return {"date": self._date, "used": self.used_today(), "limit": self.daily_limit, "per_minute": self.per_minute}


_shared_budget: Budget | None = None
_shared_lock = threading.Lock()


def shared_budget(cfg, conn: sqlite3.Connection | None) -> Budget:
    """Process-wide budget so ``scanners.files`` and the DNS worker draw from the same daily quota."""
    global _shared_budget
    limit = int(cfg_get(cfg, "dns", "virustotal_daily_budget", 400) or 0)
    with _shared_lock:
        if _shared_budget is None or _shared_budget.daily_limit != limit or (_shared_budget.conn is None and conn is not None):
            _shared_budget = Budget(conn, limit)
        return _shared_budget


# ---- lookups ------------------------------------------------------------------------------------
@dataclass
class ReputationResult:
    domain: str
    verdict: str = "unknown"
    malicious: int = 0
    suspicious: int = 0
    source: str = "none"
    raw: dict = field(default_factory=dict)
    cached: bool = False
    checked_at: str = ""


def _session_or_default(session):
    if session is not None:
        return session
    import requests

    return requests.Session()


def vt_lookup(domain: str, api_key: str, *, session=None, timeout: float = HTTP_TIMEOUT) -> dict | None:
    """VirusTotal v3 ``/domains/<d>`` → ``last_analysis_stats`` dict, or None on any failure."""
    if not _HOSTNAME_RE.match(domain):
        return None
    s = _session_or_default(session)
    try:
        resp = s.get(VT_URL.format(domain=quote(domain, safe="")), headers={"x-apikey": api_key, "accept": "application/json"}, timeout=timeout)
    except Exception as exc:
        logger.debug("VT request failed for %s: %s", domain, exc)
        return None
    status = getattr(resp, "status_code", 0)
    if status == 404:
        return {"malicious": 0, "suspicious": 0, "harmless": 0, "undetected": 0, "_not_found": True}
    if status != 200:
        logger.info("VT returned HTTP %s for %s", status, domain)
        return None
    try:
        body = resp.json()
        stats = body["data"]["attributes"]["last_analysis_stats"]
        return {k: int(stats.get(k, 0) or 0) for k in ("malicious", "suspicious", "harmless", "undetected")}
    except (ValueError, KeyError, TypeError, AttributeError):
        logger.debug("VT response unparsable for %s", domain)
        return None


def urlhaus_lookup(domain: str, *, auth_key: str = "", session=None, timeout: float = HTTP_TIMEOUT) -> dict | None:
    """URLhaus host API → ``{listed, online, offline}``; None on network/parse failure."""
    if not _HOSTNAME_RE.match(domain):
        return None
    s = _session_or_default(session)
    headers = {"accept": "application/json"}
    if auth_key:
        headers["Auth-Key"] = auth_key
    try:
        resp = s.post(URLHAUS_URL, data={"host": domain}, headers=headers, timeout=timeout)
    except Exception as exc:
        logger.debug("URLhaus request failed for %s: %s", domain, exc)
        return None
    if getattr(resp, "status_code", 0) != 200:
        return None
    try:
        body = resp.json()
    except ValueError:
        return None
    if not isinstance(body, dict):
        return None
    qs = str(body.get("query_status", ""))
    if qs != "ok":
        return {"listed": False, "online": 0, "offline": 0, "query_status": qs}
    urls = body.get("urls") or []
    online = sum(1 for u in urls if isinstance(u, dict) and str(u.get("url_status", "")).lower() == "online")
    offline = sum(1 for u in urls if isinstance(u, dict) and str(u.get("url_status", "")).lower() != "online")
    return {"listed": True, "online": online, "offline": offline, "query_status": qs, "url_count": len(urls)}


def cached_result(conn: sqlite3.Connection, domain: str, ttl_hours: float) -> ReputationResult | None:
    try:
        row = db_one(
            conn,
            "SELECT domain, source, verdict, malicious, suspicious, checked_at, raw FROM reputation WHERE domain = ?",
            (domain,),
        )
    except sqlite3.Error:
        return None
    if row is None:
        return None
    cutoff = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(hours=ttl_hours)).strftime("%Y-%m-%dT%H:%M:%SZ")
    if str(row["checked_at"]) < cutoff:
        return None
    if str(row["source"]) == "none":
        # No source answered (budget spent, offline): that is not a verdict worth caching for days.
        short = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(hours=NO_VERDICT_RETRY_HOURS)).strftime("%Y-%m-%dT%H:%M:%SZ")
        if str(row["checked_at"]) < short:
            return None
    try:
        raw = json.loads(row["raw"]) if row["raw"] else {}
    except ValueError:
        raw = {}
    return ReputationResult(
        domain=domain, verdict=str(row["verdict"]), malicious=int(row["malicious"] or 0),
        suspicious=int(row["suspicious"] or 0), source=str(row["source"]), raw=raw, cached=True,
        checked_at=str(row["checked_at"]),
    )


def store_result(conn: sqlite3.Connection, result: ReputationResult) -> None:
    result.checked_at = result.checked_at or utcnow_iso()
    db_write(
        conn,
        "INSERT INTO reputation(domain, source, verdict, malicious, suspicious, checked_at, raw) VALUES (?,?,?,?,?,?,?)"
        " ON CONFLICT(domain) DO UPDATE SET source = excluded.source, verdict = excluded.verdict,"
        " malicious = excluded.malicious, suspicious = excluded.suspicious, checked_at = excluded.checked_at, raw = excluded.raw",
        (result.domain, result.source, result.verdict, result.malicious, result.suspicious, result.checked_at,
         json.dumps(result.raw, sort_keys=True)[:8000]),
    )


def lookup_domain_detail(
    cfg,
    conn: sqlite3.Connection,
    domain: str,
    *,
    session=None,
    budget: Budget | None = None,
    force: bool = False,
) -> ReputationResult:
    """Consult the cache, then VirusTotal (budgeted) and URLhaus; store and return the combined verdict."""
    d = domain.strip().rstrip(".").lower()
    ttl = float(cfg_get(cfg, "dns", "reputation_ttl_hours", 72) or 72)
    min_votes = int(cfg_get(cfg, "dns", "reputation_min_malicious_votes", 2) or 2)
    if not force:
        hit = cached_result(conn, d, ttl)
        if hit is not None:
            return hit

    result = ReputationResult(domain=d)
    sources: list[str] = []
    api_key = str(cfg_get(cfg, "dns", "virustotal_api_key", "") or "").strip()
    if api_key:
        b = budget if budget is not None else shared_budget(cfg, conn)
        if b.try_acquire():
            stats = vt_lookup(d, api_key, session=session)
            if stats is not None:
                sources.append("virustotal")
                result.raw["virustotal"] = stats
                result.malicious = max(result.malicious, stats.get("malicious", 0))
                result.suspicious = max(result.suspicious, stats.get("suspicious", 0))
        else:
            result.raw["virustotal"] = {"skipped": "budget"}

    # SPEC-GAP: no config key exists for a URLhaus Auth-Key; ``dns.urlhaus_auth_key`` is read if present.
    uh = urlhaus_lookup(d, auth_key=str(cfg_get(cfg, "dns", "urlhaus_auth_key", "") or ""), session=session)
    if uh is not None:
        sources.append("urlhaus")
        result.raw["urlhaus"] = uh
        if uh.get("online", 0) > 0:
            # SPEC-GAP: an active abuse.ch listing is one confirmed source; count it as ``min_votes`` so
            # the policy's vote threshold (meant for VirusTotal's many engines) does not ignore it.
            result.malicious = max(result.malicious, min_votes)
        elif uh.get("listed"):
            result.suspicious = max(result.suspicious, 1)

    if result.malicious >= min_votes:
        result.verdict = "malicious"
    elif result.malicious > 0 or result.suspicious > 0:
        result.verdict = "suspicious"
    elif sources:
        result.verdict = "clean"
    else:
        result.verdict = "unknown"
    result.source = "+".join(sources) if sources else "none"
    result.checked_at = utcnow_iso()
    try:
        store_result(conn, result)
    except sqlite3.Error:
        logger.exception("could not store reputation for %s", d)
    return result


def lookup_domain(cfg, conn: sqlite3.Connection, domain: str, *, session=None, budget: Budget | None = None) -> str:
    """SPEC signature: returns the verdict string only."""
    return lookup_domain_detail(cfg, conn, domain, session=session, budget=budget).verdict


def list_reputation(conn: sqlite3.Connection, limit: int = 200) -> list[dict]:
    from homesoc.dnsfilter import db_query

    rows = db_query(
        conn,
        "SELECT domain, source, verdict, malicious, suspicious, checked_at FROM reputation"
        " ORDER BY CASE verdict WHEN 'malicious' THEN 0 WHEN 'suspicious' THEN 1 ELSE 2 END, checked_at DESC LIMIT ?",
        (int(limit),),
    )
    return [dict(r) for r in rows]


# ---- findings -----------------------------------------------------------------------------------
class MaliciousFindingEmitter:
    """Emits NET-DNS-004 once per (client, domain) per 24 h via the findings engine when available."""

    def __init__(self, conn: sqlite3.Connection) -> None:
        self.conn = conn
        self._emitted: dict[tuple[str, str], float] = {}
        self._lock = threading.Lock()
        self.drafts_emitted = 0

    def emit(self, client: str, qname: str, result: ReputationResult, *, now: float | None = None):
        now = time.time() if now is None else now
        key = (client, result.domain)
        with self._lock:
            last = self._emitted.get(key)
            if last is not None and now - last < FINDING_DEDUPE_HOURS * 3600:
                return None
            self._emitted[key] = now
            if len(self._emitted) > 10000:  # bounded memory on a long-running resolver
                cutoff = now - FINDING_DEDUPE_HOURS * 3600
                self._emitted = {k: v for k, v in self._emitted.items() if v >= cutoff}
        draft = make_draft(
            "NET-DNS-004",
            f"dns:{client}",
            evidence={
                "key": result.domain,
                "domain": result.domain,
                "qname": qname,
                "client": client,
                "verdict": result.verdict,
                "malicious": result.malicious,
                "suspicious": result.suspicious,
                "source": result.source,
                "checked_at": result.checked_at,
            },
            detail=f"{client} queried {qname} ({result.domain}) — flagged malicious by {result.source} "
                   f"({result.malicious} malicious votes).",
        )
        self.drafts_emitted += 1
        apply_findings(self.conn, [draft], "dns_reputation")
        return draft


# ---- async worker -------------------------------------------------------------------------------
class ReputationWorker:
    """Background thread that looks up newly-seen registrable domains and reports malicious ones.

    ``enqueue`` is O(1) and never blocks: it dedupes on the registrable domain (24 h window), skips
    well-known domains, IP literals, single-label and never-block names, and drops when the queue is
    full — losing a lookup is always better than delaying a DNS answer.
    """

    def __init__(
        self,
        cfg,
        conn: sqlite3.Connection,
        *,
        on_malicious: Callable[[str, str, ReputationResult], None] | None = None,
        session=None,
        budget: Budget | None = None,
        skip: Callable[[str], bool] | None = None,
        enabled: bool = True,
    ) -> None:
        self.cfg = cfg
        self.conn = conn
        self.on_malicious = on_malicious
        self.session = session
        self.budget = budget
        self.skip = skip
        self.enabled = enabled
        self.emitter = MaliciousFindingEmitter(conn)
        self._queue: queue.Queue[tuple[str, str, str]] = queue.Queue(maxsize=QUEUE_MAX)
        self._seen: dict[str, float] = {}
        self._seen_lock = threading.Lock()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self.looked_up = 0
        self.malicious_found = 0
        self.dropped = 0

    # ---- lifecycle ------------------------------------------------------------------------
    def start(self) -> None:
        if not self.enabled or (self._thread is not None and self._thread.is_alive()):
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, name="dns-reputation", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        try:
            self._queue.put_nowait(("", "", ""))  # wake the worker
        except queue.Full:
            pass
        t = self._thread
        if t is not None and t.is_alive() and t is not threading.current_thread():
            t.join(timeout=5)
        self._thread = None

    # ---- producer -------------------------------------------------------------------------
    def should_lookup(self, qname: str, *, now: float | None = None) -> str | None:
        """Return the registrable domain to look up, or None when it should be skipped."""
        name = qname.strip().rstrip(".").lower()
        if not name or "." not in name or not _HOSTNAME_RE.match(name):
            return None
        reg = registrable_domain(name)
        if reg in WELL_KNOWN or _is_ip(reg) or not _HOSTNAME_RE.match(reg):
            return None
        if self.skip is not None and self.skip(name):
            return None
        now = time.time() if now is None else now
        with self._seen_lock:
            last = self._seen.get(reg)
            if last is not None and now - last < SEEN_WINDOW_HOURS * 3600:
                return None
            self._seen[reg] = now
            if len(self._seen) > 50000:
                cutoff = now - SEEN_WINDOW_HOURS * 3600
                self._seen = {k: v for k, v in self._seen.items() if v >= cutoff}
        return reg

    def enqueue(self, qname: str, client: str) -> bool:
        if not self.enabled:
            return False
        reg = self.should_lookup(qname)
        if reg is None:
            return False
        try:
            self._queue.put_nowait((reg, qname, client))
        except queue.Full:
            self.dropped += 1
            return False
        return True

    def pending(self) -> int:
        return self._queue.qsize()

    # ---- consumer -------------------------------------------------------------------------
    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                reg, qname, client = self._queue.get(timeout=1.0)
            except queue.Empty:
                continue
            if not reg:
                continue
            try:
                self.process(reg, qname, client)
            except Exception:
                logger.exception("reputation lookup failed for %s", reg)

    def process(self, reg: str, qname: str, client: str) -> ReputationResult:
        """Synchronous unit of work (also used by tests and ``dns-test``)."""
        result = lookup_domain_detail(self.cfg, self.conn, reg, session=self.session, budget=self.budget)
        self.looked_up += 1
        if result.source == "none":
            # Nobody answered: let the next query for this domain re-enqueue it after a short pause
            # instead of the full 24 h window, so a domain first seen at budget exhaustion is not
            # left unchecked until tomorrow's queries have long gone.
            with self._seen_lock:
                self._seen[reg] = time.time() - (SEEN_WINDOW_HOURS - NO_VERDICT_RETRY_HOURS) * 3600
        if result.verdict == "malicious":
            self.malicious_found += 1
            self.emitter.emit(client, qname, result)
            if self.on_malicious is not None:
                try:
                    self.on_malicious(reg, client, result)
                except Exception:
                    logger.exception("on_malicious callback failed")
        return result

    def drain(self, max_items: int = 1000) -> int:
        """Process queued items on the calling thread (tests / CLI); returns the number processed."""
        n = 0
        while n < max_items:
            try:
                reg, qname, client = self._queue.get_nowait()
            except queue.Empty:
                break
            if reg:
                self.process(reg, qname, client)
                n += 1
        return n

    def stats(self) -> dict:
        return {
            "enabled": self.enabled,
            "pending": self.pending(),
            "looked_up": self.looked_up,
            "malicious_found": self.malicious_found,
            "dropped": self.dropped,
            "seen": len(self._seen),
        }


def _is_ip(token: str) -> bool:
    try:
        ipaddress.ip_address(token)
        return True
    except ValueError:
        return False
