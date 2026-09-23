"""Read-model and JSON API for the Home SOC dashboard (SPEC section 15).

Everything reads straight from the SPEC section 4 tables with SQL written here, so the
dashboard renders even when the packages that own those tables have not run (or do not
exist yet). Writes are deliberately few and go through the owning package when it can be
imported; each fallback is marked with a SPEC-GAP comment.
"""

from __future__ import annotations

import hashlib
import importlib
import ipaddress
import json
import logging
import math
import platform
import re
import secrets
import socket
import sqlite3
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any
from urllib.parse import quote

from flask import Blueprint, Response, current_app, jsonify, request

logger = logging.getLogger(__name__)

bp = Blueprint("api", __name__, url_prefix="/api")

SEVERITIES: tuple[str, ...] = ("critical", "high", "medium", "low", "info")
STATUSES: tuple[str, ...] = ("open", "acknowledged", "resolved", "suppressed")
SCORE_PENALTY: dict[str, int] = {"critical": 25, "high": 10, "medium": 4, "low": 1, "info": 0}
SCAN_KINDS: tuple[str, ...] = ("quick", "full", "host", "exposure", "feeds", "files")
BLOCKLIST_KINDS: tuple[str, ...] = ("hosts", "domains", "adblock", "ip")
JOB_COLUMNS: tuple[str, ...] = ("last_run", "last_status", "last_duration_sec", "next_run", "runs", "failures", "last_error")

# Finding-ID prefix -> category, used when findings.catalog is not importable and for the
# category filter on /findings. Mirrors the groupings of SPEC section 9.
CATEGORY_BY_PREFIX: dict[str, str] = {
    "WIN-DEF": "defender",
    "WIN-FW": "firewall",
    "WIN-UPD": "updates",
    "WIN-ACC": "accounts",
    "WIN-NET": "host-network",
    "WIN-SYS": "system",
    "WIN-PER": "persistence",
    "AV-FILE": "files",
    "POSIX": "posix",
    "NET-DEV": "devices",
    "NET-SVC": "services",
    "NET-VUL": "vulns",
    "NET-WAN": "wan",
    "NET-RTR": "router",
    "NET-WIFI": "wifi",
    "NET-DNS": "dns",
    "SOC": "soc",
}

# Editable settings (SPEC section 15: web, network.exclude, scan, dns, notify, schedule).
# type: str | int | float | bool | list | secret. Secrets are never echoed back.
EDITABLE_SETTINGS: list[tuple[str, str]] = [
    ("web.host", "str"),
    ("web.port", "int"),
    ("web.token", "secret"),
    ("web.refresh_seconds", "int"),
    ("network.exclude", "list"),
    ("scan.use_nmap", "bool"),
    ("scan.nmap_top_ports", "int"),
    ("scan.nmap_timing", "str"),
    ("scan.version_detection", "bool"),
    ("scan.gentle_top_ports", "int"),
    ("scan.per_host_timeout_sec", "int"),
    ("scan.max_parallel_hosts", "int"),
    ("scan.scan_gateway", "bool"),
    ("dns.enabled", "bool"),
    ("dns.listen", "str"),
    ("dns.port", "int"),
    ("dns.upstreams", "list"),
    ("dns.doh_upstream", "str"),
    ("dns.block_mode", "str"),
    ("dns.cache_max_entries", "int"),
    ("dns.lists", "list"),
    ("dns.log_queries", "bool"),
    ("dns.log_retention_days", "int"),
    ("dns.virustotal_api_key", "secret"),
    ("dns.virustotal_daily_budget", "int"),
    ("dns.urlhaus_auth_key", "secret"),
    ("dns.reputation_min_malicious_votes", "int"),
    ("dns.reputation_ttl_hours", "int"),
    ("notify.min_severity", "str"),
    ("notify.ntfy_url", "secret"),
    ("notify.discord_webhook", "secret"),
    ("notify.webhook_url", "secret"),
    ("notify.windows_toast", "bool"),
    ("notify.digest_hour", "int"),
    ("schedule.discovery_minutes", "int"),
    ("schedule.services_hours", "int"),
    ("schedule.host_hours", "int"),
    ("schedule.exposure_hours", "int"),
    ("schedule.feeds_hours", "int"),
]


@dataclass
class WebContext:
    """Everything the request handlers need, stored on ``app.extensions['homesoc']``."""

    cfg: Any
    conn: sqlite3.Connection
    scheduler: Any = None
    dns_server: Any = None
    token: str = ""
    #: Results of aggregates that turned out to be slow, keyed by query (see :func:`throttled`).
    slow_cache: dict = field(default_factory=dict)
    slow_lock: Any = field(default_factory=threading.Lock)


def ctx() -> WebContext:
    return current_app.extensions["homesoc"]


# --------------------------------------------------------------------------- helpers


def cfg_get(cfg: Any, dotted: str, default: Any = None) -> Any:
    """Walk ``cfg`` by dotted key across dataclasses, namespaces or dicts.

    The Config dataclass is owned by another package; reading it structurally keeps this
    module working against a stub in tests and against the real thing in production.
    """
    cur = cfg
    for part in dotted.split("."):
        if cur is None:
            return default
        cur = cur.get(part) if isinstance(cur, dict) else getattr(cur, part, None)
    return default if cur is None else cur


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def now_iso() -> str:
    """Same ``YYYY-MM-DDTHH:MM:SSZ`` form as util.utcnow_iso so rows written here sort with everyone else's."""
    return utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")


def cutoff_iso(hours: float) -> str:
    """Timestamp lower bound as a bare prefix so ``ts >= cutoff`` works for both 'Z' and
    '+00:00' suffixed ISO strings."""
    return (utcnow() - timedelta(hours=hours)).strftime("%Y-%m-%dT%H:%M:%S")


def parse_ts(value: Any) -> datetime | None:
    if not value or not isinstance(value, str):
        return None
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def age_hours(value: Any) -> float | None:
    dt = parse_ts(value)
    return None if dt is None else round((utcnow() - dt).total_seconds() / 3600, 2)


def loads(value: Any, default: Any = None) -> Any:
    """Parse a JSON column defensively: the content is produced by other packages (and
    for evidence, ultimately by scanned devices), so never let it break a page."""
    if value in (None, ""):
        return default
    if not isinstance(value, str):
        return value
    try:
        return json.loads(value)
    except ValueError:
        return default


_write_lock = threading.RLock()


def _core_db() -> Any | None:
    try:
        return importlib.import_module("homesoc.db")
    except ImportError:
        return None


def _conn_lock() -> Any:
    """The one lock that guards the shared connection.

    Must be the SAME object core uses, not a second lock of our own: a private lock here would
    happily let a dashboard read interleave with a scanner write on the one connection every
    thread shares. Falls back to the local RLock only when core is genuinely absent.
    """
    dbmod = _core_db()
    lock = getattr(dbmod, "_WRITE_LOCK", None) if dbmod is not None else None
    return lock if lock is not None else _write_lock


def rows(conn: sqlite3.Connection, sql: str, params: tuple | list = ()) -> list[dict]:
    """Run a SELECT and return plain dicts. A missing table just means that package has
    not run yet, so log it and render the page empty instead of failing.

    The whole execute/description/fetchall sequence holds the connection lock. sqlite3 keeps
    statement state on the connection, so an interleaving reader does not just block — it reads
    another thread's cursor and gets InterfaceError, or silently gets no row at all.
    """
    try:
        with _conn_lock():
            cur = conn.execute(sql, params)
            cols = [d[0] for d in cur.description]
            return [dict(zip(cols, r)) for r in cur.fetchall()]
    except sqlite3.OperationalError as exc:
        logger.warning("query failed (%s): %s", exc, " ".join(sql.split())[:90])
        return []


def one(conn: sqlite3.Connection, sql: str, params: tuple | list = ()) -> dict | None:
    result = rows(conn, sql, params)
    return result[0] if result else None


def scalar(conn: sqlite3.Connection, sql: str, params: tuple | list = (), default: Any = 0) -> Any:
    row = one(conn, sql, params)
    if not row:
        return default
    value = next(iter(row.values()))
    return default if value is None else value


def write(conn: sqlite3.Connection, sql: str, params: tuple | list = ()) -> int:
    """Locked write. Uses core's ``db.write`` (which owns the module-level lock) when it
    exists so dashboard writes serialise with scanner writes."""
    dbmod = _core_db()
    if dbmod is not None and hasattr(dbmod, "write"):
        return int(dbmod.write(conn, sql, params) or 0)
    with _write_lock:  # SPEC-GAP: core db missing -> local lock is the best we can do
        cur = conn.execute(sql, params)
        conn.commit()
        return int(cur.lastrowid or 0)


def get_setting(conn: sqlite3.Connection, key: str, default: str | None = None) -> str | None:
    row = one(conn, "SELECT value FROM settings WHERE key=?", (key,))
    return default if row is None else row["value"]


def set_setting(conn: sqlite3.Connection, key: str, value: str) -> None:
    dbmod = _core_db()
    if dbmod is not None and hasattr(dbmod, "set_setting"):
        dbmod.set_setting(conn, key, value)
        return
    # SPEC-GAP: core db not importable -> direct upsert with the same semantics.
    write(
        conn,
        "INSERT INTO settings(key, value, updated_at) VALUES(?,?,?) "
        "ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at",
        (key, value, now_iso()),
    )


def _bool(value: Any) -> bool:
    return bool(value) and str(value).lower() not in ("0", "false", "no", "")


# --------------------------------------------------------------------------- plain language
#
# The owner is technical; the rest of the household is not. Everything in this section turns a
# stored fact into the words the dashboard shows BESIDE the technical value, never instead of it:
# a severity's action word, a device's name rather than its address, how long ago Home SOC last
# looked at the network. It is computed here, once, so every page, the JSON API and the shell's
# context processor say exactly the same thing and no template has to do the arithmetic.
#
# Two honesty rules shape the wording and are pinned by tests/test_plain_data.py:
#   * nothing here may say the network is healthy when the data is stale or a check failed;
#   * EPSS is a worldwide exploitation forecast for a flaw, not a chance that this home is attacked.

SEV_WORDS: dict[str, str] = {
    "critical": "Fix now",
    "high": "Fix this week",
    "medium": "Worth fixing",
    "low": "When you have time",
    "info": "Good to know",
}
STATUS_WORDS: dict[str, str] = {
    "open": "Needs attention",
    "acknowledged": "Seen, not fixed yet",
    "resolved": "Fixed",
    "suppressed": "Ignored (your choice)",
}
#: Score bands of DESIGN §8.2. The letter grade stays available; this is the word beside it.
SCORE_WORDS: tuple[tuple[int, str], ...] = ((80, "Good"), (50, "Fair"), (0, "Needs work"))

#: devices.kind -> the noun in "Unnamed <kind>". Discovery writes router/self/randomized and the
#: mDNS hints printer/camera/apple/iot/nas; the rest are what an owner or an older import may set.
KIND_WORDS: dict[str, str] = {
    "router": "router",
    "gateway": "router",
    "self": "computer",
    "computer": "computer",
    "laptop": "laptop",
    "desktop": "computer",
    "phone": "phone",
    "tablet": "tablet",
    "tv": "TV",
    "speaker": "speaker",
    "printer": "printer",
    "camera": "camera",
    "iot": "smart device",
    "console": "games console",
    "nas": "network storage",
    "apple": "Apple device",
    "watch": "watch",
    "pc": "computer",
    "access_point": "access point",
    "ap": "access point",
    "switch": "network switch",
    "randomized": "device",
    "unknown": "device",
}

#: A discovery sweep older than this many times its own schedule means the dashboard is showing
#: an old picture (DESIGN §8.1 rule 1; the shell's banner and every status line share it) — and
#: never more than a day, whatever the schedule says.
STALE_FACTOR = 3
STALE_CEILING_MINUTES = 24 * 60
DEFAULT_DISCOVERY_MINUTES = 10
#: Scan statuses that count as "Home SOC looked": a partial run still swept what it could.
_CHECKED_STATUSES: tuple[str, ...] = ("ok", "partial")
#: Scan statuses that mean the newest run of a kind did not complete its look.
_UNFINISHED_STATUSES: tuple[str, ...] = ("error", "aborted", "partial")
#: scans.kind -> the plain name of that check.
SCAN_WORDS: dict[str, str] = {
    "discovery": "device check",
    "services": "open-port check",
    "vulns": "software-flaw check",
    "host": "check of this computer",
    "exposure": "internet-exposure check",
    "feeds": "threat-list update",
    "files": "downloads check",
    "wifi": "Wi-Fi check",
    "quick": "quick check",
    "full": "full check",
}

_NUMBER_WORDS: tuple[str, ...] = ("no", "one", "two", "three", "four", "five", "six", "seven", "eight", "nine", "ten")
_MAC_RE = re.compile(r"^(?:[0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}$|^[0-9a-fA-F]{4}\.[0-9a-fA-F]{4}\.[0-9a-fA-F]{4}$")


def sev_word(severity: Any) -> str:
    """``high`` -> ``Fix this week``; '' for anything that is not a severity."""
    return SEV_WORDS.get(str(severity or "").strip().lower(), "")


def status_word(status: Any) -> str:
    """``acknowledged`` -> ``Seen, not fixed yet``; '' for anything that is not a status."""
    return STATUS_WORDS.get(str(status or "").strip().lower(), "")


def score_word(score: Any) -> str:
    """0-49 ``Needs work``, 50-79 ``Fair``, 80-100 ``Good``."""
    try:
        value = int(score)
    except (TypeError, ValueError):
        return ""
    for floor, word in SCORE_WORDS:
        if value >= floor:
            return word
    return SCORE_WORDS[-1][1]


def number_words(n: Any) -> str:
    """Numbers up to ten as words ("two"), larger ones as digits with separators ("1,204")."""
    try:
        value = int(n)
    except (TypeError, ValueError):
        return str(n)
    return _NUMBER_WORDS[value] if 0 <= value < len(_NUMBER_WORDS) else f"{value:,}"


def _cap(text: str) -> str:
    return text[:1].upper() + text[1:] if text else text


def _things(n: int, noun: str = "thing") -> str:
    return f"{number_words(n)} {noun}{'' if n == 1 else 's'}"


def span_words(seconds: Any) -> str:
    """A duration as a person says it: '40 minutes', '5 hours', '8 days' (rounded down)."""
    try:
        s = max(0, int(seconds))
    except (TypeError, ValueError):
        return ""
    if s < 60:
        return "less than a minute"
    for size, unit, limit in ((60, "minute", 3600), (3600, "hour", 48 * 3600), (86400, "day", None)):
        if limit is None or s < limit:
            n = s // size
            return f"{n} {unit}{'' if n == 1 else 's'}"
    return ""  # pragma: no cover - the last band has no limit


def _within_words(hours: float) -> str:
    """Upper bound of a duration, rounded UP, so "usually fixed within X" is never an undercount."""
    if hours < 1:
        minutes = max(1, math.ceil(hours * 60))
        return f"{minutes} minute{'' if minutes == 1 else 's'}"
    if hours < 48:
        n = math.ceil(hours - 1e-9)
        return f"{n} hour{'' if n == 1 else 's'}"
    n = math.ceil(hours / 24 - 1e-9)
    return f"{n} day{'' if n == 1 else 's'}"


def time_to_fix_text(median_hours: Any, p90_hours: Any, count: Any) -> str:
    """"Usually fixed within 12 hours; almost always within 3 days", honest about small samples.

    "Almost always" is the 90th percentile, which says nothing until there are a handful of fixes:
    below five the sentence names the slowest fix instead and says the sample is small.
    """
    try:
        n = int(count or 0)
        median = float(median_hours) if median_hours is not None else None
        p90 = float(p90_hours) if p90_hours is not None else None
    except (TypeError, ValueError):
        return ""
    if n <= 0 or median is None:
        return "Nothing was fixed in this period, so there is no typical time to fix yet."
    if n == 1:
        return f"The one fix in this period took about {_within_words(median)}."
    usual = f"Usually fixed within {_within_words(median)}"
    if n < 5:
        slowest = p90 if p90 is not None else median
        return f"{usual}; the slowest took {_within_words(slowest)} (only {number_words(n)} fixes so far, so this is a rough guide)."
    if p90 is None or _within_words(p90) == _within_words(median):
        return f"{usual}."
    return f"{usual}; almost always within {_within_words(p90)}."


def cvss_text(cvss: Any) -> str | None:
    """CVSS base score as "8.8 / 10" (it is a 0-10 scale; a bare 8.8 reads like a percentage)."""
    try:
        value = float(cvss)
    except (TypeError, ValueError):
        return None
    if value != value or value < 0:  # NaN or nonsense
        return None
    return f"{min(value, 10.0):.1f} / 10"


def epss_pct(epss: Any) -> float | None:
    """EPSS as a percentage; values above 1 are taken to be percentages already."""
    try:
        value = float(epss)
    except (TypeError, ValueError):
        return None
    if value != value or value < 0:
        return None
    pct = value * 100.0 if value <= 1.0 else value
    return round(min(pct, 100.0), 1)


#: The one caveat every EPSS figure travels with (CORRECTION 2 of the redesign brief).
EPSS_NOTE = (
    "EPSS is a forecast for the flaw itself, worldwide. It does not say whether your home is "
    "being targeted."
)


def epss_text(epss: Any) -> str | None:
    """"94% chance this flaw is exploited somewhere in the next 30 days".

    EPSS estimates exploitation of the flaw anywhere in the wild; it is never phrased as a chance
    that this household is attacked.
    """
    pct = epss_pct(epss)
    if pct is None:
        return None
    if pct < 1:
        shown = "Less than 1%"
    elif pct < 10:
        shown = f"{pct:.1f}%".replace(".0%", "%")
    else:
        shown = f"{pct:.0f}%"
    return f"{shown} chance this flaw is exploited somewhere in the next 30 days"


def kev_text(kev: Any) -> str:
    return (
        "Yes: attackers are known to have used this flaw in real attacks (on CISA's known-exploited list)"
        if _bool(kev)
        else "Not on CISA's known-exploited list"
    )


def _as_mapping(row: Any) -> dict:
    if isinstance(row, dict):
        return row
    if hasattr(row, "keys"):
        try:
            return {k: row[k] for k in row.keys()}
        except Exception:
            return {}
    if hasattr(row, "__dict__"):
        return dict(vars(row))
    return {}


def looks_like_address(value: Any) -> bool:
    """True for an IP or MAC address: an identifier, not a name a person gave the device."""
    text = str(value or "").strip()
    if not text:
        return False
    if _MAC_RE.match(text):
        return True
    try:
        ipaddress.ip_address(text.split("%", 1)[0])
        return True
    except ValueError:
        return False


def _name(value: Any) -> str | None:
    text = " ".join(str(value or "").split())[:200]
    return text if text and not looks_like_address(text) else None


def kind_word(kind: Any) -> str:
    """``iot`` -> ``smart device``; anything unrecognised is just a ``device``."""
    return KIND_WORDS.get(" ".join(str(kind or "").strip().lower().split()), "device")


def host_name_from_subject(subject: Any) -> str:
    """``host:HOME-PC:invoice.pdf.exe`` -> ``HOME-PC``; '' for a bare ``host`` subject."""
    text = str(subject or "")
    if not (text == "host" or text.startswith("host:")):
        return ""
    return text.split(":", 2)[1].strip() if ":" in text else ""


def this_computer_label(name: Any = None) -> str:
    shown = " ".join(str(name or "").split())[:200]
    return f"This computer ({shown})" if shown else "This computer"


def subject_label(subject: Any) -> str | None:
    """Plain words for a finding subject that is not a single LAN device, else ``None``."""
    text = str(subject or "")
    head = text.split(":", 1)[0].strip().lower()
    if head == "host":
        return this_computer_label(host_name_from_subject(text))
    return {
        "wan": "Your internet connection",
        "wifi": "Your Wi-Fi",
        "network": "Your home network",
        "feed": "Home SOC's threat lists",
        "soc": "Home SOC itself",
        "job": "Home SOC itself",
    }.get(head)


def device_label(row: Any) -> str:
    """What to call a device: its name first, never the bare IP when a name exists.

    Accepts a devices row, a joined row (``device_nickname``/``device_hostname``/``device_kind``),
    a finding (whose ``subject`` may be the host) or anything already carrying ``device_label``.
    Precedence: nickname, hostname, any other name field that is not itself an address, then
    "Unnamed <kind>" ("Unnamed camera"). The IP is shown next to this by the page, muted — it is
    never folded into the label, which is what produced "192.168.1.142 192.168.1.142".
    """
    if row is None:
        return "Unnamed device"
    d = _as_mapping(row)
    ready = d.get("device_label")
    if isinstance(ready, str) and ready.strip():
        return ready.strip()
    for key in ("nickname", "device_nickname", "hostname", "device_hostname", "display_name", "device_name", "name"):
        name = _name(d.get(key))
        if name:
            return name
    subject = str(d.get("subject") or "")
    if subject == "host" or subject.startswith("host:"):
        return this_computer_label(host_name_from_subject(subject))
    kind = d.get("kind") if d.get("kind") not in (None, "") else d.get("device_kind")
    if str(kind or "").strip().lower() == "self":
        return "This computer"
    if kind or any(d.get(k) for k in ("ip", "mac", "device_ip", "device_mac", "device_id")):
        return f"Unnamed {kind_word(kind)}"
    return subject_label(subject) or "Unnamed device"


_DEVICE_LABEL_COLUMNS = "id, ip, mac, hostname, nickname, kind, last_seen"


def _device_rows_by(conn: sqlite3.Connection, column: str, values: list[Any]) -> list[dict]:
    """Devices whose ``column`` is in ``values``, in chunks so SQLite's variable limit is never hit."""
    out: list[dict] = []
    values = [v for v in dict.fromkeys(values) if v not in (None, "")]
    for start in range(0, len(values), 400):
        chunk = values[start : start + 400]
        marks = ",".join("?" for _ in chunk)
        out.extend(rows(conn, f"SELECT {_DEVICE_LABEL_COLUMNS} FROM devices WHERE {column} IN ({marks})", chunk))
    return out


def device_labels_by_id(conn: sqlite3.Connection, ids: Any) -> dict[int, dict]:
    """device id -> ``{device_label, ip}`` for every id that exists."""
    wanted = [i for i in (_int_or_none(x) for x in (ids or [])) if i is not None]
    return {int(r["id"]): {"device_label": device_label(r), "ip": r.get("ip")} for r in _device_rows_by(conn, "id", wanted)}


def device_labels_by_ip(conn: sqlite3.Connection, ips: Any) -> dict[str, dict]:
    """ip -> ``{device_id, device_label}``. Several rows can have held one address over time; the
    most recently seen one is the device using it now."""
    out: dict[str, dict] = {}
    best: dict[str, str] = {}
    for r in _device_rows_by(conn, "ip", [str(i) for i in (ips or []) if i]):
        ip = str(r.get("ip") or "")
        seen = str(r.get("last_seen") or "")
        if ip and (ip not in best or seen > best[ip]):
            best[ip] = seen
            out[ip] = {"device_id": int(r["id"]), "device_label": device_label(r)}
    return out


def host_device(conn: sqlite3.Connection, host_name: Any = None) -> dict | None:
    """The devices row for the computer Home SOC runs on, or ``None``.

    Discovery marks it ``kind='self'``; an older inventory is matched on hostname instead (the
    ``host:<NAME>`` finding subject, then this machine's own name), ignoring case and a domain
    suffix, so ``HOME-PC`` finds ``home-pc.lan``.
    """
    found = one(conn, f"SELECT {_DEVICE_LABEL_COLUMNS} FROM devices WHERE kind='self' ORDER BY last_seen DESC LIMIT 1")
    if found:
        return found
    names: list[str] = []
    for candidate in (host_name, _safe_gethostname(socket)):
        name = str(candidate or "").strip().lower()
        if name and name not in names:
            names.append(name)
    for name in names:
        found = one(
            conn,
            f"SELECT {_DEVICE_LABEL_COLUMNS} FROM devices WHERE lower(hostname)=? OR substr(lower(hostname),1,?)=? "
            "ORDER BY last_seen DESC LIMIT 1",
            (name, len(name) + 1, name + "."),
        )
        if found:
            return found
    return None


def _safe_gethostname(socket_mod: Any) -> str:
    try:
        return str(socket_mod.gethostname() or "")
    except OSError:
        return ""


def _host_label(conn: sqlite3.Connection, subject: str, cache: dict) -> tuple[str, int | None, str | None]:
    """("This computer (Home PC)", 2, "192.168.1.20") for a ``host:`` subject; memoised in ``cache``."""
    name = host_name_from_subject(subject)
    if name not in cache:
        dev = host_device(conn, name)
        shown = (_name(dev.get("nickname")) or _name(dev.get("hostname"))) if dev else None
        cache[name] = (this_computer_label(shown or name), int(dev["id"]) if dev else None,
                       (dev.get("ip") or None) if dev else None)
    return cache[name]


def label_subject_rows(conn: sqlite3.Connection, items: list[dict]) -> list[dict]:
    """Give every finding-shaped row ``device_label`` and ``link_device_id``.

    A row joined to its device keeps that device's name; a ``host:`` subject becomes
    "This computer (<name>)" and links to the host's own device page; a ``dns:<ip>`` or
    ``device:<mac>`` subject that was written before its device row existed is looked up; any
    other subject ("wan:...", "wifi:...") gets plain words. ``device_name`` — the old join column
    that fell back to the IP and so rendered "192.168.1.142 192.168.1.142" next to ``device_ip`` —
    is set to the same label wherever there is a device, so existing pages stop doubling it.
    """
    host_cache: dict = {}
    by_ip: dict[str, dict] = {}
    by_mac: dict[str, dict] = {}
    orphans_ip = [str(f.get("subject") or "")[4:] for f in items
                  if not f.get("device_id") and str(f.get("subject") or "").startswith("dns:")]
    if orphans_ip:
        by_ip = device_labels_by_ip(conn, orphans_ip)
    orphans_mac = [str(f.get("subject") or "") for f in items
                   if not f.get("device_id") and str(f.get("subject") or "").startswith("device:")]
    if orphans_mac:
        for r in rows(conn, f"SELECT {_DEVICE_LABEL_COLUMNS} FROM devices WHERE mac IS NOT NULL AND mac<>''"):
            by_mac[str(r["mac"]).lower()] = r
    for f in items:
        subject = str(f.get("subject") or "")
        link: int | None = _int_or_none(f.get("device_id"))
        label: str | None = None
        if link is not None:
            label = device_label({
                "nickname": f.get("device_nickname"),
                "hostname": f.get("device_hostname"),
                "kind": f.get("device_kind"),
                "device_id": link,
                "name": f.get("device_name"),
            })
            f["device_name"] = label
        elif subject == "host" or subject.startswith("host:"):
            label, link, host_ip = _host_label(conn, subject, host_cache)
            if host_ip and not f.get("device_ip"):
                f["device_ip"] = host_ip
        elif subject.startswith("dns:") and subject[4:] in by_ip:
            hit = by_ip[subject[4:]]
            label, link = hit["device_label"], hit["device_id"]
            f.setdefault("device_ip", subject[4:])
        elif subject.startswith("device:") and by_mac:
            rest = subject[len("device:"):].lower()
            cut = len(rest)
            while cut > 0 and label is None:
                dev = by_mac.get(rest[:cut])
                if dev is not None:
                    label, link = device_label(dev), int(dev["id"])
                    f.setdefault("device_ip", dev.get("ip"))
                cut = rest.rfind(":", 0, cut)
        if label is None:
            label = subject_label(subject)
            if label is None and subject.startswith("dns:"):
                label = "Unnamed device"
                f.setdefault("device_ip", subject[4:])
            label = label or subject or "Unnamed device"
        f["device_label"] = label
        f["link_device_id"] = link
    return items


def last_network_check(conn: sqlite3.Connection) -> str | None:
    """When the newest discovery sweep that actually looked at the network finished."""
    marks = ",".join("?" for _ in _CHECKED_STATUSES)
    value = scalar(
        conn,
        f"SELECT finished_at FROM scans WHERE kind='discovery' AND finished_at IS NOT NULL AND status IN ({marks}) "
        "ORDER BY id DESC LIMIT 1",
        _CHECKED_STATUSES,
        default=None,
    )
    return str(value) if value else None


def _discovery_minutes(cfg: Any) -> int:
    if cfg is None:
        try:
            cfg = ctx().cfg
        except (RuntimeError, KeyError, AttributeError):  # no app context: use the default schedule
            cfg = None
    minutes = _int_or_none(cfg_get(cfg, "schedule.discovery_minutes", DEFAULT_DISCOVERY_MINUTES))
    return minutes if minutes and minutes > 0 else DEFAULT_DISCOVERY_MINUTES


def staleness(conn: sqlite3.Connection | None, cfg: Any = None, now: Any = None) -> dict:
    """Is the picture on screen current? The one answer the shell's banner, the sidebar and every
    status line share (the shell's context processor should call this, not re-derive it).

    ``stale`` is true when the newest finished discovery sweep is older than STALE_FACTOR times
    ``schedule.discovery_minutes`` (capped at a day). ``never`` is true when no sweep has finished
    at all; that is not "stale" — there is nothing old on screen to distrust — and the status line
    says it in its own words. ``age_text`` reads naturally after "last checked your network":
    "8 days ago", "4 minutes ago", "just now", "never". ``message`` is the banner sentence when
    stale, else ``None``.
    """
    minutes = _discovery_minutes(cfg)
    threshold = min(minutes * STALE_FACTOR, STALE_CEILING_MINUTES)
    out: dict[str, Any] = {
        "stale": False,
        "never": False,
        "age_text": "",
        "age": None,
        "age_seconds": None,
        "last_check": None,
        "schedule_minutes": minutes,
        "threshold_minutes": threshold,
        "message": None,
    }
    if conn is None:
        return out
    try:
        last = last_network_check(conn)
    except sqlite3.Error:
        return out
    if last is None:
        out.update(never=True, age_text="never")
        return out
    dt = parse_ts(last)
    if dt is None:
        return out
    current = now if isinstance(now, datetime) else utcnow()
    seconds = max(0, int((current - dt).total_seconds()))
    age = span_words(seconds)
    stale = seconds > threshold * 60
    out.update(
        stale=stale,
        age_text=f"{age} ago" if seconds >= 60 else "just now",
        age=age,
        age_seconds=seconds,
        last_check=dt.strftime("%Y-%m-%dT%H:%M:%SZ"),
        message=(f"Home SOC last checked your network {age} ago — what you see may be out of date."
                 if stale else None),
    )
    return out


def unfinished_checks(conn: sqlite3.Connection) -> list[dict]:
    """The newest run of each check kind that failed, stopped early or only partly worked."""
    marks = ",".join("?" for _ in _UNFINISHED_STATUSES)
    data = rows(
        conn,
        f"SELECT kind, status, finished_at, error FROM scans WHERE status IN ({marks}) AND id IN "
        "(SELECT max(id) FROM scans WHERE status<>'running' GROUP BY kind) ORDER BY kind",
        _UNFINISHED_STATUSES,
    )
    return [
        {"kind": r["kind"], "status": r["status"], "finished_at": r.get("finished_at"),
         "word": SCAN_WORDS.get(str(r["kind"]), f"{r['kind']} check")}
        for r in data
    ]


#: The checks that must each have finished recently before the dashboard may call the network
#: healthy or say Home SOC is "working normally": (scans.kind, schedule key, default hours). A device
#: check alone only says which devices exist; it says nothing about their open doors, their software
#: or this computer. ``vulns`` runs on the services schedule (cli.build_jobs).
CORE_CHECKS: tuple[tuple[str, str, int], ...] = (
    ("services", "schedule.services_hours", 24),
    ("vulns", "schedule.services_hours", 24),
    ("host", "schedule.host_hours", 6),
    ("feeds", "schedule.feeds_hours", 6),
)
#: What a never-run core check means, in words (it hasn't ... yet).
_NEVER_RAN_WORDS: dict[str, str] = {
    "services": "checked the devices' open doors (ports)",
    "vulns": "matched the devices' software against known flaws",
    "host": "checked this computer",
    "feeds": "downloaded its threat lists",
}


def _cfg_or_app(cfg: Any) -> Any:
    if cfg is not None:
        return cfg
    try:
        return ctx().cfg
    except (RuntimeError, KeyError, AttributeError):  # no app context: stock schedule
        return None


def overdue_checks(conn: sqlite3.Connection, cfg: Any = None, now: Any = None) -> list[dict]:
    """The core checks that have never finished, or whose newest finished run is older than
    STALE_FACTOR times its schedule. Each item: ``{kind, word, never, age_text, schedule_hours}``.

    ``feeds`` is left out when ``feeds.enabled`` is false. A run that finished but only partly
    worked still counts as having looked (:func:`unfinished_checks` reports it separately).
    """
    cfg = _cfg_or_app(cfg)
    current = now if isinstance(now, datetime) else utcnow()
    marks = ",".join("?" for _ in _CHECKED_STATUSES)
    out: list[dict] = []
    for kind, key, default in CORE_CHECKS:
        if kind == "feeds" and not _bool(cfg_get(cfg, "feeds.enabled", True)):
            continue
        hours = _int_or_none(cfg_get(cfg, key, default)) or default
        try:
            last = scalar(
                conn,
                f"SELECT finished_at FROM scans WHERE kind=? AND finished_at IS NOT NULL AND status IN ({marks}) "
                "ORDER BY id DESC LIMIT 1",
                (kind, *_CHECKED_STATUSES),
                default=None,
            )
        except sqlite3.Error:
            continue
        word = SCAN_WORDS.get(kind, f"{kind} check")
        if not last:
            out.append({"kind": kind, "word": word, "never": True, "age_text": "", "schedule_hours": hours})
            continue
        dt = parse_ts(last)
        if dt is None:
            continue
        seconds = max(0, int((current - dt).total_seconds()))
        if seconds > hours * STALE_FACTOR * 3600:
            out.append({"kind": kind, "word": word, "never": False, "age_text": f"{span_words(seconds)} ago",
                        "schedule_hours": hours})
    return out


def overdue_feeds(conn: sqlite3.Connection, cfg: Any = None, now: Any = None) -> list[dict]:
    """Enabled threat lists that downloaded once but are now older than their own refresh interval
    plus one feeds-job cadence (the latest they should have been refreshed by). A list that has
    never downloaded is covered by the ``feeds`` core check instead."""
    try:
        registry = importlib.import_module("homesoc.feeds.registry")
        specs = {str(name): int(getattr(spec, "hours", 0) or 0) for name, spec in registry.FEEDS.items()}
    except Exception:  # the feeds package is optional for the web layer
        return []
    cfg = _cfg_or_app(cfg)
    if not _bool(cfg_get(cfg, "feeds.enabled", True)):
        return []
    cadence = _int_or_none(cfg_get(cfg, "schedule.feeds_hours", 6)) or 6
    current = now if isinstance(now, datetime) else utcnow()
    try:
        data = rows(conn, "SELECT name, last_updated, enabled FROM feeds WHERE last_updated IS NOT NULL ORDER BY name")
    except sqlite3.Error:
        return []
    out: list[dict] = []
    for r in data:
        hours = specs.get(str(r["name"]))
        if not hours or not _bool(r.get("enabled", 1)):
            continue
        dt = parse_ts(r.get("last_updated"))
        if dt is None:
            continue
        seconds = max(0, int((current - dt).total_seconds()))
        if seconds > (hours + cadence) * 3600:
            out.append({"name": r["name"], "age_text": f"{span_words(seconds)} ago", "interval_hours": hours})
    return out


def _join_words(words: list[str]) -> str:
    if len(words) <= 1:
        return "".join(words)
    return ", ".join(words[:-1]) + " and " + words[-1]


def status_summary(conn: sqlite3.Connection, cfg: Any = None, *, counts: dict | None = None,
                   stale: dict | None = None, dns: dict | None = None) -> dict:
    """One plain sentence about the whole network, built from the real state.

    Returns ``{status_line, status_tone, status_link, unfinished}``. ``status_tone`` is the
    banner's modifier (``attention`` | ``week`` | ``stale`` | ``healthy``). First match wins:
    never checked, stale, something to fix now, something to fix this week, a check that did not
    finish, a core check that never ran or is overdue, small things only, nothing at all.
    "Healthy" is only ever said when the data is fresh, every check's newest run completed, and
    each core check (open ports, software flaws, this computer, threat lists) finished within
    STALE_FACTOR times its schedule: a device check alone proves nothing about the devices it
    found. When web blocking is switched on but not running, the line says so.
    ``dns`` is ``{enabled, running}``; without it the running app's DNS state is used.
    """
    stale = stale if stale is not None else staleness(conn, cfg)
    open_counts = (counts if counts is not None else finding_counts(conn)).get("open", {}) or {}
    crit = int(open_counts.get("critical", 0) or 0)
    high = int(open_counts.get("high", 0) or 0)
    small = int(open_counts.get("medium", 0) or 0) + int(open_counts.get("low", 0) or 0)
    unfinished = unfinished_checks(conn)
    failed_words = _join_words([u["word"] for u in unfinished][:3])
    failed_clause = f"the last {failed_words} did not finish" if unfinished else ""
    overdue = overdue_checks(conn, cfg)
    never_ran = [o for o in overdue if o["never"]]
    late = [o for o in overdue if not o["never"]]
    what = ""
    if never_ran:
        what = _join_words([_NEVER_RAN_WORDS.get(o["kind"], f"run its {o['word']}") for o in never_ran])
        what = what.replace(" and ", " or ")
    if dns is None:
        try:
            c = ctx()
            dns = {"enabled": _bool(cfg_get(c.cfg, "dns.enabled", False)), "running": dns_running(c)}
        except (RuntimeError, KeyError, AttributeError):
            dns = {}
    dns_off = bool(dns.get("enabled")) and not dns.get("running")

    def attention() -> str:
        n = crit + high
        if crit and n == crit:
            if n == 1:
                return "One thing needs your attention, and it is urgent"
            return f"{_cap(_things(n))} need your attention, and {'both' if n == 2 else 'all of them'} are urgent"
        if crit:
            return f"{_cap(_things(n))} {'needs' if n == 1 else 'need'} your attention, {number_words(crit)} of them urgent"
        return f"{_cap(_things(high))} {'needs' if high == 1 else 'need'} your attention this week"

    if stale.get("never"):
        line, tone, link = "Home SOC hasn't checked your network yet.", "stale", "/scans"
    elif stale.get("stale"):
        age = stale.get("age") or str(stale.get("age_text") or "").removesuffix(" ago") or "a while"
        line = f"Home SOC hasn't checked your network for {age}, so what you see may be out of date"
        if crit or high:
            parts = []
            if crit:
                parts.append(f"{number_words(crit)} {'thing' if crit == 1 else 'things'} needed fixing right away")
            if high:
                parts.append(f"{number_words(high)} more this week" if crit
                             else f"{number_words(high)} {'thing' if high == 1 else 'things'} needed fixing this week")
            line += "; at that check, " + " and ".join(parts)
        line += "."
        tone, link = "stale", "/telemetry"
    elif crit or high:
        line = attention()
        # Account for the rest, so this sentence adds up to the "N to fix" chip beside it. Without
        # it the banner said "Eight things need your attention" next to "33 to fix", two true numbers
        # a non-technical reader can only see as disagreeing.
        rest = sum(int(v or 0) for v in open_counts.values()) - (crit + high)
        if rest > 0:
            line += f"; {number_words(rest)} more can wait"
        if unfinished:
            line += f" — and {failed_clause}, so there may be more"
        elif never_ran:
            line += " — and Home SOC hasn't run every check yet, so there may be more"
        line += "."
        tone = "attention" if crit else "week"
        link = "/findings?status=open" if crit and high else f"/findings?status=open&severity={'critical' if crit else 'high'}"
    elif unfinished:
        line = f"{_cap(failed_clause)}, so Home SOC can't confirm your network is healthy."
        tone, link = "stale", "/scans"
    elif never_ran:
        if any(o["kind"] == "services" for o in never_ran):
            line = f"Home SOC has only looked for devices so far; it hasn't {what} yet, so it can't say whether your network is healthy."
        else:
            line = f"Home SOC hasn't {what} yet, so it can't say whether your network is healthy."
        tone, link = "stale", "/scans"
    elif late:
        line = ("Some checks are overdue — " + _join_words(
            [f"the {o['word']} last finished {o['age_text']}" for o in late[:3]])
            + " — so Home SOC can't confirm your network is healthy.")
        tone, link = "stale", "/telemetry"
    elif small:
        verb = "is" if small == 1 else "are"
        line = f"Your network looks healthy; {_things(small, 'small thing')} {verb} worth fixing when you have time."
        tone, link = "healthy", "/findings?status=open"
    else:
        line, tone, link = "Your network looks healthy — nothing needs your attention right now.", "healthy", "/findings?status=open"
    if dns_off and not stale.get("never"):
        line += " Web blocking is not running."
    return {"status_line": line, "status_tone": tone, "status_link": link, "unfinished": unfinished,
            "overdue": overdue}


#: An aggregate that took longer than this is served from memory for a while afterwards.
SLOW_QUERY_SECONDS = 0.25
#: ...for at least this long, and never for less than ten times what it cost to compute.
SLOW_QUERY_MIN_TTL = 15.0
SLOW_QUERY_MAX_TTL = 300.0


def throttled(c: WebContext, key: tuple, compute: Any) -> Any:
    """Run ``compute()`` — unless it was slow last time, in which case reuse that answer for a bit.

    Every query holds the one connection lock every thread shares, so an aggregate that has grown
    slow (a LAN device flooding the DNS log, a device table swollen by MAC churn) stalls the
    scheduler, the query-log flush and every other request for as long as it runs. A dashboard
    left polling every 15 s, several open tabs, or a page looping a request must not multiply
    that: a result that took longer than :data:`SLOW_QUERY_SECONDS` is reused for ten times its
    cost (15 s to 5 min), which caps the share of the lock such a query can take at about 10%.
    Fast answers are never cached, so a normal-sized home sees live numbers exactly as before.
    """
    now = time.monotonic()
    with c.slow_lock:
        hit = c.slow_cache.get(key)
        if hit is not None and hit[0] > now:
            return hit[1]
    started = time.monotonic()
    value = compute()
    took = time.monotonic() - started
    with c.slow_lock:
        if took >= SLOW_QUERY_SECONDS:
            ttl = min(SLOW_QUERY_MAX_TTL, max(SLOW_QUERY_MIN_TTL, took * 10))
            if len(c.slow_cache) >= 256:
                c.slow_cache.clear()
            c.slow_cache[key] = (time.monotonic() + ttl, value)
            logger.info("%s took %.2fs; reusing its result for %.0fs", key[0], took, ttl)
        else:
            c.slow_cache.pop(key, None)
    return value


# --------------------------------------------------------------------------- dashboard sessions
#
# The browser cookie is a random session id, never ``web.token`` itself. Cookies are not isolated
# by port, so any other server on 127.0.0.1 the owner is lured to (another local account's, a dev
# server) receives this cookie; what it gets is a session that expires, dies on logout and dies when
# the token changes — not the master credential that also works as ``X-Token`` from a script.
# Only a SHA-256 of each id is stored, in the settings table under a key that is not a config key.

DASHBOARD_COOKIE = "homesoc_token"
#: The name under --tls: ``__Host-`` makes the browser refuse it unless Secure, Path=/ and host-only.
DASHBOARD_COOKIE_SECURE = "__Host-homesoc_token"
SESSION_PREFIX = "websession."
SESSION_TOKEN_KEY = "websession-token-check"
SESSION_TTL_SECONDS = 7 * 86400
#: A session used within its last six days is extended, so a wall-mounted dashboard stays signed in.
SESSION_RENEW_AFTER_SECONDS = 86400
SESSION_MAX = 20
_TOKEN_CHECK_ITERATIONS = 100_000


def _sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _token_check(token: str, salt: str) -> str:
    """A slow, salted fingerprint of ``web.token``: enough to notice it changed, useless to guess it."""
    digest = hashlib.pbkdf2_hmac("sha256", token.encode("utf-8"), bytes.fromhex(salt), _TOKEN_CHECK_ITERATIONS)
    return f"pbkdf2_sha256${_TOKEN_CHECK_ITERATIONS}${salt}${digest.hex()}"


def _session_keys(conn: sqlite3.Connection) -> list[dict]:
    return rows(conn, "SELECT key, value FROM settings WHERE key LIKE ? ORDER BY key", (SESSION_PREFIX + "%",))


def sessions_revoke_all(conn: sqlite3.Connection) -> int:
    keys = [str(r["key"]) for r in _session_keys(conn)]
    for key in keys:
        write(conn, "DELETE FROM settings WHERE key=?", (key,))
    return len(keys)


def sessions_sync_token(conn: sqlite3.Connection, token: str) -> None:
    """At startup: sign every browser out when ``web.token`` is not the one the sessions were made under.

    Rotating a leaked token has to end the sessions it opened, or the person who had it keeps a
    live cookie for another week.
    """
    try:
        stored = str(get_setting(conn, SESSION_TOKEN_KEY, "") or "")
        if token and stored.count("$") == 3:
            _algo, _iters, salt, _digest = stored.split("$")
            try:
                if secrets.compare_digest(_token_check(token, salt), stored):
                    return
            except ValueError:
                pass
        revoked = sessions_revoke_all(conn)
        if token:
            set_setting(conn, SESSION_TOKEN_KEY, _token_check(token, secrets.token_hex(16)))
        else:
            write(conn, "DELETE FROM settings WHERE key=?", (SESSION_TOKEN_KEY,))
        if revoked:
            logger.info("web.token changed: signed out %d browser session(s)", revoked)
    except sqlite3.Error as exc:  # pragma: no cover - a pre-settings database
        logger.warning("could not check dashboard sessions: %s", exc)


def _session_state(raw: Any) -> dict:
    state = loads(raw, {})
    return state if isinstance(state, dict) else {}


def session_create(conn: sqlite3.Connection) -> str:
    """Mint a session for a browser that just presented the right token; returns the cookie value."""
    now = utcnow()
    live: list[tuple[str, str]] = []
    for r in _session_keys(conn):
        state = _session_state(r["value"])
        expires = str(state.get("expires_at") or "")
        if not expires or expires <= now.strftime("%Y-%m-%dT%H:%M:%SZ"):
            write(conn, "DELETE FROM settings WHERE key=?", (str(r["key"]),))
        else:
            live.append((str(state.get("created_at") or ""), str(r["key"])))
    for _created, key in sorted(live)[: max(0, len(live) - SESSION_MAX + 1)]:
        write(conn, "DELETE FROM settings WHERE key=?", (key,))  # oldest first, so the table stays small
    sid = secrets.token_urlsafe(32)
    set_setting(conn, SESSION_PREFIX + _sha256(sid), json.dumps({
        "created_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "expires_at": (now + timedelta(seconds=SESSION_TTL_SECONDS)).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }))
    return sid


def session_check(conn: sqlite3.Connection, sid: str | None) -> str | None:
    """``"ok"``, ``"renewed"`` (extended: re-send the cookie) or ``None`` for no valid session."""
    if not sid or len(sid) > 128:
        return None
    key = SESSION_PREFIX + _sha256(sid)
    raw = get_setting(conn, key)
    if raw is None:
        return None
    state = _session_state(raw)
    expires = parse_ts(state.get("expires_at"))
    now = utcnow()
    if expires is None or expires <= now:
        write(conn, "DELETE FROM settings WHERE key=?", (key,))
        return None
    if (expires - now).total_seconds() < SESSION_TTL_SECONDS - SESSION_RENEW_AFTER_SECONDS:
        state["expires_at"] = (now + timedelta(seconds=SESSION_TTL_SECONDS)).strftime("%Y-%m-%dT%H:%M:%SZ")
        set_setting(conn, key, json.dumps(state))
        return "renewed"
    return "ok"


def session_revoke(conn: sqlite3.Connection, sid: str | None) -> None:
    if sid and len(sid) <= 128:
        write(conn, "DELETE FROM settings WHERE key=?", (SESSION_PREFIX + _sha256(sid),))


def presented_session() -> str | None:
    return request.cookies.get(DASHBOARD_COOKIE_SECURE) or request.cookies.get(DASHBOARD_COOKIE)


# --------------------------------------------------------------------------- token guessing
#
# Every place that compares a presented ``web.token`` counts failures per source address, and
# across all addresses, in memory: a LAN host (or another local account) otherwise gets thousands
# of guesses a second at a token the owner may have picked by hand, and leaves no trace. A valid
# session cookie is not a guess and keeps working while an address is locked out, so the owner's
# own open dashboard is never the thing that gets refused.

TOKEN_GUESS_LIMIT = 10
TOKEN_GUESS_GLOBAL_LIMIT = 100
TOKEN_GUESS_WINDOW_SECONDS = 600
TOKEN_GUESS_LOCKOUT_SECONDS = 900
_GLOBAL_GUESSES = "*"
_guess_lock = threading.Lock()
_guesses: dict[str, list[float]] = {}  # source -> [window_start, failures, blocked_until]


def _guess_source_is_loopback(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip.split("%", 1)[0])
    except ValueError:
        return False
    mapped = getattr(addr, "ipv4_mapped", None)
    return bool((mapped or addr).is_loopback)


def token_guess_retry_after(ip: str) -> int:
    """Seconds this source (or everyone, during a spread-out attack) must wait; 0 when it may try.

    The all-addresses lockout exists to stop a guesser that hops between LAN addresses. It is not
    applied to this machine's own loopback address: that source cannot hop, its own per-address
    limit still holds, and otherwise any host that can reach an exposed dashboard could lock the
    owner out of signing in at the desk.
    """
    now = time.monotonic()
    keys = (ip,) if _guess_source_is_loopback(ip) else (ip, _GLOBAL_GUESSES)
    with _guess_lock:
        waits = [state[2] - now for key in keys if (state := _guesses.get(key)) and state[2] > now]
    return int(max(waits)) + 1 if waits else 0


def token_guess_failed(conn: sqlite3.Connection, ip: str) -> None:
    now = time.monotonic()
    tripped: list[tuple[str, int]] = []
    with _guess_lock:
        if len(_guesses) > 4096:
            for key in [k for k, s in _guesses.items() if s[2] <= now and now - s[0] > TOKEN_GUESS_WINDOW_SECONDS]:
                del _guesses[key]
            if len(_guesses) > 4096:  # an address-hopping flood: keep the global counter, drop the rest
                _guesses.clear()
        for key, limit in ((ip, TOKEN_GUESS_LIMIT), (_GLOBAL_GUESSES, TOKEN_GUESS_GLOBAL_LIMIT)):
            state = _guesses.setdefault(key, [now, 0.0, 0.0])
            if now - state[0] > TOKEN_GUESS_WINDOW_SECONDS:
                state[0], state[1] = now, 0.0
            state[1] += 1
            if state[1] >= limit and state[2] <= now:
                state[2] = now + TOKEN_GUESS_LOCKOUT_SECONDS
                tripped.append((key, int(state[1])))
    for key, count in tripped:
        who = "from all addresses together" if key == _GLOBAL_GUESSES else f"from {ip}"
        _record_event(conn, "warning", "web",
                      f"{count} wrong dashboard tokens {who}; refusing token sign-ins "
                      f"{'from anywhere' if key == _GLOBAL_GUESSES else 'from there'} for "
                      f"{TOKEN_GUESS_LOCKOUT_SECONDS // 60} minutes",
                      {"source": key, "failures": count})


def token_guess_reset(ip: str) -> None:
    with _guess_lock:
        _guesses.pop(ip, None)


def check_token_guess(conn: sqlite3.Connection, expected: str, presented: str | None, ip: str) -> bool:
    """Compare a presented token, counting it when wrong. Always False while the source is locked out."""
    if not presented or not expected:
        return False
    if token_guess_retry_after(ip):
        return False
    if secrets.compare_digest(presented.encode("utf-8"), expected.encode("utf-8")):
        return True
    token_guess_failed(conn, ip)
    return False


# --------------------------------------------------------------------------- findings


def finding_counts(conn: sqlite3.Connection) -> dict[str, dict[str, int]]:
    counts = {status: {sev: 0 for sev in SEVERITIES} for status in STATUSES}
    for r in rows(conn, "SELECT status, severity, count(*) AS n FROM findings GROUP BY status, severity"):
        counts.setdefault(r["status"], {sev: 0 for sev in SEVERITIES})
        counts[r["status"]][r["severity"]] = counts[r["status"]].get(r["severity"], 0) + int(r["n"])
    return counts


#: Findings raised by something that happened (a device joined, a lookup was made, a threat was
#: detected, a new autostart entry appeared) rather than by a state a later check looks at again.
#: No scan re-raises them, so "I've fixed it" can never be confirmed: they stay closed until the
#: event happens again.
NOT_RECHECKED_IDS: frozenset[str] = frozenset({
    "NET-DEV-001", "NET-DEV-004", "NET-DNS-004", "NET-DEP-002",
    "WIN-DEF-011", "WIN-PER-001", "WIN-PER-002", "WIN-PER-003",
})


def resolved_how(conn: sqlite3.Connection, row_ids: list[int]) -> dict[int, str]:
    """row id -> ``auto`` when the newest lifecycle event is Home SOC's own check closing it (the
    problem was gone at a later scan), else ``manual`` (someone pressed "I've fixed it")."""
    out: dict[int, str] = {}
    ids = [int(i) for i in row_ids]
    for start in range(0, len(ids), 400):
        chunk = ids[start:start + 400]
        marks = ",".join("?" for _ in chunk)
        try:
            data = rows(
                conn,
                f"SELECT finding_row_id, event FROM finding_events WHERE finding_row_id IN ({marks}) "
                "AND id IN (SELECT max(id) FROM finding_events GROUP BY finding_row_id)",
                chunk,
            )
        except sqlite3.Error:
            return out
        for r in data:
            out[int(r["finding_row_id"])] = "auto" if str(r["event"]) == "auto_resolved" else "manual"
    return out


def resolved_split(conn: sqlite3.Connection) -> dict[str, int]:
    """``{resolved, confirmed, marked}``: every fixed finding, how many a later check confirmed
    were gone, and how many were only marked fixed by a person."""
    try:
        total = int(scalar(conn, "SELECT count(*) FROM findings WHERE status='resolved'", default=0) or 0)
        confirmed = int(scalar(
            conn,
            "SELECT count(*) FROM findings f JOIN finding_events e ON e.finding_row_id=f.id "
            "WHERE f.status='resolved' AND e.event='auto_resolved' AND e.id IN "
            "(SELECT max(id) FROM finding_events GROUP BY finding_row_id)",
            default=0,
        ) or 0)
    except sqlite3.Error:
        return {"resolved": 0, "confirmed": 0, "marked": 0}
    return {"resolved": total, "confirmed": confirmed, "marked": max(0, total - confirmed)}


def _findings_score() -> Any | None:
    """``homesoc.findings.score`` when it is installed, else ``None``.

    findings owns the scoring formula (SPEC section 10). The dashboard must show *its* number,
    or the score card and the "what is costing you points" list underneath it would disagree.
    """
    try:
        return importlib.import_module("homesoc.findings.score")
    except ImportError:
        return None


def _local_security_score(conn: sqlite3.Connection) -> int:
    """SPEC section 10 formula from SQL — the fallback when findings.score is not installed."""
    score = 100
    for sev, n in finding_counts(conn)["open"].items():
        score -= SCORE_PENALTY.get(sev, 0) * n
    return max(0, score)


def security_score(conn: sqlite3.Connection) -> int:
    fn = getattr(_findings_score(), "security_score", None)
    if callable(fn):
        try:
            return max(0, min(100, int(fn(conn))))
        except Exception:  # a scoring bug must not blank the dashboard
            logger.warning("findings.score.security_score failed; using the local formula", exc_info=True)
    return _local_security_score(conn)


def grade(score: int) -> str:
    fn = getattr(_findings_score(), "grade", None)
    if callable(fn):
        try:
            letter = str(fn(int(score)) or "").strip().upper()[:1]
            if letter in ("A", "B", "C", "D", "F"):
                return letter
        except Exception:
            logger.warning("findings.score.grade failed; using the local bands", exc_info=True)
    # SPEC-GAP: thresholds not given; classic 90/80/70/60 bands.
    for floor, letter in ((90, "A"), (80, "B"), (70, "C"), (60, "D")):
        if score >= floor:
            return letter
    return "F"


def score_trend(conn: sqlite3.Connection, days: int = 30) -> list[list]:
    data = rows(
        conn,
        "SELECT substr(ts,1,10) AS d, avg(value) AS v FROM metrics WHERE name='score' AND ts>=? "
        "GROUP BY d ORDER BY d",
        (cutoff_iso(days * 24),),
    )
    return [[r["d"], round(float(r["v"]), 1)] for r in data]


# --------------------------------------------------------------------------- score breakdown

# How many rows the "what is costing you points" list shows by default. Six fits the score
# card without scrolling and is enough to see the shape of the problem.
SCORE_BREAKDOWN_LIMIT = 6


def _sev_rank(severity: Any) -> int:
    sev = str(severity or "").lower()
    return SEVERITIES.index(sev) if sev in SEVERITIES else len(SEVERITIES)


# Words a de-templated catalog title must not end on ("Last cumulative update was" reads worse
# than the concrete title it came from).
_DANGLING_WORDS: frozenset[str] = frozenset(
    {"a", "an", "and", "are", "as", "at", "by", "for", "from", "has", "have", "in", "is", "of", "on", "or", "the", "to", "was", "were", "with"}
)


def _generic_title(catalog_title: Any) -> str:
    """A catalog title with its ``{placeholders}`` cut off, or '' when nothing readable is left.

    ``"New device on the network: {ip} ({vendor})"`` -> ``"New device on the network"``. Used
    when one catalog ID is open on many subjects, where no single subject's wording is fair.
    """
    head = str(catalog_title or "").split("{", 1)[0].strip()
    head = head.rstrip(" \t–—-:;,(").strip()
    words = head.split()
    while words and words[-1].lower() in _DANGLING_WORDS:
        words.pop()
    head = " ".join(words)
    return head if len(head) >= 8 else ""


def _open_finding_facts(conn: sqlite3.Connection) -> dict[str, dict]:
    """finding_id -> {title, severity, count, penalty} over the currently *open* findings.

    One catalog ID can be open on several subjects (``NET-SVC-001`` on three devices) and, in
    principle, at different severities, so counts and penalties are summed and the worst
    severity wins. A single open finding keeps its own concrete title ("Telnet is open on
    192.168.1.74"); several share the catalog's generic one.
    """
    facts: dict[str, dict] = {}
    data = rows(
        conn,
        "SELECT finding_id, severity, count(*) AS n, min(title) AS title FROM findings "
        "WHERE status='open' GROUP BY finding_id, severity",
    )
    for r in data:
        fid = str(r["finding_id"] or "").strip()
        if not fid:
            continue
        sev = str(r["severity"] or "info").lower()
        n = max(0, int(r["n"] or 0))
        f = facts.setdefault(fid, {"finding_id": fid, "title": None, "severity": "info", "count": 0, "penalty": 0})
        f["count"] += n
        f["penalty"] += SCORE_PENALTY.get(sev, 0) * n
        if f["title"] is None or _sev_rank(sev) < _sev_rank(f["severity"]):
            f["severity"] = sev
            f["title"] = r["title"]
    for fid, f in facts.items():
        generic = _generic_title(getattr(catalog_spec(fid), "title", None))
        if f["count"] > 1 and generic:
            f["title"] = generic
        f["title"] = str(f["title"] or generic or fid)
    return facts


def _score_breakdown_from_findings(conn: sqlite3.Connection) -> list[dict] | None:
    """``homesoc.findings.score.score_breakdown`` when that package ships it, else ``None``.

    findings owns the scoring formula, so its numbers win whenever they are available; this
    module is only allowed to guess when they are not.
    """
    fn = getattr(_findings_score(), "score_breakdown", None)
    if not callable(fn):
        return None
    try:
        result = fn(conn)
    except Exception:  # a breakdown must never take the dashboard down
        logger.warning("findings.score.score_breakdown failed; using the local fallback", exc_info=True)
        return None
    if not isinstance(result, (list, tuple)):
        return None
    return [r for r in result if isinstance(r, dict)]


def score_breakdown(conn: sqlite3.Connection, limit: int = SCORE_BREAKDOWN_LIMIT) -> list[dict]:
    """Which open findings are costing the most points, most expensive first.

    Rows are ``{finding_id, title, count, penalty, gain, severity, category}`` — the fields
    findings.score produces plus what the dashboard needs to colour and link the row. ``gain``
    is how far the score would rise if every finding of that type were cleared: findings.score
    reports it as ``score_gain`` when its curve is non-linear, otherwise it equals ``penalty``.
    Only findings that actually cost points appear, so an all-``info`` database yields ``[]``.
    """
    limit = max(1, min(int(limit or 1), 50))
    facts = _open_finding_facts(conn)
    raw = _score_breakdown_from_findings(conn)
    if raw is None:
        raw = list(facts.values())

    out: list[dict] = []
    for item in raw:
        fid = str(item.get("finding_id") or "").strip()
        if not fid:
            continue
        known = facts.get(fid, {})
        try:
            penalty = int(round(float(item.get("penalty") or 0)))
            count = int(item.get("count") or known.get("count") or 0)
        except (TypeError, ValueError):
            continue
        if penalty <= 0:
            continue
        try:
            gain = int(round(float(item["score_gain"]))) if item.get("score_gain") is not None else penalty
        except (TypeError, ValueError):
            gain = penalty
        # A supplied title wins unless it still carries "{placeholders}" from the catalog.
        supplied = str(item.get("title") or "").strip()
        title = supplied if supplied and "{" not in supplied else str(known.get("title") or supplied or fid)
        out.append(
            {
                "finding_id": fid,
                "title": title,
                "count": max(0, count),
                "penalty": penalty,
                "gain": max(0, gain),
                "severity": str(item.get("severity") or known.get("severity") or "info").lower(),
                "category": category_for(fid),
            }
        )
    out.sort(key=lambda r: (-r["penalty"], -r["count"], r["finding_id"]))
    out = out[:limit]
    _breakdown_plain(conn, out)
    return out


def _breakdown_plain(conn: sqlite3.Connection, items: list[dict]) -> None:
    """Plain words for "Fix these first": the action word, "+4 points", and where it is.

    ``device_label``/``link_device_id`` are set when every open finding of that type is on one
    device (or on this computer); ``where_text`` always says where, e.g. "Home router and
    Kitchen TV" or "Home router, Kitchen TV and 3 more".
    """
    fids = [r["finding_id"] for r in items]
    places: dict[str, list[dict]] = {}
    if fids:
        marks = ",".join("?" for _ in fids)
        found = rows(
            conn,
            "SELECT f.finding_id, f.subject, f.evidence, f.device_id, d.ip AS device_ip, d.nickname AS device_nickname, "
            "d.hostname AS device_hostname, d.kind AS device_kind FROM findings f "
            f"LEFT JOIN devices d ON d.id=f.device_id WHERE f.status='open' AND f.finding_id IN ({marks}) "
            "ORDER BY f.id LIMIT 5000",
            fids,
        )
        for r in label_subject_rows(conn, found):
            bucket = places.setdefault(str(r["finding_id"]), [])
            if all(p["device_label"] != r["device_label"] for p in bucket):
                bucket.append(r)
    for item in items:
        item["severity_word"] = sev_word(item.get("severity"))
        gain = int(item.get("gain") or 0)
        item["gain_text"] = f"+{gain} point{'' if gain == 1 else 's'}"
        spots = places.get(item["finding_id"], [])
        labels = [p["device_label"] for p in spots]
        first = spots[0] if spots else {}
        item["plain_title"] = catalog_plain_title(item["finding_id"], first.get("evidence"), str(first.get("subject") or ""))
        if len(spots) == 1:
            item["device_label"] = labels[0]
            item["link_device_id"] = spots[0].get("link_device_id")
        else:
            item["device_label"] = None
            item["link_device_id"] = None
        if len(labels) <= 2:
            item["where_text"] = " and ".join(labels) or None
        else:
            item["where_text"] = f"{labels[0]}, {labels[1]} and {len(labels) - 2} more"


def category_for(finding_id: str) -> str:
    spec = catalog_spec(finding_id)
    cat = getattr(spec, "category", None) if spec is not None else None
    if cat:
        return str(cat)
    for prefix, cat in CATEGORY_BY_PREFIX.items():
        if finding_id.startswith(prefix):
            return cat
    return "other"


def catalog_spec(finding_id: str) -> Any | None:
    try:
        catalog = importlib.import_module("homesoc.findings.catalog")
    except ImportError:
        return None
    table = getattr(catalog, "CATALOG", None) or {}
    return table.get(finding_id)


def catalog_remediation(finding_id: str, evidence: dict, subject: str = "") -> list[str]:
    """Remediation steps with this finding's own evidence interpolated.

    28 of the 88 catalog entries phrase a step around a `{path}` / `{ip}` / `{profile}`
    placeholder, so handing the raw templates to the dashboard shows the user
    "right-click '{path}' > Delete". ``catalog.render_remediation`` fills them in;
    the raw list is only the fallback when the findings package is unavailable.
    """
    try:
        catalog = importlib.import_module("homesoc.findings.catalog")
        steps = catalog.render_remediation(finding_id, evidence, subject)
    except Exception:  # noqa: BLE001 - the dashboard must render even if the catalog is broken
        steps = []
    if steps:
        return list(steps)
    spec = catalog_spec(finding_id)
    return list(getattr(spec, "remediation", None) or [])


def catalog_plain_title(finding_id: str, evidence: Any = None, subject: str = "") -> str:
    """The catalog's plain-language headline for a stored finding, or "" (the caller then shows
    the technical title). Never raises: a broken catalog must not break a page."""
    try:
        catalog = importlib.import_module("homesoc.findings.catalog")
        return str(catalog.render_plain_title(str(finding_id or ""), evidence if isinstance(evidence, dict) else loads(evidence, {}), subject or "") or "")
    except Exception:  # noqa: BLE001
        return ""


def catalog_why(finding_id: str, evidence: Any = None, subject: str = "") -> str:
    """"Why it matters" with the evidence interpolated, or "" when the catalog has none."""
    try:
        catalog = importlib.import_module("homesoc.findings.catalog")
        return str(catalog.render_why(str(finding_id or ""), evidence if isinstance(evidence, dict) else loads(evidence, {}), subject or "") or "")
    except Exception:  # noqa: BLE001
        return ""


def _decorate_finding(f: dict) -> dict:
    spec = catalog_spec(f["finding_id"])
    evidence = loads(f.get("evidence"), {})
    f["evidence"] = evidence
    f["evidence_pretty"] = json.dumps(evidence, indent=2, sort_keys=True, default=str) if evidence else ""
    f["category"] = category_for(f["finding_id"])
    f["remediation"] = catalog_remediation(f["finding_id"], evidence, str(f.get("subject") or ""))
    f["refs"] = list(getattr(spec, "refs", None) or [])
    subject = str(f.get("subject") or "")
    # "Why it matters" with this finding's evidence filled in (a few rationales carry
    # {placeholders}); the plain headline sits beside the technical title, never instead of it.
    f["rationale"] = catalog_why(f["finding_id"], evidence, subject) or getattr(spec, "rationale", None) or ""
    f["plain_title"] = catalog_plain_title(f["finding_id"], evidence, subject)
    f["severity_word"] = sev_word(f.get("severity"))
    f["status_word"] = status_word(f.get("status"))
    return f


def findings_list(
    conn: sqlite3.Connection,
    *,
    status: str | None = None,
    severity: str | None = None,
    q: str | None = None,
    category: str | None = None,
    device_id: int | None = None,
    limit: int = 500,
) -> list[dict]:
    where, params = ["1=1"], []
    if status in STATUSES:
        where.append("f.status=?")
        params.append(status)
    if severity in SEVERITIES:
        where.append("f.severity=?")
        params.append(severity)
    if q:
        like = f"%{q}%"
        where.append("(f.title LIKE ? OR f.subject LIKE ? OR f.detail LIKE ? OR f.finding_id LIKE ?)")
        params += [like, like, like, like]
    if device_id is not None:
        where.append("f.device_id=?")
        params.append(device_id)
    order = "CASE f.severity " + " ".join(f"WHEN '{s}' THEN {i}" for i, s in enumerate(SEVERITIES)) + " ELSE 9 END"
    data = rows(
        conn,
        "SELECT f.*, d.ip AS device_ip, COALESCE(d.nickname, d.hostname, d.ip) AS device_name, "
        "d.nickname AS device_nickname, d.hostname AS device_hostname, d.kind AS device_kind "
        f"FROM findings f LEFT JOIN devices d ON d.id=f.device_id WHERE {' AND '.join(where)} "
        f"ORDER BY {order}, f.last_seen DESC LIMIT ?",
        params + [max(1, min(int(limit), 5000))],
    )
    out = label_subject_rows(conn, [_decorate_finding(f) for f in data])
    if category:
        out = [f for f in out if f["category"] == category]
    # "Fixed" only when Home SOC's own check confirmed it; "Marked fixed" when a person said so.
    how = resolved_how(conn, [int(f["id"]) for f in out if f.get("status") == "resolved" and f.get("id") is not None])
    for f in out:
        f["rechecks"] = str(f.get("finding_id") or "") not in NOT_RECHECKED_IDS
        if f.get("status") == "resolved":
            f["resolved_how"] = how.get(int(f["id"]), "manual") if f.get("id") is not None else None
    return out


def set_finding_status(conn: sqlite3.Connection, row_id: int, status: str, note: str | None = None) -> bool:
    if status not in STATUSES:
        raise ValueError("invalid status")
    if one(conn, "SELECT id FROM findings WHERE id=?", (row_id,)) is None:
        return False
    try:
        engine = importlib.import_module("homesoc.findings.engine")
    except ImportError:
        engine = None
    if engine is not None and hasattr(engine, "set_status"):
        engine.set_status(conn, row_id, status, note)
        return True
    # SPEC-GAP: findings.engine not importable -> apply the lifecycle change directly.
    now = now_iso()
    resolved_at = now if status == "resolved" else None
    write(conn, "UPDATE findings SET status=?, resolved_at=? WHERE id=?", (status, resolved_at, row_id))
    write(
        conn,
        "INSERT INTO finding_events(finding_row_id, event, at, note) VALUES(?,?,?,?)",
        (row_id, status, now, note),
    )
    return True


# --------------------------------------------------------------------------- devices


def _device_row(d: dict) -> dict:
    d["online"] = _bool(d.get("online"))
    d["trusted"] = _bool(d.get("trusted"))
    d["display_name"] = d.get("nickname") or d.get("hostname") or d.get("ip") or d.get("mac")
    d["device_label"] = device_label(d)
    d["mdns_services"] = loads(d.get("mdns_services"), [])
    return d


def _mark_host_device(conn: sqlite3.Connection, devices: list[dict]) -> None:
    """Flag the computer Home SOC runs on and count the open ``host:`` findings that are about it.

    Those findings carry no device_id (they are about the machine's own settings), so without this
    the host's device page said "No findings" while twenty were open on the This computer page.
    """
    data = rows(conn, "SELECT subject, count(*) AS n FROM findings WHERE status='open' AND "
                      "(subject='host' OR substr(subject,1,5)='host:') GROUP BY subject")
    names = sorted({host_name_from_subject(r["subject"]) for r in data if host_name_from_subject(r["subject"])})
    if not names:  # no open host finding names the machine: ask any finding that ever did
        named = scalar(conn, "SELECT subject FROM findings WHERE substr(subject,1,5)='host:' ORDER BY id DESC LIMIT 1",
                       default=None)
        names = [host_name_from_subject(named)] if named and host_name_from_subject(named) else []
    host = host_device(conn, names[0] if names else None)
    host_id = int(host["id"]) if host else None
    host_open = sum(int(r["n"] or 0) for r in data)
    host_subject = f"host:{names[0]}" if names else "host"
    for d in devices:
        mine = host_id is not None and int(d["id"]) == host_id
        d["is_this_computer"] = mine
        d["host_findings_open"] = host_open if mine else 0
        d["host_findings_link"] = ("/findings?status=open&q=" + quote(host_subject, safe="")) if mine else None


def _device_ids_for_subject(subject: str, by_mac: dict[str, int]) -> set[int]:
    """Devices a ``device:<mac>`` / ``device:<mac>:<rest>`` finding subject names.

    MACs contain colons themselves, so every colon-delimited prefix of the remainder is tried
    (a handful of dictionary probes), which matches ``subject = 'device:'||mac`` and
    ``subject LIKE 'device:'||mac||':%'`` without a per-device scan.
    """
    if not subject.startswith("device:"):
        return set()
    rest = subject[len("device:"):].lower()
    found: set[int] = set()
    cut = len(rest)
    while cut > 0:
        device_id = by_mac.get(rest[:cut])
        if device_id is not None:
            found.add(device_id)
        cut = rest.rfind(":", 0, cut)
    return found


def devices_list(conn: sqlite3.Connection) -> list[dict]:
    """Every device with its open-port and open-finding counts.

    Three linear queries joined in Python, not a correlated subquery per device: the old
    ``(SELECT count(*) FROM findings WHERE device_id=d.id OR subject=... OR subject LIKE ...)``
    could not use an index, so it scanned every open finding once per device — quadratic in a
    table a LAN device can grow at will by answering ARP with fresh MACs, and all of it under
    the connection lock every other thread waits on.
    """
    data = rows(conn, "SELECT d.* FROM devices d ORDER BY d.online DESC, d.last_seen DESC")
    ports = {
        int(r["device_id"]): int(r["n"] or 0)
        for r in rows(conn, "SELECT device_id, count(*) AS n FROM services WHERE state='open' GROUP BY device_id")
        if r.get("device_id") is not None
    }
    ids = {int(d["id"]) for d in data}
    by_mac = {str(d["mac"]).lower(): int(d["id"]) for d in data if d.get("mac")}
    findings_open: dict[int, int] = {}
    for f in rows(conn, "SELECT device_id, subject FROM findings WHERE status='open'"):
        owners = _device_ids_for_subject(str(f.get("subject") or ""), by_mac)
        if f.get("device_id") is not None and int(f["device_id"]) in ids:
            owners.add(int(f["device_id"]))
        for device_id in owners:
            findings_open[device_id] = findings_open.get(device_id, 0) + 1
    for d in data:
        d["open_ports"] = ports.get(int(d["id"]), 0)
        d["open_findings"] = findings_open.get(int(d["id"]), 0)
    out = [_device_row(d) for d in data]
    _mark_host_device(conn, out)
    return out


def device_counts(conn: sqlite3.Connection) -> dict[str, int]:
    return {
        "online": int(scalar(conn, "SELECT count(*) FROM devices WHERE online=1")),
        "total": int(scalar(conn, "SELECT count(*) FROM devices")),
    }


def device_detail(conn: sqlite3.Connection, device_id: int) -> dict | None:
    d = one(conn, "SELECT * FROM devices WHERE id=?", (device_id,))
    if d is None:
        return None
    _device_row(d)
    _mark_host_device(conn, [d])
    d["services"] = rows(
        conn,
        "SELECT * FROM services WHERE device_id=? ORDER BY CASE state WHEN 'open' THEN 0 ELSE 1 END, port",
        (device_id,),
    )
    d["vulns"] = vulns_list(conn, device_id=device_id)
    d["findings"] = findings_list(conn, device_id=device_id, limit=200)
    week = cutoff_iso(7 * 24)
    d["sightings"] = rows(
        conn,
        "SELECT ip, seen_at, method FROM device_sightings WHERE device_id=? AND seen_at>=? "
        "ORDER BY seen_at DESC LIMIT 500",
        (device_id, week),
    )
    per_day = {
        r["d"]: int(r["n"])
        for r in rows(
            conn,
            "SELECT substr(seen_at,1,10) AS d, count(*) AS n FROM device_sightings "
            "WHERE device_id=? AND seen_at>=? GROUP BY d",
            (device_id, week),
        )
    }
    today = utcnow().date()
    d["presence"] = [
        {"date": (today - timedelta(days=i)).isoformat(), "count": per_day.get((today - timedelta(days=i)).isoformat(), 0)}
        for i in range(6, -1, -1)
    ]
    return d


def update_device(conn: sqlite3.Connection, device_id: int, payload: dict) -> bool:
    """Nickname/notes/trusted are the user's annotations; the dashboard is their only
    editor, so it writes the three columns directly (SPEC-GAP: devices is owned by
    discovery, which never touches these columns)."""
    if one(conn, "SELECT id FROM devices WHERE id=?", (device_id,)) is None:
        return False
    sets, params = [], []
    if "nickname" in payload:
        sets.append("nickname=?")
        params.append((str(payload.get("nickname") or "")[:80]) or None)
    if "notes" in payload:
        sets.append("notes=?")
        params.append((str(payload.get("notes") or "")[:2000]) or None)
    trusted: bool | None = None
    if "trusted" in payload:
        trusted = _bool(payload.get("trusted"))
        sets.append("trusted=?")
        params.append(1 if trusted else 0)
    if not sets:
        return True
    params.append(device_id)
    write(conn, f"UPDATE devices SET {', '.join(sets)} WHERE id=?", params)
    if trusted:
        _resolve_new_device_findings(conn, device_id)
    return True


def _resolve_new_device_findings(conn: sqlite3.Connection, device_id: int) -> None:
    """Marking a device trusted answers the "new device" question; close the open NET-DEV-001 row
    (through the findings engine so the event trail stays intact)."""
    rows_ = rows(conn, "SELECT id FROM findings WHERE finding_id='NET-DEV-001' AND device_id=? AND status IN ('open','acknowledged')", (device_id,))
    if not rows_:
        return
    try:
        engine = importlib.import_module("homesoc.findings.engine")
    except ImportError:
        engine = None
    for r in rows_:
        try:
            if engine is not None:
                engine.set_status(conn, int(r["id"]), "resolved", note="device marked trusted")
            else:  # SPEC-GAP: engine absent -> direct update so the dashboard still behaves
                write(conn, "UPDATE findings SET status='resolved', resolved_at=? WHERE id=?", (now_iso(), int(r["id"])))
        except Exception:
            logger.exception("could not resolve NET-DEV-001 for device %s", device_id)


# --------------------------------------------------------------------------- vulns


def vulns_list(
    conn: sqlite3.Connection,
    *,
    kev: bool | None = None,
    q: str | None = None,
    device_id: int | None = None,
    min_cvss: float | None = None,
    limit: int = 1000,
) -> list[dict]:
    where, params = ["1=1"], []
    if kev:
        where.append("v.kev=1")
    if device_id is not None:
        where.append("v.device_id=?")
        params.append(device_id)
    if min_cvss is not None:
        where.append("COALESCE(v.cvss,0)>=?")
        params.append(float(min_cvss))
    if q:
        like = f"%{q}%"
        where.append("(v.cve LIKE ? OR v.title LIKE ? OR d.ip LIKE ? OR s.product LIKE ?)")
        params += [like, like, like, like]
    data = rows(
        conn,
        "SELECT v.*, d.ip AS device_ip, d.mac AS device_mac, "
        "COALESCE(d.nickname, d.hostname, d.ip) AS device_name, "
        "d.nickname AS device_nickname, d.hostname AS device_hostname, d.kind AS device_kind, "
        "s.port, s.proto, s.name AS service_name, s.product, s.version AS service_version "
        "FROM vulns v LEFT JOIN devices d ON d.id=v.device_id LEFT JOIN services s ON s.id=v.service_id "
        f"WHERE {' AND '.join(where)} ORDER BY v.kev DESC, COALESCE(v.cvss,0) DESC, v.first_seen DESC LIMIT ?",
        params + [max(1, min(int(limit), 5000))],
    )
    for v in data:
        v["kev"] = _bool(v.get("kev"))
        v["nvd_url"] = f"https://nvd.nist.gov/vuln/detail/{v['cve']}"
        v["kev_url"] = "https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext=" + str(v["cve"])
        if v.get("device_id") is not None:
            v["device_label"] = device_label({
                "nickname": v.get("device_nickname"), "hostname": v.get("device_hostname"),
                "kind": v.get("device_kind"), "device_id": v.get("device_id"),
            })
            v["device_name"] = v["device_label"]  # was the IP for an unnamed device: shown twice
        else:
            v["device_label"] = "Unnamed device"
        v["cvss_text"] = cvss_text(v.get("cvss"))
        v["epss_pct"] = epss_pct(v.get("epss"))
        v["epss_text"] = epss_text(v.get("epss"))
        v["epss_note"] = EPSS_NOTE if v["epss_text"] else None
        v["kev_text"] = kev_text(v.get("kev"))
    return data


# --------------------------------------------------------------------------- host


def host_data(conn: sqlite3.Connection) -> dict:
    checks = rows(conn, "SELECT * FROM host_checks ORDER BY check_id")
    for c in checks:
        c["needs_admin"] = _bool(c.get("needs_admin"))
        c["group"] = category_for(c["check_id"])
    defender = loads(get_setting(conn, "defender.status_json"), {}) or {}
    # SPEC-GAP: the spec only names defender.status_json; threats are taken from an optional
    # defender.threats_json key plus the open WIN-DEF-011 findings, whichever exists.
    threats = loads(get_setting(conn, "defender.threats_json"), []) or []
    if not threats:
        threats = [
            {"name": f["title"], "detail": f.get("detail"), "seen": f["last_seen"], "evidence": f["evidence"]}
            for f in findings_list(conn, status="open", limit=100)
            if f["finding_id"] == "WIN-DEF-011"
        ]
    software = rows(
        conn,
        "SELECT * FROM software WHERE available IS NOT NULL AND available<>'' AND "
        "(version IS NULL OR available<>version) ORDER BY name",
    )
    persistence = rows(conn, "SELECT * FROM persistence ORDER BY baseline ASC, last_seen DESC")
    for p in persistence:
        p["baseline"] = _bool(p.get("baseline"))
    # SPEC-GAP: no table holds pending Windows updates / listeners. scanners.updates keeps its
    # probe JSON under updates.status_json ({pending, hotfix, history}) and scanners.host_* the
    # posture probe under host.posture_json ({listeners: [{port, address, pid, process}], hotfix}).
    updates_json = loads(get_setting(conn, "updates.status_json"), {}) or {}
    posture_json = loads(get_setting(conn, "host.posture_json"), {}) or {}
    if not isinstance(updates_json, dict):
        updates_json = {}
    if not isinstance(posture_json, dict):
        posture_json = {}
    pending = _as_list(updates_json.get("pending")) or loads(get_setting(conn, "updates.pending_json"), []) or []
    listeners = _as_list(posture_json.get("listeners")) or loads(get_setting(conn, "host.listeners_json"), []) or []
    if not listeners:
        listeners = [
            {"port": c["check_id"], "value": c.get("value"), "status": c["status"]}
            for c in checks
            if c["check_id"].startswith(("WIN-NET-006", "POSIX-NET-001"))
        ]
    updates = {
        "pending": pending,
        "checks": [c for c in checks if c["check_id"].startswith(("WIN-UPD", "POSIX-UPD"))],
        "last_hotfix": _last_hotfix(updates_json.get("hotfix"), posture_json.get("hotfix"))
        or get_setting(conn, "updates.last_hotfix"),
    }
    defender_summary = {
        "status": defender,
        "signature_age_days": defender.get("AntivirusSignatureAge") or defender.get("signature_age_days"),
        "last_quick_scan": defender.get("QuickScanEndTime") or defender.get("last_quick_scan"),
        "last_full_scan": defender.get("FullScanEndTime") or defender.get("last_full_scan"),
        "threats": threats,
        "checked_at": get_setting(conn, "defender.checked_at"),
    }
    return {
        "checks": checks,
        "defender": defender_summary,
        "updates": updates,
        "software": software,
        "persistence": persistence,
        "listeners": listeners,
        "platform": platform.system(),
    }


def _as_list(value: Any) -> list:
    """Probe sections are a list on success and an error string on failure; only lists are data."""
    return [v for v in value if isinstance(v, dict)] if isinstance(value, list) else []


def _last_hotfix(*sections: Any) -> str | None:
    """'KB5060842 (2026-07-16)' from whichever probe (updates.ps1 or posture.ps1) reported a hotfix."""
    for section in sections:
        if not isinstance(section, dict):
            continue
        hotfix_id = section.get("id") or section.get("last_id")
        installed = section.get("installed") or section.get("last_installed")
        if hotfix_id or installed:
            return f"{hotfix_id or 'hotfix'} ({installed})" if installed else str(hotfix_id)
    return None


# Defender actions shell out to MpCmdRun.exe: a quick scan takes minutes and a signature update
# took up to 15 minutes inline, which pinned a Flask worker and let a second click start a second
# MpCmdRun. Both are fire-and-forget now: one guarded worker thread per action, de-duplicated by
# ``_defender_jobs``, with the outcome kept for ``GET /api/defender/status`` to poll.
DEFENDER_ACTIONS: dict[str, tuple[str, ...]] = {
    "quick-scan": ("trigger_quick_scan", "quick_scan"),
    "update": ("trigger_signature_update", "update_signatures"),
}
_DEFENDER_RUNNING_PROBE: dict[str, str] = {"quick-scan": "quick_scan_running", "update": "update_running"}
# The scanner runs MpCmdRun on its own thread and publishes the real outcome here. When these
# exist they are authoritative: our trigger call returns as soon as the child is LAUNCHED, so a
# web-side "finished" stamp would otherwise claim success milliseconds into a minutes-long update.
_DEFENDER_STATUS_PROBE: dict[str, str] = {"quick-scan": "quick_scan_status", "update": "update_status"}
_defender_lock = threading.Lock()
_defender_jobs: dict[str, dict] = {}


def _defender_module() -> Any | None:
    try:
        return importlib.import_module("homesoc.scanners.defender")
    except ImportError:
        return None


def _defender_probe(action: str, which: dict[str, str]) -> Any | None:
    defender = _defender_module()
    if defender is None:
        return None
    probe = getattr(defender, which[action], None)
    return probe if callable(probe) else None


def _defender_worker(cfg: Any, action: str, func: Any) -> None:
    ok, error = False, None
    try:
        ok = bool(func(cfg))
    except Exception as exc:  # the action shells out; never let it kill the thread silently
        logger.exception("defender action %s failed", action)
        error = str(exc)[:200]
    if error is None and _defender_probe(action, _DEFENDER_STATUS_PROBE) is not None:
        # The trigger only LAUNCHED MpCmdRun. The scanner owns the outcome from here, so leave
        # this job open and let defender_status() read the real state instead of stamping "done".
        with _defender_lock:
            _defender_jobs.setdefault(action, {})["handed_off"] = True
        return
    with _defender_lock:
        job = _defender_jobs.setdefault(action, {})
        job.update({"running": False, "finished_at": now_iso(), "ok": ok, "error": error})


def defender_action(cfg: Any, action: str) -> dict:
    """Start ``action`` in the background and return immediately (HTTP 202).

    Returns ``ok=False`` only when the integration is missing; a click while the same action is
    already running is a success ("already running"), not an error, so the UI stays idempotent.
    """
    names = DEFENDER_ACTIONS.get(action)
    if names is None:
        return {"ok": False, "error": "unknown action"}
    defender = _defender_module()
    func = next((getattr(defender, n) for n in names if defender is not None and hasattr(defender, n)), None)
    if func is None:
        logger.warning("defender action %s unavailable", action)
        return {"ok": False, "error": "defender integration unavailable"}
    # A handed-off job stays flagged running until the scanner says otherwise, so ask the scanner
    # before refusing a second click -- otherwise the button dead-ends after the first update.
    still_running = None
    running_probe = _defender_probe(action, _DEFENDER_RUNNING_PROBE)
    if running_probe is not None:
        try:
            still_running = bool(running_probe())
        except Exception:
            logger.exception("defender %s probe failed", action)
    with _defender_lock:
        job = _defender_jobs.get(action)
        busy = bool(job and job.get("running")) if still_running is None else still_running
        if busy:
            return {"ok": True, "action": action, "status": "already running",
                    "started_at": (job or {}).get("started_at")}
        started = now_iso()
        _defender_jobs[action] = {"running": True, "started_at": started, "finished_at": None, "ok": None, "error": None}
    thread = threading.Thread(
        target=_defender_worker, args=(cfg, action, func), name=f"homesoc-defender-{action}", daemon=True
    )
    thread.start()
    return {"ok": True, "action": action, "status": "started", "started_at": started}


def defender_status() -> dict:
    """State of both background actions, for the UI to poll after a 202."""
    defender = _defender_module()
    out: dict[str, Any] = {"available": defender is not None, "actions": {}}
    with _defender_lock:
        jobs = {k: dict(v) for k, v in _defender_jobs.items()}
    for action in DEFENDER_ACTIONS:
        job = jobs.get(action) or {"running": False, "started_at": None, "finished_at": None, "ok": None, "error": None}
        handed_off = bool(job.pop("handed_off", False))
        state = None
        status_probe = _defender_probe(action, _DEFENDER_STATUS_PROBE)
        if status_probe is not None:
            try:  # the scanner owns the real process and the real outcome
                state = status_probe()
            except Exception:
                logger.exception("defender %s status probe failed", action)
        if isinstance(state, dict):
            job.update({
                "running": bool(state.get("running")),
                "started_at": state.get("started_at") or job.get("started_at"),
                "finished_at": state.get("finished_at"),
                "ok": state.get("ok"),
                "error": (state.get("message") or None) if state.get("ok") is False else job.get("error"),
                "rc": state.get("rc"),
                "message": state.get("message") or "",
            })
        else:
            running_probe = _defender_probe(action, _DEFENDER_RUNNING_PROBE)
            if running_probe is not None:
                try:
                    job["running"] = bool(running_probe()) or bool(job.get("running"))
                except Exception:
                    logger.exception("defender %s probe failed", action)
            elif handed_off:  # no way to observe the child; do not claim it finished
                job["running"] = True
        out["actions"][action] = job
    return out


# --------------------------------------------------------------------------- dns


def dns_running(c: WebContext) -> bool:
    if c.dns_server is None:
        return False
    flag = getattr(c.dns_server, "running", None)
    if callable(flag):
        try:
            return bool(flag())
        except Exception:
            return False
    return True if flag is None else bool(flag)


#: How many of the newest raw rows the cache-hit rate and average latency are measured over.
DNS_SAMPLE_ROWS = 20000


def _dns_window(conn: sqlite3.Connection, hours: float) -> tuple[str, str | None, str | None]:
    """Split a trailing window into ``(since, first_hourly, rolled_up_until)``.

    ``dns_hourly`` is rewritten for the last 48 h by every hourly ``dns_rollup`` run, so every
    hour strictly before its newest row is complete. The window is read as: raw rows for the
    partial first hour, rolled-up rows for the whole hours in the middle, and raw rows again only
    from the newest rolled-up hour on — at most an hour or two of raw rows however long the
    window, instead of every query of the last day (or fortnight) under the shared lock.
    ``rolled_up_until`` is ``None`` when there is nothing rolled up to use, in which case the
    caller reads the window from raw rows alone, exactly as before.
    """
    since = cutoff_iso(hours)
    start = parse_ts(since) or utcnow()
    first_hourly = (start.replace(minute=0, second=0, microsecond=0) + timedelta(hours=1)).strftime("%Y-%m-%dT%H:00")
    newest = scalar(conn, "SELECT max(hour) FROM dns_hourly WHERE hour>=?", (first_hourly,), default=None)
    if not newest or str(newest) <= first_hourly:
        return since, None, None
    return since, first_hourly, str(newest)


def _hour_to_ts(hour: str) -> str:
    """``2026-09-04T12:00`` -> ``2026-09-04T12:00:00``: comparable with raw ``ts`` values."""
    return hour[:13] + ":00:00"


def dns_window_counts(conn: sqlite3.Connection, hours: float = 24) -> dict[str, int]:
    """``{total, blocked, clients}`` over the trailing window, mostly from ``dns_hourly``."""
    since, first_hourly, newest = _dns_window(conn, hours)
    if newest is None:
        agg = one(
            conn,
            "SELECT count(*) AS total, sum(action='block') AS blocked, count(DISTINCT client) AS clients "
            "FROM dns_queries WHERE ts>=?",
            (since,),
        ) or {}
        return {k: int(agg.get(k) or 0) for k in ("total", "blocked", "clients")}
    head_end, tail_start = _hour_to_ts(first_hourly), _hour_to_ts(newest)
    agg = one(
        conn,
        "SELECT sum(total) AS total, sum(blocked) AS blocked FROM ("
        " SELECT count(*) AS total, sum(action='block') AS blocked FROM dns_queries WHERE ts>=? AND ts<?"
        " UNION ALL SELECT sum(total), sum(blocked) FROM dns_hourly WHERE hour>=? AND hour<?"
        " UNION ALL SELECT count(*), sum(action='block') FROM dns_queries WHERE ts>=?)",
        (since, head_end, first_hourly, newest, tail_start),
    ) or {}
    clients = scalar(
        conn,
        "SELECT count(*) FROM ("
        " SELECT client FROM dns_queries WHERE ts>=? AND ts<?"
        " UNION SELECT client FROM dns_hourly WHERE hour>=? AND hour<?"
        " UNION SELECT client FROM dns_queries WHERE ts>=?)",
        (since, head_end, first_hourly, newest, tail_start),
    )
    return {"total": int(agg.get("total") or 0), "blocked": int(agg.get("blocked") or 0), "clients": int(clients or 0)}


def _dns_recent_sample(conn: sqlite3.Connection, since: str) -> dict[str, Any]:
    """Cache hits and mean latency over the newest :data:`DNS_SAMPLE_ROWS` rows of the window."""
    return one(
        conn,
        "SELECT count(*) AS n, sum(action='cache') AS cached, avg(ms) AS avg_ms FROM "
        "(SELECT action, ms FROM dns_queries WHERE ts>=? ORDER BY ts DESC LIMIT ?)",
        (since, DNS_SAMPLE_ROWS),
    ) or {}


def dns_summary(c: WebContext) -> dict:
    conn = c.conn

    def compute() -> dict:
        counts = dns_window_counts(conn, 24)
        sample = _dns_recent_sample(conn, cutoff_iso(24))
        sampled = int(sample.get("n") or 0)
        cached = int(sample.get("cached") or 0)
        if sampled and counts["total"] > sampled:
            cached = round(cached * counts["total"] / sampled)  # an estimate once the day outgrows the sample
        return {**counts, "cached": cached, "avg_ms": sample.get("avg_ms")}

    agg = throttled(c, ("dns_summary",), compute)
    total = int(agg.get("total") or 0)
    blocked = int(agg.get("blocked") or 0)
    today = utcnow().strftime("%Y-%m-%d")
    budget_used = int(str(get_setting(conn, f"vt.budget.{today}", "0") or "0").split(".")[0] or 0)
    return {
        "total24h": total,
        "blocked24h": blocked,
        "blocked_pct": round(100.0 * blocked / total, 1) if total else 0.0,
        "cached24h": int(agg.get("cached") or 0),
        "clients24h": int(agg.get("clients") or 0),
        "avg_ms": round(float(agg.get("avg_ms") or 0.0), 1),
        "running": dns_running(c),
        "enabled": _bool(cfg_get(c.cfg, "dns.enabled", False)),
        "listen": str(cfg_get(c.cfg, "dns.listen", "0.0.0.0")),
        "port": int(cfg_get(c.cfg, "dns.port", 53) or 53),
        "upstreams": list(cfg_get(c.cfg, "dns.upstreams", []) or []),
        "block_mode": str(cfg_get(c.cfg, "dns.block_mode", "null")),
        "overrides": int(scalar(conn, "SELECT count(*) FROM dns_overrides")),
        "reputation_entries": int(scalar(conn, "SELECT count(*) FROM reputation")),
        "vt_budget": {
            "date": today,
            "used": budget_used,
            "limit": int(cfg_get(c.cfg, "dns.virustotal_daily_budget", 400) or 0),
            "key_set": bool(cfg_get(c.cfg, "dns.virustotal_api_key", "")),
        },
    }


def dns_series(conn: sqlite3.Connection, hours: int = 24) -> list[dict]:
    """Per-hour totals; the current (not yet rolled-up) hour is included from raw rows and whole
    rolled-up hours come from dns_hourly (see :func:`_dns_window`). Missing hours are zero-filled
    so charts always show the full window."""
    hours = max(1, min(int(hours), 24 * 14))
    since, first_hourly, newest = _dns_window(conn, hours)
    if newest is None:
        data = rows(
            conn,
            "SELECT substr(ts,1,13) AS hour, count(*) AS total, sum(action='block') AS blocked "
            "FROM dns_queries WHERE ts>=? GROUP BY hour ORDER BY hour",
            (since,),
        )
    else:
        data = rows(
            conn,
            "SELECT hour, sum(total) AS total, sum(blocked) AS blocked FROM ("
            " SELECT substr(ts,1,13) AS hour, count(*) AS total, sum(action='block') AS blocked"
            "  FROM dns_queries WHERE ts>=? AND ts<? GROUP BY 1"
            " UNION ALL SELECT substr(hour,1,13), sum(total), sum(blocked)"
            "  FROM dns_hourly WHERE hour>=? AND hour<? GROUP BY 1"
            " UNION ALL SELECT substr(ts,1,13), count(*), sum(action='block')"
            "  FROM dns_queries WHERE ts>=? GROUP BY 1"
            ") GROUP BY hour ORDER BY hour",
            (since, _hour_to_ts(first_hourly), first_hourly, newest, _hour_to_ts(newest)),
        )
    by_hour = {r["hour"]: r for r in data}
    now = utcnow().replace(minute=0, second=0, microsecond=0)
    out = []
    for i in range(hours - 1, -1, -1):
        key = (now - timedelta(hours=i)).strftime("%Y-%m-%dT%H")
        r = by_hour.get(key, {})
        out.append({"hour": key, "total": int(r.get("total") or 0), "blocked": int(r.get("blocked") or 0)})
    return out


def label_clients(conn: sqlite3.Connection, items: list[dict], key: str = "client") -> list[dict]:
    """Add ``device_id``/``device_label``/``device_ip`` to rows keyed on a DNS client address.

    A client with no device row is an address Home SOC has never inventoried; it reads
    "Unnamed device", and the address stays in ``client``/``device_ip`` for the page to show muted.
    """
    known = device_labels_by_ip(conn, [r.get(key) for r in items])
    for r in items:
        ip = str(r.get(key) or "")
        hit = known.get(ip)
        r["device_id"] = hit["device_id"] if hit else None
        r["device_label"] = hit["device_label"] if hit else "Unnamed device"
        r["device_ip"] = ip or None
    return items


def dns_top(conn: sqlite3.Connection, kind: str = "blocked", hours: int = 24, limit: int = 20) -> list[dict]:
    if kind == "clients":
        return label_clients(conn, _dns_top(conn, kind, hours, limit))
    return _dns_top(conn, kind, hours, limit)


def _dns_top(conn: sqlite3.Connection, kind: str = "blocked", hours: int = 24, limit: int = 20) -> list[dict]:
    hours = max(1, min(int(hours), 24 * 30))
    since = cutoff_iso(hours)
    limit = max(1, min(int(limit), 200))
    if kind == "clients":
        _, first_hourly, newest = _dns_window(conn, hours)
        if newest is None:
            return rows(
                conn,
                "SELECT client, count(*) AS total, sum(action='block') AS blocked FROM dns_queries "
                "WHERE ts>=? GROUP BY client ORDER BY total DESC LIMIT ?",
                (since, limit),
            )
        return rows(
            conn,
            "SELECT client, sum(total) AS total, sum(blocked) AS blocked FROM ("
            " SELECT client, count(*) AS total, sum(action='block') AS blocked"
            "  FROM dns_queries WHERE ts>=? AND ts<? GROUP BY client"
            " UNION ALL SELECT client, sum(total), sum(blocked) FROM dns_hourly WHERE hour>=? AND hour<? GROUP BY client"
            " UNION ALL SELECT client, count(*), sum(action='block') FROM dns_queries WHERE ts>=? GROUP BY client"
            ") GROUP BY client ORDER BY total DESC LIMIT ?",
            (since, _hour_to_ts(first_hourly), first_hourly, newest, _hour_to_ts(newest), limit),
        )
    return rows(
        conn,
        "SELECT qname AS domain, count(*) AS hits, max(reason) AS reason, count(DISTINCT client) AS clients "
        "FROM dns_queries WHERE ts>=? AND action='block' GROUP BY qname ORDER BY hits DESC LIMIT ?",
        (since, limit),
    )


def dns_log(conn: sqlite3.Connection, limit: int = 100, client: str | None = None, action: str | None = None) -> list[dict]:
    where, params = ["1=1"], []
    if client:
        where.append("client=?")
        params.append(client)
    if action in ("allow", "block", "cache", "error"):
        where.append("action=?")
        params.append(action)
    params.append(max(1, min(int(limit), 1000)))
    data = label_clients(conn, rows(
        conn,
        f"SELECT * FROM dns_queries WHERE {' AND '.join(where)} ORDER BY id DESC LIMIT ?",
        params,
    ))
    _attach_verdicts(conn, data)
    return data


#: Threat-list names (mirrors homesoc.web.feed.THREAT_LISTS, which imports this module).
_THREAT_LIST_NAMES: frozenset[str] = frozenset(
    {"urlhaus", "threatfox", "openphish", "phishing_army", "feodo", "feodo_ips", "spamhaus_drop", "urlhaus_filter"}
)


def _attach_verdicts(conn: sqlite3.Connection, data: list[dict]) -> None:
    """Give each log row a ``reputation`` word so a one-tap "allow" can warn loudly.

    ``verdict`` is the cached reputation verdict for the name, if any. ``reputation`` is
    "malicious" when the name was blocked by the reputation check or by a threat list, else the
    verdict. Nothing here changes what was logged.
    """
    names = sorted({str(r.get("qname") or "").lower().rstrip(".") for r in data} - {""})
    verdicts: dict[str, str] = {}
    for start in range(0, len(names), 500):
        chunk = names[start:start + 500]
        marks = ",".join("?" for _ in chunk)
        try:
            for r in rows(conn, f"SELECT domain, verdict FROM reputation WHERE domain IN ({marks})", chunk):
                verdicts[str(r["domain"]).lower()] = str(r.get("verdict") or "")
        except sqlite3.Error:
            break
    for r in data:
        verdict = verdicts.get(str(r.get("qname") or "").lower().rstrip("."), "") or None
        reason = str(r.get("reason") or "")
        on_threat_list = reason.startswith("list:") and reason[5:] in _THREAT_LIST_NAMES
        r["verdict"] = verdict
        r["reputation"] = "malicious" if (reason == "reputation" or on_threat_list) else verdict


def dns_lists(c: WebContext) -> list[dict]:
    active = {str(n) for n in (cfg_get(c.cfg, "dns.lists", []) or [])}
    placeholders = ",".join("?" for _ in BLOCKLIST_KINDS)
    data = rows(
        c.conn,
        f"SELECT name, kind, url, status, entries, bytes, last_updated, last_checked, enabled, error "
        f"FROM feeds WHERE kind IN ({placeholders}) ORDER BY name",
        BLOCKLIST_KINDS,
    )
    for r in data:
        r["enabled"] = _bool(r.get("enabled"))
        r["active"] = r["name"] in active
        r["age_hours"] = age_hours(r.get("last_updated"))
    return data


def dns_overrides(conn: sqlite3.Connection) -> list[dict]:
    return rows(conn, "SELECT * FROM dns_overrides ORDER BY created_at DESC")


def normalise_domain(value: Any) -> str | None:
    domain = str(value or "").strip().lower().rstrip(".")
    if not domain or len(domain) > 253 or any(ch in domain for ch in " /\\\t\n\r'\";"):
        return None
    if not all(label and len(label) <= 63 for label in domain.split(".")):
        return None
    return domain


def dns_override_set(conn: sqlite3.Connection, domain: Any, action: Any, note: Any = None) -> dict:
    name = normalise_domain(domain)
    if name is None:
        return {"ok": False, "error": "invalid domain"}
    if action not in ("allow", "deny"):
        return {"ok": False, "error": "action must be allow or deny"}
    write(
        conn,
        "INSERT INTO dns_overrides(domain, action, note, created_at) VALUES(?,?,?,?) "
        "ON CONFLICT(domain) DO UPDATE SET action=excluded.action, note=excluded.note, created_at=excluded.created_at",
        (name, action, (str(note or "")[:200]) or None, now_iso()),
    )
    return {"ok": True, "domain": name, "action": action}


def dns_override_delete(conn: sqlite3.Connection, domain: Any) -> dict:
    name = normalise_domain(domain)
    if name is None:
        return {"ok": False, "error": "invalid domain"}
    write(conn, "DELETE FROM dns_overrides WHERE domain=?", (name,))
    return {"ok": True, "domain": name}


def dns_reputation(conn: sqlite3.Connection, limit: int = 200) -> list[dict]:
    data = rows(
        conn,
        "SELECT domain, source, verdict, malicious, suspicious, checked_at FROM reputation "
        "ORDER BY CASE verdict WHEN 'malicious' THEN 0 WHEN 'suspicious' THEN 1 ELSE 2 END, checked_at DESC LIMIT ?",
        (max(1, min(int(limit), 2000)),),
    )
    return data


# --------------------------------------------------------------------------- telemetry


def _series_key(name: str, tags: Any) -> str:
    """One chart per metric name *and* tag set, so job.duration becomes one series per job."""
    tags = loads(tags, {}) if isinstance(tags, str) else (tags or {})
    if isinstance(tags, dict) and tags:
        return name + " · " + "/".join(str(v) for _, v in sorted(tags.items()))
    return name


def telemetry_metrics(conn: sqlite3.Connection, name: str | None = None, hours: int = 24 * 7) -> dict:
    hours = max(1, min(int(hours), 24 * 90))
    where, params = ["ts>=?"], [cutoff_iso(hours)]
    if name:
        where.append("name=?")
        params.append(name)
    data = rows(
        conn,
        f"SELECT ts, name, value, tags FROM metrics WHERE {' AND '.join(where)} ORDER BY name, ts LIMIT 50000",
        params,
    )
    series: dict[str, list[list]] = {}
    for r in data:
        series.setdefault(_series_key(r["name"], r.get("tags")), []).append([r["ts"], float(r["value"])])
    # The newest measurement of any age, so an empty window can say "none in the last 7 days —
    # the last one was 8 days ago" instead of implying nothing has ever been recorded.
    newest = scalar(conn, "SELECT max(ts) FROM metrics" + (" WHERE name=?" if name else ""),
                    (name,) if name else (), default=None)
    return {"hours": hours, "names": sorted(series), "series": series, "last_ts": newest}


def telemetry_jobs(c: WebContext) -> list[dict]:
    data = rows(c.conn, "SELECT * FROM jobs ORDER BY name")
    if c.scheduler is not None and hasattr(c.scheduler, "status"):
        try:
            live = {str(j.get("name")): j for j in (c.scheduler.status() or []) if isinstance(j, dict)}
        except Exception:  # a scheduler bug must not take the page down
            logger.exception("scheduler.status() failed")
            live = {}
        known = {r["name"] for r in data}
        for r in data:
            r.update({k: v for k, v in live.get(r["name"], {}).items() if v is not None})
        data.extend(dict(v) for k, v in live.items() if k not in known)
    for r in data:
        # Jobs the scheduler knows but has never run have no table row yet; give them the
        # table's columns so templates can treat every job alike.
        for col in JOB_COLUMNS:
            r.setdefault(col, None)
        r["runs"] = int(r.get("runs") or 0)
        r["failures"] = int(r.get("failures") or 0)
        r["last_age_hours"] = age_hours(r.get("last_run"))
    return data


def telemetry_events(conn: sqlite3.Connection, level: str | None = None, limit: int = 100) -> list[dict]:
    where, params = ["1=1"], []
    if level:
        where.append("upper(level)=?")
        params.append(level.upper())
    params.append(max(1, min(int(limit), 2000)))
    data = rows(conn, f"SELECT * FROM events WHERE {' AND '.join(where)} ORDER BY id DESC LIMIT ?", params)
    for r in data:
        r["data"] = loads(r.get("data"), None)
    return data


def scans_list(conn: sqlite3.Connection, limit: int = 200) -> list[dict]:
    data = rows(conn, "SELECT * FROM scans ORDER BY id DESC LIMIT ?", (max(1, min(int(limit), 2000)),))
    for r in data:
        r["summary"] = loads(r.get("summary"), r.get("summary"))
        start, end = parse_ts(r.get("started_at")), parse_ts(r.get("finished_at"))
        r["duration_sec"] = round((end - start).total_seconds(), 1) if start and end else None
    return data


def feeds_list(conn: sqlite3.Connection) -> list[dict]:
    data = rows(
        conn,
        "SELECT name, kind, status, last_checked, last_updated, entries, bytes, enabled, error FROM feeds ORDER BY name",
    )
    for r in data:
        r["enabled"] = _bool(r.get("enabled"))
        r["age_hours"] = age_hours(r.get("last_updated"))
    return data


def last_scans(conn: sqlite3.Connection) -> dict[str, str]:
    data = rows(conn, "SELECT kind, started_at FROM scans WHERE id IN (SELECT max(id) FROM scans GROUP BY kind)")
    return {r["kind"]: r["started_at"] for r in data}




# --------------------------------------------------------------------------- events, in words
#
# The Home page's "Recent activity" used to print Home SOC's own log lines ("hourly rollup
# written", "matched 38 services against KEV, NVD and EPSS: 7 CVEs, 1 KEV", "paired a new device:
# Pixel in the hallway" — which reads as a stranger joining the network). Each event now carries a
# plain sentence beside its raw message; the raw message stays in the row's tooltip and on System
# health. Addresses are replaced by the device's name. A message no rule knows keeps its own words.

_IPV4_IN_TEXT = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def _n(text: str) -> int:
    try:
        return int(str(text).replace(",", ""))
    except ValueError:
        return 0


def _plural(n: int, one: str, many: str | None = None) -> str:
    return one if n == 1 else (many or one + "s")


#: (source prefix, message pattern, sentence builder). First match wins.
_EVENT_RULES: tuple[tuple[str, re.Pattern[str], Any], ...] = (
    ("lens", re.compile(r"^paired a new device:\s*(?P<name>.+)$", re.I),
     lambda m: f"A phone was paired with Lens, the camera app: {m['name']}. This is the app, not a new device on your network."),
    ("scheduler", re.compile(r"^discovery finished.*\((?P<total>[\d,]+) devices?, (?P<online>[\d,]+) online\)", re.I),
     lambda m: f"Home SOC checked your network: {m['online']} of {m['total']} known devices were there."),
    ("scheduler", re.compile(r"^score recorded$", re.I), lambda m: "The safety score was updated."),
    ("dnsfilter", re.compile(r"^hourly rollup written$", re.I), lambda m: "Web blocking saved its hourly summary."),
    ("dnsfilter", re.compile(r"^blocked a known-malicious domain for (?P<who>.+)$", re.I),
     lambda m: f"Web blocking stopped {m['who']} from reaching a known-dangerous website."),
    ("vulns", re.compile(r"^matched (?P<svc>[\d,]+) services? against .*?: (?P<cves>[\d,]+) CVEs?, (?P<kev>[\d,]+) KEV", re.I),
     lambda m: (f"Checked the software on your devices against lists of known flaws: {m['cves']} "
                f"{_plural(_n(m['cves']), 'flaw')} matched, {m['kev']} on the list attackers are known to use.")),
    ("scanners.ports", re.compile(r"^service scan of (?P<n>[\d,]+) hosts? finished", re.I),
     lambda m: f"Checked the open doors (ports) on {m['n']} {_plural(_n(m['n']), 'device')}."),
    ("scanners.ports", re.compile(r"^Telnet is open on (?P<who>.+?):(?P<port>\d+)$", re.I),
     lambda m: f"Found Telnet (an old, unencrypted remote login) open on {m['who']}."),
    ("feeds", re.compile(r"^updated (?P<what>.+)$", re.I),
     lambda m: "Threat lists updated: " + ", ".join(p.split(" (")[0] for p in m["what"].split("), ")) + "."),
    ("feeds", re.compile(r"^kev catalog(?:ue)? is current", re.I),
     lambda m: "The list of flaws attackers are known to use is up to date."),
    ("defender", re.compile(r"^Defender status read:\s*(?P<rest>.+)$", re.I),
     lambda m: f"Checked Windows' antivirus (Defender): {m['rest']}."),
    ("defender", re.compile(r"^quick scan finished, nothing found", re.I),
     lambda m: "The antivirus quick scan finished and found nothing."),
    ("defender", re.compile(r"^quarantined (?P<what>\S+)", re.I),
     lambda m: f"The antivirus quarantined a threat ({m['what']})."),
    ("defender", re.compile(r"^real-time protection is off", re.I),
     lambda m: "The antivirus's real-time protection is off."),
    ("scanners.host", re.compile(r"^posture scan: (?P<fail>[\d,]+) failing checks?, (?P<admin>[\d,]+) need administrator", re.I),
     lambda m: (f"Checked this computer's safety settings: {m['fail']} need fixing, {m['admin']} "
                "could not be checked without administrator rights.")),
    ("scanners.exposure", re.compile(r"^UPnP mapping found: WAN (?P<ext>\d+) -> (?P<who>[^:]+):(?P<port>\d+)", re.I),
     lambda m: f"Your router opened a door to the internet by itself (UPnP) for {m['who']}."),
    ("scanners.exposure", re.compile(r"^InternetDB lookup failed", re.I),
     lambda m: "Home SOC could not check how your network looks from the internet this time."),
    ("scanners.files", re.compile(r"^hashed (?P<n>[\d,]+) files? in Downloads, nothing new", re.I),
     lambda m: f"Checked {m['n']} {_plural(_n(m['n']), 'file')} in Downloads: nothing new to report."),
    ("scanners.files", re.compile(r"^new download flagged by VirusTotal: (?P<hit>\d+)/(?P<of>\d+)", re.I),
     lambda m: f"A new download was flagged as dangerous by {m['hit']} of {m['of']} virus scanners."),
    ("scanners.discovery", re.compile(r"^new device on the network: (?P<who>.+)$", re.I),
     lambda m: f"A device Home SOC had not seen before joined your network: {m['who']}."),
    ("housekeeping", re.compile(r"^purged ", re.I), lambda m: "Home SOC tidied away old records."),
    ("notify", re.compile(r"^digest sent to (?P<n>\d+) channel", re.I), lambda m: "The daily summary was sent."),
    ("findings", re.compile(r"^(?P<n>[\d,]+) findings? auto-resolved after a rescan", re.I),
     lambda m: f"A later check confirmed {m['n']} {_plural(_n(m['n']), 'problem')} fixed."),
    ("findings", re.compile(r"^(?P<cve>CVE-\d{4}-\d+) matched the (?P<what>.+?) and is in the CISA KEV", re.I),
     lambda m: f"A known software flaw on the {m['what']} is on the list attackers are known to use ({m['cve']})."),
)


def plain_events(conn: sqlite3.Connection, events: list[dict]) -> list[dict]:
    """Add ``plain`` (a sentence for the Home page) to each event; ``message`` is left as it was.

    Addresses inside a message are replaced by the device's name ("Ellie's iPhone (192.168.1.32)").
    """
    ips = sorted({ip for e in events for ip in _IPV4_IN_TEXT.findall(str(e.get("message") or ""))})
    try:
        names = device_labels_by_ip(conn, ips) if ips else {}
    except sqlite3.Error:
        names = {}

    def named(text: str) -> str:
        def swap(m: re.Match[str]) -> str:
            hit = names.get(m.group(0))
            label = hit.get("device_label") if hit else None
            return f"{label} ({m.group(0)})" if label and label != m.group(0) else m.group(0)
        return _IPV4_IN_TEXT.sub(swap, text)

    for e in events:
        source = str(e.get("source") or "").lower()
        message = str(e.get("message") or "")
        plain = None
        for prefix, pattern, build in _EVENT_RULES:
            if not source.startswith(prefix):
                continue
            m = pattern.search(message)
            if m:
                try:
                    plain = build(m)
                except (KeyError, IndexError, ValueError):
                    plain = None
                break
        e["plain"] = named(plain or message)
    return events


def collapse_repeats(events: list[dict]) -> list[dict]:
    """Fold a run of back-to-back events with the same sentence into one row carrying
    ``repeats`` (the Home page showed "A phone was paired…" three times in a row)."""
    out: list[dict] = []
    for e in events:
        if out and out[-1].get("plain") == e.get("plain") and out[-1].get("level") == e.get("level"):
            out[-1]["repeats"] = int(out[-1].get("repeats") or 1) + 1
            continue
        out.append(e)
    return out


# --------------------------------------------------------------------------- summary


def summary(c: WebContext) -> dict:
    conn = c.conn
    score = security_score(conn)
    dns = dns_summary(c)
    counts = finding_counts(conn)
    stale = staleness(conn, c.cfg)
    status = status_summary(conn, c.cfg, counts=counts, stale=stale,
                            dns={"enabled": dns.get("enabled"), "running": dns.get("running")})
    return {
        # Plain-language layer (additive): one sentence about the whole network, the banner tone,
        # where it links, whether the picture is current, and the score's band word.
        "status_line": status["status_line"],
        "status_tone": status["status_tone"],
        "status_link": status["status_link"],
        "unfinished_checks": status["unfinished"],
        "overdue_checks": status["overdue"],
        "overdue_feeds": overdue_feeds(conn, c.cfg),
        "staleness": stale,
        "score_word": score_word(score),
        "dns_note": dns_note(dns),
        "generated_at": now_iso(),
        "name": str(cfg_get(c.cfg, "general.name", "Home SOC")),
        "refresh_seconds": int(cfg_get(c.cfg, "web.refresh_seconds", 15) or 15),
        "score": score,
        "grade": grade(score),
        "trend": score_trend(conn),
        "score_breakdown": score_breakdown(conn),
        "counts": counts,
        "devices": device_counts(conn),
        "dns": {k: dns[k] for k in ("total24h", "blocked24h", "clients24h", "running", "blocked_pct", "enabled")},
        "jobs": telemetry_jobs(c),
        "feeds": feeds_list(conn),
        "last_scans": last_scans(conn),
        "events": collapse_repeats(plain_events(conn, telemetry_events(conn, limit=20))),
        "scheduler": c.scheduler is not None,
    }


def dns_note(dns: dict) -> str | None:
    """The sentence the overview shows when web blocking is switched on but not working."""
    if dns.get("enabled") and not dns.get("running"):
        return "Web blocking is switched on but not running, so nothing is being filtered right now."
    return None


# --------------------------------------------------------------------------- scans

_running_lock = threading.Lock()
_running: set[str] = set()

# Fallback steps when no scheduler is wired in: (scan kind, module, callable, kwargs).
_HOST_MODULE = "homesoc.scanners.host_windows" if platform.system() == "Windows" else "homesoc.scanners.host_posix"
SCAN_STEPS: dict[str, list[tuple[str, str, str, dict]]] = {
    "quick": [("discovery", "homesoc.scanners.discovery", "run", {}), ("services", "homesoc.scanners.ports", "run", {"quick": True})],
    "full": [
        ("discovery", "homesoc.scanners.discovery", "run", {}),
        ("services", "homesoc.scanners.ports", "run", {}),
        ("vulns", "homesoc.vulns.matcher", "match_services", {}),
    ],
    "host": [("host", _HOST_MODULE, "run", {})],
    "exposure": [("exposure", "homesoc.scanners.exposure", "run", {})],
    "feeds": [("feeds", "homesoc.feeds.updater", "update", {})],
    "files": [("files", "homesoc.scanners.files", "run", {})],
}
# Scheduler job names per kind. cli.build_jobs registers manual-only "quick" and "full" jobs
# (discovery + quick services + vulns + wifi, and every step) so one run_now covers the whole scan.
SCAN_JOBS: dict[str, list[str]] = {
    "quick": ["quick"],
    "full": ["full"],
    "host": ["host"],
    "exposure": ["exposure"],
    "feeds": ["feeds"],
    "files": ["files"],
}


def _apply_findings(conn: sqlite3.Connection, result: Any, source: str) -> None:
    drafts = getattr(result, "findings", None)
    if not drafts:
        return
    try:
        engine = importlib.import_module("homesoc.findings.engine")
        engine.apply(conn, drafts, source)
    except Exception:
        logger.exception("findings.apply failed for %s", source)


def _run_steps(c: WebContext, kind: str) -> None:
    """Background fallback runner: records a scans row per step (SPEC-GAP: scans is core's
    table, but without a scheduler nobody else would) and applies findings if possible."""
    conn = c.conn
    try:
        for scan_kind, module_name, func_name, kwargs in SCAN_STEPS.get(kind, []):
            started = now_iso()
            row_id = write(conn, "INSERT INTO scans(kind, started_at, status) VALUES(?,?,?)", (scan_kind, started, "running"))
            status, error, summary_json = "ok", None, None
            try:
                mod = importlib.import_module(module_name)
                result = getattr(mod, func_name)(c.cfg, conn, **kwargs)
                _apply_findings(conn, result, scan_kind)
                err = getattr(result, "error", None)
                if err:
                    status, error = "error", str(err)[:500]
                summ = getattr(result, "summary", result if isinstance(result, dict) else None)
                summary_json = json.dumps(summ, default=str)[:4000] if summ is not None else None
            except Exception as exc:
                logger.exception("scan step %s failed", scan_kind)
                status, error = "error", str(exc)[:500]
            write(
                conn,
                "UPDATE scans SET finished_at=?, status=?, summary=?, error=? WHERE id=?",
                (now_iso(), status, summary_json, error, row_id),
            )
    finally:
        with _running_lock:
            _running.discard(kind)


def trigger_scan(c: WebContext, kind: str) -> dict:
    if kind not in SCAN_KINDS:
        return {"ok": False, "error": "kind must be one of " + ", ".join(SCAN_KINDS)}
    if c.scheduler is not None and hasattr(c.scheduler, "run_now"):
        started = [job for job in SCAN_JOBS[kind] if _safe_run_now(c.scheduler, job)]
        return {"ok": bool(started), "kind": kind, "mode": "scheduler", "jobs": started}
    with _running_lock:
        if kind in _running:
            return {"ok": False, "kind": kind, "error": "already running"}
        _running.add(kind)
    threading.Thread(target=_run_steps, args=(c, kind), name=f"homesoc-scan-{kind}", daemon=True).start()
    return {"ok": True, "kind": kind, "mode": "thread", "jobs": [s[0] for s in SCAN_STEPS[kind]]}


def _safe_run_now(scheduler: Any, job: str) -> bool:
    try:
        return bool(scheduler.run_now(job))
    except Exception:
        logger.exception("scheduler.run_now(%s) failed", job)
        return False


def _run_device_scan(c: WebContext, device_id: int) -> None:
    """Thread fallback when no scheduler is wired in (``serve``-less test setups)."""
    key = f"device:{device_id}"
    try:
        mod = importlib.import_module("homesoc.scanners.ports")
        # SPEC-GAP: the scanner interface has no per-device entry point; ports.scan_device is it.
        func = getattr(mod, "scan_device", None)
        if func is None:
            logger.warning("ports.scan_device unavailable; device %s not scanned", device_id)
            return
        result = func(c.cfg, c.conn, device_id)
        _apply_findings(c.conn, result, "services")
    except Exception:
        logger.exception("device scan %s failed", device_id)
    finally:
        with _running_lock:
            _running.discard(key)


def trigger_device_scan(c: WebContext, device_id: int) -> dict:
    if one(c.conn, "SELECT id FROM devices WHERE id=?", (device_id,)) is None:
        return {"ok": False, "error": "no such device"}
    # Preferred path: queue the id for the scheduler's manual-only ``device_scan`` job so it is
    # serialised with the scheduled service scan and can never race it in the services table.
    if c.scheduler is not None and hasattr(c.scheduler, "run_now") and "device_scan" in getattr(c.scheduler, "jobs", {}):
        try:
            cli = importlib.import_module("homesoc.cli")
            cli.queue_device_scan(device_id)
        except Exception:
            logger.exception("could not queue device scan %s", device_id)
            return {"ok": False, "error": "could not queue the scan"}
        _safe_run_now(c.scheduler, "device_scan")  # False = already queued/running; the id is in the queue anyway
        return {"ok": True, "device_id": device_id, "mode": "scheduler"}
    key = f"device:{device_id}"
    with _running_lock:
        if key in _running:
            return {"ok": False, "error": "already running"}
        _running.add(key)
    threading.Thread(target=_run_device_scan, args=(c, device_id), name=f"homesoc-{key}", daemon=True).start()
    return {"ok": True, "device_id": device_id, "mode": "thread"}


# --------------------------------------------------------------------------- settings


def _unknown_blocklists(value: Any) -> list[str]:
    """dns.lists entries that are not feed names from the registry (paths, "..", UNC shares...)."""
    from homesoc.dnsfilter.policy import valid_list_name

    names = json.loads(_encode_setting("list", value))
    return [str(n)[:64] for n in names if not valid_list_name(str(n))]


def _encode_setting(kind: str, value: Any) -> str:
    """Overrides are stored as strings (db.set_setting). SPEC-GAP: encoding is not specified;
    bools as true/false, lists as a JSON array, everything else str()."""
    if kind == "bool":
        return "true" if _bool(value) else "false"
    if kind == "list":
        if isinstance(value, str):
            value = [v.strip() for v in value.replace("\n", ",").split(",") if v.strip()]
        return json.dumps([str(v) for v in (value or [])])
    if kind == "int":
        return str(int(value))
    if kind == "float":
        return str(float(value))
    return str(value if value is not None else "")


def _display_value(kind: str, value: Any) -> Any:
    if kind == "list":
        parsed = loads(value, None) if isinstance(value, str) and value.startswith("[") else value
        if isinstance(parsed, (list, tuple)):
            return ", ".join(str(v) for v in parsed)
        return str(parsed or "")
    if kind == "bool":
        return _bool(value)
    return "" if value is None else value


#: Overrides that matter most when they silently beat config.toml: a credential, where the
#: dashboard listens, and where the whole house's DNS goes.
SHADOW_WARN_KEYS: frozenset[str] = frozenset({
    "web.token", "web.host", "web.port", "notify.ntfy_url", "notify.discord_webhook", "notify.webhook_url",
    "vulns.nvd_api_key", "dns.virustotal_api_key", "dns.urlhaus_auth_key", "dns.upstreams", "dns.doh_upstream",
    "dns.listen", "dns.enabled",
})


def _config_file_values() -> dict[str, Any]:
    """Dotted key -> value as written in config.toml (not merged with anything), or {}."""
    try:
        import tomllib

        from homesoc import paths

        with open(paths.config_path(), "rb") as handle:
            data = tomllib.load(handle)
    except (ImportError, OSError, ValueError):
        return {}
    out: dict[str, Any] = {}
    for section, values in (data or {}).items():
        if isinstance(values, dict):
            for name, value in values.items():
                out[f"{section}.{name}"] = value
    return out


def _same_setting(kind: str, stored: str, file_value: Any) -> bool:
    try:
        return _encode_setting(kind, file_value) == stored
    except (TypeError, ValueError):
        return False


def shadowed_overrides(conn: sqlite3.Connection, keys: Any = None) -> list[str]:
    """Editable keys whose Settings-page override differs from what config.toml says.

    The override wins (config.load merges the settings table last), so an owner who rotates a
    leaked token or webhook in config.toml, as every doc tells them to, otherwise changes nothing.
    """
    kinds = dict(EDITABLE_SETTINGS)
    wanted = [k for k in (keys if keys is not None else kinds) if k in kinds]
    if not wanted:
        return []
    placeholders = ",".join("?" for _ in wanted)
    overrides = {str(r["key"]): str(r["value"])
                 for r in rows(conn, f"SELECT key, value FROM settings WHERE key IN ({placeholders})", wanted)}
    if not overrides:
        return []  # the common case: nothing to compare, so config.toml is not even opened
    file_values = _config_file_values()
    return [key for key in wanted
            if key in overrides and key in file_values
            and not _same_setting(kinds[key], overrides[key], file_values[key])]


def warn_shadowed_overrides(conn: sqlite3.Connection) -> list[str]:
    """At startup: say loudly when a sensitive Settings-page override is hiding config.toml."""
    try:
        keys = shadowed_overrides(conn, [k for k, _ in EDITABLE_SETTINGS if k in SHADOW_WARN_KEYS])
    except sqlite3.Error:  # pragma: no cover - a pre-settings database
        return []
    if keys:
        message = ("Settings-page values are overriding config.toml for " + ", ".join(keys) + ". Changing them "
                   "in config.toml has no effect until the override is cleared on the Settings page.")
        logger.warning(message)
        try:
            _record_event(conn, "warning", "web", message, {"keys": keys})
        except sqlite3.Error:  # pragma: no cover
            pass
    return keys


def settings_get(c: WebContext) -> list[dict]:
    out = []
    shadowed = set(shadowed_overrides(c.conn))
    for key, kind in EDITABLE_SETTINGS:
        override = get_setting(c.conn, key)
        raw = override if override is not None else cfg_get(c.cfg, key, "")
        item = {"key": key, "section": key.split(".")[0], "type": kind, "source": "override" if override is not None else "config"}
        # Secrets too: which file a secret comes from is not itself secret, and it is exactly
        # what the owner needs to know to rotate one that leaked.
        item["clearable"] = override is not None
        item["shadows_config"] = key in shadowed
        if kind == "secret":
            item["value"] = ""
            item["set"] = bool(raw)
        else:
            item["value"] = _display_value(kind, raw)
        out.append(item)
    return out


def settings_clear(c: WebContext, keys: Any) -> dict:
    """Drop Settings-page overrides so config.toml (or the default) applies again after a restart.

    Clearing ``web.token`` also signs out every browser: its sessions were opened with the token
    that is going away.
    """
    allowed = dict(EDITABLE_SETTINGS)
    wanted = [keys] if isinstance(keys, str) else list(keys or [])
    cleared, errors = [], {}
    for key in (str(k) for k in wanted):
        if key not in allowed:
            errors[key] = "not editable"
            continue
        if get_setting(c.conn, key) is None:
            continue
        write(c.conn, "DELETE FROM settings WHERE key=?", (key,))
        cleared.append(key)
        logger.info("config override %s cleared from the dashboard", key)
    if "web.token" in cleared:
        sessions_revoke_all(c.conn)
    return {"ok": not errors, "cleared": cleared, "errors": errors, "restart_required": bool(cleared)}


def settings_post(c: WebContext, payload: dict) -> dict:
    allowed = dict(EDITABLE_SETTINGS)
    saved, errors = [], {}
    for key, value in (payload or {}).items():
        kind = allowed.get(str(key))
        if kind is None:
            errors[str(key)] = "not editable"
            continue
        if kind == "secret" and not value:
            continue  # blank secret field means "keep what is there"
        if key == "dns.lists":
            bad = _unknown_blocklists(value)
            if bad:
                errors[str(key)] = "not a blocklist feed: " + ", ".join(bad[:5])
                continue
        try:
            set_setting(c.conn, str(key), _encode_setting(kind, value))
            saved.append(str(key))
        except (TypeError, ValueError):
            errors[str(key)] = f"expected {kind}"
    return {"ok": not errors, "saved": saved, "errors": errors, "restart_required": bool(saved)}


def notify_test(c: WebContext) -> dict:
    try:
        channels = importlib.import_module("homesoc.notify.channels")
    except ImportError:
        return {"ok": False, "error": "notify package unavailable"}
    try:
        result = channels.test_channels(c.cfg, c.conn)
    except Exception as exc:
        logger.exception("test_channels failed")
        return {"ok": False, "error": str(exc)[:200]}
    return {"ok": True, "channels": result}


def export_data(c: WebContext, full: bool = False) -> dict:
    conn = c.conn
    data = {
        "generated_at": now_iso(),
        "version": "0.1.0",
        "findings": findings_list(conn, limit=5000),
        "devices": devices_list(conn),
        "vulns": vulns_list(conn, limit=5000),
    }
    if full:
        # Support bundle: everything useful for a bug report, minus secrets.
        data.update(
            {
                "platform": {"system": platform.system(), "release": platform.release(), "python": platform.python_version()},
                "settings": [s for s in settings_get(c)],
                "jobs": telemetry_jobs(c),
                "feeds": feeds_list(conn),
                "scans": scans_list(conn, 100),
                "events": telemetry_events(conn, limit=300),
                "host": host_data(conn),
                "dns": dns_summary(c),
            }
        )
    return data


# --------------------------------------------------------------------------- map (SPEC addendum C)
#
# Dependencies and blast radius. The engine itself lives in ``homesoc.topology`` (C3/C4), a
# package this one does not own, so every call into it is resolved lazily: an install without it
# serves the rest of the API unchanged and the map routes answer 503 with a sentence that says why.
#
# The defining constraint of the whole feature is that Home SOC has **no packet visibility**. LAN
# traffic between two devices never passes through it, so it cannot know that the laptop is talking
# to the NAS. Two rules follow, and they are enforced here rather than left to the UI:
#
#   * ``note`` rides in every map payload. It is part of the data, not decoration, so a script
#     polling /api/map inherits the caveat along with the numbers.
#   * every edge keeps its own ``confidence`` and ``evidence``. This layer never flattens them
#     away for convenience — a client must be able to tell what was seen from what was worked out,
#     and an edge claiming to be ``observed`` with nothing behind it is downgraded, never rendered
#     as though Home SOC had watched it happen.

#: The honest sentence, carried by /api/map, /api/map/blast, /api/map/criticality,
#: /api/map/outages and the Lens ``blast`` section. Wording from SPEC addendum C7.
MAP_NOTE = (
    "Home SOC cannot see traffic between devices — it has no packet visibility. "
    "These links are what it has observed or can reasonably infer."
)

#: The three confidence levels of C2, in descending strength. An edge that arrives with anything
#: else is dropped rather than drawn with a style the legend does not explain.
MAP_CONFIDENCES: tuple[str, ...] = ("observed", "inferred", "assumed")
#: ``blast_radius`` may additionally report "mixed" when it used both kinds of evidence.
BLAST_CONFIDENCES: tuple[str, ...] = MAP_CONFIDENCES + ("mixed",)
MAP_NODE_KINDS: tuple[str, ...] = ("device", "internet", "resolver", "cloud", "provider")

DEFAULT_MAP_HOURS = 168
MAX_MAP_HOURS = 24 * 365
#: Lens fetches its ``blast`` section on every identification, so the strings are capped.
BLAST_TEXT_LIMIT = 400

# The legend is the user's key for reading the picture, so it describes the evidence that
# *ships*, not the evidence the design contemplated. It used to promise UPnP port mappings, SSDP
# advertisements and DHCP-assigned resolvers: there is no UPnP source in EDGE_SOURCES at all,
# infer.mdns_types reads the "mdns" key and discards "ssdp", and dns_edges' own docstring
# explains that the DHCP half of C2.3 is deliberately not emitted because Home SOC cannot read
# DHCP options. Those three belong in docs/TOPOLOGY.md's "what would make this better", and are
# now there.
_MAP_LEGEND_CONFIDENCE: tuple[dict[str, str], ...] = (
    {
        "key": "observed",
        "label": "Observed",
        "style": "solid",
        "line": "Home SOC saw this happen: a DNS query that arrived from this device at its own "
                "resolver, a service the device advertised over mDNS, or devices that went offline "
                "in the same discovery cycle.",
    },
    {
        "key": "inferred",
        "label": "Inferred",
        "style": "dashed",
        "line": "Not seen, but it follows from the shape of the network: every device on this "
                "subnet reaches the internet through the default gateway.",
    },
    {
        "key": "assumed",
        "label": "Assumed",
        "style": "dotted",
        "line": "A reasonable default that has not been confirmed, such as a device being reachable "
                "through the gateway when Home SOC has no route data at all.",
    },
)

#: kind -> (label, one line). Keyed on MAP_NODE_KINDS so the legend cannot drift from the
#: vocabulary C4 defines: every node kind the graph can contain is explained here.
_MAP_KIND_LINES: dict[str, tuple[str, str]] = {
    "device": ("Device", "Something Home SOC has found on the local network."),
    "internet": ("Internet", "Everything beyond the gateway, as one node."),
    "resolver": ("Resolver", "Whatever answers name lookups for the network."),
    "cloud": ("External service", "A domain devices here look up, grouped by its vendor when one is recognisable."),
    "provider": (
        "Service provider",
        "A device offering a service (printing, AirPlay, file sharing). Without evidence of "
        "who uses it, it has no confirmed consumers and therefore no consumer edges.",
    ),
}


class TopologyUnavailable(RuntimeError):
    """The topology engine is missing or does not provide what the map needs."""


TOPOLOGY_MISSING = (
    "The dependency map is not available on this install: the homesoc.topology package is missing."
)
TOPOLOGY_MODULES: tuple[str, ...] = ("homesoc.topology", "homesoc.topology.graph", "homesoc.topology.outages")


def _topology_fn(*names: str) -> Any:
    """First callable named ``names`` anywhere in the topology package.

    Resolved per call, not at import: T1 owns that package and the dashboard must start, serve and
    be testable without it. Both spellings are tried across ``homesoc.topology`` and its two
    modules, so a re-export in ``__init__`` and a bare module function both work.
    """
    present = False
    for module_name in TOPOLOGY_MODULES:
        try:
            module = importlib.import_module(module_name)
        except ImportError:
            continue
        except Exception:  # a broken engine must not take the dashboard with it
            logger.exception("could not import %s", module_name)
            continue
        present = True
        for name in names:
            fn = getattr(module, name, None)
            if callable(fn):
                return fn
    if not present:
        raise TopologyUnavailable(TOPOLOGY_MISSING)
    raise TopologyUnavailable(f"the topology package does not provide {names[0]}()")


def topology_available() -> bool:
    try:
        _topology_fn("build_graph")
    except TopologyUnavailable:
        return False
    return True


def map_legend() -> dict[str, list[dict[str, str]]]:
    """A fresh copy, so a caller mutating the payload cannot edit the module's constants."""
    return {
        "confidence": [dict(item) for item in _MAP_LEGEND_CONFIDENCE],
        "kinds": [
            {"key": kind, "label": _MAP_KIND_LINES[kind][0], "line": _MAP_KIND_LINES[kind][1]}
            for kind in MAP_NODE_KINDS
        ],
    }


def _field(obj: Any, name: str, default: Any = None) -> Any:
    """Read ``name`` off a dataclass, a namespace or a dict — the engine's Node/Edge are frozen
    dataclasses (C4), but a stub or a future JSON cache is a plain dict."""
    if isinstance(obj, dict):
        value = obj.get(name, default)
    else:
        value = getattr(obj, name, default)
    return default if value is None else value


def _int_or_none(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _text(value: Any, limit: int = 400) -> str:
    return str(value if value is not None else "").strip()[:limit]


def map_node(raw: Any) -> dict | None:
    """One Node (C4) as JSON, or ``None`` when it has no id to hang edges off."""
    node_id = _text(_field(raw, "id", ""), 200)
    if not node_id:
        return None
    kind = _text(_field(raw, "kind", "device"), 40).lower() or "device"
    severity = _text(_field(raw, "severity", ""), 20).lower()
    return {
        "id": node_id,
        "kind": kind,
        "label": _text(_field(raw, "label", ""), 200) or node_id,
        "sublabel": _text(_field(raw, "sublabel", ""), 200) or None,
        "device_id": _int_or_none(_field(raw, "device_id")),
        "criticality": max(0, _int_or_none(_field(raw, "criticality", 0)) or 0),
        "severity": severity if severity in SEVERITIES else None,
        "online": _bool(_field(raw, "online", False)),
    }


def map_edge(raw: Any) -> tuple[dict | None, str | None]:
    """One Edge (C4) as JSON, plus why it was changed or dropped.

    Returns ``(edge, reason)``: ``reason`` is ``None`` when the edge came through untouched,
    ``"dropped"`` when it is not renderable at all, and ``"downgraded"`` when it claimed to be
    ``observed`` with neither an evidence line nor a single observation behind it. That last case
    is the one this feature exists to get right: an edge nobody can justify must not be drawn as
    something Home SOC watched happen, so it is shown as an inference and says so.
    """
    src = _text(_field(raw, "src", ""), 200)
    dst = _text(_field(raw, "dst", ""), 200)
    if not src or not dst:
        return None, "dropped"
    confidence = _text(_field(raw, "confidence", ""), 20).lower()
    if confidence not in MAP_CONFIDENCES:
        # A style the legend cannot explain is worse than a missing edge.
        logger.warning("dropping topology edge %s->%s with confidence %r", src, dst, confidence)
        return None, "dropped"
    evidence = _text(_field(raw, "evidence", ""), 500)
    observed_count = max(0, _int_or_none(_field(raw, "observed_count", 0)) or 0)
    reason = None
    if confidence == "observed" and not evidence and observed_count <= 0:
        logger.warning("topology edge %s->%s claims 'observed' with no evidence; downgrading", src, dst)
        confidence = "inferred"
        evidence = "Reported as observed with nothing recorded behind it, so it is shown as an inference."
        reason = "downgraded"
    return (
        {
            "src": src,
            "dst": dst,
            "edge_type": _text(_field(raw, "edge_type", ""), 40) or "depends",
            "protocol": _text(_field(raw, "protocol", ""), 40) or None,
            "confidence": confidence,
            "evidence": evidence,
            "observed_count": observed_count,
        },
        reason,
    )


def _split_graph(result: Any) -> tuple[list, list]:
    """``build_graph`` returns ``(nodes, edges)`` (C4); a dict is accepted too."""
    if isinstance(result, dict):
        return list(result.get("nodes") or []), list(result.get("edges") or [])
    if isinstance(result, (tuple, list)) and len(result) == 2:
        return list(result[0] or []), list(result[1] or [])
    raise TopologyUnavailable("build_graph did not return (nodes, edges)")


_MAP_SLOW: dict[tuple, tuple[float, dict, Any]] = {}
_MAP_SLOW_LOCK = threading.Lock()


def map_graph(conn: sqlite3.Connection, *, hours: int = DEFAULT_MAP_HOURS, include_cloud: bool = True,
              engine_out: list | None = None) -> dict:
    """The dependency graph, reusing a recent build when building it was slow.

    The overview page, /map, /api/map and every Lens card build the graph from a week of
    ``dns_queries`` under the shared connection lock. Same rule as :func:`throttled`: a build that
    took SLOW_QUERY_SECONDS or more is reused for ten times its cost (15 s to 5 min); fast builds
    are never cached. Callers get a shallow copy, so the keys they add stay their own.
    """
    key = (id(conn), max(1, min(int(hours or DEFAULT_MAP_HOURS), MAX_MAP_HOURS)), bool(include_cloud))
    now = time.monotonic()
    with _MAP_SLOW_LOCK:
        hit = _MAP_SLOW.get(key)
    if hit is not None and hit[0] > now:
        if engine_out is not None:
            engine_out.append(hit[2])
        return dict(hit[1])
    built: list = []
    started = time.monotonic()
    payload = _map_graph_build(conn, hours=hours, include_cloud=include_cloud, engine_out=built)
    took = time.monotonic() - started
    engine = built[0] if built else None
    if engine_out is not None and built:
        engine_out.append(engine)
    with _MAP_SLOW_LOCK:
        if took >= SLOW_QUERY_SECONDS:
            if len(_MAP_SLOW) >= 32:
                _MAP_SLOW.clear()
            _MAP_SLOW[key] = (time.monotonic() + min(SLOW_QUERY_MAX_TTL, max(SLOW_QUERY_MIN_TTL, took * 10)), dict(payload), engine)
            logger.info("dependency graph took %.2fs; reusing it for a while", took)
        else:
            _MAP_SLOW.pop(key, None)
    return payload


def _map_graph_build(conn: sqlite3.Connection, *, hours: int = DEFAULT_MAP_HOURS, include_cloud: bool = True,
                     engine_out: list | None = None) -> dict:
    """The ``{nodes, edges, legend, generated_at, note}`` payload of C7.

    Node and edge order is the engine's, untouched: C9 requires the same data to produce the same
    picture, and re-sorting here would hide a non-deterministic engine rather than expose it.

    ``engine_out``, when a list is passed, receives the engine's own ``(nodes, edges)`` so the
    caller can hand it straight back to :func:`map_criticality` and :func:`map_blast` instead of
    paying for a second and third ``build_graph``. It is the raw objects rather than the
    normalised payload on purpose: the engine is the only thing that can consume them, and the
    payload above is the shape this layer promises everyone else.
    """
    build = _topology_fn("build_graph")
    hours = max(1, min(int(hours or DEFAULT_MAP_HOURS), MAX_MAP_HOURS))
    include_cloud = bool(include_cloud)
    try:
        result = build(conn, hours=hours, include_cloud=include_cloud)
    except TypeError:  # an engine that takes only the connection
        logger.debug("build_graph rejected hours/include_cloud; calling it bare", exc_info=True)
        result = build(conn)
    if engine_out is not None:
        engine_out.append(result)

    nodes_raw, edges_raw = _split_graph(result)
    nodes = [n for n in (map_node(raw) for raw in nodes_raw) if n is not None]
    known = {n["id"] for n in nodes}

    edges: list[dict] = []
    dropped = downgraded = 0
    for raw in edges_raw:
        edge, reason = map_edge(raw)
        if edge is None:
            dropped += 1
            continue
        if edge["src"] not in known or edge["dst"] not in known:
            # An edge to a node that is not in the payload cannot be drawn and cannot be checked.
            logger.warning("dropping topology edge %s->%s: endpoint missing from the node list", edge["src"], edge["dst"])
            dropped += 1
            continue
        if reason == "downgraded":
            downgraded += 1
        edges.append(edge)

    by_confidence = {level: 0 for level in MAP_CONFIDENCES}
    incoming: dict[str, int] = {}
    outgoing: dict[str, int] = {}
    for edge in edges:
        by_confidence[edge["confidence"]] += 1
        outgoing[edge["src"]] = outgoing.get(edge["src"], 0) + 1
        incoming[edge["dst"]] = incoming.get(edge["dst"], 0) + 1
    for node in nodes:
        node["depends_on"] = outgoing.get(node["id"], 0)
        node["depended_on_by"] = incoming.get(node["id"], 0)
    attach_device_labels(conn, nodes)

    return {
        "ok": True,
        "generated_at": now_iso(),
        # C1/C7: the honesty statement is a field of the payload, so every consumer inherits it.
        "note": MAP_NOTE,
        "legend": map_legend(),
        "window_hours": hours,
        "include_cloud": include_cloud,
        "nodes": nodes,
        "edges": edges,
        "counts": {
            "nodes": len(nodes),
            "edges": len(edges),
            "by_confidence": by_confidence,
            "edges_dropped": dropped,
            "edges_downgraded": downgraded,
            # C2 rule 5: a provider nobody was seen using is reported as exactly that.
            "providers_without_consumers": sum(
                1 for n in nodes if n["kind"] == "provider" and n["depended_on_by"] == 0
            ),
        },
    }


def attach_device_labels(conn: sqlite3.Connection, items: list[dict], id_key: str = "device_id",
                         out_key: str = "device_label") -> list[dict]:
    """Set ``out_key`` (and ``device_ip``) on every row whose ``id_key`` names a known device.

    Rows without a device (the internet node, a resolver, a cloud service) get ``None``: the map
    labels those itself, and this field is only ever a device's name.
    """
    known = device_labels_by_id(conn, [r.get(id_key) for r in items])
    for r in items:
        hit = known.get(_int_or_none(r.get(id_key)))  # type: ignore[arg-type]
        r[out_key] = hit["device_label"] if hit else None
        if out_key == "device_label":
            r.setdefault("device_ip", hit["ip"] if hit else None)
    return items


def _blast_members(raw: Any) -> list[dict]:
    """``[{device_id, label, why}]`` from whatever the engine listed."""
    out: list[dict] = []
    for item in raw if isinstance(raw, (list, tuple)) else []:
        device_id = _int_or_none(_field(item, "device_id"))
        label = _text(_field(item, "label", ""), 200)
        if device_id is None and not label:
            continue
        entry = {"device_id": device_id, "label": label or (f"device {device_id}" if device_id else "")}
        why = _text(_field(item, "why", ""), 300)
        if why:
            entry["why"] = why
        out.append(entry)
    return out


def outage_resolution(cfg: Any = None) -> str:
    """C3, the *fallback*: the cadence in force right now, phrased in the present tense.

    Only correct when no particular outage is being described. An outage carries the cadence
    that was actually running when it happened (``outages.cycle_seconds``), and that is what
    every surface reporting one must state — see :func:`recorded_resolution`. Building this
    sentence from today's ``schedule.discovery_minutes`` and stamping it over a recorded outage
    claimed six-times-better resolution than the evidence supported, in the same payload as an
    evidence line that still said "60-minute discovery cycle".
    """
    minutes = _int_or_none(cfg_get(cfg, "schedule.discovery_minutes", 10)) or 10
    return (
        f"Home SOC looks for devices every {minutes} minutes, so 'dropped together' means "
        f"'went offline in the same discovery cycle', not 'within seconds'."
    )


def recorded_resolution(cycle_seconds: Any) -> str | None:
    """The resolution of one recorded outage, from the cadence stored with it.

    Deliberately a local two-line formatter rather than an import of
    ``topology.outages.resolution_note``: this module resolves the topology package lazily and
    per call, and the outage read models here work on a database whose topology package is not
    installed. The wording is kept identical to the engine's on purpose — a reader must not be
    able to tell which of the two produced the sentence in front of them.
    """
    seconds = _int_or_none(cycle_seconds)
    if not seconds or seconds <= 0:
        return None
    minutes = max(1, int(seconds) // 60)
    return (f"Discovery ran every {minutes} minute{'s' if minutes != 1 else ''} at the time, so "
            f"\"dropped together\" means \"went missing in the same {minutes}-minute discovery cycle\", "
            "not \"within seconds\".")


def map_blast(conn: sqlite3.Connection, device_id: int, *, cfg: Any = None, engine_graph: Any = None) -> dict:
    """The ``blast_radius`` shape of C4, normalised and carrying the honesty note.

    Raises :class:`TopologyUnavailable` when the engine is absent; the caller has already checked
    that the device exists, so an empty answer from the engine is reported as an empty blast
    radius rather than a 404.

    ``engine_graph`` is the ``(nodes, edges)`` a caller already built (see ``map_graph``'s
    ``engine_out``). Engines that do not accept it are called the old way — this layer must keep
    working with an engine it did not ship with.
    """
    fn = _topology_fn("blast_radius")
    raw = _call_with_graph(fn, conn, int(device_id), graph=engine_graph)
    if not isinstance(raw, dict):
        raise TopologyUnavailable("blast_radius did not return a mapping")

    offline = attach_device_labels(conn, _blast_members(raw.get("offline")))
    degraded = attach_device_labels(conn, _blast_members(raw.get("degraded")))
    unaffected = attach_device_labels(conn, _blast_members(raw.get("unaffected")))
    confidence = _text(raw.get("confidence"), 20).lower()
    evidence = _text(raw.get("evidence"), 600)
    device = raw.get("device")
    if not isinstance(device, dict):
        device = one(conn, "SELECT id, mac, ip, hostname, nickname, kind, vendor, online FROM devices WHERE id=?", (int(device_id),)) or {}
        device = _device_row(dict(device)) if device else {}
    elif "device_label" not in device:
        device = dict(device)
        device["device_label"] = device_label(device)
    return {
        "ok": True,
        "generated_at": now_iso(),
        "note": MAP_NOTE,
        "device_id": int(device_id),
        "device": device,
        "offline": offline,
        "degraded": degraded,
        "unaffected": unaffected,
        "services_lost": [s for s in (_text(x, 200) for x in (raw.get("services_lost") or [])) if s],
        "headline": _text(raw.get("headline"), 600),
        "confidence": confidence if confidence in BLAST_CONFIDENCES else None,
        # None, not "", when nothing has actually been observed (C4).
        "evidence": evidence or None,
        # The engine's sentence first: it is built from the cadence recorded with the outage,
        # which is the only honest resolution for a specific one (C3). Today's config is the
        # fallback for a radius that rests on no outage at all.
        "cycle_seconds": _int_or_none(raw.get("cycle_seconds")),
        "resolution": (_text(raw.get("resolution"), 400)
                       or (outage_resolution(cfg) if (evidence or confidence in ("observed", "mixed")) else None)),
        "counts": {"offline": len(offline), "degraded": len(degraded), "unaffected": len(unaffected)},
    }


def blast_summary(conn: sqlite3.Connection, device_id: int, *, cfg: Any = None) -> dict | None:
    """The small "if this fails" section Lens puts on the device card (C7).

    Headline, the two counts, the confidence and the evidence line — and the packet-visibility
    note, because the phone is exactly where someone would otherwise read the picture as a live
    traffic diagram. ``None`` (never an exception) when the topology package is not installed, so
    the rest of the overlay still renders.
    """
    device_id = _int_or_none(device_id) or 0
    if not (0 < device_id <= 2**63 - 1):
        return None
    try:
        blast = map_blast(conn, device_id, cfg=cfg)
    except TopologyUnavailable as exc:
        logger.debug("no blast radius for device %s: %s", device_id, exc)
        return None
    except Exception:  # a broken engine must not blank the whole Lens payload
        logger.exception("blast radius failed for device %s", device_id)
        return None
    return {
        "headline": _text(blast.get("headline"), BLAST_TEXT_LIMIT),
        "offline_count": int(blast["counts"]["offline"]),
        "degraded_count": int(blast["counts"]["degraded"]),
        "confidence": blast.get("confidence"),
        "evidence": _text(blast.get("evidence"), BLAST_TEXT_LIMIT) or None,
        "note": MAP_NOTE,
    }


def _call_with_graph(fn: Any, conn: sqlite3.Connection, *args: Any, graph: Any = None, kw: str = "graph") -> Any:
    """Call an engine function with a pre-built graph, falling back if it does not take one.

    The reuse is worth the guard: /, /map and /devices/<id> each rendered the graph and then a
    ranking or a radius that silently rebuilt it, so a house with a week of DNS paid for the
    same expensive ``GROUP BY dns_queries`` two or three times per request — under the shared
    write lock, which stalls the resolver's own writes while it runs.
    """
    if graph is None:
        return fn(conn, *args)
    try:
        return fn(conn, *args, **{kw: graph})
    except TypeError:
        logger.debug("engine function %r does not accept %s; rebuilding", getattr(fn, "__name__", fn), kw)
        return fn(conn, *args)


def map_criticality(conn: sqlite3.Connection, limit: int = 50, *, engine_edges: Any = None) -> list[dict]:
    """``[{device_id, label, dependents, weight, why}]``, most load-bearing first (C4)."""
    fn = _topology_fn("criticality")
    raw = _call_with_graph(fn, conn, graph=engine_edges, kw="edges")
    out: list[dict] = []
    for item in raw if isinstance(raw, (list, tuple)) else []:
        device_id = _int_or_none(_field(item, "device_id"))
        label = _text(_field(item, "label", ""), 200)
        if device_id is None and not label:
            continue
        try:
            weight = round(float(_field(item, "weight", 0) or 0), 4)
        except (TypeError, ValueError):
            weight = 0.0
        out.append(
            {
                "device_id": device_id,
                "label": label or f"device {device_id}",
                "dependents": max(0, _int_or_none(_field(item, "dependents", 0)) or 0),
                "weight": weight,
                "why": _text(_field(item, "why", ""), 300),
            }
        )
    # The engine returns this descending; sorting again keeps the API's order stable whatever it does.
    out.sort(key=lambda r: (-r["weight"], -r["dependents"], str(r["label"]).lower()))
    return attach_device_labels(conn, out[: max(1, min(int(limit or 1), 500))])


def map_outages(conn: sqlite3.Connection, limit: int = 20) -> list[dict]:
    """Recorded outages with their members, newest first (C3/C5).

    Read straight from ``outages``/``outage_members`` like every other read model in this file, so
    it works whether or not the topology package is importable — and answers with an empty list,
    not a 503, on a database where no outage has ever been recorded.
    """
    limit = max(1, min(int(limit or 1), 500))
    recorded = rows(
        conn,
        "SELECT o.id, o.started_at, o.ended_at, o.cycle_seconds, o.trigger_device_id, o.trigger_kind, "
        "o.member_count, COALESCE(d.nickname, d.hostname, d.ip, d.mac) AS trigger_label "
        "FROM outages o LEFT JOIN devices d ON d.id=o.trigger_device_id "
        "ORDER BY o.started_at DESC, o.id DESC LIMIT ?",
        (limit,),
    )
    if not recorded:
        return []
    ids = [int(r["id"]) for r in recorded]
    placeholders = ",".join("?" for _ in ids)
    members: dict[int, list[dict]] = {}
    for m in rows(
        conn,
        "SELECT m.outage_id, m.device_id, m.dropped_at, m.returned_at, "
        "COALESCE(d.nickname, d.hostname, d.ip, d.mac) AS label "
        f"FROM outage_members m LEFT JOIN devices d ON d.id=m.device_id WHERE m.outage_id IN ({placeholders}) "
        "ORDER BY m.outage_id, m.device_id",
        ids,
    ):
        members.setdefault(int(m["outage_id"]), []).append(
            {
                "device_id": _int_or_none(m.get("device_id")),
                "label": _text(m.get("label"), 200) or f"device {m.get('device_id')}",
                "dropped_at": m.get("dropped_at"),
                "returned_at": m.get("returned_at"),
            }
        )
    out = []
    for r in recorded:
        outage_id = int(r["id"])
        listed = members.get(outage_id, [])
        out.append(
            {
                "id": outage_id,
                "started_at": r.get("started_at"),
                "ended_at": r.get("ended_at"),
                "ongoing": not r.get("ended_at"),
                "cycle_seconds": _int_or_none(r.get("cycle_seconds")),
                "trigger_device_id": _int_or_none(r.get("trigger_device_id")),
                "trigger_label": _text(r.get("trigger_label"), 200) or None,
                "trigger_kind": _text(r.get("trigger_kind"), 40) or "unknown",
                "member_count": _int_or_none(r.get("member_count")) or len(listed),
                # Per row, from the cadence recorded with *this* outage. One top-level sentence
                # built from today's config was stamped over a list whose rows each carry their
                # own, so a 60-minute-cadence outage was reported at 10-minute resolution.
                "resolution": recorded_resolution(r.get("cycle_seconds")),
                "members": listed,
            }
        )
    attach_device_labels(conn, out, id_key="trigger_device_id", out_key="trigger_device_label")
    attach_device_labels(conn, [m for outage in out for m in outage["members"]])
    return out


# --------------------------------------------------------------------------- routes


def _int_arg(name: str, default: int, lo: int = 1, hi: int = 100000) -> int:
    try:
        return max(lo, min(int(request.args.get(name, default)), hi))
    except (TypeError, ValueError):
        return default


def _payload() -> dict:
    body = request.get_json(silent=True)
    return body if isinstance(body, dict) else {}


def _status(result: dict, ok_code: int = 200) -> tuple[Response, int]:
    if result.get("ok", True):
        return jsonify(result), ok_code
    code = 404 if "no such" in str(result.get("error", "")) else 400
    return jsonify(result), code


@bp.get("/summary")
def api_summary():
    return jsonify(summary(ctx()))


@bp.get("/findings")
def api_findings():
    return jsonify(
        findings_list(
            ctx().conn,
            status=request.args.get("status") or None,
            severity=request.args.get("severity") or None,
            q=(request.args.get("q") or "").strip()[:200] or None,
            category=request.args.get("category") or None,
            limit=_int_arg("limit", 500, 1, 5000),
        )
    )


@bp.post("/findings/<int:row_id>/status")
def api_finding_status(row_id: int):
    body = _payload()
    status = str(body.get("status", ""))
    if status not in STATUSES:
        return jsonify({"ok": False, "error": "status must be one of " + ", ".join(STATUSES)}), 400
    note = (str(body.get("note") or "")[:500]) or None
    if not set_finding_status(ctx().conn, row_id, status, note):
        return jsonify({"ok": False, "error": "no such finding"}), 404
    return jsonify({"ok": True, "id": row_id, "status": status})


@bp.get("/devices")
def api_devices():
    c = ctx()
    return jsonify(throttled(c, ("devices_list",), lambda: devices_list(c.conn)))


@bp.get("/devices/<int:device_id>")
def api_device(device_id: int):
    d = device_detail(ctx().conn, device_id)
    if d is None:
        return jsonify({"ok": False, "error": "no such device"}), 404
    return jsonify(d)


@bp.post("/devices/<int:device_id>")
def api_device_update(device_id: int):
    if not update_device(ctx().conn, device_id, _payload()):
        return jsonify({"ok": False, "error": "no such device"}), 404
    return jsonify({"ok": True, "id": device_id})


@bp.post("/devices/<int:device_id>/scan")
def api_device_scan(device_id: int):
    return _status(trigger_device_scan(ctx(), device_id), 202)


@bp.get("/vulns")
def api_vulns():
    min_cvss = request.args.get("min_cvss")
    try:
        min_cvss_f = float(min_cvss) if min_cvss else None
    except ValueError:
        min_cvss_f = None
    device = request.args.get("device_id")
    return jsonify(
        vulns_list(
            ctx().conn,
            kev=_bool(request.args.get("kev")),
            q=(request.args.get("q") or "").strip()[:200] or None,
            device_id=int(device) if device and device.isdigit() else None,
            min_cvss=min_cvss_f,
        )
    )


@bp.get("/host")
def api_host():
    return jsonify(host_data(ctx().conn))


@bp.post("/defender/quick-scan")
def api_defender_quick_scan():
    result = defender_action(ctx().cfg, "quick-scan")
    return (jsonify(result), 202) if result["ok"] else (jsonify(result), 503)


@bp.post("/defender/update")
def api_defender_update():
    result = defender_action(ctx().cfg, "update")
    return (jsonify(result), 202) if result["ok"] else (jsonify(result), 503)


@bp.get("/defender/status")
def api_defender_status():
    """Poll target for the two fire-and-forget actions above."""
    return jsonify(defender_status())


@bp.get("/dns/summary")
def api_dns_summary():
    return jsonify(dns_summary(ctx()))


@bp.get("/dns/series")
def api_dns_series():
    c, hours = ctx(), _int_arg("hours", 24, 1, 24 * 14)
    return jsonify(throttled(c, ("dns_series", hours), lambda: dns_series(c.conn, hours)))


@bp.get("/dns/top")
def api_dns_top():
    c = ctx()
    kind = "clients" if request.args.get("kind", "blocked") == "clients" else "blocked"
    hours, limit = _int_arg("hours", 24, 1, 24 * 30), _int_arg("limit", 20, 1, 200)
    return jsonify(throttled(c, ("dns_top", kind, hours, limit), lambda: dns_top(c.conn, kind, hours, limit)))


@bp.get("/dns/log")
def api_dns_log():
    return jsonify(
        dns_log(
            ctx().conn,
            _int_arg("limit", 100, 1, 1000),
            (request.args.get("client") or "").strip()[:64] or None,
            request.args.get("action") or None,
        )
    )


@bp.get("/dns/lists")
def api_dns_lists():
    return jsonify(dns_lists(ctx()))


@bp.post("/dns/override")
def api_dns_override():
    body = _payload()
    return _status(dns_override_set(ctx().conn, body.get("domain"), body.get("action"), body.get("note")))


@bp.delete("/dns/override/<domain>")
def api_dns_override_delete(domain: str):
    return _status(dns_override_delete(ctx().conn, domain))


@bp.get("/dns/overrides")
def api_dns_overrides():
    return jsonify(dns_overrides(ctx().conn))


@bp.get("/dns/reputation")
def api_dns_reputation():
    return jsonify(dns_reputation(ctx().conn, _int_arg("limit", 200, 1, 2000)))


@bp.get("/telemetry/metrics")
def api_telemetry_metrics():
    return jsonify(telemetry_metrics(ctx().conn, (request.args.get("name") or "").strip()[:100] or None, _int_arg("hours", 24 * 7, 1, 24 * 90)))


@bp.get("/telemetry/jobs")
def api_telemetry_jobs():
    return jsonify(telemetry_jobs(ctx()))


@bp.get("/telemetry/events")
def api_telemetry_events():
    return jsonify(telemetry_events(ctx().conn, (request.args.get("level") or "").strip()[:16] or None, _int_arg("limit", 100, 1, 2000)))


@bp.get("/scans")
def api_scans():
    return jsonify(scans_list(ctx().conn, _int_arg("limit", 200, 1, 2000)))


@bp.post("/scan")
def api_scan():
    body = _payload()
    kind = str(body.get("kind") or request.args.get("kind") or "")
    result = trigger_scan(ctx(), kind)
    if not result.get("ok"):
        return jsonify(result), 409 if result.get("error") == "already running" else 400
    return jsonify(result), 202


@bp.get("/settings")
def api_settings_get():
    return jsonify(settings_get(ctx()))


@bp.post("/settings")
def api_settings_post():
    result = settings_post(ctx(), _payload())
    return jsonify(result), (200 if result["ok"] else 400)


@bp.post("/settings/clear")
def api_settings_clear():
    """``{"keys": [...]}``: forget Settings-page overrides so config.toml applies again."""
    result = settings_clear(ctx(), _payload().get("keys"))
    return jsonify(result), (200 if result["ok"] else 400)


@bp.delete("/settings/<key>")
def api_settings_clear_one(key: str):
    result = settings_clear(ctx(), [key])
    return jsonify(result), (200 if result["ok"] else 400)


@bp.post("/notify/test")
def api_notify_test():
    result = notify_test(ctx())
    return jsonify(result), (200 if result["ok"] else 503)


@bp.get("/export")
def api_export():
    full = _bool(request.args.get("full")) or _bool(request.args.get("bundle"))
    body = json.dumps(export_data(ctx(), full), indent=2, default=str)
    name = "homesoc-support-bundle.json" if full else "homesoc-export.json"
    return Response(body, mimetype="application/json", headers={"Content-Disposition": f'attachment; filename="{name}"'})


# --------------------------------------------------------------------------- map routes (C7)
#
# Authorisation: these are dashboard API routes and nothing more. They are NOT under
# ``/api/lens/``, so ``app._auth_and_csrf`` applies the dashboard credential to them exactly as it
# does to /api/summary or /api/devices, and a Lens token buys no access to them at all.
#
# That is deliberate, not an oversight. A Lens token is a long-lived secret carried around on a
# phone, granted by typing an eight-character code, and its whole point is "tell me about the box I
# am standing in front of". The map is the opposite shape: one request returns every device, every
# external service the house talks to and a ranked list of which single boxes take the most of the
# house down — the most useful page in this product for someone casing the network, and the least
# recoverable if a phone is lost. So the phone gets the blast radius of the one device it has
# identified, through ``/api/lens/device/<id>``, bounded and read-only; the map itself stays behind
# the dashboard credential. ``_map_guard`` enforces that even where the dashboard has no token set
# (loopback-only, per ``_dashboard_session``), so presenting a Lens token here can never widen
# access beyond what the same request would get with no token at all.


def _map_guard() -> tuple[Response, int] | None:
    """Refuse a paired phone's token on the map routes; ``None`` when the request may proceed."""
    if request.headers.get("X-Lens-Token") and not _dashboard_session():
        return (
            jsonify(
                {
                    "ok": False,
                    "code": "dashboard_only",
                    "error": "The dependency map is a dashboard view. A paired phone sees the blast "
                             "radius of the device it identified at /api/lens/device/<id>.",
                }
            ),
            403,
        )
    return None


def _map_unavailable(exc: TopologyUnavailable) -> tuple[Response, int]:
    return jsonify({"ok": False, "code": "topology_unavailable", "error": str(exc), "note": MAP_NOTE}), 503


def _map_failed(exc: Exception, what: str) -> tuple[Response, int]:
    """A broken engine is the map being unavailable, not the dashboard being broken.

    Same judgement the rest of this file makes for findings.score and the scheduler: one package
    failing degrades its own panel and nothing else. The traceback goes to the log, never to the
    client.
    """
    logger.exception("topology %s failed", what)
    return (
        jsonify(
            {
                "ok": False,
                "code": "topology_error",
                "error": f"The dependency map could not be built: {type(exc).__name__}. See the Home SOC log.",
                "note": MAP_NOTE,
            }
        ),
        503,
    )


@bp.get("/map")
def api_map():
    """The dependency graph: ``{nodes, edges, legend, generated_at, note}`` (C7)."""
    denial = _map_guard()
    if denial is not None:
        return denial
    c = ctx()
    default_hours = _int_or_none(cfg_get(c.cfg, "topology.window_hours", DEFAULT_MAP_HOURS)) or DEFAULT_MAP_HOURS
    default_cloud = _bool(cfg_get(c.cfg, "topology.include_cloud", True))
    cloud_arg = request.args.get("cloud")
    try:
        graph = map_graph(
            c.conn,
            hours=_int_arg("hours", default_hours, 1, MAX_MAP_HOURS),
            include_cloud=default_cloud if cloud_arg is None else _bool(cloud_arg),
        )
    except TopologyUnavailable as exc:
        return _map_unavailable(exc)
    except Exception as exc:  # noqa: BLE001 - a broken engine must not 500 the dashboard
        return _map_failed(exc, "build_graph")
    return jsonify(graph)


@bp.get("/map/blast/<int:device_id>")
def api_map_blast(device_id: int):
    """What the house loses when this device fails (C4)."""
    denial = _map_guard()
    if denial is not None:
        return denial
    c = ctx()
    # Flask's <int:...> converter happily accepts a 20-digit id and SQLite raises OverflowError
    # rather than simply not matching (the same trap lens_device documents). Out of range is "no
    # such device", not a traceback.
    if not (0 < device_id <= 2**63 - 1) or one(c.conn, "SELECT id FROM devices WHERE id=?", (device_id,)) is None:
        return jsonify({"ok": False, "error": "no such device"}), 404
    try:
        return jsonify(map_blast(c.conn, device_id, cfg=c.cfg))
    except TopologyUnavailable as exc:
        return _map_unavailable(exc)
    except Exception as exc:  # noqa: BLE001
        return _map_failed(exc, "blast_radius")


@bp.get("/map/criticality")
def api_map_criticality():
    """The load-bearing devices, most dependents first (C4)."""
    denial = _map_guard()
    if denial is not None:
        return denial
    try:
        ranked = map_criticality(ctx().conn, _int_arg("limit", 50, 1, 500))
    except TopologyUnavailable as exc:
        return _map_unavailable(exc)
    except Exception as exc:  # noqa: BLE001
        return _map_failed(exc, "criticality")
    return jsonify({"ok": True, "generated_at": now_iso(), "note": MAP_NOTE, "criticality": ranked})


@bp.get("/map/outages")
def api_map_outages():
    """Outages Home SOC actually recorded, with their members (C3).

    ``resolution`` is not decoration either: co-dropping means "in the same discovery cycle", and
    a consumer of this endpoint must not read the timestamps as second-by-second truth. It sits
    on each *outage*, built from the ``cycle_seconds`` recorded with that one — a single
    top-level sentence from today's ``schedule.discovery_minutes`` claimed one resolution for
    rows that may each have been recorded at a different cadence. ``resolution_now`` is what the
    cadence is today, which is a different question and is labelled as one.
    """
    denial = _map_guard()
    if denial is not None:
        return denial
    c = ctx()
    return jsonify(
        {
            "ok": True,
            "generated_at": now_iso(),
            "note": MAP_NOTE,
            "resolution_now": outage_resolution(c.cfg),
            "outages": map_outages(c.conn, _int_arg("limit", 20, 1, 500)),
        }
    )


# --------------------------------------------------------------------------- lens (SPEC addendum B6/B7)
#
# Lens is the only part of the dashboard meant to be reached from a phone on the LAN, so every
# route here is stricter than the rest of this file: the whole surface disappears (404) when
# ``lens.enabled`` is false, identification is POST so no code or device data can land in a URL or
# an access log, acting requires both the ``act`` scope and ``lens.allow_actions``, and every
# response carries ``Cache-Control: no-store``.

LENS_ACTIONS: tuple[str, ...] = ("rescan", "acknowledge", "set_trusted")
LENS_SCOPE_READ = "read"
LENS_SCOPE_ACT = "act"
_LOOPBACK: frozenset[str] = frozenset({"127.0.0.1", "::1", "localhost"})


def _lens_module() -> Any | None:
    try:
        return importlib.import_module("homesoc.web.lens")
    except ImportError:  # pragma: no cover - lens ships with this package
        logger.warning("homesoc.web.lens is not importable; Lens routes are disabled")
        return None


def lens_enabled(c: WebContext) -> bool:
    return _bool(cfg_get(c.cfg, "lens.enabled", False))


def _record_event(conn: sqlite3.Connection, level: str, source: str, message: str, data: dict | None = None) -> None:
    dbmod = _core_db()
    if dbmod is not None and hasattr(dbmod, "record_event"):
        try:
            dbmod.record_event(conn, level, source, message, data)
            return
        except Exception:
            logger.exception("could not record event %r", message)
    write(  # SPEC-GAP: core db not importable -> the same row, written here
        conn,
        "INSERT INTO events(ts, level, source, message, data) VALUES(?,?,?,?,?)",
        (now_iso(), level.lower(), source, message, json.dumps(data, default=str) if data else None),
    )


def _json_no_store(payload: dict | list, code: int = 200) -> tuple[Response, int]:
    resp = jsonify(payload)
    resp.headers["Cache-Control"] = "no-store"
    return resp, code


def _client_ip() -> str:
    return str(request.remote_addr or "unknown")[:45]


def _is_loopback(addr: str) -> bool:
    return addr in _LOOPBACK or addr.startswith("127.")


def _dashboard_session() -> bool:
    """True when this request is the owner at the desktop rather than a paired phone.

    ``app._auth_and_csrf`` deliberately exempts ``/api/lens/*`` from the dashboard token because
    Lens authenticates itself, so this re-checks the dashboard credential rather than assuming it
    was checked upstream. With no ``web.token`` configured the dashboard has no credential at all,
    and the only requests we are willing to treat as the owner's are the ones from this machine —
    a LAN client must present a Lens token.
    """
    c = ctx()
    if not c.token:
        return _is_loopback(_client_ip())
    presented = request.headers.get("X-Token")
    if presented:
        return check_token_guess(c.conn, c.token, presented, _client_ip())
    return session_check(c.conn, presented_session()) is not None


def lens_principal() -> tuple[dict | None, tuple[Response, int] | None]:
    """``(principal, error_response)`` -- exactly one of the two is ever set."""
    c = ctx()
    if not lens_enabled(c):
        return None, _json_no_store({"ok": False, "error": "not found"}, 404)
    lens = _lens_module()
    if lens is None:
        return None, _json_no_store({"ok": False, "error": "lens is unavailable on this install"}, 503)
    presented = request.headers.get("X-Lens-Token")
    if presented:
        info = lens.verify_token(c.conn, presented, ip=_client_ip())
        if info is None:
            return None, _json_no_store(
                {"ok": False, "code": "unpaired",
                 "error": "This phone is not paired, or its access was revoked. "
                          "Open the dashboard and pair it again."},
                401,
            )
        return {
            "kind": "lens",
            "label": str(info.get("label") or "paired phone"),
            "scopes": list(info.get("scopes") or [LENS_SCOPE_READ]),
            "token_id": info.get("id"),
        }, None
    if _dashboard_session():
        return {"kind": "dashboard", "label": "dashboard",
                "scopes": [LENS_SCOPE_READ, LENS_SCOPE_ACT], "token_id": None}, None
    return None, _json_no_store(
        {"ok": False, "code": "no_token",
         "error": "Lens needs a paired phone. Send the X-Lens-Token header you received when pairing."},
        401,
    )


def lens_can_act(c: WebContext, principal: dict) -> bool:
    return _bool(cfg_get(c.cfg, "lens.allow_actions", False)) and LENS_SCOPE_ACT in (principal.get("scopes") or [])


def _lens_act_denial(c: WebContext, principal: dict) -> tuple[Response, int] | None:
    """The 403 a read-only principal gets for a mutating route, or ``None`` when it may act."""
    if not _bool(cfg_get(c.cfg, "lens.allow_actions", False)):
        return _json_no_store(
            {"ok": False, "code": "actions_disabled",
             "error": "Lens is read-only. Set lens.allow_actions = true in config.toml to allow actions."},
            403,
        )
    if LENS_SCOPE_ACT not in (principal.get("scopes") or []):
        return _json_no_store(
            {"ok": False, "code": "missing_scope", "error": "This phone was paired read-only."}, 403
        )
    return None


def _lens_act_guard() -> tuple[dict | None, tuple[Response, int] | None]:
    principal, error = lens_principal()
    if error is not None:
        return None, error
    denial = _lens_act_denial(ctx(), principal)
    if denial is not None:
        return None, denial
    return principal, None


def lens_actions_for(c: WebContext, principal: dict) -> dict:
    allowed = lens_can_act(c, principal)
    return {"can_rescan": allowed, "can_acknowledge": allowed, "can_set_trusted": allowed}


def lens_payload(c: WebContext, principal: dict, device_id: int, hours: int = 24) -> dict | None:
    lens = _lens_module()
    if lens is None:
        return None
    payload = lens.lens_device(
        c.conn,
        device_id,
        hours=hours,
        dns_enabled=_bool(cfg_get(c.cfg, "dns.enabled", False)),
        actions=lens_actions_for(c, principal),
    )
    return payload or None


@bp.post("/lens/claim")
def api_lens_claim():
    """Exchange a single-use pairing code for a long-lived, scoped token (B4).

    Rate-limited per source IP; a refusal is recorded so a burst of guesses shows up in the feed.
    """
    c = ctx()
    if not lens_enabled(c):
        return _json_no_store({"ok": False, "error": "not found"}, 404)
    lens = _lens_module()
    if lens is None:
        return _json_no_store({"ok": False, "error": "lens is unavailable on this install"}, 503)
    ip = _client_ip()
    allowed, retry_after = lens.claim_allowed(c.conn, ip)  # writes its own events row when it trips
    if not allowed:
        minutes = max(1, int(retry_after or 3600) // 60)
        return _json_no_store(
            {"ok": False, "code": "rate_limited", "retry_after": int(retry_after or 3600),
             "error": f"Too many pairing attempts. Try again in about {minutes} minutes."},
            429,
        )
    body = _payload()
    result = lens.claim(
        c.conn,
        body.get("code"),
        ip=ip,
        label=(str(body.get("label") or "")[:60]) or None,
        ttl_days=int(cfg_get(c.cfg, "lens.token_ttl_days", 90) or 0),
        max_tokens=int(cfg_get(c.cfg, "lens.max_tokens", 10) or 10),
        allow_actions=_bool(cfg_get(c.cfg, "lens.allow_actions", False)),
    )
    if not result.get("ok"):
        _record_event(c.conn, "warning", "lens", "a Lens pairing attempt was refused",
                      {"ip": ip, "reason": result.get("error")})
        return _json_no_store(result, 400)
    lens.claim_reset(c.conn, ip)  # a successful pairing clears that address's attempt counter
    return _json_no_store(
        {"ok": True, "token": result.get("token"), "label": result.get("label"),
         "scopes": result.get("scopes"), "expires_at": result.get("expires_at")}
    )


@bp.post("/lens/identify")
def api_lens_identify():
    """POST, never GET: a decoded code must not end up in a URL, a log or the phone's history."""
    principal, error = lens_principal()
    if error is not None:
        return error
    c = ctx()
    lens = _lens_module()
    body = _payload()
    code = body.get("code")
    hint = body.get("hint") if isinstance(body.get("hint"), dict) else None
    if code is not None and lens.normalise_code(code) is None:
        return _json_no_store({"ok": False, "error": "that code is not something Lens can store"}, 400)
    match = lens.identify(c.conn, code=code, hint=hint)
    out = dict(match.as_dict())
    out["ok"] = True
    out["learnable"] = bool(
        _bool(cfg_get(c.cfg, "lens.tag_learning", True)) and code and match.device_id is None and match.via != "ignored"
    )
    if match.confidence == "exact" and match.device_id is not None:
        out["device"] = lens_payload(c, principal, int(match.device_id), _int_arg("hours", 24, 1, 24 * 30))
    return _json_no_store(out)


@bp.post("/lens/learn")
def api_lens_learn():
    """Bind an unknown code to a device -- the one tap that makes every later scan instant."""
    principal, error = lens_principal()
    if error is not None:
        return error
    c = ctx()
    if not _bool(cfg_get(c.cfg, "lens.tag_learning", True)):
        return _json_no_store(
            {"ok": False, "code": "learning_off",
             "error": "Learning new codes is switched off (lens.tag_learning)."},
            403,
        )
    lens = _lens_module()
    body = _payload()
    raw_device = body.get("device_id")
    device_id: int | None
    if raw_device in (None, "", "null"):
        device_id = None  # "Not a device / ignore this code" (B8)
    else:
        try:
            device_id = int(raw_device)
        except (TypeError, ValueError):
            return _json_no_store({"ok": False, "error": "device_id must be a number, or null to ignore the code"}, 400)
    kind = "ignored" if device_id is None else str(body.get("kind") or "learned")
    if kind not in ("learned", "sticker", "ignored"):
        return _json_no_store({"ok": False, "error": "kind must be learned, sticker or ignored"}, 400)
    owner = principal.get("kind") == "dashboard"
    if kind == "sticker" and not owner:
        # Sticker rows are what the printed sheet reuses (B9); only the dashboard mints them.
        return _json_no_store(
            {"ok": False, "code": "sticker_kind", "error": "Only the dashboard creates sticker codes."}, 403
        )
    # B8 lets any paired phone teach Lens a code it has never seen; B10 keeps a phone without the
    # ``act`` scope read-only. So such a phone may only *add*: moving, or ignoring, a code that is
    # already known (a printed sticker above all) is the same destruction api_lens_forget refuses.
    may_change = owner or lens_can_act(c, principal)
    try:
        tag_id = lens.learn_tag(
            c.conn, body.get("code"), device_id, kind=kind,
            label=body.get("label"), created_by=str(principal.get("label") or "lens")[:40],
            overwrite=may_change,
        )
    except lens.TagExists:
        denial = _lens_act_denial(c, principal)
        return denial if denial is not None else _json_no_store({"ok": False, "error": "that code is already known"}, 409)
    except ValueError as exc:
        return _json_no_store({"ok": False, "error": str(exc)}, 404 if "no such" in str(exc) else 400)
    return _json_no_store({"ok": True, "tag_id": tag_id, "device_id": device_id, "kind": kind})


@bp.delete("/lens/tag/<path:code>")
def api_lens_forget(code: str):
    """Unlearn a code.

    This is a destructive inventory change, not a read: deleting a sticker tag kills a label
    that is physically stuck to a device, and the next sheet then prints a *different* QR for
    it. So it needs the same permission every other mutating Lens route needs — B10's "without
    the ``act`` scope Lens is strictly read-only" has to mean this route too, or a read-only
    phone (or anyone who picks one up) can silently destroy every printed sticker mapping.
    The owner at the desktop is exempt: docs/LENS_SETUP.md sends them here to fix a mis-learned
    code, and that is a dashboard-authenticated request, not a paired phone.
    """
    principal, error = lens_principal()
    if error is not None:
        return error
    c = ctx()
    if principal.get("kind") != "dashboard":
        denial = _lens_act_denial(c, principal)
        if denial is not None:
            return denial
    lens = _lens_module()
    if not lens.forget_tag(c.conn, code):
        return _json_no_store({"ok": False, "error": "no such tag"}, 404)
    return _json_no_store({"ok": True, "forgotten": True})


@bp.get("/lens/devices")
def api_lens_devices():
    """The ranked picker list -- what Lens shows with no code, or when the guess was wrong."""
    _, error = lens_principal()
    if error is not None:
        return error
    lens = _lens_module()
    hint = {k: v for k, v in (("kind", request.args.get("kind")), ("q", request.args.get("q"))) if v}
    return _json_no_store(
        {"ok": True, "devices": lens.rank_candidates(ctx().conn, hint=hint or None, limit=_int_arg("limit", 50, 1, 200))}
    )


@bp.get("/lens/device/<int:device_id>")
def api_lens_device(device_id: int):
    principal, error = lens_principal()
    if error is not None:
        return error
    payload = lens_payload(ctx(), principal, device_id, _int_arg("hours", 24, 1, 24 * 30))
    if payload is None:
        return _json_no_store({"ok": False, "error": "no such device"}, 404)
    return _json_no_store(payload)


@bp.post("/lens/action")
def api_lens_action():
    """rescan / acknowledge / set_trusted -- needs the ``act`` scope and ``lens.allow_actions``."""
    principal, error = _lens_act_guard()
    if error is not None:
        return error
    c = ctx()
    body = _payload()
    action = str(body.get("action") or "")
    if action not in LENS_ACTIONS:
        return _json_no_store({"ok": False, "error": "action must be one of " + ", ".join(LENS_ACTIONS)}, 400)
    try:
        device_id = int(body.get("device_id"))
    except (TypeError, ValueError):
        return _json_no_store({"ok": False, "error": "device_id must be a number"}, 400)
    if one(c.conn, "SELECT id FROM devices WHERE id=?", (device_id,)) is None:
        return _json_no_store({"ok": False, "error": "no such device"}, 404)
    payload = body.get("payload") if isinstance(body.get("payload"), dict) else {}
    _record_event(c.conn, "info", "lens", f"{action} requested from Lens",
                  {"device_id": device_id, "by": principal.get("label")})

    if action == "rescan":
        result = trigger_device_scan(c, device_id)  # the existing scheduler path, never a new one
        return _json_no_store(result, 202 if result.get("ok") else 409)
    if action == "set_trusted":
        trusted = _bool(payload.get("trusted", True))
        update_device(c.conn, device_id, {"trusted": trusted})
        return _json_no_store({"ok": True, "device_id": device_id, "trusted": trusted})
    try:
        row_id = int(payload.get("row_id"))
    except (TypeError, ValueError):
        return _json_no_store({"ok": False, "error": "payload.row_id must be the finding's row id"}, 400)
    owner = one(c.conn, "SELECT device_id FROM findings WHERE id=?", (row_id,))
    if owner is None or int(owner.get("device_id") or 0) != device_id:
        return _json_no_store({"ok": False, "error": "no such finding on this device"}, 404)
    if not set_finding_status(c.conn, row_id, "acknowledged", "acknowledged from Lens"):
        return _json_no_store({"ok": False, "error": "no such finding"}, 404)
    return _json_no_store({"ok": True, "row_id": row_id, "status": "acknowledged"})


@bp.get("/lens/health")
def api_lens_health():
    principal, error = lens_principal()
    if error is not None:
        return error
    c = ctx()
    try:
        version = str(getattr(importlib.import_module("homesoc"), "__version__", "") or "")
    except ImportError:  # pragma: no cover
        version = ""
    return _json_no_store(
        {
            "ok": True,
            "https": bool(request.is_secure),
            "version": version,
            "dns_enabled": _bool(cfg_get(c.cfg, "dns.enabled", False)),
            "devices": int(scalar(c.conn, "SELECT count(*) FROM devices")),
            "paired_as": principal.get("label"),
            "scopes": principal.get("scopes"),
            "can_act": lens_can_act(c, principal),
            "tag_learning": _bool(cfg_get(c.cfg, "lens.tag_learning", True)),
        }
    )
