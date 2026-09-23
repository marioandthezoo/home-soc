"""Lens identification engine and overlay payload (SPEC addendum B, sections B5–B7).

Lens answers one question the dashboard never had to: *which physical object is the phone
pointing at?* The answer comes from ``lens_tags`` — a decoded barcode or a Home SOC sticker
mapped to a device — with a ranked manual picker for everything that has no tag yet.

Everything the phone shows comes from :func:`lens_device` in a single round trip, so the
plain-English wording (what a port means, what a CVE's EPSS score means in practice, whether
the DNS numbers are complete) is generated *here* and the phone stays a dumb renderer.

Text produced here is plain text, never HTML: device nicknames, hostnames, service banners and
domains come straight off the network, so every consumer escapes them for its own medium.
"""

from __future__ import annotations

import hashlib
import importlib
import json
import logging
import re
import secrets
import sqlite3
import threading
import time
from contextlib import nullcontext as _nullcontext
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Any

from homesoc.web import api

logger = logging.getLogger(__name__)

# --------------------------------------------------------------------------- constants

# Sticker payloads are opaque (B2/B10): "hs1:" plus 22 url-safe base64 characters from
# secrets.token_urlsafe(16). A photograph of a sticker reveals nothing about the network.
STICKER_PREFIX = "hs1:"
STICKER_ENTROPY_BYTES = 16

TAG_KINDS: tuple[str, ...] = ("sticker", "learned", "ignored")
CONFIDENCES: tuple[str, ...] = ("exact", "probable", "ambiguous", "unknown")

# A decoded barcode is attacker-controlled text of unknown length. Anything longer than this,
# or carrying control characters, is not a code we are willing to store.
MAX_CODE_LEN = 512
_CONTROL = re.compile(r"[\x00-\x1f\x7f-\x9f]")

# "Currently online" for ranking (B6 rule 1) means the online flag *and* a recent sighting;
# a device that dropped off an hour ago should not outrank the one in your hand.
ONLINE_MINUTES = 10

# B4: 10 claim attempts per hour per source IP, then refused for an hour.
CLAIM_MAX_ATTEMPTS = 10
CLAIM_WINDOW_SEC = 3600

# Scopes (B4). ``act`` is only ever granted while lens.allow_actions is true.
SCOPE_READ = "read"
SCOPE_ACT = "act"

TIMELINE_LIMIT = 20
# How far back the timeline looks. The feed's own sources are each bounded by a LIMIT, so a
# generous window costs little and stops a quiet device showing an empty History section.
TIMELINE_WINDOW_HOURS = 24 * 90

# --------------------------------------------------------------------------- dependencies (C7)

#: How many relationships each Lens dependency list carries before the rest becomes a count.
#: The payload is fetched on every identification, so a router with seventeen clients must not
#: put seventeen rows through the air to be rendered on a 390px card nobody scrolls that far.
DEPS_LIMIT = 6
#: Evidence lines are read one-handed in a cupboard, so they are capped harder than the map's.
DEPS_TEXT_LIMIT = 220
#: The graph window. 168 hours matches /map and ``topology.window_hours``, so the evidence
#: sentences the phone shows ("183 DNS queries in the last 7 days") are the same ones the
#: dashboard shows for the same edge.
DEPS_WINDOW_HOURS = 168

#: Edge type -> what the other end *is*, in the vocabulary the phone renders. ``hosted_by`` is
#: absent on purpose: it points from a service to the box running it, which is a statement about
#: this device, not about anything that depends on it.
DEP_KIND_BY_EDGE: dict[str, str] = {
    "gateway": "device",
    "internet": "internet",
    "dns": "resolver",
    "cloud": "cloud",
    "cloud_blocked": "cloud_blocked",
    "uses": "service",
}
#: Edge types that can make one *device* depend on another directly. ``uses`` usually reaches a
#: provider node — those consumers are resolved through the provider in :func:`deps_section` —
#: but it points straight at a device when the device offers several services and the evidence
#: cannot say which one was involved, so it belongs here too.
DEP_INBOUND_EDGES: frozenset[str] = frozenset({"gateway", "uses"})

_DEP_CONFIDENCE_RANK: dict[str, int] = {"observed": 0, "inferred": 1, "assumed": 2}

#: Said once, next to the lists themselves. The blast section carries the map's own note; this
#: one is about these two lists specifically, because a list of devices under the heading
#: "Depended on by" is exactly where a reader would otherwise assume Home SOC watched them talk.
DEPS_NOTE = (
    "Only relationships with evidence are listed. Home SOC cannot see traffic between devices, "
    "so this is what it has observed or inferred — never a record of who talked to whom."
)
DEPS_UNMAPPED_NOTE = (
    "This device is not on the dependency graph yet, so nothing is known about what it depends "
    "on or what depends on it."
)

DDL_LENS_TAGS = """
CREATE TABLE IF NOT EXISTS lens_tags (
    id           INTEGER PRIMARY KEY,
    code         TEXT NOT NULL UNIQUE,
    kind         TEXT NOT NULL,
    device_id    INTEGER REFERENCES devices(id) ON DELETE SET NULL,
    label        TEXT,
    created_at   TEXT NOT NULL,
    created_by   TEXT NOT NULL,
    last_seen_at TEXT,
    scans        INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_lens_tags_device ON lens_tags(device_id);
"""

# SPEC-GAP: L1 owns lens_tokens (B4) and its migration. This DDL is the fallback so the
# identification package works against a database that has not had L1's migration applied;
# it is byte-for-byte the B4 column list, so whichever runs first, the other is a no-op.
DDL_LENS_TOKENS = """
CREATE TABLE IF NOT EXISTS lens_tokens (
    id           INTEGER PRIMARY KEY,
    token_hash   TEXT NOT NULL UNIQUE,
    label        TEXT NOT NULL,
    scopes       TEXT NOT NULL DEFAULT 'read',
    created_at   TEXT NOT NULL,
    last_seen_at TEXT,
    last_ip      TEXT,
    expires_at   TEXT,
    revoked_at   TEXT
);
"""

# --------------------------------------------------------------------------- plain English

# port -> (name, what it means to a human, risk while the port is open).
# The gloss lives here, not on the phone, so the CLI and the dashboard say the same thing.
PORT_INFO: dict[int, tuple[str, str, str]] = {
    21: ("FTP", "file transfer with no encryption — the password is sent in clear text", "high"),
    22: ("SSH", "encrypted remote shell; fine when you meant to turn it on", "low"),
    23: ("Telnet", "remote control with no encryption at all — anyone on the network can read the password", "critical"),
    25: ("SMTP", "outgoing mail; on a home device this is usually a leftover or a relay", "medium"),
    53: ("DNS", "answers name lookups for other devices", "low"),
    80: ("Web page (HTTP)", "a web interface served without encryption, so its password crosses the network in the clear", "low"),
    110: ("POP3", "mail collection without encryption", "medium"),
    139: ("NetBIOS", "legacy Windows file sharing, superseded and best turned off", "medium"),
    143: ("IMAP", "mail access without encryption", "medium"),
    161: ("SNMP", "management interface that often still uses the factory 'public' password", "medium"),
    443: ("Web page (HTTPS)", "an encrypted web interface — the normal way to manage a device", "info"),
    445: ("SMB file sharing", "Windows file sharing; this is the door ransomware worms walk through", "high"),
    515: ("Printer (LPD)", "the old print protocol; no password, no encryption", "medium"),
    554: ("RTSP camera stream", "live video, which cameras very often serve with no password", "high"),
    631: ("Printer (IPP)", "network printing; check whether it needs a password", "low"),
    1433: ("Microsoft SQL Server", "a database engine listening on the network", "high"),
    1900: ("UPnP / SSDP", "lets other devices punch holes in your router by themselves", "medium"),
    2323: ("Telnet (alternate port)", "remote control with no encryption — a favourite of IoT botnets", "critical"),
    3306: ("MySQL", "a database engine listening on the network", "high"),
    3389: ("Remote Desktop (RDP)", "full remote control of the screen and keyboard", "high"),
    5353: ("mDNS", "how devices announce themselves on the local network; normal, but it leaks the model name", "info"),
    5432: ("PostgreSQL", "a database engine listening on the network", "high"),
    5900: ("VNC", "remote control of the screen, and frequently with no password", "high"),
    6379: ("Redis", "an in-memory database that historically ships with no password at all", "critical"),
    7547: ("TR-069 remote management", "lets an ISP (or anyone imitating one) reconfigure the device", "high"),
    8080: ("Web page (HTTP, alternate port)", "a second web interface, unencrypted", "low"),
    8443: ("Web page (HTTPS, alternate port)", "a second web interface, encrypted", "info"),
    9100: ("Raw printing", "anyone on the network can print, and often read back what was printed", "medium"),
    27017: ("MongoDB", "a database engine listening on the network", "high"),
}

# Finding ID -> a clause for the headline, written to read as "this camera <clause>".
# Anything without an entry falls back to the finding's own title, which is always truthful.
FINDING_CLAUSE: dict[str, str] = {
    "NET-SVC-001": "accepts Telnet logins, which send the password across the network in clear text",
    "NET-SVC-002": "offers FTP, so file transfers and the password are unencrypted",
    "NET-SVC-003": "shares files over SMB, the protocol ransomware worms spread through",
    "NET-SVC-004": "has its remote-desktop screen open to anyone on this network",
    "NET-SVC-005": "serves its admin web page without encryption",
    "NET-SVC-006": "lets other devices open holes in the router by themselves through UPnP",
    "NET-SVC-007": "has a database port open to the network",
    "NET-SVC-008": "accepts print jobs from anyone, with no password",
    "NET-SVC-009": "answers SNMP with the factory password, handing over its configuration",
    "NET-SVC-010": "streams its camera video to anyone who asks",
    "NET-SVC-011": "runs an out-of-date SSH server",
    "NET-SVC-012": "announces its exact hardware model to every device on the network",
    "NET-DEV-001": "has not been confirmed as yours yet",
    "NET-DEV-002": "hides behind a randomised MAC address, so it cannot be recognised reliably",
    "NET-DEV-003": "has been missing from the network for days",
    "NET-VUL-001": "runs software with a flaw criminals are exploiting right now",
    "NET-VUL-002": "may run software with a flaw criminals are exploiting right now",
    "NET-VUL-003": "runs software with publicly known security flaws",
    "NET-VUL-004": "runs software attackers are likely to attack next",
    "NET-RTR-002": "is a router still using its factory administrator password",
    "NET-WIFI-001": "is on a Wi-Fi network with no encryption",
    "NET-WIFI-002": "is on a Wi-Fi network still using WPA2 rather than WPA3",
    "NET-WIFI-003": "is on a Wi-Fi network using TKIP, an encryption scheme broken years ago",
    "NET-WIFI-004": "is on a Wi-Fi network with WPS enabled, which can be brute-forced",
    "NET-WAN-001": "has a port reachable from the public internet, not just from your home",
    "NET-WAN-002": "is reachable from the internet and running software with known flaws",
    "NET-WAN-003": "has punched a hole through the router to itself using UPnP, so the internet can reach it",
}

# Nouns the headline can use instead of "device", taken from devices.kind.
KIND_NOUN: dict[str, str] = {
    "router": "router", "gateway": "router", "camera": "camera", "printer": "printer",
    "nas": "NAS", "tv": "TV", "phone": "phone", "tablet": "tablet", "laptop": "laptop",
    "desktop": "PC", "pc": "PC", "speaker": "speaker", "thermostat": "thermostat",
    "plug": "smart plug", "bulb": "smart bulb", "console": "games console", "iot": "gadget",
}

_SEVERITY_WORD: dict[str, str] = {
    "critical": "critical", "high": "serious", "medium": "notable", "low": "minor", "info": "informational",
}
_NUMBER_WORD: tuple[str, ...] = (
    "no", "One", "Two", "Three", "Four", "Five", "Six", "Seven", "Eight", "Nine", "Ten",
)


def _count_word(n: int) -> str:
    return _NUMBER_WORD[n] if 0 <= n < len(_NUMBER_WORD) else str(n)


def _join_clauses(parts: list[str]) -> str:
    """Join with a serial comma throughout: the clauses themselves contain commas
    ("accepts Telnet logins, which send the password ..."), so a bare " and " runs them together."""
    if not parts:
        return ""
    if len(parts) == 1:
        return parts[0]
    return ", ".join(parts[:-1]) + ", and " + parts[-1]


# --------------------------------------------------------------------------- schema


def _core_db() -> Any | None:
    """``homesoc.db`` when it is importable — it owns the schema and the write lock."""
    try:
        return importlib.import_module("homesoc.db")
    except ImportError:  # identification still works without the core package
        return None


def _lens_tables_present(conn: sqlite3.Connection) -> bool:
    return {
        str(r["name"])
        for r in api.rows(
            conn,
            "SELECT name FROM sqlite_master WHERE type='table' AND name IN ('lens_tags','lens_tokens')",
        )
    } >= {"lens_tags", "lens_tokens"}


def ensure_tables(conn: sqlite3.Connection) -> None:
    """Create ``lens_tags`` (and, as a fallback, ``lens_tokens``) when they do not exist.

    SPEC-GAP: B5 says ``db.init_schema`` creates both through a migration, which the transport
    package owns. Creating them here too is idempotent (``IF NOT EXISTS``) and means Lens works
    on a database that predates that migration.
    """
    try:
        have = _lens_tables_present(conn)
        if have:  # the common case: one cheap read, no write lock taken
            return
    except Exception:
        # The check is deliberately lock-free, and one sqlite3 connection is shared by every
        # thread, so a concurrent writer can leave this read with nothing usable. "I could not
        # tell" must mean "create them anyway" — the creation path below is idempotent and does
        # take the lock — and never an exception escaping into a 500.
        logger.debug("could not read the Lens table list; creating them instead", exc_info=True)

    # One connection is shared by every thread and every writer serialises on db._WRITE_LOCK.
    # ``executescript`` issues an implicit COMMIT before it runs, so creating the tables on the
    # bare connection would commit whatever unit of work a scheduler thread happens to have open
    # (and turn its later rollback into a no-op). Hand the job to the module that owns both the
    # schema and the lock; it is idempotent and records the migration, so schema_version stays
    # truthful rather than claiming v1 on a database that now has the v2 tables.
    dbmod = _core_db()
    try:
        if dbmod is not None and hasattr(dbmod, "init_schema"):
            dbmod.init_schema(conn)
            if _lens_tables_present(conn):
                return
            # schema_migrations claims a version that already covers these tables but they are
            # not there (a hand-edited database, a restored partial backup). Create them anyway,
            # still under the write lock — Lens working matters more than the version number.
        scope = dbmod.transaction(conn) if dbmod is not None and hasattr(dbmod, "transaction") else _nullcontext()
        with scope:
            conn.executescript(DDL_LENS_TAGS)
            conn.executescript(DDL_LENS_TOKENS)
            if not hasattr(dbmod, "transaction"):
                conn.commit()
    except sqlite3.Error:
        logger.exception("could not ensure the Lens tables exist")


# --------------------------------------------------------------------------- codes


def normalise_code(value: Any) -> str | None:
    """A decoded barcode as we are willing to store it, or ``None`` when it is not usable.

    Treated as hostile input: the payload comes off a sticker a visitor could have printed.
    """
    code = str(value or "").strip()
    if not code or len(code) > MAX_CODE_LEN:
        return None
    if _CONTROL.search(code):
        return None
    return code


def clean_text(value: Any, limit: int) -> str:
    """Free text from the phone, as we are willing to store it.

    Labels travel the same road a decoded code does — straight off a request body — and end up
    in ``lens_tags``/``lens_tokens``, in an ``events`` row and in the fixed-width table
    ``python -m homesoc lens tokens`` prints. Control characters are stripped for the same
    reason :func:`normalise_code` refuses them: a CR, a NUL or an ANSI escape in a label can
    forge or hide a row in the very listing the owner uses to decide what to revoke.
    """
    return _CONTROL.sub("", str(value or "")).strip()[:limit].strip()


def is_sticker_code(code: str) -> bool:
    return code.startswith(STICKER_PREFIX)


def new_sticker_code() -> str:
    return STICKER_PREFIX + secrets.token_urlsafe(STICKER_ENTROPY_BYTES)


# --------------------------------------------------------------------------- match


@dataclass(frozen=True)
class Match:
    """The result of pointing the camera at something (B6)."""

    device_id: int | None
    confidence: str  # "exact" | "probable" | "ambiguous" | "unknown"
    via: str  # "sticker" | "learned" | "manual" | "ignored"
    candidates: list[dict] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "device_id": self.device_id,
            "confidence": self.confidence,
            "via": self.via,
            "candidates": list(self.candidates),
        }


# --------------------------------------------------------------------------- ranking

# Scores are banded so the B6 precedence is exact: no number of open findings can lift an
# offline device above an online one, and nothing below can overtake a findings hit.
_SCORE_ONLINE = 1000
_SCORE_FINDINGS = 400
_SCORE_HINT_KIND = 200
_SCORE_UNTRUSTED = 100
_SCORE_NEW = 50
_SEVERITY_BONUS: dict[str, int] = {"critical": 40, "high": 25, "medium": 10, "low": 5, "info": 1}


def _display_name(d: dict) -> str:
    return str(d.get("nickname") or d.get("hostname") or d.get("ip") or d.get("mac") or f"device {d.get('id')}")


def _ip_sort_key(ip: Any) -> tuple:
    """Sort 192.168.1.9 before 192.168.1.10 rather than the other way round."""
    parts = str(ip or "").split(".")
    if len(parts) == 4 and all(p.isdigit() for p in parts):
        return (0,) + tuple(int(p) for p in parts)
    return (1, str(ip or ""))


def rank_candidates(conn: sqlite3.Connection, *, hint: dict | None = None, limit: int = 25) -> list[dict]:
    """Devices the user is most plausibly pointing at, best first (B6).

    Precedence: online now, then devices with open findings, then a ``hint`` kind match, then
    untrusted / newly seen, then everything else alphabetically. Every candidate explains itself
    through ``why`` so the picker is readable rather than a wall of IP addresses.
    """
    limit = max(1, min(int(limit or 1), 200))
    hint = hint if isinstance(hint, dict) else {}
    want_kind = str(hint.get("kind") or "").strip().lower()[:40]
    want_vendor = str(hint.get("vendor") or "").strip().lower()[:60]
    want_ip = str(hint.get("ip") or "").strip()[:45]
    want_mac = str(hint.get("mac") or "").strip().lower()[:32]
    needle = str(hint.get("q") or "").strip().lower()[:80]

    fresh = api.cutoff_iso(ONLINE_MINUTES / 60.0)
    week = api.cutoff_iso(24 * 7)
    data = api.rows(
        conn,
        "SELECT d.id, d.mac, d.ip, d.hostname, d.vendor, d.kind, d.nickname, d.trusted, d.online, "
        "d.first_seen, d.last_seen, "
        "(SELECT count(*) FROM findings f WHERE f.device_id=d.id AND f.status='open') AS open_findings, "
        "(SELECT f.severity FROM findings f WHERE f.device_id=d.id AND f.status='open' "
        " ORDER BY CASE f.severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 "
        "          WHEN 'low' THEN 3 ELSE 4 END LIMIT 1) AS worst_severity "
        "FROM devices d",
    )

    out: list[dict] = []
    for d in data:
        name = _display_name(d)
        if needle:
            haystack = " ".join(str(v or "").lower() for v in (name, d.get("ip"), d.get("vendor"), d.get("kind"), d.get("hostname")))
            if needle not in haystack:
                continue
        online = api._bool(d.get("online"))
        online_now = online and str(d.get("last_seen") or "") >= fresh
        open_findings = int(d.get("open_findings") or 0)
        worst = str(d.get("worst_severity") or "").lower()
        kind = str(d.get("kind") or "").lower()
        trusted = api._bool(d.get("trusted"))
        is_new = str(d.get("first_seen") or "") >= week

        score = 0
        why: list[str] = []
        if online_now:
            score += _SCORE_ONLINE
            why.append("online")
        elif online:
            why.append("last seen recently")
        else:
            age = api.age_hours(d.get("last_seen"))
            why.append("offline" if age is None else f"offline for {_span_hours(age)}")
        if open_findings:
            score += _SCORE_FINDINGS + min(open_findings, 9) * 5 + _SEVERITY_BONUS.get(worst, 0)
            why.append(f"{open_findings} open finding" + ("s" if open_findings != 1 else ""))
        # B6 rules 3 and 4 live in one band *below* the findings band. Added straight onto the
        # score they are not: kind hint (200) + vendor hint (100) + untrusted (100) + new (50)
        # comes to 450, which overtakes the 445 an offline device with one open critical finding
        # can reach. Clamping the sum keeps the bands disjoint, so nothing below rule 2 can ever
        # overtake a findings hit — which is what the comment above _SCORE_ONLINE promises.
        lower_band = 0
        if want_kind and kind == want_kind:
            lower_band += _SCORE_HINT_KIND
        if want_vendor and want_vendor in str(d.get("vendor") or "").lower():
            lower_band += _SCORE_HINT_KIND // 2
        if not trusted:
            lower_band += _SCORE_UNTRUSTED
            why.append("not marked trusted")
        if is_new:
            lower_band += _SCORE_NEW
            why.append("first seen this week")
        score += min(lower_band, _SCORE_FINDINGS - 1)
        # An explicit address is not a heuristic — the caller told us which device it is — so it
        # deliberately sits above every band, including "online now".
        if want_ip and str(d.get("ip") or "") == want_ip:
            score += _SCORE_ONLINE * 2
            why.append("matches the address you gave")
        if want_mac and str(d.get("mac") or "").lower() == want_mac:
            score += _SCORE_ONLINE * 2
        if kind:
            why.insert(0, kind)

        out.append(
            {
                "device_id": int(d["id"]),
                "name": name,
                "ip": d.get("ip"),
                "kind": d.get("kind"),
                "vendor": d.get("vendor"),
                "score": score,
                "why": ", ".join(why[:4]),
            }
        )
    out.sort(key=lambda c: (-c["score"], str(c["name"]).lower(), _ip_sort_key(c["ip"])))
    return out[:limit]


def _span_hours(hours: float) -> str:
    if hours < 1:
        return f"{int(hours * 60)} min"
    if hours < 48:
        return f"{hours:.0f} h"
    return f"{hours / 24:.0f} days"


# --------------------------------------------------------------------------- tags


def tag_for_code(conn: sqlite3.Connection, code: str) -> dict | None:
    return api.one(conn, "SELECT * FROM lens_tags WHERE code=?", (code,))


def tags_for_device(conn: sqlite3.Connection, device_id: int) -> list[dict]:
    return api.rows(conn, "SELECT * FROM lens_tags WHERE device_id=? ORDER BY id", (int(device_id),))


class TagExists(ValueError):
    """``learn_tag(..., overwrite=False)`` found the code already bound (or ignored)."""


def learn_tag(
    conn: sqlite3.Connection,
    code: str,
    device_id: int | None,
    *,
    kind: str = "learned",
    label: str | None = None,
    created_by: str = "lens",
    overwrite: bool = True,
) -> int:
    """Bind ``code`` to ``device_id`` and return the tag's row id.

    ``device_id=None`` with ``kind='ignored'`` records "this code is not a device", so the phone
    stops asking about the barcode on the back of the sofa. Re-learning an existing code moves it
    rather than creating a duplicate; a sticker keeps its ``sticker`` kind so reprints stay valid.

    ``overwrite=False`` is the read-only phone's mode (B8 lets it teach Lens a *new* code; B10
    forbids it changing anything that exists): it only ever inserts, and raises
    :class:`TagExists` when the code is already stored, whatever its kind. The check and the
    insert share one unit of work, so a concurrent learn cannot slip between them.
    """
    if not overwrite:
        dbmod = _core_db()
        scope = dbmod.transaction(conn) if dbmod is not None and hasattr(dbmod, "transaction") else _nullcontext()
        with scope:
            normalised = normalise_code(code)
            if normalised is not None and tag_for_code(conn, normalised) is not None:
                raise TagExists("that code is already known")
            return learn_tag(conn, code, device_id, kind=kind, label=label, created_by=created_by)
    normalised = normalise_code(code)
    if normalised is None:
        raise ValueError("invalid code")
    if kind not in TAG_KINDS:
        raise ValueError("kind must be one of " + ", ".join(TAG_KINDS))
    if device_id is not None:
        device_id = int(device_id)
        if api.one(conn, "SELECT id FROM devices WHERE id=?", (device_id,)) is None:
            raise ValueError("no such device")
    elif kind != "ignored":
        raise ValueError("a tag with no device must have kind 'ignored'")

    ensure_tables(conn)
    clean_label = clean_text(label, 80) or None
    creator = clean_text(created_by, 40) or "lens"
    # One statement, not a SELECT followed by an INSERT: ``code`` is UNIQUE, and two phones
    # scanning the same new barcode at once (or two /lens/stickers loads minting side by side)
    # would otherwise interleave between the two and raise IntegrityError — an HTTP 500 with a
    # traceback instead of a bound tag.
    #
    # A sticker keeps its ``sticker`` kind unless the caller explicitly asks for another one,
    # so the owner scanning their own printed label and tapping the device again cannot quietly
    # downgrade it to ``learned`` and make the next sheet print a different QR than the one
    # already stuck to the device (B9).
    api.write(
        conn,
        "INSERT INTO lens_tags(code, kind, device_id, label, created_at, created_by, scans) "
        "VALUES(?,?,?,?,?,?,0) "
        "ON CONFLICT(code) DO UPDATE SET "
        "  device_id=excluded.device_id, "
        "  kind=CASE WHEN lens_tags.kind='sticker' AND excluded.kind='learned' "
        "            THEN 'sticker' ELSE excluded.kind END, "
        "  label=COALESCE(excluded.label, lens_tags.label)",
        (normalised, kind, device_id, clean_label, api.now_iso(), creator),
    )
    row = tag_for_code(conn, normalised)
    return int(row["id"]) if row is not None else 0


def forget_tag(conn: sqlite3.Connection, code: str) -> bool:
    """Unlearn a code. ``True`` when a tag was actually removed."""
    normalised = normalise_code(code)
    if normalised is None:
        return False
    if tag_for_code(conn, normalised) is None:
        return False
    api.write(conn, "DELETE FROM lens_tags WHERE code=?", (normalised,))
    return True


def existing_sticker_codes(conn: sqlite3.Connection, device_ids: list[int]) -> dict[int, str]:
    """device id -> sticker payload for devices that already have one. Never mints."""
    ensure_tables(conn)
    wanted: list[int] = []
    for raw in device_ids or []:
        try:
            device_id = int(raw)
        except (TypeError, ValueError):
            continue
        if device_id not in wanted:
            wanted.append(device_id)
    if not wanted:
        return {}
    placeholders = ",".join("?" for _ in wanted)
    out: dict[int, str] = {}
    for r in api.rows(
        conn,
        f"SELECT device_id, code FROM lens_tags WHERE code LIKE ? AND device_id IN ({placeholders}) ORDER BY id",
        [STICKER_PREFIX + "%"] + wanted,
    ):
        if r.get("device_id") is not None:
            out[int(r["device_id"])] = str(r["code"])  # same row mint_sticker_codes reuses
    return out


def mint_sticker_codes(conn: sqlite3.Connection, device_ids: list[int]) -> dict[int, str]:
    """device id -> sticker payload, minting only what is missing.

    Idempotent by contract (B9): reprinting a sheet must never invalidate a sticker that is
    already stuck to a device, so an existing ``sticker`` tag is always reused.
    """
    ensure_tables(conn)
    wanted: list[int] = []
    for raw in device_ids or []:
        try:
            device_id = int(raw)
        except (TypeError, ValueError):
            continue
        if device_id not in wanted:
            wanted.append(device_id)
    if not wanted:
        return {}
    placeholders = ",".join("?" for _ in wanted)
    dbmod = _core_db()
    # Read and mint inside one unit of work so a second sheet load cannot interleave and give
    # one device two different sticker codes — two printed sheets that disagree.
    scope = dbmod.transaction(conn) if dbmod is not None and hasattr(dbmod, "transaction") else _nullcontext()
    with scope:
        known = {int(r["id"]) for r in api.rows(conn, f"SELECT id FROM devices WHERE id IN ({placeholders})", wanted)}
        existing = {
            int(r["device_id"]): str(r["code"])
            for r in api.rows(
                conn,
                # Keyed on the payload shape, not on the mutable ``kind`` column: STICKER_PREFIX
                # is what actually makes a code a printed sticker, so a row whose kind was moved
                # still reuses its code and the sheet reprints the QR already on the device (B9).
                f"SELECT device_id, code FROM lens_tags WHERE code LIKE ? AND device_id IN ({placeholders}) ORDER BY id",
                [STICKER_PREFIX + "%"] + wanted,
            )
            if r.get("device_id") is not None
        }
        out: dict[int, str] = {}
        for device_id in wanted:
            if device_id not in known:
                continue
            code = existing.get(device_id)
            if code is None:
                code = new_sticker_code()
                learn_tag(conn, code, device_id, kind="sticker", created_by="dashboard")
            out[device_id] = code
    return out


def _touch_tag(conn: sqlite3.Connection, tag_id: int) -> None:
    api.write(conn, "UPDATE lens_tags SET scans=scans+1, last_seen_at=? WHERE id=?", (api.now_iso(), int(tag_id)))


# --------------------------------------------------------------------------- identify


def identify(conn: sqlite3.Connection, *, code: str | None = None, hint: dict | None = None) -> Match:
    """Resolve a decoded code (or a bare hint) to a device (B6).

    A known code is an ``exact`` match and is the fast path every repeat scan takes. An unknown
    code is never an error: it comes back ``unknown`` with the ranked picker attached, which is
    what turns "new code" into one tap and a permanent mapping.
    """
    ensure_tables(conn)
    candidates = rank_candidates(conn, hint=hint)
    normalised = normalise_code(code) if code is not None else None

    if normalised is not None:
        tag = tag_for_code(conn, normalised)
        if tag is not None:
            _touch_tag(conn, int(tag["id"]))
            kind = str(tag.get("kind") or "learned")
            device_id = tag.get("device_id")
            if kind == "ignored" or device_id is None:
                # Either the user said "not a device", or the device was deleted and the tag was
                # unlearned rather than left dangling (B5).
                return Match(None, "unknown", "ignored" if kind == "ignored" else "manual", candidates)
            device_id = int(device_id)
            if api.one(conn, "SELECT id FROM devices WHERE id=?", (device_id,)) is None:
                # B5: a tag whose device is gone becomes unlearned, never a dangling pointer.
                # Self-healing here means the rule holds however the row disappeared.
                api.write(conn, "UPDATE lens_tags SET device_id=NULL WHERE id=?", (int(tag["id"]),))
                return Match(None, "unknown", "manual", candidates)
            return Match(device_id, "exact", kind if kind in ("sticker", "learned") else "learned", candidates)
        return Match(None, "unknown", "manual", candidates)

    # No code: the desktop picker, or the phone asking "what is near me?" with a filter.
    if hint and candidates:
        if len(candidates) == 1:
            return Match(int(candidates[0]["device_id"]), "probable", "manual", candidates)
        top, second = candidates[0], candidates[1]
        if top["score"] == second["score"]:
            return Match(None, "ambiguous", "manual", candidates)
        if top["score"] - second["score"] >= _SCORE_HINT_KIND:
            return Match(int(top["device_id"]), "probable", "manual", candidates)
    return Match(None, "unknown", "manual", candidates)


# --------------------------------------------------------------------------- overlay payload


def _severity_counts(findings: list[dict]) -> dict[str, int]:
    counts = {sev: 0 for sev in api.SEVERITIES}
    for f in findings:
        sev = str(f.get("severity") or "info").lower()
        if sev in counts:
            counts[sev] += 1
    return counts


def _device_noun(device: dict) -> str:
    return KIND_NOUN.get(str(device.get("kind") or "").lower(), "device")


def _clause_for(finding: dict) -> str:
    clause = FINDING_CLAUSE.get(str(finding.get("finding_id") or ""))
    if clause:
        return clause
    title = str(finding.get("title") or "").strip()
    if not title:
        return "has a problem Home SOC could not describe"
    return "has this open: " + _decapitalise(title)


def _decapitalise(title: str) -> str:
    """Lower the first letter for mid-sentence use, unless it starts an acronym.

    ``title[0].lower()`` alone turns "UPnP port mapping..." into "uPnP port mapping...",
    and "WPS appears..." into "wPS appears...". A second capital (or a digit) means the
    first word is a name or acronym, so it is left exactly as written.
    """
    if len(title) > 1 and (title[1].isupper() or title[1].isdigit()):
        return title
    return title[0].lower() + title[1:]


def headline(device: dict, open_findings: list[dict], *, scanned: bool = True) -> str:
    """One sentence a non-expert understands, built from the worst open findings.

    "Two critical problems: this camera accepts Telnet logins, which send the password across
    the network in clear text, and it streams its camera video to anyone who asks."
    """
    noun = _device_noun(device)
    name = "this " + noun
    if not open_findings:
        if not scanned:
            return f"Home SOC has not scanned {name} yet, so there is nothing to report — run a scan to check it."
        return f"Nothing is open on {name} right now. Home SOC has checked it and found no problems."

    ranked = sorted(open_findings, key=lambda f: api.SEVERITIES.index(str(f.get("severity") or "info").lower())
                    if str(f.get("severity") or "info").lower() in api.SEVERITIES else 9)
    total = len(ranked)
    worst = str(ranked[0].get("severity") or "info").lower()
    worst_n = sum(1 for f in ranked if str(f.get("severity") or "info").lower() == worst)
    word = _SEVERITY_WORD.get(worst, "notable")

    shown = ranked[:3]
    clauses = [_clause_for(f) for f in shown]
    clauses[0] = name + " " + clauses[0]
    for i in range(1, len(clauses)):
        clauses[i] = "it " + clauses[i]
    if total > len(shown):
        # "..., and N more" is the closing conjunction; the clauses before it just take commas.
        # The count is spelled out to match the "Four problems" lead -- "Four problems ... and 1 more"
        # reads like two different voices in one sentence.
        rest = total - len(shown)
        body = ", ".join(clauses) + f", and {_count_word(rest).lower()} more"
    else:
        body = _join_clauses(clauses)

    noun_word = "problem" if total == 1 else "problems"
    if worst_n == total:
        lead = f"{_count_word(total)} {word} {noun_word}"
    else:
        lead = f"{_count_word(total)} {noun_word}, {_count_word(worst_n).lower()} of them {word}"
    return f"{lead}: {body}."


def service_view(service: dict) -> dict:
    """One row of the Exposed section: the port, what it is for, and how much it matters."""
    try:
        port = int(service.get("port") or 0)
    except (TypeError, ValueError):
        port = 0
    state = str(service.get("state") or "").lower()
    known = PORT_INFO.get(port)
    name = str(service.get("name") or "") or (known[0] if known else "")
    gloss = known[1] if known else ""
    risk = known[2] if known else "low"
    if state != "open":
        risk = "info"
        gloss = gloss or "not reachable right now"
    elif not gloss:
        gloss = "an unrecognised service; check whether you meant to run it"
    product = str(service.get("product") or "").strip()
    version = str(service.get("version") or "").strip()
    if state == "open" and product:
        lead = gloss.rstrip()
        if lead and lead[-1] not in ".!?":
            lead += "."
        gloss = f"{lead} Running {product}{(' ' + version) if version else ''}."
    return {
        "port": port,
        "proto": str(service.get("proto") or "tcp"),
        "name": name or (known[0] if known else "unknown"),
        "product": product or None,
        "version": version or None,
        "state": state or "unknown",
        "risk": risk,
        "label": known[0] if known else (name or f"port {port}"),
        "gloss": gloss.strip(),
    }


def _epss_text(epss: float | None) -> str:
    """EPSS as something to act on rather than a decimal nobody can weigh."""
    if epss is None:
        return "No exploitation forecast available."
    pct = epss * 100.0
    if pct >= 10:
        shape = "very likely to be attacked"
    elif pct >= 1:
        shape = "worth fixing soon"
    else:
        shape = "unlikely to be attacked in the near term"
    shown = f"{pct:.1f}%" if pct < 10 else f"{pct:.0f}%"
    return f"{shown} chance of exploitation in the next 30 days — {shape}."


def vuln_view(v: dict) -> dict:
    """One row of the Vulnerabilities section. KEV is called out separately because
    'someone is exploiting this today' outranks every score."""
    try:
        epss = float(v["epss"]) if v.get("epss") is not None else None
    except (TypeError, ValueError):
        epss = None
    try:
        cvss = float(v["cvss"]) if v.get("cvss") is not None else None
    except (TypeError, ValueError):
        cvss = None
    kev = api._bool(v.get("kev"))
    port = v.get("port")
    service = str(v.get("service_name") or v.get("product") or "").strip()
    if port:
        service = f"{service} on port {port}".strip() if service else f"port {port}"
    remediation = str(v.get("remediation") or "").strip()
    if not remediation:
        product = str(v.get("product") or "").strip() or "this device's firmware"
        remediation = f"Update {product} to the newest version the manufacturer offers, then rescan this device."
    return {
        "cve": str(v.get("cve") or ""),
        "kev": kev,
        "cvss": cvss,
        "epss": epss,
        "title": str(v.get("title") or v.get("cve") or ""),
        "service": service or None,
        "remediation": remediation,
        "epss_pct": round(epss * 100.0, 1) if epss is not None else None,
        "epss_text": _epss_text(epss),
        "kev_note": "Listed by CISA as actively exploited — fix this first." if kev else "",
        "severity": _cvss_severity(cvss, kev),
    }


def _cvss_severity(cvss: float | None, kev: bool) -> str:
    if kev:
        return "critical"
    if cvss is None:
        return "medium"
    if cvss >= 9.0:
        return "critical"
    if cvss >= 7.0:
        return "high"
    if cvss >= 4.0:
        return "medium"
    return "low"


def _threat_lists() -> frozenset[str]:
    """The feed names that mean malware/phishing rather than advertising."""
    try:
        feedmod = importlib.import_module("homesoc.web.feed")
        names = getattr(feedmod, "THREAT_LISTS", None)
        if names:
            return frozenset(str(n).lower() for n in names)
    except Exception:  # pragma: no cover - feed module is part of this package
        logger.debug("feed.THREAT_LISTS unavailable", exc_info=True)
    return frozenset({"urlhaus", "threatfox", "openphish", "phishing_army", "feodo"})


def dns_section(
    conn: sqlite3.Connection,
    device: dict,
    *,
    hours: int = 24,
    enabled: bool | None = None,
    top: int = 8,
) -> dict:
    """What this device has been talking to, keyed on its current IP (B7).

    The honesty rules matter more than the numbers: ``note`` says so when the resolver is off,
    when the device changed address inside the window, when the address was shared with another
    device, or when nothing was logged at all.
    """
    ip = str(device.get("ip") or "")
    device_id = int(device.get("id") or 0)
    window_start = api.cutoff_iso(hours)
    since = window_start
    if enabled is None:
        # SPEC-GAP: lens_device has no config handle. Read the stored setting rather than
        # inferring from traffic: "nothing was logged in the window" is also what a quiet
        # network, log_queries=false and a retention purge look like, and telling the owner
        # their resolver is switched off when it is running is exactly the kind of confident
        # falsehood B7 forbids. An absent setting is reported as unknown, not as off.
        raw = api.get_setting(conn, "dns.enabled", "")
        enabled = api._bool(raw) if str(raw or "").strip() != "" else None

    out: dict[str, Any] = {
        "enabled": bool(enabled) if enabled is not None else None,
        "window_hours": hours,
        "total": 0,
        "blocked": 0,
        "block_rate": 0.0,
        "top_allowed": [],
        "top_blocked": [],
        "threats": [],
        "note": "",
        "client_ip": ip or None,
    }
    notes: list[str] = []
    if enabled is False:
        out["note"] = ("The DNS filter is switched off, so Home SOC cannot see what this device talks to. "
                       "Turn on dns.enabled and point this device's DNS at Home SOC to fill this in.")
        return out
    if enabled is None:
        notes.append("Home SOC could not tell whether the DNS filter is switched on, so what follows "
                     "is only what happens to be in the query log.")
    if not ip:
        out["note"] = " ".join(notes + [
            "Home SOC has no current IP address for this device, so its DNS traffic cannot be matched."
        ])
        return out

    # B7 honesty, the part that matters most: every query below is keyed on `client = <this
    # device's current IP>`, and a DHCP lease moves. Without a floor, a laptop that held this
    # address earlier in the window donates its lookups — threat-list hits included — to whatever
    # picked the address up afterwards, and the innocent device's card shows a malware hit and a
    # block rate that are somebody else's.
    #
    # The floor is only applied when the address really was shared: device_sightings holds one
    # row per scan, so "this device's earliest sighting at this IP" is the earliest scan in the
    # window, not the start of its tenure, and clamping to that unconditionally would throw away
    # traffic that is genuinely this device's. When another device was seen at the address, its
    # last sighting is the handover point, and this device's first sighting at or after it is
    # tighter still.
    handover = api.scalar(
        conn,
        "SELECT max(seen_at) FROM device_sightings WHERE ip=? AND device_id<>? AND seen_at>=?",
        (ip, device_id, window_start),
        None,
    )
    if handover:
        took_over = api.scalar(
            conn,
            "SELECT min(seen_at) FROM device_sightings WHERE device_id=? AND ip=? AND seen_at>=?",
            (device_id, ip, str(handover)),
            None,
        )
        since = max(window_start, str(handover), str(took_over or ""))

    agg = api.one(
        conn,
        "SELECT count(*) AS total, sum(action='block') AS blocked FROM dns_queries WHERE client=? AND ts>=?",
        (ip, since),
    ) or {}
    total = int(agg.get("total") or 0)
    blocked = int(agg.get("blocked") or 0)
    out["total"] = total
    out["blocked"] = blocked
    out["block_rate"] = round(blocked / total, 4) if total else 0.0

    limit = max(1, min(int(top), 50))
    out["top_allowed"] = [
        {"domain": r["domain"], "count": int(r["count"])}
        for r in api.rows(
            conn,
            "SELECT qname AS domain, count(*) AS count FROM dns_queries "
            "WHERE client=? AND ts>=? AND action IN ('allow','cache') GROUP BY qname ORDER BY count DESC, qname LIMIT ?",
            (ip, since, limit),
        )
    ]
    blocked_rows = api.rows(
        conn,
        "SELECT qname AS domain, count(*) AS count, max(reason) AS reason, max(ts) AS last_seen FROM dns_queries "
        "WHERE client=? AND ts>=? AND action='block' GROUP BY qname ORDER BY count DESC, qname LIMIT ?",
        (ip, since, max(limit, 25)),
    )
    out["top_blocked"] = [
        {"domain": r["domain"], "count": int(r["count"]), "reason": r.get("reason") or "blocklist"}
        for r in blocked_rows[:limit]
    ]

    threat_lists = _threat_lists()
    threats: dict[str, dict] = {}
    for r in blocked_rows:
        reason = str(r.get("reason") or "").lower()
        if reason in threat_lists or reason.startswith("reputation"):
            threats[str(r["domain"])] = {
                "domain": r["domain"],
                "count": int(r["count"]),
                "reason": r.get("reason") or "threat list",
                "last_seen": r.get("last_seen"),
            }
    for r in api.rows(
        conn,
        "SELECT q.qname AS domain, count(*) AS count, r.verdict AS verdict, r.source AS source, max(q.ts) AS last_seen "
        "FROM dns_queries q JOIN reputation r ON r.domain=q.qname "
        "WHERE q.client=? AND q.ts>=? AND r.verdict IN ('malicious','suspicious') "
        "GROUP BY q.qname ORDER BY count DESC, q.qname LIMIT ?",
        (ip, since, limit),
    ):
        domain = str(r["domain"])
        existing = threats.get(domain)
        reason = f"{r.get('verdict')} ({r.get('source')})"
        if existing is None:
            threats[domain] = {"domain": domain, "count": int(r["count"]), "reason": reason, "last_seen": r.get("last_seen")}
        else:
            existing["reason"] = f"{existing['reason']}, {reason}"
    out["threats"] = sorted(threats.values(), key=lambda t: (-int(t["count"]), str(t["domain"])))[:limit]

    # Honesty (B7): an address change inside the window means these figures are partial.
    other_ips = [
        str(r["ip"])
        for r in api.rows(
            conn,
            "SELECT DISTINCT ip FROM device_sightings WHERE device_id=? AND seen_at>=? AND ip<>?",
            (device_id, window_start, ip),
        )
    ]
    if other_ips:
        notes.append(
            f"This device also used {', '.join(other_ips[:3])} in the last {hours} hours, "
            f"so these figures only cover {ip} and are partial."
        )
    # ...and the other half of the same truth: somebody else held this address earlier.
    if handover:
        notes.append(
            f"{ip} was also used by another device inside this window, so only traffic from "
            f"{since} onwards is counted here."
        )
    if total == 0:
        notes.append(
            f"No DNS queries from {ip} were logged in the last {hours} hours — either the device is not using "
            "Home SOC as its resolver, or it has been quiet."
        )
    out["note"] = " ".join(notes)
    return out


def dependency_graph(conn: sqlite3.Connection, *, hours: int = DEPS_WINDOW_HOURS) -> tuple[dict | None, Any]:
    """``(map payload, engine (nodes, edges))`` for this identification, or ``(None, None)``.

    Built once and shared by :func:`deps_section` and :func:`blast_section`. That matters: the
    phone asks for this payload every time it recognises a sticker, and ``build_graph`` reads a
    week of ``dns_queries`` with a ``GROUP BY`` — under the connection's shared write lock, so a
    second build would stall the resolver's own writes as well as the card.

    ``homesoc.topology`` is a separate package that may not be installed, so this resolves through
    :func:`api.map_graph`, which imports it lazily and raises rather than exploding at import
    time. Anything that goes wrong answers ``(None, None)`` and costs the card two sections.
    """
    fn = getattr(api, "map_graph", None)
    if not callable(fn):  # an older api module: no map, and therefore no dependency lists
        return None, None
    engine_out: list = []
    unavailable = getattr(api, "TopologyUnavailable", None)
    try:
        payload = fn(conn, hours=int(hours), include_cloud=True, engine_out=engine_out)
    except TypeError:  # an api module whose map_graph predates engine_out
        logger.debug("map_graph rejected engine_out; calling it bare", exc_info=True)
        try:
            payload = fn(conn)
        except Exception:
            logger.debug("no dependency graph for Lens", exc_info=True)
            return None, None
    except Exception as exc:
        if unavailable is not None and isinstance(exc, unavailable):
            # The ordinary "topology is not installed here" case, not a fault.
            logger.debug("no dependency graph for Lens: %s", exc)
        else:
            logger.exception("could not build the dependency graph for Lens")
        return None, None
    if not isinstance(payload, dict):
        return None, None
    return payload, (engine_out[0] if engine_out else None)


def blast_section(conn: sqlite3.Connection, device_id: int, *, engine_graph: Any = None) -> dict | None:
    """"If this fails": what the house loses without this box (SPEC addendum C7).

    The single best use of the dependency map — point the phone at a box and learn what depends on
    it — so it ships inside the identification payload rather than costing a second round trip. It
    stays deliberately small: the headline, the two counts, the confidence and the evidence line,
    plus the packet-visibility note, and none of the three member lists.

    The engine lives in ``homesoc.topology``, which is a separate package and may not be installed:
    :func:`api.blast_summary` imports it lazily and answers ``None`` rather than raising, so a
    missing (or broken) topology package costs the phone this one section and nothing else.

    ``engine_graph`` is the cloud-inclusive ``(nodes, edges)`` :func:`dependency_graph` already
    built; handing it over produces exactly the same section without a second ``build_graph``.
    ``tests/test_lens_api.py::test_the_blast_section_is_identical_with_and_without_a_shared_graph``
    pins the two paths together so this reuse can never quietly change what the phone reads.
    """
    if engine_graph is not None:
        shared = _blast_from_graph(conn, device_id, engine_graph)
        if shared is not None:
            return shared
    fn = getattr(api, "blast_summary", None)
    if not callable(fn):  # an older api module: the overlay simply has no blast section
        return None
    try:
        return fn(conn, int(device_id))
    except Exception:  # belt and braces: this must never blank the rest of the card
        logger.exception("could not build the Lens blast section for device %s", device_id)
        return None


def _blast_from_graph(conn: sqlite3.Connection, device_id: int, engine_graph: Any) -> dict | None:
    """:func:`api.blast_summary`'s shape, from a graph the caller already paid for.

    Deliberately the same six keys in the same order: ``blast_summary`` is the contract the phone
    renders against, and this is only a cheaper route to it, never a second opinion.
    """
    fn = getattr(api, "map_blast", None)
    if not callable(fn):
        return None
    try:
        blast = fn(conn, int(device_id), engine_graph=engine_graph)
    except TypeError:  # an api module whose map_blast does not take a pre-built graph
        logger.debug("map_blast does not accept engine_graph; falling back", exc_info=True)
        return None
    except Exception:
        logger.debug("could not reuse the graph for the Lens blast section", exc_info=True)
        return None
    if not isinstance(blast, dict) or not isinstance(blast.get("counts"), dict):
        return None
    limit = int(getattr(api, "BLAST_TEXT_LIMIT", 400))
    return {
        "headline": api._text(blast.get("headline"), limit),
        "offline_count": int(blast["counts"]["offline"]),
        "degraded_count": int(blast["counts"]["degraded"]),
        "confidence": blast.get("confidence"),
        "evidence": api._text(blast.get("evidence"), limit) or None,
        "note": getattr(api, "MAP_NOTE", ""),
    }


# --------------------------------------------------------------------------- dependency lists


def _dep_text(value: Any) -> str:
    return api._text(value, DEPS_TEXT_LIMIT)


def _dep_label(node: dict, kind: str) -> str:
    """What to print for the other end of the relationship.

    A vendor label on its own ("Ring") hides the domain, which is the part someone standing in
    front of a camera can check; a provider label on its own ("Printing") hides which box offers
    it. Both are folded back in here, because the phone does no string building of its own.
    """
    label = str(node.get("label") or node.get("id") or "").strip()
    sub = str(node.get("sublabel") or "").strip()
    if not sub:
        return label
    if kind in ("cloud", "cloud_blocked"):
        # "ipcam-vendor.example" or "ring.com — blocked by the DNS filter".
        domain = sub.split(" — ")[0].strip()
        if domain and domain.lower() != label.lower():
            return f"{label} ({domain})"
        return label
    if kind == "service" and sub.lower().startswith("on "):
        # "on Epson printer — 1 confirmed consumer" -> "Printing on Epson printer".
        return f"{label} {sub.split(' — ')[0].strip()}".strip()
    return label


def _dep_entry(node: dict, kind: str, edge: dict, *, evidence: Any = None) -> dict:
    """One row of a Lens dependency list — small, already worded, nothing for the phone to do."""
    return {
        "label": _dep_label(node, kind),
        "kind": kind,
        "confidence": str(edge.get("confidence") or "inferred"),
        "evidence": _dep_text(edge.get("evidence") if evidence is None else evidence),
        # Present for anything that is a device on this network, null for the internet, the
        # resolver and external endpoints. The phone does not link anywhere today; the id is
        # here so it can, without a second shape.
        "device_id": node.get("device_id"),
    }


def _dep_sort_key(item: tuple[int, dict]) -> tuple:
    """Best-evidenced first: confidence band, then how much was actually counted, then name."""
    strength, entry = item
    return (
        _DEP_CONFIDENCE_RANK.get(str(entry.get("confidence") or ""), 9),
        -int(strength or 0),
        str(entry.get("label") or "").lower(),
    )


def _dep_cap(items: list[tuple[int, dict]]) -> tuple[list[dict], int]:
    """Sorted, capped at :data:`DEPS_LIMIT`, with however many were left behind."""
    ordered = sorted(items, key=_dep_sort_key)
    return [entry for _strength, entry in ordered[:DEPS_LIMIT]], max(0, len(ordered) - DEPS_LIMIT)


def _merge_evidence(keep: str, extra: str) -> str:
    if not extra or extra in keep:
        return keep
    if not keep:
        return _dep_text(extra)
    return _dep_text(f"{keep}; {extra}")


def deps_section(graph: dict | None, device_id: int) -> dict | None:
    """"Depends on" and "Depended on by" for the Lens card (SPEC addendum C7).

    The device page and /map have carried these lists since the feature shipped; the phone —
    the surface where you are actually standing in front of the box — had only the consequence.

    Two rules do all the work here, and both are the honesty rule of C1/C2 in list form:

    * **nothing is listed without an edge.** A printer that advertises printing and could
      plausibly serve five devices has no ``uses`` edge from any of them, so its "depended on by"
      list is empty and says so. Inventing rows for the devices that *might* print is exactly
      the lie the whole feature exists not to tell.
    * **a blocked domain is not a dependency.** The graph separates ``cloud`` from
      ``cloud_blocked`` (C2.4) and so does this: blocked endpoints come back in their own
      ``blocked`` list, never in ``depends_on``, because a camera hammering a telemetry endpoint
      the filter refuses is asking for something, not relying on it.

    ``graph`` is the payload from :func:`api.map_graph` — already normalised, already capped,
    already stripped of edges whose confidence the legend cannot explain. ``None`` when the
    topology package is unavailable, which the caller turns into ``deps: None``.
    """
    if not isinstance(graph, dict):
        return None
    try:
        device_id = int(device_id)
    except (TypeError, ValueError):
        return None
    nodes = {str(n.get("id")): n for n in (graph.get("nodes") or []) if isinstance(n, dict) and n.get("id")}
    edges = [e for e in (graph.get("edges") or []) if isinstance(e, dict)]
    me = f"device:{device_id}"
    empty = {
        "depends_on": [], "depends_on_more": 0,
        "depended_on_by": [], "depended_on_by_more": 0,
        "blocked": [], "blocked_more": 0,
    }
    if me not in nodes:
        return dict(empty, note=DEPS_UNMAPPED_NOTE)

    # ---- what this device depends on: every edge that leaves it.
    upstream: list[tuple[int, dict]] = []
    blocked: list[tuple[int, dict]] = []
    for edge in edges:
        if str(edge.get("src")) != me:
            continue
        edge_type = str(edge.get("edge_type") or "")
        kind = DEP_KIND_BY_EDGE.get(edge_type)
        other = nodes.get(str(edge.get("dst")))
        if kind is None or other is None:
            continue
        if edge_type == "uses" and str(other.get("kind") or "") != "provider":
            # A co-drop that cannot say *which* service was involved points at the box itself
            # (C2.5), and calling that box "a service" would name something the evidence did not.
            kind = "device"
        strength = int(edge.get("observed_count") or 0)
        (blocked if kind == "cloud_blocked" else upstream).append((strength, _dep_entry(other, kind, edge)))

    # ---- what depends on this device. Two sources, and neither is "who might plausibly".
    downstream: dict[str, tuple[int, dict]] = {}

    def remember(node: dict, edge: dict, *, evidence: Any = None) -> None:
        node_id = str(node.get("id") or "")
        if not node_id or node_id == me:
            return
        entry = _dep_entry(node, "device", edge, evidence=evidence)
        strength = int(edge.get("observed_count") or 0)
        previous = downstream.get(node_id)
        if previous is None:
            downstream[node_id] = (strength, entry)
            return
        # A device can both route through this one and use a service on it. That is one row
        # saying both things, ranked by the stronger of the two claims.
        best = min([(strength, entry), previous], key=_dep_sort_key)
        other = previous if best[1] is entry else (strength, entry)
        best[1]["evidence"] = _merge_evidence(best[1]["evidence"], other[1]["evidence"])
        downstream[node_id] = (max(strength, previous[0]), best[1])

    for edge in edges:
        if str(edge.get("dst")) != me or str(edge.get("edge_type") or "") not in DEP_INBOUND_EDGES:
            continue
        other = nodes.get(str(edge.get("src")))
        if other is not None:
            remember(other, edge)

    # Services this device offers, and the devices *seen* using them (C2.5). A provider with no
    # ``uses`` edge contributes no rows at all — it contributes a sentence to ``note`` instead.
    hosted: list[dict] = [
        node
        for node in (nodes.get(str(e.get("src"))) for e in edges
                     if str(e.get("dst")) == me and str(e.get("edge_type") or "") == "hosted_by")
        if node is not None
    ]
    hosted_ids = {str(n.get("id")) for n in hosted}
    consumed: set[str] = set()
    for edge in edges:
        if str(edge.get("edge_type") or "") != "uses" or str(edge.get("dst")) not in hosted_ids:
            continue
        consumed.add(str(edge.get("dst")))
        other = nodes.get(str(edge.get("src")))
        if other is not None:
            remember(other, edge)

    depends_on, depends_on_more = _dep_cap(upstream)
    depended_on_by, depended_on_by_more = _dep_cap(list(downstream.values()))
    blocked_rows, blocked_more = _dep_cap(blocked)

    return {
        "depends_on": depends_on,
        "depends_on_more": depends_on_more,
        "depended_on_by": depended_on_by,
        "depended_on_by_more": depended_on_by_more,
        # Kept out of ``depends_on`` on purpose (C2.4): asked for, not depended on.
        "blocked": blocked_rows,
        "blocked_more": blocked_more,
        "note": _deps_note([n for n in hosted if str(n.get("id")) not in consumed], bool(downstream)),
    }


def _deps_note(orphan_providers: list[dict], has_dependents: bool) -> str:
    """The honesty line under the lists, plus the "no confirmed consumers" case spelled out.

    This is the sentence the printer exists to produce: it advertises printing, five devices
    could plausibly use it, none has been seen doing so, and the card says that in words rather
    than leaving an empty list to be read as a bug.
    """
    names = sorted({label for label in (str(n.get("label") or "").strip() for n in orphan_providers) if label})
    if not names:
        return DEPS_NOTE
    # The engine's own labels, verbatim and in a parenthetical, so they need no grammatical
    # surgery: "Camera stream" and "DNS resolution" both read correctly there, and neither has
    # to be lower-cased into "camera stream" or mangled into "dNS resolution".
    offered = f"the {'service' if len(names) == 1 else 'services'} it offers ({', '.join(names)})"
    tail = (
        f"Nothing has been seen using {offered}; anything listed here depends on it for "
        "another reason."
        if has_dependents
        else f"Nothing has been seen using {offered}, so nothing is listed as depending on it."
    )
    return f"{DEPS_NOTE} {tail}"


def timeline(conn: sqlite3.Connection, device: dict, *, limit: int = TIMELINE_LIMIT) -> list[dict]:
    """The device's slice of the activity feed (A2), so Lens and the feed can never disagree."""
    device_id = int(device.get("id") or 0)
    ip = str(device.get("ip") or "")
    mac = str(device.get("mac") or "")
    try:
        feedmod = importlib.import_module("homesoc.web.feed")
        # Bounded to this device in SQL, not filtered out of a whole-network page afterwards.
        # The old shape asked for the busiest 500 rows on the network and then kept this
        # device's: a few normal days of DNS blocks from other clients pushed a camera's own
        # threat hits off the end and the phone rendered "Nothing recorded for this device yet",
        # which was false. It is also far cheaper — no 500-row global merge per card.
        items, _ = feedmod.build_feed(
            conn,
            since=api.cutoff_iso(TIMELINE_WINDOW_HOURS),
            limit=max(int(limit) * 3, 60),
            device=feedmod.DeviceFilter(device_id=device_id, ip=ip, mac=mac),
        )
    except TypeError:  # an older feed module without the device filter: fall back, still bounded
        try:
            items, _ = feedmod.build_feed(
                conn, since=api.cutoff_iso(TIMELINE_WINDOW_HOURS), limit=feedmod.MAX_LIMIT
            )
        except Exception:
            logger.exception("could not build the Lens timeline")
            return []
    except Exception:  # a broken feed must not blank the whole overlay
        logger.exception("could not build the Lens timeline")
        return []

    out: list[dict] = []
    for item in items:
        ref = item.ref if isinstance(item.ref, dict) else {}
        link = str(item.link or "")
        hit = (
            (ref.get("device_id") is not None and int(ref["device_id"] or 0) == device_id)
            or link == f"/devices/{device_id}"
            or (bool(ip) and str(ref.get("client") or "") == ip)
            or (bool(ip) and str(ref.get("ip") or "") == ip)
            or (bool(mac) and str(ref.get("mac") or "") == mac)
            or (bool(mac) and mac in str(ref.get("subject") or ""))
        )
        if not hit:
            continue
        out.append({"ts": item.ts, "kind": item.kind, "severity": item.severity, "title": item.title})
        if len(out) >= limit:
            break
    return out


def lens_device(
    conn: sqlite3.Connection,
    device_id: int,
    *,
    hours: int = 24,
    dns_enabled: bool | None = None,
    actions: dict | None = None,
) -> dict:
    """Everything the phone renders over the camera image, in one round trip (B7).

    ``dns_enabled`` and ``actions`` come from config and the caller's scopes, which this module
    has no handle on; both default to the safe answer (infer / everything forbidden).
    """
    hours = max(1, min(int(hours or 24), 24 * 30))
    # Flask's <int:device_id> converter happily accepts a 20-digit id, and SQLite raises
    # OverflowError ("Python int too large to convert to SQLite INTEGER") rather than simply
    # not matching — a 500 with a traceback in the log for any paired phone that asks. Every
    # other bound on this surface is clamped; this one is too. Out of range is "no such device".
    try:
        device_id = int(device_id)
    except (TypeError, ValueError):
        return {}
    if not (0 < device_id <= 2**63 - 1):
        return {}
    ensure_tables(conn)
    device = api.device_detail(conn, device_id)
    if device is None:
        return {}

    findings = list(device.get("findings") or [])
    open_findings = [f for f in findings if str(f.get("status") or "") == "open"]
    services = [service_view(s) for s in (device.get("services") or [])]
    services.sort(key=lambda s: (api.SEVERITIES.index(s["risk"]) if s["risk"] in api.SEVERITIES else 9, s["port"]))
    vulns = [vuln_view(v) for v in (device.get("vulns") or [])]
    vulns.sort(key=lambda v: (not v["kev"], -(v["cvss"] or 0.0), v["cve"]))

    counts = _severity_counts(open_findings)
    contribution = sum(api.SCORE_PENALTY.get(sev, 0) * n for sev, n in counts.items())

    # One graph, two sections. Both "if this fails" and the two relationship lists are views of
    # the same dependency graph, and building it twice per identification is the cost the
    # ``engine_graph`` seam in ``api`` exists to avoid.
    graph, engine_graph = dependency_graph(conn)

    payload = {
        "device": {
            "id": int(device["id"]),
            "nickname": device.get("nickname"),
            "hostname": device.get("hostname"),
            "ip": device.get("ip"),
            "mac": device.get("mac"),
            "vendor": device.get("vendor"),
            "kind": device.get("kind"),
            "trusted": api._bool(device.get("trusted")),
            "online": api._bool(device.get("online")),
            "first_seen": device.get("first_seen"),
            "last_seen": device.get("last_seen"),
            "last_service_scan": device.get("last_service_scan"),
            "display_name": device.get("display_name"),
        },
        "posture": {
            "score_contribution": contribution,
            "severity_counts": counts,
            "headline": headline(device, open_findings, scanned=bool(device.get("last_service_scan"))),
        },
        # None when the topology package is not installed (C7) — the key is always present so the
        # phone can tell "nothing depends on this" from "this install cannot answer that".
        "blast": blast_section(conn, int(device["id"]), engine_graph=engine_graph),
        # The relationships behind that consequence: what this device leans on, and what leans on
        # it. Same three-state contract as ``blast`` — null means "this install cannot answer",
        # empty lists mean "nothing has been established", which is a real answer and is said out
        # loud rather than hidden.
        "deps": deps_section(graph, int(device["id"])),
        "services": services,
        "vulns": vulns,
        "findings": [
            {
                "row_id": int(f.get("id") or 0),
                "finding_id": f.get("finding_id"),
                "severity": str(f.get("severity") or "info").lower(),
                "title": f.get("title"),
                "detail": f.get("detail"),
                "status": f.get("status"),
                "first_seen": f.get("first_seen"),
                "remediation": list(f.get("remediation") or []),
                "refs": list(f.get("refs") or []),
            }
            for f in _findings_worst_first(findings)[:50]
        ],
        "dns": dns_section(conn, device, hours=hours, enabled=dns_enabled),
        "timeline": timeline(conn, device),
        "actions": {
            "can_rescan": bool((actions or {}).get("can_rescan")),
            "can_acknowledge": bool((actions or {}).get("can_acknowledge")),
            "can_set_trusted": bool((actions or {}).get("can_set_trusted")),
        },
        "tags": [
            {"kind": t.get("kind"), "label": t.get("label"), "scans": int(t.get("scans") or 0)}
            for t in tags_for_device(conn, int(device["id"]))
        ],
        "generated_at": api.now_iso(),
    }
    return payload


def _findings_worst_first(findings: list[dict]) -> list[dict]:
    def key(f: dict) -> tuple:
        status = str(f.get("status") or "")
        sev = str(f.get("severity") or "info").lower()
        return (
            0 if status == "open" else 1 if status == "acknowledged" else 2,
            api.SEVERITIES.index(sev) if sev in api.SEVERITIES else 9,
            str(f.get("first_seen") or ""),
        )

    return sorted(findings, key=key)


# --------------------------------------------------------------------------- tokens (B4)
#
# The token table, pairing codes and the claim rate limit are owned by the transport package and
# live as ``db.lens_*`` functions on ``homesoc.db``. Everything below delegates to them so a code
# minted by ``/lens/pair`` is redeemable here, and falls back to a local B4/B10-conformant
# implementation when that layer is absent, so identification is testable on its own.

_L1_MODULES: tuple[str, ...] = ("homesoc.db", "homesoc.web.lens_auth", "homesoc.web.lens_tokens")


def _l1(*names: str) -> Any | None:
    """The first callable named ``names`` on the transport layer, else ``None``.

    Names are tried both bare and with the ``lens_`` prefix ``homesoc.db`` uses.
    """
    for module_name in _L1_MODULES:
        try:
            module = importlib.import_module(module_name)
        except ImportError:
            continue
        for name in names:
            for candidate in (name, "lens_" + name):
                fn = getattr(module, candidate, None)
                if callable(fn):
                    return fn
    return None


def token_hash(token: str) -> str:
    return hashlib.sha256(str(token or "").encode("utf-8")).hexdigest()


def parse_scopes(value: Any) -> list[str]:
    """``"read,act"`` / ``"read act"`` / ``["read"]`` -> the canonical ordered list."""
    if isinstance(value, (list, tuple, set)):
        raw = [str(v).strip().lower() for v in value]
    else:
        raw = str(value or "").replace(",", " ").split()
    return [s for s in (SCOPE_READ, SCOPE_ACT) if s in raw]


def verify_token(conn: sqlite3.Connection, presented: Any, *, ip: str | None = None) -> dict | None:
    """``{id, label, scopes}`` for a live paired phone, or ``None``.

    Only the SHA-256 of a token is ever stored and the comparison is ``secrets.compare_digest``,
    so a wrong token, a revoked one and an expired one are indistinguishable from outside.
    """
    delegate = _l1("verify_token")
    if delegate is not None:
        try:
            row = delegate(conn, presented, ip=ip)
        except TypeError:
            row = delegate(conn, presented)
        except Exception:
            logger.exception("token verification failed")
            return None
        if not isinstance(row, dict):
            return None if not row else {"id": None, "label": "paired phone", "scopes": [SCOPE_READ]}
        return {
            "id": row.get("id"),
            "label": str(row.get("label") or "paired phone"),
            "scopes": parse_scopes(row.get("scopes")),
        }

    token = str(presented or "")
    if not token or len(token) > 512:
        return None
    ensure_tables(conn)
    wanted = token_hash(token)
    now = api.now_iso()
    match: dict | None = None
    for row in api.rows(conn, "SELECT * FROM lens_tokens WHERE revoked_at IS NULL"):
        if not secrets.compare_digest(str(row.get("token_hash") or ""), wanted):
            continue
        expires = str(row.get("expires_at") or "")
        if expires and expires <= now:
            return None
        match = row
        break
    if match is None:
        return None
    api.write(
        conn,
        "UPDATE lens_tokens SET last_seen_at=?, last_ip=? WHERE id=?",
        (now, (str(ip or "")[:45]) or None, int(match["id"])),
    )
    return {
        "id": int(match["id"]),
        "label": str(match.get("label") or "paired phone"),
        "scopes": parse_scopes(match.get("scopes")),
    }


def active_token_count(conn: sqlite3.Connection) -> int:
    """How many phones are currently paired (revoked and expired rows do not count)."""
    delegate = _l1("active_tokens")
    if delegate is not None:
        try:
            return len(delegate(conn) or [])
        except Exception:
            logger.exception("could not count active Lens tokens")
    ensure_tables(conn)
    return int(
        api.scalar(
            conn,
            "SELECT count(*) FROM lens_tokens WHERE revoked_at IS NULL AND (expires_at IS NULL OR expires_at>?)",
            (api.now_iso(),),
            0,
        )
    )


RATE_LIMIT_MESSAGE = "too many Lens pairing attempts; refusing this source for an hour"

# Fallback claim counters, used only when the transport layer is absent. In memory on purpose:
# this is abuse control for a LAN service, not an audit trail.
_claim_lock = threading.Lock()
_claim_attempts: dict[str, list[float]] = {}


def claim_allowed(conn: sqlite3.Connection, ip: str | None, *, now: float | None = None) -> tuple[bool, int]:
    """``(allowed, retry_after_seconds)`` for one claim attempt from ``ip`` (B4).

    Ten attempts per hour per source address; the eleventh locks that address out for an hour
    and writes an ``events`` row so a burst of guesses is visible in the activity feed.
    """
    delegate = _l1("claim_attempt")
    if delegate is not None:
        try:
            allowed, retry = delegate(conn, ip)
            return bool(allowed), int(retry or 0)
        except Exception:
            logger.exception("claim rate limiting failed; falling back to the local counter")
    stamp = time.time() if now is None else now
    key = str(ip or "unknown")[:45]
    with _claim_lock:
        attempts = [t for t in _claim_attempts.get(key, []) if stamp - t < CLAIM_WINDOW_SEC]
        tripped = len(attempts) >= CLAIM_MAX_ATTEMPTS
        if not tripped:
            attempts.append(stamp)
        _claim_attempts[key] = attempts
    if tripped:
        api._record_event(conn, "warning", "lens", RATE_LIMIT_MESSAGE,
                          {"limit": CLAIM_MAX_ATTEMPTS, "source": key})
        return False, CLAIM_WINDOW_SEC
    return True, 0


def claim_reset(conn: sqlite3.Connection, ip: str | None) -> None:
    """Forget one address's attempt counter, called after a successful claim."""
    delegate = _l1("claim_reset")
    if delegate is not None:
        try:
            delegate(conn, ip)
        except Exception:
            logger.exception("could not reset the claim counter")
    with _claim_lock:
        _claim_attempts.pop(str(ip or "unknown")[:45], None)


def reset_claim_limits(conn: sqlite3.Connection | None = None) -> None:
    """Drop every claim counter. For tests, and for ``lens.enabled`` going false."""
    with _claim_lock:
        _claim_attempts.clear()
    if conn is None:
        return
    for row in api.rows(conn, "SELECT key FROM settings WHERE key LIKE 'lens.claim.%'"):
        api.write(conn, "DELETE FROM settings WHERE key=?", (str(row["key"]),))


def _pairing_setting_key() -> str:
    # SPEC-GAP: B4 says the pairing code lives in ``settings`` but does not name the key.
    return "lens.pairing"


def mint_pairing_code(conn: sqlite3.Connection, *, minutes: int = 5) -> str:
    """Single-use pairing code, returned once and stored only as a hash (B4/B10).

    The desktop ``/lens/pair`` page mints through the same helper, so a code shown there is
    exactly the code ``/api/lens/claim`` will accept.
    """
    delegate = _l1("new_pairing_code", "mint_pairing_code", "create_pairing_code")
    if delegate is not None:
        try:
            return str(delegate(conn))
        except Exception:
            logger.exception("pairing-code minting failed; using the local fallback")
    alphabet = "23456789ABCDEFGHJKMNPQRSTUVWXYZ"  # no look-alike characters
    code = "".join(secrets.choice(alphabet) for _ in range(8))
    expires = (api.utcnow() + timedelta(minutes=max(1, int(minutes)))).strftime("%Y-%m-%dT%H:%M:%SZ")
    api.set_setting(conn, _pairing_setting_key(), json.dumps({"hash": token_hash(code), "expires_at": expires}))
    return code


BAD_CODE_MESSAGE = "That pairing code is wrong, already used, or has expired. Generate a new one on the dashboard."


def _consume_pairing_code(conn: sqlite3.Connection, presented: str) -> bool:
    delegate = _l1("consume_pairing_code", "redeem_pairing_code")
    if delegate is not None:
        try:
            return bool(delegate(conn, presented))
        except Exception:
            logger.exception("could not consume the pairing code")
            return False
    stored = api.loads(api.get_setting(conn, _pairing_setting_key()), None)
    if not isinstance(stored, dict):
        return False
    expires_at = str(stored.get("expires_at") or "")
    if expires_at and expires_at <= api.now_iso():
        api.set_setting(conn, _pairing_setting_key(), "")
        return False
    if not secrets.compare_digest(str(stored.get("hash") or ""), token_hash(presented)):
        return False
    api.set_setting(conn, _pairing_setting_key(), "")  # single use
    return True


def claim(conn: sqlite3.Connection, code: Any, *, ip: str | None = None, label: str | None = None,
          ttl_days: int = 90, max_tokens: int = 10, allow_actions: bool = False) -> dict:
    """Exchange a pairing code for a long-lived, scoped Lens token (B4).

    The token exists in the response and nowhere else: only its SHA-256 is stored. The
    ``max_tokens`` ceiling is checked *before* the code is spent, so hitting the limit does not
    silently burn the user's pairing code.
    """
    presented = str(code or "").strip()
    if not presented or len(presented) > 64:
        return {"ok": False, "error": BAD_CODE_MESSAGE}
    ensure_tables(conn)
    limit = max(1, int(max_tokens or 1))
    if active_token_count(conn) >= limit:
        return {
            "ok": False,
            "error": f"{limit} phones are already paired; revoke one first "
                     f"(python -m homesoc lens revoke <id>).",
        }
    if not _consume_pairing_code(conn, presented):
        return {"ok": False, "error": BAD_CODE_MESSAGE}

    name = (str(label or "").strip()[:60]) or "paired phone"
    scopes = "read,act" if allow_actions else "read"
    mint = _l1("mint_token")
    if mint is not None:
        try:
            row = mint(conn, label=name, scopes=scopes, ttl_days=int(ttl_days or 0), max_tokens=limit)
        except Exception as exc:  # LensTokenLimit, and anything else the token layer refuses with
            logger.warning("minting a Lens token was refused: %s", exc)
            return {"ok": False, "error": str(exc)[:200]}
        return {
            "ok": True,
            "token": row.get("token"),
            "label": row.get("label") or name,
            "scopes": parse_scopes(row.get("scopes")),
            "expires_at": row.get("expires_at"),
        }

    token = secrets.token_urlsafe(32)
    expiry = None
    if int(ttl_days or 0) > 0:
        expiry = (api.utcnow() + timedelta(days=int(ttl_days))).strftime("%Y-%m-%dT%H:%M:%SZ")
    api.write(
        conn,
        "INSERT INTO lens_tokens(token_hash, label, scopes, created_at, last_ip, expires_at) VALUES(?,?,?,?,?,?)",
        (token_hash(token), name, scopes, api.now_iso(), (str(ip or "")[:45]) or None, expiry),
    )
    return {"ok": True, "token": token, "label": name, "scopes": parse_scopes(scopes), "expires_at": expiry}


__all__ = [
    "Match",
    "DEPS_LIMIT",
    "DEPS_NOTE",
    "PORT_INFO",
    "STICKER_PREFIX",
    "blast_section",
    "claim",
    "claim_allowed",
    "claim_reset",
    "dependency_graph",
    "deps_section",
    "dns_section",
    "ensure_tables",
    "forget_tag",
    "headline",
    "identify",
    "learn_tag",
    "TagExists",
    "lens_device",
    "mint_pairing_code",
    "mint_sticker_codes",
    "new_sticker_code",
    "normalise_code",
    "parse_scopes",
    "rank_candidates",
    "reset_claim_limits",
    "service_view",
    "tag_for_code",
    "tags_for_device",
    "timeline",
    "token_hash",
    "verify_token",
    "vuln_view",
]
