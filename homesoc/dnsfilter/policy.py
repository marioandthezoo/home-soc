"""Blocking policy: overrides → never-block → blocklists → reputation → allow (SPEC §12).

Matching walks the labels of a name from most to least specific (``a.b.example.com`` → ``b.example.com``
→ ``example.com`` → ``com``) so every lookup costs at most ``len(labels)`` set/dict probes regardless
of how large the lists are. All list entries therefore act as suffix rules, which is what hosts-style
and wildcard-style feeds both intend for a DNS sinkhole.
"""
from __future__ import annotations

import ipaddress
import logging
import os
import re
import sqlite3
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Iterator
from urllib.parse import urlsplit

from homesoc.dnsfilter import cfg_get, db_query, db_write, utcnow_iso

logger = logging.getLogger(__name__)

RELOAD_CHECK_SECONDS = 60.0
STALE_LIST_DAYS = 3
MAX_LINE = 253
_DOMAIN_RE = re.compile(r"^(?=.{1,253}$)[a-z0-9_](?:[a-z0-9_-]{0,62}[a-z0-9_])?(?:\.[a-z0-9_](?:[a-z0-9_-]{0,62}[a-z0-9_])?)+$")
_SKIP_HOSTS = frozenset(
    {"localhost", "localhost.localdomain", "local", "broadcasthost", "ip6-localhost", "ip6-loopback",
     "ip6-localnet", "ip6-mcastprefix", "ip6-allnodes", "ip6-allrouters", "ip6-allhosts", "0.0.0.0"}
)

# SPEC-GAP: the spec names localhost, *.local, *.arpa and the upstreams' names; the other private-use
# suffixes (RFC 6762 §4 / RFC 8375 / common router defaults) are added because blocking a LAN name is
# never useful and some ad lists contain entries like "home" by mistake.
NEVER_BLOCK_SUFFIXES: frozenset[str] = frozenset(
    {"localhost", "local", "arpa", "home.arpa", "lan", "home", "internal", "localdomain", "intranet", "corp", "private"}
)


@dataclass(frozen=True)
class Decision:
    action: str            # "allow" | "block"
    reason: str            # e.g. "override:allow", "never_block", "list:oisd_small", "reputation", "default"
    matched: str | None = None  # the list entry / override domain that matched, if any

    @property
    def blocked(self) -> bool:
        return self.action == "block"


@dataclass
class ListStatus:
    name: str
    path: Path | None
    entries: int = 0
    mtime: float | None = None
    loaded: bool = False
    error: str | None = None


def normalize_name(name: str) -> str:
    return name.strip().rstrip(".").lower()


def iter_suffixes(name: str) -> Iterator[str]:
    """``a.b.c`` → ``a.b.c``, ``b.c``, ``c`` (most specific first)."""
    labels = name.split(".")
    for i in range(len(labels)):
        yield ".".join(labels[i:])


# ---- list parsing -------------------------------------------------------------------------------
def parse_list_line(line: str) -> str | None:
    """Extract one domain from a line of any supported feed format, or None.

    Handles hosts files (``0.0.0.0 dom``), ABP (``||dom^``), wildcard (``*.dom``), URLs and plain
    domains. Untrusted input: length-limited, regex-validated, never evaluated.
    """
    s = line.strip()
    if not s or len(s) > 2048:
        return None
    if s[0] in "#!;[":
        return None
    if "#" in s:
        s = s.split("#", 1)[0].strip()
    if not s:
        return None
    if s.startswith("@@"):  # ABP exception rule — not a block entry
        return None
    if s.startswith("||"):
        body = s[2:]
        for sep in ("^", "/", "$", "|"):
            body = body.split(sep, 1)[0]
        s = body
    elif "://" in s:
        try:
            s = urlsplit(s).hostname or ""
        except ValueError:
            return None
    else:
        parts = s.split()
        if len(parts) >= 2 and _looks_like_ip(parts[0]):
            s = parts[1]
        elif len(parts) > 1:
            return None
    if s.startswith("*."):
        s = s[2:]
    if s.startswith("."):
        s = s[1:]
    s = s.rstrip(".").lower()
    if not s or len(s) > MAX_LINE or s in _SKIP_HOSTS:
        return None
    if ":" in s or _looks_like_ip(s):
        return None
    if not _DOMAIN_RE.match(s):
        return None
    return s


def _looks_like_ip(token: str) -> bool:
    try:
        ipaddress.ip_address(token)
        return True
    except ValueError:
        return False


def parse_list_text(text: str) -> set[str]:
    out: set[str] = set()
    for line in text.splitlines():
        d = parse_list_line(line)
        if d:
            out.add(d)
    return out


def load_list_file(path: Path, *, max_bytes: int = 256 * 1024 * 1024) -> set[str]:
    """Parse a list file line by line (never ``read()`` + ``splitlines()``: that triples the peak
    memory of a 64 MB list) and close it before the caller merges, keeping the window in which
    ``os.replace`` of a fresh download can collide on Windows as short as possible."""
    size = path.stat().st_size
    if size > max_bytes:
        raise ValueError(f"{path.name} is {size} bytes; refusing to load > {max_bytes}")
    out: set[str] = set()
    with path.open("r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            d = parse_list_line(line)
            if d:
                out.add(d)
    return out


# ---- feed file location -------------------------------------------------------------------------
def _feeds_dir() -> Path:
    try:
        from homesoc.paths import feeds_dir  # type: ignore

        return Path(feeds_dir())
    except Exception:
        env = os.environ.get("HOMESOC_DATA")
        if env:
            return Path(env) / "feeds"
        here = Path(__file__).resolve()
        for parent in here.parents:
            if (parent / "pyproject.toml").exists():
                return parent / "data" / "feeds"
        return here.parents[2] / "data" / "feeds"


# A list name becomes part of a file path, so it is held to the feed registry's naming: lowercase
# letters, digits, '_' and '-'. No dot, separator, drive letter or UNC prefix can reach the filesystem
# (``../../x``, ``C:\x`` and ``//host/share/x`` all used to be joined onto the feeds folder, turning
# any readable file into a blocklist and making Windows authenticate to the named SMB server).
_LIST_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")


def valid_list_name(name: str, list_dir: Path | None = None) -> bool:
    """True when ``name`` may be used as a ``dns.lists`` entry.

    With the real feeds folder (``list_dir`` None) the name must also be a feed in
    ``homesoc.feeds.registry``; an explicit ``list_dir`` (tests, tools) only needs the grammar.
    """
    if not isinstance(name, str) or not _LIST_NAME_RE.match(name):
        return False
    if list_dir is not None:
        return True
    try:
        from homesoc.feeds import registry  # type: ignore
    except Exception:  # registry unavailable: the grammar alone already keeps the path in the folder
        return True
    return name in registry.FEEDS


def _is_within(path: Path, base: Path) -> bool:
    try:
        return path.resolve().is_relative_to(base.resolve())
    except (OSError, ValueError):
        return False


def find_list_file(name: str, list_dir: Path | None = None) -> Path | None:
    """Locate a feed's on-disk file: the feeds package's ``feed_path`` first, then common names.

    Only valid list names are looked up (see ``valid_list_name``), and a candidate must resolve to a
    file inside the feeds folder, so a symlink planted there cannot point the policy elsewhere.
    """
    if not valid_list_name(name, list_dir):
        return None
    if list_dir is None:
        try:
            from homesoc.feeds import updater  # type: ignore

            p = Path(updater.feed_path(name))
            if p.is_file() and _is_within(p, p.parent):
                return p
        except Exception:
            pass
    base = list_dir if list_dir is not None else _feeds_dir()
    for candidate in (base / name, base / f"{name}.txt", base / f"{name}.list", base / f"{name}.hosts"):
        if candidate.is_file() and _is_within(candidate, base):
            return candidate
    return None


# ---- overrides table helpers (dnsfilter owns dns_overrides) -------------------------------------
def add_override(conn: sqlite3.Connection, domain: str, action: str, note: str | None = None) -> str:
    d = normalize_name(domain)
    if action not in ("allow", "deny"):
        raise ValueError("action must be allow or deny")
    if not d or (d != "localhost" and not _DOMAIN_RE.match(d)):
        raise ValueError("invalid domain")
    db_write(
        conn,
        "INSERT INTO dns_overrides(domain, action, note, created_at) VALUES (?,?,?,?)"
        " ON CONFLICT(domain) DO UPDATE SET action = excluded.action, note = excluded.note, created_at = excluded.created_at",
        (d, action, note, utcnow_iso()),
    )
    return d


def remove_override(conn: sqlite3.Connection, domain: str) -> bool:
    d = normalize_name(domain)
    before = db_query(conn, "SELECT 1 FROM dns_overrides WHERE domain = ?", (d,))
    db_write(conn, "DELETE FROM dns_overrides WHERE domain = ?", (d,))
    return bool(before)


def list_overrides(conn: sqlite3.Connection) -> list[dict]:
    rows = db_query(conn, "SELECT domain, action, note, created_at FROM dns_overrides ORDER BY created_at DESC, domain")
    return [dict(r) for r in rows]


# ---- the policy ---------------------------------------------------------------------------------
class Policy:
    """Immutable-per-reload lookup tables; ``decide`` is lock-free and safe from any thread."""

    def __init__(
        self,
        *,
        list_names: Iterable[str] = (),
        never_block: Iterable[str] = (),
        min_malicious_votes: int = 2,
        reputation_ttl_hours: float = 72,
        list_dir: Path | None = None,
        conn: sqlite3.Connection | None = None,
    ) -> None:
        self.list_names = [n for n in list_names if n]
        for n in self.list_names:
            if not valid_list_name(n, list_dir):
                logger.warning("ignoring DNS list name %r: not a feed from the registry", str(n)[:80])
        self.never_block: frozenset[str] = frozenset(NEVER_BLOCK_SUFFIXES | {normalize_name(n) for n in never_block if n})
        self.min_malicious_votes = max(1, int(min_malicious_votes))
        self.reputation_ttl_hours = float(reputation_ttl_hours)
        self.list_dir = list_dir
        self.conn = conn
        self._blocked: dict[str, str] = {}          # domain -> list name (the only per-entry container kept)
        self._overrides: dict[str, str] = {}        # domain -> allow|deny
        self._override_sig: tuple = ()              # (count, max created_at) of dns_overrides last seen
        self._malicious: frozenset[str] = frozenset()
        self.lists: dict[str, ListStatus] = {n: ListStatus(n, None) for n in self.list_names}
        self._last_check = 0.0
        self._reload_lock = threading.Lock()
        self.loaded_at: float | None = None

    # ---- construction ---------------------------------------------------------------------
    @classmethod
    def load(cls, cfg, conn: sqlite3.Connection | None, *, list_dir: Path | None = None) -> "Policy":
        names = list(cfg_get(cfg, "dns", "lists", []) or [])
        never = set()
        for u in cfg_get(cfg, "dns", "upstreams", []) or []:
            host = str(u).split(":")[0] if str(u).count(":") == 1 else str(u).strip("[]")
            if host and not _looks_like_ip(host):
                never.add(host)
        doh = cfg_get(cfg, "dns", "doh_upstream", "") or ""
        if doh:
            try:
                h = urlsplit(doh).hostname
                if h:
                    never.add(h)
            except ValueError:
                pass
        p = cls(
            list_names=names,
            never_block=never,
            min_malicious_votes=int(cfg_get(cfg, "dns", "reputation_min_malicious_votes", 2) or 2),
            reputation_ttl_hours=float(cfg_get(cfg, "dns", "reputation_ttl_hours", 72) or 72),
            list_dir=list_dir,
            conn=conn,
        )
        p.reload(force=True)
        return p

    # ---- decisions ------------------------------------------------------------------------
    def decide(self, qname: str, qtype: str = "A", client: str = "") -> Decision:
        name = normalize_name(qname)
        if not name:
            return Decision("allow", "default")
        overrides, blocked, malicious = self._overrides, self._blocked, self._malicious
        # 1+2: overrides (allow beats deny even when a deny is more specific — the user asked for it)
        if overrides:
            deny_hit: str | None = None
            for s in iter_suffixes(name):
                act = overrides.get(s)
                if act == "allow":
                    return Decision("allow", "override:allow", s)
                if act == "deny" and deny_hit is None:
                    deny_hit = s
            if deny_hit is not None:
                return Decision("block", "override:deny", deny_hit)
        # 3: never-block
        for s in iter_suffixes(name):
            if s in self.never_block:
                return Decision("allow", "never_block", s)
        # 4: blocklists
        for s in iter_suffixes(name):
            src = blocked.get(s)
            if src is not None:
                return Decision("block", f"list:{src}", s)
        # 5: reputation
        for s in iter_suffixes(name):
            if s in malicious:
                return Decision("block", "reputation", s)
        return Decision("allow", "default")

    def is_never_block(self, qname: str) -> bool:
        return any(s in self.never_block for s in iter_suffixes(normalize_name(qname)))

    # ---- reload -------------------------------------------------------------------------
    def maybe_reload(self, *, now: float | None = None, force: bool = False) -> bool:
        """Cheap to call per query or per tick: re-checks file mtimes at most every 60 s."""
        now = time.monotonic() if now is None else now
        if not force and now - self._last_check < RELOAD_CHECK_SECONDS:
            return False
        return self.reload(force=force, now=now)

    def reload(self, *, force: bool = False, now: float | None = None) -> bool:
        now = time.monotonic() if now is None else now
        if not self._reload_lock.acquire(blocking=False):
            return False  # another thread is already reloading
        try:
            self._last_check = now
            changed = self._reload_lists(force=force)
            self._reload_overrides()
            self._override_sig = self._overrides_signature()
            self._reload_reputation()
            if changed:
                self.loaded_at = now
            return changed
        finally:
            self._reload_lock.release()

    def _reload_lists(self, *, force: bool) -> bool:
        """Re-read every list when any file changed (or is forced), building the merged dict directly.

        Only the merged ``domain -> list`` dict survives; keeping a per-list set as well would cost
        ~70 B per entry permanently (25-30 MB for the default lists), and a full re-read every 12 h
        is far cheaper than that.
        """
        located: dict[str, tuple[Path | None, float | None]] = {}
        changed = force
        for name in self.list_names:
            st = self.lists[name]
            path = find_list_file(name, self.list_dir)
            mtime = None
            if path is not None:
                try:
                    mtime = path.stat().st_mtime
                except OSError:
                    path = None
            located[name] = (path, mtime)
            # A list that is still missing is not a change; only a new/updated/removed file is.
            if path != st.path or mtime != st.mtime or (path is not None and not st.loaded):
                changed = True
        if not changed:
            return False
        merged: dict[str, str] = {}
        # Later lists never overwrite an earlier attribution, so the reason names the first list configured.
        for name in self.list_names:
            st = self.lists[name]
            path, mtime = located[name]
            st.path, st.mtime = path, mtime
            if path is None:
                if not valid_list_name(name, self.list_dir):
                    st.loaded, st.entries, st.error = False, 0, "invalid list name (must be a feed from the registry)"
                    continue
                st.loaded, st.entries, st.error = False, 0, "file not found"
                logger.warning("DNS blocklist %r has no downloaded file yet", name)
                continue
            try:
                entries = load_list_file(path)
            except Exception as exc:
                st.loaded, st.entries, st.error = False, 0, f"{type(exc).__name__}: {exc}"
                logger.exception("failed to load DNS blocklist %s from %s", name, path)
                continue
            st.entries, st.loaded, st.error = len(entries), True, None
            for d in entries:
                merged.setdefault(d, name)
            del entries
        self._blocked = merged
        logger.info("DNS blocklists loaded: %d lists, %d entries", self.lists_loaded, len(merged))
        return True

    def _reload_overrides(self) -> None:
        if self.conn is None:
            return
        try:
            rows = db_query(self.conn, "SELECT domain, action FROM dns_overrides")
        except sqlite3.Error:
            logger.debug("dns_overrides not readable", exc_info=True)
            return
        self._overrides = {normalize_name(r["domain"]): str(r["action"]) for r in rows if r["action"] in ("allow", "deny")}

    def reload_overrides(self) -> None:
        """Called by the dashboard after editing overrides so the change applies immediately."""
        self._reload_overrides()
        self._override_sig = self._overrides_signature()

    def _overrides_signature(self) -> tuple:
        if self.conn is None:
            return ()
        try:
            row = db_query(self.conn, "SELECT COUNT(*) AS n, MAX(created_at) AS m FROM dns_overrides")
        except sqlite3.Error:
            return ()
        return (int(row[0]["n"] or 0), row[0]["m"]) if row else ()

    def refresh_overrides_if_changed(self) -> bool:
        """Cheap poll (one aggregate query) so overrides written by the dashboard apply within seconds."""
        sig = self._overrides_signature()
        if sig == self._override_sig:
            return False
        self._override_sig = sig
        self._reload_overrides()
        return True

    def _reload_reputation(self) -> None:
        if self.conn is None:
            return
        try:
            import datetime as dt

            cutoff = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(hours=self.reputation_ttl_hours)).strftime(
                "%Y-%m-%dT%H:%M:%SZ"
            )
            rows = db_query(
                self.conn,
                "SELECT domain FROM reputation WHERE verdict = 'malicious' AND malicious >= ? AND checked_at >= ?",
                (self.min_malicious_votes, cutoff),
            )
        except sqlite3.Error:
            logger.debug("reputation table not readable", exc_info=True)
            return
        self._malicious = frozenset(normalize_name(r["domain"]) for r in rows)

    def mark_malicious(self, domain: str) -> None:
        """Immediate block after a fresh verdict, without waiting for the 60 s refresh."""
        self._malicious = self._malicious | {normalize_name(domain)}

    # ---- introspection --------------------------------------------------------------------
    @property
    def lists_loaded(self) -> int:
        return sum(1 for s in self.lists.values() if s.loaded)

    @property
    def list_entries(self) -> int:
        return len(self._blocked)

    @property
    def override_count(self) -> int:
        return len(self._overrides)

    @property
    def malicious_count(self) -> int:
        return len(self._malicious)

    def stale_lists(self, *, max_age_days: float = STALE_LIST_DAYS, now: float | None = None) -> list[str]:
        """Names of configured lists missing or older than ``max_age_days`` (for NET-DNS-003)."""
        now = time.time() if now is None else now
        out = []
        for name, st in self.lists.items():
            if st.mtime is None or now - st.mtime > max_age_days * 86400:
                out.append(name)
        return out

    def list_status(self) -> list[dict]:
        return [
            {
                "name": s.name,
                "path": str(s.path) if s.path else None,
                "entries": s.entries,
                "loaded": s.loaded,
                "mtime": s.mtime,
                "error": s.error,
            }
            for s in self.lists.values()
        ]
