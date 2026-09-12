"""TTL-respecting LRU cache for upstream answers (SPEC §12).

Why a minimum TTL: many CDNs publish 5–20 s TTLs, which would make a LAN resolver hammer upstreams
for the same names; clamping to 30 s costs nothing for a home network. Why a negative TTL: NXDOMAIN
and NODATA answers are cached for a fixed 60 s so typo storms and probing clients stay cheap.
"""
from __future__ import annotations

import logging
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass

from dnslib import DNSRecord, RCODE

logger = logging.getLogger(__name__)

DEFAULT_MIN_TTL = 30
DEFAULT_NEGATIVE_TTL = 60
DEFAULT_MAX_ENTRIES = 20000
# Upper bound like most sinkholes: an authoritative server (attacker-controlled for its own C2 name)
# may answer with a multi-year TTL, and a blocklist update must be able to catch up within an hour.
DEFAULT_MAX_TTL = 3600


@dataclass
class CacheEntry:
    wire: bytes          # packed reply (id irrelevant; rewritten on hit)
    stored_at: float     # monotonic seconds
    expires_at: float    # monotonic seconds


def cache_key(qname: str, qtype: str) -> tuple[str, str]:
    """Names are case-insensitive and clients randomise case (0x20 hardening), so normalise."""
    return (qname.rstrip(".").lower(), qtype.upper())


class DnsCache:
    """Thread-safe LRU keyed by ``(qname.lower(), qtype)``.

    Entries store the packed reply; a hit returns a fresh ``DNSRecord`` with TTLs decremented by the
    time already spent in the cache, so downstream clients never see a TTL longer than the origin's.
    """

    def __init__(
        self,
        max_entries: int = DEFAULT_MAX_ENTRIES,
        *,
        min_ttl: int = DEFAULT_MIN_TTL,
        negative_ttl: int = DEFAULT_NEGATIVE_TTL,
        max_ttl: int = DEFAULT_MAX_TTL,
    ) -> None:
        self.max_entries = max(1, int(max_entries))
        self.min_ttl = int(min_ttl)
        self.negative_ttl = int(negative_ttl)
        self.max_ttl = max(self.min_ttl, int(max_ttl))
        self._entries: OrderedDict[tuple[str, str], CacheEntry] = OrderedDict()
        self._lock = threading.Lock()
        self.hits = 0
        self.misses = 0

    # ---- public API -------------------------------------------------------------------------
    def get(self, qname: str, qtype: str, *, now: float | None = None) -> DNSRecord | None:
        now = time.monotonic() if now is None else now
        key = cache_key(qname, qtype)
        with self._lock:
            entry = self._entries.get(key)
            if entry is None:
                self.misses += 1
                return None
            if entry.expires_at <= now:
                del self._entries[key]
                self.misses += 1
                return None
            self._entries.move_to_end(key)
            self.hits += 1
        try:
            reply = DNSRecord.parse(entry.wire)
        except Exception:  # corrupted entry should never poison the resolver
            logger.debug("dropping unparsable cache entry for %s", key)
            with self._lock:
                self._entries.pop(key, None)
            return None
        elapsed = int(now - entry.stored_at)
        if elapsed > 0:
            for section in (reply.rr, reply.auth, reply.ar):
                for rr in section:
                    if rr.rtype == 41:  # OPT pseudo-RR carries flags in the TTL field
                        continue
                    rr.ttl = max(1, rr.ttl - elapsed)
        return reply

    def put(self, qname: str, qtype: str, reply: DNSRecord, *, now: float | None = None) -> bool:
        """Store a reply; returns False when the answer is not cacheable (SERVFAIL/REFUSED/…)."""
        ttl = self.ttl_for(reply)
        if ttl is None:
            return False
        now = time.monotonic() if now is None else now
        key = cache_key(qname, qtype)
        try:
            wire = bytes(reply.pack())
        except Exception:
            return False
        entry = CacheEntry(wire=wire, stored_at=now, expires_at=now + ttl)
        with self._lock:
            self._entries[key] = entry
            self._entries.move_to_end(key)
            while len(self._entries) > self.max_entries:
                self._entries.popitem(last=False)
        return True

    def ttl_for(self, reply: DNSRecord) -> int | None:
        """How long to keep a reply, or None if it must not be cached."""
        rcode = reply.header.rcode
        if rcode == RCODE.NXDOMAIN:
            return self.negative_ttl
        if rcode != RCODE.NOERROR:
            return None
        if reply.header.tc:
            return None
        answers = [rr for rr in reply.rr if rr.rtype != 41]
        if not answers:
            return self.negative_ttl
        ttl = min(rr.ttl for rr in answers)
        return min(self.max_ttl, max(self.min_ttl, int(ttl)))

    def invalidate(self, qname: str, qtype: str | None = None) -> int:
        """Drop entries for a name *and its subdomains* (all types when qtype is None).

        Suffix semantics because callers pass a registrable domain after a reputation verdict or an
        override change, and the sinkhole must take effect for ``cdn.bad.example`` at once.
        """
        name = qname.rstrip(".").lower()
        suffix = "." + name
        with self._lock:
            keys = [
                k for k in self._entries
                if (k[0] == name or k[0].endswith(suffix)) and (qtype is None or k[1] == qtype.upper())
            ]
            for k in keys:
                del self._entries[k]
        return len(keys)

    def clear(self) -> None:
        with self._lock:
            self._entries.clear()

    def purge_expired(self, *, now: float | None = None) -> int:
        now = time.monotonic() if now is None else now
        with self._lock:
            dead = [k for k, e in self._entries.items() if e.expires_at <= now]
            for k in dead:
                del self._entries[k]
        return len(dead)

    def __len__(self) -> int:
        with self._lock:
            return len(self._entries)

    @property
    def size(self) -> int:
        return len(self)
