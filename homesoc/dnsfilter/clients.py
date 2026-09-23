"""Which DNS clients are real devices: the inventory's addresses, used to reserve capacity for them.

A UDP source address costs nothing to forge on a LAN, so any budget that is shared by "every source
address" can be used up by one device inventing thousands of them. The resolver keeps its per-source
limits, but the pieces the owner relies on — the query log and the reputation queue — also set aside
capacity for addresses that belong to devices in the inventory (``devices.ip``). An attacker cannot
add to that set by forging packets: devices enter the inventory through discovery, whose growth is
rate-limited on its own. Forging a *known* address only spends that one address's own allowance.

The set is swapped atomically, so ``client in known`` is a lock-free O(1) probe on the answer path.
It is refreshed from the database by the resolver's housekeeping thread, never by a query.
"""
from __future__ import annotations

import datetime as dt
import logging
import sqlite3
import threading
import time
from typing import Iterable

from homesoc.dnsfilter import db_query

logger = logging.getLogger(__name__)

REFRESH_SECONDS = 60.0
MAX_KNOWN = 1024              # inventory addresses honoured (most recently seen first)
MAX_AGE_DAYS = 30             # a device not seen for this long no longer gets a reservation
ALWAYS_KNOWN = frozenset({"127.0.0.1", "::1"})  # the host itself; loopback cannot arrive from the LAN


class KnownClients:
    """``addr in KnownClients(conn)`` → True for the host itself and for inventory devices."""

    def __init__(self, conn: sqlite3.Connection | None = None, *, addresses: Iterable[str] = ()) -> None:
        self.conn = conn
        self._addresses: frozenset[str] = ALWAYS_KNOWN | frozenset(str(a) for a in addresses)
        self._refreshed_at: float | None = None
        self._lock = threading.Lock()

    def __contains__(self, client: object) -> bool:
        return isinstance(client, str) and client in self._addresses

    def __len__(self) -> int:
        return len(self._addresses)

    def set(self, addresses: Iterable[str]) -> None:
        """Replace the set (tests, or a caller that already has the inventory at hand)."""
        self._addresses = ALWAYS_KNOWN | frozenset(str(a) for a in list(addresses)[:MAX_KNOWN])

    def maybe_refresh(self, now: float | None = None) -> bool:
        now = time.monotonic() if now is None else now
        if self._refreshed_at is not None and now - self._refreshed_at < REFRESH_SECONDS:
            return False
        return self.refresh(now=now)

    def refresh(self, *, now: float | None = None) -> bool:
        """Reload from ``devices``; keeps the previous set when the table is missing or unreadable."""
        self._refreshed_at = time.monotonic() if now is None else now
        if self.conn is None:
            return False
        cutoff = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=MAX_AGE_DAYS)).strftime("%Y-%m-%dT%H:%M:%SZ")
        with self._lock:
            try:
                rows = db_query(
                    self.conn,
                    "SELECT ip FROM devices WHERE ip IS NOT NULL AND ip <> '' AND last_seen >= ?"
                    " ORDER BY last_seen DESC LIMIT ?",
                    (cutoff, MAX_KNOWN),
                )
            except sqlite3.Error:
                logger.debug("device inventory not readable; keeping %d known DNS clients", len(self), exc_info=True)
                return False
            addresses = []
            for r in rows:
                try:
                    addresses.append(str(r["ip"]).strip())
                except (IndexError, KeyError, TypeError):
                    addresses.append(str(r[0]).strip())
            self._addresses = ALWAYS_KNOWN | frozenset(a for a in addresses if a)
        return True
