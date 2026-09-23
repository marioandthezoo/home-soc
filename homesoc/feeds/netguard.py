"""Socket-level guards for outbound fetches of untrusted content (feed downloads, NVD lookups).

URL checks and requests' timeouts leave two gaps that only the socket layer can close:

* **Where the fetch really connects.** A URL checked with one parser and fetched with another
  (``https://10.0.0.1\\@example.com/`` is ``example.com`` to ``urlsplit`` and ``10.0.0.1`` to
  urllib3), or a name that resolves differently the second time, gets past any check made on the
  URL string. A :class:`Watch` sees every ``socket.connect`` its thread makes (through a
  ``sys.audit`` hook) and refuses any address its ``check_address`` rejects, before the connect.
* **How long the fetch really takes.** requests' read timeout is per ``recv``; a server that sends
  one header byte every 59 s, or one body byte at a time into a 64 KB read, never trips it. A
  :class:`Watch` arms a timer for its wall clock and, when it fires, shuts down every socket the
  fetch opened. The blocked read in the fetching thread then fails at once, whatever phase it is
  in (TLS handshake, status line, headers, body).

The audit hook is installed once per process and does nothing unless the calling thread is inside
an active watch, so other threads (the DNS resolver, the web server) are never affected.
"""

from __future__ import annotations

import ipaddress
import logging
import socket
import sys
import threading
from collections.abc import Callable
from typing import Any

logger = logging.getLogger(__name__)

_state = threading.local()
_hook_lock = threading.Lock()
_hook_installed = False

# Address ranges that ipaddress.is_global still calls global but that must never be a fetch
# target: the IPv6 forms that embed (or used to reach) an IPv4 or site-local address.
_NAT64_WKP = ipaddress.ip_network("64:ff9b::/96")
_NAT64_LOCAL = ipaddress.ip_network("64:ff9b:1::/48")
_V4_COMPATIBLE = ipaddress.ip_network("::/96")
_SITE_LOCAL = ipaddress.ip_network("fec0::/10")
_TEREDO = ipaddress.ip_network("2001::/32")
_SIX_TO_FOUR = ipaddress.ip_network("2002::/16")


class BlockedAddress(ConnectionRefusedError):
    """A connect to an address the watch does not permit (an OSError, so urllib3 cleans up the socket)."""


class WallClockExceeded(TimeoutError):
    """A connect attempted after the watch's wall clock ran out."""


def is_public_ip(value: str) -> bool:
    """True only for globally routable unicast addresses.

    Refuses loopback, RFC 1918, link-local, CGNAT, multicast and reserved space, IPv4-mapped
    and IPv4-compatible IPv6, deprecated site-local fec0::/10, Teredo, and NAT64 / 6to4
    addresses whose embedded IPv4 address is not itself public.
    """
    try:
        ip = ipaddress.ip_address(str(value).split("%", 1)[0])
    except ValueError:
        return False
    if isinstance(ip, ipaddress.IPv6Address):
        if ip.ipv4_mapped is not None:
            ip = ip.ipv4_mapped
        elif ip in _NAT64_WKP:
            ip = ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF)
        elif ip in _SIX_TO_FOUR:
            embedded = ip.sixtofour
            if embedded is None or not is_public_ip(str(embedded)):
                return False
        elif ip in _V4_COMPATIBLE or ip in _NAT64_LOCAL or ip in _SITE_LOCAL or ip in _TEREDO:
            return False
    return ip.is_global and not ip.is_multicast


def _audit(event: str, args: tuple[Any, ...]) -> None:
    if event != "socket.connect":
        return
    watch = getattr(_state, "watch", None)
    if watch is not None:
        watch._on_connect(args[0], args[1])


def _install_hook() -> None:
    global _hook_installed
    with _hook_lock:
        if not _hook_installed:
            sys.addaudithook(_audit)
            _hook_installed = True


def current() -> "Watch | None":
    """The watch active in this thread, if any."""
    return getattr(_state, "watch", None)


def response_socket(resp: Any) -> socket.socket | None:
    """Best-effort: the socket under a streamed requests/urllib3 response (None for fakes)."""
    raw = getattr(resp, "raw", None)
    conn = getattr(raw, "_connection", None) or getattr(raw, "connection", None)
    sock = getattr(conn, "sock", None)
    if isinstance(sock, socket.socket):
        return sock
    # "Connection: close": http.client detaches the socket from the connection and the response
    # reads it through its own file object (http.client.HTTPResponse.fp -> SocketIO._sock).
    fp = getattr(getattr(raw, "_fp", None), "fp", None)
    sock = getattr(getattr(fp, "raw", None), "_sock", None)
    return sock if isinstance(sock, socket.socket) else None


class Watch:
    """Wall clock and connect policy for one fetch, enforced on the sockets themselves.

    Use as a context manager in the thread that does the I/O. It is re-entrant: nested ``with``
    blocks share one timer, and the sockets are released when the outermost block exits.
    ``remaining`` is read when the outermost block is entered, so one watch can be handed from
    ``_open`` to the body reader and keep counting down.
    """

    def __init__(self, remaining: Callable[[], float], what: str = "request",
                 check_address: Callable[[Any], bool] | None = None) -> None:
        self._remaining = remaining
        self.what = what
        self.check_address = check_address
        self.expired = False
        self.allowed_hosts: set[str] = set()
        self._lock = threading.Lock()
        # (socket object, handle, peer address) as seen at connect time
        self._connected: list[tuple[socket.socket, int, tuple]] = []
        self._adopted: list[socket.socket] = []
        self._timer: threading.Timer | None = None
        self._depth = 0
        self._outer: Watch | None = None

    # -- context management ---------------------------------------------------------------------

    def __enter__(self) -> "Watch":
        if self._depth == 0:
            _install_hook()
            self._outer = getattr(_state, "watch", None)
            _state.watch = self
            seconds = max(0.0, float(self._remaining()))
            if seconds <= 0:
                self.expired = True
            else:
                self._timer = threading.Timer(seconds, self._fire)
                self._timer.daemon = True
                self._timer.start()
        self._depth += 1
        return self

    def __exit__(self, *exc: object) -> None:
        self._depth -= 1
        if self._depth > 0:
            return
        if self._timer is not None:
            self._timer.cancel()
            self._timer = None
        _state.watch = self._outer
        self._outer = None
        with self._lock:
            self._connected = []
            self._adopted = []

    # -- registration ---------------------------------------------------------------------------

    def allow(self, address: str) -> None:
        """Permit connects to one extra address (the owner's configured proxy)."""
        self.allowed_hosts.add(str(address).split("%", 1)[0])

    def adopt(self, sock: socket.socket | None) -> None:
        """Put a socket that was connected outside the watch under its wall clock."""
        if sock is None:
            return
        with self._lock:
            self._adopted.append(sock)
            expired = self.expired
        if expired:
            _shutdown(sock)

    def _on_connect(self, sock: socket.socket, address: Any) -> None:
        if self.expired:
            raise WallClockExceeded(f"{self.what}: wall clock exceeded before connecting")
        host = address[0] if isinstance(address, tuple) and address else address
        if self.check_address is not None and str(host).split("%", 1)[0] not in self.allowed_hosts:
            if not isinstance(host, str) or not self.check_address(host):
                raise BlockedAddress(f"refusing to connect to non-public address {host}")
        if not isinstance(address, tuple):
            return
        try:
            fd = sock.fileno()
        except OSError:
            return
        with self._lock:
            self._connected.append((sock, fd, address))
            expired = self.expired
        if expired:
            _abort(sock, fd, address)

    # -- expiry ---------------------------------------------------------------------------------

    def _fire(self) -> None:
        with self._lock:
            self.expired = True
            connected = list(self._connected)
            adopted = list(self._adopted)
        logger.debug("%s: wall clock expired, aborting %d socket(s)", self.what, len(connected) + len(adopted))
        for sock in adopted:
            _shutdown(sock)
        for sock, fd, peer in connected:
            _abort(sock, fd, peer)


def _shutdown(sock: socket.socket) -> None:
    try:
        sock.shutdown(socket.SHUT_RDWR)
    except (OSError, ValueError):
        pass


def _abort(sock: socket.socket, fd: int, peer: tuple) -> None:
    """Shut down the connection a watched connect opened, so a read blocked on it returns at once.

    While the object seen at connect time still owns its handle (plain http) it is shut down
    directly. A TLS connection moves the handle to a new SSLSocket and detaches the original
    object, so the handle is then reached by number -- but only shut down after checking that it
    is still connected to the same peer, so a handle number that was closed and reused by some
    other connection is never touched. A shutdown (unlike a close) wakes a blocked recv on
    Windows and POSIX alike and never frees the handle under the thread that is using it.
    """
    try:
        if sock.fileno() == fd:
            _shutdown(sock)
            return
    except OSError:
        pass
    try:
        live = socket.socket(fileno=fd)
    except (OSError, ValueError):
        return
    try:
        if tuple(live.getpeername()[:2]) == tuple(peer[:2]):
            live.shutdown(socket.SHUT_RDWR)
    except OSError:
        pass
    finally:
        live.detach()  # never close a handle this code does not own
