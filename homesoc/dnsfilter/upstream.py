"""Upstream forwarding: UDP (2 s) → TCP on truncation → DoH POST wire-format fallback (SPEC §12).

The transport order matters for a home network: plain UDP to Cloudflare/Quad9 is the fastest and
works through any router; TCP is only tried when an answer is truncated; DoH is the last resort for
networks whose ISP intercepts port 53. Health is tracked here so the server can raise NET-DNS-005
when *every* path has been failing for a minute.

Two defensive details that are easy to get wrong in a forwarder:

* UDP sockets are ``connect()``-ed so the kernel drops datagrams from anyone but the upstream, and
  a reply is only accepted when its question section matches the request (id alone is 16 bits).
  On top of that the outbound name is 0x20-randomised, so an off-path spoofer must also guess the
  case pattern of the name, not just the 16-bit id.
* Once every path has failed, a circuit breaker lets one probe through every few seconds and fails
  the rest instantly; without it every LAN query would cost 9 s of timeouts on its own thread, and a
  host that uses Home SOC as its own resolver would recurse into itself while bootstrapping DoH.
"""
from __future__ import annotations

import ipaddress
import logging
import random
import socket
import struct
import threading
import time
from dataclasses import dataclass, field
from urllib.parse import urlsplit, urlunsplit

from dnslib import CLASS, QTYPE, DNSError, DNSLabel, DNSRecord

logger = logging.getLogger(__name__)

DEFAULT_TIMEOUT = 2.0
DOH_TIMEOUT = 5.0
MAX_MESSAGE = 65535
DOH_CONTENT_TYPE = "application/dns-message"
# While all upstreams are down, one query per this interval is allowed to probe; the rest fail fast.
BREAKER_PROBE_SECONDS = 5.0
# How long a DoH address learned through the UDP upstreams stays valid.
DOH_BOOTSTRAP_TTL = 24 * 3600.0
# After a reply that matches the question but not the 0x20 case pattern, wait this long for a
# correctly-cased one before concluding that the upstream normalises case (see _query_udp).
CASE_MATCH_GRACE = 0.2

_rand = random.SystemRandom()  # os.urandom-backed: the 0x20 pattern must not be predictable

# SPEC-GAP: the spec's default DoH URL names a hostname, which the OS resolver would have to resolve —
# through Home SOC itself once the router points DHCP at this PC. Well-known DoH hosts publish their
# resolver IPs (all carry the IP in the certificate SAN), so they can be reached without any lookup.
DOH_BOOTSTRAP_IPS: dict[str, tuple[str, ...]] = {
    "cloudflare-dns.com": ("1.1.1.1", "1.0.0.1"),
    "one.one.one.one": ("1.1.1.1", "1.0.0.1"),
    "security.cloudflare-dns.com": ("1.1.1.2", "1.0.0.2"),
    "family.cloudflare-dns.com": ("1.1.1.3", "1.0.0.3"),
    "dns.quad9.net": ("9.9.9.9", "149.112.112.112"),
    "dns.google": ("8.8.8.8", "8.8.4.4"),
    "dns.adguard-dns.com": ("94.140.14.14", "94.140.15.15"),
}


class UpstreamError(Exception):
    """All upstreams (UDP, TCP fallback and DoH) failed for one query."""


@dataclass(frozen=True)
class UpstreamAddress:
    host: str
    port: int = 53

    @property
    def label(self) -> str:
        return f"{self.host}:{self.port}" if self.port != 53 else self.host


def parse_upstream(spec: str) -> UpstreamAddress:
    """Accept ``1.1.1.2``, ``1.1.1.2:5353``, ``[::1]:53`` or ``2620:fe::fe`` (bare IPv6 → port 53)."""
    s = spec.strip()
    if s.startswith("["):
        host, _, rest = s[1:].partition("]")
        port = int(rest[1:]) if rest.startswith(":") and rest[1:].isdigit() else 53
        return UpstreamAddress(host, port)
    if s.count(":") == 1:
        host, _, port_s = s.partition(":")
        return UpstreamAddress(host, int(port_s) if port_s.isdigit() else 53)
    return UpstreamAddress(s, 53)


def _is_ipv6(host: str) -> bool:
    try:
        return ipaddress.ip_address(host).version == 6
    except ValueError:
        return False


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def same_question(request: DNSRecord, reply: DNSRecord) -> bool:
    """True when the reply answers the question we asked (name case-insensitive, type and class equal)."""
    if not request.questions or not reply.questions:
        return False
    rq, pq = request.q, reply.q
    return (
        str(rq.qname).rstrip(".").lower() == str(pq.qname).rstrip(".").lower()
        and rq.qtype == pq.qtype
        and rq.qclass == pq.qclass
    )


def same_question_exact(request: DNSRecord, reply: DNSRecord) -> bool:
    """``same_question`` plus a byte-exact name, which is what makes 0x20 randomisation worth anything."""
    return same_question(request, reply) and str(request.q.qname) == str(reply.q.qname)


def randomize_case(label: DNSLabel) -> DNSLabel:
    """0x20 encoding: flip the case of ASCII letters at random (RFC-safe, names are case-insensitive)."""
    parts = []
    for part in label.label:
        bits = _rand.getrandbits(len(part)) if part else 0
        parts.append(bytes(
            (c ^ 0x20) if (bits >> i) & 1 and (0x41 <= (c & 0xDF) <= 0x5A) else c
            for i, c in enumerate(part)
        ))
    return DNSLabel(tuple(parts))


def restore_case(reply: DNSRecord, original: DNSRecord) -> None:
    """Undo the 0x20 scrambling in place so neither the client nor the cache ever sees it."""
    if not original.questions or not reply.questions:
        return
    qname = original.q.qname
    if str(reply.q.qname) == str(qname):
        return
    lowered = str(qname).lower()
    for q in reply.questions:
        q.qname = qname
    for section in (reply.rr, reply.auth, reply.ar):
        for rr in section:
            if str(rr.rname).lower() == lowered:
                rr.rname = qname


@dataclass
class UpstreamHealth:
    ok: bool = True
    last_ok_at: float | None = None
    failing_since: float | None = None
    consecutive_failures: int = 0
    last_error: str | None = None
    last_upstream: str | None = None
    per_upstream_failures: dict[str, int] = field(default_factory=dict)


class Upstream:
    """Resolve wire-format requests against a list of upstreams; thread-safe."""

    def __init__(
        self,
        upstreams: list[str] | tuple[str, ...],
        doh_upstream: str = "",
        *,
        timeout: float = DEFAULT_TIMEOUT,
        doh_timeout: float = DOH_TIMEOUT,
        session=None,
        randomize_query_case: bool = True,
    ) -> None:
        self.addresses = [parse_upstream(u) for u in upstreams if u and u.strip()]
        self.doh_upstream = (doh_upstream or "").strip()
        self.timeout = float(timeout)
        self.doh_timeout = float(doh_timeout)
        self._session = session  # injectable for tests; a requests.Session is created lazily
        self.randomize_query_case = bool(randomize_query_case)
        self.health = UpstreamHealth()
        self._lock = threading.Lock()
        self._next_probe_at = 0.0
        self.breaker_rejections = 0
        self._doh_ip: str | None = None
        self._doh_ip_at = 0.0
        self._doh_mounted: set[str] = set()
        # Upstreams (or middleboxes) observed to lowercase the question: 0x20 is skipped for those,
        # otherwise every query to them would pay the CASE_MATCH_GRACE wait.
        self._case_normalizing: set[str] = set()

    # ---- public ---------------------------------------------------------------------------
    @property
    def ok(self) -> bool:
        return self.health.ok

    def failing_for(self, now: float | None = None) -> float:
        """Seconds since the last successful answer while failing; 0 when healthy."""
        now = time.monotonic() if now is None else now
        with self._lock:
            if self.health.ok or self.health.failing_since is None:
                return 0.0
            return max(0.0, now - self.health.failing_since)

    def resolve(self, request: DNSRecord, *, tcp_only: bool = False) -> DNSRecord:
        """Return the upstream's reply for ``request`` (id preserved). Raises ``UpstreamError``."""
        if not self._breaker_allows():
            raise UpstreamError("all upstreams are down (circuit open); retry shortly")
        plain_wire = request.pack()
        errors: list[str] = []
        for addr in self.addresses:
            probe, wire, strict = self._probe_for(addr, request, plain_wire)
            try:
                reply = self._query_tcp(addr, wire) if tcp_only else self._query_udp_then_tcp(addr, wire, probe, strict)
            except (OSError, ValueError, DNSError, UpstreamError) as exc:
                msg = f"{addr.label}: {type(exc).__name__}: {exc}"
                errors.append(msg)
                self._note_failure(addr.label, msg)
                continue
            if reply.header.id != request.header.id or not same_question(request, reply):
                errors.append(f"{addr.label}: reply does not match the question")
                self._note_failure(addr.label, "reply mismatch")
                continue
            self._note_success(addr.label)
            restore_case(reply, request)
            return reply
        if self.doh_upstream:
            try:
                # DoH runs over TLS to a pinned host, so 0x20 buys nothing: send the plain question.
                reply = self._query_doh(plain_wire)
                if reply.header.id != request.header.id or not same_question(request, reply):
                    raise UpstreamError("doh reply does not match the question")
            except Exception as exc:  # requests raises many types; DoH is best-effort
                msg = f"doh {self.doh_upstream}: {type(exc).__name__}: {exc}"
                errors.append(msg)
                self._note_failure("doh", msg)
            else:
                self._note_success("doh")
                return reply
        raise UpstreamError("; ".join(errors) or "no upstreams configured")

    # ---- circuit breaker ------------------------------------------------------------------
    def _breaker_allows(self, now: float | None = None) -> bool:
        """Healthy → always; failing → one probe per BREAKER_PROBE_SECONDS, everything else fails fast."""
        now = time.monotonic() if now is None else now
        with self._lock:
            if self.health.ok:
                return True
            if now >= self._next_probe_at:
                self._next_probe_at = now + BREAKER_PROBE_SECONDS
                return True
            self.breaker_rejections += 1
            return False

    # ---- 0x20 query randomisation -----------------------------------------------------------
    def _probe_for(self, addr: UpstreamAddress, request: DNSRecord, plain_wire: bytes) -> tuple[DNSRecord, bytes, bool]:
        """The request actually put on the wire for ``addr``: 0x20-scrambled unless it is known to
        normalise case. Returns ``(probe_record, probe_wire, strict_case)``; ``request`` is untouched.

        ``strict_case`` says whether *we* scrambled the name — the client's own capitalisation must
        never switch strict matching on, or a client that already does 0x20 would pay the grace wait.
        """
        if not self.randomize_query_case or not request.questions or addr.label in self._case_normalizing:
            return request, plain_wire, False
        try:
            probe = DNSRecord.parse(plain_wire)
            probe.q.qname = randomize_case(request.q.qname)
            return probe, probe.pack(), True
        except (DNSError, ValueError, IndexError):  # pragma: no cover - a request we built ourselves
            return request, plain_wire, False

    # ---- transports -----------------------------------------------------------------------
    def _query_udp_then_tcp(
        self, addr: UpstreamAddress, wire: bytes, request: DNSRecord, strict_case: bool = False
    ) -> DNSRecord:
        reply = self._query_udp(addr, wire, request, strict_case=strict_case)
        if reply.header.tc:
            logger.debug("truncated answer from %s; retrying over TCP", addr.label)
            reply = self._query_tcp(addr, wire)
        return reply

    def _query_udp(
        self, addr: UpstreamAddress, wire: bytes, request: DNSRecord, *, strict_case: bool = False
    ) -> DNSRecord:
        family = socket.AF_INET6 if _is_ipv6(addr.host) else socket.AF_INET
        expected_id = struct.unpack("!H", wire[:2])[0]
        soft: DNSRecord | None = None
        with socket.socket(family, socket.SOCK_DGRAM) as sock:
            sock.settimeout(self.timeout)
            # connect() makes the kernel discard datagrams from any other peer, so a spoofer must
            # also forge the upstream's source address, not just guess a 16-bit id.
            sock.connect((addr.host, addr.port))
            sock.send(wire)
            deadline = time.monotonic() + self.timeout
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    if soft is not None:
                        # Only reachable when no correctly-cased answer ever arrived: the upstream (or a
                        # middlebox) lowercases questions. Accept it and stop paying the grace wait.
                        self._case_normalizing.add(addr.label)
                        logger.debug("%s normalises question case; disabling 0x20 for it", addr.label)
                        return soft
                    raise socket.timeout("udp timeout")
                sock.settimeout(remaining)
                try:
                    data = sock.recv(MAX_MESSAGE)
                except TimeoutError:
                    continue  # let the deadline check above decide between `soft` and a real timeout
                # Stray/garbage datagrams (wrong id, unparsable, other question) are ignored and we
                # keep waiting for the real answer until the deadline.
                if len(data) < 12 or struct.unpack("!H", data[:2])[0] != expected_id:
                    continue
                try:
                    reply = DNSRecord.parse(data)
                except DNSError:
                    continue
                if not same_question(request, reply):
                    continue
                if not strict_case or same_question_exact(request, reply):
                    return reply
                if soft is None:
                    soft = reply
                    deadline = min(deadline, time.monotonic() + CASE_MATCH_GRACE)

    def _query_tcp(self, addr: UpstreamAddress, wire: bytes) -> DNSRecord:
        family = socket.AF_INET6 if _is_ipv6(addr.host) else socket.AF_INET
        with socket.socket(family, socket.SOCK_STREAM) as sock:
            sock.settimeout(self.timeout)
            sock.connect((addr.host, addr.port))
            sock.sendall(struct.pack("!H", len(wire)) + wire)
            header = _recv_exact(sock, 2)
            (length,) = struct.unpack("!H", header)
            data = _recv_exact(sock, length)
        return DNSRecord.parse(data)

    def _query_doh(self, wire: bytes) -> DNSRecord:
        session = self._get_session()
        url, headers = self._doh_target(session)
        headers.update({"content-type": DOH_CONTENT_TYPE, "accept": DOH_CONTENT_TYPE})
        resp = session.post(url, data=wire, headers=headers, timeout=self.doh_timeout)
        status = getattr(resp, "status_code", 0)
        if status != 200:
            raise UpstreamError(f"doh http {status}")
        body = resp.content
        if not body or len(body) > MAX_MESSAGE:
            raise UpstreamError("doh: empty or oversized body")
        return DNSRecord.parse(body)

    def _get_session(self):
        if self._session is None:
            import requests  # local import keeps the UDP path free of the dependency

            self._session = requests.Session()
        return self._session

    # ---- DoH bootstrap --------------------------------------------------------------------
    def _doh_target(self, session) -> tuple[str, dict[str, str]]:
        """URL + extra headers for the DoH POST, reaching the server by IP whenever we know one.

        Order: literal IP in the URL → built-in table → address learned via the UDP upstreams (cached
        24 h). Only when none applies does the hostname go through the OS resolver; with the circuit
        breaker that recursion is bounded, but it is still the slowest path.
        """
        parts = urlsplit(self.doh_upstream)
        host = parts.hostname or ""
        if not host or _is_ip(host) or not hasattr(session, "mount"):
            return self.doh_upstream, {}
        ip = self._doh_bootstrap_ip(host)
        if ip is None:
            return self.doh_upstream, {}
        netloc = (f"[{ip}]" if _is_ipv6(ip) else ip) + (f":{parts.port}" if parts.port else "")
        url = urlunsplit((parts.scheme, netloc, parts.path or "/", parts.query, ""))
        if not self._mount_pinned(session, ip, host):
            return self.doh_upstream, {}
        return url, {"Host": host}

    def _doh_bootstrap_ip(self, host: str) -> str | None:
        known = DOH_BOOTSTRAP_IPS.get(host.lower())
        if known:
            return known[0]
        now = time.monotonic()
        if self._doh_ip and now - self._doh_ip_at < DOH_BOOTSTRAP_TTL:
            return self._doh_ip
        if not self.health.ok:
            # The UDP upstreams just failed for this very query; re-asking them would only add another
            # round of timeouts before the DoH POST that is supposed to rescue us.
            return self._doh_ip
        ip = self._resolve_via_udp(host)
        if ip:
            self._doh_ip, self._doh_ip_at = ip, now
            return ip
        return self._doh_ip  # possibly stale but still better than the OS resolver

    def _resolve_via_udp(self, host: str) -> str | None:
        request = DNSRecord.question(host, "A")
        wire = request.pack()
        for addr in self.addresses:
            try:
                reply = self._query_udp(addr, wire, request)
            except (OSError, ValueError, DNSError, UpstreamError):
                continue
            for rr in reply.rr:
                if rr.rtype == QTYPE.A and rr.rclass == CLASS.IN:
                    return str(rr.rdata)
        return None

    def _mount_pinned(self, session, ip: str, host: str) -> bool:
        """Verify the certificate against ``host`` while connecting to ``ip`` (TLS SNI + hostname check)."""
        prefix = f"https://{ip}/"
        if prefix in self._doh_mounted:
            return True
        try:
            from requests.adapters import HTTPAdapter

            class _PinnedAdapter(HTTPAdapter):
                def init_poolmanager(self, connections, maxsize, block=False, **kw):  # type: ignore[override]
                    kw["server_hostname"] = host
                    kw["assert_hostname"] = host
                    super().init_poolmanager(connections, maxsize, block=block, **kw)

            session.mount(prefix, _PinnedAdapter())
        except Exception as exc:  # pragma: no cover - depends on the requests/urllib3 build
            logger.debug("cannot pin DoH host %s to %s: %s", host, ip, exc)
            return False
        self._doh_mounted.add(prefix)
        return True

    # ---- health ---------------------------------------------------------------------------
    def _note_success(self, label: str) -> None:
        with self._lock:
            self.health.ok = True
            self.health.last_ok_at = time.monotonic()
            self.health.failing_since = None
            self.health.consecutive_failures = 0
            self.health.last_upstream = label
            self.health.per_upstream_failures[label] = 0
            self._next_probe_at = 0.0

    def _note_failure(self, label: str, msg: str) -> None:
        with self._lock:
            self.health.per_upstream_failures[label] = self.health.per_upstream_failures.get(label, 0) + 1
            self.health.last_error = msg

    def mark_all_failed(self) -> None:
        """Called by ``resolve`` callers after an ``UpstreamError`` so health reflects whole-query failures."""
        with self._lock:
            self.health.consecutive_failures += 1
            if self.health.ok:
                self.health.ok = False
                self.health.failing_since = time.monotonic()

    def status(self) -> dict:
        with self._lock:
            h = self.health
            return {
                "ok": h.ok,
                "consecutive_failures": h.consecutive_failures,
                "last_error": h.last_error,
                "last_upstream": h.last_upstream,
                "upstreams": [a.label for a in self.addresses],
                "doh": self.doh_upstream,
                "breaker_rejections": self.breaker_rejections,
                "case_randomized": self.randomize_query_case,
                "case_normalizing": sorted(self._case_normalizing),
            }


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    chunks = bytearray()
    while len(chunks) < n:
        part = sock.recv(n - len(chunks))
        if not part:
            raise UpstreamError("tcp connection closed early")
        chunks.extend(part)
    return bytes(chunks)
