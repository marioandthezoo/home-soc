"""The embedded resolver: UDP + TCP listeners, the per-query pipeline and health findings (SPEC §12).

Pipeline per query: rate limit → parse → refuse non-IN/ANY → policy → block answer, or cache →
upstream guard → upstream forward → cache store → query log → reputation enqueue. Policy runs before
the cache so a name that was allowed (and cached) once is blocked the moment a list update or a
reputation verdict says so. Everything after "parse" runs on a socketserver worker thread; nothing
in the hot path touches the network except the upstream call.

Fairness rule for every limit in this module: one source, one name or one zone must never be able
to use up a resource that every other device in the house needs. UDP source addresses cost nothing
to forge on a LAN, so no shared counter is allowed to *drop* queries (see ``handle_query``).
"""
from __future__ import annotations

import ipaddress
import logging
import platform
import socket
import socketserver
import struct
import subprocess
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass
from pathlib import Path

from dnslib import AAAA, CLASS, EDNS0, OPCODE, QTYPE, RCODE, RR, A, DNSError, DNSQuestion, DNSRecord

from homesoc.dnsfilter import apply_findings, cfg_get, make_draft, record_event, record_metric
from homesoc.dnsfilter.cache import DnsCache
from homesoc.dnsfilter.policy import Policy
from homesoc.dnsfilter.querylog import QueryLog, distinct_clients, ensure_schema
from homesoc.dnsfilter.reputation import ReputationWorker, registrable_domain, shared_budget
from homesoc.dnsfilter.upstream import CircuitOpenError, Upstream, UpstreamError

logger = logging.getLogger(__name__)

BLOCK_TTL = 60
RATE_LIMIT_QPS = 300
# SPEC-GAP: the spec only names the per-client limit. A global ceiling bounds the amplification a
# reflector abuser can extract with spoofed sources — but it applies only to UDP answers larger than
# MIN_UDP_SIZE (the amplification case), and over the ceiling those are truncated (TC=1), never
# dropped. It used to gate every query, so ~11 forged sources could silence the whole house.
GLOBAL_RATE_LIMIT_QPS = 3000
GLOBAL_CLIENT_KEY = "*"
# Beyond this many live buckets in one second (only reachable with forged sources) new sources share a
# bucket per /24 (IPv4) or /64 (IPv6), so the limiter's memory stays bounded.
RATE_LIMIT_MAX_KEYS = 65536
EDNS_UDP_SIZE = 1232          # DNS flag day 2020 recommendation
MIN_UDP_SIZE = 512
MAX_UDP_SIZE = EDNS_UDP_SIZE  # never honour a larger client-advertised size: it is the amplification factor
TCP_IDLE_TIMEOUT = 10.0       # wait for the first byte of the next message
TCP_MESSAGE_DEADLINE = 5.0    # a whole message (length prefix + body) must arrive within this
TCP_MAX_CONNECTION_SECONDS = 120.0
TCP_MAX_QUERIES_PER_CONNECTION = 100
TCP_MAX_CONNECTIONS = 64
TCP_MAX_CONNECTIONS_PER_CLIENT = 8
# Upstream guard (RFC 9520: resolution failures must be cached). One name's or one zone's trouble —
# including an attacker's deliberately slow authoritative server — stays with that name or zone.
FAIL_CACHE_SECONDS = 5.0      # a (qname, qtype) that failed on every path is SERVFAILed locally this long
ZONE_FAIL_THRESHOLD = 3       # this many failures under one registrable domain within the window ...
ZONE_FAIL_WINDOW = 30.0
ZONE_HOLD_SECONDS = 30.0      # ... fail that zone fast for this long instead of tying up a thread per query
UPSTREAM_INFLIGHT_PER_CLIENT = 32
UPSTREAM_INFLIGHT_PER_ZONE = 32
UPSTREAM_INFLIGHT_TOTAL = 1024  # thread-count safety valve, far above what a home network needs
GUARD_MAX_ENTRIES = 10000
HOUSEKEEPING_TICK = 5.0
HEALTH_INTERVAL = 60.0
METRIC_INTERVAL = 300.0       # dns.qps / dns.cache_size samples: every 5 min, or sooner when the value changed
UPSTREAM_FAIL_SECONDS = 60.0
CLIENTS_CHECK_MIN_UPTIME = 3600.0
SOURCE_HEALTH = "dns_health"


class _RateLimiter:
    """Per-key fixed-window counter: > ``max_qps`` in one second → refuse (amplification guard)."""

    def __init__(self, max_qps: int = RATE_LIMIT_QPS, *, max_keys: int = RATE_LIMIT_MAX_KEYS) -> None:
        self.max_qps = max(1, int(max_qps))
        self.max_keys = max(1, int(max_keys))
        self._buckets: dict[str, list[int]] = {}
        self._lock = threading.Lock()
        self._purged_sec: int | None = None
        self.dropped = 0

    def allow(self, client: str, *, now: float | None = None) -> bool:
        sec = int(time.monotonic() if now is None else now)
        with self._lock:
            b = self._buckets.get(client)
            if b is None and len(self._buckets) >= self.max_keys:
                if self._purged_sec != sec:  # at most one O(n) sweep per second
                    self._purged_sec = sec
                    for c in [c for c, v in self._buckets.items() if v[0] != sec]:
                        del self._buckets[c]
                if len(self._buckets) >= self.max_keys:
                    client = _prefix_key(client)
                    b = self._buckets.get(client)
                    if b is None and len(self._buckets) >= 2 * self.max_keys:
                        client = "overflow"  # hard memory bound; UDP callers answer TC=1, so TCP still works
                        b = self._buckets.get(client)
            if b is None or b[0] != sec:
                self._buckets[client] = [sec, 1]
                return True
            b[1] += 1
            if b[1] > self.max_qps:
                self.dropped += 1
                return False
            return True

    def cleanup(self, *, now: float | None = None) -> None:
        sec = int(time.monotonic() if now is None else now)
        with self._lock:
            stale = [c for c, b in self._buckets.items() if sec - b[0] > 2]
            for c in stale:
                del self._buckets[c]


def _prefix_key(client: str) -> str:
    """The /24 (IPv4) or /64 (IPv6) a source belongs to; the string itself when it is not an address."""
    try:
        addr = ipaddress.ip_address(client.split("%", 1)[0])
    except ValueError:
        return "net:" + client[:64]
    bits = 24 if addr.version == 4 else 64
    return "net:" + str(ipaddress.ip_network(f"{addr}/{bits}", strict=False))


class _UpstreamGuard:
    """Keeps one name's, one zone's or one client's upstream trouble from costing anyone else.

    * A (qname, qtype) that just failed on every path is answered SERVFAIL locally for
      ``FAIL_CACHE_SECONDS`` (RFC 9520 requires caching resolution failures).
    * A registrable domain with ``ZONE_FAIL_THRESHOLD`` failures in ``ZONE_FAIL_WINDOW`` is failed
      fast for ``ZONE_HOLD_SECONDS``: an attacker's slow authoritative server then costs a handful of
      upstream timeouts per half minute instead of a thread per query.
    * Concurrent upstream work is capped per client and per zone, with a large total safety valve.

    Every table is bounded (``GUARD_MAX_ENTRIES``, oldest evicted first).
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._failed_names: OrderedDict[tuple[str, str], float] = OrderedDict()  # -> expiry
        self._zone_failures: OrderedDict[str, list[float]] = OrderedDict()       # -> recent failure times
        self._zone_hold: OrderedDict[str, float] = OrderedDict()                 # -> expiry
        self._inflight_client: dict[str, int] = {}
        self._inflight_zone: dict[str, int] = {}
        self.inflight = 0
        self.fast_failed = 0
        self.busy_rejected = 0

    @staticmethod
    def _bounded_set(table: OrderedDict, key, value) -> None:
        table[key] = value
        table.move_to_end(key)
        while len(table) > GUARD_MAX_ENTRIES:
            table.popitem(last=False)

    def check(self, qname: str, qtype: str, zone: str, *, now: float | None = None) -> str | None:
        """None when the query may go upstream, else the reason it is failed locally."""
        now = time.monotonic() if now is None else now
        key = (qname.lower(), qtype)
        with self._lock:
            expiry = self._failed_names.get(key)
            if expiry is not None:
                if now < expiry:
                    self.fast_failed += 1
                    return "upstream:recent-failure"
                del self._failed_names[key]
            hold = self._zone_hold.get(zone)
            if hold is not None:
                if now < hold:
                    self.fast_failed += 1
                    return "upstream:zone-failing"
                del self._zone_hold[zone]
        return None

    def acquire(self, client: str, zone: str) -> bool:
        with self._lock:
            if (
                self.inflight >= UPSTREAM_INFLIGHT_TOTAL
                or self._inflight_client.get(client, 0) >= UPSTREAM_INFLIGHT_PER_CLIENT
                or self._inflight_zone.get(zone, 0) >= UPSTREAM_INFLIGHT_PER_ZONE
            ):
                self.busy_rejected += 1
                return False
            self.inflight += 1
            self._inflight_client[client] = self._inflight_client.get(client, 0) + 1
            self._inflight_zone[zone] = self._inflight_zone.get(zone, 0) + 1
            return True

    def release(self, client: str, zone: str) -> None:
        with self._lock:
            self.inflight = max(0, self.inflight - 1)
            for table, key in ((self._inflight_client, client), (self._inflight_zone, zone)):
                n = table.get(key, 0) - 1
                if n > 0:
                    table[key] = n
                else:
                    table.pop(key, None)

    def note_failure(self, qname: str, qtype: str, zone: str, *, now: float | None = None) -> None:
        now = time.monotonic() if now is None else now
        with self._lock:
            self._bounded_set(self._failed_names, (qname.lower(), qtype), now + FAIL_CACHE_SECONDS)
            times = [t for t in self._zone_failures.get(zone, ()) if now - t < ZONE_FAIL_WINDOW]
            times.append(now)
            if len(times) >= ZONE_FAIL_THRESHOLD:
                self._zone_failures.pop(zone, None)
                self._bounded_set(self._zone_hold, zone, now + ZONE_HOLD_SECONDS)
                logger.info("DNS zone %s keeps failing upstream; failing it fast for %d s", zone, ZONE_HOLD_SECONDS)
            else:
                self._bounded_set(self._zone_failures, zone, times)

    def stats(self) -> dict:
        with self._lock:
            return {"inflight": self.inflight, "fast_failed": self.fast_failed, "busy_rejected": self.busy_rejected,
                    "zones_held": len(self._zone_hold)}


def _zone_of(qname: str) -> str:
    """The unit a failing authority is charged to: the registrable domain, or one level up for PTRs
    (``4.3.2.1.in-addr.arpa`` → ``3.2.1.in-addr.arpa``) so one slow reverse zone cannot hold them all."""
    name = qname.lower().rstrip(".")
    if name.endswith(".arpa"):
        return name.split(".", 1)[1] if name.count(".") > 2 else name
    return registrable_domain(name) or "."


@dataclass
class QueryOutcome:
    action: str
    reason: str | None
    reply: DNSRecord | None


# ---- socketserver plumbing ----------------------------------------------------------------------
class _UdpHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        data, sock = self.request
        server: _UdpServer = self.server  # type: ignore[assignment]
        reply = server.dns.handle_query(data, self.client_address[0], tcp=False)
        if reply:
            try:
                sock.sendto(reply, self.client_address)
            except OSError as exc:
                logger.debug("udp send to %s failed: %s", self.client_address, exc)


def _recv_until(sock: socket.socket, n: int, deadline: float) -> bytes | None:
    """Exactly ``n`` bytes before ``deadline`` (monotonic), or None on EOF / timeout / error.

    The deadline covers the whole read: a per-``recv`` timeout alone lets a client that trickles one
    byte every few seconds hold its handler thread forever.
    """
    buf = bytearray()
    while len(buf) < n:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return None
        try:
            sock.settimeout(remaining)
            part = sock.recv(n - len(buf))
        except (OSError, socket.timeout):
            return None
        if not part:
            return None
        buf.extend(part)
    return bytes(buf)


class _TcpHandler(socketserver.BaseRequestHandler):
    """RFC 7766 framing with hard bounds: idle wait, per-message deadline, lifetime and query count."""

    def handle(self) -> None:
        server: _TcpServer = self.server  # type: ignore[assignment]
        sock: socket.socket = self.request
        client = self.client_address[0]
        closes_at = time.monotonic() + TCP_MAX_CONNECTION_SECONDS
        for _ in range(TCP_MAX_QUERIES_PER_CONNECTION):
            now = time.monotonic()
            first = _recv_until(sock, 1, min(now + TCP_IDLE_TIMEOUT, closes_at))
            if first is None:
                return
            deadline = min(time.monotonic() + TCP_MESSAGE_DEADLINE, closes_at)
            rest = _recv_until(sock, 1, deadline)
            if rest is None:
                return
            (length,) = struct.unpack("!H", first + rest)
            data = _recv_until(sock, length, deadline) if length else b""
            if data is None:
                return
            reply = server.dns.handle_query(data, client, tcp=True)
            if not reply:
                return
            try:
                sock.settimeout(TCP_MESSAGE_DEADLINE)
                sock.sendall(struct.pack("!H", len(reply)) + reply)
            except (OSError, socket.timeout):
                return


class _QuietMixin:
    daemon_threads = True

    def handle_error(self, request, client_address) -> None:  # noqa: D401 - socketserver hook
        logger.debug("handler error for %s", client_address, exc_info=True)


class _UdpServer(_QuietMixin, socketserver.ThreadingUDPServer):
    max_packet_size = 65535
    allow_reuse_address = False  # keep bind failing loudly when another resolver owns the port
    dns: "DnsServer"

    def server_bind(self) -> None:
        super().server_bind()
        # Windows reports ICMP port-unreachable for *previous* sends as ConnectionResetError on the next
        # recvfrom, which would kill the listener; SIO_UDP_CONNRESET disables that behaviour.
        if hasattr(socket, "ioctl") and platform.system() == "Windows":
            try:
                self.socket.ioctl(getattr(socket, "SIO_UDP_CONNRESET", 0x9800000C), False)
            except (OSError, AttributeError):  # pragma: no cover
                pass

    def verify_request(self, request, client_address) -> bool:  # noqa: D401 - socketserver hook
        # Refuse Internet sources before a handler thread is spent on them.
        return _accept_source(getattr(self, "dns", None), client_address[0])


class _TcpServer(_QuietMixin, socketserver.ThreadingTCPServer):
    """One thread per connection, but only ``TCP_MAX_CONNECTIONS`` of them (and
    ``TCP_MAX_CONNECTIONS_PER_CLIENT`` per source); extra connections are closed at accept time."""

    allow_reuse_address = platform.system() != "Windows"  # avoid TIME_WAIT bind failures on POSIX only
    request_queue_size = 64
    dns: "DnsServer"

    def __init__(self, *args, **kwargs) -> None:
        self._conn_lock = threading.Lock()
        self._conn_by_client: dict[str, int] = {}
        self.active_connections = 0
        self.refused_connections = 0
        super().__init__(*args, **kwargs)

    def verify_request(self, request, client_address) -> bool:  # noqa: D401 - socketserver hook
        client = client_address[0]
        if not _accept_source(getattr(self, "dns", None), client):
            return False
        with self._conn_lock:
            if (
                self.active_connections >= TCP_MAX_CONNECTIONS
                or self._conn_by_client.get(client, 0) >= TCP_MAX_CONNECTIONS_PER_CLIENT
            ):
                self.refused_connections += 1
                return False
            self.active_connections += 1
            self._conn_by_client[client] = self._conn_by_client.get(client, 0) + 1
        return True

    def _release(self, client: str) -> None:
        with self._conn_lock:
            self.active_connections = max(0, self.active_connections - 1)
            n = self._conn_by_client.get(client, 0) - 1
            if n > 0:
                self._conn_by_client[client] = n
            else:
                self._conn_by_client.pop(client, None)

    def process_request(self, request, client_address) -> None:
        try:
            super().process_request(request, client_address)
        except BaseException:  # the thread never started, so its finally below never runs
            self._release(client_address[0])
            raise

    def process_request_thread(self, request, client_address) -> None:
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._release(client_address[0])


def _accept_source(dns: "DnsServer | None", client: str) -> bool:
    if _client_is_local(client):
        return True
    if dns is not None:
        dns.dropped_foreign += 1
    return False


# ---- the server ---------------------------------------------------------------------------------
class DnsServer:
    """``DnsServer(cfg, conn).start()`` / ``.stop()``; components are injectable for tests."""

    def __init__(
        self,
        cfg,
        conn,
        *,
        policy: Policy | None = None,
        upstream: Upstream | None = None,
        cache: DnsCache | None = None,
        querylog: QueryLog | None = None,
        reputation: ReputationWorker | None = None,
        list_dir: Path | None = None,
    ) -> None:
        self.cfg = cfg
        self.conn = conn
        self.listen = str(cfg_get(cfg, "dns", "listen", "0.0.0.0") or "0.0.0.0")
        self.configured_port = int(cfg_get(cfg, "dns", "port", 53) or 0)
        self.block_mode = str(cfg_get(cfg, "dns", "block_mode", "null") or "null").lower()
        if self.block_mode not in ("null", "nxdomain"):
            logger.warning("unknown dns.block_mode %r; using 'null'", self.block_mode)
            self.block_mode = "null"
        self.list_dir = list_dir
        self.policy = policy
        self.upstream = upstream or Upstream(
            list(cfg_get(cfg, "dns", "upstreams", ["1.1.1.2", "9.9.9.9"]) or []),
            str(cfg_get(cfg, "dns", "doh_upstream", "") or ""),
        )
        self.cache = cache or DnsCache(int(cfg_get(cfg, "dns", "cache_max_entries", 20000) or 20000))
        self.querylog = querylog or QueryLog(conn, enabled=bool(cfg_get(cfg, "dns", "log_queries", True)))
        self.reputation = reputation
        self.ratelimit = _RateLimiter(RATE_LIMIT_QPS)          # UDP, keyed on the (forgeable) source
        self.tcp_ratelimit = _RateLimiter(RATE_LIMIT_QPS)      # TCP sources are real: their own buckets
        self.global_ratelimit = _RateLimiter(GLOBAL_RATE_LIMIT_QPS)  # large UDP answers only (see handle_query)
        self.guard = _UpstreamGuard()
        self.rate_limit_slipped = 0
        self._udp: _UdpServer | None = None
        self._tcp: _TcpServer | None = None
        self._threads: list[threading.Thread] = []
        self._stop = threading.Event()
        self._started_at: float | None = None
        self._last_health = 0.0
        self._last_metric = 0.0
        self._last_metric_values: dict[str, float] = {}
        self.dropped_foreign = 0
        self._lock = threading.Lock()
        self.last_error: str | None = None
        self.firewall_rule_present: bool | None = None
        self.queries_total = 0
        self.blocked_total = 0

    # ---- lifecycle ------------------------------------------------------------------------
    @property
    def running(self) -> bool:
        return self._udp is not None and self._started_at is not None

    @property
    def port(self) -> int:
        if self._udp is not None:
            return int(self._udp.server_address[1])
        return self.configured_port

    def ensure_components(self) -> None:
        """Build the heavy components lazily so constructing a DnsServer is cheap (CLI ``status``)."""
        try:
            ensure_schema(self.conn)
        except Exception:
            logger.debug("ensure_schema skipped", exc_info=True)
        if self.policy is None:
            self.policy = Policy.load(self.cfg, self.conn, list_dir=self.list_dir)
        if self.reputation is None:
            self.reputation = ReputationWorker(
                self.cfg,
                self.conn,
                on_malicious=self._on_malicious,
                budget=shared_budget(self.cfg, self.conn),
                skip=self.policy.is_never_block,
            )

    def start(self) -> bool:
        """Bind UDP+TCP and start worker threads. Returns False (and files NET-DNS-002) on a port conflict."""
        with self._lock:
            if self.running:
                return True
            self.ensure_components()
            addr = (self.listen, self.configured_port)
            try:
                self._udp = _UdpServer(addr, _UdpHandler)
                self._udp.dns = self
                bound = (self.listen, int(self._udp.server_address[1]))
                self._tcp = _TcpServer(bound, _TcpHandler)
                self._tcp.dns = self
            except OSError as exc:
                self._close_sockets()
                self.last_error = f"cannot bind {addr[0]}:{addr[1]}: {exc}"
                logger.error("DNS resolver not started: %s", self.last_error)
                record_event(self.conn, "error", "dns", self.last_error, {"listen": addr[0], "port": addr[1]})
                self._apply_health([self._port_conflict_draft(addr, str(exc))])
                return False
            self._stop.clear()
            self._started_at = time.monotonic()
            self.querylog.start()
            if self.reputation is not None:
                self.reputation.start()
            for name, target in (
                ("dns-udp", self._udp.serve_forever),
                ("dns-tcp", self._tcp.serve_forever),
                ("dns-housekeeping", self._housekeeping_loop),
            ):
                t = threading.Thread(target=target, name=name, daemon=True)
                t.start()
                self._threads.append(t)
            logger.info("DNS resolver listening on %s:%d (udp+tcp), block_mode=%s", bound[0], bound[1], self.block_mode)
            record_event(self.conn, "info", "dns", f"resolver listening on {bound[0]}:{bound[1]}")
            return True

    def stop(self) -> None:
        with self._lock:
            self._stop.set()
            for srv in (self._udp, self._tcp):
                if srv is not None:
                    try:
                        srv.shutdown()
                    except Exception:  # pragma: no cover
                        pass
            self._close_sockets()
            for t in self._threads:
                if t is not threading.current_thread():
                    t.join(timeout=5)
            self._threads.clear()
            if self.reputation is not None:
                self.reputation.stop()
            self.querylog.stop()
            self._started_at = None
            logger.info("DNS resolver stopped")

    def _close_sockets(self) -> None:
        for attr in ("_udp", "_tcp"):
            srv = getattr(self, attr)
            if srv is not None:
                try:
                    srv.server_close()
                except Exception:  # pragma: no cover
                    pass
            setattr(self, attr, None)

    # ---- query pipeline -------------------------------------------------------------------
    def handle_query(self, data: bytes, client: str, *, tcp: bool = False) -> bytes | None:
        """Wire-format in → wire-format out (None = drop silently). Never raises."""
        t0 = time.perf_counter()
        if not _client_is_local(client):
            # A home resolver only serves the LAN; queries from the Internet (a port-forward, or a
            # spoofed victim address) are dropped without an answer so we cannot be used as a reflector.
            self.dropped_foreign += 1
            return None
        # Only per-source limits here: a shared counter that drops queries lets a few forged sources
        # silence every device in the house. A UDP source over its limit gets a bare TC=1 reply instead
        # of silence, so a genuine client whose address is being forged retries over TCP (unforgeable,
        # separate bucket), while the forger gets back no more bytes than it sent.
        if tcp:
            if not self.tcp_ratelimit.allow(client):
                return None
        elif not self.ratelimit.allow(client):
            self.rate_limit_slipped += 1
            return _truncated_bytes(data)
        try:
            request = DNSRecord.parse(data)
        except (DNSError, Exception):
            return _formerr_bytes(data)
        if request.header.qr or not request.questions:
            return None if request.header.qr else _rcode_reply(request, RCODE.FORMERR)
        if request.header.opcode != OPCODE.QUERY:
            return _rcode_reply(request, RCODE.NOTIMP)
        try:
            outcome = self._process(request, client)
        except Exception:
            logger.exception("unexpected error handling query from %s", client)
            outcome = QueryOutcome("error", "internal", request.reply(ra=1, aa=0))
            outcome.reply.header.rcode = RCODE.SERVFAIL
        ms = (time.perf_counter() - t0) * 1000.0
        q = request.q
        qname = str(q.qname).rstrip(".") or "."
        self.queries_total += 1
        if outcome.action == "block":
            self.blocked_total += 1
        if outcome.action != "refused":
            self.querylog.record(client, qname, _qtype_name(q.qtype), outcome.action, outcome.reason, ms)
        if outcome.reply is None:
            return None
        return _finalize(request, outcome.reply, tcp=tcp, large_allowed=self._large_udp_allowed)

    def _large_udp_allowed(self) -> bool:
        """Global amplification ceiling, consulted only for UDP answers above ``MIN_UDP_SIZE``."""
        return self.global_ratelimit.allow(GLOBAL_CLIENT_KEY)

    def _process(self, request: DNSRecord, client: str) -> QueryOutcome:
        if self.policy is None:
            self.ensure_components()
        q: DNSQuestion = request.q
        qname = str(q.qname).rstrip(".") or "."
        qtype = _qtype_name(q.qtype)
        if q.qclass != CLASS.IN or qtype == "ANY":
            reply = request.reply(ra=1, aa=0)
            reply.header.rcode = RCODE.REFUSED
            return QueryOutcome("refused", "class/any", reply)

        # Policy first: a few dict probes, and a block must never be served from a stale cache entry.
        decision = self.policy.decide(qname, qtype, client)  # type: ignore[union-attr]
        if decision.blocked:
            return QueryOutcome("block", decision.reason, self._block_reply(request, qname, qtype))

        cached = self.cache.get(qname, qtype)
        if cached is not None:
            return QueryOutcome("cache", None, cached)

        zone = _zone_of(qname)
        refusal = self.guard.check(qname, qtype, zone)
        if refusal is not None:
            return QueryOutcome("error", refusal, _servfail(request))
        if not self.guard.acquire(client, zone):
            return QueryOutcome("error", "upstream:busy", _servfail(request))
        error: UpstreamError | None = None
        try:
            reply = self.upstream.resolve(_upstream_request(q))
        except UpstreamError as exc:
            error = exc
        finally:
            self.guard.release(client, zone)
        if error is not None:
            if not isinstance(error, CircuitOpenError):
                logger.warning("upstream failure for %s/%s: %s", qname, qtype, error)
                # One name failing is not evidence that the upstreams are down (its authority may be
                # slow on purpose); the upstream object decides that with its own canary. Only when the
                # upstreams are fine is the failure charged to this name and zone.
                if not self.upstream.note_query_failure():
                    self.guard.note_failure(qname, qtype, zone)
            return QueryOutcome("error", "upstream", _servfail(request))
        self.cache.put(qname, qtype, reply)
        if self.reputation is not None and reply.header.rcode == RCODE.NOERROR:
            self.reputation.enqueue(qname, client)
        return QueryOutcome("allow", decision.reason if decision.reason != "default" else None, reply)

    def _block_reply(self, request: DNSRecord, qname: str, qtype: str) -> DNSRecord:
        reply = request.reply(ra=1, aa=0)
        if self.block_mode == "nxdomain":
            reply.header.rcode = RCODE.NXDOMAIN
            return reply
        if qtype == "A":
            reply.add_answer(RR(request.q.qname, QTYPE.A, ttl=BLOCK_TTL, rdata=A("0.0.0.0")))
        elif qtype == "AAAA":
            reply.add_answer(RR(request.q.qname, QTYPE.AAAA, ttl=BLOCK_TTL, rdata=AAAA("::")))
        # any other type: NODATA (NOERROR, empty answer)
        return reply

    def _on_malicious(self, domain: str, client: str, result) -> None:
        """Reputation worker callback: block from now on and forget any cached answers."""
        if self.policy is not None:
            self.policy.mark_malicious(domain)
        self.cache.invalidate(domain)
        logger.warning("reputation: %s flagged malicious (%s) after query from %s", domain, result.source, client)

    def test_query(self, qname: str, qtype: str = "A") -> dict:
        """``dns-test`` helper: the policy decision plus the upstream answer (bypasses cache/log)."""
        self.ensure_components()
        decision = self.policy.decide(qname, qtype, "cli")  # type: ignore[union-attr]
        out = {"qname": qname, "qtype": qtype, "action": decision.action, "reason": decision.reason,
               "matched": decision.matched, "answers": [], "error": None}
        try:
            reply = self.upstream.resolve(DNSRecord.question(qname, qtype))
            out["answers"] = [str(rr.rdata) for rr in reply.rr]
            out["rcode"] = RCODE.get(reply.header.rcode)
        except UpstreamError as exc:
            out["error"] = str(exc)
        return out

    # ---- housekeeping & health ------------------------------------------------------------
    def _housekeeping_loop(self) -> None:
        self._check_firewall_rule()
        while not self._stop.wait(HOUSEKEEPING_TICK):
            try:
                self.housekeeping()
            except Exception:
                logger.exception("dns housekeeping tick failed")

    def housekeeping(self, *, now: float | None = None, force_health: bool = False) -> None:
        now = time.monotonic() if now is None else now
        if self.policy is not None:
            lists_changed = self.policy.maybe_reload(now=now)
            overrides_changed = self.policy.refresh_overrides_if_changed()
            if lists_changed or overrides_changed:
                self.cache.clear()  # a new list entry or allow/deny must beat answers cached under the old policy
        self.ratelimit.cleanup(now=now)
        self.tcp_ratelimit.cleanup(now=now)
        self.global_ratelimit.cleanup(now=now)
        if force_health or now - self._last_health >= HEALTH_INTERVAL:
            self._last_health = now
            self.cache.purge_expired(now=now)
            self._record_metrics(now, force=force_health)
            self._apply_health(self.health_findings(now=now))

    def _record_metrics(self, now: float, *, force: bool = False) -> None:
        """dns.qps / dns.cache_size, down-sampled: a resolver that idles all night must not write
        two metric rows a minute forever."""
        values = {"dns.qps": self.querylog.qps_1m(), "dns.cache_size": float(self.cache.size)}
        due = force or now - self._last_metric >= METRIC_INTERVAL
        if not due and all(self._last_metric_values.get(k) == v for k, v in values.items()):
            return
        self._last_metric = now
        self._last_metric_values = values
        for name, value in values.items():
            record_metric(self.conn, name, value)

    def health_findings(self, *, now: float | None = None) -> list:
        """Drafts for NET-DNS-001/003/005/006 that currently apply (empty list = all healthy)."""
        now = time.monotonic() if now is None else now
        drafts: list = []
        failing = self.upstream.failing_for(now)
        if failing >= UPSTREAM_FAIL_SECONDS:
            drafts.append(make_draft(
                "NET-DNS-005", "dns",
                evidence={"failing_seconds": int(failing), **self.upstream.status()},
                detail=f"All DNS upstreams have failed for {int(failing)} s; clients get SERVFAIL.",
            ))
        if self.policy is not None:
            stale = self.policy.stale_lists()
            if stale and self.policy.list_names:
                ages = [
                    (time.time() - float(s["mtime"])) / 86400.0
                    for s in self.policy.list_status() if s.get("mtime") is not None
                ]
                drafts.append(make_draft(
                    "NET-DNS-003", "dns",
                    evidence={"lists": stale, "status": self.policy.list_status(),
                              "age_days": int(max(ages)) if ages else "never downloaded"},
                    detail=f"Blocklists older than 3 days or missing: {', '.join(stale)}.",
                ))
        uptime = 0.0 if self._started_at is None else now - self._started_at
        if self.running and uptime >= CLIENTS_CHECK_MIN_UPTIME:
            # SPEC-GAP: the spec does not say when to start counting; wait an hour of uptime so a fresh
            # install is not immediately told "nobody uses the resolver".
            try:
                clients = distinct_clients(self.conn, 24)
            except Exception:
                clients = None
            if clients is not None and clients < 2:
                drafts.append(make_draft(
                    "NET-DNS-001", "dns",
                    evidence={"clients_24h": clients, "listen": self.listen, "port": self.port,
                              "ip": _advertised_ip(self.listen)},
                    detail="Fewer than 2 devices used the Home SOC resolver in 24 h; point the router's DHCP DNS at this host.",
                ))
        if self.running and self.firewall_rule_present is False and not self.listen.startswith("127."):
            drafts.append(make_draft(
                "NET-DNS-006", "dns",
                evidence={"listen": self.listen, "port": self.port},
                detail="Resolver is bound to the LAN but no inbound firewall rule for port 53 was found; run scripts/enable-lan-dns.ps1.",
            ))
        return drafts

    def _apply_health(self, drafts: list) -> None:
        apply_findings(self.conn, drafts, SOURCE_HEALTH, scope="dns")

    def _port_conflict_draft(self, addr: tuple[str, int], error: str):
        reason = f"port {addr[1]} in use" if "10048" in error or "in use" in error.lower() else error[:120]
        return make_draft(
            "NET-DNS-002", "dns",
            evidence={"listen": addr[0], "port": addr[1], "error": error, "reason": reason},
            detail=f"The DNS resolver could not bind {addr[0]}:{addr[1]} ({error}). Another resolver may own the port.",
        )

    def _check_firewall_rule(self) -> None:
        """Best-effort Windows check for an inbound allow rule on port 53 (feeds NET-DNS-006)."""
        if platform.system() != "Windows" or self.listen.startswith("127."):
            return
        try:
            proc = subprocess.run(
                ["netsh", "advfirewall", "firewall", "show", "rule", "name=all", "dir=in"],
                capture_output=True, text=True, timeout=30, encoding="utf-8", errors="replace",
            )
        except (OSError, subprocess.TimeoutExpired):
            return
        text = proc.stdout or ""
        # A rule block contains "LocalPort:  53" (or "Any") together with "Action: Allow".
        present = False
        for block in text.split("\n\n"):
            if "Allow" in block and ("Home SOC DNS" in block or "LocalPort:" in block and _has_port_53(block)):
                present = True
                break
        self.firewall_rule_present = present

    # ---- stats ----------------------------------------------------------------------------
    def stats(self) -> dict:
        budget_used = 0
        try:
            budget_used = shared_budget(self.cfg, self.conn).used_today()
        except Exception:
            pass
        return {
            "running": self.running,
            "port": self.port,
            "qps_1m": self.querylog.qps_1m(),
            "cache_size": self.cache.size,
            "lists_loaded": self.policy.lists_loaded if self.policy else 0,
            "list_entries": self.policy.list_entries if self.policy else 0,
            "upstream_ok": self.upstream.ok,
            "vt_budget_used": budget_used,
            "queries_total": self.queries_total,
            "blocked_total": self.blocked_total,
            "rate_limited": self.ratelimit.dropped + self.tcp_ratelimit.dropped + self.global_ratelimit.dropped,
            "rate_limit_slipped": self.rate_limit_slipped,
            "upstream_guard": self.guard.stats(),
            "tcp_refused": self._tcp.refused_connections if self._tcp is not None else 0,
            "dropped_foreign": self.dropped_foreign,
            "block_mode": self.block_mode,
            "listen": self.listen,
            "last_error": self.last_error,
            "reputation": self.reputation.stats() if self.reputation else None,
        }


# ---- wire helpers -------------------------------------------------------------------------------
def _client_is_local(client: str) -> bool:
    """Loopback, RFC 1918/ULA, link-local and CGNAT sources are served; anything global is not."""
    try:
        addr = ipaddress.ip_address(client.split("%", 1)[0])
    except ValueError:
        return False
    return addr.is_private or addr.is_loopback or addr.is_link_local or not addr.is_global


def _advertised_ip(listen: str) -> str:
    """The address other devices should use as their DNS server (0.0.0.0 is meaningless to them)."""
    if listen and not listen.startswith(("0.0.0.0", "::", "127.")):
        return listen
    try:
        from homesoc.util import default_interface_ip  # type: ignore

        return default_interface_ip()
    except Exception:
        return listen


def _qtype_name(qtype: int) -> str:
    try:
        return QTYPE[qtype]
    except (KeyError, DNSError):
        return f"TYPE{qtype}"


def _has_port_53(block: str) -> bool:
    for line in block.splitlines():
        if line.strip().startswith("LocalPort"):
            value = line.split(":", 1)[1].strip() if ":" in line else ""
            return value == "Any" or "53" in [p.strip() for p in value.split(",")]
    return False


def _upstream_request(q: DNSQuestion) -> DNSRecord:
    """Fresh request (new id, minimal EDNS) so client-specific EDNS options never leak upstream."""
    req = DNSRecord(q=DNSQuestion(q.qname, q.qtype, q.qclass))
    req.header.rd = 1
    req.add_ar(EDNS0(udp_len=EDNS_UDP_SIZE))
    return req


def _client_opt(request: DNSRecord):
    for rr in request.ar:
        if rr.rtype == QTYPE.OPT:
            return rr
    return None


def _servfail(request: DNSRecord) -> DNSRecord:
    reply = request.reply(ra=1, aa=0)
    reply.header.rcode = RCODE.SERVFAIL
    return reply


def _truncated_bytes(data: bytes) -> bytes | None:
    """A bare TC=1 answer echoing the id and the single question, built without a full parse.

    Never longer than the query itself (no answer or additional section), so it is worthless as a
    reflector. None for anything that is not a plain one-question QUERY.
    """
    if len(data) < 12 or data[2] & 0x80 or (data[2] >> 3) & 0x0F != OPCODE.QUERY:
        return None
    if data[4:6] != b"\x00\x01":
        return None
    i = 12
    while True:
        if i >= len(data) or i - 12 > 255:
            return None
        n = data[i]
        if n == 0:
            i += 1
            break
        if n & 0xC0:  # compression pointer / extended label type: not something a stub resolver sends
            return None
        i += 1 + n
    end = i + 4
    if end > len(data):
        return None
    flags = bytes([0x80 | (data[2] & 0x79) | 0x02, 0x80])  # QR, opcode+RD copied, TC; RA, NOERROR
    return data[:2] + flags + b"\x00\x01\x00\x00\x00\x00\x00\x00" + data[12:end]


def _finalize(request: DNSRecord, reply: DNSRecord, *, tcp: bool, large_allowed=None) -> bytes:
    """Make ``reply`` a valid answer to ``request``: id/question/flags, EDNS presence, UDP size.

    ``large_allowed`` (optional callable) is asked before a UDP answer larger than ``MIN_UDP_SIZE``
    goes out; when it says no the answer is truncated (TC=1) so the client retries over TCP.
    """
    reply.header.id = request.header.id
    reply.header.qr = 1
    reply.header.ra = 1
    reply.header.aa = 0
    reply.header.rd = request.header.rd
    reply.questions = list(request.questions)
    client_opt = _client_opt(request)
    reply.ar = [rr for rr in reply.ar if rr.rtype != QTYPE.OPT]
    max_udp = MIN_UDP_SIZE
    if client_opt is not None:
        reply.add_ar(EDNS0(udp_len=EDNS_UDP_SIZE))
        # Clamp to 1232 regardless of what the client advertises: larger answers go over TCP (TC=1),
        # which a spoofed source cannot complete.
        max_udp = max(MIN_UDP_SIZE, min(MAX_UDP_SIZE, int(client_opt.edns_len)))
    packed = bytes(reply.pack())  # dnslib hands back a bytearray
    if tcp or (
        len(packed) <= max_udp
        and (len(packed) <= MIN_UDP_SIZE or large_allowed is None or large_allowed())
    ):
        return packed
    reply.header.tc = 1
    reply.rr, reply.auth = [], []
    reply.ar = [rr for rr in reply.ar if rr.rtype == QTYPE.OPT]
    return bytes(reply.pack())


def _rcode_reply(request: DNSRecord, rcode: int) -> bytes:
    reply = request.reply(ra=1, aa=0)
    reply.header.rcode = rcode
    return bytes(reply.pack())


def _formerr_bytes(data: bytes) -> bytes | None:
    """Echo the id with FORMERR when at least a header is present; otherwise drop."""
    if len(data) < 12:
        return None
    ident = data[:2]
    # QR=1, opcode copied from request, RCODE=1; zero counts.
    flags = bytes([(data[2] & 0x78) | 0x80, 0x01])
    return ident + flags + b"\x00" * 8
