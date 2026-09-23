"""Security regressions for homesoc.dnsfilter, second round (2026-09-22).

Each test encodes one verified exploit from the second audit and asserts it no longer works. The
common thread: UDP source addresses are free to forge on a LAN, so no limit shared by "all sources"
may fail anyone's queries or blind the owner's records. Everything runs in-process or on 127.0.0.1
with fake upstreams; nothing touches the real network, data/ or config.toml.
"""
from __future__ import annotations

import socket
import socketserver
import sqlite3
import struct
import threading
import time
import types

import pytest
from dnslib import NS, QTYPE, RCODE, RR, A, DNSRecord

from homesoc.dnsfilter import querylog
from homesoc.dnsfilter import reputation
from homesoc.dnsfilter import server as server_mod
from homesoc.dnsfilter import upstream as upstream_mod
from homesoc.dnsfilter.clients import KnownClients
from homesoc.dnsfilter.reputation import Budget, ReputationWorker
from homesoc.dnsfilter.server import DnsServer
from homesoc.dnsfilter.upstream import Upstream


# ---- helpers ------------------------------------------------------------------------------------
def make_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(":memory:", check_same_thread=False)
    conn.row_factory = sqlite3.Row
    querylog.ensure_schema(conn)
    conn.executescript(
        "CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY, value TEXT NOT NULL, updated_at TEXT NOT NULL);"
        "CREATE TABLE IF NOT EXISTS events(id INTEGER PRIMARY KEY, ts TEXT NOT NULL, level TEXT NOT NULL,"
        " source TEXT NOT NULL, message TEXT NOT NULL, data TEXT);"
        "CREATE TABLE IF NOT EXISTS devices(id INTEGER PRIMARY KEY, mac TEXT UNIQUE, ip TEXT, hostname TEXT,"
        " first_seen TEXT NOT NULL, last_seen TEXT NOT NULL);"
    )
    conn.commit()
    return conn


def add_device(conn: sqlite3.Connection, ip: str, mac: str) -> None:
    now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    conn.execute("INSERT INTO devices(mac, ip, first_seen, last_seen) VALUES (?,?,?,?)", (mac, ip, now, now))
    conn.commit()


def make_cfg(**dns_overrides) -> types.SimpleNamespace:
    dns = dict(
        enabled=True, listen="127.0.0.1", port=0, upstreams=["127.0.0.1:1"], doh_upstream="", block_mode="null",
        cache_max_entries=1000, lists=["oisd_small"], log_queries=True, log_retention_days=14,
        virustotal_api_key="", virustotal_daily_budget=400, reputation_min_malicious_votes=2, reputation_ttl_hours=72,
    )
    dns.update(dns_overrides)
    return types.SimpleNamespace(dns=types.SimpleNamespace(**dns))


class FakeUpstream:
    """UDP fake recursive resolver on 127.0.0.1: answers the root NS canary and ``*.victim.org`` at once,
    never answers ``*.slow.test`` / ``*.slow.example`` (an attacker's slow authority)."""

    def __init__(self) -> None:
        self.queries: list[str] = []
        outer = self

        class Handler(socketserver.BaseRequestHandler):
            def handle(self_inner) -> None:
                data, sock = self_inner.request
                req = DNSRecord.parse(data)
                name = str(req.q.qname).rstrip(".").lower()
                outer.queries.append(name or ".")
                if ".slow." in f".{name}" or name.endswith(".slow.test"):
                    return
                reply = req.reply()
                if name == "" and req.q.qtype == QTYPE.NS:
                    reply.add_answer(RR(".", QTYPE.NS, ttl=3600, rdata=NS("a.root-servers.net.")))
                elif name.endswith("victim.org"):
                    reply.add_answer(RR(req.q.qname, QTYPE.A, ttl=300, rdata=A("10.0.0.1")))
                else:
                    reply.header.rcode = RCODE.NXDOMAIN
                sock.sendto(reply.pack(), self_inner.client_address)

        self.srv = socketserver.ThreadingUDPServer(("127.0.0.1", 0), Handler)
        self.srv.daemon_threads = True
        self.addr = f"127.0.0.1:{self.srv.server_address[1]}"
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()

    def close(self) -> None:
        self.srv.shutdown()
        self.srv.server_close()


@pytest.fixture
def conn():
    return make_conn()


@pytest.fixture
def lists_dir(tmp_path):
    (tmp_path / "oisd_small.txt").write_text("||ads.example.com^\n", encoding="utf-8")
    return tmp_path


@pytest.fixture
def fake_upstream():
    fu = FakeUpstream()
    try:
        yield fu
    finally:
        fu.close()


def _resolver(conn, lists_dir, upstream_addr="127.0.0.1:1", **up_kw) -> DnsServer:
    cfg = make_cfg(upstreams=[upstream_addr])
    up = Upstream([upstream_addr], "", **({"timeout": 0.3} | up_kw))
    srv = DnsServer(cfg, conn, list_dir=lists_dir, upstream=up, reputation=ReputationWorker(cfg, conn, enabled=False))
    srv.ensure_components()
    return srv


def _parse(wire: bytes | None) -> DNSRecord | None:
    return None if wire is None else DNSRecord.parse(wire)


class _StubSock:
    def __init__(self) -> None:
        self.sent: list[tuple[bytes, tuple]] = []

    def sendto(self, data, addr) -> None:
        self.sent.append((bytes(data), addr))


# ---- 1. UDP: no thread per datagram; limits run on the listener before anything is queued -------
def test_udp_listener_starts_no_thread_per_datagram_and_sheds_with_tc():
    """Round two's finding: ThreadingUDPServer spawned a thread for every datagram before any limit ran.
    Now process_request (the listener's per-datagram hook) only enqueues; the fixed pool does the work."""
    srv = server_mod._UdpServer(("127.0.0.1", 0), server_mod._UdpHandler, workers=2, queue_max=16)
    try:
        srv.dns = types.SimpleNamespace(ratelimit=server_mod._RateLimiter(10_000), rate_limit_slipped=0)
        sock = _StubSock()
        q = DNSRecord.question("www.victim.org").pack()
        before = threading.active_count()
        for i in range(500):
            srv.process_request((q, sock), (f"10.0.{i >> 8}.{i & 255}", 5353))
        assert threading.active_count() == before, "no thread may be started per datagram"
        assert srv._work.qsize() == 16 and srv.shed == 500 - 16
        tc = [DNSRecord.parse(d) for d, _ in sock.sent]
        assert len(tc) == 484 and all(r.header.tc == 1 and not r.rr for r in tc)   # shed = TC=1, never silence
        assert all(len(d) <= len(q) for d, _ in sock.sent)                         # never an amplifier
    finally:
        srv.server_close()


def test_udp_rate_limit_runs_on_the_listener_before_the_queue():
    srv = server_mod._UdpServer(("127.0.0.1", 0), server_mod._UdpHandler, workers=1, queue_max=1000)
    try:
        srv.dns = types.SimpleNamespace(ratelimit=server_mod._RateLimiter(5), rate_limit_slipped=0)
        sock = _StubSock()
        q = DNSRecord.question("www.victim.org").pack()
        for _ in range(50):
            srv.process_request((q, sock), ("192.168.1.66", 5353))
        assert srv._work.qsize() <= 6                                  # over-limit datagrams never queue
        assert srv.dns.rate_limit_slipped >= 44 and len(sock.sent) == srv.dns.rate_limit_slipped
    finally:
        srv.server_close()


def _udp_ask(port: int, name: str, timeout: float = 2.0, src: str = "127.0.0.1") -> DNSRecord | None:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.bind((src, 0))
        s.settimeout(timeout)
        s.sendto(DNSRecord.question(name).pack(), ("127.0.0.1", port))
        return DNSRecord.parse(s.recv(65535))
    except socket.timeout:
        return None
    finally:
        s.close()


def test_slow_names_cannot_hold_the_udp_workers_and_threads_stay_bounded(conn, lists_dir, fake_upstream):
    """A burst of slow upstream names used to cost a thread each and share the workers with everyone
    else; now they wait on the bounded upstream pool while blocked/cached names are answered at once."""
    srv = _resolver(conn, lists_dir, fake_upstream.addr, timeout=1.0)
    assert srv.start()
    try:
        port = srv.port
        before = threading.active_count()
        flood = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            for i in range(200):
                flood.sendto(DNSRecord.question(f"n{i}.z{i}.slow.example").pack(), ("127.0.0.1", port))
            time.sleep(0.2)
            t0 = time.perf_counter()
            r = _udp_ask(port, "ads.example.com")
            elapsed = time.perf_counter() - t0
        finally:
            flood.close()
        assert r is not None and [str(x.rdata) for x in r.rr] == ["0.0.0.0"]
        assert elapsed < 0.5, f"blocked name waited {elapsed:.2f}s behind slow upstream work"
        grown = threading.active_count() - before
        assert grown <= server_mod.UPSTREAM_INFLIGHT_PER_CLIENT + 4, grown   # per-source cap bounds its pool use
        assert srv.guard.stats()["inflight_udp"] <= server_mod.UPSTREAM_INFLIGHT_PER_CLIENT
    finally:
        srv.stop()


# ---- 2. upstream guard: a pinned UDP total must not SERVFAIL innocent clients --------------------
def test_pinned_udp_upstream_total_answers_tc_and_tcp_still_resolves(conn, lists_dir, fake_upstream):
    """The PoC: 32 forged clients x 32 zones held the shared total (then 1024) and every innocent
    uncached lookup got SERVFAIL 'upstream:busy'."""
    srv = _resolver(conn, lists_dir, fake_upstream.addr)
    g = srv.guard
    held = 0
    for i in range(32):
        for k in range(32):
            if g.acquire(f"10.0.{i}.{k}", f"{i}.{k}.10.in-addr.arpa"):
                held += 1
    assert g.inflight_udp == server_mod.UPSTREAM_INFLIGHT_TOTAL
    assert not g.acquire("192.168.1.50", "victim.org")                     # the UDP total is pinned ...
    udp = _parse(srv.handle_query(DNSRecord.question("www.victim.org").pack(), "192.168.1.50"))
    assert udp.header.rcode == RCODE.NOERROR and udp.header.tc == 1 and not udp.rr   # ... TC=1, not SERVFAIL
    tcp = _parse(srv.handle_query(DNSRecord.question("www.victim.org").pack(), "192.168.1.50", tcp=True))
    assert tcp.header.rcode == RCODE.NOERROR and [str(x.rdata) for x in tcp.rr] == ["10.0.0.1"]


def test_forged_victim_udp_inflight_does_not_block_its_tcp_retry():
    g = server_mod._UpstreamGuard()
    for i in range(server_mod.UPSTREAM_INFLIGHT_PER_CLIENT):
        assert g.acquire("192.168.1.50", f"z{i}.example")                  # forged as the victim over UDP
    assert not g.acquire("192.168.1.50", "victim.org")
    assert g.acquire("192.168.1.50", "victim.org", tcp=True)               # separate TCP accounting
    g.release("192.168.1.50", "victim.org", tcp=True)
    assert g.stats()["inflight"] == server_mod.UPSTREAM_INFLIGHT_PER_CLIENT


def test_reverse_zones_are_charged_per_16_and_per_32():
    """PTR names were charged per /24 (IPv6: per nibble), an unlimited supply of distinct slow zones."""
    z = server_mod._zone_of
    assert z("4.3.2.1.in-addr.arpa") == z("9.9.2.1.in-addr.arpa") == "2.1.in-addr.arpa"
    v6 = "f.e.d.c.b.a.9.8.7.6.5.4.3.2.1.0.8.b.d.0.1.0.0.2.ip6.arpa"
    other = "0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa"
    assert z(v6) == z(other) == "8.b.d.0.1.0.0.2.ip6.arpa"
    assert z("www.example.co.uk") == "example.co.uk" and z("1.in-addr.arpa") == "1.in-addr.arpa"


# ---- 3. TCP fallback: a full table evicts an idle connection instead of refusing -----------------
class _StubDns:
    def __init__(self) -> None:
        self.dropped_foreign = 0

    def handle_query(self, data, client, *, tcp=False):
        return DNSRecord.parse(data).reply().pack()


@pytest.fixture
def small_tcp_server(monkeypatch):
    monkeypatch.setattr(server_mod, "TCP_MAX_CONNECTIONS", 4)
    monkeypatch.setattr(server_mod, "TCP_MAX_CONNECTIONS_PER_CLIENT", 2)
    monkeypatch.setattr(server_mod, "TCP_IDLE_TIMEOUT", 10.0)
    monkeypatch.setattr(server_mod, "TCP_IDLE_TIMEOUT_BUSY", 10.0)
    srv = server_mod._TcpServer(("127.0.0.1", 0), server_mod._TcpHandler)
    srv.dns = _StubDns()
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    try:
        yield srv
    finally:
        srv.shutdown()
        srv.server_close()


def _tcp_connect(addr, src: str) -> socket.socket:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((src, 0))
    s.connect(addr)
    return s


def _tcp_query(s: socket.socket, name: str, timeout: float = 2.0) -> DNSRecord | None:
    q = DNSRecord.question(name).pack()
    s.settimeout(timeout)
    try:
        s.sendall(struct.pack("!H", len(q)) + q)
        head = s.recv(2)
        if len(head) < 2:
            return None
        (n,) = struct.unpack("!H", head)
        return DNSRecord.parse(s.recv(n))
    except OSError:
        return None


def _handler_threads() -> int:
    return sum(1 for t in threading.enumerate() if "process_request_thread" in t.name)


def _closed_within(sock: socket.socket, seconds: float) -> bool:
    sock.settimeout(seconds)
    try:
        return sock.recv(1) == b""
    except (ConnectionResetError, ConnectionAbortedError):
        return True
    except socket.timeout:
        return False


def test_attacker_holding_every_tcp_slot_cannot_refuse_the_victims_fallback(small_tcp_server):
    """The PoC: 8 addresses x 8 idle connections filled all 64 slots and the victim's TCP retry (after
    a forged-flood TC=1) was refused for as long as the attacker kept them open."""
    addr = small_tcp_server.server_address
    base = _handler_threads()
    try:
        held = [_tcp_connect(addr, "127.0.0.2"), _tcp_connect(addr, "127.0.0.2"),
                _tcp_connect(addr, "127.0.0.3"), _tcp_connect(addr, "127.0.0.3")]
    except OSError:
        pytest.skip("this platform cannot bind 127.0.0.x aliases")
    try:
        for s in held:
            assert _tcp_query(s, "keepalive.example") is not None       # all four slots active, then idle
        assert small_tcp_server.active_connections == 4
        victim = _tcp_connect(addr, "127.0.0.50")
        try:
            r = _tcp_query(victim, "www.victim.org")
            assert r is not None and r.header.qr == 1, "the victim's TCP retry must be served"
        finally:
            victim.close()
        assert small_tcp_server.evicted_connections == 1 and small_tcp_server.refused_connections == 0
        assert sum(_closed_within(s, 1.0) for s in held) == 1               # exactly one idle attacker conn closed
        assert small_tcp_server.active_connections <= 4
        # the evicted connection's handler thread exits too (shutdown alone does not wake recv on Windows)
        deadline = time.monotonic() + 3
        while _handler_threads() > base + 3 and time.monotonic() < deadline:
            time.sleep(0.05)
        assert _handler_threads() <= base + 3
    finally:
        for s in held:
            s.close()


def test_tcp_idle_timeout_shrinks_when_the_table_is_busy(monkeypatch):
    srv = types.SimpleNamespace(active_connections=0)
    monkeypatch.setattr(server_mod, "TCP_MAX_CONNECTIONS", 64)
    assert server_mod._TcpServer.idle_timeout(srv) == server_mod.TCP_IDLE_TIMEOUT
    srv.active_connections = 40
    assert server_mod._TcpServer.idle_timeout(srv) == server_mod.TCP_IDLE_TIMEOUT_BUSY < server_mod.TCP_IDLE_TIMEOUT


# ---- 4. query log: forged sources cannot blind it to inventory devices ---------------------------
def test_forged_sources_cannot_stop_inventory_devices_being_logged(conn, lists_dir):
    """The PoC: 4096 forged sources at the start of a minute and no later client (a C2 lookup, the
    victim) was logged for the rest of the minute, without even an 'over budget' event."""
    add_device(conn, "192.168.1.50", "aa:bb:cc:00:00:50")
    add_device(conn, "192.168.1.66", "aa:bb:cc:00:00:66")
    srv = _resolver(conn, lists_dir)
    srv.known_clients.refresh()
    srv.querylog = querylog.QueryLog(conn, known=srv.known_clients)
    for i in range(querylog.LOG_BUDGET_MAX_CLIENTS):
        srv.handle_query(DNSRecord.question(f"f{i}.ads.example.com").pack(), f"10.0.{i >> 8}.{i & 255}")
    srv.handle_query(DNSRecord.question("c2-exfil.ads.example.com").pack(), "192.168.1.66")
    srv.handle_query(DNSRecord.question("victim-lookup.ads.example.com").pack(), "192.168.1.50")
    srv.handle_query(DNSRecord.question("unlisted.ads.example.com").pack(), "192.168.7.7")
    srv.querylog.flush()
    logged = {r["qname"]: r["client"] for r in conn.execute("SELECT qname, client FROM dns_queries WHERE client LIKE '192.168.%'")}
    assert logged.get("c2-exfil.ads.example.com") == "192.168.1.66"
    assert logged.get("victim-lookup.ads.example.com") == "192.168.1.50"
    assert "unlisted.ads.example.com" not in logged and srv.querylog.overflowed == 1
    ev = conn.execute("SELECT message FROM events WHERE message LIKE '%forging source addresses%'").fetchall()
    assert len(ev) == 1                                                     # the overflow leaves a trace now


def test_total_budget_exhaustion_does_not_reach_known_devices(conn):
    known = KnownClients(addresses=["192.168.1.50"])
    ql = querylog.QueryLog(conn, client_budget=10, total_budget=25, known=known)
    for i in range(100):
        ql.record(f"10.9.{i // 250}.{i % 250}", "x.example", "A", "block")    # forged sources use the total
    ql.record("192.168.1.50", "real.example", "A", "allow")
    assert ql.pending() == 26
    for _ in range(20):
        ql.record("192.168.1.50", "real.example", "A", "allow")
    assert ql.pending() == 25 + 10                                          # still its own per-client budget


def test_known_clients_come_from_the_inventory(conn):
    add_device(conn, "192.168.1.9", "aa:bb:cc:00:00:09")
    k = KnownClients(conn)
    assert "192.168.1.9" not in k and "127.0.0.1" in k
    assert k.refresh() and "192.168.1.9" in k and "10.1.2.3" not in k
    assert not KnownClients(sqlite3.connect(":memory:")).refresh()          # no devices table: keeps defaults


# ---- 5. reputation: forged sources cannot shut inventory devices out, nor spend all of VT ----------
def test_forged_sources_cannot_crowd_an_inventory_device_out_of_the_reputation_queue(conn):
    """The PoC: 11 forged sources x 500 filled the 5000-slot queue; a real device's lookup was refused."""
    w = ReputationWorker(make_cfg(), conn, session=_VtSession(), known=KnownClients(addresses=["192.168.1.5"]))
    for c in range(11):
        for i in range(reputation.QUEUE_PER_CLIENT_MAX):
            w.enqueue(f"www.flood{c}x{i}.com", f"192.168.1.{100 + c}")
    assert w.pending() == reputation.QUEUE_MAX
    assert not w.enqueue("x.other-forged.net", "192.168.1.200")            # unknown sources: still full
    assert w.enqueue("beacon.evil-c2.net", "192.168.1.5")                  # inventory device: own lane
    assert w._queue.get_nowait()[0] == "evil-c2.net"                       # ... and served first


def test_known_lane_is_bounded_per_device(conn):
    w = ReputationWorker(make_cfg(), conn, session=_VtSession(), known=KnownClients(addresses=["192.168.1.5"]))
    ok = sum(w.enqueue(f"www.k{i}.com", "192.168.1.5")
             for i in range(reputation.KNOWN_LANE_PER_CLIENT + reputation.QUEUE_PER_CLIENT_MAX + 10))
    assert ok == reputation.KNOWN_LANE_PER_CLIENT + reputation.QUEUE_PER_CLIENT_MAX
    w.drain(max_items=10_000)
    assert not w._pending_known and not w._pending_by_client               # slots released on dequeue


class _VtSession:
    def __init__(self) -> None:
        self.vt_calls = 0

    def get(self, url, **kw):
        self.vt_calls += 1
        body = {"data": {"attributes": {"last_analysis_stats": {"malicious": 0, "suspicious": 0,
                                                                 "harmless": 50, "undetected": 10}}}}
        return types.SimpleNamespace(status_code=200, json=lambda: body)

    def post(self, url, **kw):
        return types.SimpleNamespace(status_code=200, json=lambda: {"query_status": "no_results"})


def test_one_source_cannot_spend_the_whole_virustotal_budget(conn):
    cfg = make_cfg(virustotal_api_key="k" * 64)
    sess = _VtSession()
    budget = Budget(None, 400, per_minute=10_000)
    w = ReputationWorker(cfg, conn, session=sess, budget=budget, known=KnownClients(addresses=["192.168.1.5"]))
    for i in range(100):
        w.process(f"attacker{i}.example", f"www.attacker{i}.example", "192.168.1.66")
    assert sess.vt_calls == int(400 * reputation.VT_CLIENT_SHARE)           # 40, not 100
    for c in range(10):                                                      # rotating (forged) sources
        for i in range(50):
            w.process(f"rot{c}x{i}.example", f"rot{c}x{i}.example", f"10.7.{c}.1")
    assert sess.vt_calls == int(400 * reputation.VT_UNKNOWN_SHARE)          # all unknown sources: 200
    before = sess.vt_calls
    res = w.process("real-device-domain.example", "real-device-domain.example", "192.168.1.5")
    assert sess.vt_calls == before + 1 and "virustotal" in res.source       # inventory device still checked


def test_reputation_table_is_pruned(conn):
    old = "2020-01-01T00:00:00Z"
    new = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    rows = [(f"old{i}.example", "urlhaus", "clean", 0, 0, old, "{}") for i in range(50)]
    rows += [("evil-old.example", "urlhaus", "malicious", 2, 0, old, "{}")]
    rows += [(f"new{i}.example", "urlhaus", "clean", 0, 0, new, "{}") for i in range(30)]
    conn.executemany("INSERT INTO reputation(domain, source, verdict, malicious, suspicious, checked_at, raw)"
                     " VALUES (?,?,?,?,?,?,?)", rows)
    conn.commit()
    assert reputation.prune_reputation(conn, max_rows=20) == 61
    left = {r["domain"] for r in conn.execute("SELECT domain FROM reputation")}
    assert "evil-old.example" in left and len(left) == 20                   # malicious evicted last
    assert not any(d.startswith("old") for d in left)


# ---- 6. 0x20: one wrong-case reply no longer disables it for the life of the process -------------
class _CaseUpstream:
    """Raw UDP fake: lowercases the question on the replies listed in ``lower_on`` (1-based), echoes
    the exact case otherwise, and records the wire names it saw."""

    def __init__(self, lower_on: set[int]) -> None:
        self.lower_on = lower_on
        self.names: list[str] = []
        outer = self

        class Handler(socketserver.BaseRequestHandler):
            def handle(self_inner) -> None:
                data, sock = self_inner.request
                req = DNSRecord.parse(data)
                name = str(req.q.qname).rstrip(".")
                outer.names.append(name)
                qname = name.lower() if len(outer.names) in outer.lower_on else name
                out = DNSRecord.question(qname)
                out.header.id = req.header.id
                reply = out.reply()
                reply.add_answer(RR(qname, QTYPE.A, ttl=60, rdata=A("10.3.3.3")))
                sock.sendto(reply.pack(), self_inner.client_address)

        self.srv = socketserver.ThreadingUDPServer(("127.0.0.1", 0), Handler)
        self.srv.daemon_threads = True
        self.addr = f"127.0.0.1:{self.srv.server_address[1]}"
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()

    def close(self) -> None:
        self.srv.shutdown()
        self.srv.server_close()


def _expire_exclusion(up: Upstream, label: str) -> None:
    up._case_normalizing[label] = time.monotonic() - 1


def test_one_soft_reply_disables_0x20_only_temporarily():
    """The PoC: a single lowercased reply put the upstream in _case_normalizing forever; every later
    query went out in plain lowercase even though the upstream echoed case correctly."""
    fake = _CaseUpstream(lower_on={1})
    try:
        up = Upstream([fake.addr], timeout=1.0)
        name = "abcdefghijklmnop.example.org"
        assert up.resolve(DNSRecord.question(name)).rr
        until = up._case_normalizing[fake.addr]
        assert upstream_mod.CASE_EXCLUDE_FIRST - 5 < until - time.monotonic() <= upstream_mod.CASE_EXCLUDE_FIRST
        assert fake.addr in up.status()["case_normalizing"]
        assert up.resolve(DNSRecord.question(name)).rr
        assert fake.names[-1] == name                                        # excluded: plain name for now
        _expire_exclusion(up, fake.addr)
        for _ in range(3):
            assert up.resolve(DNSRecord.question(name)).rr
        assert any(n != name for n in fake.names[-3:]), "0x20 must come back after the exclusion expires"
        assert fake.addr not in up.status()["case_normalizing"] and not up._case_strikes
    finally:
        fake.close()


def test_repeated_soft_replies_back_off_and_are_capped():
    fake = _CaseUpstream(lower_on=set(range(1, 100)))                        # a real case-normalising upstream
    try:
        up = Upstream([fake.addr], timeout=1.0)
        holds = []
        for _ in range(9):
            assert up.resolve(DNSRecord.question("abcdefghijklmnop.example.org")).rr
            holds.append(round(up._case_normalizing[fake.addr] - time.monotonic()))
            _expire_exclusion(up, fake.addr)
        assert holds[0] <= 60 and holds[1] <= 120 and holds[1] > holds[0]
        assert max(holds) <= upstream_mod.CASE_EXCLUDE_MAX
    finally:
        fake.close()
