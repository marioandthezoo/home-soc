"""Security regressions for homesoc.dnsfilter (2026-09-22 audit).

Each test encodes one verified exploit and asserts it no longer works. Everything runs in-process or
on 127.0.0.1 with fake upstreams; nothing touches the real network, data/ or config.toml.
"""
from __future__ import annotations

import pathlib
import socket
import socketserver
import sqlite3
import struct
import threading
import time
import types
from pathlib import Path

import pytest
from dnslib import EDNS0, NS, QTYPE, RCODE, RR, A, DNSRecord

from homesoc.dnsfilter import policy as policy_mod
from homesoc.dnsfilter import querylog
from homesoc.dnsfilter import reputation
from homesoc.dnsfilter import server as server_mod
from homesoc.dnsfilter.policy import Policy, find_list_file, valid_list_name
from homesoc.dnsfilter.reputation import ReputationWorker
from homesoc.dnsfilter.server import DnsServer
from homesoc.dnsfilter.upstream import Upstream


# ---- helpers ------------------------------------------------------------------------------------
def make_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(":memory:", check_same_thread=False)
    conn.row_factory = sqlite3.Row
    querylog.ensure_schema(conn)
    conn.execute("CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY, value TEXT NOT NULL, updated_at TEXT NOT NULL)")
    conn.commit()
    return conn


def make_cfg(**dns_overrides) -> types.SimpleNamespace:
    dns = dict(
        enabled=True, listen="127.0.0.1", port=0, upstreams=["127.0.0.1:1"], doh_upstream="", block_mode="null",
        cache_max_entries=1000, lists=["oisd_small"], log_queries=True, log_retention_days=14,
        virustotal_api_key="", virustotal_daily_budget=400, reputation_min_malicious_votes=2, reputation_ttl_hours=72,
    )
    dns.update(dns_overrides)
    return types.SimpleNamespace(dns=types.SimpleNamespace(**dns))


class SlowZoneUpstream:
    """Fake recursive resolver on 127.0.0.1: answers the root NS canary and ``*.victim.org`` at once,
    never answers ``*.slow.test`` (an attacker's slow authority), and answers nothing when ``dead``."""

    def __init__(self) -> None:
        self.dead = False
        self.queries: list[str] = []
        outer = self

        class Handler(socketserver.BaseRequestHandler):
            def handle(self_inner) -> None:
                data, sock = self_inner.request
                req = DNSRecord.parse(data)
                name = str(req.q.qname).rstrip(".").lower()
                outer.queries.append(name or ".")
                if outer.dead or name.endswith("slow.test"):
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
def slow_upstream():
    fu = SlowZoneUpstream()
    try:
        yield fu
    finally:
        fu.close()


def _resolver(conn, lists_dir, upstream_addr="127.0.0.1:1", **up_kw) -> DnsServer:
    cfg = make_cfg(upstreams=[upstream_addr])
    up = Upstream([upstream_addr], "", **({"timeout": 0.3} | up_kw))
    srv = DnsServer(cfg, conn, list_dir=lists_dir, upstream=up,
                    reputation=ReputationWorker(cfg, conn, enabled=False))
    srv.ensure_components()
    return srv


def _rcode(wire: bytes | None) -> int | None:
    return None if wire is None else DNSRecord.parse(wire).header.rcode


class _FrozenLimiter(server_mod._RateLimiter):
    """Always the same one-second window, so a test never straddles a window boundary."""

    def allow(self, client, *, now=None):
        return super().allow(client, now=1000.0)


class _Deny:
    dropped = 0

    def allow(self, *a, **kw):
        return False

    def cleanup(self, **kw):
        pass


# ---- 1. global limiter: forged sources must not silence the house --------------------------------
def test_forged_sources_cannot_exhaust_a_shared_bucket(conn, lists_dir):
    """3000 junk packets from 3000 forged LAN sources used to use up the global bucket, after which an
    innocent device's query was dropped for the rest of the second."""
    srv = _resolver(conn, lists_dir)
    srv.ratelimit = _FrozenLimiter(server_mod.RATE_LIMIT_QPS)
    for i in range(3000):
        srv.handle_query(b"\x00" * 12, f"10.{(i >> 16) & 255}.{(i >> 8) & 255}.{i & 255}")
    victim = srv.handle_query(DNSRecord.question("ads.example.com").pack(), "192.168.1.50")
    assert victim is not None and _rcode(victim) == RCODE.NOERROR
    assert DNSRecord.parse(victim).rr, "victim got a real (sinkholed) answer, not silence or TC"
    assert srv.global_ratelimit.dropped == 0


def test_global_ceiling_only_truncates_large_udp_answers(conn, lists_dir):
    """The amplification ceiling now applies to >512-byte UDP answers only, and truncates instead of dropping."""
    srv = _resolver(conn, lists_dir)
    big = DNSRecord.question("huge.example.org").reply()
    for i in range(60):
        big.add_answer(RR("huge.example.org", QTYPE.A, ttl=300, rdata=A(f"10.0.0.{i}")))
    srv.cache.put("huge.example.org", "A", big)
    q = DNSRecord.question("huge.example.org")
    q.add_ar(EDNS0(udp_len=1232))
    first = DNSRecord.parse(srv.handle_query(q.pack(), "192.168.1.10"))
    srv.global_ratelimit = _Deny()                                     # ceiling reached
    second = DNSRecord.parse(srv.handle_query(q.pack(), "192.168.1.11"))
    assert first.header.tc == 0 and len(first.rr) == 60
    assert second.header.tc == 1 and not second.rr                    # over the ceiling: TC, not silence
    small = srv.handle_query(DNSRecord.question("ads.example.com").pack(), "192.168.1.12")
    assert DNSRecord.parse(small).rr                                   # small answers never consult it


def test_forged_victim_address_falls_back_to_tcp(conn, lists_dir):
    """Forging one victim's IP past the per-client limit used to cut that victim's DNS entirely."""
    srv = _resolver(conn, lists_dir)
    srv.ratelimit = _FrozenLimiter(server_mod.RATE_LIMIT_QPS)
    q = DNSRecord.question("ads.example.com").pack()
    for _ in range(server_mod.RATE_LIMIT_QPS + 50):
        srv.handle_query(b"\x00" * 12, "192.168.1.77")                 # forged junk as the victim
    udp = srv.handle_query(q, "192.168.1.77")
    assert udp is not None, "victim must hear something"
    r = DNSRecord.parse(udp)
    assert r.header.tc == 1 and r.header.qr == 1 and not r.rr and str(r.q.qname).rstrip(".") == "ads.example.com"
    assert len(udp) <= len(q)                                          # never an amplifier
    tcp = srv.handle_query(q, "192.168.1.77", tcp=True)                # the retry a real stub makes
    assert DNSRecord.parse(tcp).rr and DNSRecord.parse(tcp).header.tc == 0


def test_truncated_slip_reply_rejects_non_queries():
    assert server_mod._truncated_bytes(b"\x00" * 11) is None
    reply = DNSRecord.question("x.example").reply().pack()
    assert server_mod._truncated_bytes(reply) is None                  # a response, not a query
    ptr = bytearray(DNSRecord.question("x.example").pack())
    ptr[12] = 0xC0                                                     # compression pointer in the question
    assert server_mod._truncated_bytes(bytes(ptr)) is None


def test_rate_limiter_memory_is_bounded():
    rl = server_mod._RateLimiter(max_qps=5, max_keys=100)
    for i in range(1000):
        rl.allow(f"fd00::{i:x}", now=10.0)
    assert len(rl._buckets) <= 2 * 100 + 1


# ---- 2. circuit breaker: one slow zone must not SERVFAIL the house -------------------------------
def test_one_slow_name_does_not_open_the_breaker(conn, lists_dir, slow_upstream):
    srv = _resolver(conn, lists_dir, slow_upstream.addr)
    r = srv.handle_query(DNSRecord.question("a1.slow.test").pack(), "192.168.1.66")
    assert _rcode(r) == RCODE.SERVFAIL
    assert srv.upstream.ok, "a per-name timeout must not mark every upstream as down"
    assert srv.upstream.canary_runs == 1
    victim = srv.handle_query(DNSRecord.question("www1.victim.org").pack(), "192.168.1.20")
    assert _rcode(victim) == RCODE.NOERROR and DNSRecord.parse(victim).rr


def test_sustained_slow_zone_attack_leaves_other_names_resolving(conn, lists_dir, slow_upstream):
    """The PoC: an attacker streams unique *.slow.test names; before the fix ~93-100 % of the victim's
    uncached lookups got SERVFAIL."""
    srv = _resolver(conn, lists_dir, slow_upstream.addr)
    stop = threading.Event()

    def attacker() -> None:
        i = 0
        while not stop.is_set():
            i += 1
            threading.Thread(target=srv.handle_query, args=(DNSRecord.question(f"a{i}.slow.test").pack(), "192.168.1.66"),
                             daemon=True).start()
            time.sleep(0.05)

    t = threading.Thread(target=attacker, daemon=True)
    t.start()
    try:
        time.sleep(0.4)
        results = []
        for i in range(30):
            results.append(_rcode(srv.handle_query(DNSRecord.question(f"v{i}.victim.org").pack(), "192.168.1.20")))
            time.sleep(0.03)
    finally:
        stop.set()
        t.join(timeout=2)
    assert results.count(RCODE.NOERROR) == len(results), results
    assert srv.upstream.ok and srv.upstream.breaker_rejections == 0
    # the slow zone itself is now failed fast instead of costing a thread + timeout per query
    t0 = time.perf_counter()
    assert _rcode(srv.handle_query(DNSRecord.question("zz.slow.test").pack(), "192.168.1.66")) == RCODE.SERVFAIL
    assert time.perf_counter() - t0 < 0.2
    assert srv.guard.stats()["zones_held"] >= 1


def test_breaker_still_opens_when_upstreams_are_really_down(conn, lists_dir, slow_upstream):
    srv = _resolver(conn, lists_dir, slow_upstream.addr)
    slow_upstream.dead = True
    assert _rcode(srv.handle_query(DNSRecord.question("x.victim.org").pack(), "192.168.1.20")) == RCODE.SERVFAIL
    assert not srv.upstream.ok                                         # canary failed too → genuinely down
    assert srv.guard.stats()["zones_held"] == 0                        # an outage is not charged to zones
    slow_upstream.dead = False


def test_healthy_canary_closes_a_breaker_that_a_failed_probe_held_open(slow_upstream):
    up = Upstream([slow_upstream.addr], "", timeout=0.3)
    up.mark_all_failed()
    assert not up.ok
    assert up.note_query_failure() is False                            # attacker's probe failed, canary fine
    assert up.ok and up.failing_for() == 0.0


def test_repeated_failing_name_is_cached_not_retried(conn, lists_dir, slow_upstream):
    srv = _resolver(conn, lists_dir, slow_upstream.addr)
    q = DNSRecord.question("same.slow.test").pack()
    srv.handle_query(q, "192.168.1.66")
    before = len(slow_upstream.queries)
    t0 = time.perf_counter()
    assert _rcode(srv.handle_query(q, "192.168.1.66")) == RCODE.SERVFAIL
    assert time.perf_counter() - t0 < 0.2 and len(slow_upstream.queries) == before


def test_upstream_inflight_is_capped_per_client():
    g = server_mod._UpstreamGuard()
    got = [g.acquire("192.168.1.66", f"z{i}.example") for i in range(server_mod.UPSTREAM_INFLIGHT_PER_CLIENT + 5)]
    assert got.count(True) == server_mod.UPSTREAM_INFLIGHT_PER_CLIENT
    assert g.acquire("192.168.1.20", "victim.org")                     # other devices unaffected
    g.release("192.168.1.66", "z0.example")
    assert g.acquire("192.168.1.66", "z0.example")


# ---- 3. reputation: bounded seen-set, rollback on a full queue, per-client share -----------------
def test_seen_set_stays_bounded_and_cheap_past_50k():
    w = ReputationWorker(None, None)
    now = time.time()
    for i in range(reputation.SEEN_MAX + 10):
        w.should_lookup(f"www.d{i}.com", now=now)
    t0 = time.perf_counter()
    for i in range(2000):
        assert w.should_lookup(f"www.extra{i}.com", now=now) == f"extra{i}.com"
    elapsed = time.perf_counter() - t0
    assert len(w._seen) <= reputation.SEEN_MAX
    assert elapsed < 1.0, f"2000 inserts took {elapsed:.2f}s (was ~6.5 ms each)"


def test_finding_dedupe_table_is_bounded(conn, monkeypatch):
    monkeypatch.setattr(reputation, "apply_findings", lambda *a, **kw: None)
    em = reputation.MaliciousFindingEmitter(conn)
    res = reputation.ReputationResult("evil.example", "malicious", 2, 0, "urlhaus", checked_at="t")
    t0 = time.perf_counter()
    for i in range(reputation.EMITTED_MAX + 2000):
        assert em.emit(f"10.0.{i >> 8}.{i & 255}", "x.evil.example", res, now=1000.0) is not None
    assert len(em._emitted) <= reputation.EMITTED_MAX
    assert time.perf_counter() - t0 < 2.0
    last = reputation.EMITTED_MAX + 1999
    assert em.emit(f"10.0.{last >> 8}.{last & 255}", "x.evil.example", res, now=1000.0) is None  # still deduped


class _NoResultsSession:
    def __init__(self) -> None:
        self.hosts: list[str] = []

    def post(self, url, data=None, headers=None, timeout=None, **kwargs):
        self.hosts.append((data or {}).get("host", ""))
        return types.SimpleNamespace(status_code=200, json=lambda: {"query_status": "no_results"})

    def get(self, *a, **kw):  # pragma: no cover - no VT key configured
        raise AssertionError("VirusTotal must not be called without a key")


def test_full_queue_does_not_suppress_a_domain_for_24h(conn):
    sess = _NoResultsSession()
    w = ReputationWorker(make_cfg(), conn, session=sess)
    for i in range(reputation.QUEUE_MAX):                             # flood from many (forged) sources
        assert w.enqueue(f"www.flood{i}.com", f"10.1.{i // 250}.{i % 250}")
    assert w.pending() == reputation.QUEUE_MAX
    assert not w.enqueue("beacon.evil-c2.net", "192.168.1.20")        # dropped while full ...
    assert "evil-c2.net" not in w._seen                                # ... but not marked as seen
    w.drain(max_items=10)
    assert w.enqueue("beacon.evil-c2.net", "192.168.1.20")            # the next query gets it checked
    w.drain(max_items=reputation.QUEUE_MAX + 10)
    assert "evil-c2.net" in sess.hosts


def test_one_client_cannot_hold_the_whole_queue(conn):
    w = ReputationWorker(make_cfg(), conn, session=_NoResultsSession())
    ok = sum(w.enqueue(f"www.flood{i}.com", "192.168.1.66") for i in range(reputation.QUEUE_PER_CLIENT_MAX + 100))
    assert ok == reputation.QUEUE_PER_CLIENT_MAX
    assert w.enqueue("cdn.victim-site.org", "192.168.1.20")
    assert "flood" + str(reputation.QUEUE_PER_CLIENT_MAX + 50) + ".com" not in w._seen   # refused ones roll back
    w.drain(max_items=50)
    assert w.enqueue("www.flood-late.com", "192.168.1.66")             # slots come back as the queue drains


# ---- 4. TCP listener: bounded connections and per-message deadline --------------------------------
class _StubDns:
    def __init__(self) -> None:
        self.dropped_foreign = 0

    def handle_query(self, data, client, *, tcp=False):
        return DNSRecord.parse(data).reply().pack()


@pytest.fixture
def tcp_server(monkeypatch):
    monkeypatch.setattr(server_mod, "TCP_IDLE_TIMEOUT", 1.0)
    monkeypatch.setattr(server_mod, "TCP_MESSAGE_DEADLINE", 0.6)
    monkeypatch.setattr(server_mod, "TCP_MAX_CONNECTIONS_PER_CLIENT", 2)
    srv = server_mod._TcpServer(("127.0.0.1", 0), server_mod._TcpHandler)
    srv.dns = _StubDns()
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    try:
        yield srv
    finally:
        srv.shutdown()
        srv.server_close()


def _closed_within(sock: socket.socket, seconds: float) -> bool:
    sock.settimeout(seconds)
    try:
        return sock.recv(1) == b""
    except (ConnectionResetError, ConnectionAbortedError):
        return True
    except socket.timeout:
        return False


def test_tcp_trickle_cannot_hold_a_thread(tcp_server):
    """One byte every few seconds used to keep a handler thread alive forever (per-read timeout only)."""
    s = socket.create_connection(tcp_server.server_address)
    try:
        t0 = time.monotonic()
        s.sendall(b"\x00")                                             # length prefix, one byte at a time
        time.sleep(0.3)
        s.sendall(b"\x64")                                             # a 100-byte body ...
        closed = False
        while time.monotonic() - t0 < 4.0:                             # ... trickled a byte per 0.3 s
            if _closed_within(s, 0.3):
                closed = True
                break
            try:
                s.sendall(b"x")
            except OSError:
                closed = True
                break
        assert closed and time.monotonic() - t0 < 2.0                  # message deadline is 0.6 s here
    finally:
        s.close()


def test_tcp_connections_are_capped_per_source(tcp_server):
    held = [socket.create_connection(tcp_server.server_address) for _ in range(2)]
    try:
        time.sleep(0.2)
        extra = socket.create_connection(tcp_server.server_address)
        try:
            assert _closed_within(extra, 1.0), "third connection from one source must be refused"
        finally:
            extra.close()
        assert tcp_server.refused_connections >= 1
        # a well-behaved query on an accepted connection still works
        q = DNSRecord.question("ok.example").pack()
        held[0].sendall(struct.pack("!H", len(q)) + q)
        held[0].settimeout(2)
        (n,) = struct.unpack("!H", held[0].recv(2))
        assert DNSRecord.parse(held[0].recv(n)).header.qr == 1
    finally:
        for s in held:
            s.close()
    deadline = time.monotonic() + 3
    while tcp_server.active_connections and time.monotonic() < deadline:
        time.sleep(0.05)
    assert tcp_server.active_connections == 0                          # slots are released on close


def test_tcp_and_udp_refuse_internet_sources_before_spawning_a_thread():
    dns = _StubDns()
    fake_server = types.SimpleNamespace(dns=dns)
    assert server_mod._accept_source(dns, "8.8.8.8") is False and dns.dropped_foreign == 1
    assert server_mod._accept_source(dns, "192.168.1.5") is True
    assert server_mod._UdpServer.verify_request(fake_server, None, ("1.1.1.1", 53)) is False
    assert dns.dropped_foreign == 2


# ---- 5. query log: budgets, truncation, bounded rows ---------------------------------------------
def test_one_client_cannot_flood_the_query_log(conn, lists_dir):
    """A device sending long unique blocked names at its rate limit used to write ~10 GB/day."""
    srv = _resolver(conn, lists_dir)
    srv.querylog = querylog.QueryLog(conn, client_budget=50)
    label = "x" * 60
    for i in range(200):
        name = f"{label}.{label}.{label}.{i:05d}.ads.example.com"
        srv.handle_query(DNSRecord.question(name).pack(), "192.168.1.66")
    srv.handle_query(DNSRecord.question("ads.example.com").pack(), "192.168.1.20")
    assert srv.querylog.pending() == 51 and srv.querylog.suppressed == 150
    srv.querylog.flush()
    clients = {r["client"] for r in querylog.recent(conn, 100)}
    assert "192.168.1.20" in clients                                   # other devices still logged


def test_query_log_truncates_and_bounds_its_counters(conn):
    ql = querylog.QueryLog(conn)
    ql.record("192.168.1.66", "a" * 1000, "A", "block", "list:x" * 100, 0.1)
    for _ in range(20000):
        ql.record("192.168.1.67", "b.example", "A", "block")
    assert len(ql._recent) <= 61                                       # was one float per query
    ql.flush()
    row = conn.execute("SELECT qname, reason FROM dns_queries WHERE client='192.168.1.66'").fetchone()
    assert len(row["qname"]) <= querylog.MAX_QNAME_LOG and len(row["reason"]) <= 200


def test_query_log_total_budget(conn):
    ql = querylog.QueryLog(conn, client_budget=10, total_budget=25)
    for i in range(100):
        ql.record(f"10.9.{i // 250}.{i % 250}", "x.example", "A", "block")   # forged sources
    assert ql.pending() == 25


def test_row_cap_evicts_oldest(conn):
    rows = [(f"2026-09-22T00:00:{i % 60:02d}Z", "c", f"n{i}.example", "A", "block", None, 0.1) for i in range(1000)]
    conn.executemany("INSERT INTO dns_queries(ts,client,qname,qtype,action,reason,ms) VALUES (?,?,?,?,?,?,?)", rows)
    conn.commit()
    assert querylog.enforce_row_cap(conn, 100, chunk=37) == 900
    assert conn.execute("SELECT COUNT(*) FROM dns_queries").fetchone()[0] == 100
    assert conn.execute("SELECT COUNT(*) FROM dns_queries WHERE qname = 'n999.example'").fetchone()[0] == 1
    assert conn.execute("SELECT COUNT(*) FROM dns_queries WHERE qname = 'n0.example'").fetchone()[0] == 0
    assert querylog.enforce_row_cap(conn, 100) == 0


# ---- 6. dns.lists names are not filesystem paths --------------------------------------------------
@pytest.fixture
def private_tree(tmp_path):
    feeds = tmp_path / "data" / "feeds"
    feeds.mkdir(parents=True)
    (feeds / "oisd_small.txt").write_text("||ads.example.com^\n", encoding="utf-8")
    private = tmp_path / "private"
    private.mkdir()
    (private / "notes.txt").write_text("secret-vpn.internal-corp.example\n", encoding="utf-8")
    (private / "abs_hosts").write_text("10.0.0.1 onlyinabsfile.example\n", encoding="utf-8")
    return feeds, private


def test_list_names_cannot_escape_the_feeds_folder(private_tree, monkeypatch):
    feeds, private = private_tree
    touched: list[str] = []
    real_is_file = pathlib.Path.is_file

    def spy(self, *a, **kw):
        touched.append(str(self))
        return real_is_file(self, *a, **kw)

    monkeypatch.setattr(pathlib.Path, "is_file", spy)
    for bad in ("../../private/notes", str(private / "abs_hosts"), "//attacker/share/x", "\\\\attacker\\share\\x",
                "C:/Windows/System32/drivers/etc/hosts", "..", "OISD_small", "a.b"):
        assert find_list_file(bad, feeds) is None, bad
    assert not any("attacker" in p for p in touched), "a UNC name must never reach the filesystem"
    p = Policy(list_names=["oisd_small", "../../private/notes", str(private / "abs_hosts")], list_dir=feeds)
    p.reload(force=True)
    assert p.decide("secret-vpn.internal-corp.example").action == "allow"
    assert p.decide("onlyinabsfile.example").action == "allow"
    assert p.decide("ads.example.com").blocked                         # legitimate list still works
    errors = {s["name"]: s["error"] for s in p.list_status()}
    assert "invalid list name" in errors["../../private/notes"]


def test_real_feeds_folder_requires_a_registry_feed(monkeypatch):
    assert valid_list_name("oisd_small") and valid_list_name("hagezi_pro")
    assert not valid_list_name("notes")                                # grammar-valid but not a feed
    assert not valid_list_name("../x") and not valid_list_name("")
    assert valid_list_name("my-list", Path(".")) and not valid_list_name("my.list", Path("."))


def test_symlink_out_of_the_feeds_folder_is_refused(private_tree):
    feeds, private = private_tree
    link = feeds / "hagezi_pro.txt"
    try:
        link.symlink_to(private / "notes.txt")
    except (OSError, NotImplementedError):
        pytest.skip("creating symlinks needs extra privileges on this platform")
    assert find_list_file("hagezi_pro", feeds) is None
    assert policy_mod.find_list_file("oisd_small", feeds) == feeds / "oisd_small.txt"
