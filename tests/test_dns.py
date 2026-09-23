"""Offline tests for homesoc.dnsfilter (SPEC §12, §17).

A fake in-process upstream (UDP + TCP on one ephemeral port) stands in for 1.1.1.2; a fake HTTP
session stands in for VirusTotal / URLhaus / DoH. No test touches the real network.
"""
from __future__ import annotations

import datetime as dt
import json
import os
import socket
import socketserver
import sqlite3
import struct
import threading
import time
import types
from pathlib import Path

import pytest
from dnslib import AAAA, EDNS0, QTYPE, RCODE, RR, A, DNSError, DNSRecord

from homesoc.dnsfilter import (
    DnsServer,
    cache as cache_mod,
    policy as policy_mod,
    querylog,
    reputation,
    server as server_mod,
    upstream as upstream_mod,
)
from homesoc.dnsfilter.cache import DnsCache
from homesoc.dnsfilter.policy import Decision, Policy, add_override, parse_list_line, remove_override
from homesoc.dnsfilter.reputation import Budget, ReputationWorker, lookup_domain, lookup_domain_detail, registrable_domain
from homesoc.dnsfilter.server import _RateLimiter
from homesoc.dnsfilter.upstream import Upstream, UpstreamError, parse_upstream


# ---- helpers ------------------------------------------------------------------------------------
class FakeUpstream:
    """Answers A/AAAA from a table; ``big.*`` names come back truncated over UDP and complete over TCP."""

    def __init__(self) -> None:
        self.table: dict[str, str] = {"allowed.example.org": "93.184.216.34", "big.example.org": "10.0.0.9"}
        self.ttl = 300
        self.udp_queries = 0
        self.tcp_queries = 0
        self.drop_all = False
        self.seen_names: list[str] = []   # exactly as received, so 0x20 randomisation is observable
        fake = self

        class UdpHandler(socketserver.BaseRequestHandler):
            def handle(self_inner) -> None:
                data, sock = self_inner.request
                fake.udp_queries += 1
                if fake.drop_all:
                    return
                sock.sendto(fake.answer(data, tcp=False), self_inner.client_address)

        class TcpHandler(socketserver.StreamRequestHandler):
            def handle(self_inner) -> None:
                hdr = self_inner.rfile.read(2)
                if len(hdr) < 2:
                    return
                (n,) = struct.unpack("!H", hdr)
                data = self_inner.rfile.read(n)
                fake.tcp_queries += 1
                if fake.drop_all:
                    return
                out = fake.answer(data, tcp=True)
                self_inner.wfile.write(struct.pack("!H", len(out)) + out)

        for _ in range(20):
            self.udp = socketserver.ThreadingUDPServer(("127.0.0.1", 0), UdpHandler)
            port = self.udp.server_address[1]
            try:
                self.tcp = socketserver.ThreadingTCPServer(("127.0.0.1", port), TcpHandler)
                break
            except OSError:
                self.udp.server_close()
        else:  # pragma: no cover
            raise RuntimeError("could not find a free port pair")
        self.udp.daemon_threads = self.tcp.daemon_threads = True
        self.port = port
        self.addr = f"127.0.0.1:{port}"
        threading.Thread(target=self.udp.serve_forever, daemon=True).start()
        threading.Thread(target=self.tcp.serve_forever, daemon=True).start()

    def answer(self, data: bytes, *, tcp: bool) -> bytes:
        req = DNSRecord.parse(data)
        reply = req.reply()
        self.seen_names.append(str(req.q.qname).rstrip("."))
        name = str(req.q.qname).rstrip(".").lower()
        if name.startswith("big.") and not tcp:
            reply.header.tc = 1
            return reply.pack()
        ip = self.table.get(name)
        if ip is None:
            reply.header.rcode = RCODE.NXDOMAIN
        elif req.q.qtype == QTYPE.A:
            reply.add_answer(RR(req.q.qname, QTYPE.A, ttl=self.ttl, rdata=A(ip)))
        elif req.q.qtype == QTYPE.AAAA:
            reply.add_answer(RR(req.q.qname, QTYPE.AAAA, ttl=self.ttl, rdata=AAAA("2001:db8::1")))
        return reply.pack()

    def close(self) -> None:
        for s in (self.udp, self.tcp):
            s.shutdown()
            s.server_close()


class FakeResponse:
    def __init__(self, status: int = 200, body: dict | bytes | None = None) -> None:
        self.status_code = status
        self._body = body

    def json(self):
        if isinstance(self._body, dict):
            return self._body
        raise ValueError("not json")

    @property
    def content(self) -> bytes:
        if isinstance(self._body, (bytes, bytearray)):
            return bytes(self._body)
        return json.dumps(self._body or {}).encode()


class FakeSession:
    """Routes VT / URLhaus / DoH calls to canned responses and records what was asked."""

    def __init__(self, *, mountable: bool = False) -> None:
        self.vt: dict[str, dict] = {}
        self.urlhaus: dict[str, dict] = {}
        self.calls: list[tuple[str, str]] = []
        self.doh_answer: bytes | None = None
        self.fail = False
        self.headers_seen: list[dict] = []
        self.mounts: list[str] = []
        if mountable:  # a real requests.Session has .mount; the DoH IP pin is only used when it does
            self.mount = self._mount

    def _mount(self, prefix, adapter):
        self.mounts.append(prefix)

    def get(self, url, headers=None, timeout=None, **kwargs):  # stream/allow_redirects since the redirect fix
        self.headers_seen.append(dict(headers or {}))
        self.calls.append(("GET", url))
        if self.fail:
            raise ConnectionError("offline")
        domain = url.rsplit("/", 1)[-1]
        if domain in self.vt:
            return FakeResponse(200, {"data": {"attributes": {"last_analysis_stats": self.vt[domain]}}})
        return FakeResponse(404, {})

    def post(self, url, data=None, headers=None, timeout=None, **kwargs):
        self.headers_seen.append(dict(headers or {}))
        self.calls.append(("POST", url))
        if self.fail:
            raise ConnectionError("offline")
        if "dns-query" in url:
            if self.doh_answer is None:
                return FakeResponse(503, b"")
            req = DNSRecord.parse(data)
            reply = DNSRecord.parse(self.doh_answer)
            reply.header.id = req.header.id
            return FakeResponse(200, reply.pack())
        host = (data or {}).get("host", "")
        return FakeResponse(200, self.urlhaus.get(host, {"query_status": "no_results"}))


class RawUdpUpstream:
    """UDP-only fake whose reply bytes come from a callable: garbage, wrong question, spoof attempts."""

    def __init__(self, make_reply) -> None:
        self.make_reply = make_reply
        self.queries = 0
        outer = self

        class Handler(socketserver.BaseRequestHandler):
            def handle(self_inner) -> None:
                data, sock = self_inner.request
                outer.queries += 1
                out = outer.make_reply(data)
                if out:
                    sock.sendto(out, self_inner.client_address)

        self.srv = socketserver.ThreadingUDPServer(("127.0.0.1", 0), Handler)
        self.srv.daemon_threads = True
        self.port = int(self.srv.server_address[1])
        self.addr = f"127.0.0.1:{self.port}"
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()

    def close(self) -> None:
        self.srv.shutdown()
        self.srv.server_close()


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
        cache_max_entries=1000, lists=["oisd_small", "hagezi_pro"], log_queries=True, log_retention_days=14,
        virustotal_api_key="", virustotal_daily_budget=400, reputation_min_malicious_votes=2, reputation_ttl_hours=72,
    )
    dns.update(dns_overrides)
    return types.SimpleNamespace(dns=types.SimpleNamespace(**dns))


def write_lists(d: Path) -> Path:
    (d / "oisd_small.txt").write_text("! title\n||ads.example.com^\n||tracker.net^\n@@||good.tracker.net^\n", encoding="utf-8")
    (d / "hagezi_pro.txt").write_text("# hagezi\n*.evil.test\n*.malware.example\n", encoding="utf-8")
    return d


def query(port: int, name: str, qtype: str = "A", *, tcp: bool = False, edns: int | None = None) -> DNSRecord:
    q = DNSRecord.question(name, qtype)
    if edns is not None:
        q.add_ar(EDNS0(udp_len=edns))
    return DNSRecord.parse(q.send("127.0.0.1", port, tcp=tcp, timeout=3))


# ---- fixtures -----------------------------------------------------------------------------------
@pytest.fixture(scope="module")
def fake_upstream():
    fu = FakeUpstream()
    yield fu
    fu.close()


@pytest.fixture
def conn():
    return make_conn()


@pytest.fixture
def lists_dir(tmp_path):
    return write_lists(tmp_path)


@pytest.fixture
def server(conn, lists_dir, fake_upstream):
    cfg = make_cfg(upstreams=[fake_upstream.addr])
    srv = DnsServer(cfg, conn, list_dir=lists_dir, querylog=querylog.QueryLog(conn, flush_interval=0.2))
    assert srv.start() is True
    yield srv
    srv.stop()


# ---- policy -------------------------------------------------------------------------------------
@pytest.mark.parametrize(
    "line,expected",
    [
        ("0.0.0.0 ads.example.com", "ads.example.com"),
        ("127.0.0.1 tracker.net # comment", "tracker.net"),
        ("||abp.example.net^", "abp.example.net"),
        ("||abp.example.net^$third-party", "abp.example.net"),
        ("*.wild.org", "wild.org"),
        ("https://phish.example/login?x=1", "phish.example"),
        ("Plain.Domain.IO.", "plain.domain.io"),
        ("# comment", None),
        ("! abp comment", None),
        ("[Adblock Plus 2.0]", None),
        ("127.0.0.1 localhost", None),
        ("::1 ip6-localhost", None),
        ("1.2.3.4", None),
        ("@@||exception.example^", None),
        ("bad domain here", None),
        ("not_a_domain", None),
        ("", None),
    ],
)
def test_parse_list_line(line, expected):
    assert parse_list_line(line) == expected


def test_policy_decisions(conn, lists_dir):
    p = Policy.load(make_cfg(doh_upstream="https://cloudflare-dns.com/dns-query"), conn, list_dir=lists_dir)
    assert p.lists_loaded == 2 and p.list_entries == 4
    assert p.decide("ads.example.com", "A", "c") == Decision("block", "list:oisd_small", "ads.example.com")
    assert p.decide("cdn.ads.example.com", "A", "c").blocked            # parent-suffix match
    assert p.decide("ADS.Example.COM.", "A", "c").blocked                # case + trailing dot
    assert p.decide("notads.example.com", "A", "c").action == "allow"   # not a label boundary
    assert p.decide("x.evil.test", "AAAA", "c").reason == "list:hagezi_pro"
    assert p.decide("example.com", "A", "c") == Decision("allow", "default")
    # never-block wins over lists even if a list contains the name
    (lists_dir / "oisd_small.txt").write_text("||localhost^\n||printer.local^\n||1.168.192.in-addr.arpa^\n||cloudflare-dns.com^\n")
    p.reload(force=True)
    for name in ("localhost", "printer.local", "1.168.192.in-addr.arpa", "cloudflare-dns.com", "router.lan"):
        assert p.decide(name, "A", "c").reason == "never_block", name


def test_policy_overrides_and_reputation(conn, lists_dir):
    p = Policy.load(make_cfg(), conn, list_dir=lists_dir)
    add_override(conn, "ads.example.com", "allow", "needed for app")
    add_override(conn, "EXAMPLE.org.", "deny")
    p.reload_overrides()
    assert p.decide("ads.example.com", "A", "c") == Decision("allow", "override:allow", "ads.example.com")
    assert p.decide("sub.ads.example.com", "A", "c").action == "allow"
    assert p.decide("www.example.org", "A", "c") == Decision("block", "override:deny", "example.org")
    assert remove_override(conn, "example.org") is True
    assert remove_override(conn, "example.org") is False
    p.reload_overrides()
    assert p.decide("www.example.org", "A", "c").action == "allow"
    with pytest.raises(ValueError):
        add_override(conn, "example.org", "maybe")
    with pytest.raises(ValueError):
        add_override(conn, "not a domain", "deny")
    # reputation table: malicious with enough votes blocks, too few votes or stale does not
    now = reputation.utcnow_iso()
    conn.execute("INSERT INTO reputation VALUES ('bad.example.net','virustotal','malicious',5,0,?,NULL)", (now,))
    conn.execute("INSERT INTO reputation VALUES ('meh.example.net','virustotal','malicious',1,0,?,NULL)", (now,))
    conn.execute("INSERT INTO reputation VALUES ('old.example.net','virustotal','malicious',9,0,'2020-01-01T00:00:00Z',NULL)")
    conn.commit()
    p.reload(force=True)
    assert p.decide("cdn.bad.example.net", "A", "c") == Decision("block", "reputation", "bad.example.net")
    assert p.decide("meh.example.net", "A", "c").action == "allow"
    assert p.decide("old.example.net", "A", "c").action == "allow"
    p.mark_malicious("fresh.example.net")
    assert p.decide("fresh.example.net", "A", "c").reason == "reputation"


def test_policy_reload_on_mtime_change(conn, lists_dir, monkeypatch):
    p = Policy.load(make_cfg(), conn, list_dir=lists_dir)
    assert p.decide("newbad.example", "A", "c").action == "allow"
    path = lists_dir / "oisd_small.txt"
    path.write_text("||newbad.example^\n")
    import os

    os.utime(path, (time.time() + 5, time.time() + 5))  # guarantee a different mtime on coarse filesystems
    assert p.maybe_reload(now=p._last_check + 1) is False       # < 60 s: no check
    assert p.maybe_reload(now=p._last_check + 61) is True        # mtime changed → reloaded
    assert p.decide("newbad.example", "A", "c").blocked
    assert p.decide("ads.example.com", "A", "c").action == "allow"
    # missing / old lists are reported as stale
    assert p.stale_lists(now=time.time() + 4 * 86400) == ["oisd_small", "hagezi_pro"]
    assert p.stale_lists() == []
    status = {s["name"]: s for s in p.list_status()}
    assert status["oisd_small"]["entries"] == 1 and status["hagezi_pro"]["loaded"]


def test_policy_missing_list_file(conn, tmp_path):
    p = Policy.load(make_cfg(lists=["oisd_small", "nope"]), conn, list_dir=tmp_path)
    assert p.lists_loaded == 0 and p.list_entries == 0
    assert p.stale_lists() == ["oisd_small", "nope"]
    assert p.decide("anything.example", "A", "c").action == "allow"


# ---- cache --------------------------------------------------------------------------------------
def _reply(name: str, ttl: int, rcode: int = RCODE.NOERROR, answer: bool = True) -> DNSRecord:
    q = DNSRecord.question(name)
    r = q.reply()
    r.header.rcode = rcode
    if answer and rcode == RCODE.NOERROR:
        r.add_answer(RR(q.q.qname, QTYPE.A, ttl=ttl, rdata=A("10.1.1.1")))
    return r


def test_cache_ttl_and_lru():
    c = DnsCache(max_entries=2, min_ttl=30, negative_ttl=60)
    assert c.put("a.example", "A", _reply("a.example", 300), now=1000.0)
    hit = c.get("A.EXAMPLE.", "a", now=1010.0)
    assert hit is not None and hit.rr[0].ttl == 290                # decremented by time in cache
    assert c.get("a.example", "A", now=1300.0) is None             # expired at 1000+300
    assert c.put("short.example", "A", _reply("short.example", 5), now=0.0)
    assert c.get("short.example", "A", now=20.0) is not None       # min TTL 30 s
    assert c.get("short.example", "A", now=31.0) is None
    assert c.put("nx.example", "A", _reply("nx.example", 0, rcode=RCODE.NXDOMAIN), now=0.0)
    assert c.get("nx.example", "A", now=59.0) is not None          # negative cache 60 s
    assert c.get("nx.example", "A", now=61.0) is None
    assert c.put("nodata.example", "A", _reply("nodata.example", 0, answer=False), now=0.0)
    assert c.ttl_for(_reply("sf.example", 0, rcode=RCODE.SERVFAIL)) is None
    assert not c.put("sf.example", "A", _reply("sf.example", 0, rcode=RCODE.SERVFAIL))
    # LRU cap of 2
    c.clear()
    for n in ("one", "two", "three"):
        c.put(f"{n}.example", "A", _reply(f"{n}.example", 300), now=0.0)
    assert c.size == 2 and c.get("one.example", "A", now=1.0) is None
    assert c.invalidate("two.example") == 1 and c.size == 1
    assert c.purge_expired(now=10_000.0) == 1 and c.size == 0


# ---- upstream -----------------------------------------------------------------------------------
def test_parse_upstream():
    assert parse_upstream("1.1.1.2") == upstream_mod.UpstreamAddress("1.1.1.2", 53)
    assert parse_upstream("127.0.0.1:5353") == upstream_mod.UpstreamAddress("127.0.0.1", 5353)
    assert parse_upstream("[::1]:5353") == upstream_mod.UpstreamAddress("::1", 5353)
    assert parse_upstream("2620:fe::fe") == upstream_mod.UpstreamAddress("2620:fe::fe", 53)


def test_upstream_udp_and_tcp_fallback(fake_upstream):
    up = Upstream([fake_upstream.addr], timeout=2.0)
    r = up.resolve(DNSRecord.question("allowed.example.org"))
    assert str(r.rr[0].rdata) == "93.184.216.34" and up.ok
    before_tcp = fake_upstream.tcp_queries
    r = up.resolve(DNSRecord.question("big.example.org"))
    assert not r.header.tc and str(r.rr[0].rdata) == "10.0.0.9"
    assert fake_upstream.tcp_queries == before_tcp + 1            # TC bit → retried over TCP


def test_upstream_iteration_and_doh_fallback(fake_upstream):
    sess = FakeSession()
    up = Upstream(["127.0.0.1:1", fake_upstream.addr], timeout=0.5, session=sess)
    r = up.resolve(DNSRecord.question("allowed.example.org"))
    assert r.rr and up.health.last_upstream == fake_upstream.addr    # first upstream dead → second answered
    dead = Upstream(["127.0.0.1:1"], "https://cloudflare-dns.com/dns-query", timeout=0.3, session=sess)
    with pytest.raises(UpstreamError):
        dead.resolve(DNSRecord.question("allowed.example.org"))     # DoH returns 503
    dead.mark_all_failed()
    assert not dead.ok and dead.failing_for(time.monotonic() + 100) >= 100
    sess.doh_answer = _reply("allowed.example.org", 120).pack()
    r = dead.resolve(DNSRecord.question("allowed.example.org"))
    assert str(r.rr[0].rdata) == "10.1.1.1" and dead.ok and dead.failing_for() == 0.0
    assert any(url.endswith("dns-query") for _, url in sess.calls)


# ---- server -------------------------------------------------------------------------------------
def test_server_block_allow_tcp(server, fake_upstream):
    port = server.port
    r = query(port, "ads.example.com")
    assert r.header.rcode == RCODE.NOERROR and r.header.qr == 1 and r.header.ra == 1 and r.header.aa == 0
    assert [str(rr.rdata) for rr in r.rr] == ["0.0.0.0"] and r.rr[0].ttl == 60
    r6 = query(port, "ads.example.com", "AAAA")
    assert [str(rr.rdata) for rr in r6.rr] == ["::"]
    rtxt = query(port, "ads.example.com", "TXT")
    assert rtxt.header.rcode == RCODE.NOERROR and not rtxt.rr                       # NODATA
    before = fake_upstream.udp_queries
    r = query(port, "allowed.example.org")
    assert str(r.rr[0].rdata) == "93.184.216.34" and fake_upstream.udp_queries == before + 1
    r = query(port, "allowed.example.org")                                            # cache hit
    assert str(r.rr[0].rdata) == "93.184.216.34" and fake_upstream.udp_queries == before + 1
    assert r.rr[0].ttl <= 300
    r = query(port, "ads.example.com", tcp=True)                                     # TCP framing
    assert [str(rr.rdata) for rr in r.rr] == ["0.0.0.0"]
    r = query(port, "big.example.org", tcp=True)
    assert str(r.rr[0].rdata) == "10.0.0.9"
    nx = query(port, "unknown.example.org")
    assert nx.header.rcode == RCODE.NXDOMAIN
    server.querylog.flush()
    rows = querylog.recent(server.conn, 50)
    actions = {(row["qname"], row["qtype"]): row["action"] for row in rows}
    assert actions[("ads.example.com", "A")] == "block"
    assert actions[("big.example.org", "A")] == "allow"
    assert any(row["action"] == "cache" for row in rows)
    assert all(row["ms"] is not None and row["client"] == "127.0.0.1" for row in rows)
    st = server.stats()
    assert st["running"] and st["port"] == port and st["lists_loaded"] == 2 and st["list_entries"] == 4
    assert st["upstream_ok"] and st["cache_size"] >= 1 and st["vt_budget_used"] == 0 and st["qps_1m"] > 0
    assert set(st) >= {"running", "port", "qps_1m", "cache_size", "lists_loaded", "list_entries", "upstream_ok", "vt_budget_used"}


def test_server_refuses_any_and_non_in(server):
    q = DNSRecord.question("allowed.example.org", "ANY")
    r = DNSRecord.parse(q.send("127.0.0.1", server.port, timeout=3))
    assert r.header.rcode == RCODE.REFUSED
    q = DNSRecord.question("allowed.example.org", "A", "CH")
    r = DNSRecord.parse(server.handle_query(q.pack(), "10.0.0.5"))
    assert r.header.rcode == RCODE.REFUSED and r.header.id == q.header.id


def test_server_edns_and_truncation(server):
    r = query(server.port, "ads.example.com", edns=4096)
    opts = [rr for rr in r.ar if rr.rtype == QTYPE.OPT]
    assert len(opts) == 1 and opts[0].edns_len == 1232
    r = query(server.port, "ads.example.com")
    assert not [rr for rr in r.ar if rr.rtype == QTYPE.OPT]
    # oversized answer over UDP without EDNS → TC and no answers; over TCP → complete
    big = DNSRecord.question("huge.example.org").reply()
    for i in range(60):
        big.add_answer(RR("huge.example.org", QTYPE.A, ttl=300, rdata=A(f"10.0.{i // 250}.{i % 250}")))
    server.cache.put("huge.example.org", "A", big)
    q = DNSRecord.question("huge.example.org")
    r = DNSRecord.parse(server.handle_query(q.pack(), "10.0.0.5"))
    assert r.header.tc == 1 and not r.rr and r.q.qname == q.q.qname
    r = DNSRecord.parse(server.handle_query(q.pack(), "10.0.0.5", tcp=True))
    assert r.header.tc == 0 and len(r.rr) == 60


def test_server_malformed_and_rate_limit(server):
    assert server.handle_query(b"\x00\x01", "10.0.0.5") is None                   # too short → drop
    garbage = b"\x12\x34" + b"\x01\x00" + b"\x00\x01" + b"\x00" * 6 + b"\xff\xff\xff"
    r = server.handle_query(garbage, "10.0.0.5")
    assert r is not None and r[:2] == b"\x12\x34" and (r[3] & 0x0F) == RCODE.FORMERR
    response_pkt = DNSRecord.question("x.example").reply().pack()
    assert server.handle_query(response_pkt, "10.0.0.5") is None                  # replies are dropped
    rl = _RateLimiter(max_qps=3)
    assert [rl.allow("c", now=100.0) for _ in range(4)] == [True, True, True, False]
    assert rl.allow("other", now=100.0) and rl.allow("c", now=101.0) and rl.dropped == 1
    rl.cleanup(now=200.0)
    assert rl._buckets == {}
    q = DNSRecord.question("ads.example.com").pack()
    server.ratelimit = _RateLimiter(max_qps=5)
    results = [server.handle_query(q, "10.9.9.9") for _ in range(10)]
    # Over the per-client limit a UDP query no longer vanishes: it gets a bare TC=1 "slip"
    # reply (no answers, never larger than the query), so a victim whose address is being
    # forged falls back to TCP instead of losing DNS.
    parsed = [DNSRecord.parse(r) for r in results if r is not None]
    slipped = [p for p in parsed if p.header.tc]
    assert len(slipped) >= 5 and all(not p.rr for p in slipped)
    assert all(len(r) <= len(q) for r in results if r is not None and DNSRecord.parse(r).header.tc)


def test_server_nxdomain_mode_and_servfail(conn, lists_dir):
    cfg = make_cfg(block_mode="nxdomain", upstreams=["127.0.0.1:1"], doh_upstream="")
    srv = DnsServer(cfg, conn, list_dir=lists_dir, upstream=Upstream(["127.0.0.1:1"], timeout=0.3))
    srv.ensure_components()
    r = DNSRecord.parse(srv.handle_query(DNSRecord.question("ads.example.com").pack(), "10.0.0.5"))
    assert r.header.rcode == RCODE.NXDOMAIN and not r.rr
    r = DNSRecord.parse(srv.handle_query(DNSRecord.question("allowed.example.org").pack(), "10.0.0.5"))
    assert r.header.rcode == RCODE.SERVFAIL and not srv.upstream.ok
    srv.querylog.flush()
    assert querylog.recent(conn, 1)[0]["action"] == "error"
    drafts = srv.health_findings(now=time.monotonic() + 61)
    assert [d.finding_id for d in drafts] == ["NET-DNS-005"]
    assert drafts[0].subject == "dns" and drafts[0].evidence["failing_seconds"] >= 60


def test_server_picks_up_dashboard_overrides(server, conn):
    q = DNSRecord.question("allowed.example.org").pack()
    assert DNSRecord.parse(server.handle_query(q, "10.0.0.5")).rr[0].rdata.__str__() == "93.184.216.34"
    assert server.cache.size >= 1
    conn.execute("INSERT INTO dns_overrides VALUES ('example.org','deny',NULL,'2026-09-04T00:00:00Z')")
    conn.commit()                                  # what the web layer does, without telling the policy
    server.housekeeping()                          # one 5 s tick
    assert server.cache.size == 0
    assert [str(rr.rdata) for rr in DNSRecord.parse(server.handle_query(q, "10.0.0.5")).rr] == ["0.0.0.0"]
    assert server.policy.refresh_overrides_if_changed() is False
    conn.execute("DELETE FROM dns_overrides")
    conn.commit()
    assert server.policy.refresh_overrides_if_changed() is True


def test_server_port_conflict(conn, lists_dir):
    blocker = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    blocker.bind(("127.0.0.1", 0))
    port = blocker.getsockname()[1]
    try:
        srv = DnsServer(make_cfg(port=port), conn, list_dir=lists_dir)
        assert srv.start() is False and not srv.running and "cannot bind" in (srv.last_error or "")
        assert srv.stats()["running"] is False
        srv.stop()  # must be safe after a failed start
    finally:
        blocker.close()


def test_server_health_drafts(conn, tmp_path, fake_upstream):
    srv = DnsServer(make_cfg(upstreams=[fake_upstream.addr], lists=["oisd_small"]), conn, list_dir=tmp_path)
    srv.ensure_components()
    ids = [d.finding_id for d in srv.health_findings()]
    assert ids == ["NET-DNS-003"]                       # list file missing → stale
    srv._started_at = time.monotonic() - 7200          # pretend 2 h uptime with a listener
    srv._udp = types.SimpleNamespace(server_address=("127.0.0.1", 5353))
    srv.firewall_rule_present = False
    ids = [d.finding_id for d in srv.health_findings()]
    assert "NET-DNS-001" in ids and "NET-DNS-006" not in ids   # bound to 127.* → no firewall finding
    srv.listen = "0.0.0.0"
    assert "NET-DNS-006" in [d.finding_id for d in srv.health_findings()]
    srv._udp = None
    srv._started_at = None


def test_server_reputation_integration(conn, lists_dir, fake_upstream):
    sess = FakeSession()
    sess.urlhaus["example.org"] = {"query_status": "ok", "urls": [{"url_status": "online"}]}  # registrable domain
    cfg = make_cfg(upstreams=[fake_upstream.addr])

    srv = DnsServer(cfg, conn, list_dir=lists_dir)
    srv.ensure_components()
    srv.reputation = ReputationWorker(cfg, conn, on_malicious=srv._on_malicious, session=sess, budget=Budget(conn, 400))
    q = DNSRecord.question("allowed.example.org").pack()
    r = DNSRecord.parse(srv.handle_query(q, "192.168.1.50"))
    assert r.rr and srv.reputation.pending() == 1
    assert srv.reputation.drain() == 1
    assert srv.reputation.malicious_found == 1 and srv.cache.get("allowed.example.org", "A") is None
    r = DNSRecord.parse(srv.handle_query(q, "192.168.1.50"))
    assert [str(rr.rdata) for rr in r.rr] == ["0.0.0.0"]        # now sinkholed via reputation
    assert srv.policy.decide("allowed.example.org", "A", "c").reason == "reputation"
    assert srv.reputation.emitter.drafts_emitted == 1


# ---- querylog -----------------------------------------------------------------------------------
def test_querylog_flush_rollup_purge(conn):
    ql = querylog.QueryLog(conn, flush_interval=0.1, batch_size=3)
    ql.record("10.0.0.1", "a.example", "A", "allow", None, 1.5)
    ql.record("10.0.0.1", "b.example", "A", "block", "list:x", 0.2)
    assert ql.pending() == 2 and querylog.recent(conn, 10) == []
    ql.record("10.0.0.2", "c.example", "AAAA", "cache", None, 0.1)   # hits batch size → wakes thread
    ql.start()
    deadline = time.time() + 3
    while ql.pending() and time.time() < deadline:
        time.sleep(0.05)
    ql.stop()
    rows = querylog.recent(conn, 10)
    assert len(rows) == 3 and rows[0]["qname"] == "c.example" and rows[-1]["ms"] == 1.5
    assert querylog.recent(conn, 10, client="10.0.0.2")[0]["qtype"] == "AAAA"
    assert [r["qname"] for r in querylog.recent(conn, 10, action="block")] == ["b.example"]
    assert ql.qps_1m() > 0
    # old rows for rollup/purge
    old_ts = "2020-01-02T03:04:05Z"
    conn.execute("INSERT INTO dns_queries(ts,client,qname,qtype,action) VALUES (?,?,?,?,?)", (old_ts, "10.0.0.9", "z.example", "A", "block"))
    conn.commit()
    assert querylog.rollup(conn, hours_back=24 * 365 * 10) == 3       # 3 (hour, client) groups
    hourly = {(r["hour"], r["client"]): (r["total"], r["blocked"]) for r in conn.execute("SELECT * FROM dns_hourly")}
    assert hourly[("2020-01-02T03:00", "10.0.0.9")] == (1, 1)
    cur_hour = querylog.hour_key(reputation.utcnow_iso())
    assert hourly[(cur_hour, "10.0.0.1")] == (2, 1)
    assert querylog.purge(conn, 14) == 1
    assert conn.execute("SELECT COUNT(*) FROM dns_queries").fetchone()[0] == 3
    assert conn.execute("SELECT COUNT(*) FROM dns_hourly WHERE hour < '2021'").fetchone()[0] == 0
    assert querylog.maintenance(make_cfg(), conn) == {"rollup_rows": 2, "purged": 0}


def test_querylog_aggregates(conn):
    ts = reputation.utcnow_iso()
    rows = [
        (ts, "10.0.0.1", "ads.example.com", "A", "block", "list:oisd_small", 0.1),
        (ts, "10.0.0.1", "ads.example.com", "AAAA", "block", "list:oisd_small", 0.1),
        (ts, "10.0.0.2", "tracker.net", "A", "block", "list:oisd_small", 0.1),
        (ts, "10.0.0.2", "good.example", "A", "allow", None, 5.0),
        (ts, "10.0.0.3", "good.example", "A", "cache", None, 0.05),
    ]
    conn.executemany("INSERT INTO dns_queries(ts,client,qname,qtype,action,reason,ms) VALUES (?,?,?,?,?,?,?)", rows)
    conn.commit()
    top = querylog.top_blocked(conn, 24)
    assert top[0] == {"domain": "ads.example.com", "count": 2, "reason": "list:oisd_small"} and len(top) == 2
    clients = querylog.top_clients(conn, 24)
    assert clients[0]["client"] in ("10.0.0.1", "10.0.0.2") and clients[0]["total"] == 2
    assert {c["client"]: c["blocked"] for c in clients} == {"10.0.0.1": 2, "10.0.0.2": 1, "10.0.0.3": 0}
    s = querylog.series(conn, 24)
    assert len(s) == 24 and s[-1]["total"] == 5 and s[-1]["blocked"] == 3 and s[0]["total"] == 0
    assert set(s[0]) == {"hour", "total", "blocked"}
    assert querylog.summary(conn, 24) == {"total": 5, "blocked": 3, "clients": 3}
    assert querylog.distinct_clients(conn, 24) == 3
    assert len(querylog.top_blocked(conn, 24, limit=1)) == 1 and querylog.series(conn, 1)[0]["total"] == 5


# ---- reputation ---------------------------------------------------------------------------------
@pytest.mark.parametrize(
    "name,expected",
    [
        ("www.example.com", "example.com"),
        ("a.b.c.example.co.uk", "example.co.uk"),
        ("example.com", "example.com"),
        ("localhost", "localhost"),
        ("10.0.0.1", "10.0.0.1"),
        ("Cdn.Google.COM.", "google.com"),
    ],
)
def test_registrable_domain(name, expected):
    assert registrable_domain(name) == expected


def test_well_known_list():
    assert len(reputation.WELL_KNOWN) >= 200
    assert reputation.is_well_known("safebrowsing.googleapis.com") and not reputation.is_well_known("evil.example")


def test_budget_persists_daily_counter(conn):
    b = Budget(conn, daily_limit=5, per_minute=4)
    t = 1000.0
    assert [b.try_acquire(now=t) for _ in range(5)] == [True, True, True, True, False]   # 4/min bucket
    assert b.used_today() == 4
    assert b.try_acquire(now=t + 15.0) is True                    # one token refilled after 15 s
    assert b.try_acquire(now=t + 120.0) is False                  # daily limit 5 reached
    assert b.remaining_today() == 0
    b2 = Budget(conn, daily_limit=5)                              # persisted in settings vt.budget.<date>
    assert b2.used_today() == 5
    key = Budget.SETTING_PREFIX + b2._date
    assert conn.execute("SELECT value FROM settings WHERE key=?", (key,)).fetchone()[0] == "5"
    assert Budget(None, daily_limit=0).try_acquire() is False
    assert b.status()["limit"] == 5


def test_lookup_domain_sources_and_cache(conn):
    sess = FakeSession()
    sess.vt["bad.example"] = {"malicious": 7, "suspicious": 1, "harmless": 60, "undetected": 5}
    sess.vt["meh.example"] = {"malicious": 1, "suspicious": 0, "harmless": 60, "undetected": 5}
    sess.urlhaus["host.example"] = {"query_status": "ok", "urls": [{"url_status": "offline"}]}
    cfg = make_cfg(virustotal_api_key="k" * 10)
    budget = Budget(conn, 400)
    assert lookup_domain(cfg, conn, "bad.example", session=sess, budget=budget) == "malicious"
    assert lookup_domain(cfg, conn, "meh.example", session=sess, budget=budget) == "suspicious"
    assert lookup_domain(cfg, conn, "clean.example", session=sess, budget=budget) == "clean"     # VT 404 + no URLhaus
    assert lookup_domain(cfg, conn, "host.example", session=sess, budget=budget) == "suspicious"  # offline URLhaus entry
    assert budget.used_today() == 4
    calls_before = len(sess.calls)
    res = lookup_domain_detail(cfg, conn, "bad.example", session=sess, budget=budget)
    assert res.cached and res.verdict == "malicious" and res.malicious == 7 and len(sess.calls) == calls_before
    row = conn.execute("SELECT source, verdict, malicious FROM reputation WHERE domain='bad.example'").fetchone()
    assert tuple(row) == ("virustotal+urlhaus", "malicious", 7)
    assert reputation.list_reputation(conn)[0]["domain"] == "bad.example"
    # keyless: URLhaus only; network failure → unknown and nothing cached as "clean"
    keyless = make_cfg()
    sess.urlhaus["online.example"] = {"query_status": "ok", "urls": [{"url_status": "online"}, {"url_status": "online"}]}
    assert lookup_domain(keyless, conn, "online.example", session=sess) == "malicious"
    sess.fail = True
    assert lookup_domain(keyless, conn, "offline.example", session=sess) == "unknown"
    # budget exhausted → VT skipped, URLhaus still consulted
    sess.fail = False
    exhausted = Budget(None, 0)
    res = lookup_domain_detail(cfg, conn, "nobudget.example", session=sess, budget=exhausted)
    assert res.raw["virustotal"] == {"skipped": "budget"} and res.source == "urlhaus"


def test_worker_filters_and_finding_dedupe(conn):
    sess = FakeSession()
    sess.urlhaus["evil.example"] = {"query_status": "ok", "urls": [{"url_status": "online"}]}
    seen: list[tuple[str, str]] = []
    w = ReputationWorker(make_cfg(), conn, on_malicious=lambda d, c, r: seen.append((d, c)), session=sess,
                         skip=lambda n: n.endswith(".lan"))
    assert not w.enqueue("www.google.com", "c1")                  # well-known
    assert not w.enqueue("printer.lan", "c1")                     # skip callback (never-block)
    assert not w.enqueue("localhost", "c1")                       # single label
    assert not w.enqueue("10.0.0.1", "c1")
    assert w.enqueue("cdn.evil.example", "192.168.1.7")
    assert not w.enqueue("other.evil.example", "192.168.1.8")     # same registrable domain within 24 h
    assert w.pending() == 1 and w.drain() == 1
    assert seen == [("evil.example", "192.168.1.7")] and w.stats()["malicious_found"] == 1
    em = w.emitter
    res = reputation.ReputationResult("evil.example", "malicious", 2, 0, "urlhaus", checked_at="t")
    assert em.emit("192.168.1.7", "x.evil.example", res, now=1000.0) is None      # already emitted in drain()
    d = em.emit("192.168.1.9", "x.evil.example", res, now=1000.0)
    assert d.finding_id == "NET-DNS-004" and d.subject == "dns:192.168.1.9" and d.evidence["key"] == "evil.example"
    assert em.emit("192.168.1.9", "x.evil.example", res, now=1000.0 + 23 * 3600) is None
    assert em.emit("192.168.1.9", "x.evil.example", res, now=1000.0 + 25 * 3600) is not None
    w.start()
    assert w.enqueue("new.example", "c")
    deadline = time.time() + 3
    while w.pending() and time.time() < deadline:
        time.sleep(0.05)
    w.stop()
    assert w.looked_up == 2


# ---- regressions for the nine verified defects ---------------------------------------------------
def test_cache_caps_upstream_ttl():
    """A C2 domain's authoritative server must not be able to pin an answer in the cache for years."""
    c = DnsCache(max_entries=10, min_ttl=30, negative_ttl=60)
    forever = _reply("evil.example", 2**31 - 1)
    assert c.ttl_for(forever) == cache_mod.DEFAULT_MAX_TTL
    assert c.put("evil.example", "A", forever, now=0.0)
    assert c.get("evil.example", "A", now=cache_mod.DEFAULT_MAX_TTL - 1) is not None
    assert c.get("evil.example", "A", now=cache_mod.DEFAULT_MAX_TTL + 1) is None
    assert DnsCache(10, min_ttl=30, max_ttl=10).max_ttl == 30          # the cap never sinks below min_ttl


def test_policy_is_evaluated_before_the_cache(server):
    """A name already in the cache must still be blocked the moment the policy says so."""
    server.cache.put("cached.example.org", "A", _reply("cached.example.org", 300))
    assert server.cache.get("cached.example.org", "A") is not None
    server.policy.mark_malicious("cached.example.org")                 # no cache flush involved
    r = DNSRecord.parse(server.handle_query(DNSRecord.question("cached.example.org").pack(), "10.0.0.5"))
    assert [str(rr.rdata) for rr in r.rr] == ["0.0.0.0"]
    assert server.cache.get("cached.example.org", "A") is not None     # entry survived; it was simply not consulted


def test_blocklist_reload_flushes_the_cache(server, lists_dir):
    q = DNSRecord.question("allowed.example.org").pack()
    assert str(DNSRecord.parse(server.handle_query(q, "10.0.0.5")).rr[0].rdata) == "93.184.216.34"
    assert server.cache.size >= 1
    path = lists_dir / "hagezi_pro.txt"
    path.write_text("||allowed.example.org^\n", encoding="utf-8")
    os.utime(path, (time.time() + 10, time.time() + 10))
    server.housekeeping(now=time.monotonic() + 120)                    # a feed update landed
    assert server.cache.size == 0
    assert [str(rr.rdata) for rr in DNSRecord.parse(server.handle_query(q, "10.0.0.5")).rr] == ["0.0.0.0"]


def test_upstream_fails_over_on_dnserror():
    """dnslib's DNSError is not a ValueError; catching only OSError/ValueError skipped every fallback."""
    assert not issubclass(DNSError, ValueError)
    fu = FakeUpstream()
    try:
        up = Upstream(["127.0.0.1:1", fu.addr], timeout=0.5)
        real = up._query_udp_then_tcp
        seen: list[str] = []

        def flaky(addr, wire, request, strict_case=False):
            seen.append(addr.label)
            if len(seen) == 1:
                raise DNSError("truncated wire data")
            return real(addr, wire, request, strict_case)

        up._query_udp_then_tcp = flaky
        r = up.resolve(DNSRecord.question("allowed.example.org"))
        assert r.rr and up.health.last_upstream == fu.addr and up.ok
    finally:
        fu.close()


def test_upstream_ignores_garbage_and_wrong_question_replies(fake_upstream):
    """Junk (or an answer to another question) with the right id must not be accepted or cached."""
    garbage = RawUdpUpstream(lambda data: data[:2] + b"\xff" * 40)
    wrong = RawUdpUpstream(lambda data: _spoof_other_question(data))
    try:
        up = Upstream([garbage.addr, fake_upstream.addr], timeout=0.5)
        r = up.resolve(DNSRecord.question("allowed.example.org"))
        assert str(r.rr[0].rdata) == "93.184.216.34" and up.health.last_upstream == fake_upstream.addr
        assert garbage.queries == 1
        only_wrong = Upstream([wrong.addr], timeout=0.5)
        with pytest.raises(UpstreamError):
            only_wrong.resolve(DNSRecord.question("allowed.example.org"))
        assert wrong.queries == 1
    finally:
        garbage.close()
        wrong.close()


def _spoof_other_question(data: bytes) -> bytes:
    req = DNSRecord.parse(data)
    other = DNSRecord.question("attacker.example.net")
    other.header.id = req.header.id
    reply = other.reply()
    reply.add_answer(RR("attacker.example.net", QTYPE.A, ttl=86400, rdata=A("6.6.6.6")))
    return reply.pack()


def test_upstream_randomizes_query_case_and_restores_it(fake_upstream):
    up = Upstream([fake_upstream.addr], timeout=1.0)
    fake_upstream.seen_names.clear()
    for _ in range(12):
        r = up.resolve(DNSRecord.question("allowed.example.org"))
        assert str(r.q.qname).rstrip(".") == "allowed.example.org"        # client never sees the scrambling
        assert str(r.rr[0].rname).rstrip(".") == "allowed.example.org"
    assert any(n != "allowed.example.org" for n in fake_upstream.seen_names)
    plain = Upstream([fake_upstream.addr], timeout=1.0, randomize_query_case=False)
    fake_upstream.seen_names.clear()
    assert plain.resolve(DNSRecord.question("allowed.example.org")).rr
    assert fake_upstream.seen_names == ["allowed.example.org"]


def test_upstream_tolerates_case_normalizing_upstream():
    """An upstream that lowercases the question still works; 0x20 is disabled for it after one query."""
    lowering = RawUdpUpstream(_lowercased_answer)
    try:
        up = Upstream([lowering.addr], timeout=2.0)
        t0 = time.perf_counter()
        r = up.resolve(DNSRecord.question("Allowed.Example.Org"))
        first = time.perf_counter() - t0
        assert str(r.rr[0].rdata) == "10.2.2.2"
        assert first < 1.5 and lowering.addr in up._case_normalizing      # grace wait, not the full timeout
        t0 = time.perf_counter()
        assert up.resolve(DNSRecord.question("Allowed.Example.Org")).rr
        assert time.perf_counter() - t0 < upstream_mod.CASE_MATCH_GRACE   # no grace wait any more
    finally:
        lowering.close()


def _lowercased_answer(data: bytes) -> bytes:
    req = DNSRecord.parse(data)
    name = str(req.q.qname).rstrip(".").lower()
    out = DNSRecord.question(name)
    out.header.id = req.header.id
    reply = out.reply()
    reply.add_answer(RR(name, QTYPE.A, ttl=60, rdata=A("10.2.2.2")))
    return reply.pack()


def test_upstream_circuit_breaker_fails_fast():
    up = Upstream(["127.0.0.1:1", "127.0.0.1:2"], timeout=0.4)
    with pytest.raises(UpstreamError):
        up.resolve(DNSRecord.question("x.example"))
    up.mark_all_failed()
    assert up._breaker_allows() is True                    # one probe per BREAKER_PROBE_SECONDS
    t0 = time.perf_counter()
    for _ in range(20):
        with pytest.raises(UpstreamError):
            up.resolve(DNSRecord.question("x.example"))
    assert time.perf_counter() - t0 < 1.0                  # no socket work at all while the circuit is open
    assert up.breaker_rejections >= 20 and up.status()["breaker_rejections"] >= 20
    assert up._breaker_allows(now=time.monotonic() + upstream_mod.BREAKER_PROBE_SECONDS + 1) is True


def test_doh_bootstraps_by_ip_instead_of_the_os_resolver():
    """The host points its own DNS at Home SOC, so the DoH hostname must never go to getaddrinfo."""
    sess = FakeSession(mountable=True)
    sess.doh_answer = _reply("a.example", 60).pack()
    up = Upstream([], "https://cloudflare-dns.com/dns-query", session=sess)
    r = up.resolve(DNSRecord.question("a.example"))
    assert r.rr and sess.calls[-1] == ("POST", "https://1.1.1.1/dns-query")
    assert sess.mounts == ["https://1.1.1.1/"]
    assert sess.headers_seen[-1].get("Host") == "cloudflare-dns.com"   # cert is still checked against the name
    # a session that cannot pin (or a URL that is already an IP) falls back cleanly
    plain = FakeSession()
    plain.doh_answer = sess.doh_answer
    up2 = Upstream([], "https://cloudflare-dns.com/dns-query", session=plain)
    assert up2.resolve(DNSRecord.question("a.example")).rr
    assert plain.calls[-1] == ("POST", "https://cloudflare-dns.com/dns-query")
    assert upstream_mod.DOH_BOOTSTRAP_IPS["dns.quad9.net"][0] == "9.9.9.9"


def test_server_drops_internet_sources_and_clamps_udp_payload(server):
    q = DNSRecord.question("ads.example.com")
    q.add_ar(EDNS0(udp_len=4096))
    before = server.dropped_foreign
    assert server.handle_query(q.pack(), "8.8.4.4") is None            # never answer a routable source
    assert server.handle_query(q.pack(), "2606:4700:4700::1111") is None
    assert server.dropped_foreign == before + 2
    r = DNSRecord.parse(server.handle_query(q.pack(), "192.168.1.10"))
    assert [rr.edns_len for rr in r.ar if rr.rtype == QTYPE.OPT] == [1232]
    assert server_mod.MAX_UDP_SIZE == server_mod.EDNS_UDP_SIZE == 1232
    # the global ceiling is keyed on nothing spoofable, unlike the per-client one
    gl = _RateLimiter(max_qps=2)
    assert [gl.allow(server_mod.GLOBAL_CLIENT_KEY, now=5.0) for _ in range(3)] == [True, True, False]
    assert server.stats()["dropped_foreign"] >= 2


def test_reputation_rejects_hostile_domain_names(conn):
    """DNS labels may contain '/', '?' or '%'; none of that may reach the VirusTotal URL path."""
    sess = FakeSession()
    w = ReputationWorker(make_cfg(), conn, session=sess)
    for bad in ("x?foo=bar.com", "a/b/c.com", "e vil.com", "-bad.com", "..com", "%2e%2e.com", "a.com/../files"):
        assert w.should_lookup(bad) is None, bad
    assert reputation.vt_lookup("x?foo=bar.com", "k" * 10, session=sess) is None
    assert reputation.urlhaus_lookup("a/b/c.com", session=sess) is None
    assert sess.calls == []                                            # nothing left the process
    assert w.should_lookup("cdn.legit-domain.example") == "legit-domain.example"
    assert reputation.VT_URL.format(domain="a.b") == "https://www.virustotal.com/api/v3/domains/a.b"


def test_no_verdict_is_not_cached_for_days(conn):
    cfg = make_cfg(virustotal_api_key="k" * 10)
    sess = FakeSession()
    sess.fail = True                                                   # URLhaus offline
    res = lookup_domain_detail(cfg, conn, "fresh.example", session=sess, budget=Budget(None, 0))
    assert res.verdict == "unknown" and res.source == "none"
    assert reputation.cached_result(conn, "fresh.example", 72) is not None      # inside the 1 h retry window
    two_hours_ago = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(hours=2)).strftime("%Y-%m-%dT%H:%M:%SZ")
    conn.execute("UPDATE reputation SET checked_at = ? WHERE domain = 'fresh.example'", (two_hours_ago,))
    conn.commit()
    assert reputation.cached_result(conn, "fresh.example", 72) is None          # re-checked, not stuck for 72 h
    conn.execute("UPDATE reputation SET source = 'urlhaus', verdict = 'clean' WHERE domain = 'fresh.example'")
    conn.commit()
    assert reputation.cached_result(conn, "fresh.example", 72) is not None      # a real verdict keeps the full TTL
    # the worker's 24 h dedupe is shortened too, so the next query re-enqueues it
    w = ReputationWorker(cfg, conn, session=sess, budget=Budget(None, 0))
    assert w.enqueue("a.nobody.example", "c") and w.drain() == 1
    assert w.should_lookup("b.nobody.example") is None                          # not immediately
    assert w.should_lookup("b.nobody.example", now=time.time() + 3700) == "nobody.example"


def test_list_loading_streams_and_keeps_one_container(tmp_path):
    path = tmp_path / "big.txt"
    path.write_text("".join(f"d{i}.example\n" for i in range(5000)), encoding="utf-8")
    entries = policy_mod.load_list_file(path)
    assert len(entries) == 5000 and "d4999.example" in entries
    with pytest.raises(ValueError):
        policy_mod.load_list_file(path, max_bytes=100)                 # oversize is refused before reading
    p = Policy(list_names=["big"], list_dir=tmp_path)
    p.reload(force=True)
    assert p.list_entries == 5000
    assert not hasattr(p, "_per_list")                                 # only the merged dict survives
    assert p.decide("x.d1.example", "A", "c").reason == "list:big"


def test_import_surface():
    from homesoc import dnsfilter

    assert dnsfilter.DnsServer is DnsServer
    assert callable(cache_mod.DnsCache) and callable(policy_mod.Policy.load) and callable(upstream_mod.Upstream)
    for name in ("top_blocked", "top_clients", "recent", "series", "rollup", "purge", "maintenance"):
        assert callable(getattr(querylog, name))
    for name in ("Budget", "lookup_domain", "shared_budget", "ReputationWorker"):
        assert callable(getattr(reputation, name))
