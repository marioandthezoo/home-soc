"""Security regressions, round two, for homesoc.feeds and homesoc.vulns (2026-09-22).

Each test encodes an exploit that worked before the fix and asserts it now fails:

* a feed (or NVD) server that drips its TLS handshake, its headers or its body one byte at a time
  held the single scheduler thread far past FEED_MAX_SECONDS, because requests' read timeout is
  per recv and the deadline was only checked between 64 KB chunks;
* a redirect to ``https://127.0.0.1:8443\\@example.com/`` passed the public-address check as
  ``example.com`` (urlsplit) while urllib3 connected to 127.0.0.1, and NAT64 / IPv4-compatible /
  site-local IPv6 forms of private addresses counted as public;
* a list feed served as one enormous line of short tokens cost ~20x its size in RAM when the
  parsers split it (and was installed, for OUI);
* a malformed NVD answer (JSON nested past the stack, wrong field types) raised out of
  nvd_for_cpe and aborted the whole vulns scan.

Everything is offline: fake responses, or throwaway socket servers on 127.0.0.1 that are closed at
teardown. Tests that need loopback stand in for "a public feed host" by relaxing only the URL and
address checks; the deadline and streaming code under test is the real one.
"""

from __future__ import annotations

import dataclasses
import json
import socket
import threading
import time
import tracemalloc
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import urlsplit

import pytest
import requests

from homesoc import db
from homesoc.feeds import netguard, parsers, registry, updater
from homesoc.vulns import enrich, matcher
from homesoc.vulns.cpe import CPE

MB = 1024 * 1024
SLACK = 6.0  # generous upper bound for "stopped at the ~1 s deadline", for slow CI machines


# ------------------------------------------------------------------ helpers ---


class DripServer:
    """A loopback TCP server that answers each connection with `prelude`, then one `drip` per `every` s.

    It never sends more than `max_seconds` of drip, and close() stops it and joins its threads.
    """

    def __init__(self, prelude: bytes, drip: bytes = b"a", every: float = 0.1, max_seconds: float = 20.0):
        self.prelude, self.drip, self.every, self.max_seconds = prelude, drip, every, max_seconds
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(8)
        self.sock.settimeout(0.1)
        self.port = self.sock.getsockname()[1]
        self.stop = threading.Event()
        self.accepted = 0
        self.first_bytes: list[bytes] = []
        self._threads: list[threading.Thread] = []
        self._run_thread = threading.Thread(target=self._run, daemon=True)
        self._run_thread.start()

    def _run(self) -> None:
        while not self.stop.is_set():
            try:
                client, _ = self.sock.accept()
            except (TimeoutError, socket.timeout):
                continue
            except OSError:
                return
            self.accepted += 1
            t = threading.Thread(target=self._handle, args=(client,), daemon=True)
            self._threads.append(t)
            t.start()

    def _handle(self, client: socket.socket) -> None:
        try:
            client.settimeout(1.0)
            try:
                self.first_bytes.append(client.recv(4096))
            except OSError:
                pass
            client.sendall(self.prelude)
            until = time.monotonic() + self.max_seconds
            while not self.stop.is_set() and time.monotonic() < until:
                client.sendall(self.drip)
                self.stop.wait(self.every)
        except OSError:
            pass
        finally:
            client.close()

    def close(self) -> None:
        self.stop.set()
        self.sock.close()
        self._run_thread.join(2)
        for t in self._threads:
            t.join(2)


@pytest.fixture
def drip():
    started: list[DripServer] = []

    def start(prelude: bytes, **kw) -> DripServer:
        srv = DripServer(prelude, **kw)
        started.append(srv)
        return srv

    try:
        yield start
    finally:
        for srv in started:
            srv.close()


@pytest.fixture
def loopback_feed_host(monkeypatch):
    """Let 127.0.0.1 stand in for a public feed host: only the URL/address policy is relaxed."""
    monkeypatch.setenv("NO_PROXY", "127.0.0.1,localhost")
    monkeypatch.setattr(updater, "_check_hop", lambda url: urlsplit(url).hostname)
    monkeypatch.setattr(updater, "_check_resolves_public", lambda host: None)
    monkeypatch.setattr(updater, "_connect_permitted", lambda host: True)


HEADER_DRIP = b"HTTP/1.1 200 OK\r\nX-Drip: "
BODY_DRIP = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 70000\r\n\r\n"
# A body without Content-Length ends at connection close: cut short, it looks complete.
CLOSE_DELIMITED = b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n0.0.0.0 evil.example.com\n"
# A TLS record header announcing a 16 KB handshake message that never finishes arriving.
TLS_HANDSHAKE_DRIP = b"\x16\x03\x03\x40\x00"


# ------------------------------------------------- 1. drip vs. the wall clock ---


def test_header_drip_is_cut_off_at_the_feed_deadline(drip, loopback_feed_host):
    srv = drip(HEADER_DRIP)
    started = time.monotonic()
    with pytest.raises(updater.FeedError, match="exceeded"):
        updater._open(f"http://127.0.0.1:{srv.port}/list.txt", {}, updater._Deadline(1.0))
    assert time.monotonic() - started < SLACK


def test_tls_handshake_drip_is_cut_off_at_the_feed_deadline(drip, loopback_feed_host):
    srv = drip(TLS_HANDSHAKE_DRIP, drip=b"\x00")
    started = time.monotonic()
    with pytest.raises(updater.FeedError, match="exceeded"):
        updater._open(f"https://127.0.0.1:{srv.port}/list.txt", {}, updater._Deadline(1.0))
    assert time.monotonic() - started < SLACK


def test_body_drip_is_cut_off_even_inside_one_64k_chunk(drip, loopback_feed_host, tmp_path):
    """The PoC: the response was opened outside any watch; _stream_to_tmp must still stop it."""
    srv = drip(BODY_DRIP)
    resp = requests.get(f"http://127.0.0.1:{srv.port}/", stream=True, timeout=(5, 60))
    started = time.monotonic()
    with resp, pytest.raises(updater.FeedError, match="exceeded"):
        updater._stream_to_tmp(resp, tmp_path / "x.tmp", 10 * MB, updater._Deadline(1.0))
    assert time.monotonic() - started < SLACK


def test_cut_off_close_delimited_body_is_never_taken_as_complete(drip, loopback_feed_host, tmp_path):
    srv = drip(CLOSE_DELIMITED, drip=b"0")
    deadline = updater._Deadline(1.0)
    started = time.monotonic()
    resp = updater._open(f"http://127.0.0.1:{srv.port}/list.txt", {}, deadline)
    with resp, pytest.raises(updater.FeedError, match="exceeded"):
        updater._stream_to_tmp(resp, tmp_path / "x.tmp", 10 * MB, deadline)
    assert time.monotonic() - started < SLACK


def test_update_with_a_dripping_mirror_fails_fast_and_keeps_the_old_list(conn, drip, loopback_feed_host, monkeypatch):
    registry.clear_cache()
    srv = drip(HEADER_DRIP)
    spec = dataclasses.replace(registry.FEEDS["urlhaus"], url=f"http://127.0.0.1:{srv.port}/hostfile/")
    monkeypatch.setitem(registry.FEEDS, "urlhaus", spec)
    monkeypatch.setattr(updater, "FEED_MAX_SECONDS", 1.0)
    path = updater.feed_path("urlhaus")
    path.write_bytes(b"0.0.0.0 old.example.com\n")
    cfg = SimpleNamespace(feeds=SimpleNamespace(enabled=True, max_download_mb=64))
    started = time.monotonic()
    assert updater.update(cfg, conn, ["urlhaus"], force=True)["urlhaus"] == "error"
    assert time.monotonic() - started < SLACK
    error = conn.execute("SELECT error FROM feeds WHERE name='urlhaus'").fetchone()[0]
    assert "exceeded" in error
    assert path.read_bytes() == b"0.0.0.0 old.example.com\n"
    registry.clear_cache()


def test_nvd_drip_is_cut_off_at_the_request_wall_clock(drip, monkeypatch):
    srv = drip(HEADER_DRIP)
    monkeypatch.setenv("NO_PROXY", "127.0.0.1,localhost")
    monkeypatch.setattr(enrich, "NVD_URL", f"http://127.0.0.1:{srv.port}/rest/json/cves/2.0")
    monkeypatch.setattr(enrich, "REQUEST_TIMEOUT_SEC", 5.0)  # per recv: the drip never trips it
    monkeypatch.setattr(enrich, "REQUEST_MAX_SECONDS", 1.0)
    started = time.monotonic()
    body = enrich._fetch({"cpeName": "cpe:2.3:a:x:y:1:*:*:*:*:*:*:*"}, "", enrich.Budget(seconds=60),
                         enrich.RateLimiter(max_requests=50), None)
    assert body is None
    assert time.monotonic() - started < SLACK


def test_watch_leaves_other_threads_and_unwatched_code_alone(drip):
    srv = drip(b"HTTP/1.1 204 No Content\r\n\r\n", max_seconds=0)
    watch = netguard.Watch(lambda: 30.0, check_address=lambda host: False)
    inside = threading.Event()
    release = threading.Event()

    def hold_watch():
        with watch:
            inside.set()
            release.wait(5)

    holder = threading.Thread(target=hold_watch)
    holder.start()
    try:
        assert inside.wait(5)
        # another thread, no watch: a loopback connect is none of the watch's business
        with socket.create_connection(("127.0.0.1", srv.port), timeout=2):
            pass
    finally:
        release.set()
        holder.join(5)
    assert netguard.current() is None
    with socket.create_connection(("127.0.0.1", srv.port), timeout=2):
        pass


# ------------------------------------------- 2. redirect parser differential ---


@pytest.mark.parametrize("url", [
    "https://127.0.0.1:8443\\@example.com/list.txt",
    "https://10.0.0.1\\@example.com/x",
    "https://192.168.1.1:9100\\@example.com/",
    "https://user@example.com/list.txt",
    "https://example.com@10.0.0.1/list.txt",
    "https://example.com /list.txt",
    "https://example.com/\tlist.txt",
    "https://exa\nmple.com/list.txt",
    "https://exämple.com/list.txt",
])
def test_check_hop_refuses_urls_the_http_client_would_read_differently(url):
    with pytest.raises(updater.FeedError, match="refusing"):
        updater._check_hop(url)


def test_check_hop_host_is_the_host_urllib3_connects_to():
    for url in ("https://urlhaus.abuse.ch/downloads/hostfile/", "https://EXAMPLE.com:8443/a?b=c#d",
                "https://[2606:4700::1111]/x"):
        from urllib3.util import parse_url

        assert updater._check_hop(url) == parse_url(url).host.strip("[]").lower()


@pytest.mark.parametrize("addr", [
    "64:ff9b::a00:1",        # NAT64 of 10.0.0.1
    "64:ff9b::7f00:1",       # NAT64 of 127.0.0.1
    "64:ff9b:1::a00:1",      # local-use NAT64
    "::a00:1",               # IPv4-compatible 10.0.0.1
    "::7f00:1",
    "fec0::1",               # deprecated site-local
    "2002:a00:1::1",         # 6to4 of 10.0.0.1
    "2001::1",               # Teredo
    "::ffff:192.168.1.1",
    "127.0.0.1", "10.1.2.3", "100.64.0.1", "169.254.1.1", "224.0.0.1", "::1", "fe80::1%eth0",
])
def test_non_public_ipv6_forms_are_refused(addr):
    assert not updater._is_public_ip(addr)


@pytest.mark.parametrize("addr", ["93.184.215.14", "2606:4700::1111", "64:ff9b::5db8:d70e"])
def test_public_addresses_still_pass(addr):
    assert updater._is_public_ip(addr)


def test_socket_guard_refuses_a_loopback_connect_whatever_the_url_check_said(drip, monkeypatch):
    """Defence in depth: even a URL check fooled by some future parser trick cannot reach the LAN.

    _check_hop is replaced by the old urlsplit-only view (host 'example.com', a public name), so
    the request proceeds to urllib3, which connects to 127.0.0.1. The socket guard refuses it.
    """
    srv = drip(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok", max_seconds=0)
    monkeypatch.setenv("NO_PROXY", "127.0.0.1,localhost,example.com")
    monkeypatch.setattr(updater, "_check_hop", lambda url: "example.com")
    real_resolve = socket.getaddrinfo

    def fake_resolve(host, port, *a, **k):
        if host == "example.com":
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.215.14", port))]
        return real_resolve(host, port, *a, **k)

    monkeypatch.setattr(updater.socket, "getaddrinfo", fake_resolve)
    with pytest.raises(updater.FeedError, match="non-public"):
        updater._open(f"http://127.0.0.1:{srv.port}/list.txt", {}, updater._Deadline(10.0))
    time.sleep(0.3)
    assert srv.accepted == 0 and srv.first_bytes == []


def test_backslash_redirect_poc_never_reaches_the_listener(drip, monkeypatch):
    """The original PoC end to end: 302 -> https://127.0.0.1:<port>\\@example.com/list.txt."""
    listener = drip(b"", max_seconds=0)
    calls: list[str] = []
    real_http_get = updater._http_get

    class Redirect:
        status_code = 302

        def __init__(self, location):
            self.headers = {"Location": location}

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

    def scripted_get(url, headers, timeout):
        calls.append(url)
        if len(calls) == 1:
            return Redirect(f"https://127.0.0.1:{listener.port}\\@example.com/list.txt")
        return real_http_get(url, headers, timeout)

    monkeypatch.setattr(updater, "_http_get", scripted_get)
    with pytest.raises(updater.FeedError, match="refusing"):
        updater._open("https://feed.example/list.txt", {}, updater._Deadline(10.0))
    time.sleep(0.3)
    assert len(calls) == 1 and listener.accepted == 0


# ------------------------------------------------ 3. one-line feed amplification ---


def _one_line_file(path: Path, prefix: str, sep: str, mb: int = 6) -> Path:
    tokens = (mb * MB) // 3
    path.write_text(prefix + sep.join(["ab"] * tokens) + "\n", encoding="utf-8")
    return path


@pytest.mark.parametrize("feed,prefix,sep,extra", [
    ("hagezi_pro", "0.0.0.0 ", " ", ""),
    ("urlhaus", "0.0.0.0 ", " ", "0.0.0.0 good.example.com\n"),
    ("oui", "", "\t", "00:00:01\tAcme\tAcme Inc\n"),
])
def test_one_huge_line_is_skipped_without_splitting_it(tmp_path, feed, prefix, sep, extra):
    path = tmp_path / f"{feed}.txt"
    size = _one_line_file(path, prefix, sep).stat().st_size
    if extra:
        path.write_text(extra + path.read_text(encoding="utf-8"), encoding="utf-8")
    spec = registry.FEEDS[feed]
    tracemalloc.start()
    try:
        try:
            count = updater._count_entries(spec, path, 64 * MB, updater._Deadline(60))
        except updater.FeedError as exc:
            count = str(exc)
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    # before the fix: ~20x the file size (1.2-1.6 GB for 60 MB); now a few KB per line
    assert peak < size / 2, f"peak {peak / MB:.1f} MB for a {size / MB:.1f} MB one-line file"
    assert count == (1 if extra else "downloaded file contains no entries")


def test_registry_oui_loader_skips_a_huge_line_and_the_oui_feed_has_its_own_cap(conn, tmp_path):
    registry.clear_cache()
    assert registry.size_cap(registry.FEEDS["oui"]) == 16 * MB
    path = updater.feed_path("oui")
    _one_line_file(path, "00:00:01\tAcme\tAcme Inc\n", "\t")
    size = path.stat().st_size
    tracemalloc.start()
    try:
        table = registry.load_oui()
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
        registry.clear_cache()
    assert table == {"00:00:01": "Acme Inc"}
    assert peak < size / 2, f"peak {peak / MB:.1f} MB"


def test_registry_blocklist_loader_skips_a_huge_line(conn):
    registry.clear_cache()
    path = updater.feed_path("urlhaus")
    path.write_text("0.0.0.0 good.example.com\n0.0.0.0 " + " ".join(["a.b"] * 300_000) + "\n", encoding="utf-8")
    try:
        assert registry.load_blocklist("urlhaus") == {"good.example.com"}
    finally:
        registry.clear_cache()


def test_bounded_lines_keeps_normal_lines_and_drains_long_ones(tmp_path):
    path = tmp_path / "x.txt"
    limit = parsers.MAX_LINE_CHARS
    exact = "a" * limit
    path.write_bytes(("one\r\n" + "x" * (limit * 3 + 7) + "\r\ntwo\n" + exact + "\nthree").encode())
    with path.open("r", encoding="utf-8", newline="") as fh:
        got = [line.rstrip("\r\n") for line in parsers.bounded_lines(fh)]
    assert got == ["one", "two", exact, "three"]
    with path.open("r", encoding="utf-8") as fh:
        assert [line.rstrip("\n") for line in parsers.bounded_lines(fh)] == ["one", "two", exact, "three"]


def test_parsers_drop_over_long_lines_from_text_too():
    text = "0.0.0.0 ok.example.com\n0.0.0.0 " + " ".join(f"h{i}.example.com" for i in range(2000)) + "\n"
    assert list(parsers.parse_hosts(text)) == ["ok.example.com"]
    assert list(parsers.parse_wildcard("*.ok.example.com\n" + "x" * 10_000 + "\n")) == ["ok.example.com"]
    assert list(parsers.parse_urls("https://ok.example.com/a\n" + "y" * 10_000 + "\n")) == ["ok.example.com"]


def test_single_line_feodo_json_is_still_counted_as_one_document(tmp_path):
    """Feodo is a JSON document; the line-length bound must not apply to it."""
    items = [{"ip_address": f"198.51.{i // 256}.{i % 256}", "port": 443} for i in range(400)]
    path = tmp_path / "feodo_ips.txt"
    path.write_text(json.dumps(items), encoding="utf-8")  # one line, far past MAX_LINE_CHARS
    assert path.stat().st_size > parsers.MAX_LINE_CHARS
    assert updater._count_entries(registry.FEEDS["feodo_ips"], path, 64 * MB) == 400


# ------------------------------------------------------- 4. malformed NVD JSON ---


class _Resp:
    def __init__(self, body: bytes):
        self.status_code = 200
        self.headers = {"Content-Length": str(len(body))}
        self._body = body

    def iter_content(self, chunk_size=65536):
        for i in range(0, len(self._body), chunk_size):
            yield self._body[i:i + chunk_size]

    def close(self):
        pass


class _Session:
    def __init__(self, body: bytes):
        self.body = body

    def get(self, url, **kw):
        return _Resp(self.body)


def _cve(**fields):
    base = {"id": "CVE-2024-0001", "published": "2024-01-02T00:00:00",
            "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 9.8}}]},
            "descriptions": [{"lang": "en", "value": "bad"}]}
    base.update(fields)
    return json.dumps({"totalResults": 1, "vulnerabilities": [{"cve": base}]}).encode()


LIGHTTPD = "cpe:2.3:a:lighttpd:lighttpd:1.4.0:*:*:*:*:*:*:*"


@pytest.mark.parametrize("body", [
    b"[" * 100_000,
    b'{"vulnerabilities": ' + b"[" * 100_000,
    b'{"vulnerabilities": 5}',
    b'{"vulnerabilities": [{"cve": {"id": 5}}]}',
    _cve(metrics=[1]),
    _cve(descriptions=5),
    _cve(descriptions=[{"lang": "en", "value": ["x"]}]),
    _cve(published=json.loads("[" * 900 + "]" * 900)),
], ids=["deep-array", "deep-vulns", "vulns-number", "id-number", "metrics-list", "descriptions-number",
        "description-value-list", "published-nested"])
def test_malformed_nvd_answers_never_raise(body):
    out = enrich.nvd_for_cpe(LIGHTTPD, None, None, session=_Session(body))
    assert out is None or isinstance(out, dict)


def test_well_formed_nvd_answer_is_still_summarized():
    out = enrich.nvd_for_cpe(LIGHTTPD, None, None, session=_Session(_cve()))
    assert out["count"] == 1 and out["max_cvss"] == 9.8 and out["top"][0]["title"] == "bad"
    assert out["top"][0]["published"] == "2024-01-02"


def test_one_bad_nvd_answer_costs_one_service_not_the_scan(conn, monkeypatch):
    now = "2026-09-22T00:00:00Z"
    dev = db.write(conn, "INSERT INTO devices(mac, ip, hostname, vendor, kind, first_seen, last_seen) "
                         "VALUES(?,?,?,?,?,?,?)", ("00:11:22:00:00:01", "192.168.1.254", "gw", "X", "router", now, now))
    for port in (80, 81):
        db.write(conn, "INSERT INTO services(device_id, port, proto, state, name, product, version, cpe, "
                       "first_seen, last_seen) VALUES(?,?,?,?,?,?,?,?,?,?)",
                 (dev, port, "tcp", "open", "http", "lighttpd", "1.4.0", None, now, now))
    calls: list[int] = []

    def flaky(cpe, version, api_key, **kw):
        calls.append(1)
        if len(calls) == 1:
            raise RecursionError("maximum recursion depth exceeded")
        return {"count": 1, "max_cvss": 9.8, "cached": False, "match": "cpe", "returned": 1,
                "top": [{"cve": "CVE-2024-0001", "cvss": 9.8, "published": "2024-01-02", "title": "bad"}]}

    monkeypatch.setattr(matcher, "_load_kev", lambda: registry.KevCatalog())
    monkeypatch.setattr(matcher, "_load_epss", lambda: {})
    monkeypatch.setattr(matcher.enrich, "nvd_for_cpe", flaky)
    cfg = SimpleNamespace(vulns=SimpleNamespace(kev=True, nvd_enrich=True, nvd_api_key="", epss=True,
                                                min_cvss_report=7.0))
    result = matcher.match_services(cfg, conn)
    assert len(calls) == 2 and result.summary["services_checked"] == 2
    assert result.summary["nvd_skipped"] == 1 and result.summary["nvd_queried"] == 1
    assert any(d.finding_id == "NET-VUL-003" for d in result.findings)
    assert "nvd:" in (result.error or "")


def test_feed_json_loaders_survive_json_nested_past_the_stack(conn):
    deep = "[" * 100_000
    assert list(parsers.parse_feodo(deep)) == []
    assert parsers.kev_document(deep) == ({}, [])
    registry.clear_cache()
    path = updater.feed_path("kev")
    path.write_text('{"vulnerabilities": ' + deep, encoding="utf-8")
    try:
        assert registry.load_kev().count == 0
    finally:
        registry.clear_cache()
