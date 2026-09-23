"""Security regressions for homesoc.feeds and homesoc.vulns (feed supply-chain review, 2026-09-22).

Each test encodes an exploit that worked before the fix and asserts it now fails:

* a gzip'd feed inflating to 8x the download cap and then being parsed whole in memory
  (~25x RAM amplification for JSON), for any feed, gzip-declared or not;
* the feed downloader following redirects to plain http and into loopback / the LAN
  (blind GET SSRF, content downgrade);
* the NVD client reading the whole (gunzipped) body before its size cap, and forwarding
  the custom ``apiKey`` header across a cross-host redirect.

Everything is offline: fake responses, or throwaway HTTP servers on 127.0.0.1.
"""

from __future__ import annotations

import dataclasses
import gzip
import http.server as httpserver
import json
import socket
import threading
import tracemalloc
from pathlib import Path
from types import SimpleNamespace

import pytest
import requests

from homesoc.feeds import parsers, registry, updater
from homesoc.vulns import enrich
from homesoc.vulns.cpe import CPE

FIXTURES = Path(__file__).parent / "fixtures" / "feeds"
MB = 1024 * 1024


# ------------------------------------------------------------------ helpers ---


def make_cfg(max_download_mb: float = 64):
    return SimpleNamespace(feeds=SimpleNamespace(enabled=True, max_download_mb=max_download_mb))


class FakeResponse:
    def __init__(self, status: int, body: bytes = b"", headers: dict | None = None):
        self.status_code = status
        self.headers = dict(headers or {})
        self._body = body
        self.closed = False

    def iter_content(self, chunk_size=65536):
        for i in range(0, len(self._body), chunk_size):
            yield self._body[i : i + chunk_size]

    def close(self):
        self.closed = True

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.closed = True
        return False


@pytest.fixture
def env(conn):
    registry.clear_cache()
    yield SimpleNamespace(conn=conn)
    registry.clear_cache()


@pytest.fixture
def http(monkeypatch):
    """Script updater._http_get; every URL it is asked for is recorded."""
    calls: list[str] = []
    queue: list[FakeResponse] = []

    def fake_get(url, headers, timeout):
        calls.append(url)
        if not queue:
            raise AssertionError(f"unexpected request to {url}")
        return queue.pop(0)

    monkeypatch.setattr(updater, "_http_get", fake_get)
    return SimpleNamespace(calls=calls, queue=queue)


class _Recorder(httpserver.BaseHTTPRequestHandler):
    """Logs every request (path, Host, apiKey, x-apikey) and answers from the server's `route`."""

    def do_GET(self):  # noqa: N802
        srv = self.server
        srv.hits.append((self.path, self.headers.get("Host"), self.headers.get("apiKey"), self.headers.get("x-apikey")))
        status, headers, body = srv.route(self.path)
        self.send_response(status)
        for k, v in headers.items():
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


@pytest.fixture
def servers():
    """Factory for throwaway HTTP servers on 127.0.0.1; all shut down at teardown."""
    started: list[httpserver.ThreadingHTTPServer] = []

    def start(route):
        srv = httpserver.ThreadingHTTPServer(("127.0.0.1", 0), _Recorder)
        srv.hits = []
        srv.route = route
        srv.daemon_threads = True
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        started.append(srv)
        return srv

    try:
        yield start
    finally:
        for srv in started:
            srv.shutdown()
            srv.server_close()


def _hosts_body() -> bytes:
    return b"0.0.0.0 attacker-chosen.example\n0.0.0.0 bank.example\n"


# ------------------------------------------------- gzip / parse amplification ---


def test_gzip_body_is_refused_for_a_feed_not_published_gzipped(env, http):
    """KEV is plain JSON: a gzip'd KEV body (the PoC's 16 MB-of-{} bomb) must not be inflated at all."""
    bomb = b'{"vulnerabilities":[' + b"{}," * 200_000 + b'{"cveID":"CVE-2024-0001"}]}'
    http.queue.append(FakeResponse(200, gzip.compress(bomb)))
    assert updater.update(make_cfg(), env.conn, ["kev"], force=True)["kev"] == "error"
    assert not updater.feed_path("kev").exists()
    assert "gzip" in env.conn.execute("SELECT error FROM feeds WHERE name='kev'").fetchone()[0]


def test_inflated_size_is_capped_at_the_download_cap_not_a_multiple(env, http):
    """EPSS is gzip'd: valid CSV inflating to 2x the cap was accepted under the old 8x rule."""
    header = b"#model_version:v1\ncve,epss,percentile\n"
    rows = b"".join(b"CVE-2020-%07d,0.5,0.5\n" % i for i in range(90_000))  # ~2 MB of valid rows
    body = gzip.compress(header + rows)
    assert len(body) < 1 * MB < len(header + rows)
    http.queue.append(FakeResponse(200, body))
    assert updater.update(make_cfg(max_download_mb=1), env.conn, ["epss"], force=True)["epss"] == "error"
    assert not updater.feed_path("epss").exists()
    assert "inflated size exceeded" in env.conn.execute("SELECT error FROM feeds WHERE name='epss'").fetchone()[0]


def test_legitimate_gzipped_epss_still_updates(env, http):
    raw = (FIXTURES / "epss_sample.csv").read_bytes()
    http.queue.append(FakeResponse(200, gzip.compress(raw)))
    assert updater.update(make_cfg(), env.conn, ["epss"], force=True)["epss"] == "updated"
    assert updater.feed_path("epss").read_bytes() == raw
    assert registry.load_epss()["CVE-2024-6387"] == pytest.approx(0.61834)


def test_whole_document_feeds_have_an_absolute_cap_below_the_configured_one():
    """Raising max_download_mb must not raise what a JSON feed may cost in RAM."""
    assert registry.size_cap(registry.FEEDS["kev"], 64 * MB) <= 16 * MB
    assert registry.size_cap(registry.FEEDS["kev"], 1024 * MB) <= 16 * MB
    assert registry.size_cap(registry.FEEDS["epss"], 1024 * MB) <= 32 * MB
    assert registry.size_cap(registry.FEEDS["feodo_ips"], 1024 * MB) <= 8 * MB
    # the configured cap still wins when it is tighter
    assert registry.size_cap(registry.FEEDS["kev"], 1 * MB) == 1 * MB
    assert registry.FEEDS["epss"].gzip and not any(s.gzip for s in registry.FEEDS.values() if s.name != "epss")


def test_kev_over_its_own_cap_is_refused_before_the_body_is_read(env, http):
    small = (FIXTURES / "kev_sample.json").read_bytes()
    http.queue.append(FakeResponse(200, small, {"Content-Length": str(17 * MB)}))
    assert updater.update(make_cfg(max_download_mb=64), env.conn, ["kev"], force=True)["kev"] == "error"
    assert "exceeds cap" in env.conn.execute("SELECT error FROM feeds WHERE name='kev'").fetchone()[0]


def test_count_entries_refuses_an_oversized_file_without_reading_it(tmp_path, monkeypatch):
    path = tmp_path / "kev.json"
    path.write_bytes(b" " * 2048)
    spec = dataclasses.replace(registry.FEEDS["kev"], max_bytes=1024)

    def no_read(*a, **k):
        raise AssertionError("oversized file was read")

    monkeypatch.setattr(Path, "read_text", no_read)
    with pytest.raises(updater.FeedError, match="exceeds cap"):
        updater._count_entries(spec, path, 64 * MB)


def test_registry_loader_ignores_a_feed_file_over_its_cap(env, monkeypatch):
    """A bomb that is already on disk (written by an older version) is not parsed in every new process."""
    monkeypatch.setitem(registry.FEEDS, "kev", dataclasses.replace(registry.FEEDS["kev"], max_bytes=1024))
    path = updater.feed_path("kev")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes((FIXTURES / "kev_sample.json").read_bytes() + b" " * 2048)
    assert path.stat().st_size > 1024
    registry.clear_cache()
    assert registry.load_kev().count == 0
    # within the cap it loads normally
    monkeypatch.setitem(registry.FEEDS, "kev", dataclasses.replace(registry.FEEDS["kev"], max_bytes=16 * MB))
    registry.clear_cache()
    assert registry.load_kev().count > 0


def test_epss_is_parsed_from_the_file_row_by_row(env):
    text = (FIXTURES / "epss_sample.csv").read_text(encoding="utf-8")
    assert parsers.parse_epss_lines(iter(text.splitlines(keepends=True))) == parsers.parse_epss(text)
    # a malformed/oversized row is dropped, not fatal to the rest of the list
    junk = 'CVE-2020-0001,"' + "x" * 200_000 + '"\nCVE-2020-0002,0.25,0.5\n'
    assert parsers.parse_epss_lines(iter(junk.splitlines(keepends=True))) == {"CVE-2020-0002": 0.25}
    path = updater.feed_path("epss")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    assert registry.load_epss() == parsers.parse_epss(text)


def test_parse_step_is_covered_by_the_feed_deadline(tmp_path):
    expired = updater._Deadline(0)
    expired.started -= 1
    lines = "".join(f"0.0.0.0 host{i}.example.com\n" for i in range(updater.PARSE_DEADLINE_EVERY_LINES + 5))
    hosts = tmp_path / "urlhaus.txt"
    hosts.write_text(lines, encoding="utf-8")
    with pytest.raises(updater.FeedError, match="parse exceeded"):
        updater._count_entries(registry.FEEDS["urlhaus"], hosts, 64 * MB, expired)
    csv_text = "".join(f"CVE-2020-{i:07d},0.5,0.5\n" for i in range(updater.PARSE_DEADLINE_EVERY_LINES + 5))
    epss = tmp_path / "epss.csv"
    epss.write_text(csv_text, encoding="utf-8")
    with pytest.raises(updater.FeedError, match="parse exceeded"):
        updater._count_entries(registry.FEEDS["epss"], epss, 64 * MB, expired)


# -------------------------------------------------------- redirects / SSRF ---


def test_redirect_to_plain_http_localhost_is_not_followed(env, http, servers):
    """The PoC: 302 to http://127.0.0.1:<port>/cgi-bin/reboot.cgi must not reach the internal service."""
    internal = servers(lambda path: (200, {}, _hosts_body()))
    target = f"http://127.0.0.1:{internal.server_port}/cgi-bin/reboot.cgi?confirm=1"
    http.queue.append(FakeResponse(302, headers={"Location": target}))
    assert updater.update(make_cfg(), env.conn, ["urlhaus"], force=True)["urlhaus"] == "error"
    assert internal.hits == []
    assert http.calls == [registry.FEEDS["urlhaus"].url]
    assert not updater.feed_path("urlhaus").exists()
    assert "non-https" in env.conn.execute("SELECT error FROM feeds WHERE name='urlhaus'").fetchone()[0]


@pytest.mark.parametrize(
    "location",
    [
        "http://mirror.example.net/hosts.txt",  # downgrade to plain http
        "https://127.0.0.1/cgi-bin/reboot.cgi?confirm=1",
        "https://192.168.1.1/cgi-bin/reboot.cgi",
        "https://10.0.0.1/",
        "https://169.254.169.254/latest/meta-data/",
        "https://100.64.0.1/",  # CGNAT
        "https://[::1]/",
        "https://[fe80::1]/",
        "https://[::ffff:192.168.1.1]/",
        "https://224.0.0.251/",
        "https://0.0.0.0/",
        "ftp://mirror.example.net/hosts.txt",
        "file:///C:/Windows/win.ini",
    ],
)
def test_redirect_hops_must_be_https_to_public_addresses(env, http, location):
    http.queue.append(FakeResponse(302, headers={"Location": location}))
    assert updater.update(make_cfg(), env.conn, ["urlhaus"], force=True)["urlhaus"] == "error"
    assert len(http.calls) == 1, "the refused hop must never be requested"


def test_redirect_chain_is_bounded(env, http):
    for i in range(updater.MAX_REDIRECTS + 1):
        http.queue.append(FakeResponse(302, headers={"Location": f"https://mirror.example.net/{i}"}))
    assert updater.update(make_cfg(), env.conn, ["urlhaus"], force=True)["urlhaus"] == "error"
    assert len(http.calls) == updater.MAX_REDIRECTS + 1
    assert "redirects" in env.conn.execute("SELECT error FROM feeds WHERE name='urlhaus'").fetchone()[0]


def test_legitimate_https_redirect_is_still_followed(env, http):
    http.queue.append(FakeResponse(301, headers={"Location": "/downloads/hostfile/v2"}))
    http.queue.append(FakeResponse(200, b"0.0.0.0 malware.example.com\n"))
    assert updater.update(make_cfg(), env.conn, ["urlhaus"], force=True)["urlhaus"] == "updated"
    assert http.calls == [registry.FEEDS["urlhaus"].url, "https://urlhaus.abuse.ch/downloads/hostfile/v2"]


def test_real_http_get_refuses_names_resolving_to_private_addresses(monkeypatch):
    """DNS is checked too: https://router.evil.example/ resolving to the LAN is never requested."""
    sent: list[str] = []
    monkeypatch.setattr(updater.requests, "get", lambda url, **kw: sent.append(url))

    def fake_resolve(ip):
        return lambda host, port, *a, **k: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, port))]

    monkeypatch.setattr(updater.socket, "getaddrinfo", fake_resolve("192.168.1.1"))
    with pytest.raises(updater.FeedError, match="non-public"):
        updater._http_get("https://router.evil.example/cgi-bin/reboot.cgi", {}, (1, 1))
    assert sent == []

    # a public name goes through, and requests is told not to follow redirects on its own
    kwargs_seen: list[dict] = []
    monkeypatch.setattr(updater.requests, "get", lambda url, **kw: kwargs_seen.append(kw) or FakeResponse(200, b"x"))
    monkeypatch.setattr(updater.socket, "getaddrinfo", fake_resolve("93.184.215.14"))
    updater._http_get("https://feeds.example.org/list.txt", {}, (1, 1))
    assert kwargs_seen and kwargs_seen[0]["allow_redirects"] is False and kwargs_seen[0]["stream"] is True


def test_real_http_get_never_connects_to_localhost(servers):
    internal = servers(lambda path: (200, {}, _hosts_body()))
    for url in (f"http://127.0.0.1:{internal.server_port}/", f"https://127.0.0.1:{internal.server_port}/",
                f"https://localhost:{internal.server_port}/"):
        with pytest.raises(updater.FeedError):
            updater._http_get(url, {}, (1, 1))
    assert internal.hits == []


# ----------------------------------------------------------------- NVD API ---


class _RecordingSession:
    def __init__(self, response):
        self.response = response
        self.kwargs: list[dict] = []

    def get(self, url, **kwargs):
        self.kwargs.append(kwargs)
        return self.response


def _nvd_ok() -> bytes:
    return json.dumps({"totalResults": 0, "vulnerabilities": []}).encode()


def test_nvd_request_is_streamed_and_does_not_follow_redirects(conn):
    resp = FakeResponse(200, _nvd_ok())
    session = _RecordingSession(resp)
    out = enrich.nvd_for_cpe(CPE("a", "f5", "nginx", "1.0"), "1.0", "k", conn=conn, session=session)
    assert out is not None and out["count"] == 0
    assert session.kwargs[0]["stream"] is True and session.kwargs[0]["allow_redirects"] is False
    assert resp.closed


def test_nvd_api_key_is_not_forwarded_across_a_redirect(monkeypatch, servers):
    """The PoC: NVD 302 -> another host; the sink must never see the apiKey (or anything)."""
    sink = servers(lambda path: (200, {"Content-Type": "application/json"}, _nvd_ok()))
    stolen = f"http://localhost:{sink.server_port}/steal"
    redirector = servers(lambda path: (302, {"Location": stolen}, b""))
    monkeypatch.setattr(enrich, "NVD_URL", f"http://127.0.0.1:{redirector.server_port}/rest/json/cves/2.0")
    monkeypatch.setattr(enrich, "_sleep", lambda s: None)
    body = enrich._fetch({"cpeName": "cpe:2.3:a:f5:nginx:1.0:*:*:*:*:*:*:*"}, "NVD-SECRET-KEY",
                         enrich.Budget(), enrich.RateLimiter(max_requests=50), None)
    assert body is None
    assert len(redirector.hits) == 1 and redirector.hits[0][2] == "NVD-SECRET-KEY"
    assert sink.hits == []


def test_nvd_size_cap_bounds_memory_for_a_compressed_body(monkeypatch, servers):
    """A ~60 KB gzip body inflating to ~60 MB used to be fully decompressed before the 8 MB check."""
    inflated = b'{"vulnerabilities":[' + b" " * (60 * MB) + b"]}"
    body = gzip.compress(inflated, compresslevel=9)
    assert len(body) < 1 * MB
    srv = servers(lambda path: (200, {"Content-Type": "application/json", "Content-Encoding": "gzip"}, body))
    monkeypatch.setattr(enrich, "NVD_URL", f"http://127.0.0.1:{srv.server_port}/rest/json/cves/2.0")
    tracemalloc.start()
    try:
        out = enrich._fetch({"cpeName": "x"}, "", enrich.Budget(), enrich.RateLimiter(max_requests=50),
                            requests.Session())
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert out is None
    assert peak < 3 * enrich.MAX_RESPONSE_BYTES, f"peak {peak / MB:.1f} MB: body was buffered before the cap"
