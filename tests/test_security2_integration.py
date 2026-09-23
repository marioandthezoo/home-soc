"""Round-two security fixes that cross area boundaries (integration pass).

* One shared sanitiser (util.safe_one_line) behind util.device_text, notify.channels._one_line and
  topology.infer.clean_text, so every layer strips the same bidi/invisible set.
* A wall clock on the socket (feeds.netguard.Watch) for the VirusTotal file lookup and the
  notification poster, whose per-recv timeouts a dripping server never trips.
* An elevated process never runs a user-writable winget.

All servers here listen on 127.0.0.1 with an OS-assigned port and are closed by each test.
"""
from __future__ import annotations

import socket
import threading
import time

import pytest

from homesoc import util
from homesoc.notify import channels
from homesoc.scanners import files, updates
from homesoc.topology import infer

SNEAKY = {
    "ALM U+061C": "\u061c",
    "ZWSP": "\u200b",
    "ZWJ": "\u200d",
    "WJ": "\u2060",
    "BOM": "\ufeff",
    "SHY": "\u00ad",
    "Hangul filler": "\u3164",
    "RLO": "\u202e",
    "RLI": "\u2067",
    "LS U+2028": "\u2028",
    "LF": "\n",
    "lone surrogate": "\ud800",
}


@pytest.mark.parametrize("name", sorted(SNEAKY))
def test_every_layer_strips_the_same_characters(name):
    ch = SNEAKY[name]
    text = f"cam{ch}01"
    for fn in (util.device_text, channels._one_line, infer.clean_text, util.safe_one_line):
        assert ch not in fn(text), (name, fn.__qualname__)


def test_nickname_with_rlo_is_flattened_in_graph_labels():
    assert infer.display_name({"nickname": "Front\u202eDoor"}) == "Front Door"
    assert infer.clean_text("a\nb") == "a b"


def test_ordinary_names_are_untouched():
    for name in ("Caf\u00e9 TV", "\u6771\u4eac-cam", "\u0645\u0637\u0628\u062e", "TV \U0001F4FA"):
        assert util.device_text(name) == name
        assert infer.clean_text(name) == name
        assert channels._one_line(name) == name


# ------------------------------------------------------------------ dripping servers


class _DripServer:
    """Accepts one connection, sends ``head`` and then one byte every 0.2 s until closed."""

    def __init__(self, head: bytes) -> None:
        self.head = head
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(4)
        self.port = self.sock.getsockname()[1]
        self.stop = threading.Event()
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()

    def _run(self) -> None:
        self.sock.settimeout(0.2)
        conns = []
        try:
            while not self.stop.is_set():
                try:
                    conn, _ = self.sock.accept()
                except OSError:
                    for c in conns:
                        try:
                            c.sendall(b"a")
                        except OSError:
                            pass
                    continue
                conn.settimeout(1)
                try:
                    conn.recv(65536)
                    conn.sendall(self.head)
                except OSError:
                    pass
                conns.append(conn)
        finally:
            for c in conns:
                c.close()

    def close(self) -> None:
        self.stop.set()
        self.thread.join(5)
        self.sock.close()


@pytest.fixture
def drip_headers():
    srv = _DripServer(b"HTTP/1.1 500 Oops\r\nX-Drip: ")
    yield srv
    srv.close()


@pytest.fixture
def drip_body():
    srv = _DripServer(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 70000\r\n\r\n")
    yield srv
    srv.close()


def test_notification_poster_is_bounded_by_a_wall_clock(monkeypatch, drip_headers):
    pytest.importorskip("requests")
    monkeypatch.setattr(channels, "HTTP_WALL_CLOCK", 1.0)
    start = time.monotonic()
    ok, err = channels._default_poster(f"http://127.0.0.1:{drip_headers.port}/secret-topic", data=b"x")
    elapsed = time.monotonic() - start
    assert ok is False and "secret-topic" not in (err or "")
    assert elapsed < 6.0, elapsed


def test_notification_error_body_is_capped(monkeypatch):
    class Raw:
        def read(self, amt, decode_content=True):
            assert amt == channels.HTTP_MAX_ERROR_BODY
            return b"x" * amt

    class Resp:
        status_code = 500
        encoding = "utf-8"
        raw = Raw()
        closed = False

        def close(self):
            Resp.closed = True

    requests = pytest.importorskip("requests")
    monkeypatch.setattr(requests, "post", lambda url, **kw: Resp())
    ok, err = channels._default_poster("https://ntfy.invalid/topic", data=b"x")
    assert ok is False and err.startswith("HTTP 500") and Resp.closed


def test_virustotal_lookup_is_bounded_by_a_wall_clock(monkeypatch, drip_body):
    pytest.importorskip("requests")
    monkeypatch.setattr(files, "VT_FILE_URL", f"http://127.0.0.1:{drip_body.port}/api/v3/files/{{sha256}}")
    monkeypatch.setattr(files, "VT_WALL_CLOCK_FACTOR", 1)
    start = time.monotonic()
    status, body = files.vt_fetch("SECRET", "0" * 64, timeout=1)
    elapsed = time.monotonic() - start
    assert body is None and status in (0, 200)
    assert elapsed < 6.0, elapsed


# ------------------------------------------------------------------ elevated winget


def test_elevated_process_never_runs_a_user_writable_winget(monkeypatch):
    monkeypatch.setattr(updates, "is_elevated", lambda: True)
    monkeypatch.setattr(updates, "which", lambda name: r"C:\Users\x\AppData\Local\Microsoft\WindowsApps\winget.exe")
    assert updates.winget_exe() is None
    assert updates.winget_upgrades() == ([], "winget not found")


def test_normal_process_still_finds_winget(monkeypatch):
    monkeypatch.setattr(updates, "is_elevated", lambda: False)
    monkeypatch.setattr(updates, "which", lambda name: r"C:\winget.exe")
    assert updates.winget_exe() == r"C:\winget.exe"


def test_is_elevated_never_raises():
    assert util.is_elevated() in (True, False)
