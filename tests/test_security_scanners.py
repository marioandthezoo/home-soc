"""Security regressions for the network scanners (exposure / mdns_ssdp / ports / discovery).

Each test encodes an exploit a malicious LAN device could run against Home SOC and asserts it now
fails.  Everything runs on loopback sockets or unit-level stubs: nothing is sent to a real device.
"""

from __future__ import annotations

import logging
import socket
import socketserver
import threading
import time
from types import SimpleNamespace

import pytest

from homesoc.scanners import discovery, exposure, mdns_ssdp, ports

try:
    from dnslib import QTYPE, RR, A, DNSHeader, DNSLabel, DNSRecord
except Exception:  # pragma: no cover - dnslib is a declared dependency
    DNSRecord = None  # type: ignore[assignment]


# --------------------------------------------------------------------------- helpers

def make_cfg(cidr: str = "192.168.1.0/24") -> SimpleNamespace:
    return SimpleNamespace(network=SimpleNamespace(cidr=cidr, gateway="192.168.1.254", exclude=[]))


class _Recorder(socketserver.ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = True


def _serve(handle):
    """A loopback TCP server; ``handle(sock, server)`` runs per connection. Yields (port, hits)."""

    class Handler(socketserver.BaseRequestHandler):
        def handle(self):
            try:
                handle(self.request, self.server)
            except OSError:
                pass

    srv = _Recorder(("127.0.0.1", 0), Handler)
    srv.hits = []
    srv.stop = threading.Event()
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    return srv


def _stop(srv) -> None:
    srv.stop.set()
    srv.shutdown()
    srv.server_close()


def _read_request(sock: socket.socket) -> bytes:
    sock.settimeout(2.0)
    data = b""
    while b"\r\n\r\n" not in data:
        chunk = sock.recv(4096)
        if not chunk:
            break
        data += chunk
    return data


def _drip_body(sock, srv):
    """200 headers promising a big body, then one byte every 0.3 s: never trips a per-recv timeout."""
    srv.hits.append(_read_request(sock).split(b"\r\n", 1)[0])
    sock.sendall(b"HTTP/1.0 200 OK\r\nContent-Type: text/xml\r\nContent-Length: 600000\r\n\r\n<root>")
    while not srv.stop.is_set():
        sock.sendall(b" ")
        time.sleep(0.3)


def _drip_headers(sock, srv):
    """The status line itself arrives one byte at a time (urllib's open() never returns)."""
    srv.hits.append(_read_request(sock).split(b"\r\n", 1)[0])
    for b in b"HTTP/1.0 200 OK\r\nX-Slow: " + b"a" * 10_000:
        if srv.stop.is_set():
            return
        sock.sendall(bytes([b]))
        time.sleep(0.3)


def _record_only(sock, srv):
    srv.hits.append(_read_request(sock).split(b"\r\n", 1)[0])
    sock.sendall(b"HTTP/1.0 404 Not Found\r\nContent-Length: 0\r\n\r\n")


@pytest.fixture
def allow_loopback_lan(monkeypatch):
    """Treat 127.0.0.1 as a LAN host so a loopback server can stand in for a rogue device."""
    real = exposure._is_lan_address
    monkeypatch.setattr(exposure, "_is_lan_address", lambda host: host == "127.0.0.1" or real(host))


# =========================================================================== log forging (SSDP)

FORGED = "\r2026-09-22 03:14:07 INFO    homesoc.scanners.defender: Defender full scan finished: no threats found\x1b[2K"


class TestSsdpLogForging:
    def test_exposure_parser_drops_values_with_control_chars(self):
        reply = ("HTTP/1.1 200 OK\r\nST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n"
                 "USN: uuid:x::urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n"
                 f"LOCATION: http://8.8.8.8/{FORGED}\r\nSERVER: a\x1b]0;pwn\x07b\r\n\r\n")
        got = exposure.parse_ssdp_response(reply)
        assert got["location"] == "" and got["server"] == ""
        assert got["st"] == exposure.IGD_ST  # clean headers survive

    @pytest.mark.parametrize("bad", ["\x1b[2K", "\x00", "\x7f", "\x9b31m", " ", " ", "\x85"])
    def test_every_control_class_is_rejected(self, bad):
        got = exposure.parse_ssdp_response(f"HTTP/1.1 200 OK\r\nLOCATION: http://192.168.1.1/{bad}x\r\n\r\n")
        assert got["location"] == ""
        got2 = mdns_ssdp.parse_ssdp_response(f"HTTP/1.1 200 OK\r\nLOCATION: http://192.168.1.1/{bad}x\r\n\r\n")
        assert got2["location"] == ""

    def test_overlong_location_is_dropped(self):
        got = exposure.parse_ssdp_response("HTTP/1.1 200 OK\r\nLOCATION: http://192.168.1.1/" + "a" * 5000 + "\r\n\r\n")
        assert got["location"] == ""

    def test_igd_warning_escapes_device_supplied_url(self, caplog):
        with caplog.at_level(logging.WARNING, logger="homesoc.scanners.exposure"):
            assert exposure.igd_services("http://8.8.8.8/" + FORGED) == []
        msgs = [r.getMessage() for r in caplog.records if r.name == "homesoc.scanners.exposure"]
        assert msgs, "the refusal is still logged"
        assert all("\r" not in m and "\n" not in m and "\x1b" not in m for m in msgs)

    def test_mdns_ssdp_parser_drops_control_chars(self):
        got = mdns_ssdp.parse_ssdp_response(f"HTTP/1.1 200 OK\r\nSERVER: cam{FORGED}\r\nST: upnp:rootdevice\r\n\r\n")
        assert got["server"] == "" and got["st"] == "upnp:rootdevice"


# =========================================================================== UPnP/IGD SSRF

class TestIgdSsrf:
    @pytest.mark.parametrize("url", [
        "http://127.0.0.1:8787/api/scan", "http://127.9.9.9/", "http://[::1]/", "http://0.0.0.0/",
        "http://0.0.0.1/", "http://169.254.169.254/latest/meta-data/", "http://[::ffff:127.0.0.1]/",
        "http://[fe80::1]/", "http://224.0.0.1/", "http://255.255.255.255/", "http://localhost/",
        "http://2130706433/", "http://8.8.8.8/",
    ])
    def test_non_lan_hosts_are_refused(self, url):
        assert exposure._is_private_url(url) is False

    @pytest.mark.parametrize("url", ["http://192.168.1.254:1900/igd.xml", "http://10.0.0.1/", "http://172.16.5.5:5000/"])
    def test_lan_hosts_still_accepted(self, url):
        assert exposure._is_private_url(url) is True

    def test_loopback_description_is_never_fetched(self):
        srv = _serve(_record_only)
        try:
            port = srv.server_address[1]
            assert exposure.igd_services(f"http://127.0.0.1:{port}/api/v1/shutdown?confirm=yes") == []
            assert exposure.enumerate_mappings(f"http://127.0.0.1:{port}/admin/prune?force=1",
                                               "urn:schemas-upnp-org:service:WANIPConnection:1") == []
            time.sleep(0.2)
            assert srv.hits == []
        finally:
            _stop(srv)

    def test_run_ignores_location_not_on_the_responder(self, conn, monkeypatch):
        """The PoC: a rogue device at .66 answers M-SEARCH with LOCATION on 127.0.0.1."""
        srv = _serve(_record_only)
        try:
            port = srv.server_address[1]
            rogue = {"location": f"http://127.0.0.1:{port}/desc.xml", "server": "x", "st": exposure.IGD_ST,
                     "usn": "", "from": "192.168.1.66"}
            other = {"location": "http://192.168.1.77/desc.xml", "server": "x", "st": exposure.IGD_ST,
                     "usn": "", "from": "192.168.1.66"}
            monkeypatch.setattr(exposure, "public_ip", lambda timeout=5.0: None)
            monkeypatch.setattr(discovery, "local_ip", lambda: "192.168.1.105")
            monkeypatch.setattr(exposure, "discover_igd", lambda iface, seconds=3.0: [rogue, other])
            fetched = []
            real = exposure.igd_services
            monkeypatch.setattr(exposure, "igd_services", lambda loc, timeout=5.0: fetched.append(loc) or real(loc, timeout))
            res = exposure.run(make_cfg(), conn)
            time.sleep(0.2)
            assert srv.hits == [] and fetched == []
            assert res.summary["igds"] == [] and not [f for f in res.findings if f.finding_id.startswith("NET-")]
        finally:
            _stop(srv)

    def test_run_ignores_gateways_outside_the_scan_cidr(self, conn, monkeypatch):
        igd = {"location": "http://10.9.9.9/desc.xml", "server": "x", "st": exposure.IGD_ST, "usn": "", "from": "10.9.9.9"}
        monkeypatch.setattr(exposure, "public_ip", lambda timeout=5.0: None)
        monkeypatch.setattr(discovery, "local_ip", lambda: "192.168.1.105")
        monkeypatch.setattr(exposure, "discover_igd", lambda iface, seconds=3.0: [igd])
        monkeypatch.setattr(exposure, "igd_services", lambda loc, timeout=5.0: pytest.fail("outside the CIDR"))
        res = exposure.run(make_cfg(), conn)
        assert res.summary["igd_found"] == 0

    def test_discover_igd_requires_location_on_the_responder_and_caps_the_list(self, monkeypatch, allow_loopback_lan):
        """A real M-SEARCH over loopback: the 'rogue' socket answers with 30 LOCATIONs."""
        rogue = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        rogue.bind(("127.0.0.1", 0))
        rogue.settimeout(3.0)
        monkeypatch.setattr(exposure, "SSDP_GROUP", rogue.getsockname())
        got: list = []
        t = threading.Thread(target=lambda: got.extend(exposure.discover_igd("127.0.0.1", seconds=1.0)))
        t.start()
        try:
            _msg, addr = rogue.recvfrom(4096)
            head = "HTTP/1.1 200 OK\r\nST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n"
            rogue.sendto((head + "LOCATION: http://127.0.0.2:5000/desc.xml\r\n\r\n").encode(), addr)
            rogue.sendto((head + "LOCATION: http://169.254.169.254/latest\r\n\r\n").encode(), addr)
            for i in range(30):
                rogue.sendto((head + f"LOCATION: http://127.0.0.1:{5000 + i}/d.xml\r\n\r\n").encode(), addr)
        finally:
            t.join(5)
            rogue.close()
        locations = [g["location"] for g in got]
        assert all(loc.startswith("http://127.0.0.1:") for loc in locations)  # other hosts dropped
        assert 1 <= len(locations) <= exposure.MAX_IGDS
        assert all(g["from"] == "127.0.0.1" for g in got)

    def test_service_type_injection_is_refused(self, monkeypatch):
        desc = b"""<root><URLBase>http://192.168.1.254:1900/</URLBase><device><serviceList>
          <service><serviceType>urn:schemas-upnp-org:service:WANIPConnection:1"&gt;&lt;inj&gt;x&lt;/inj&gt;</serviceType>
           <controlURL>/admin/prune?force=1</controlURL></service>
          <service><serviceType>evil-WANPPPConnection-ish</serviceType><controlURL>/a</controlURL></service>
          <service><serviceType>urn:schemas-upnp-org:service:WANIPConnection:1</serviceType>
           <controlURL>/ctl/IP&#13;&#10;X-Injected: 1</controlURL></service>
          <service><serviceType>urn:schemas-upnp-org:service:WANPPPConnection:1</serviceType>
           <controlURL>/ctl/PPP</controlURL></service>
        </serviceList></device></root>"""
        monkeypatch.setattr(exposure, "_http", lambda url, **k: (200, desc))
        svcs = exposure.igd_services("http://192.168.1.254:1900/desc.xml")
        assert svcs == [{"service_type": "urn:schemas-upnp-org:service:WANPPPConnection:1",
                         "control_url": "http://192.168.1.254:1900/ctl/PPP"}]

    def test_enumerate_mappings_refuses_markup_in_service_type(self, monkeypatch):
        monkeypatch.setattr(exposure, "_http", lambda *a, **k: pytest.fail("must not POST"))
        bad = 'urn:x:WANIPConnection:1"><inj>attacker-controlled-body</inj><x a="'
        assert exposure.enumerate_mappings("http://192.168.1.254/ctl", bad) == []


# =========================================================================== slow-drip DoS

class TestWallClockDeadlines:
    @pytest.mark.parametrize("handler", [_drip_body, _drip_headers], ids=["body", "headers"])
    def test_http_has_a_wall_clock_limit(self, handler):
        srv = _serve(handler)
        try:
            t0 = time.monotonic()
            with pytest.raises(OSError):
                exposure._http(f"http://127.0.0.1:{srv.server_address[1]}/desc.xml", timeout=1.5)
            assert time.monotonic() - t0 < 4.0
        finally:
            _stop(srv)

    def test_http_honours_an_earlier_deadline(self):
        srv = _serve(_drip_body)
        try:
            t0 = time.monotonic()
            with pytest.raises(OSError):
                exposure._http(f"http://127.0.0.1:{srv.server_address[1]}/", timeout=30.0, deadline=t0 + 1.0)
            assert time.monotonic() - t0 < 3.5
            with pytest.raises(OSError):  # an exhausted budget sends nothing at all
                exposure._http(f"http://127.0.0.1:{srv.server_address[1]}/", timeout=30.0, deadline=t0 - 1)
        finally:
            _stop(srv)

    def test_enumerate_mappings_cannot_be_held_by_one_dripped_answer(self, allow_loopback_lan):
        srv = _serve(_drip_body)
        try:
            t0 = time.monotonic()
            got = exposure.enumerate_mappings(f"http://127.0.0.1:{srv.server_address[1]}/ctl",
                                              "urn:schemas-upnp-org:service:WANIPConnection:1",
                                              timeout=30.0, deadline=t0 + 1.0)
            assert got == [] and time.monotonic() - t0 < 3.5
        finally:
            _stop(srv)

    def test_run_budget_holds_against_a_dripping_description(self, conn, monkeypatch, allow_loopback_lan):
        """The PoC end to end: the whole exposure run stays within RUN_BUDGET_SEC (+ slack)."""
        srv = _serve(_drip_body)
        try:
            port = srv.server_address[1]
            igds = [{"location": f"http://127.0.0.1:{port}/d{i}.xml", "server": "x", "st": exposure.IGD_ST,
                     "usn": "", "from": "127.0.0.1"} for i in range(50)]
            monkeypatch.setattr(exposure, "RUN_BUDGET_SEC", 2.0)
            monkeypatch.setattr(exposure, "public_ip", lambda timeout=5.0: None)
            monkeypatch.setattr(discovery, "local_ip", lambda: "192.168.1.105")
            monkeypatch.setattr(exposure, "discover_igd", lambda iface, seconds=3.0: igds)
            done: list = []
            t = threading.Thread(target=lambda: done.append(exposure.run(make_cfg(cidr="127.0.0.0/24"), conn)),
                                 daemon=True)
            t0 = time.monotonic()
            t.start()
            t.join(10)
            assert done, "exposure.run is still stuck on the dripping gateway"
            assert time.monotonic() - t0 < 6.0
            assert done[0].summary["partial"] is True
            assert done[0].summary["igd_found"] <= exposure.MAX_IGDS
        finally:
            _stop(srv)

    def test_run_with_real_lan_gateway_still_enumerates(self, conn, monkeypatch):
        """Legitimate behaviour unchanged: the router at .254 answering for itself is walked."""
        igd = {"location": "http://192.168.1.254:1900/igd.xml", "server": "MiniUPnPd", "st": exposure.IGD_ST,
               "usn": "", "from": "192.168.1.254"}
        monkeypatch.setattr(exposure, "public_ip", lambda timeout=5.0: None)
        monkeypatch.setattr(discovery, "local_ip", lambda: "192.168.1.105")
        monkeypatch.setattr(exposure, "discover_igd", lambda iface, seconds=3.0: [igd])
        monkeypatch.setattr(exposure, "igd_services", lambda loc, timeout=5.0: [
            {"service_type": "urn:schemas-upnp-org:service:WANIPConnection:1", "control_url": "http://192.168.1.254:1900/ctl"}])
        monkeypatch.setattr(exposure, "enumerate_mappings", lambda url, st, **k: [
            {"external_port": 32400, "internal_port": 32400, "protocol": "TCP", "internal_client": "192.168.1.50",
             "enabled": True, "description": "Plex", "remote_host": "", "lease_duration": 0, "index": 0}])
        res = exposure.run(make_cfg(), conn)
        assert res.summary["igd_found"] == 1 and res.summary["mappings_count"] == 1


# =========================================================================== mDNS/SSDP flood

class TestProbeCaps:
    def test_ssdp_fields_are_truncated(self):
        got = mdns_ssdp.parse_ssdp_response("HTTP/1.1 200 OK\r\nSERVER: " + "A" * 8000 + "\r\n\r\n")
        assert len(got["server"]) == mdns_ssdp.MAX_FIELD

    def test_probe_caps_entries_per_responder(self, monkeypatch):
        """Real probe() over loopback: one responder floods 300 distinct SSDP answers."""
        attacker = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        attacker.bind(("127.0.0.1", 0))
        attacker.settimeout(3.0)
        sink = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # swallows the mDNS query
        sink.bind(("127.0.0.1", 0))
        monkeypatch.setattr(mdns_ssdp, "SSDP_GROUP", attacker.getsockname())
        monkeypatch.setattr(mdns_ssdp, "MDNS_GROUP", sink.getsockname())
        monkeypatch.setattr(mdns_ssdp, "_mdns_listener", lambda iface: None)
        out: dict = {}
        t = threading.Thread(target=lambda: out.update(mdns_ssdp.probe("127.0.0.1", seconds=1.5)))
        t.start()
        try:
            _msg, addr = attacker.recvfrom(9000)
            for i in range(300):
                pkt = f"HTTP/1.1 200 OK\r\nST: urn:junk:{i}\r\nSERVER: {'X' * 2000}\r\nLOCATION: http://127.0.0.1/{i}\r\n\r\n"
                attacker.sendto(pkt.encode(), addr)
        finally:
            t.join(5)
            attacker.close()
            sink.close()
        entry = out["127.0.0.1"]
        assert len(entry["ssdp"]) == mdns_ssdp.MAX_SSDP_PER_HOST
        assert all(len(v) <= mdns_ssdp.MAX_FIELD for e in entry["ssdp"] for v in e.values())


# =========================================================================== CRLF via mDNS hostname

CRLF_NAME = [b"cam\r\nX-Injected: 1\r\n\r\nGET /apply", b"cgi?reset=1 HTTP/1", b"0\r\nX: y", b"local"]


@pytest.mark.skipif(DNSRecord is None, reason="dnslib not installed")
def test_mdns_names_with_control_chars_are_dropped():
    rec = DNSRecord(DNSHeader(qr=1, aa=1))
    rec.add_answer(RR(DNSLabel(CRLF_NAME), QTYPE.A, rdata=A("192.168.1.1"), ttl=120))
    rec.add_answer(RR("printer.local", QTYPE.A, rdata=A("192.168.1.1"), ttl=120))
    got = mdns_ssdp.parse_mdns_response(rec.pack())
    assert got["names"] == ["printer"]


class TestBannerHostHeader:
    def _capture(self, monkeypatch, sni):
        srv = socket.socket()
        srv.bind(("127.0.0.1", 0))
        srv.listen(1)
        real = socket.create_connection
        monkeypatch.setattr(ports.socket, "create_connection",
                            lambda addr, timeout=None, *a, **k: real(srv.getsockname(), timeout))
        received: list[bytes] = []

        def accept():
            c, _ = srv.accept()
            with c:
                received.append(_read_request(c))
                c.sendall(b"HTTP/1.0 200 OK\r\nServer: lighttpd/1.4\r\n\r\n")

        t = threading.Thread(target=accept, daemon=True)
        t.start()
        try:
            ports.grab_banner("192.168.1.1", 80, sni=sni)
            t.join(3)
        finally:
            srv.close()
        return received[0]

    def test_crlf_hostname_cannot_inject_headers(self, monkeypatch):
        evil = "cam\r\nX-Injected: 1\r\n\r\nGET /apply.cgi?reset=1 HTTP/1.0\r\nX: y"
        assert self._capture(monkeypatch, evil) == b"GET / HTTP/1.0\r\nHost: 192.168.1.1\r\n\r\n"

    def test_plain_hostname_is_still_sent(self, monkeypatch):
        assert self._capture(monkeypatch, "cam-1.local") == b"GET / HTTP/1.0\r\nHost: cam-1.local\r\n\r\n"

    @pytest.mark.parametrize("name", ["a b", "a\x1b[2K", "x" * 64 + ".lan", "a..b", "café", ""])
    def test_safe_hostname_rejects_non_hostnames(self, name):
        assert ports._safe_hostname(name) is None


def test_reverse_dns_names_with_control_chars_are_dropped(monkeypatch):
    table = {"192.168.1.10": "evil\r\nX-Injected: 1", "192.168.1.11": "nas.lan."}
    monkeypatch.setattr(discovery.socket, "gethostbyaddr", lambda ip: (table[ip], [], [ip]))
    assert discovery.resolve_hostnames(list(table)) == {"192.168.1.11": "nas.lan"}
