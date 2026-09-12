"""Service scan of known LAN devices: nmap when available, pure Python otherwise (SPEC 6.2).

Why two engines: nmap gives product/version/CPE (which the vulnerability
matcher needs) but on the target laptop it only works in connect() mode and
may be missing entirely on other installs.  The Python scanner is a
deliberately modest connect-and-read-a-banner loop - enough to know that
Telnet or a database is listening, never a substitute for ``-sV``.

Safety: only devices already in the inventory are touched, only inside
``cfg.network.cidr``, never anything in ``network.exclude``; fragile vendors and
printer/camera/IoT-looking devices get the gentle profile (fewer ports, no
version probes) because cheap embedded stacks hang when poked.
"""

from __future__ import annotations

import concurrent.futures as cf
import ipaddress
import logging
import os
import re
import shutil
import socket
import ssl
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Callable, Iterable

from homesoc import db
from homesoc.models import Device, FindingDraft, ScanResult, Service
from homesoc.scanners import IS_WINDOWS, cfg_get, discovery, nmap_xml, run_command, services
from homesoc.util import utcnow_iso

if TYPE_CHECKING:
    import sqlite3

    from homesoc.config import Config

logger = logging.getLogger(__name__)

__all__ = [
    "run", "scan_device", "find_nmap", "build_nmap_command", "python_scan", "grab_banner", "parse_banner",
    "TOP_PORTS", "PORT_NAMES", "select_targets",
]

# nmap's top-100 TCP ports in frequency order (nmap-services), so a prefix of
# this list is "the top N".  A few home-network extras are appended after the
# 100 for the full (non-gentle) fallback profile.
TOP_PORTS: tuple[int, ...] = (
    80, 23, 443, 21, 22, 25, 3389, 110, 445, 139, 143, 53, 135, 3306, 8080, 1723, 111, 995, 993, 5900,
    1025, 587, 8888, 199, 1720, 465, 548, 113, 81, 6001, 10000, 514, 5060, 179, 1026, 2000, 8443, 8000,
    32768, 554, 26, 1433, 49152, 2001, 515, 8008, 49154, 1027, 5666, 646, 5000, 5631, 631, 49153, 8081,
    2049, 88, 79, 5800, 106, 2121, 1110, 49155, 6000, 513, 990, 5357, 427, 49156, 543, 544, 5101, 144, 7,
    389, 8009, 3128, 444, 9999, 5009, 7070, 5190, 3000, 5432, 1900, 3986, 13, 1029, 9, 5051, 6646, 49157,
    1028, 873, 1755, 2717, 4899, 9100, 119, 37,
)
# SPEC-GAP: extras beyond the top-100 that matter on home LANs (iOS sync, AirPlay, Plex, MQTT,
# Home Assistant, Redis, Mongo, camera DVR ports).  Only used by the full Python profile.
EXTRA_HOME_PORTS: tuple[int, ...] = (62078, 7000, 32400, 1883, 8123, 6379, 27017, 8554, 37777, 34567, 9200, 5353)

PORT_NAMES: dict[int, str] = {
    7: "echo", 9: "discard", 13: "daytime", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 37: "time",
    53: "domain", 79: "finger", 80: "http", 81: "http", 88: "kerberos", 110: "pop3", 111: "rpcbind",
    113: "ident", 119: "nntp", 135: "msrpc", 139: "netbios-ssn", 143: "imap", 179: "bgp", 389: "ldap",
    427: "svrloc", 443: "https", 444: "snpp", 445: "microsoft-ds", 465: "smtps", 513: "login", 514: "shell",
    515: "printer", 548: "afp", 554: "rtsp", 587: "submission", 631: "ipp", 873: "rsync", 990: "ftps",
    993: "imaps", 995: "pop3s", 1433: "ms-sql-s", 1521: "oracle", 1723: "pptp", 1883: "mqtt", 1900: "upnp",
    2049: "nfs", 2121: "ftp", 3000: "http", 3128: "http-proxy", 3306: "mysql", 3389: "ms-wbt-server",
    5000: "upnp", 5009: "airport-admin", 5060: "sip", 5353: "mdns", 5357: "wsdapi", 5432: "postgresql",
    5800: "vnc-http", 5900: "vnc", 5901: "vnc", 6000: "x11", 6379: "redis", 7000: "afs3-fileserver",
    7070: "realserver", 8000: "http-alt", 8008: "http", 8009: "ajp13", 8080: "http-proxy", 8081: "http",
    8123: "http", 8443: "https-alt", 8554: "rtsp-alt", 8888: "http", 9100: "jetdirect", 9200: "elasticsearch",
    9999: "abyss", 10000: "snet-sensor-mgmt", 27017: "mongodb", 32400: "plex", 34567: "dvr", 37777: "dahua-dvr",
    49152: "unknown", 62078: "iphone-sync",
}
BANNER_PORTS = frozenset({21, 22, 25, 80, 110, 143, 3306, 6379})
TLS_PORTS = frozenset({443, 8443})
_BANNER_BYTES = 256
_BANNER_TIMEOUT = 1.0
NMAP_TIMEOUT_GRACE = 30.0

_SSH_RE = re.compile(r"SSH-[\d.]+-([A-Za-z][\w.-]*?)[_ ]v?(\d[\w.]*)\s*(.*)")
_SERVER_RE = re.compile(r"^Server:\s*(.+)$", re.IGNORECASE | re.MULTILINE)
_PRODVER_RE = re.compile(r"([A-Za-z][A-Za-z0-9+.-]{1,30}?)[/ _-]v?(\d+(?:\.\d+)+[\w-]*)")


@dataclass
class HostScan:
    device_id: int
    ip: str
    ports: list[dict[str, Any]]
    method: str
    gentle: bool
    partial: bool = False
    error: str | None = None


# --------------------------------------------------------------------------- nmap

def find_nmap() -> str | None:
    """Path to nmap on PATH or in its default Windows install folders."""
    found = shutil.which("nmap")
    if found:
        return found
    if IS_WINDOWS:
        for env in ("ProgramFiles(x86)", "ProgramFiles"):
            base = os.environ.get(env)
            if base:
                cand = os.path.join(base, "Nmap", "nmap.exe")
                if os.path.isfile(cand):
                    return cand
    return None


def _timing(cfg: Any) -> str:
    """Clamp ``scan.nmap_timing`` to T0..T3 - never faster than T3 on a home LAN."""
    raw = str(cfg_get(cfg, "scan.nmap_timing", "T3") or "T3").upper().lstrip("-")
    m = re.fullmatch(r"T([0-5])", raw)
    level = int(m.group(1)) if m else 3
    return f"-T{min(level, 3)}"


def build_nmap_command(nmap_path: str, ip: str, cfg: Any, *, gentle: bool) -> list[str]:
    """Exactly the SPEC 6.2 argv: ``-sT -sV --version-light -T3 --top-ports N -n -Pn --host-timeout Ns -oX -``."""
    ipaddress.ip_address(ip)  # refuse anything that is not a bare IP literal
    top = int(cfg_get(cfg, "scan.gentle_top_ports", 25) if gentle else cfg_get(cfg, "scan.nmap_top_ports", 100))
    host_timeout = int(cfg_get(cfg, "scan.per_host_timeout_sec", 180))
    argv = [nmap_path, "-sT"]
    if not gentle and bool(cfg_get(cfg, "scan.version_detection", True)):
        argv += ["-sV", "--version-light"]
    argv += [_timing(cfg), "--top-ports", str(max(1, top)), "-n", "-Pn",
             "--host-timeout", f"{max(10, host_timeout)}s", "-oX", "-", ip]
    return argv


def _nmap_scan(nmap_path: str, ip: str, cfg: Any, *, gentle: bool) -> tuple[list[dict[str, Any]], bool] | None:
    """Run nmap; None when it failed outright so the caller can fall back."""
    argv = build_nmap_command(nmap_path, ip, cfg, gentle=gentle)
    timeout = int(cfg_get(cfg, "scan.per_host_timeout_sec", 180)) + NMAP_TIMEOUT_GRACE
    res = run_command(argv, timeout=timeout)
    if res.missing:
        return None
    hosts = nmap_xml.parse(res.out)
    if not hosts:
        logger.warning("nmap produced no host for %s (rc=%s timed_out=%s): %s", ip, res.rc, res.timed_out,
                       res.err.strip()[:200])
        return None
    host = next((h for h in hosts if h.get("ip") == ip), hosts[0])
    # "partial" covers a truncated document, nmap's own --host-timeout (timedout="true") and a host
    # without any <ports> section: none of those mean "every port is closed".
    return host["ports"], bool(host.get("partial")) or bool(host.get("timedout")) or res.timed_out


# --------------------------------------------------------------------------- python fallback

def _der_tlv(buf: bytes, pos: int) -> tuple[int, int, int]:
    """Minimal DER reader: (tag, content_start, content_end)."""
    tag = buf[pos]
    ln = buf[pos + 1]
    pos += 2
    if ln & 0x80:
        n = ln & 0x7F
        ln = int.from_bytes(buf[pos:pos + n], "big")
        pos += n
    return tag, pos, pos + ln


def _der_children(buf: bytes, start: int, end: int) -> list[tuple[int, int, int]]:
    out = []
    pos = start
    while pos < end:
        tag, cs, ce = _der_tlv(buf, pos)
        out.append((tag, cs, ce))
        pos = ce
    return out


def _cert_subject(der: bytes) -> dict[str, str]:
    """CN/O/OU from an unverified peer certificate (ssl refuses to decode those for us)."""
    oids = {b"\x55\x04\x03": "CN", b"\x55\x04\x0a": "O", b"\x55\x04\x0b": "OU"}
    try:
        _, c0, c1 = _der_tlv(der, 0)                      # Certificate
        _, t0, t1 = _der_tlv(der, c0)                     # tbsCertificate
        fields = _der_children(der, t0, t1)
        if fields and fields[0][0] == 0xA0:               # explicit version
            fields = fields[1:]
        subject = fields[4]                               # serial, sigalg, issuer, validity, subject
        out: dict[str, str] = {}
        for _set_tag, s0, s1 in _der_children(der, subject[1], subject[2]):
            for _seq_tag, q0, q1 in _der_children(der, s0, s1):
                parts = _der_children(der, q0, q1)
                if len(parts) != 2:
                    continue
                oid = der[parts[0][1]:parts[0][2]]
                vtag, v0, v1 = parts[1]
                raw = der[v0:v1]
                value = raw.decode("utf-16-be", "replace") if vtag == 0x1E else raw.decode("utf-8", "replace")
                if oid in oids:
                    out[oids[oid]] = value
        return out
    except (IndexError, ValueError):
        return {}


def parse_banner(port: int, banner: str) -> dict[str, Any]:
    """Turn a raw banner into name/product/version/extrainfo; unknown text lands in extrainfo."""
    info: dict[str, Any] = {"name": PORT_NAMES.get(port), "product": None, "version": None, "extrainfo": None}
    text = banner.strip()
    if not text:
        return info
    if port == 22 or text.startswith("SSH-"):
        info["name"] = "ssh"
        m = _SSH_RE.search(text)
        if m:
            info.update(product=m.group(1), version=m.group(2), extrainfo=m.group(3).strip() or None)
        else:
            info["extrainfo"] = text[:120]
        return info
    if port in (80, 8080, 8000, 8008, 8081, 8888) or text.startswith("HTTP/"):
        info["name"] = "http"
        m = _SERVER_RE.search(text)
        if m:
            server = m.group(1).strip()
            pv = _PRODVER_RE.search(server)
            if pv:
                info.update(product=pv.group(1), version=pv.group(2),
                            extrainfo=server.replace(pv.group(0), "").strip(" ()") or None)
            else:
                info["product"] = server[:80]
        return info
    pv = _PRODVER_RE.search(text)
    if pv:
        info.update(product=pv.group(1), version=pv.group(2))
    info["extrainfo"] = text.splitlines()[0][:120]
    return info


def _mysql_greeting(data: bytes) -> dict[str, Any]:
    info: dict[str, Any] = {"name": "mysql", "product": "MySQL", "version": None, "extrainfo": None}
    if len(data) > 5 and data[4] == 10:
        ver = data[5:].split(b"\x00", 1)[0].decode("ascii", "replace")
        info["version"] = ver
        if "mariadb" in ver.lower():
            info["product"] = "MariaDB"
    elif len(data) > 4 and data[4] == 0xFF:
        info["extrainfo"] = data[7:].decode("utf-8", "replace").strip()[:120]
    return info


def grab_banner(ip: str, port: int, *, sni: str | None = None, timeout: float = _BANNER_TIMEOUT) -> dict[str, Any]:
    """Read up to 256 bytes from a handful of well-known ports; TLS ports report the cert subject."""
    info: dict[str, Any] = {"name": PORT_NAMES.get(port), "product": None, "version": None,
                            "extrainfo": None, "tunnel": None}
    try:
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            if port in TLS_PORTS:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                with ctx.wrap_socket(sock, server_hostname=sni or None) as tls:
                    der = tls.getpeercert(binary_form=True) or b""
                    subj = _cert_subject(der)
                    info.update(name="https", tunnel="ssl",
                                extrainfo=", ".join(f"{k}={v}" for k, v in subj.items()) or None,
                                product=subj.get("O") or subj.get("CN"))
                return info
            if port in (80, 8080, 8000, 8008, 8081, 8888):
                # GET rather than HEAD: several embedded servers (the target's
                # lighttpd among them) stay silent on HEAD.  256 bytes is
                # enough to see the status line and Server header.
                sock.sendall(f"GET / HTTP/1.0\r\nHost: {sni or ip}\r\n\r\n".encode("ascii", "replace"))
            data = b""
            try:
                data = sock.recv(_BANNER_BYTES)
                # SPEC-GAP: spec says "recv 256 bytes"; HTTP responses often
                # put Set-Cookie before Server, so for HTTP ports keep reading
                # to the end of headers (max 1 KB) inside the same 1 s budget.
                while (port in (80, 8080, 8000, 8008, 8081, 8888) and data and b"\r\n\r\n" not in data
                       and len(data) < 4 * _BANNER_BYTES):
                    chunk = sock.recv(_BANNER_BYTES)
                    if not chunk:
                        break
                    data += chunk
            except (socket.timeout, OSError):
                pass
            if port == 3306 and data:
                info.update(_mysql_greeting(data))
                return info
            info.update(parse_banner(port, data.decode("utf-8", "replace")))
    except (OSError, ssl.SSLError, ValueError):
        pass
    return info


def python_scan(ip: str, ports: Iterable[int], *, timeout: float = 1.0, workers: int = 64,
                banners: bool = True, sni: str | None = None, max_seconds: float = 180.0) -> list[dict[str, Any]]:
    """Connect scan + light banner grab; returns port dicts shaped like ``nmap_xml.parse``."""
    ipaddress.ip_address(ip)
    port_list = list(dict.fromkeys(int(p) for p in ports))
    deadline = time.monotonic() + max_seconds
    open_ports: list[int] = []

    def probe(port: int) -> tuple[int, bool]:
        if time.monotonic() >= deadline:
            return port, False
        return port, discovery._connect(ip, port, timeout) == "open"

    pool = cf.ThreadPoolExecutor(max_workers=max(1, min(workers, 128)))
    try:
        for fut in cf.as_completed([pool.submit(probe, p) for p in port_list], timeout=max_seconds + 5):
            port, is_open = fut.result()
            if is_open:
                open_ports.append(port)
    except cf.TimeoutError:
        logger.warning("python scan of %s hit the %.0fs cap", ip, max_seconds)
    finally:
        pool.shutdown(wait=False, cancel_futures=True)

    results = []
    for port in sorted(open_ports):
        entry: dict[str, Any] = {"port": port, "proto": "tcp", "state": "open", "reason": "syn-ack",
                                 "name": PORT_NAMES.get(port), "product": None, "version": None,
                                 "extrainfo": None, "tunnel": None, "cpe": None, "cpes": [], "method": "python"}
        if banners and (port in BANNER_PORTS or port in TLS_PORTS) and time.monotonic() < deadline:
            entry.update({k: v for k, v in grab_banner(ip, port, sni=sni).items() if v is not None})
        results.append(entry)
    return results


# --------------------------------------------------------------------------- targets

def _row_device(row: Any) -> Device:
    return Device(
        id=int(row["id"]), mac=row["mac"], ip=row["ip"], hostname=row["hostname"], vendor=row["vendor"],
        kind=row["kind"], first_seen=row["first_seen"], last_seen=row["last_seen"], online=bool(row["online"]),
        trusted=bool(row["trusted"]), nickname=row["nickname"],
    )


def select_targets(cfg: Any, conn: "sqlite3.Connection", *, quick: bool,
                   network: ipaddress.IPv4Network, gateway: str | None, me: str | None) -> list[Device]:
    """Online devices inside the CIDR minus excludes/self; quick = gateway + 5 most recent."""
    exclude = {str(x) for x in (cfg_get(cfg, "network.exclude", []) or [])}
    scan_gateway = bool(cfg_get(cfg, "scan.scan_gateway", True))
    rows = db.query(conn, "SELECT * FROM devices WHERE online=1 ORDER BY last_seen DESC, id ASC")
    devices: list[Device] = []
    for row in rows:
        ip = row["ip"]
        try:
            addr = ipaddress.ip_address(ip)
        except (TypeError, ValueError):
            continue
        if addr not in network or ip in exclude:
            continue
        if ip == me:
            continue  # SPEC-GAP: the host's own listeners are covered by WIN-NET-006, not NET-SVC
        if gateway and ip == gateway and not scan_gateway:
            continue
        dev = _row_device(row)
        if gateway and ip == gateway and not dev.kind:
            dev.kind = "router"
        devices.append(dev)
    if not quick:
        return devices
    gw = [d for d in devices if gateway and d.ip == gateway]
    others = [d for d in devices if not (gateway and d.ip == gateway)][:5]
    return gw + others


# --------------------------------------------------------------------------- per-host

def _scan_one(cfg: Any, device: Device, *, nmap_path: str | None, gentle: bool) -> HostScan:
    use_nmap = bool(cfg_get(cfg, "scan.use_nmap", True)) and nmap_path is not None
    per_host = float(cfg_get(cfg, "scan.per_host_timeout_sec", 180))
    if use_nmap:
        try:
            got = _nmap_scan(nmap_path, device.ip, cfg, gentle=gentle)
        except Exception as exc:
            logger.warning("nmap failed for %s: %s", device.ip, exc)
            got = None
        if got is not None:
            ports, partial = got
            return HostScan(device.id or 0, device.ip, ports, "nmap", gentle, partial=partial)
    try:
        count = int(cfg_get(cfg, "scan.gentle_top_ports", 25)) if gentle else int(cfg_get(cfg, "scan.nmap_top_ports", 100))
        port_list = list(TOP_PORTS[:max(1, count)])
        if not gentle:
            port_list += [p for p in EXTRA_HOME_PORTS if p not in port_list]
        ports = python_scan(device.ip, port_list, banners=not gentle, sni=device.hostname, max_seconds=per_host,
                            workers=16 if gentle else 64)
        return HostScan(device.id or 0, device.ip, ports, "python", gentle)
    except Exception as exc:
        logger.warning("python scan failed for %s: %s", device.ip, exc)
        return HostScan(device.id or 0, device.ip, [], "python", gentle, error=f"{type(exc).__name__}: {exc}")


def _upsert_services(conn: "sqlite3.Connection", scan: HostScan, now: str) -> list[Service]:
    """Write open ports for one device, close the rest, and return the current service list."""
    seen_keys: list[tuple[int, str]] = []
    for p in scan.ports:
        if p.get("state") != "open":
            continue
        port, proto = int(p["port"]), p.get("proto") or "tcp"
        seen_keys.append((port, proto))
        # COALESCE keeps a product learned by an earlier -sV scan when a gentle
        # pass (no version probes) reports nothing; fresh data always wins.
        db.write(
            conn,
            "INSERT INTO services(device_id, port, proto, state, name, product, version, extrainfo, cpe, tunnel, "
            "first_seen, last_seen) VALUES (?,?,?,?,?,?,?,?,?,?,?,?) "
            "ON CONFLICT(device_id, port, proto) DO UPDATE SET state='open', "
            "name=COALESCE(excluded.name, services.name), product=COALESCE(excluded.product, services.product), "
            "version=COALESCE(excluded.version, services.version), "
            "extrainfo=COALESCE(excluded.extrainfo, services.extrainfo), cpe=COALESCE(excluded.cpe, services.cpe), "
            "tunnel=COALESCE(excluded.tunnel, services.tunnel), last_seen=excluded.last_seen",
            (scan.device_id, port, proto, "open", p.get("name"), p.get("product"), p.get("version"),
             p.get("extrainfo"), p.get("cpe"), p.get("tunnel"), now, now),
        )
    if not scan.partial and scan.error is None:
        rows = db.query(conn, "SELECT id, port, proto FROM services WHERE device_id=? AND state='open'", (scan.device_id,))
        for row in rows:
            if (int(row["port"]), row["proto"]) not in seen_keys:
                db.write(conn, "UPDATE services SET state='closed' WHERE id=?", (int(row["id"]),))
    db.write(conn, "UPDATE devices SET last_service_scan=? WHERE id=?", (now, scan.device_id))
    out: list[Service] = []
    for row in db.query(conn, "SELECT * FROM services WHERE device_id=? ORDER BY port", (scan.device_id,)):
        out.append(Service(device_id=scan.device_id, port=int(row["port"]), proto=row["proto"], state=row["state"],
                           name=row["name"], product=row["product"], version=row["version"],
                           extrainfo=row["extrainfo"], cpe=row["cpe"], tunnel=row["tunnel"]))
    return out


# --------------------------------------------------------------------------- run

def run(cfg: "Config", conn: "sqlite3.Connection", *, quick: bool = False,
        progress: Callable[[str], None] | None = None) -> ScanResult:
    """Service-scan online devices with ``max_parallel_hosts`` workers and upsert ``services``.

    ``summary["scopes"]`` lists ``device:<mac>`` for every device that was scanned completely, so
    the caller auto-resolves NET-SVC findings only where a fresh, complete answer exists — never
    for a device that was asleep, timed out or simply not selected.
    """
    return _scan_targets(cfg, conn, quick=quick, progress=progress, only_device_id=None)


def scan_device(cfg: "Config", conn: "sqlite3.Connection", device_id: int, *,
                progress: Callable[[str], None] | None = None) -> ScanResult:
    """Service-scan one device by id (the dashboard's "Scan this device now"); same pipeline as run()."""
    return _scan_targets(cfg, conn, quick=False, progress=progress, only_device_id=int(device_id))


def _scan_targets(cfg: "Config", conn: "sqlite3.Connection", *, quick: bool,
                  progress: Callable[[str], None] | None, only_device_id: int | None) -> ScanResult:
    started = time.monotonic()
    say = progress or (lambda _m: None)
    now = utcnow_iso()
    findings: list[FindingDraft] = []
    summary: dict[str, Any] = {"hosts_scanned": 0, "hosts_failed": 0, "services_open": 0, "gentle_hosts": 0,
                               "method": "", "duration_sec": 0.0, "quick": quick, "scopes": [], "targets": []}
    error: str | None = None
    try:
        # SOC-SYS-001 (nmap missing) is emitted by cli.soc_health_drafts only, so one source owns it.
        nmap_path = find_nmap() if bool(cfg_get(cfg, "scan.use_nmap", True)) else None
        me = discovery.local_ip()
        if _is_loopback(me):
            summary["method"] = "none"
            return ScanResult(kind="services", findings=[], summary=summary, error="no LAN interface (offline?)")
        network = discovery.resolve_network(cfg)
        gateway = discovery.default_gateway(cfg, network)
        targets = select_targets(cfg, conn, quick=quick, network=network, gateway=gateway, me=me)
        if only_device_id is not None:
            targets = _single_target(conn, only_device_id, network, cfg)
        fragile = list(cfg_get(cfg, "network.fragile_vendors", []) or [])
        workers = max(1, int(cfg_get(cfg, "scan.max_parallel_hosts", 3)))
        say(f"service scan of {len(targets)} device(s) via {'nmap' if nmap_path else 'python'}")

        plans = [(dev, services.wants_gentle(dev, fragile)) for dev in targets]
        summary["gentle_hosts"] = sum(1 for _, g in plans if g)
        methods: set[str] = set()
        complete: list[str] = []
        with cf.ThreadPoolExecutor(max_workers=workers) as pool:
            futures = {pool.submit(_scan_one, cfg, dev, nmap_path=nmap_path, gentle=g): dev for dev, g in plans}
            for fut in cf.as_completed(futures):
                dev = futures[fut]
                try:
                    scan = fut.result()
                except Exception as exc:  # _scan_one already guards; belt and braces
                    scan = HostScan(dev.id or 0, dev.ip, [], "none", False, error=str(exc))
                say(f"{dev.ip}: {len([p for p in scan.ports if p.get('state') == 'open'])} open ({scan.method})")
                if scan.error:
                    summary["hosts_failed"] += 1
                else:
                    summary["hosts_scanned"] += 1
                    if not scan.partial:
                        complete.append(f"device:{dev.mac}")
                methods.add(scan.method)
                svc_rows = _upsert_services(conn, scan, now)
                open_now = [s for s in svc_rows if s.state == "open"]
                summary["services_open"] += len(open_now)
                findings.extend(services.evaluate(dev, svc_rows))
        summary["method"] = "+".join(sorted(m for m in methods if m != "none")) or ("nmap" if nmap_path else "python")
        summary["targets"] = [d.ip for d in targets]
        summary["scopes"] = sorted(complete)
    except Exception as exc:
        logger.exception("service scan failed")
        error = f"{type(exc).__name__}: {exc}"
    summary["duration_sec"] = round(time.monotonic() - started, 2)
    return ScanResult(kind="services", findings=findings, summary=summary, error=error)


def _is_loopback(ip: str) -> bool:
    """One definition of "no LAN route yet", shared with discovery and exposure."""
    return discovery._is_unusable_ip(ip)


def _single_target(conn: "sqlite3.Connection", device_id: int, network: ipaddress.IPv4Network, cfg: Any) -> list[Device]:
    row = db.one(conn, "SELECT * FROM devices WHERE id=?", (device_id,))
    if row is None:
        raise ValueError(f"no such device id {device_id}")
    exclude = {str(x) for x in (cfg_get(cfg, "network.exclude", []) or [])}
    try:
        addr = ipaddress.ip_address(row["ip"])
    except (TypeError, ValueError):
        raise ValueError(f"device {device_id} has no usable IP") from None
    if addr not in network or row["ip"] in exclude:
        raise ValueError(f"device {device_id} ({row['ip']}) is outside the scan boundary or excluded")
    return [_row_device(row)]
