"""What does the internet see of this home? (SPEC 6.3)

Three cheap, read-only questions, all answered with the standard library:

1. ipify - what is our public IP.
2. Shodan InternetDB - has Shodan already observed open ports / CVEs on it.
   (We never port-scan our own WAN address ourselves.)
3. The router's UPnP IGD, if it answers SSDP - which port mappings exist,
   because that is how malware and "helpful" apps quietly expose the LAN.

Every response is untrusted: sizes are capped, every HTTP exchange has a
wall-clock deadline, XML is parsed with ElementTree only, the description URL
must point at the LAN host that answered SSDP, and control URLs must stay on
that same host.
"""

from __future__ import annotations

import functools
import http.client
import ipaddress
import json
import logging
import re
import select
import socket
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import TYPE_CHECKING, Any, Callable
from xml.etree import ElementTree as ET

from homesoc import db
from homesoc.models import FindingDraft, ScanResult
from homesoc.scanners import discovery
from homesoc.util import device_text, utcnow_iso

if TYPE_CHECKING:
    import sqlite3

    from homesoc.config import Config

logger = logging.getLogger(__name__)

__all__ = [
    "run", "public_ip", "internetdb", "discover_igd", "igd_services", "enumerate_mappings",
    "parse_mapping_response", "parse_ssdp_response", "IPIFY_URL", "INTERNETDB_URL", "IGD_ST",
]

IPIFY_URL = "https://api.ipify.org?format=json"
INTERNETDB_URL = "https://internetdb.shodan.io/{ip}"
SSDP_GROUP = ("239.255.255.250", 1900)
IGD_ST = "urn:schemas-upnp-org:device:InternetGatewayDevice:1"
# SPEC-GAP: IGD:2 gateways answer the IGD:2 ST; sending both costs one more packet.
IGD_ST_V2 = "urn:schemas-upnp-org:device:InternetGatewayDevice:2"
WAN_SERVICE_TYPES = ("WANIPConnection", "WANPPPConnection")
USER_AGENT = "HomeSOC/0.1 (+local security scanner)"
MAX_BODY = 512 * 1024
MAX_MAPPINGS = 100
# Wall-clock budget for the whole exposure step and for the SOAP walk; a gateway that accepts the
# connection but answers slowly must not hold the single scheduler thread for minutes.
RUN_BUDGET_SEC = 60.0
SOAP_TIMEOUT_SEC = 3.0
SLOW_RESPONSE_SEC = 2.0
MAX_CONSECUTIVE_SLOW = 2
# Every SSDP responder can claim to be a gateway; a real home has one or two.
MAX_IGDS = 4
MAX_HEADER_VALUE = 512
_READ_CHUNK = 64 * 1024
# The only service types we ever SOAP; the value goes into the request body and SOAPAction header.
_WAN_SERVICE_RE = re.compile(r"urn:schemas-upnp-org:service:WAN(?:IP|PPP)Connection:[12]")
_SERVICE_TYPE_OK = re.compile(r"[A-Za-z0-9:._-]{1,128}")
# C0/C1 controls, DEL and the Unicode line separators: a device-supplied header value carrying any of
# these is forging log lines or terminal escapes, never describing a gateway.
_CONTROL_CHARS = re.compile("[\x00-\x1f\x7f-\x9f\u2028\u2029]")
_URL_BAD_CHARS = re.compile("[\x00-\x20\x7f-\x9f\u2028\u2029]")
_THIS_NETWORK = ipaddress.ip_network("0.0.0.0/8")


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """A rogue SSDP responder must not bounce us from its private LOCATION to another host."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D401 - urllib hook
        return None


class _DeadlineSocket(socket.socket):
    """A socket whose sends and receives share one wall-clock deadline.

    urllib's ``timeout`` bounds each socket operation separately, so a LAN device that drips one
    byte every few seconds (status line, headers or body) would never trip it and could hold the
    single scheduler thread for days.  Here every operation only gets what is left of the budget.
    """

    deadline = 0.0

    def _arm(self) -> None:
        left = self.deadline - time.monotonic()
        if left <= 0:
            raise TimeoutError("HTTP exchange exceeded its wall-clock budget")
        self.settimeout(left)

    def recv(self, *args, **kwargs):  # noqa: D102 - socket API
        self._arm()
        return super().recv(*args, **kwargs)

    def recv_into(self, *args, **kwargs):  # noqa: D102 - socket API
        self._arm()
        return super().recv_into(*args, **kwargs)

    def send(self, *args, **kwargs):  # noqa: D102 - socket API
        self._arm()
        return super().send(*args, **kwargs)

    def sendall(self, *args, **kwargs):  # noqa: D102 - socket API
        self._arm()
        return super().sendall(*args, **kwargs)


class _DeadlineHTTPConnection(http.client.HTTPConnection):
    def __init__(self, *args, deadline: float, **kwargs):
        super().__init__(*args, **kwargs)
        self._deadline = deadline

    def connect(self) -> None:
        super().connect()
        raw = self.sock
        sock = _DeadlineSocket(raw.family, raw.type, raw.proto, fileno=raw.detach())
        sock.deadline = self._deadline
        self.sock = sock


class _DeadlineHTTPHandler(urllib.request.HTTPHandler):
    """Plain http (the LAN side: IGD description + SOAP) runs on :class:`_DeadlineSocket`."""

    def http_open(self, req):  # noqa: D401 - urllib hook
        deadline = getattr(req, "homesoc_deadline", None)
        if deadline is None:
            return super().http_open(req)
        return self.do_open(functools.partial(_DeadlineHTTPConnection, deadline=deadline), req)


_OPENER = urllib.request.build_opener(_NoRedirect, _DeadlineHTTPHandler)
_SOAP_ENVELOPE = (
    '<?xml version="1.0"?>'
    '<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" '
    's:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/"><s:Body>'
    '<u:GetGenericPortMappingEntry xmlns:u="{service_type}">'
    "<NewPortMappingIndex>{index}</NewPortMappingIndex>"
    "</u:GetGenericPortMappingEntry></s:Body></s:Envelope>"
)


# --------------------------------------------------------------------------- HTTP helpers

def _read_capped(resp: Any, deadline: float) -> bytes:
    """Read at most MAX_BODY bytes, giving up at ``deadline`` even if the peer keeps dripping."""
    read = getattr(resp, "read1", None) or resp.read
    chunks: list[bytes] = []
    total = 0
    while total <= MAX_BODY:
        if time.monotonic() >= deadline:
            raise TimeoutError("HTTP body exceeded its wall-clock budget")
        chunk = read(min(_READ_CHUNK, MAX_BODY + 1 - total))
        if not chunk:
            break
        chunks.append(chunk)
        total += len(chunk)
    return b"".join(chunks)[:MAX_BODY]


def _http(url: str, *, timeout: float, data: bytes | None = None, headers: dict[str, str] | None = None,
          deadline: float | None = None) -> tuple[int, bytes]:
    """GET/POST with a size cap and no redirects; returns (status, body). Raises OSError to the caller.

    ``timeout`` is a wall-clock limit for the whole exchange (plain http: connect, headers and body;
    https: the body, plus ``timeout`` per operation before it), cut shorter by ``deadline`` (monotonic).
    """
    scheme = urllib.parse.urlparse(url).scheme.lower()
    if scheme not in ("http", "https"):
        raise ValueError(f"refusing non-http(s) URL scheme {scheme!r}")
    limit = time.monotonic() + timeout
    if deadline is not None:
        limit = min(limit, deadline)
    left = limit - time.monotonic()
    if left <= 0:
        raise TimeoutError("no time left for this HTTP request")
    req = urllib.request.Request(url, data=data, headers={"User-Agent": USER_AGENT, **(headers or {})})
    req.homesoc_deadline = limit  # type: ignore[attr-defined] - read by _DeadlineHTTPHandler
    try:
        with _OPENER.open(req, timeout=left) as resp:  # noqa: S310 - fixed https/LAN urls only
            return resp.status, _read_capped(resp, limit)
    except urllib.error.HTTPError as exc:
        body = _read_capped(exc, limit) if hasattr(exc, "read") else b""
        return exc.code, body
    except http.client.HTTPException as exc:
        # IncompleteRead, InvalidURL, BadStatusLine...: a garbled answer, not a crash of the whole run.
        raise OSError(f"bad HTTP exchange: {type(exc).__name__}") from exc


def _is_lan_address(host: str) -> bool:
    """A unicast private address another box on the LAN could own: no loopback, link-local,
    unspecified, "this network", multicast or reserved space (all of which ``is_private`` admits)."""
    try:
        addr = ipaddress.ip_address(host)
    except ValueError:
        return False
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
        addr = addr.ipv4_mapped
    if isinstance(addr, ipaddress.IPv4Address) and addr in _THIS_NETWORK:
        return False
    return addr.is_private and not (addr.is_loopback or addr.is_link_local or addr.is_unspecified
                                    or addr.is_multicast or addr.is_reserved)


def _is_private_url(url: str) -> bool:
    """True for a URL whose host is a literal LAN address (see :func:`_is_lan_address`)."""
    try:
        host = urllib.parse.urlparse(url).hostname or ""
    except ValueError:
        return False
    return _is_lan_address(host)


def _url_host(url: str) -> str | None:
    """Canonical literal IP of ``url``'s host, or None for a name / garbage."""
    try:
        host = urllib.parse.urlparse(url).hostname
        return str(ipaddress.ip_address(host)) if host else None
    except ValueError:
        return None


# --------------------------------------------------------------------------- public IP / InternetDB

def public_ip(timeout: float = 5.0) -> str | None:
    try:
        status, body = _http(IPIFY_URL, timeout=timeout)
        if status != 200:
            return None
        ip = str(json.loads(body.decode("utf-8", "replace")).get("ip", "")).strip()
        ipaddress.ip_address(ip)
        return ip
    except (urllib.error.URLError, OSError, ValueError, json.JSONDecodeError) as exc:
        logger.info("public IP lookup failed: %s", exc)
        return None


def internetdb(ip: str, timeout: float = 8.0) -> dict[str, Any]:
    """Shodan InternetDB verdict: status clean | exposed | error, plus the raw lists."""
    out: dict[str, Any] = {"status": "error", "ports": [], "vulns": [], "cpes": [], "hostnames": [], "tags": [], "error": None}
    try:
        ipaddress.ip_address(ip)
        status, body = _http(INTERNETDB_URL.format(ip=ip), timeout=timeout)
        text = body.decode("utf-8", "replace")
        if status == 404 or "No information available" in text:
            out["status"] = "clean"
            return out
        if status != 200:
            out["error"] = f"HTTP {status}"
            return out
        data = json.loads(text)
        if not isinstance(data, dict):
            out["error"] = "unexpected payload"
            return out
        for key in ("ports", "vulns", "cpes", "hostnames", "tags"):
            vals = data.get(key) or []
            out[key] = [v for v in vals if isinstance(v, (str, int))][:200]
        out["ports"] = sorted({int(p) for p in out["ports"] if str(p).isdigit()})
        out["status"] = "exposed" if (out["ports"] or out["vulns"]) else "clean"
    except (urllib.error.URLError, OSError, ValueError, json.JSONDecodeError) as exc:
        out["error"] = str(exc)
    return out


# --------------------------------------------------------------------------- UPnP / IGD

def parse_ssdp_response(text: str) -> dict[str, str] | None:
    """Headers of an SSDP 200 response.  A value carrying control characters (log forging, terminal
    escapes) or longer than MAX_HEADER_VALUE is dropped: it never describes a real gateway."""
    lines = text.replace("\r\n", "\n").split("\n")
    if not lines or "200" not in lines[0]:
        return None
    hdr: dict[str, str] = {}
    for line in lines[1:]:
        if ":" in line:
            k, v = line.split(":", 1)
            v = v.strip()
            if len(v) > MAX_HEADER_VALUE or _CONTROL_CHARS.search(v):
                v = ""
            hdr[k.strip().lower()] = v
    return {"location": hdr.get("location", ""), "server": hdr.get("server", ""), "st": hdr.get("st", ""),
            "usn": hdr.get("usn", "")}


def discover_igd(interface_ip: str, seconds: float = 3.0) -> list[dict[str, str]]:
    """M-SEARCH for an Internet Gateway Device from ``interface_ip``; one dict per distinct LOCATION."""
    found: dict[str, dict[str, str]] = {}
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    except OSError:
        return []
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((interface_ip, 0))
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
        try:
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(interface_ip))
        except OSError:
            pass
        for st in (IGD_ST, IGD_ST_V2):
            msg = (f"M-SEARCH * HTTP/1.1\r\nHOST: {SSDP_GROUP[0]}:{SSDP_GROUP[1]}\r\n"
                   f'MAN: "ssdp:discover"\r\nMX: 2\r\nST: {st}\r\n\r\n').encode("ascii")
            sock.sendto(msg, SSDP_GROUP)
        sock.setblocking(False)
        deadline = time.monotonic() + max(0.5, seconds)
        while True:
            left = deadline - time.monotonic()
            if left <= 0:
                break
            r, _, _ = select.select([sock], [], [], min(left, 0.5))
            if not r:
                continue
            try:
                data, addr = sock.recvfrom(4096)
            except OSError:
                continue
            parsed = parse_ssdp_response(data.decode("utf-8", "replace"))
            if not parsed or not parsed["location"]:
                continue
            if "InternetGatewayDevice" not in parsed["st"] and "InternetGatewayDevice" not in parsed["usn"]:
                continue
            # The description must live on the box that answered: otherwise any LAN device could aim
            # our GET (and the SOAP POSTs after it) at localhost or at a third host that trusts this PC.
            if not _is_lan_address(addr[0]) or _url_host(parsed["location"]) != addr[0]:
                logger.info("ignoring SSDP gateway answer from %s: LOCATION is not on the responder", addr[0])
                continue
            parsed["from"] = addr[0]
            if parsed["location"] not in found and len(found) >= MAX_IGDS:
                continue
            found.setdefault(parsed["location"], parsed)
    except OSError as exc:
        logger.debug("SSDP IGD search failed: %s", exc)
    finally:
        sock.close()
    return list(found.values())


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def igd_services(location: str, timeout: float = 5.0) -> list[dict[str, str]]:
    """Fetch the IGD description and return WAN*Connection services with absolute control URLs.

    ``timeout`` bounds the whole fetch in wall-clock seconds, not each socket read.
    """
    if not _is_private_url(location):
        # %r: the URL is device-supplied, and a raw CR/ESC in it would forge log lines.
        logger.warning("ignoring IGD description outside the LAN: %r", location[:MAX_HEADER_VALUE])
        return []
    try:
        status, body = _http(location, timeout=timeout)
        if status != 200:
            return []
        root = ET.fromstring(body)
    except (urllib.error.URLError, OSError, ET.ParseError, ValueError) as exc:
        logger.debug("IGD description fetch failed: %s", exc)
        return []
    base = location
    for el in root.iter():
        if _local(el.tag) == "URLBase" and el.text and el.text.strip():
            base = el.text.strip()
            break
    igd_host = urllib.parse.urlparse(location).hostname
    out: list[dict[str, str]] = []
    for svc in root.iter():
        if _local(svc.tag) != "service":
            continue
        stype = ctrl = ""
        for child in svc:
            if _local(child.tag) == "serviceType":
                stype = (child.text or "").strip()
            elif _local(child.tag) == "controlURL":
                ctrl = (child.text or "").strip()
        # Exact allow-list: the service type is echoed into the SOAP body and SOAPAction header.
        if not _WAN_SERVICE_RE.fullmatch(stype) or not ctrl:
            continue
        try:
            control_url = urllib.parse.urljoin(base, ctrl)
            ctrl_host = urllib.parse.urlparse(control_url).hostname
        except ValueError:
            continue
        # The description is untrusted: never let it point us at another host.
        if ctrl_host != igd_host:
            logger.warning("IGD control URL host mismatch; skipped: %r", control_url[:MAX_HEADER_VALUE])
            continue
        if len(control_url) > MAX_HEADER_VALUE or _URL_BAD_CHARS.search(control_url):
            continue
        out.append({"service_type": stype, "control_url": control_url})
    return out


def parse_mapping_response(xml_text: str | bytes) -> dict[str, Any] | None:
    """Flatten a GetGenericPortMappingEntryResponse; None on a SOAP fault or garbage."""
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return None
    fields: dict[str, str] = {}
    for el in root.iter():
        name = _local(el.tag)
        if name.startswith("New"):
            fields[name] = (el.text or "").strip()
        elif name in ("Fault", "UPnPError"):
            return None
    if "NewExternalPort" not in fields:
        return None

    def as_int(v: str) -> int | None:
        return int(v) if v.isdigit() else None

    def as_ipv4(v: str) -> str:
        # Whoever answers the SOAP call writes these fields; only a real IPv4 address is kept, so
        # a newline or markup cannot ride into a finding title through "internal_client".
        try:
            return str(ipaddress.IPv4Address(v.strip()))
        except ValueError:
            return ""

    protocol = fields.get("NewProtocol", "").strip().upper()
    return {
        "remote_host": as_ipv4(fields.get("NewRemoteHost", "")),
        "external_port": as_int(fields.get("NewExternalPort", "")),
        "protocol": protocol if protocol in ("TCP", "UDP") else device_text(protocol, 8),
        "internal_port": as_int(fields.get("NewInternalPort", "")),
        "internal_client": as_ipv4(fields.get("NewInternalClient", "")),
        "enabled": fields.get("NewEnabled", "1") not in ("0", "false", ""),
        "description": device_text(fields.get("NewPortMappingDescription", ""), 120),
        "lease_duration": as_int(fields.get("NewLeaseDuration", "")),
    }


def enumerate_mappings(control_url: str, service_type: str, *, timeout: float = SOAP_TIMEOUT_SEC,
                       max_entries: int = MAX_MAPPINGS, deadline: float | None = None) -> list[dict[str, Any]]:
    """Walk GetGenericPortMappingEntry 0..max_entries-1 until the gateway errors out.

    Stops early at ``deadline`` (monotonic seconds) or after two consecutive slow answers, because
    a sluggish gateway would otherwise cost up to 100 x timeout on the scheduler thread.
    """
    if not _is_private_url(control_url) or not _SERVICE_TYPE_OK.fullmatch(service_type or ""):
        return []
    mappings: list[dict[str, Any]] = []
    slow = 0
    for index in range(max_entries):
        if deadline is not None and time.monotonic() >= deadline:
            logger.info("port mapping enumeration stopped at %d entries: time budget exhausted", index)
            break
        body = _SOAP_ENVELOPE.format(service_type=service_type, index=index).encode("utf-8")
        headers = {"Content-Type": 'text/xml; charset="utf-8"',
                   "SOAPAction": f'"{service_type}#GetGenericPortMappingEntry"'}
        t0 = time.monotonic()
        try:
            status, resp = _http(control_url, timeout=timeout, data=body, headers=headers, deadline=deadline)
        except (urllib.error.URLError, OSError, ValueError) as exc:
            logger.debug("port mapping query %d failed: %s", index, exc)
            break
        slow = slow + 1 if time.monotonic() - t0 >= SLOW_RESPONSE_SEC else 0
        if status != 200:
            break
        entry = parse_mapping_response(resp)
        if entry is None:
            break
        entry["index"] = index
        mappings.append(entry)
        if slow >= MAX_CONSECUTIVE_SLOW:
            logger.info("port mapping enumeration stopped at %d entries: gateway too slow", index + 1)
            break
    return mappings


# --------------------------------------------------------------------------- run

def _wan_findings(ip: str | None, idb: dict[str, Any]) -> list[FindingDraft]:
    drafts = []
    for port in idb.get("ports", []):
        drafts.append(FindingDraft(finding_id="NET-WAN-001", subject="wan",
                                   evidence={"key": str(port), "port": port, "public_ip": ip,
                                             "source": "internetdb", "hostnames": idb.get("hostnames", [])}))
    if idb.get("vulns"):
        drafts.append(FindingDraft(finding_id="NET-WAN-002", subject="wan",
                                   evidence={"public_ip": ip, "vulns": idb["vulns"][:50], "cpes": idb.get("cpes", [])[:20],
                                             "ports": idb.get("ports", []), "source": "internetdb"}))
    return drafts


def _upnp_findings(igds: list[dict[str, str]], mappings: list[dict[str, Any]]) -> list[FindingDraft]:
    drafts = []
    for igd in igds:
        drafts.append(FindingDraft(finding_id="NET-RTR-002", subject="wan",
                                   evidence={"key": igd.get("from") or igd.get("location"), "igd_ip": igd.get("from"),
                                             "location": igd.get("location"), "server": igd.get("server")}))
    for m in mappings:
        key = f"{m.get('protocol')}/{m.get('external_port')}"
        drafts.append(FindingDraft(finding_id="NET-WAN-003", subject="wan", evidence={"key": key, **m}))
    return drafts


def _igd_in_scope(igd: dict[str, str], network: ipaddress.IPv4Network) -> bool:
    """The IGD must be the LAN host that answered SSDP, inside the configured scan boundary."""
    host = igd.get("from") or ""
    if not _is_lan_address(host) or _url_host(igd.get("location") or "") != host:
        return False
    try:
        return ipaddress.ip_address(host) in network
    except ValueError:
        return False


def run(cfg: "Config", conn: "sqlite3.Connection", *, quick: bool = False,
        progress: Callable[[str], None] | None = None) -> ScanResult:
    """Public IP + InternetDB + UPnP mappings; stores ``exposure.public_ip`` / ``exposure.last_json``."""
    started = time.monotonic()
    deadline = started + RUN_BUDGET_SEC
    say = progress or (lambda _m: None)
    findings: list[FindingDraft] = []
    summary: dict[str, Any] = {"public_ip": None, "internetdb": None, "igd_found": 0, "igds": [],
                               "mappings": [], "mappings_count": 0, "wan_ports": [], "duration_sec": 0.0,
                               "partial": False}
    error: str | None = None
    errors: list[str] = []
    try:
        iface = discovery.local_ip()
        if discovery._is_unusable_ip(iface):
            summary["duration_sec"] = round(time.monotonic() - started, 2)
            return ScanResult(kind="exposure", findings=[], summary=summary, error="no LAN interface (offline?)")
        say("looking up public IP")
        ip = public_ip()
        summary["public_ip"] = ip
        if ip is None:
            errors.append("public IP lookup failed (offline?)")
        else:
            say("querying Shodan InternetDB")
            idb = internetdb(ip)
            summary["internetdb"] = idb
            summary["wan_ports"] = idb.get("ports", [])
            if idb.get("error"):
                errors.append(f"internetdb: {idb['error']}")
            findings.extend(_wan_findings(ip, idb))

        say("searching for a UPnP gateway")
        network = discovery.resolve_network(cfg)
        igds = [igd for igd in discover_igd(iface, seconds=3.0) if _igd_in_scope(igd, network)][:MAX_IGDS]
        summary["igd_found"] = len(igds)
        summary["igds"] = igds
        mappings: list[dict[str, Any]] = []
        for igd in igds:
            left = deadline - time.monotonic()
            if left <= 0:
                summary["partial"] = True
                break
            # Wall-clock bound on the description fetch too: the budget must hold before the SOAP walk.
            for svc in igd_services(igd["location"], timeout=min(5.0, left)):
                if time.monotonic() >= deadline:
                    summary["partial"] = True
                    break
                say(f"enumerating port mappings on {svc['control_url']}")
                mappings.extend(enumerate_mappings(svc["control_url"], svc["service_type"], deadline=deadline))
        if time.monotonic() >= deadline:
            summary["partial"] = True
        summary["mappings"] = mappings
        summary["mappings_count"] = len(mappings)
        findings.extend(_upnp_findings(igds, mappings))

        snapshot = {"checked_at": utcnow_iso(), **summary}
        try:
            db.set_setting(conn, "exposure.public_ip", ip or "")
            db.set_setting(conn, "exposure.last_json", json.dumps(snapshot, default=str))
        except Exception as exc:
            logger.debug("could not persist exposure snapshot: %s", exc)
    except Exception as exc:
        logger.exception("exposure check failed")
        errors.append(f"{type(exc).__name__}: {exc}")
    if errors:
        error = "; ".join(errors)
    summary["duration_sec"] = round(time.monotonic() - started, 2)
    return ScanResult(kind="exposure", findings=findings, summary=summary, error=error)
