"""What does the internet see of this home? (SPEC 6.3)

Three cheap, read-only questions, all answered with the standard library:

1. ipify - what is our public IP.
2. Shodan InternetDB - has Shodan already observed open ports / CVEs on it.
   (We never port-scan our own WAN address ourselves.)
3. The router's UPnP IGD, if it answers SSDP - which port mappings exist,
   because that is how malware and "helpful" apps quietly expose the LAN.

Every response is untrusted: sizes are capped, XML is parsed with
ElementTree only, and control URLs must stay on the same private host that
answered SSDP.
"""

from __future__ import annotations

import ipaddress
import json
import logging
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
from homesoc.util import utcnow_iso

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


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """A rogue SSDP responder must not bounce us from its private LOCATION to another host."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D401 - urllib hook
        return None


_OPENER = urllib.request.build_opener(_NoRedirect)
_SOAP_ENVELOPE = (
    '<?xml version="1.0"?>'
    '<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" '
    's:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/"><s:Body>'
    '<u:GetGenericPortMappingEntry xmlns:u="{service_type}">'
    "<NewPortMappingIndex>{index}</NewPortMappingIndex>"
    "</u:GetGenericPortMappingEntry></s:Body></s:Envelope>"
)


# --------------------------------------------------------------------------- HTTP helpers

def _http(url: str, *, timeout: float, data: bytes | None = None, headers: dict[str, str] | None = None) -> tuple[int, bytes]:
    """GET/POST with a size cap and no redirects; returns (status, body). Raises URLError to the caller."""
    scheme = urllib.parse.urlparse(url).scheme.lower()
    if scheme not in ("http", "https"):
        raise ValueError(f"refusing non-http(s) URL scheme {scheme!r}")
    req = urllib.request.Request(url, data=data, headers={"User-Agent": USER_AGENT, **(headers or {})})
    try:
        with _OPENER.open(req, timeout=timeout) as resp:  # noqa: S310 - fixed https/LAN urls only
            return resp.status, resp.read(MAX_BODY + 1)[:MAX_BODY]
    except urllib.error.HTTPError as exc:
        body = exc.read(MAX_BODY + 1)[:MAX_BODY] if hasattr(exc, "read") else b""
        return exc.code, body


def _is_private_url(url: str) -> bool:
    try:
        host = urllib.parse.urlparse(url).hostname or ""
        return ipaddress.ip_address(host).is_private
    except ValueError:
        return False


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
    lines = text.replace("\r\n", "\n").split("\n")
    if not lines or "200" not in lines[0]:
        return None
    hdr: dict[str, str] = {}
    for line in lines[1:]:
        if ":" in line:
            k, v = line.split(":", 1)
            hdr[k.strip().lower()] = v.strip()
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
            parsed["from"] = addr[0]
            found.setdefault(parsed["location"], parsed)
    except OSError as exc:
        logger.debug("SSDP IGD search failed: %s", exc)
    finally:
        sock.close()
    return list(found.values())


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def igd_services(location: str, timeout: float = 5.0) -> list[dict[str, str]]:
    """Fetch the IGD description and return WAN*Connection services with absolute control URLs."""
    if not _is_private_url(location):
        logger.warning("ignoring IGD description outside private space: %s", location)
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
        if not any(w in stype for w in WAN_SERVICE_TYPES) or not ctrl:
            continue
        control_url = urllib.parse.urljoin(base, ctrl)
        # The description is untrusted: never let it point us at another host.
        if urllib.parse.urlparse(control_url).hostname != igd_host:
            logger.warning("IGD control URL host mismatch; skipped: %s", control_url)
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

    return {
        "remote_host": fields.get("NewRemoteHost", ""),
        "external_port": as_int(fields.get("NewExternalPort", "")),
        "protocol": fields.get("NewProtocol", "").upper(),
        "internal_port": as_int(fields.get("NewInternalPort", "")),
        "internal_client": fields.get("NewInternalClient", ""),
        "enabled": fields.get("NewEnabled", "1") not in ("0", "false", ""),
        "description": fields.get("NewPortMappingDescription", "")[:120],
        "lease_duration": as_int(fields.get("NewLeaseDuration", "")),
    }


def enumerate_mappings(control_url: str, service_type: str, *, timeout: float = SOAP_TIMEOUT_SEC,
                       max_entries: int = MAX_MAPPINGS, deadline: float | None = None) -> list[dict[str, Any]]:
    """Walk GetGenericPortMappingEntry 0..max_entries-1 until the gateway errors out.

    Stops early at ``deadline`` (monotonic seconds) or after two consecutive slow answers, because
    a sluggish gateway would otherwise cost up to 100 x timeout on the scheduler thread.
    """
    if not _is_private_url(control_url):
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
            status, resp = _http(control_url, timeout=timeout, data=body, headers=headers)
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
        igds = discover_igd(iface, seconds=3.0)
        summary["igd_found"] = len(igds)
        summary["igds"] = igds
        mappings: list[dict[str, Any]] = []
        for igd in igds:
            for svc in igd_services(igd["location"]):
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
