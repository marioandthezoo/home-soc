"""One mDNS query and one SSDP M-SEARCH, then listen for a few seconds (SPEC 6.4).

This is the cheapest way to learn what a device *says* it is - printers
advertise ``_ipp._tcp``, Apple gear ``_airplay._tcp``, casting sticks
``_googlecast._tcp`` - and to pick up hostnames for boxes the router's reverse
DNS does not know.  Two multicast packets, no follow-up probes, no findings.
"""

from __future__ import annotations

import logging
import select
import socket
import struct
import time
from typing import Any

logger = logging.getLogger(__name__)

try:  # dnslib is a declared dependency, but the probe must degrade if absent
    from dnslib import CLASS, QTYPE, DNSHeader, DNSQuestion, DNSRecord
except Exception:  # pragma: no cover - exercised only without dnslib
    DNSRecord = None  # type: ignore[assignment]

__all__ = [
    "probe", "build_mdns_query", "parse_mdns_response", "build_ssdp_msearch", "parse_ssdp_response",
    "MDNS_GROUP", "SSDP_GROUP", "SERVICES_QNAME",
]

MDNS_GROUP = ("224.0.0.251", 5353)
SSDP_GROUP = ("239.255.255.250", 1900)
SERVICES_QNAME = "_services._dns-sd._udp.local"
# QU bit (top bit of qclass) asks responders to answer us directly, so we do
# not depend on being able to bind port 5353 next to the OS resolver.
QU_IN = 0x8001
# A few common types ride along in the same packet so SRV/A answers give us
# hostnames as well as the bare service-type list.
EXTRA_TYPES = ("_http._tcp.local", "_ipp._tcp.local", "_airplay._tcp.local", "_googlecast._tcp.local",
               "_hap._tcp.local", "_smb._tcp.local", "_workstation._tcp.local", "_device-info._tcp.local")
MAX_PACKET = 9000


# --------------------------------------------------------------------------- mDNS

def build_mdns_query() -> bytes:
    if DNSRecord is None:
        raise RuntimeError("dnslib is not installed")
    q = DNSRecord(DNSHeader(id=0, qr=0, aa=0, rd=0))
    q.add_question(DNSQuestion(SERVICES_QNAME, QTYPE.PTR, QU_IN))
    for t in EXTRA_TYPES:
        q.add_question(DNSQuestion(t, QTYPE.PTR, QU_IN))
    return q.pack()


def _label(name: Any) -> str:
    """Plain text of a dnslib label; ``str()`` would escape spaces as ``\\032``."""
    raw = getattr(name, "label", None)
    if raw is not None:
        try:
            return b".".join(raw).decode("utf-8", "replace").rstrip(".")
        except (TypeError, AttributeError):
            pass
    return str(name).rstrip(".")


def parse_mdns_response(data: bytes) -> dict[str, list[str]]:
    """Pull service types, instance names and hostnames out of one mDNS answer.

    Returns ``{"services": [...], "instances": [...], "names": [...]}``; any
    malformed packet (they happen - some IoT stacks are creative) yields empty lists.
    """
    out: dict[str, list[str]] = {"services": [], "instances": [], "names": []}
    if DNSRecord is None:
        return out
    try:
        rec = DNSRecord.parse(data)
    except Exception:
        return out

    def add(bucket: str, value: str) -> None:
        if value and value not in out[bucket]:
            out[bucket].append(value)

    for rr in list(rec.rr) + list(rec.auth) + list(rec.ar):
        try:
            rtype = QTYPE.get(rr.rtype)
            rname = _label(rr.rname)
        except Exception:
            continue
        if rtype == "PTR":
            target = _label(rr.rdata.label) if hasattr(rr.rdata, "label") else _label(rr.rdata)
            if rname.lower() == SERVICES_QNAME:
                add("services", target)
            elif rname.startswith("_"):
                add("services", rname)
                add("instances", target)
        elif rtype == "SRV":
            target = _label(getattr(rr.rdata, "target", ""))
            if target:
                add("names", target.removesuffix(".local"))
            if rname.startswith("_") or "._" in rname:
                svc = rname[rname.find("._") + 1:] if "._" in rname else rname
                add("services", svc)
        elif rtype in ("A", "AAAA"):
            add("names", rname.removesuffix(".local"))
    return out


# --------------------------------------------------------------------------- SSDP

def build_ssdp_msearch(st: str = "ssdp:all", mx: int = 2) -> bytes:
    lines = [
        "M-SEARCH * HTTP/1.1",
        f"HOST: {SSDP_GROUP[0]}:{SSDP_GROUP[1]}",
        'MAN: "ssdp:discover"',
        f"MX: {int(mx)}",
        f"ST: {st}",
        "",
        "",
    ]
    return "\r\n".join(lines).encode("ascii", errors="replace")


def parse_ssdp_response(text: str) -> dict[str, str] | None:
    """Headers of an SSDP 200 response as lower-case keys; None for anything else."""
    lines = text.replace("\r\n", "\n").split("\n")
    if not lines or "200" not in lines[0].upper():
        return None
    headers: dict[str, str] = {}
    for line in lines[1:]:
        if ":" not in line:
            continue
        k, v = line.split(":", 1)
        headers[k.strip().lower()] = v.strip()
    return {
        "st": headers.get("st", ""),
        "server": headers.get("server", ""),
        "location": headers.get("location", ""),
        "usn": headers.get("usn", ""),
    }


# --------------------------------------------------------------------------- sockets

def _udp_socket(interface_ip: str, port: int = 0) -> socket.socket:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((interface_ip, port))
    s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
    try:
        s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(interface_ip))
    except OSError:
        pass
    s.setblocking(False)
    return s


def _mdns_listener(interface_ip: str) -> socket.socket | None:
    """Best-effort membership socket on 5353 for responders that ignore the QU bit."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if hasattr(socket, "SO_REUSEPORT"):
            try:
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
            except OSError:
                pass
        s.bind(("", MDNS_GROUP[1]))
        mreq = struct.pack("4s4s", socket.inet_aton(MDNS_GROUP[0]), socket.inet_aton(interface_ip))
        s.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
        s.setblocking(False)
        return s
    except OSError as exc:
        logger.debug("mDNS group listener unavailable (%s); relying on unicast replies", exc)
        return None


def probe(interface_ip: str, seconds: float = 3.0) -> dict[str, dict[str, Any]]:
    """Send one mDNS query + one SSDP M-SEARCH from ``interface_ip`` and collect answers.

    Returns ``{ip: {"mdns": [service types], "ssdp": [{"st","server","location"}], "names": [hostnames]}}``.
    Never raises: a host without multicast routing just yields ``{}``.
    """
    results: dict[str, dict[str, Any]] = {}
    socks: list[tuple[str, socket.socket]] = []
    try:
        try:
            m = _udp_socket(interface_ip)
            m.sendto(build_mdns_query(), MDNS_GROUP)
            socks.append(("mdns", m))
        except (OSError, RuntimeError) as exc:
            logger.debug("mDNS query not sent: %s", exc)
        listener = _mdns_listener(interface_ip)
        if listener is not None:
            socks.append(("mdns", listener))
        try:
            s = _udp_socket(interface_ip)
            s.sendto(build_ssdp_msearch(), SSDP_GROUP)
            socks.append(("ssdp", s))
        except OSError as exc:
            logger.debug("SSDP M-SEARCH not sent: %s", exc)
        if not socks:
            return results

        deadline = time.monotonic() + max(0.2, float(seconds))
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            readable, _, _ = select.select([s for _, s in socks], [], [], min(remaining, 0.5))
            for sock in readable:
                kind = next(k for k, s in socks if s is sock)
                try:
                    data, addr = sock.recvfrom(MAX_PACKET)
                except OSError:
                    continue
                ip = addr[0]
                entry = results.setdefault(ip, {"mdns": [], "ssdp": [], "names": []})
                if kind == "mdns":
                    parsed = parse_mdns_response(data)
                    for t in parsed["services"]:
                        if t not in entry["mdns"]:
                            entry["mdns"].append(t)
                    for n in parsed["names"]:
                        if n not in entry["names"]:
                            entry["names"].append(n)
                else:
                    parsed_ssdp = parse_ssdp_response(data.decode("utf-8", errors="replace"))
                    if parsed_ssdp and parsed_ssdp not in entry["ssdp"]:
                        entry["ssdp"].append(parsed_ssdp)
    except Exception as exc:  # pragma: no cover - defensive: probing is optional
        logger.debug("mDNS/SSDP probe aborted: %s", exc)
    finally:
        for _, s in socks:
            try:
                s.close()
            except OSError:
                pass
    # Drop entries that answered with nothing we could parse.
    return {ip: v for ip, v in results.items() if v["mdns"] or v["ssdp"] or v["names"]}
