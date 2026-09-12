"""LAN device discovery: ARP-first, TCP sweep second (SPEC 6.1).

Ground truth on the target laptop: an nmap ping sweep in connect() mode takes
50 s and finds two hosts, while the OS neighbor table right after a quick
TCP-connect sweep lists 17 hosts with MACs in 40 ms.  So the neighbor table
is the source of record, and the sweep exists mainly to refresh it (every
connect attempt forces an ARP resolution) plus to catch hosts that answer TCP
but never showed up in ARP.

Nothing here ever touches an address outside ``cfg.network.cidr``.
"""

from __future__ import annotations

import concurrent.futures as cf
import ipaddress
import json
import logging
import re
import socket
import time
import uuid
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Callable, Iterable

from homesoc import db
from homesoc.models import FindingDraft, ScanResult
from homesoc.scanners import IS_LINUX, IS_MAC, IS_WINDOWS, cfg_get, powershell, run_command
from homesoc.util import utcnow_iso

if TYPE_CHECKING:
    import sqlite3

    from homesoc.config import Config

logger = logging.getLogger(__name__)

__all__ = [
    "run", "Neighbor", "normalize_mac", "is_unicast_mac", "is_randomized_mac",
    "parse_neighbor_json", "parse_arp_a", "parse_ip_neigh", "read_neighbors", "sweep",
    "resolve_hostnames", "local_ip", "local_mac", "resolve_network", "default_gateway",
    "kind_hint_from_mdns",
]

NEIGHBOR_PS = (
    'Get-NetNeighbor -AddressFamily IPv4 | Where-Object {$_.State -in "Reachable","Stale","Permanent","Delay","Probe"} '
    "| Select-Object IPAddress,LinkLayerAddress,State | ConvertTo-Json"
)
GATEWAY_PS = (
    "Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' | "
    "Sort-Object RouteMetric,InterfaceMetric | Select-Object -First 1 -ExpandProperty NextHop"
)

# Get-NetNeighbor's State enum serializes as an integer through ConvertTo-Json.
_PS_STATE_NAMES = {0: "Unreachable", 1: "Incomplete", 2: "Probe", 3: "Delay", 4: "Stale",
                   5: "Reachable", 6: "Permanent", 7: "TBD"}
_LIVE_STATES = frozenset({"Reachable", "Stale", "Permanent", "Delay", "Probe"})

SWEEP_MAX_SECONDS = 60.0          # hard cap on the TCP sweep (SPEC: never longer)
SWEEP_MAX_HOSTS = 1024            # SPEC-GAP: spec is silent on huge CIDRs; cap to /22-sized sweeps
HOSTNAME_TIMEOUT = 1.0
OFFLINE_TRUSTED_DAYS = 30
STALE_IP_KEY_PREFIX = "ip:"

_MAC_HEX_RE = re.compile(r"[^0-9a-f]")
_ARP_LINE_RE = re.compile(
    r"(?P<ip>\d{1,3}(?:\.\d{1,3}){3}).*?(?P<mac>(?:[0-9A-Fa-f]{1,2}[:-]){5}[0-9A-Fa-f]{1,2})(?P<rest>.*)$"
)
_IP_NEIGH_RE = re.compile(
    r"^(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s.*?lladdr\s+(?P<mac>[0-9a-fA-F:]{17}).*?\b(?P<state>[A-Z]+)\s*$"
)

# mDNS service types that reveal what a box is; used only as a kind hint.
_MDNS_KIND_HINTS: list[tuple[str, tuple[str, ...]]] = [
    ("printer", ("_ipp.", "_ipps.", "_printer.", "_pdl-datastream.", "_scanner.", "_uscan.")),
    ("camera", ("_rtsp.", "_axis-video.", "_hikvision.")),
    ("apple", ("_airplay.", "_raop.", "_companion-link.", "_apple-mobdev", "_touch-able.", "_sleep-proxy.")),
    ("iot", ("_googlecast.", "_hap.", "_sonos.", "_spotify-connect.", "_hue.", "_nanoleaf.", "_shelly.",
             "_esphomelib.", "_amzn-wplay.", "_matter.", "_roku.")),
    ("nas", ("_afpovertcp.", "_smb.", "_nfs.", "_adisk.")),
]


@dataclass(frozen=True)
class Neighbor:
    ip: str
    mac: str
    state: str


# --------------------------------------------------------------------------- MAC helpers

def normalize_mac(raw: str | None) -> str | None:
    """Canonical ``aa:bb:cc:dd:ee:ff`` from any of the vendor/OS spellings, else None."""
    if not raw:
        return None
    hexs = _MAC_HEX_RE.sub("", raw.strip().lower())
    if len(hexs) != 12:
        # macOS arp prints single-digit octets ("0:1c:b3:..."); re-pad them.
        parts = re.split(r"[:-]", raw.strip().lower())
        if len(parts) == 6 and all(1 <= len(p) <= 2 and re.fullmatch(r"[0-9a-f]+", p) for p in parts):
            hexs = "".join(p.zfill(2) for p in parts)
        else:
            return None
    return ":".join(hexs[i:i + 2] for i in range(0, 12, 2))


def is_unicast_mac(mac: str) -> bool:
    """Drops broadcast, multicast (I/G bit) and the all-zero placeholder."""
    if mac in ("ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00"):
        return False
    return (int(mac[:2], 16) & 0x01) == 0


def is_randomized_mac(mac: str) -> bool:
    """Locally-administered bit set: phones/laptops with MAC privacy, or virtual adapters."""
    return is_unicast_mac(mac) and bool(int(mac[:2], 16) & 0x02)


# --------------------------------------------------------------------------- neighbor table parsers

def parse_neighbor_json(text: str) -> list[Neighbor]:
    """Parse ``Get-NetNeighbor | ConvertTo-Json`` (object or array; State int or name)."""
    text = text.strip()
    if not text:
        return []
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        logger.debug("Get-NetNeighbor JSON unparseable")
        return []
    if isinstance(data, dict):
        data = [data]
    if not isinstance(data, list):
        return []
    out: list[Neighbor] = []
    for row in data:
        if not isinstance(row, dict):
            continue
        mac = normalize_mac(str(row.get("LinkLayerAddress") or ""))
        ip = str(row.get("IPAddress") or "").strip()
        state = row.get("State")
        if isinstance(state, int):
            state = _PS_STATE_NAMES.get(state, str(state))
        state = str(state or "Stale")
        if mac and ip:
            out.append(Neighbor(ip=ip, mac=mac, state=state))
    return out


def parse_arp_a(text: str) -> list[Neighbor]:
    """Parse Windows ``arp -a`` and macOS/BSD ``arp -a`` output lines."""
    out: list[Neighbor] = []
    for line in text.splitlines():
        m = _ARP_LINE_RE.search(line)
        if not m:
            continue
        mac = normalize_mac(m.group("mac"))
        if not mac:
            continue
        rest = m.group("rest").lower()
        state = "Permanent" if "static" in rest or "permanent" in rest else "Stale"
        if "incomplete" in rest or "invalid" in rest:
            continue
        out.append(Neighbor(ip=m.group("ip"), mac=mac, state=state))
    return out


def parse_ip_neigh(text: str) -> list[Neighbor]:
    """Parse Linux ``ip -j neigh`` (JSON) or plain ``ip neigh`` text."""
    stripped = text.strip()
    out: list[Neighbor] = []
    if stripped.startswith("["):
        try:
            rows = json.loads(stripped)
        except json.JSONDecodeError:
            rows = []
        for row in rows:
            if not isinstance(row, dict):
                continue
            mac = normalize_mac(row.get("lladdr"))
            ip = row.get("dst")
            states = row.get("state") or []
            state = str(states[0]).title() if states else "Stale"
            if mac and ip and state not in ("Failed", "Incomplete"):
                out.append(Neighbor(ip=str(ip), mac=mac, state=state))
        return out
    for line in stripped.splitlines():
        m = _IP_NEIGH_RE.match(line.strip())
        if not m:
            continue
        mac = normalize_mac(m.group("mac"))
        state = m.group("state").title()
        if mac and state not in ("Failed", "Incomplete"):
            out.append(Neighbor(ip=m.group("ip"), mac=mac, state=state))
    return out


def _raw_neighbors() -> tuple[list[Neighbor], str]:
    """Platform dispatch; returns (neighbors, method label)."""
    if IS_WINDOWS:
        res = powershell(NEIGHBOR_PS, timeout=20)
        if res.ok:
            parsed = parse_neighbor_json(res.out)
            if parsed:
                return parsed, "get-netneighbor"
        res = run_command(["arp", "-a"], timeout=10)
        return parse_arp_a(res.out), "arp"
    if IS_LINUX:
        res = run_command(["ip", "-j", "neigh"], timeout=10)
        if res.ok and res.out.strip():
            return parse_ip_neigh(res.out), "ip-neigh"
        res = run_command(["ip", "neigh"], timeout=10)
        if res.ok:
            return parse_ip_neigh(res.out), "ip-neigh"
    res = run_command(["arp", "-a"], timeout=10)
    return parse_arp_a(res.out), "arp"


def read_neighbors(network: ipaddress.IPv4Network) -> dict[str, Neighbor]:
    """Live unicast neighbors inside ``network`` keyed by IP; last entry wins on duplicates."""
    raw, method = _raw_neighbors()
    out: dict[str, Neighbor] = {}
    for n in raw:
        try:
            addr = ipaddress.ip_address(n.ip)
        except ValueError:
            continue
        if addr not in network or addr == network.broadcast_address or addr == network.network_address:
            continue
        if not is_unicast_mac(n.mac) or n.state not in _LIVE_STATES:
            continue
        out[n.ip] = n
    logger.debug("neighbor table via %s: %d live hosts in %s", method, len(out), network)
    return out


# --------------------------------------------------------------------------- interface / network

def local_ip() -> str:
    """IP of the default-route interface (no packets are sent by a UDP connect)."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(1.0)
            s.connect(("8.8.8.8", 53))
            return s.getsockname()[0]
    except OSError:
        pass
    try:
        ip = socket.gethostbyname(socket.gethostname())
        if not ip.startswith("127."):
            return ip
    except OSError:
        pass
    return "127.0.0.1"


def local_mac(ip: str) -> str | None:
    """MAC of the adapter that owns ``ip``; falls back to ``uuid.getnode`` when unsure."""
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return None
    if IS_WINDOWS:
        script = (
            f"$idx = (Get-NetIPAddress -AddressFamily IPv4 -IPAddress '{ip}' -ErrorAction SilentlyContinue | "
            "Select-Object -First 1).InterfaceIndex; "
            "if ($idx) { (Get-NetAdapter -InterfaceIndex $idx -ErrorAction SilentlyContinue).MacAddress }"
        )
        res = powershell(script, timeout=20)
        mac = normalize_mac(res.out.strip().splitlines()[0]) if res.ok and res.out.strip() else None
        if mac:
            return mac
    elif IS_LINUX:
        res = run_command(["ip", "-j", "addr"], timeout=10)
        if res.ok:
            try:
                for iface in json.loads(res.out):
                    for a in iface.get("addr_info", []):
                        if a.get("local") == ip:
                            mac = normalize_mac(iface.get("address"))
                            if mac:
                                return mac
            except (json.JSONDecodeError, AttributeError, TypeError):
                pass
    elif IS_MAC:
        res = run_command(["ifconfig"], timeout=10)
        if res.ok:
            block_mac = None
            for block in re.split(r"\n(?=\S)", res.out):
                m = re.search(r"ether\s+([0-9a-f:]{11,17})", block)
                block_mac = normalize_mac(m.group(1)) if m else None
                if f"inet {ip} " in block and block_mac:
                    return block_mac
    node = uuid.getnode()
    if (node >> 40) & 0x01:  # multicast bit set => uuid made one up
        return None
    return normalize_mac(f"{node:012x}")


def resolve_network(cfg: Any) -> ipaddress.IPv4Network:
    """The scan boundary. "auto" = the /24 of the default interface."""
    cidr = str(cfg_get(cfg, "network.cidr", "auto") or "auto").strip()
    me = local_ip()
    if cidr.lower() == "auto":
        return ipaddress.ip_network(f"{me}/24", strict=False)
    try:
        net = ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        logger.warning("network.cidr %r invalid; using auto /24", cidr)
        return ipaddress.ip_network(f"{me}/24", strict=False)
    if not isinstance(net, ipaddress.IPv4Network):
        logger.warning("network.cidr %r is not IPv4; using auto /24", cidr)
        return ipaddress.ip_network(f"{me}/24", strict=False)
    return net


def default_gateway(cfg: Any, network: ipaddress.IPv4Network) -> str | None:
    """Gateway IP from config or the OS routing table; only accepted when inside ``network``."""
    gw = str(cfg_get(cfg, "network.gateway", "auto") or "auto").strip()
    candidate: str | None = None
    if gw.lower() != "auto":
        candidate = gw
    elif IS_WINDOWS:
        res = powershell(GATEWAY_PS, timeout=20)
        candidate = res.out.strip().splitlines()[0].strip() if res.ok and res.out.strip() else None
    elif IS_LINUX:
        res = run_command(["ip", "-j", "route", "show", "default"], timeout=10)
        try:
            rows = json.loads(res.out) if res.ok else []
            candidate = next((r.get("gateway") for r in rows if r.get("gateway")), None)
        except (json.JSONDecodeError, AttributeError):
            candidate = None
    elif IS_MAC:
        res = run_command(["route", "-n", "get", "default"], timeout=10)
        m = re.search(r"gateway:\s*(\S+)", res.out) if res.ok else None
        candidate = m.group(1) if m else None
    if not candidate:
        return None
    try:
        addr = ipaddress.ip_address(candidate)
    except ValueError:
        return None
    return str(addr) if addr in network else None


# --------------------------------------------------------------------------- TCP sweep

def _connect(ip: str, port: int, timeout: float) -> str:
    """'open' | 'refused' (host alive) | 'none'."""
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return "open"
    except ConnectionRefusedError:
        return "refused"
    except (OSError, socket.timeout):
        return "none"


def sweep(
    network: ipaddress.IPv4Network,
    ports: Iterable[int],
    *,
    threads: int = 128,
    timeout: float = 0.4,
    exclude: Iterable[str] = (),
    max_seconds: float = SWEEP_MAX_SECONDS,
    progress: Callable[[str], None] | None = None,
) -> dict[str, dict[str, Any]]:
    """TCP-connect every (host, port) pair in ``network`` with a thread pool and a hard deadline.

    Returns ``{ip: {"open": [ports], "alive": bool}}`` for hosts that answered
    at all (SYN-ACK or RST).  A RST still proves the host is up, which is what
    matters for refreshing the neighbor table.
    """
    ports = [int(p) for p in ports]
    excluded = set(exclude)
    hosts = [str(h) for h in network.hosts() if str(h) not in excluded][:SWEEP_MAX_HOSTS]
    if network.num_addresses - 2 > SWEEP_MAX_HOSTS:
        logger.warning("sweep capped at %d of %d hosts in %s", SWEEP_MAX_HOSTS, network.num_addresses, network)
    deadline = time.monotonic() + max_seconds
    results: dict[str, dict[str, Any]] = {}
    if not hosts or not ports:
        return results

    def task(ip: str, port: int) -> tuple[str, int, str]:
        if time.monotonic() >= deadline:
            return ip, port, "skipped"
        return ip, port, _connect(ip, port, timeout)

    total = len(hosts) * len(ports)
    done = 0
    pool = cf.ThreadPoolExecutor(max_workers=max(1, min(int(threads), 512)))
    try:
        futures = [pool.submit(task, ip, port) for ip in hosts for port in ports]
        for fut in cf.as_completed(futures, timeout=max_seconds + 5):
            try:
                ip, port, verdict = fut.result()
            except Exception:  # pragma: no cover - task() swallows socket errors already
                continue
            done += 1
            if verdict in ("open", "refused"):
                entry = results.setdefault(ip, {"open": [], "alive": True})
                if verdict == "open":
                    entry["open"].append(port)
            if progress and done % 500 == 0:
                progress(f"sweep {done}/{total}")
            if time.monotonic() >= deadline:
                break
    except cf.TimeoutError:
        logger.warning("TCP sweep hit the %.0fs cap", max_seconds)
    finally:
        pool.shutdown(wait=False, cancel_futures=True)
    for entry in results.values():
        entry["open"].sort()
    return results


# --------------------------------------------------------------------------- names

def resolve_hostnames(ips: Iterable[str], timeout: float = HOSTNAME_TIMEOUT) -> dict[str, str]:
    """Reverse-DNS each IP in parallel, waiting ~1 s total; slow answers are simply dropped."""
    ips = list(dict.fromkeys(ips))
    if not ips:
        return {}
    pool = cf.ThreadPoolExecutor(max_workers=min(64, len(ips)))
    futures = {pool.submit(socket.gethostbyaddr, ip): ip for ip in ips}
    out: dict[str, str] = {}
    try:
        done, _ = cf.wait(futures, timeout=timeout + 0.5)
        for fut in done:
            try:
                name = fut.result()[0]
            except (OSError, socket.herror, socket.gaierror):
                continue
            if name and not name.replace(".", "").isdigit():
                out[futures[fut]] = name.rstrip(".")
    finally:
        pool.shutdown(wait=False, cancel_futures=True)
    return out


def kind_hint_from_mdns(service_types: Iterable[str]) -> str | None:
    types = [t.lower() for t in service_types]
    for kind, prefixes in _MDNS_KIND_HINTS:
        if any(t.startswith(p) for t in types for p in prefixes):
            return kind
    return None


def _probe_mdns(interface_ip: str) -> dict[str, dict[str, Any]]:
    try:
        from homesoc.scanners import mdns_ssdp
        return mdns_ssdp.probe(interface_ip, seconds=3.0)
    except Exception as exc:  # optional enrichment: never fail discovery over it
        logger.debug("mDNS/SSDP probe unavailable: %s", exc)
        return {}


def _lookup_vendor(mac: str) -> str | None:
    try:
        from homesoc.feeds import registry
    except Exception:
        return None
    try:
        return registry.lookup_vendor(mac)
    except Exception as exc:
        logger.debug("lookup_vendor failed for %s: %s", mac, exc)
        return None


# --------------------------------------------------------------------------- persistence

@dataclass
class _Seen:
    mac: str
    ip: str
    hostname: str | None
    vendor: str | None
    kind: str | None
    method: str
    mdns: dict[str, Any] | None = None
    is_self: bool = False


def _upsert_device(conn: "sqlite3.Connection", seen: _Seen, now: str) -> tuple[int, bool, bool]:
    """Insert or refresh one device row; returns (id, is_new, trusted)."""
    row = db.one(conn, "SELECT id, hostname, vendor, kind, trusted FROM devices WHERE mac = ?", (seen.mac,))
    mdns_json = json.dumps(seen.mdns, sort_keys=True) if seen.mdns else None
    if row is None:
        device_id = db.write(
            conn,
            "INSERT INTO devices(mac, ip, hostname, vendor, kind, first_seen, last_seen, online, mdns_services) "
            "VALUES (?,?,?,?,?,?,?,1,?)",
            (seen.mac, seen.ip, seen.hostname, seen.vendor, seen.kind, now, now, mdns_json),
        )
        is_new, trusted = True, False
    else:
        device_id = int(row["id"])
        trusted = bool(row["trusted"])
        # Only overwrite descriptive columns when we learned something new;
        # a failed reverse lookup must not erase a name we already know.
        db.write(
            conn,
            "UPDATE devices SET ip=?, hostname=COALESCE(?, hostname), vendor=COALESCE(?, vendor), "
            "kind=COALESCE(kind, ?), last_seen=?, online=1, mdns_services=COALESCE(?, mdns_services) WHERE id=?",
            (seen.ip, seen.hostname, seen.vendor, seen.kind, now, mdns_json, device_id),
        )
        is_new = False
    db.write(
        conn,
        "INSERT INTO device_sightings(device_id, ip, seen_at, method) VALUES (?,?,?,?)",
        (device_id, seen.ip, now, seen.method),
    )
    return device_id, is_new, trusted


def _retire_ip_keyed_duplicates(conn: "sqlite3.Connection", seen: list[_Seen]) -> None:
    """A host first seen without a MAC gets an ``ip:`` key; once ARP names it, park the placeholder."""
    claimed = {s.ip for s in seen if not s.mac.startswith(STALE_IP_KEY_PREFIX)}
    for ip in claimed:
        db.write(conn, "UPDATE devices SET online=0 WHERE mac=? AND online=1", (f"{STALE_IP_KEY_PREFIX}{ip}",))


def _mark_offline(conn: "sqlite3.Connection", interval_minutes: int, now_ts: float) -> None:
    from datetime import datetime, timezone

    cutoff = datetime.fromtimestamp(now_ts - 2 * 60 * max(1, int(interval_minutes)), tz=timezone.utc)
    cutoff_iso = cutoff.strftime("%Y-%m-%dT%H:%M:%S")
    db.write(conn, "UPDATE devices SET online=0 WHERE online=1 AND last_seen < ?", (cutoff_iso,))


def _stale_trusted(conn: "sqlite3.Connection", now_ts: float) -> list[FindingDraft]:
    from datetime import datetime, timezone

    cutoff = datetime.fromtimestamp(now_ts - OFFLINE_TRUSTED_DAYS * 86400, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")
    drafts = []
    for row in db.query(conn, "SELECT id, mac, ip, hostname, nickname, last_seen FROM devices WHERE trusted=1 AND last_seen < ?", (cutoff,)):
        drafts.append(FindingDraft(
            finding_id="NET-DEV-003", subject=f"device:{row['mac']}", device_id=int(row["id"]),
            evidence={"ip": row["ip"], "hostname": row["hostname"], "last_seen": row["last_seen"],
                      "name": row["nickname"] or row["hostname"] or row["ip"] or row["mac"],
                      "days": OFFLINE_TRUSTED_DAYS},
        ))
    return drafts


def _is_unusable_ip(ip: str) -> bool:
    """Loopback/link-local means no LAN route yet (Wi-Fi not associated at logon or after resume)."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return True
    return addr.is_loopback or addr.is_link_local or addr.is_unspecified


def _is_first_run(conn: "sqlite3.Connection") -> bool:
    row = db.one(conn, "SELECT COUNT(*) AS n FROM devices")
    return row is None or int(row["n"]) == 0


BASELINE_DETAIL = (
    "First inventory: this is the first time Home SOC has looked at your network, so everything it found is "
    "recorded as the starting point rather than reported as an intrusion. Skim the Devices page, name the ones "
    "you recognise and tick 'Trusted'; anything you cannot place is worth a closer look. From now on a device "
    "that was not in this baseline is reported as a real new-device finding. "
    "To accept the whole list in one go later, run: python -m homesoc baseline"
)


# --------------------------------------------------------------------------- run

def run(cfg: "Config", conn: "sqlite3.Connection", *, quick: bool = False,
        progress: Callable[[str], None] | None = None) -> ScanResult:
    """Discover LAN devices and upsert ``devices``/``device_sightings``.

    ``quick`` sweeps only the first four discovery ports so a dashboard-triggered
    refresh returns in a few seconds; the neighbor table still does the heavy
    lifting.  # SPEC-GAP: the spec does not define quick for discovery.
    """
    started = time.monotonic()
    started_ts = time.time()
    say = progress or (lambda _m: None)
    now = utcnow_iso()
    summary: dict[str, Any] = {"hosts_total": 0, "hosts_new": 0, "hosts_online": 0, "duration_sec": 0.0, "method": ""}
    findings: list[FindingDraft] = []
    error: str | None = None

    try:
        me = local_ip()
        if _is_unusable_ip(me):
            # Sweeping 127.0.0.0/24 would rewrite this host's own row to 127.0.0.1 and mark every
            # real device offline; report the outage instead and leave the inventory untouched.
            summary["method"] = "none"
            summary["duration_sec"] = round(time.monotonic() - started, 2)
            return ScanResult(kind="discovery", findings=[], summary=summary, error="no LAN interface (offline?)")
        network = resolve_network(cfg)
        baseline = _is_first_run(conn)
        exclude = {str(x) for x in (cfg_get(cfg, "network.exclude", []) or [])}
        ports = list(cfg_get(cfg, "network.discovery_ports", [80, 443, 22, 445, 139, 8080, 62078, 7000, 9100, 1900, 5353, 8443, 3389, 23, 21, 53]))
        if quick:
            ports = ports[:4]
        threads = int(cfg_get(cfg, "network.discovery_threads", 128))
        timeout = float(cfg_get(cfg, "network.discovery_timeout", 0.4))
        gateway = default_gateway(cfg, network)

        say(f"reading neighbor table for {network}")
        before = read_neighbors(network)
        say(f"sweeping {network} on {len(ports)} ports")
        swept = sweep(network, ports, threads=threads, timeout=timeout, exclude=exclude, progress=progress)
        after = read_neighbors(network)
        neighbors = {**before, **after}
        methods = []
        if neighbors:
            methods.append("arp")
        if swept:
            methods.append("tcp")
        summary["method"] = "+".join(methods) or "none"

        say("resolving names")
        candidate_ips = set(neighbors) | set(swept) | {me}
        candidate_ips = {ip for ip in candidate_ips if ipaddress.ip_address(ip) in network}
        names = resolve_hostnames(candidate_ips)
        mdns = _probe_mdns(me)

        seen: list[_Seen] = []
        for ip in sorted(candidate_ips, key=lambda s: ipaddress.ip_address(s)):
            is_self = ip == me
            if is_self:
                mac = local_mac(ip) or f"{STALE_IP_KEY_PREFIX}{ip}"
                method = "self"
            elif ip in neighbors:
                mac = neighbors[ip].mac
                method = "arp"
            else:
                mac = f"{STALE_IP_KEY_PREFIX}{ip}"
                method = "tcp"
            info = mdns.get(ip) or {}
            mdns_names = [n for n in info.get("names", []) if n]
            hostname = names.get(ip) or (mdns_names[0] if mdns_names else None)
            if is_self and not hostname:
                hostname = socket.gethostname()
            vendor = _lookup_vendor(mac) if not mac.startswith(STALE_IP_KEY_PREFIX) else None
            kind = kind_hint_from_mdns(info.get("mdns", []))
            if kind is None and gateway and ip == gateway:
                kind = "router"
            if kind is None and not mac.startswith(STALE_IP_KEY_PREFIX) and is_randomized_mac(mac):
                kind = "randomized"
            if is_self:
                kind = "self"
            seen.append(_Seen(mac=mac, ip=ip, hostname=hostname, vendor=vendor, kind=kind, method=method,
                              mdns=info or None, is_self=is_self))

        say(f"updating inventory ({len(seen)} hosts)")
        for s in seen:
            device_id, is_new, _trusted = _upsert_device(conn, s, now)
            if is_new:
                summary["hosts_new"] += 1
                if not s.is_self:
                    # SPEC-GAP: the very first discovery is a baseline — everything it finds is what the
                    # user already owns, so "new device" is informational instead of medium (17 devices
                    # would otherwise cost 68 points before any real problem is found) and carries the
                    # "first inventory" wording instead of the catalog's intruder rationale.
                    # A device cannot be new and trusted at the same time, so spec §6.1's "unless
                    # trusted" never bites here; trusting a device *later* closes this finding through
                    # findings.engine.trust_device (and `python -m homesoc baseline` does the lot).
                    findings.append(FindingDraft(
                        finding_id="NET-DEV-001", subject=f"device:{s.mac}", device_id=device_id,
                        severity="info" if baseline else None,
                        detail=BASELINE_DETAIL if baseline else None,
                        evidence={"ip": s.ip, "hostname": s.hostname, "vendor": s.vendor, "first_seen": now,
                                  "mac": s.mac, "method": s.method, "baseline": baseline},
                    ))
            if s.is_self or s.mac.startswith(STALE_IP_KEY_PREFIX):
                continue
            randomized = is_randomized_mac(s.mac)
            if s.vendor is None or randomized:
                findings.append(FindingDraft(
                    finding_id="NET-DEV-002", subject=f"device:{s.mac}", device_id=device_id,
                    evidence={"ip": s.ip, "hostname": s.hostname, "mac": s.mac,
                              "reason": "randomized_mac" if randomized else "unknown_vendor"},
                ))
        _retire_ip_keyed_duplicates(conn, seen)
        _mark_offline(conn, int(cfg_get(cfg, "schedule.discovery_minutes", 10)), started_ts)
        findings.extend(_stale_trusted(conn, started_ts))

        summary["hosts_online"] = len(seen)
        summary["baseline"] = baseline
        total_row = db.one(conn, "SELECT COUNT(*) AS n FROM devices")
        summary["hosts_total"] = int(total_row["n"]) if total_row is not None else len(seen)
        summary["network"] = str(network)
        summary["gateway"] = gateway
        try:
            db.record_metric(conn, "discovery.hosts_online", float(len(seen)))
        except Exception as exc:  # metrics are best-effort
            logger.debug("record_metric failed: %s", exc)
    except Exception as exc:  # expected failures become ScanResult.error, never a raise
        logger.exception("discovery failed")
        error = f"{type(exc).__name__}: {exc}"

    summary["duration_sec"] = round(time.monotonic() - started, 2)
    return ScanResult(kind="discovery", findings=findings, summary=summary, error=error)
