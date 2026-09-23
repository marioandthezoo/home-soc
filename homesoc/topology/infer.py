"""Where edges come from (SPEC addendum C2).

**The rule that shapes this whole module: Home SOC has no packet visibility.** LAN traffic
between two devices never passes through it, so it cannot know that the laptop is talking to
the NAS. Every function here therefore starts from something that was genuinely recorded — a
DNS query with a client address, an mDNS advertisement, an open port, a set of devices that
vanished in the same discovery cycle — and stops there.

The negative rule matters as much as the positive ones. A printer advertising ``_printer._tcp``
becomes a provider node with *no consumer edges at all*, because nothing in the database says
who prints. Sprouting an arrow to every device that might plausibly print would make a prettier
picture and a worthless one: the entire value of this feature is that the user can trust it.

Adding a real flow source later (C8)
------------------------------------
Every edge in the graph is produced by one of :data:`EDGE_SOURCES` and then funnelled through
:func:`merge_edges`, which keeps the *strongest* confidence for a given (src, dst, type). So a
future collector — conntrack from an OpenWrt router, an SNMP bridge table, a passive listener —
is a new entry in that list returning ``observed`` edges. It needs no new table, no new column
and no change to the graph, the API or the UI: the inferred gateway edge it confirms simply
becomes an observed one, and the edge that was never more than a guess gains a query count.
Register one with :func:`register_source`.
"""

from __future__ import annotations

import bisect
import ipaddress
import json
import logging
import re
import sqlite3
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from homesoc import config, db
from homesoc.topology.graph import (
    CONFIDENCE_RANK,
    INTERNET_ID,
    RESOLVER_ID,
    Edge,
    Node,
)
from homesoc.util import iso_ago, safe_one_line

logger = logging.getLogger(__name__)

#: Every name goes through util.safe_one_line before it is put in a label, a headline or a log
#: line: control, line-separator and bidi characters (RLO, LRI, U+061C, U+2028...) become a space
#: and invisible characters are removed. Nicknames are owner-supplied and legacy hostname rows
#: predate ingestion-time sanitising; both reach a terminal table, notifications and a JSON
#: payload. HTML escaping belongs to the web layer (double-escaping here would corrupt it).
MAX_LABEL = 48

#: How many cloud endpoints one device may contribute to the map. The map has to stay readable
#: at 25-40 nodes (C7); a chatty TV alone resolves hundreds of domains a day.
MAX_CLOUD_PER_DEVICE = 6
#: Below this many queries in the window, a domain is noise rather than a dependency.
MIN_CLOUD_QUERIES = 5

#: A consumer edge needs the co-drop to have happened in at least this many outages the
#: provider's device *triggered*, and in this fraction of them. Both are deliberately strict:
#: a wrong consumer edge is worse than a missing one, because it is the kind of mistake that
#: teaches a user the map cannot be trusted.
MIN_CONSUMER_OUTAGES = 2
MIN_CONSUMER_RATIO = 0.75


# ------------------------------------------------------------------- small helpers


def clean_text(value: Any, limit: int = MAX_LABEL) -> str:
    return safe_one_line(value or "").strip()[:limit].strip()


def display_name(row: Mapping[str, Any] | sqlite3.Row) -> str:
    """The name a person would use for a device: nickname, else hostname, else address."""
    get = row.__getitem__ if isinstance(row, sqlite3.Row) else row.get  # type: ignore[union-attr]
    for key in ("nickname", "hostname", "ip", "mac"):
        try:
            value = get(key)
        except (KeyError, IndexError):
            continue
        text = clean_text(value)
        if text:
            return text
    return "unknown device"


#: Public suffixes with two labels, so ``co.uk`` does not become the registrable domain.
_TWO_LEVEL_SUFFIXES: frozenset[str] = frozenset({
    "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk", "net.uk", "sch.uk",
    "com.au", "net.au", "org.au", "co.nz", "co.jp", "co.kr", "co.in", "co.za",
    "com.br", "com.mx", "com.cn", "com.tr", "com.sg", "com.hk", "com.tw",
})


#: What a DNS name may contain before it is treated as one: letters, digits, hyphen, underscore
#: (``_dmarc``, ``_tcp``) and dots — after IDNA, so every real name fits. 253 is the DNS limit.
_DOMAIN_CHARS = re.compile(r"[a-z0-9_.-]+")
MAX_DOMAIN = 253


def registrable_domain(name: str) -> str:
    """``www.eu.example.co.uk`` -> ``example.co.uk``; best effort, no public-suffix list.

    A local copy rather than an import from the DNS filter: the topology package must keep
    working with ``dnsfilter`` absent, and the cross-package import rules do not allow it.
    """
    text = str(name or "").strip().strip(".").lower()
    if len(text) > MAX_DOMAIN or not _DOMAIN_CHARS.fullmatch(text):
        # Not a hostname. The resolver logs whatever arrived in the question section, escaped
        # the way dnslib prints it ("\032", "<", "](") — and the qname is chosen by whoever
        # sent the packet, whose source address anyone on a flat LAN can forge. Such a name must
        # not become a cloud node, a map label or a finding's evidence under a household
        # device's name, so it is not a domain at all. IDNs arrive as their xn-- ASCII form.
        return ""
    labels = [p for p in text.split(".") if p]
    if len(labels) <= 2:
        return ".".join(labels)
    if ".".join(labels[-2:]) in _TWO_LEVEL_SUFFIXES and len(labels) >= 3:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


#: Registrable domain -> the name a person would recognise. Only entries that are unambiguous;
#: anything unknown keeps its domain as the label, which is honest and still readable.
VENDOR_LABELS: dict[str, str] = {
    "amazon.com": "Amazon", "amazonaws.com": "Amazon Web Services", "amazontrust.com": "Amazon",
    "apple.com": "Apple", "icloud.com": "Apple iCloud", "mzstatic.com": "Apple",
    "epson.com": "Epson", "github.com": "GitHub",
    "google.com": "Google", "googleapis.com": "Google", "gstatic.com": "Google", "youtube.com": "YouTube",
    "microsoft.com": "Microsoft", "office365.com": "Microsoft 365", "windowsupdate.com": "Windows Update",
    "netflix.com": "Netflix", "nflxvideo.net": "Netflix", "nintendo.net": "Nintendo",
    "ring.com": "Ring", "samsungqbe.com": "Samsung", "samsungcloudsolution.com": "Samsung",
    "sonos.com": "Sonos", "spotify.com": "Spotify", "whatsapp.net": "WhatsApp",
    "tuya.com": "Tuya", "tuyaus.com": "Tuya", "espressif.com": "Espressif",
}


def cloud_label(domain: str) -> str:
    return VENDOR_LABELS.get(domain, domain)


# ------------------------------------------------------------------ provider rules


@dataclass(frozen=True)
class Provider:
    """A service a device was *seen* offering — advertised over mDNS or listening on a port.

    ``label`` titles the node on the map; ``phrase`` is the same thing worded to sit inside a
    sentence ("3 devices lose printing"). They are separate fields rather than a lower()
    call because "DNS resolution" and "AirPlay" must not be flattened into "dns resolution"
    and "airplay" in a sentence a person reads.
    """

    device_id: int
    key: str
    label: str
    phrase: str
    protocol: str | None
    evidence: str

    @property
    def node_id(self) -> str:
        return f"provider:{self.device_id}:{self.key}"


#: mDNS service type -> (key, node label, sentence phrase, protocol). Only types whose meaning
#: is unambiguous: an advertisement Home SOC cannot read is not evidence of anything.
MDNS_PROVIDERS: dict[str, tuple[str, str, str, str]] = {
    "_printer._tcp": ("printing", "Printing", "printing", "lpd"),
    "_pdl-datastream._tcp": ("printing", "Printing", "printing", "raw"),
    "_ipp._tcp": ("printing", "Printing", "printing", "ipp"),
    "_ipps._tcp": ("printing", "Printing", "printing", "ipps"),
    "_scanner._tcp": ("scanning", "Scanning", "scanning", "mdns"),
    "_uscan._tcp": ("scanning", "Scanning", "scanning", "esclp"),
    "_uscans._tcp": ("scanning", "Scanning", "scanning", "esclp"),
    "_smb._tcp": ("file_sharing", "File sharing", "file sharing", "smb"),
    "_afpovertcp._tcp": ("file_sharing", "File sharing", "file sharing", "afp"),
    "_nfs._tcp": ("file_sharing", "File sharing", "file sharing", "nfs"),
    "_airplay._tcp": ("airplay", "AirPlay", "AirPlay", "airplay"),
    "_raop._tcp": ("airplay", "AirPlay audio", "AirPlay audio", "raop"),
    "_googlecast._tcp": ("cast", "Google Cast", "Google Cast", "cast"),
    "_spotify-connect._tcp": ("spotify", "Spotify Connect", "Spotify Connect", "spotify"),
    "_sonos._tcp": ("sonos", "Sonos playback", "Sonos playback", "sonos"),
    "_ssh._tcp": ("ssh", "SSH access", "SSH access", "ssh"),
    "_sftp-ssh._tcp": ("ssh", "SSH access", "SSH access", "sftp"),
    "_rfb._tcp": ("remote_desktop", "Remote desktop", "remote desktop", "vnc"),
}

#: (port, proto) -> (key, node label, sentence phrase, protocol). A listening port is weaker
#: evidence of intent than an advertisement, so the list is deliberately short and only holds
#: ports whose purpose is not in doubt.
PORT_PROVIDERS: dict[tuple[int, str], tuple[str, str, str, str]] = {
    (515, "tcp"): ("printing", "Printing", "printing", "lpd"),
    (631, "tcp"): ("printing", "Printing", "printing", "ipp"),
    (9100, "tcp"): ("printing", "Printing", "printing", "raw"),
    (445, "tcp"): ("file_sharing", "File sharing", "file sharing", "smb"),
    (548, "tcp"): ("file_sharing", "File sharing", "file sharing", "afp"),
    (2049, "tcp"): ("file_sharing", "File sharing", "file sharing", "nfs"),
    (53, "udp"): ("dns", "DNS resolution", "DNS resolution", "dns"),
    (53, "tcp"): ("dns", "DNS resolution", "DNS resolution", "dns"),
    (554, "tcp"): ("camera_stream", "Camera stream", "the camera stream", "rtsp"),
    (3389, "tcp"): ("remote_desktop", "Remote desktop", "remote desktop", "rdp"),
    (5900, "tcp"): ("remote_desktop", "Remote desktop", "remote desktop", "vnc"),
    (1883, "tcp"): ("mqtt", "MQTT messaging", "MQTT messaging", "mqtt"),
    (8883, "tcp"): ("mqtt", "MQTT messaging", "MQTT messaging", "mqtts"),
}

#: mDNS types that mean "this is a bridge to devices Home SOC cannot see". An advertisement is
#: the device saying so itself, which is the only hub signal strong enough to be ``observed``.
HUB_MDNS: frozenset[str] = frozenset({"_hap._tcp", "_hue._tcp", "_matter._tcp", "_matterc._udp", "_zigbee._tcp"})
#: Name fragments that *suggest* a hub. Far weaker: a vendor string and a hostname are not
#: evidence of a broadcast, and a whole invisible dependency tree must not be asserted from one.
HUB_NAME_HINTS: tuple[str, ...] = (
    "hue", "bridge", "smartthings", "hubitat", "deconz", "conbee", "zigbee", "zwave", "z-wave",
    "aqara", "lutron", "caseta", "homey", "bond", "harmony hub",
)
#: Whole words only. A bare substring match declared a Cambridge Audio streamer a Zigbee hub,
#: because "Cambridge" contains "bridge" — and then printed, as something Home SOC had observed,
#: that the streamer controls devices it cannot see. "Bondi" and "Huerta" did the same.
_HUB_NAME_RE = re.compile(
    r"(?<![a-z0-9])(?:" + "|".join(re.escape(h) for h in HUB_NAME_HINTS) + r")(?![a-z0-9])",
    re.IGNORECASE,
)


def mdns_types(row: Mapping[str, Any] | sqlite3.Row) -> list[str]:
    """The mDNS service types recorded for a device, whatever shape discovery stored them in."""
    try:
        raw = row["mdns_services"]
    except (KeyError, IndexError, TypeError):
        return []
    if not raw:
        return []
    try:
        data = json.loads(raw) if isinstance(raw, (str, bytes)) else raw
    except (TypeError, ValueError):
        return []
    found: list[str] = []
    if isinstance(data, dict):  # discovery stores {"mdns": [...], "ssdp": [...]}
        data = data.get("mdns") or []
    if isinstance(data, (list, tuple)):
        for item in data:
            text = str(item or "").strip().lower().rstrip(".")
            text = text.replace(".local", "")
            if text:
                found.append(text)
    return sorted(set(found))


#: What a hub node may claim, by how it was established. The two are not interchangeable:
#: ``observed`` asserts a broadcast Home SOC received, ``assumed`` asserts only that a name
#: looks like one — and a hub node carries the statement that an entire invisible dependency
#: tree hangs off this box, which is far too large a claim to make from a vendor string.
HUB_EVIDENCE: dict[str, str] = {
    "observed": "advertises itself as a bridge or hub",
    "assumed": "its vendor or hostname suggests a hub; nothing it advertised confirms it",
}


def hub_signal(row: Mapping[str, Any] | sqlite3.Row) -> str | None:
    """``"observed"``, ``"assumed"`` or None — how strongly this device looks like a hub.

    Never accompanied by a child count either way: the devices behind a Zigbee/Z-Wave/Thread/
    Bluetooth hub are not on the IP network, so Home SOC cannot see them, cannot count them and
    must not imply that it can.
    """
    if set(mdns_types(row)) & HUB_MDNS:
        return "observed"
    haystack = " ".join(str(row[k] or "") for k in ("hostname", "nickname", "vendor"))
    return "assumed" if _HUB_NAME_RE.search(haystack) else None


def is_hub(row: Mapping[str, Any] | sqlite3.Row) -> bool:
    """True when anything at all suggests this device bridges a non-IP network.

    Use :func:`hub_signal` wherever the *strength* of that suggestion is going to be shown to a
    person; this predicate exists for the places that only need to know a hub note belongs on
    the picture at all.
    """
    return hub_signal(row) is not None


def hub_device_ids(conn: sqlite3.Connection) -> set[int]:
    rows = db.query(conn, "SELECT id, hostname, nickname, vendor, mdns_services FROM devices")
    return {int(r["id"]) for r in rows if is_hub(r)}


def providers(conn: sqlite3.Connection) -> list[Provider]:
    """Every service a device was seen offering, deduplicated per (device, service).

    Both evidence kinds are recorded in the sentence, because "advertises _ipp._tcp and listens
    on tcp/631" is a stronger claim than either alone.
    """
    found: dict[tuple[int, str], dict[str, Any]] = {}

    def add(device_id: int, rule: tuple[str, str, str, str], evidence: str) -> None:
        key, label, phrase, protocol = rule
        entry = found.setdefault((device_id, key), {"label": label, "phrase": phrase,
                                                    "protocols": set(), "evidence": []})
        entry["protocols"].add(protocol)
        if evidence not in entry["evidence"]:
            entry["evidence"].append(evidence)

    for row in db.query(conn, "SELECT id, mdns_services FROM devices ORDER BY id"):
        for service_type in mdns_types(row):
            rule = MDNS_PROVIDERS.get(service_type)
            if rule is not None:
                add(int(row["id"]), rule, f"advertises {service_type}")

    for row in db.query(
        conn,
        "SELECT device_id, port, proto, name FROM services WHERE state = 'open' ORDER BY device_id, port, proto",
    ):
        rule = PORT_PROVIDERS.get((int(row["port"]), str(row["proto"] or "tcp").lower()))
        if rule is not None:
            add(int(row["device_id"]), rule, f"listens on {row['proto']}/{int(row['port'])}")

    out: list[Provider] = []
    for (device_id, key), entry in sorted(found.items()):
        out.append(Provider(
            device_id=device_id,
            key=key,
            label=str(entry["label"]),
            phrase=str(entry["phrase"]),
            protocol=sorted(entry["protocols"])[0] if entry["protocols"] else None,
            evidence=" and ".join(entry["evidence"]),
        ))
    return out


# ---------------------------------------------------------------- shared context


@dataclass(frozen=True)
class InferenceContext:
    """Everything the edge sources need, resolved once so they all agree with each other."""

    hours: int
    include_cloud: bool
    since: str
    gateway_device_id: int | None
    gateway_confidence: str
    #: Who holds each address *now*. Never use it to attribute a timestamped row — see
    #: :attr:`address_owners`, which knows who held it at the time.
    device_ips: Mapping[str, int]
    address_owners: "AddressOwners"
    device_rows: Sequence[sqlite3.Row]
    providers: Sequence[Provider]
    resolver_present: bool
    resolver_label: str
    dns_enabled: bool
    #: trigger device id -> {member device id: how many of that device's outages it dropped in}
    outage_triggers: Mapping[int, Mapping[int, int]] = field(default_factory=dict)
    #: trigger device id -> how many recorded outages it triggered
    outage_trigger_counts: Mapping[int, int] = field(default_factory=dict)


def gateway_device(conn: sqlite3.Connection, cfg: config.Config | None = None) -> tuple[sqlite3.Row | None, str]:
    """The device acting as the default gateway, and how confident we are that it is.

    ``inferred`` when a device's address matches the gateway the OS routing table (or the
    config) names — that is the network's shape, not a guess. ``assumed`` when no route data is
    available and the only clue is that a device calls itself a router, which is exactly the
    C2 definition of an assumption.
    """
    rows = db.query(conn, "SELECT id, mac, ip, hostname, nickname, vendor, kind, online FROM devices ORDER BY id")
    configured = ""
    try:
        cfg = cfg or config.load(conn)
        raw = str(cfg.network.gateway or "auto").strip()
        # "auto" would go and read the live routing table of *this* machine. That is right for a
        # scan and wrong for a graph built from stored rows (tests, a copied database, a machine
        # on another network), so the stored override is preferred and auto only falls through
        # to the kind heuristic below.
        configured = raw if raw.lower() != "auto" else ""
    except Exception as exc:  # a broken config must not take the map down
        logger.debug("cannot read network.gateway: %s", exc)
    if not configured:
        configured = str(db.get_setting(conn, "network.gateway", "") or "").strip()
    if configured and configured.lower() != "auto":
        for row in rows:
            if str(row["ip"] or "") == configured:
                return row, "inferred"
    for row in rows:
        if str(row["kind"] or "").lower() in ("router", "gateway"):
            return row, "assumed"
    return None, "assumed"


@dataclass(frozen=True)
class AddressOwners:
    """Who held which address, *when* — so a query is attributed to the device that made it.

    DHCP recycles leases. A tablet gives up 192.168.1.50 on Monday and a camera takes it on
    Tuesday; a flat ``{address: device}`` map then hands the tablet's whole week of lookups to
    the camera, at ``observed`` confidence, with an evidence sentence — and the device that
    actually made them gets no edge at all. That is an invented dependency on the map and one
    household member's browsing history moved onto another person's device card.

    So ownership is an interval, not a fact: each sighting owns the address from its timestamp
    until the next sighting of that address by a *different* device. A query outside every
    interval, or inside one that cannot be told apart, is dropped. A missing edge is the
    documented preference over a wrong one.
    """

    #: address -> ascending [(first sighting, last sighting, device id)] within the window
    spans: Mapping[str, Sequence[tuple[str, str, int]]]
    #: address -> device that holds it now; the answer when no sighting covers the address
    current: Mapping[str, int]
    #: address -> (runs overlap?, ascending first-sighting stamps). Filled on first use, so an
    #: address that many identities have held costs one pass rather than one per query row —
    #: the per-row rescan was O(rows x holders), and MAC churn on one address controls both.
    _index: dict[str, tuple[bool, list[str]]] = field(default_factory=dict, repr=False, compare=False)

    def owner_at(self, address: str, ts: str) -> int | None:
        runs = self.spans.get(address)
        if not runs:
            return self.current.get(address)
        if len(runs) == 1:
            return runs[0][2]
        cached = self._index.get(address)
        if cached is None:
            cached = (_overlapping(runs), [run[0] for run in runs])
            self._index[address] = cached
        overlapping, starts = cached
        if overlapping:
            # Two devices answered on this address in interleaved sweeps. Which one made a given
            # query cannot be recovered, so nothing is claimed for it.
            return None
        # Sequential leases: each holder owns the address from its first sighting until the next
        # holder's first sighting, so a query in the gap after a device stopped answering still
        # belongs to it rather than to nobody.
        position = bisect.bisect_right(starts, ts)
        if position == 0:
            return None  # earlier than every sighting, and more than one device has held it
        return runs[position - 1][2]

    def holders(self, address: str) -> set[int]:
        return {device_id for _f, _t, device_id in self.spans.get(address, ())}


def _overlapping(runs: Sequence[tuple[str, str, int]]) -> bool:
    return any(runs[i][1] >= runs[i + 1][0] for i in range(len(runs) - 1))


def _address_owners(conn: sqlite3.Connection, since: str) -> AddressOwners:
    """Build the per-address ownership timeline from ``device_sightings``."""
    spans: dict[str, list[tuple[str, str, int]]] = {}
    for row in db.query(
        conn,
        "SELECT device_id, ip, MIN(seen_at) AS from_at, MAX(seen_at) AS to_at FROM device_sightings "
        "WHERE seen_at >= ? AND ip IS NOT NULL AND ip != '' GROUP BY ip, device_id ORDER BY ip, from_at",
        (since,),
    ):
        spans.setdefault(str(row["ip"]), []).append(
            (str(row["from_at"]), str(row["to_at"]), int(row["device_id"])))
    for runs in spans.values():
        runs.sort()
    current = {
        str(row["ip"]): int(row["id"])
        for row in db.query(conn, "SELECT id, ip FROM devices WHERE ip IS NOT NULL AND ip != '' ORDER BY id")
    }
    return AddressOwners(spans=spans, current=current)


def _device_ip_map(conn: sqlite3.Connection, since: str) -> dict[str, int]:
    """Address -> the device that holds it *now*.

    Kept for callers that genuinely mean "who is at this address today". Anything attributing a
    timestamped row must use :class:`AddressOwners` instead: this map cannot tell Tuesday's
    holder of a recycled lease from today's, and using it for DNS was how a guest laptop
    acquired a doorbell's cloud dependencies.
    """
    owners = _address_owners(conn, since)
    out: dict[str, int] = {address: runs[-1][2] for address, runs in owners.spans.items() if runs}
    out.update(owners.current)
    return out


def build_context(conn: sqlite3.Connection, *, hours: int, include_cloud: bool) -> InferenceContext:
    from homesoc.topology import outages as outages_mod

    since = iso_ago(hours=max(1, int(hours)))
    rows = db.query(conn, "SELECT id, mac, ip, hostname, nickname, vendor, kind, online, mdns_services "
                          "FROM devices ORDER BY id")
    gateway, gateway_confidence = gateway_device(conn)
    dns_enabled = str(db.get_setting(conn, "dns.enabled", "") or "").lower() in ("1", "true", "yes", "on")
    queries = db.one(conn, "SELECT COUNT(*) AS n FROM dns_queries WHERE ts >= ?", (since,))
    has_queries = bool(queries and int(queries["n"]))
    owners = _address_owners(conn, since)
    return InferenceContext(
        hours=int(hours),
        include_cloud=bool(include_cloud),
        since=since,
        gateway_device_id=int(gateway["id"]) if gateway is not None else None,
        gateway_confidence=gateway_confidence,
        device_ips={**{a: r[-1][2] for a, r in owners.spans.items() if r}, **owners.current},
        address_owners=owners,
        device_rows=rows,
        providers=tuple(providers(conn)),
        resolver_present=has_queries or dns_enabled,
        resolver_label="Home SOC DNS filter",
        dns_enabled=dns_enabled,
        # Gateway outages are excluded on both sides: they explain every device's absence by
        # themselves, so they are no evidence at all about who uses which service.
        outage_triggers=outages_mod.trigger_members(conn, exclude_gateway=True),
        outage_trigger_counts=outages_mod.trigger_counts(conn, exclude_gateway=True),
    )


# ------------------------------------------------------------------ edge sources


def gateway_edges(conn: sqlite3.Connection, ctx: InferenceContext) -> list[Edge]:
    """C2.1 — every device on the gateway's own subnet depends on the gateway.

    "On the subnet" is now actually checked. It used to mean "has a parseable address that is
    not loopback", so a guest-VLAN device at 192.168.2.x, or a stale public address left on a
    row, was drawn depending on the 192.168.1.1 gateway under the sentence "the default route
    for this subnet" — asserting a shared subnet nothing had looked at. Those devices now get
    no gateway edge: Home SOC does not know how they reach the internet, and saying so is the
    whole point.
    """
    if ctx.gateway_device_id is None:
        return []
    target = f"device:{ctx.gateway_device_id}"
    evidence = ("the default route for this subnet" if ctx.gateway_confidence == "inferred"
                else "the only device on this subnet that identifies itself as a router")
    subnet = _gateway_subnet(conn, ctx)
    out: list[Edge] = []
    for row in ctx.device_rows:
        device_id = int(row["id"])
        if device_id == ctx.gateway_device_id:
            continue
        if not _shares_subnet(str(row["ip"] or ""), subnet):
            continue
        out.append(Edge(f"device:{device_id}", target, "gateway", None, ctx.gateway_confidence, evidence, 0))
    return out


def _gateway_subnet(conn: sqlite3.Connection, ctx: InferenceContext) -> ipaddress.IPv4Network | ipaddress.IPv6Network | None:
    """The network the gateway is on: ``network.cidr`` when configured, else its own /24.

    None when neither can be established, in which case :func:`_shares_subnet` falls back to the
    old "is it a usable address" test rather than emptying the map on an odd install.
    """
    configured = str(db.get_setting(conn, "network.cidr", "") or "").strip()
    if not configured:
        try:
            configured = str(config.load(conn).network.cidr or "").strip()
        except Exception as exc:  # a broken config must not take the map down
            logger.debug("cannot read network.cidr: %s", exc)
    # "auto" reads *this* machine's live interface, which is right for a scan and wrong for a
    # graph built from stored rows (a copied database, a test, another network) — so it falls
    # through to the gateway's own address instead.
    if configured and configured.lower() != "auto":
        try:
            return ipaddress.ip_network(configured, strict=False)
        except ValueError as exc:
            logger.debug("network.cidr %r is not a network: %s", configured, exc)
    row = next((r for r in ctx.device_rows if int(r["id"]) == ctx.gateway_device_id), None)
    try:
        address = ipaddress.ip_address(str(row["ip"] or "")) if row is not None else None
    except ValueError:
        address = None
    if address is None:
        return None
    prefix = 24 if address.version == 4 else 64
    return ipaddress.ip_network(f"{address}/{prefix}", strict=False)


def _shares_subnet(ip: str, subnet: ipaddress.IPv4Network | ipaddress.IPv6Network | None) -> bool:
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if address.is_loopback or address.is_unspecified or address.is_multicast:
        return False
    if subnet is None:
        return True
    return address.version == subnet.version and address in subnet


def internet_edges(conn: sqlite3.Connection, ctx: InferenceContext) -> list[Edge]:
    """C2.2 — the gateway is the way off the LAN, and the resolver forwards through it."""
    out: list[Edge] = []
    if ctx.gateway_device_id is not None:
        out.append(Edge(f"device:{ctx.gateway_device_id}", INTERNET_ID, "internet", None, "inferred",
                        "devices reach the internet only through the gateway", 0))
    if ctx.resolver_present:
        out.append(Edge(RESOLVER_ID, INTERNET_ID, "internet", "dns", "inferred",
                        "the resolver forwards anything it cannot answer to its upstreams", 0))
    return out


def dns_edges(conn: sqlite3.Connection, ctx: InferenceContext) -> list[Edge]:
    """C2.3 — a device that appears as a ``dns_queries.client`` depends on the resolver.

    The second half of C2.3 ("a device that does not appear but sits on a subnet whose DHCP
    hands out the resolver") is deliberately **not** emitted. Home SOC does not read DHCP
    options, so that precondition can never be established here, and a device with no queries
    at all is far more likely to be using a different resolver — which is what NET-DNS-001
    already reports. Inventing the edge would contradict C1. A future source that *can* read
    the DHCP lease file registers itself in EDGE_SOURCES and the edge appears with the
    confidence its evidence deserves.
    """
    if not ctx.resolver_present:
        return []
    counts: dict[int, int] = {}
    for client, bucket, n in _client_buckets(conn, ctx.since):
        device_id = ctx.address_owners.owner_at(client, bucket)
        if device_id is None:
            continue
        counts[device_id] = counts.get(device_id, 0) + n
    window = _window_words(ctx.hours)
    return [
        Edge(f"device:{device_id}", RESOLVER_ID, "dns", "dns", "observed",
             f"{count} DNS quer{'y' if count == 1 else 'ies'} in the last {window}", count)
        for device_id, count in sorted(counts.items())
    ]


#: Queries are resolved against the lease timeline one hour at a time. Per-query would be exact
#: and would read every row of a 200k-row table into Python; per-hour keeps the aggregate in
#: SQLite and is far finer than a DHCP lease, which is measured in hours or days.
_BUCKET_CHARS = len("2026-09-13T21")


def _client_buckets(conn: sqlite3.Connection, since: str) -> list[tuple[str, str, int]]:
    """``(client address, hour bucket, how many queries)`` — the unit attribution works in."""
    return [
        (str(r["client"]), str(r["bucket"]), int(r["n"]))
        for r in db.query(
            conn,
            f"SELECT client, substr(ts, 1, {_BUCKET_CHARS}) AS bucket, COUNT(*) AS n FROM dns_queries "
            "WHERE ts >= ? GROUP BY client, bucket ORDER BY client, bucket",
            (since,),
        )
    ]


def cloud_edges(conn: sqlite3.Connection, ctx: InferenceContext) -> list[Edge]:
    """C2.4 — external endpoints a device actually asked for, grouped by registrable domain.

    Blocked domains are recorded as ``cloud_blocked`` rather than as a dependency: a camera
    hammering a telemetry endpoint the filter refuses is worth seeing, but it is not something
    the camera depends on, and drawing it as one would be a lie in the user's favour.
    """
    if not ctx.include_cloud:
        return []
    rows = db.query(
        conn,
        f"SELECT client, substr(ts, 1, {_BUCKET_CHARS}) AS bucket, qname, action, COUNT(*) AS n "
        "FROM dns_queries WHERE ts >= ? GROUP BY client, bucket, qname, action "
        "ORDER BY client, bucket, qname, action",
        (ctx.since,),
    )
    tally: dict[tuple[int, str], dict[str, int]] = {}
    for row in rows:
        # Attributed by *when*, not by who holds the address today (see AddressOwners).
        device_id = ctx.address_owners.owner_at(str(row["client"]), str(row["bucket"]))
        if device_id is None:
            continue
        domain = registrable_domain(str(row["qname"]))
        if not domain or "." not in domain:
            continue
        bucket = tally.setdefault((device_id, domain), {"allowed": 0, "blocked": 0})
        action = str(row["action"] or "")
        if action == "block":
            bucket["blocked"] += int(row["n"])
        elif action in ("allow", "cache"):
            bucket["allowed"] += int(row["n"])

    per_device: dict[int, list[tuple[str, dict[str, int]]]] = {}
    for (device_id, domain), counts in tally.items():
        per_device.setdefault(device_id, []).append((domain, counts))

    out: list[Edge] = []
    window = _window_words(ctx.hours)
    for device_id in sorted(per_device):
        entries = per_device[device_id]
        entries.sort(key=lambda item: (-(item[1]["allowed"] + item[1]["blocked"]), item[0]))
        for domain, counts in entries[:MAX_CLOUD_PER_DEVICE]:
            total = counts["allowed"] + counts["blocked"]
            if total < MIN_CLOUD_QUERIES:
                continue
            if counts["allowed"]:
                # A registrable domain can be partly answered and partly refused: the demo
                # camera's vendor domain is answered 81 times for firmware, NTP and its device
                # gateway, and refused 46 times for `telemetry-collect.` under the same name.
                # Reporting only the 81 dropped the largest refusal on the device into a row
                # labelled OBSERVED dependency, where the Lens card's "asked for, but blocked"
                # list — the list that exists so refusals do not read as dependencies — could
                # not show it. The refusals do not make this a dependency and they do not get
                # their own row; they are stated on the row they actually belong to.
                evidence = f"{counts['allowed']} lookups answered in the last {window}"
                if counts["blocked"]:
                    evidence += (
                        f"; {counts['blocked']} more under the same name refused "
                        "— asked for, not depended on"
                    )
                out.append(Edge(f"device:{device_id}", f"cloud:{domain}", "cloud", "dns", "observed",
                                evidence, counts["allowed"]))
            else:
                out.append(Edge(f"device:{device_id}", f"cloud:{domain}", "cloud_blocked", "dns", "observed",
                                f"{counts['blocked']} lookups in the last {window}, all blocked by the DNS filter "
                                "— asked for, not depended on", counts["blocked"]))
    return out


def provider_edges(conn: sqlite3.Connection, ctx: InferenceContext) -> list[Edge]:
    """C2.5 (first half) — a service runs on the device that offers it.

    Note the direction: ``provider -> device``. The service depends on the box; the box does
    not depend on the service it offers.
    """
    out = [
        Edge(p.node_id, f"device:{p.device_id}", "hosted_by", p.protocol, "observed", p.evidence, 0)
        for p in ctx.providers
    ]
    for row in ctx.device_rows:
        signal = hub_signal(row)
        if signal is not None:
            out.append(Edge(f"provider:{int(row['id'])}:hub", f"device:{int(row['id'])}", "hosted_by",
                            None, signal, HUB_EVIDENCE[signal], 0))
    return out


def consumer_edges(conn: sqlite3.Connection, ctx: InferenceContext) -> list[Edge]:
    """C2.5 (the half that matters) — a consumer edge only ever comes from real evidence.

    The three kinds C2 allows are an mDNS *query* for the service name, a UPnP subscription, and
    co-dropping in a recorded outage. Home SOC records none of the first two today — its mDNS
    probe collects advertisements, not queries — so the only source available is the third, and
    even that is narrowed: the co-drop is only counted for outages **this device triggered**.
    A device that went down in the same cycle as the printer during a router outage tells us
    nothing whatsoever about printing.

    The practical consequence, and the point of the whole feature: a printer nobody has been
    seen to use produces a provider node and zero consumer edges.

    **One co-drop is one bit of information, and it buys exactly one edge.** A NAS that offers
    SMB, SSH, AirPlay and printing used to turn a single shared outage into four confident
    "the doorbell uses AirPlay on the NAS" claims — the co-drop cannot distinguish between
    services, so three of those four were invented and the fourth was a coin toss. So:

    * the device offers exactly one service — the edge names it, because there is nothing else
      it could have been;
    * the device offers several — one edge to the *device*, naming no service, because which
      one (if any) was involved is precisely what is not known.

    Either way the evidence sentence says what was actually seen: these two went dark in the
    same sweep. It does not say this device "triggered" anything. Nothing establishes causal
    order — ``outages._classify_trigger`` picks the infrastructure box out of the member list,
    which a tripped power strip satisfies just as well — and a sentence claiming otherwise
    would be the invented relationship this whole module exists to refuse.
    """
    out: list[Edge] = []
    by_device: dict[int, list[Provider]] = {}
    for provider in ctx.providers:
        by_device.setdefault(provider.device_id, []).append(provider)
    for device_id in sorted(by_device):
        together = dict(ctx.outage_triggers.get(device_id) or {})
        outage_count = int(ctx.outage_trigger_counts.get(device_id, 0))
        if outage_count < MIN_CONSUMER_OUTAGES:
            continue
        offered = sorted(by_device[device_id], key=lambda p: p.key)
        only = offered[0] if len(offered) == 1 else None
        for other_id in sorted(together):
            hits = int(together[other_id])
            if other_id == device_id or hits < MIN_CONSUMER_OUTAGES:
                continue
            if hits / outage_count < MIN_CONSUMER_RATIO:
                continue
            seen = (f"went offline in the same discovery cycle as this device in {hits} of "
                    f"{outage_count} recorded outages")
            if only is not None:
                out.append(Edge(
                    f"device:{other_id}", only.node_id, "uses", only.protocol, "observed",
                    f"{seen}; {only.phrase} is the only service this device offers", hits,
                ))
            else:
                out.append(Edge(
                    f"device:{other_id}", f"device:{device_id}", "uses", None, "observed",
                    f"{seen}; which of the {len(offered)} services it offers was involved, if any, "
                    "is not known — they may simply share power or a switch", hits,
                ))
    return out


def _window_words(hours: int) -> str:
    hours = max(1, int(hours))
    if hours < 48:
        return f"{hours} hours"
    days = hours // 24
    return f"{days} days" if days != 7 else "7 days"


#: The edge sources, run in order. A future flow collector (C8) appends itself here with
#: :func:`register_source` and needs nothing else: merge_edges folds its observed edges into
#: whatever is already there, raising confidence instead of duplicating structure.
EdgeSource = Callable[[sqlite3.Connection, InferenceContext], list[Edge]]
EDGE_SOURCES: list[tuple[str, EdgeSource]] = [
    ("gateway", gateway_edges),
    ("internet", internet_edges),
    ("dns", dns_edges),
    ("cloud", cloud_edges),
    ("providers", provider_edges),
    ("consumers", consumer_edges),
]


def register_source(name: str, source: EdgeSource) -> None:
    """Add an evidence source. Replaces an existing one with the same name (idempotent)."""
    global EDGE_SOURCES
    EDGE_SOURCES = [(n, s) for n, s in EDGE_SOURCES if n != name] + [(name, source)]


def merge_edges(edges: Iterable[Edge]) -> list[Edge]:
    """Fold edges sharing (src, dst, type) into one, keeping the strongest claim.

    This is the single funnel C8 depends on. When a flow collector confirms an edge Home SOC
    had only inferred, the merged edge becomes ``observed`` and keeps the collector's count and
    protocol — the graph, the API, the map and the blast radius all change without a line of
    code anywhere else.
    """
    merged: dict[tuple[str, str, str], Edge] = {}
    order: list[tuple[str, str, str]] = []
    for edge in edges:
        key = edge.key
        current = merged.get(key)
        if current is None:
            merged[key] = edge
            order.append(key)
            continue
        stronger = CONFIDENCE_RANK.get(edge.confidence, 0) > CONFIDENCE_RANK.get(current.confidence, 0)
        evidence = current.evidence if edge.evidence == current.evidence else "; ".join(
            part for part in ((edge.evidence, current.evidence) if stronger else (current.evidence, edge.evidence))
            if part
        )
        merged[key] = Edge(
            src=key[0], dst=key[1], edge_type=key[2],
            protocol=(edge.protocol if stronger else current.protocol) or current.protocol or edge.protocol,
            confidence=edge.confidence if stronger else current.confidence,
            evidence=evidence,
            observed_count=max(int(current.observed_count), int(edge.observed_count)),
        )
    return [merged[key] for key in order]


# ----------------------------------------------------------------------- result


@dataclass(frozen=True)
class InferenceResult:
    nodes: list[Node]
    edges: list[Edge]
    summary: dict[str, Any]


def infer_all(conn: sqlite3.Connection, *, hours: int = 168, include_cloud: bool = True) -> InferenceResult:
    """Run every edge source and build the non-device nodes the edges point at."""
    ctx = build_context(conn, hours=hours, include_cloud=include_cloud)
    raw: list[Edge] = []
    per_source: dict[str, int] = {}
    for name, source in EDGE_SOURCES:
        try:
            produced = list(source(conn, ctx))
        except Exception as exc:  # one broken source must not cost the whole map
            logger.exception("topology edge source %s failed", name)
            per_source[name] = -1
            del exc
            continue
        per_source[name] = len(produced)
        raw.extend(produced)
    edges = merge_edges(raw)
    nodes = _support_nodes(conn, ctx, edges)
    summary = {
        "edges": len(edges),
        "by_source": per_source,
        "providers": len(ctx.providers),
        "gateway_device_id": ctx.gateway_device_id,
        "window_hours": ctx.hours,
    }
    return InferenceResult(nodes=nodes, edges=edges, summary=summary)


def _support_nodes(conn: sqlite3.Connection, ctx: InferenceContext, edges: list[Edge]) -> list[Node]:
    """Every node that is not a device: internet, resolver, providers, cloud endpoints."""
    from homesoc.topology.graph import _dependent_counts

    names = {int(r["id"]): display_name(r) for r in ctx.device_rows}
    consumers: dict[str, int] = {}
    for edge in edges:
        if edge.edge_type == "uses":
            consumers[edge.dst] = consumers.get(edge.dst, 0) + 1
    dependents_of: dict[str, int] = {}
    for edge in edges:
        dependents_of[edge.dst] = dependents_of.get(edge.dst, 0) + 1
    # ``Node.criticality`` has one meaning across every kind of node: how many *devices* depend
    # on it, directly or through something else — which is what the map's legend promises when
    # it says bigger means more depends on it. Using the raw inbound-edge tally here instead
    # drew the internet, the node every device in the house depends on, at the smallest radius,
    # because only the gateway and the resolver point at it directly.
    reach = _dependent_counts(edges)

    nodes: list[Node] = []
    if any(e.dst == INTERNET_ID for e in edges):
        nodes.append(Node(INTERNET_ID, "internet", "The internet", "everything beyond the router",
                          None, reach.get(INTERNET_ID, 0), None, True))
    if ctx.resolver_present:
        users = sum(1 for e in edges if e.edge_type == "dns")
        nodes.append(Node(RESOLVER_ID, "resolver", ctx.resolver_label,
                          f"{users} device{'s' if users != 1 else ''} seen using it",
                          None, reach.get(RESOLVER_ID, users), None, True))

    for provider in ctx.providers:
        count = consumers.get(provider.node_id, 0)
        nodes.append(Node(
            provider.node_id, "provider", provider.label,
            f"on {names.get(provider.device_id, 'a device')} — "
            + (f"{count} confirmed consumer{'s' if count != 1 else ''}" if count else "no confirmed consumers"),
            provider.device_id, count, None, True,
        ))
    for row in ctx.device_rows:
        signal = hub_signal(row)
        if signal is None:
            continue
        device_id = int(row["id"])
        nodes.append(Node(
            f"provider:{device_id}:hub", "provider",
            "Hub (Zigbee / Z-Wave / Thread)" if signal == "observed" else "Possible hub",
            f"on {names.get(device_id, 'a device')} — "
            + ("devices behind it are invisible to Home SOC, so how many there are is unknown"
               if signal == "observed" else
               "its name suggests a hub; nothing it advertised confirms it, so what is behind it "
               "— if anything — is unknown"),
            device_id, 0, None, True,
        ))

    # Edge types arriving at each cloud node, gathered once: scanning every edge for every cloud
    # domain was O(cloud nodes x edges), both of which grow with the identities a LAN device mints.
    cloud_types: dict[str, set[str]] = {}
    for edge in edges:
        if edge.dst.startswith("cloud:"):
            cloud_types.setdefault(edge.dst, set()).add(edge.edge_type)
    for domain in sorted(node[len("cloud:"):] for node in cloud_types):
        node_id = f"cloud:{domain}"
        blocked = cloud_types[node_id] == {"cloud_blocked"}
        nodes.append(Node(
            node_id, "cloud", cloud_label(domain),
            f"{domain} — blocked by the DNS filter" if blocked else domain,
            # A refused lookup is not a dependency (C2.4), so a wholly-blocked domain's
            # criticality is 0 rather than a count of the devices that were told no.
            None, 0 if blocked else reach.get(node_id, dependents_of.get(node_id, 0)), None, True,
        ))
    return nodes


__all__ = [
    "Provider", "InferenceContext", "InferenceResult",
    "MDNS_PROVIDERS", "PORT_PROVIDERS", "HUB_MDNS", "HUB_NAME_HINTS", "HUB_EVIDENCE", "VENDOR_LABELS",
    "AddressOwners",
    "EDGE_SOURCES", "EdgeSource", "register_source", "merge_edges",
    "infer_all", "build_context", "providers", "gateway_device", "hub_device_ids", "is_hub", "hub_signal",
    "mdns_types", "display_name", "clean_text", "registrable_domain", "cloud_label",
    "gateway_edges", "internet_edges", "dns_edges", "cloud_edges", "provider_edges", "consumer_edges",
]
