"""Build the walkthrough video's demo database: a fictional but plausible family home.

``python video/seed_demo.py [--force]`` creates ``video/demo_data/homesoc.db`` with
:func:`homesoc.db.init_schema` (so the schema is always the product's own) and fills every table
the dashboard reads. Nothing here ever touches the real ``data/`` directory or ``config.toml``:
the target path is checked against the real data directory before a single byte is written, and
config overrides are stored as ``settings`` rows *inside the demo database* (config precedence is
defaults < config.toml < settings table), so the demo renders identically on any machine.

Design rules for the data itself:

* Every finding ID is looked up in :mod:`homesoc.findings.catalog`; an unknown ID, or one whose
  title/remediation still contains an unfilled ``{placeholder}``, aborts the seed. The video must
  never show the word "unknown" where a device name belongs.
* Titles and details are produced by ``catalog.render`` and dedupe keys by
  ``findings.engine.dedupe_key``, so seeded rows are indistinguishable from scanned ones.
* Every timestamp is relative to *now*, so the video never looks stale.
* No real network data: host ``HOME-PC``, SSID ``Home-WiFi``, public IP ``203.0.113.42``
  (RFC 5737 documentation range), and MACs built from real OUI prefixes with invented suffixes.
"""

from __future__ import annotations

import argparse
import json
import logging
import math
import random
import sqlite3
import sys
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable, Sequence

VIDEO_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = VIDEO_DIR.parent
if str(PROJECT_ROOT) not in sys.path:  # running the file directly, without an install
    sys.path.insert(0, str(PROJECT_ROOT))

from homesoc import db as hdb  # noqa: E402
from homesoc.findings import catalog  # noqa: E402
from homesoc.findings import engine as fengine  # noqa: E402
from homesoc.findings import score as scoremod  # noqa: E402

logger = logging.getLogger("seed_demo")

DEMO_DIR = VIDEO_DIR / "demo_data"
DEMO_DB = DEMO_DIR / "homesoc.db"
REAL_DATA_DIR = (PROJECT_ROOT / "data").resolve()

RNG_SEED = 20260907
HOST_NAME = "HOME-PC"
HOST_USER = "home"
SSID = "Home-WiFi"
PUBLIC_IP = "203.0.113.42"
LAN_CIDR = "192.168.1.0/24"
GATEWAY_IP = "192.168.1.1"
CAMERA_IP = "192.168.1.142"

NOW = datetime.now(timezone.utc).replace(microsecond=0)
RNG = random.Random(RNG_SEED)


# --------------------------------------------------------------------------- time helpers


def iso(moment: datetime) -> str:
    """``YYYY-MM-DDTHH:MM:SSZ`` — the exact form ``homesoc.util.utcnow_iso`` writes."""
    return moment.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def ago(*, days: float = 0.0, hours: float = 0.0, minutes: float = 0.0) -> datetime:
    return NOW - timedelta(days=days, hours=hours, minutes=minutes)


def iso_ago(*, days: float = 0.0, hours: float = 0.0, minutes: float = 0.0) -> str:
    return iso(ago(days=days, hours=hours, minutes=minutes))


def jdump(value: Any) -> str:
    return json.dumps(value, sort_keys=True, default=str)


# --------------------------------------------------------------------------- specs


@dataclass(frozen=True)
class ServiceSpec:
    port: int
    name: str
    proto: str = "tcp"
    state: str = "open"
    product: str | None = None
    version: str | None = None
    extrainfo: str | None = None
    cpe: str | None = None
    tunnel: str | None = None


@dataclass(frozen=True)
class DeviceSpec:
    key: str
    ip: str
    mac: str
    hostname: str | None
    vendor: str | None
    kind: str
    nickname: str | None = None
    trusted: bool = True
    online: bool = True
    first_seen_days: float = 200.0
    last_seen_minutes: float = 4.0
    notes: str | None = None
    mdns: tuple[str, ...] = ()
    services: tuple[ServiceSpec, ...] = ()


@dataclass(frozen=True)
class VulnSpec:
    device_key: str
    port: int
    cve: str
    title: str
    kev: bool
    cvss: float
    epss: float
    published: str
    matched_on: str
    remediation: str
    source: str = "nvd"
    first_seen_days: float = 9.0


@dataclass(frozen=True)
class FindingSpec:
    finding_id: str
    subject: str
    evidence: dict[str, Any]
    status: str = "open"
    device_key: str | None = None
    source: str = "scanners.ports"
    first_seen_days: float = 5.0
    resolved_after_hours: float | None = None
    occurrences: int | None = None
    note: str | None = None
    how: str = "resolved"           # 'resolved' | 'auto_resolved' for the closing event
    reopened_days: float | None = None   # opened -> auto_resolved -> reopened, still open now
    status_changed_days: float | None = None  # when acknowledge/suppress happened (default: soon after)
    severity: str | None = None
    #: What this particular scan saw, as a real scanner would supply on the draft. When it is
    #: None the catalog's rationale is used for both the detail paragraph *and* the muted
    #: "why it matters" line under it, and findings.html prints the same sentence twice.
    detail: str | None = None


@dataclass
class Counts:
    """What the run actually wrote, for the closing report."""

    rows: dict[str, int] = field(default_factory=dict)

    def note(self, table: str, n: int) -> None:
        self.rows[table] = self.rows.get(table, 0) + n


# --------------------------------------------------------------------------- the household
#
# MAC prefixes are genuine IEEE OUI assignments for the vendor named; the last three octets are
# invented. The IP camera deliberately uses a locally-administered address (the "randomised MAC"
# case) so it has no vendor at all — which is the whole point of that device in the video.

DEVICES: tuple[DeviceSpec, ...] = (
    DeviceSpec(
        key="gateway", ip=GATEWAY_IP, mac="50:C7:BF:3A:1D:04", hostname="gateway",
        vendor="TP-Link Technologies Co.,Ltd.", kind="router", nickname="Home router",
        first_seen_days=402.0, last_seen_minutes=1.0,
        notes="Archer AX21 — the box everything else hangs off.",
        services=(
            ServiceSpec(22, "ssh", product="Dropbear sshd", version="2019.78",
                        extrainfo="protocol 2.0", cpe="cpe:/a:dropbear_ssh_project:dropbear_ssh:2019.78"),
            ServiceSpec(53, "domain", product="Unbound", version="1.13.1",
                        cpe="cpe:/a:nlnetlabs:unbound:1.13.1"),
            ServiceSpec(53, "domain", proto="udp", product="Unbound", version="1.13.1"),
            ServiceSpec(80, "http", product="lighttpd", version="1.4.59",
                        extrainfo="TP-Link Archer AX21 admin", cpe="cpe:/a:lighttpd:lighttpd:1.4.59"),
            ServiceSpec(443, "https", product="lighttpd", version="1.4.59", tunnel="ssl",
                        cpe="cpe:/a:lighttpd:lighttpd:1.4.59"),
            ServiceSpec(1900, "upnp", proto="udp", product="MiniUPnPd", version="2.1",
                        extrainfo="IGD 2.0"),
            ServiceSpec(5000, "upnp", product="MiniUPnPd", version="2.1"),
        ),
    ),
    DeviceSpec(
        key="homepc", ip="192.168.1.20", mac="A4:34:D9:7C:5E:12", hostname=HOST_NAME,
        vendor="Intel Corporate", kind="computer", nickname="Home PC", first_seen_days=398.0,
        last_seen_minutes=0.5, notes="The machine Home SOC itself runs on.",
        mdns=("_smb._tcp", "_workstation._tcp"),
        services=(
            ServiceSpec(135, "msrpc", product="Microsoft Windows RPC"),
            ServiceSpec(139, "netbios-ssn", product="Microsoft Windows netbios-ssn"),
            ServiceSpec(445, "microsoft-ds", product="Windows 11 Home 26100 microsoft-ds"),
            ServiceSpec(5040, "unknown"),
            ServiceSpec(7680, "pando-pub", extrainfo="Delivery Optimization"),
        ),
    ),
    DeviceSpec(
        key="macbook_air", ip="192.168.1.21", mac="A4:83:E7:2C:91:6B", hostname="macbook-air",
        vendor="Apple, Inc.", kind="computer", nickname="MacBook Air", first_seen_days=356.0,
        last_seen_minutes=6.0, mdns=("_rdlink._tcp", "_companion-link._tcp", "_airplay._tcp"),
        services=(
            ServiceSpec(22, "ssh", state="closed"),
            ServiceSpec(5000, "rtsp", product="AirTunes rtspd", version="905.2"),
            ServiceSpec(7000, "rtsp", product="AirTunes rtspd", version="905.2"),
        ),
    ),
    DeviceSpec(
        key="macbook_pro", ip="192.168.1.22", mac="F0:18:98:4D:22:A7", hostname="macbook-pro",
        vendor="Apple, Inc.", kind="computer", nickname="MacBook Pro", first_seen_days=289.0,
        last_seen_minutes=41.0, mdns=("_companion-link._tcp", "_ssh._tcp"),
        services=(
            ServiceSpec(22, "ssh", product="OpenSSH", version="9.8",
                        extrainfo="protocol 2.0", cpe="cpe:/a:openbsd:openssh:9.8"),
            ServiceSpec(3306, "mysql", state="closed", product="MySQL"),
            ServiceSpec(5000, "rtsp", product="AirTunes rtspd", version="905.2"),
        ),
    ),
    DeviceSpec(
        key="iphone_dad", ip="192.168.1.30", mac="3C:15:C2:6E:B3:41", hostname="iphone-dad",
        vendor="Apple, Inc.", kind="phone", nickname="Dad's iPhone", first_seen_days=340.0,
        last_seen_minutes=2.0, mdns=("_companion-link._tcp",),
        services=(ServiceSpec(62078, "iphone-sync"),),
    ),
    DeviceSpec(
        key="iphone_mum", ip="192.168.1.31", mac="D0:81:7A:19:F8:5C", hostname="iphone-mum",
        vendor="Apple, Inc.", kind="phone", nickname="Mum's iPhone", first_seen_days=331.0,
        last_seen_minutes=3.0, mdns=("_companion-link._tcp",),
        services=(ServiceSpec(62078, "iphone-sync"),),
    ),
    DeviceSpec(
        key="iphone_ellie", ip="192.168.1.32", mac="AC:BC:32:70:2D:9E", hostname="iphone-ellie",
        vendor="Apple, Inc.", kind="phone", nickname="Ellie's iPhone", first_seen_days=176.0,
        last_seen_minutes=1.0, mdns=("_companion-link._tcp",),
        services=(ServiceSpec(62078, "iphone-sync"),),
    ),
    DeviceSpec(
        key="tablet", ip="192.168.1.35", mac="78:BD:BC:41:0A:33", hostname="galaxy-tab-a9",
        vendor="Samsung Electronics Co.,Ltd", kind="tablet", nickname="Kitchen tablet",
        first_seen_days=204.0, last_seen_minutes=17.0,
        services=(ServiceSpec(8009, "castv2", state="closed"),),
    ),
    DeviceSpec(
        key="tv", ip="192.168.1.40", mac="F8:04:2E:88:C1:57", hostname="samsung-tv-living-room",
        vendor="Samsung Electronics Co.,Ltd", kind="tv", nickname="Living room TV",
        first_seen_days=372.0, last_seen_minutes=9.0,
        mdns=("_airplay._tcp", "_googlecast._tcp"),
        services=(
            ServiceSpec(1900, "upnp", proto="udp", product="Samsung AllShare", version="1.0"),
            ServiceSpec(7676, "http", product="Samsung AllShare"),
            ServiceSpec(8001, "http", product="Samsung Tizen websocket API"),
            ServiceSpec(8002, "https", product="Samsung Tizen websocket API", tunnel="ssl"),
            ServiceSpec(9197, "upnp", product="Samsung AllShare"),
        ),
    ),
    DeviceSpec(
        key="sonos_kitchen", ip="192.168.1.41", mac="78:28:CA:35:9B:20", hostname="sonos-kitchen",
        vendor="Sonos, Inc.", kind="speaker", nickname="Kitchen speaker", first_seen_days=311.0,
        last_seen_minutes=2.0, mdns=("_sonos._tcp", "_spotify-connect._tcp"),
        services=(
            ServiceSpec(1400, "http", product="Linux UPnP/1.0 Sonos", version="83.1-61180"),
            ServiceSpec(1443, "https", product="Sonos", tunnel="ssl"),
            ServiceSpec(4444, "http", product="Sonos update endpoint"),
        ),
    ),
    DeviceSpec(
        key="sonos_living", ip="192.168.1.42", mac="5C:AA:FD:07:E4:88", hostname="sonos-living-room",
        vendor="Sonos, Inc.", kind="speaker", nickname="Living room speaker", first_seen_days=311.0,
        last_seen_minutes=2.0, mdns=("_sonos._tcp", "_spotify-connect._tcp"),
        services=(
            ServiceSpec(1400, "http", product="Linux UPnP/1.0 Sonos", version="83.1-61180"),
            ServiceSpec(1443, "https", product="Sonos", tunnel="ssl"),
        ),
    ),
    DeviceSpec(
        key="printer", ip="192.168.1.50", mac="9C:AE:D3:61:70:2F", hostname="epson-et2850",
        vendor="Seiko Epson Corporation", kind="printer", nickname="Epson printer",
        first_seen_days=268.0, last_seen_minutes=12.0,
        mdns=("_ipp._tcp", "_printer._tcp", "_scanner._tcp"),
        services=(
            ServiceSpec(80, "http", product="Epson ET-2850 web control"),
            ServiceSpec(161, "snmp", proto="udp", product="Epson SNMP agent", version="1",
                        extrainfo="community 'public'"),
            ServiceSpec(443, "https", product="Epson ET-2850 web control", tunnel="ssl"),
            ServiceSpec(515, "printer", product="Epson lpd"),
            ServiceSpec(631, "ipp", product="Epson IPP"),
            ServiceSpec(9100, "jetdirect", product="Epson raw print"),
        ),
    ),
    DeviceSpec(
        key="ring", ip="192.168.1.60", mac="FC:65:DE:22:4C:9A", hostname="ring-front-door",
        vendor="Amazon Technologies Inc.", kind="camera", nickname="Front door bell",
        first_seen_days=232.0, last_seen_minutes=5.0,
        notes="Cloud-only: talks out to Amazon, listens for nothing on the LAN.",
        services=(),
    ),
    DeviceSpec(
        key="plug_lamp", ip="192.168.1.70", mac="24:0A:C4:5E:33:C8", hostname="smartplug-lamp",
        vendor="Espressif Inc.", kind="iot", nickname="Lamp plug", first_seen_days=190.0,
        last_seen_minutes=4.0,
        services=(ServiceSpec(80, "http", product="ESP-IDF httpd", version="4.4"),),
    ),
    DeviceSpec(
        key="plug_heater", ip="192.168.1.71", mac="A4:CF:12:9D:81:47", hostname="smartplug-heater",
        vendor="Espressif Inc.", kind="iot", nickname="Heater plug", first_seen_days=190.0,
        last_seen_minutes=4.0,
        services=(ServiceSpec(80, "http", product="ESP-IDF httpd", version="4.4"),),
    ),
    DeviceSpec(
        key="switch", ip="192.168.1.80", mac="98:B6:E9:2A:F0:63", hostname="nintendo-switch",
        vendor="Nintendo Co.,Ltd", kind="console", nickname="Nintendo Switch",
        first_seen_days=298.0, last_seen_minutes=19.5 * 60, online=False,
        services=(),
    ),
    DeviceSpec(
        key="echo", ip="192.168.1.81", mac="44:65:0D:1B:6E:F2", hostname="echo-kitchen",
        vendor="Amazon Technologies Inc.", kind="speaker", nickname="Kitchen Echo",
        first_seen_days=6.0, last_seen_minutes=2.0,
        services=(
            ServiceSpec(4070, "http", product="Amazon Echo"),
            ServiceSpec(8888, "http", product="Amazon Echo"),
        ),
    ),
    DeviceSpec(
        key="camera", ip=CAMERA_IP, mac="8E:35:A1:4F:0C:D2", hostname=None, vendor=None,
        kind="camera", nickname=None, trusted=False, first_seen_days=3.4, last_seen_minutes=1.0,
        notes=None,
        services=(
            ServiceSpec(23, "telnet", product="BusyBox telnetd", version="1.20.2",
                        extrainfo="login prompt, no banner"),
            ServiceSpec(80, "http", product="Boa httpd", version="0.94.14rc21",
                        extrainfo="admin page reachable without a password",
                        cpe="cpe:/a:boa:boa:0.94.14"),
            ServiceSpec(554, "rtsp", product="Hipcam RealServer", version="V1.0"),
            ServiceSpec(8080, "http-alt", product="Boa httpd", version="0.94.14rc21"),
        ),
    ),
)

DEVICE_BY_KEY: dict[str, DeviceSpec] = {d.key: d for d in DEVICES}


# --------------------------------------------------------------------------- vulnerabilities
#
# Real, published CVE identifiers. CVE-2023-1389 is the only KEV entry, so exactly one
# NET-VUL-001 (critical) finding can be justified from this table.

VULNS: tuple[VulnSpec, ...] = (
    VulnSpec(
        device_key="gateway", port=80, cve="CVE-2023-1389", kev=True, cvss=8.8, epss=0.9437,
        title="TP-Link Archer AX21 unauthenticated command injection in the country parameter",
        published="2023-03-15", matched_on="cpe:2.3:o:tp-link:archer_ax21_firmware:1.1.4",
        remediation="Install TP-Link firmware 1.1.4 Build 20230219 or later from the router's admin page.",
        source="kev", first_seen_days=9.2,
    ),
    VulnSpec(
        device_key="gateway", port=80, cve="CVE-2022-22707", kev=False, cvss=9.8, epss=0.2891,
        title="lighttpd mod_extforward stack-based buffer overflow (1.4.46 - 1.4.63)",
        published="2022-01-06", matched_on="cpe:2.3:a:lighttpd:lighttpd:1.4.59",
        remediation="Update the router firmware; lighttpd 1.4.64 fixes mod_extforward.",
        first_seen_days=21.0,
    ),
    VulnSpec(
        device_key="gateway", port=53, cve="CVE-2022-30699", kev=False, cvss=7.5, epss=0.0121,
        title="Unbound NRDelegation attack causes excessive resource consumption",
        published="2022-05-18", matched_on="cpe:2.3:a:nlnetlabs:unbound:1.13.1",
        remediation="Update the router firmware; Unbound 1.16.2 fixes the delegation handling.",
        first_seen_days=21.0,
    ),
    VulnSpec(
        device_key="gateway", port=53, cve="CVE-2022-30698", kev=False, cvss=7.5, epss=0.0113,
        title="Unbound delegation cache poisoning via a rogue authoritative server",
        published="2022-05-18", matched_on="cpe:2.3:a:nlnetlabs:unbound:1.13.1",
        remediation="Update the router firmware; Unbound 1.16.2 fixes the delegation handling.",
        first_seen_days=21.0,
    ),
    VulnSpec(
        device_key="gateway", port=22, cve="CVE-2018-15599", kev=False, cvss=5.3, epss=0.0684,
        title="Dropbear recv_msg_userauth_request user enumeration",
        published="2018-08-22", matched_on="cpe:2.3:a:dropbear_ssh_project:dropbear_ssh:2019.78",
        remediation="Turn off SSH on the router, or update to Dropbear 2019.79 or later.",
        first_seen_days=21.0,
    ),
    VulnSpec(
        device_key="camera", port=80, cve="CVE-2017-9833", kev=False, cvss=7.5, epss=0.0421,
        title="Boa 0.94.14rc21 directory traversal in the web server (formRoamingCloud)",
        published="2017-06-22", matched_on="cpe:2.3:a:boa:boa:0.94.14",
        remediation="No fixed version exists: Boa has been unmaintained since 2005. Replace the device.",
        first_seen_days=3.2,
    ),
    VulnSpec(
        device_key="macbook_pro", port=22, cve="CVE-2025-26465", kev=False, cvss=6.8, epss=0.0093,
        title="OpenSSH client VerifyHostKeyDNS machine-in-the-middle",
        published="2025-02-18", matched_on="cpe:2.3:a:openbsd:openssh:9.8",
        remediation="Update to OpenSSH 9.9p2 or later (macOS 15.4 ships the fix).",
        first_seen_days=14.0,
    ),
)


# --------------------------------------------------------------------------- findings
#
# Every ID here is checked against the catalog before a row is written.

OPEN_CRITICAL: tuple[FindingSpec, ...] = (
    FindingSpec(
        "NET-SVC-001", f"device:8E:35:A1:4F:0C:D2:23",
        {"ip": CAMERA_IP, "port": 23, "proto": "tcp", "banner": "BusyBox telnetd 1.20.2",
         "product": "BusyBox telnetd", "version": "1.20.2", "hostname": "no hostname advertised",
         "vendor": "no registered vendor (locally administered MAC)", "key": "23"},
        device_key="camera", source="scanners.ports", first_seen_days=3.2, occurrences=13,
        detail=("Port 23/tcp answered on every sweep since 4 September and returned the banner "
                "\"BusyBox telnetd 1.20.2\". The device advertises no hostname and its MAC is "
                "locally administered, so the vendor cannot be identified from the address."),
    ),
    FindingSpec(
        "NET-VUL-001", "device:50:C7:BF:3A:1D:04:80",
        {"cve": "CVE-2023-1389", "ip": GATEWAY_IP, "product": "TP-Link Archer AX21 httpd",
         "version": "1.1.4 Build 20220221", "cvss": 8.8, "epss": 0.9437, "port": 80,
         "kev_date_added": "2023-04-24", "kev_due": "2023-05-15", "key": "CVE-2023-1389"},
        device_key="gateway", source="vulns.matcher", first_seen_days=9.2, occurrences=18,
        detail=("The router's web admin on port 80 reports itself as TP-Link Archer AX21 httpd "
                "1.1.4 Build 20220221, which is inside the range CISA lists for CVE-2023-1389. "
                "EPSS puts the chance of exploitation in the next thirty days at 94 percent."),
    ),
)

OPEN_HIGH: tuple[FindingSpec, ...] = (
    FindingSpec(
        "WIN-UPD-004", f"host:{HOST_NAME}",
        {"name": "Google Chrome", "version": "139.0.7258.155", "available": "141.0.7390.55",
         "id": "Google.Chrome", "source": "winget", "key": "Google.Chrome"},
        source="scanners.updates", first_seen_days=11.0, occurrences=11,
    ),
    FindingSpec(
        "WIN-UPD-004", f"host:{HOST_NAME}",
        {"name": "Oracle Java 8 Runtime", "version": "8.0.4210.12", "available": "8.0.4710.11",
         "id": "Oracle.JavaRuntimeEnvironment", "source": "winget",
         "key": "Oracle.JavaRuntimeEnvironment"},
        source="scanners.updates", first_seen_days=19.0, occurrences=19,
    ),
    FindingSpec(
        "NET-WAN-003", f"wan:{PUBLIC_IP}",
        {"external_port": 8443, "internal_client": CAMERA_IP, "internal_port": 80,
         "description": "IPCam Web", "protocol": "TCP", "public_ip": PUBLIC_IP,
         "lease_seconds": 0, "key": "TCP:8443"},
        device_key="camera", source="scanners.exposure", first_seen_days=3.1, occurrences=4,
    ),
    FindingSpec(
        "NET-VUL-004", "device:50:C7:BF:3A:1D:04:80",
        {"cves": ["CVE-2022-22707", "CVE-2023-1389"], "ip": GATEWAY_IP, "max_epss": 0.9437,
         "product": "lighttpd", "version": "1.4.59", "key": "epss"},
        device_key="gateway", source="vulns.matcher", first_seen_days=9.2, occurrences=18,
        detail=("The router's web admin on port 80 reports itself as TP-Link Archer AX21 httpd "
                "1.1.4 Build 20220221, which is inside the range CISA lists for CVE-2023-1389. "
                "EPSS puts the chance of exploitation in the next thirty days at 94 percent."),
    ),
    FindingSpec(
        "WIN-NET-001", f"host:{HOST_NAME}",
        {"state": "Enabled", "feature": "SMB1Protocol", "smb1_client": True, "smb1_server": False},
        source="scanners.host_windows", first_seen_days=26.0, occurrences=26,
    ),
    FindingSpec(
        "NET-DNS-004", "dns:192.168.1.32",
        {"client": "192.168.1.32", "domain": "secure-appleid-verify.example",
         "verdict": "malicious", "source": "virustotal", "hits": 3,
         "first_seen": iso_ago(hours=19.0), "key": "secure-appleid-verify.example"},
        device_key="iphone_ellie", source="dnsfilter.policy", first_seen_days=0.8, occurrences=3,
    ),
)

OPEN_MEDIUM: tuple[FindingSpec, ...] = (
    FindingSpec(
        "NET-SVC-010", "device:8E:35:A1:4F:0C:D2:554",
        {"ip": CAMERA_IP, "port": 554, "product": "Hipcam RealServer", "version": "V1.0",
         "auth": "none observed", "key": "554"},
        device_key="camera", source="scanners.ports", first_seen_days=3.2, occurrences=13,
        detail=("Port 23/tcp answered on every sweep since 4 September and returned the banner "
                "\"BusyBox telnetd 1.20.2\". The device advertises no hostname and its MAC is "
                "locally administered, so the vendor cannot be identified from the address."),
    ),
    FindingSpec(
        "NET-SVC-009", "device:9C:AE:D3:61:70:2F:161",
        {"ip": "192.168.1.50", "port": 161, "community": "public", "sysdescr": "EPSON ET-2850 Series",
         "key": "161"},
        device_key="printer", source="scanners.ports", first_seen_days=88.0, occurrences=176,
    ),
    FindingSpec(
        "NET-SVC-006", "device:50:C7:BF:3A:1D:04:1900",
        {"ip": GATEWAY_IP, "port": 1900, "proto": "udp", "product": "MiniUPnPd 2.1", "key": "1900"},
        device_key="gateway", source="scanners.ports", first_seen_days=118.0, occurrences=236,
    ),
    FindingSpec(
        "NET-SVC-006", "device:F8:04:2E:88:C1:57:1900",
        {"ip": "192.168.1.40", "port": 1900, "proto": "udp", "product": "Samsung AllShare 1.0",
         "key": "1900"},
        device_key="tv", source="scanners.ports", first_seen_days=118.0, occurrences=236,
    ),
    FindingSpec(
        "NET-RTR-002", "device:50:C7:BF:3A:1D:04",
        {"ip": GATEWAY_IP, "igd_version": "2.0", "control_url": "http://192.168.1.1:5000/ctl/IPConn",
         "mappings": 3},
        device_key="gateway", source="scanners.exposure", first_seen_days=118.0, occurrences=118,
    ),
    FindingSpec(
        "NET-DEV-001", "device:8E:35:A1:4F:0C:D2",
        {"ip": CAMERA_IP, "mac": "8E:35:A1:4F:0C:D2",
         "vendor": "no registered vendor (locally administered MAC)",
         "hostname": "no hostname advertised", "method": "arp"},
        device_key="camera", source="scanners.discovery", first_seen_days=3.4, occurrences=41,
    ),
    FindingSpec(
        "NET-VUL-003", "device:50:C7:BF:3A:1D:04:53",
        {"count": 2, "max_cvss": 7.5, "product": "Unbound", "version": "1.13.1", "ip": GATEWAY_IP,
         "cves": ["CVE-2022-30698", "CVE-2022-30699"], "key": "Unbound 1.13.1"},
        device_key="gateway", source="vulns.matcher", first_seen_days=21.0, occurrences=42,
    ),
    FindingSpec(
        "WIN-ACC-001", f"host:{HOST_NAME}",
        {"user": HOST_USER, "groups": ["Administrators", "Users"], "sid_suffix": "1001"},
        source="scanners.host_windows", first_seen_days=30.0, occurrences=30,
    ),
    FindingSpec(
        "WIN-DEF-004", f"host:{HOST_NAME}",
        {"IsTamperProtected": False, "TamperProtectionSource": "Local setting"},
        source="scanners.defender", first_seen_days=30.0, occurrences=41,
        reopened_days=6.0,
    ),
    FindingSpec(
        "WIN-UPD-001", f"host:{HOST_NAME}",
        {"count": 3, "important": True,
         "titles": ["2026-09 Cumulative Update for Windows 11 Version 25H2 (KB5069122)",
                    "Windows Malicious Software Removal Tool x64 - September 2026",
                    "Intel - System - 10.1.42.9"],
         "kbs": ["KB5069122", "KB890830"]},
        source="scanners.updates", first_seen_days=0.6, occurrences=1,
    ),
    FindingSpec(
        "WIN-PER-002", f"host:{HOST_NAME}",
        {"name": "MicrosoftEdgeUpdateTaskMachineUA", "location": r"\MicrosoftEdgeUpdateTaskMachineUA",
         "command": r"C:\Program Files (x86)\Microsoft\EdgeUpdate\MicrosoftEdgeUpdate.exe /ua /installsource scheduler",
         "key": r"\MicrosoftEdgeUpdateTaskMachineUA"},
        source="scanners.host_windows", first_seen_days=0.45, occurrences=1,
    ),
)

OPEN_LOW: tuple[FindingSpec, ...] = (
    FindingSpec(
        "NET-SVC-005", "device:8E:35:A1:4F:0C:D2:80",
        {"ip": CAMERA_IP, "port": 80, "product": "Boa httpd 0.94.14rc21",
         "title": "IPCam Web Admin", "auth": "none", "key": "80"},
        device_key="camera", source="scanners.ports", first_seen_days=3.2, occurrences=13,
        detail=("Port 23/tcp answered on every sweep since 4 September and returned the banner "
                "\"BusyBox telnetd 1.20.2\". The device advertises no hostname and its MAC is "
                "locally administered, so the vendor cannot be identified from the address."),
    ),
    FindingSpec(
        "NET-SVC-005", "device:50:C7:BF:3A:1D:04:80",
        {"ip": GATEWAY_IP, "port": 80, "product": "lighttpd 1.4.59",
         "title": "TP-Link Archer AX21", "auth": "form", "key": "80"},
        device_key="gateway", source="scanners.ports", first_seen_days=118.0, occurrences=236,
    ),
    FindingSpec(
        "NET-SVC-008", "device:9C:AE:D3:61:70:2F:9100",
        {"ip": "192.168.1.50", "port": 9100, "product": "Epson raw print", "key": "9100"},
        device_key="printer", source="scanners.ports", first_seen_days=88.0, occurrences=176,
    ),
    FindingSpec(
        "NET-SVC-011", "device:50:C7:BF:3A:1D:04:22",
        {"ip": GATEWAY_IP, "port": 22, "product": "Dropbear sshd", "version": "2019.78",
         "key": "22"},
        device_key="gateway", source="scanners.ports", first_seen_days=118.0, occurrences=236,
    ),
    FindingSpec(
        "WIN-UPD-003", f"host:{HOST_NAME}",
        {"name": "Inkscape", "version": "1.3.2", "available": "1.4.2", "id": "Inkscape.Inkscape",
         "source": "winget", "key": "Inkscape.Inkscape"},
        source="scanners.updates", first_seen_days=23.0, occurrences=23,
    ),
    FindingSpec(
        "WIN-UPD-003", f"host:{HOST_NAME}",
        {"name": "HandBrake", "version": "1.8.2", "available": "1.10.2", "id": "HandBrake.HandBrake",
         "source": "winget", "key": "HandBrake.HandBrake"},
        source="scanners.updates", first_seen_days=15.0, occurrences=15,
    ),
    FindingSpec(
        "WIN-NET-003", f"host:{HOST_NAME}",
        {"RequireSecuritySignature": False, "EnableSecuritySignature": True, "scope": "client"},
        source="scanners.host_windows", first_seen_days=30.0, occurrences=30,
    ),
    FindingSpec(
        "WIN-NET-004", f"host:{HOST_NAME}",
        {"EnableMulticast": 1, "policy": "not configured"},
        source="scanners.host_windows", first_seen_days=30.0, occurrences=30,
    ),
    FindingSpec(
        "WIN-SYS-003", f"host:{HOST_NAME}",
        {"HypervisorEnforcedCodeIntegrity": "not running", "VirtualizationBasedSecurityStatus": 1},
        source="scanners.host_windows", first_seen_days=30.0, occurrences=30,
    ),
    FindingSpec(
        "WIN-SYS-005", f"host:{HOST_NAME}",
        {"feature": "MicrosoftWindowsPowerShellV2Root", "state": "Enabled"},
        source="scanners.host_windows", first_seen_days=30.0, occurrences=30,
    ),
)

OPEN_INFO: tuple[FindingSpec, ...] = (
    FindingSpec(
        "NET-DEV-002", "device:8E:35:A1:4F:0C:D2",
        {"ip": CAMERA_IP, "mac": "8E:35:A1:4F:0C:D2", "vendor": "", "locally_administered": True},
        device_key="camera", source="scanners.discovery", first_seen_days=3.4, occurrences=41,
    ),
    FindingSpec(
        "NET-WIFI-002", "wifi:Wi-Fi",
        {"ssid": SSID, "authentication": "WPA2-Personal", "cipher": "CCMP", "band": "5 GHz",
         "interface": "Wi-Fi"},
        source="scanners.wifi", first_seen_days=30.0, occurrences=30,
    ),
    FindingSpec(
        "SOC-SYS-002", "soc:host",
        {"skipped": ["WIN-ACC-002", "WIN-SYS-008"], "elevated": False, "user": HOST_USER,
         "project_root": r"C:\Users\home\Home_SOC"},
        source="cli.soc_health", first_seen_days=30.0, occurrences=30,
    ),
)

ACKNOWLEDGED: tuple[FindingSpec, ...] = (
    FindingSpec(
        "WIN-NET-002", f"host:{HOST_NAME}",
        {"nla": "yes", "fDenyTSConnections": 0, "port": 3389, "UserAuthentication": 1},
        status="acknowledged", source="scanners.host_windows", first_seen_days=28.0,
        occurrences=28, note="Needed to reach this PC from work; NLA is on and the firewall rule is LAN-only.",
    ),
    FindingSpec(
        "WIN-SYS-007", f"host:{HOST_NAME}",
        {"ScreenSaveActive": 0, "ScreenSaverIsSecure": 0, "timeout_minutes": 0},
        status="acknowledged", source="scanners.host_windows", first_seen_days=28.0,
        occurrences=28, status_changed_days=0.35,
        note="Desktop lives in a locked study; accepted for now.",
    ),
)

SUPPRESSED: tuple[FindingSpec, ...] = (
    FindingSpec(
        "NET-SVC-005", "device:9C:AE:D3:61:70:2F:80",
        {"ip": "192.168.1.50", "port": 80, "product": "Epson ET-2850 web control",
         "title": "EPSON ET-2850 Series", "auth": "none", "key": "80"},
        status="suppressed", device_key="printer", source="scanners.ports",
        first_seen_days=88.0, occurrences=176, status_changed_days=11.0,
        note="Printer web page is HTTP-only by design and is not reachable from outside the LAN.",
    ),
)

RESOLVED: tuple[FindingSpec, ...] = (
    FindingSpec(
        "WIN-DEF-002", f"host:{HOST_NAME}",
        {"RealTimeProtectionEnabled": False, "DisableRealtimeMonitoring": True},
        status="resolved", source="scanners.defender", first_seen_days=27.5,
        resolved_after_hours=16.8, how="auto_resolved", occurrences=17,
    ),
    FindingSpec(
        "NET-SVC-002", "device:9C:AE:D3:61:70:2F:21",
        {"ip": "192.168.1.50", "port": 21, "product": "Epson ftpd", "anonymous": True, "key": "21"},
        status="resolved", device_key="printer", source="scanners.ports", first_seen_days=24.0,
        resolved_after_hours=72.0, how="auto_resolved", occurrences=6,
    ),
    FindingSpec(
        "WIN-FW-001", f"host:{HOST_NAME}",
        {"profile": "Public", "profiles": ["Public"], "enabled": False},
        status="resolved", source="scanners.host_windows", first_seen_days=22.0,
        resolved_after_hours=12.0, how="auto_resolved", occurrences=2,
    ),
    FindingSpec(
        "WIN-UPD-002", f"host:{HOST_NAME}",
        {"days": 63, "last": "2026-06-11", "title": "2026-06 Cumulative Update (KB5062553)",
         "source": "windows update history", "build": "26100.4652"},
        status="resolved", source="scanners.updates", first_seen_days=20.0,
        resolved_after_hours=48.0, how="resolved", occurrences=3,
        note="Installed the June and July cumulative updates and rebooted.",
    ),
    FindingSpec(
        "WIN-UPD-004", f"host:{HOST_NAME}",
        {"name": "VLC media player", "version": "3.0.20", "available": "3.0.21",
         "id": "VideoLAN.VLC", "source": "winget", "key": "VideoLAN.VLC"},
        status="resolved", source="scanners.updates", first_seen_days=17.0,
        resolved_after_hours=12.0, how="auto_resolved", occurrences=2,
    ),
    FindingSpec(
        "WIN-ACC-003", f"host:{HOST_NAME}",
        {"user": "Guest", "enabled": True},
        status="resolved", source="scanners.host_windows", first_seen_days=2.5,
        resolved_after_hours=48.0, how="resolved", occurrences=3,
        note="Disabled the Guest account from Computer Management.",
    ),
    FindingSpec(
        "AV-FILE-001", r"host:HOME-PC:invoice_2026_08.pdf.exe",
        {"path": r"C:\Users\home\Downloads\invoice_2026_08.pdf.exe",
         "sha256": "9f2c1a7be4d05f38a1b6c0d29e77ab5413c8f6021d94ae7c5b3f80d16e2a4c77",
         "detections": 41, "engines": 72, "source": "virustotal",
         "key": "9f2c1a7be4d05f38a1b6c0d29e77ab5413c8f6021d94ae7c5b3f80d16e2a4c77"},
        status="resolved", source="scanners.files", first_seen_days=12.2,
        resolved_after_hours=4.8, how="resolved", occurrences=1,
        note="Deleted from Downloads; Defender full scan afterwards came back clean.",
    ),
    FindingSpec(
        "NET-SVC-007", "device:F0:18:98:4D:22:A7:3306",
        {"ip": "192.168.1.22", "port": 3306, "product": "MySQL", "version": "8.4.2", "key": "3306"},
        status="resolved", device_key="macbook_pro", source="scanners.ports", first_seen_days=12.0,
        resolved_after_hours=9.6, how="auto_resolved", occurrences=2,
    ),
    FindingSpec(
        "WIN-DEF-005", f"host:{HOST_NAME}",
        {"MAPSReporting": 0},
        status="resolved", source="scanners.defender", first_seen_days=10.0,
        resolved_after_hours=7.2, how="auto_resolved", occurrences=8,
    ),
    FindingSpec(
        "WIN-SYS-002", f"host:{HOST_NAME}",
        {"ProtectionStatus": 0, "volume": "C:", "method": "None"},
        status="resolved", source="scanners.host_windows", first_seen_days=9.0,
        resolved_after_hours=96.0, how="resolved", occurrences=5,
        note="Turned on device encryption and saved the recovery key to the Microsoft account.",
    ),
    FindingSpec(
        "NET-DEV-001", "device:44:65:0D:1B:6E:F2",
        {"ip": "192.168.1.81", "mac": "44:65:0D:1B:6E:F2", "vendor": "Amazon Technologies Inc.",
         "hostname": "echo-kitchen", "method": "arp"},
        status="resolved", device_key="echo", source="scanners.discovery", first_seen_days=6.0,
        resolved_after_hours=2.4, how="resolved", occurrences=2,
        note="device marked trusted",
    ),
    FindingSpec(
        "NET-DNS-003", "soc:dns",
        {"age_days": 4, "lists": ["oisd_small", "hagezi_pro"], "reason": "no successful update"},
        status="resolved", source="dnsfilter.policy", first_seen_days=0.75,
        resolved_after_hours=2.4, how="auto_resolved", occurrences=2,
    ),
)

# --------------------------------------------------------------------------- host posture

HOST_CHECKS: tuple[tuple[str, str, str | None, str | None, bool], ...] = (
    # (check_id, status, value, expected, needs_admin)
    ("WIN-DEF-001", "pass", "enabled", "antivirus enabled", False),
    ("WIN-DEF-002", "pass", "on", "real-time protection on", False),
    ("WIN-DEF-003", "pass", "1 day (v1.441.708.0)", "<= 3 days", False),
    ("WIN-DEF-004", "fail", "off", "tamper protection on", False),
    ("WIN-DEF-005", "pass", "advanced", "MAPSReporting=2", False),
    ("WIN-DEF-006", "pass", "block", "PUA protection on", False),
    ("WIN-DEF-007", "pass", "6 days ago", "within 30 days", False),
    ("WIN-DEF-008", "pass", "on", "controlled folder access on", False),
    ("WIN-DEF-009", "pass", "on", "network protection on", False),
    ("WIN-DEF-010", "pass", "12 rules in block mode", "ASR rules configured", False),
    ("WIN-DEF-012", "pass", "AMServiceEnabled=True mode=Normal", "AM service running in Normal mode", False),
    ("WIN-DEF-013", "pass", "on", "Smart App Control on", False),
    ("WIN-FW-001", "pass", "Domain, Private, Public all enabled", "firewall on for every profile", False),
    ("WIN-FW-002", "unknown", None, "default inbound Block", False),
    ("WIN-UPD-001", "fail", "3 pending (security/cumulative)", "no pending updates", False),
    ("WIN-UPD-002", "pass", "9 days ago (2026-08-29)", "within 45 days", False),
    ("WIN-ACC-001", "fail", f"{HOST_USER} (Administrators)", "a standard account for daily use", False),
    ("WIN-ACC-002", "needs_admin", None, "built-in Administrator disabled", True),
    ("WIN-ACC-003", "pass", "disabled", "guest disabled", False),
    ("WIN-ACC-004", "pass", "off", "automatic logon off", False),
    ("WIN-ACC-005", "pass", "prompt on the secure desktop", "UAC enabled", False),
    ("WIN-NET-001", "fail", "SMB1Protocol-Client Enabled", "SMBv1 removed", False),
    ("WIN-NET-002", "warn", "enabled (NLA: yes)", "remote desktop off", False),
    ("WIN-NET-003", "fail", "not required", "SMB signing required", False),
    ("WIN-NET-004", "fail", "EnableMulticast=1", "LLMNR disabled", False),
    ("WIN-NET-005", "pass", "not listening", "WinRM and Remote Registry off", False),
    ("WIN-NET-006", "pass", "no unexpected LAN listeners", "no unexpected LAN listeners", False),
    ("WIN-SYS-001", "pass", "on", "Secure Boot on", False),
    ("WIN-SYS-002", "pass", "on (XTS-AES 128)", "device encryption on", False),
    ("WIN-SYS-003", "fail", "not running", "memory integrity running", False),
    ("WIN-SYS-004", "fail", "RunAsPPL not set", "RunAsPPL=1", False),
    ("WIN-SYS-005", "fail", "MicrosoftWindowsPowerShellV2Root Enabled", "PowerShell 2.0 removed", False),
    ("WIN-SYS-006", "pass", "on", "SmartScreen on", False),
    ("WIN-SYS-007", "warn", "no lock screen timeout", "screen lock after 15 minutes", False),
    ("WIN-SYS-008", "needs_admin", None, "TPM present and ready", True),
)

# WIN-SYS-004 is a medium in the catalog; it keeps the failing posture check and the finding
# list in step (every fail/warn row above has exactly one finding, and vice versa).
OPEN_MEDIUM = OPEN_MEDIUM + (
    FindingSpec(
        "WIN-SYS-004", f"host:{HOST_NAME}",
        {"RunAsPPL": 0, "path": r"HKLM\SYSTEM\CurrentControlSet\Control\Lsa"},
        source="scanners.host_windows", first_seen_days=30.0, occurrences=30,
    ),
)

ALL_FINDINGS: tuple[FindingSpec, ...] = (
    OPEN_CRITICAL + OPEN_HIGH + OPEN_MEDIUM + OPEN_LOW + OPEN_INFO
    + ACKNOWLEDGED + SUPPRESSED + RESOLVED
)

SOFTWARE: tuple[tuple[str, str, str | None, str], ...] = (
    # (name, installed version, available version or None, publisher/package id)
    ("Google Chrome", "139.0.7258.155", "141.0.7390.55", "Google.Chrome"),
    ("Oracle Java 8 Runtime", "8.0.4210.12", "8.0.4710.11", "Oracle.JavaRuntimeEnvironment"),
    ("Inkscape", "1.3.2", "1.4.2", "Inkscape.Inkscape"),
    ("HandBrake", "1.8.2", "1.10.2", "HandBrake.HandBrake"),
    ("Microsoft Edge", "141.0.3537.57", None, "Microsoft.Edge"),
    ("Mozilla Firefox", "143.0.1", None, "Mozilla.Firefox"),
    ("7-Zip", "25.01", None, "7zip.7zip"),
    ("VLC media player", "3.0.21", None, "VideoLAN.VLC"),
    ("Notepad++", "8.8.6", None, "Notepad++.Notepad++"),
    ("Python 3.14", "3.14.0", None, "Python.Python.3.14"),
    ("Git", "2.51.0", None, "Git.Git"),
    ("Spotify", "1.2.68.1024", None, "Spotify.Spotify"),
    ("Steam", "1757549572", None, "Valve.Steam"),
    ("Zoom Workplace", "6.5.7.2340", None, "Zoom.Zoom"),
)

PERSISTENCE: tuple[tuple[str, str, str | None, str, bool, float], ...] = (
    # (kind, name, command, location, baseline, first_seen_days)
    ("run", "OneDrive", r"C:\Program Files\Microsoft OneDrive\OneDrive.exe /background",
     r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run", True, 398.0),
    ("run", "SecurityHealth", r"%windir%\system32\SecurityHealthSystray.exe",
     r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run", True, 398.0),
    ("run", "Spotify", r"C:\Users\home\AppData\Roaming\Spotify\Spotify.exe --autostart",
     r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run", True, 214.0),
    ("startup", "Steam", r"C:\Program Files (x86)\Steam\steam.exe -silent",
     r"C:\Users\home\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup", True, 298.0),
    ("task", "GoogleUpdateTaskMachineUA",
     r"C:\Program Files (x86)\Google\Update\GoogleUpdate.exe /ua /installsource scheduler",
     r"\GoogleSystem\GoogleUpdater", True, 398.0),
    ("task", "Adobe Acrobat Update Task",
     r"C:\Program Files (x86)\Common Files\Adobe\ARM\1.0\AdobeARM.exe", r"\Adobe", True, 341.0),
    ("service", "EpsonCustomerResearch", r"C:\Program Files (x86)\EPSON\EAI\eai_service.exe",
     r"HKLM\SYSTEM\CurrentControlSet\Services", True, 268.0),
    ("task", "MicrosoftEdgeUpdateTaskMachineUA",
     r"C:\Program Files (x86)\Microsoft\EdgeUpdate\MicrosoftEdgeUpdate.exe /ua /installsource scheduler",
     r"\MicrosoftEdgeUpdateTaskMachineUA", False, 0.45),
)

FILE_CHECKS: tuple[tuple[str, str, int, float, str, str, str], ...] = (
    # (sha256, path, size, first_seen_days, verdict, source, detail)
    ("9f2c1a7be4d05f38a1b6c0d29e77ab5413c8f6021d94ae7c5b3f80d16e2a4c77",
     r"C:\Users\home\Downloads\invoice_2026_08.pdf.exe", 812544, 12.2, "malicious", "virustotal",
     "41/72 engines; deleted by the user, Defender full scan clean afterwards"),
    ("31d8f4c7a90b26e5148f0cd37ba95e2206f81d4ca7358be901f2d6c48a3157e0",
     r"C:\Users\home\Downloads\HomeSOC-0.1.0-py3-none-any.whl", 214016, 5.0, "clean", "virustotal",
     "0/72 engines"),
    ("6b0e2c94af7d135082a6be41f3cd7a58e9024d16bb37fc850e19d4a27c63f8b1",
     r"C:\Users\home\Downloads\ET-2850_Series_Driver.exe", 44236800, 22.0, "clean", "virustotal",
     "0/71 engines"),
    ("ce417a02d5b98f6314ea70cd82b539147f60ad2c9e83b1750fd6ac4218e35b9d",
     r"C:\Users\home\Downloads\school-timetable.xlsx", 38912, 8.0, "clean", "local",
     "not seen by any feed; extension is not executable"),
)

FEEDS: tuple[tuple[str, str, str, int, int, float, float], ...] = (
    # (name, url, kind, entries, bytes, checked_hours_ago, updated_hours_ago)
    ("kev", "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
     "kev", 1367, 2_318_944, 1.4, 9.4),
    ("epss", "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz",
     "epss", 291_842, 3_804_112, 5.4, 5.4),
    ("oui", "https://www.wireshark.org/download/automated/data/manuf",
     "oui", 54_216, 2_142_336, 41.4, 41.4),
    ("oisd_small", "https://small.oisd.nl", "domains", 48_312, 1_204_992, 2.4, 8.4),
    ("hagezi_pro", "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/pro-onlydomains.txt",
     "domains", 216_704, 4_618_240, 2.4, 8.4),
    ("urlhaus", "https://urlhaus.abuse.ch/downloads/hostfile/", "hosts", 2_146, 74_112, 0.4, 3.4),
    ("urlhaus_filter", "https://malware-filter.gitlab.io/malware-filter/urlhaus-filter-hosts.txt",
     "hosts", 3_014, 98_304, 0.4, 3.4),
    ("threatfox", "https://threatfox.abuse.ch/downloads/hostfile/", "hosts", 1_089, 41_984, 0.4, 3.4),
    ("phishing_army", "https://phishing.army/download/phishing_army_blocklist.txt",
     "domains", 32_918, 862_208, 0.4, 6.4),
    ("openphish", "https://openphish.com/feed.txt", "domains", 512, 33_792, 0.4, 6.4),
    ("feodo_ips", "https://feodotracker.abuse.ch/downloads/ipblocklist.json", "ip", 812, 24_576, 0.4, 3.4),
    ("spamhaus_drop", "https://www.spamhaus.org/drop/drop.txt", "ip", 1_204, 30_720, 11.4, 11.4),
)

DNS_ACTIVE_LISTS = ("oisd_small", "hagezi_pro", "urlhaus", "urlhaus_filter", "threatfox",
                    "phishing_army", "openphish")

#: Intervals are the shipped defaults (config.example.toml [schedule]) because the demo seeds no
#: schedule.* override: discovery 10 min, services + vulns 24 h, host 6 h, exposure 12 h, feeds 6 h.
#: ``runs`` is consistent with the interval over the instance's ~30 days of life.
#: ``last_error`` is per job — an error string only that job's own code could produce.
JOBS: tuple[tuple[str, float, float, int, int, float, str | None], ...] = (
    # (name, interval_hours, last_duration_sec, runs, failures, last_run_hours_ago, last_error)
    ("discovery", 10 / 60, 4.7, 4218, 3, 0.11,
     "arp table unavailable: no adapter answered on 192.168.1.0/24"),
    ("services", 24.0, 96.4, 30, 0, 2.4, None),
    ("vulns", 24.0, 11.2, 30, 0, 2.3, None),
    ("host", 6.0, 38.9, 118, 0, 5.2, None),
    ("exposure", 12.0, 9.8, 59, 2, 9.4, "upstream lookup timed out after 20 s"),
    ("feeds", 6.0, 27.6, 118, 1, 3.4, "HTTP 503 from the feed host; retrying next cycle"),
    ("files", 24.0, 6.1, 30, 0, 14.4, None),
    ("dns_rollup", 1.0, 0.4, 708, 0, 0.35, None),
    ("score", 1.0, 0.6, 708, 0, 0.35, None),
    ("housekeeping", 24.0, 2.9, 30, 0, 20.4, None),
    ("digest", 24.0, 1.3, 30, 0, 38.0, None),
)
# ``quick``, ``full``, ``device_scan`` and ``dns_retry`` only run when something asks them to, so
# they legitimately have no row until first use; the dashboard shows them as "never".

#: One `scans` row per scheduled run, at the same cadences as JOBS, so the timestamps on the
#: /scans history agree with what the voice and the Settings page say the scheduler does.
#: ``max_rows`` caps the high-frequency kinds: /scans lists the 200 most recent rows, and
#: seeding twenty days of ten-minute discovery would push every other kind off the page.
SCAN_CADENCE: tuple[tuple[str, float, int], ...] = (
    ("discovery", 10 / 60, 12), ("services", 24.0, 0), ("vulns", 24.0, 0), ("host", 6.0, 0),
    ("exposure", 12.0, 0), ("feeds", 6.0, 0), ("files", 24.0, 0),
)
SCAN_HISTORY_DAYS = 14

# --------------------------------------------------------------------------- DNS traffic

ALLOWED_DOMAINS: tuple[str, ...] = (
    "apple.com", "gateway.icloud.com", "push.apple.com", "gs-loc.apple.com",
    "www.google.com", "clients4.google.com", "youtube.com", "i.ytimg.com",
    "netflix.com", "nflxvideo.net", "open.spotify.com", "audio-fa.scdn.co",
    "www.bbc.co.uk", "static.files.bbci.co.uk", "github.com", "objects.githubusercontent.com",
    "cloudflare.com", "one.one.one.one", "ntp.org", "time.windows.com",
    "outlook.office365.com", "login.microsoftonline.com", "update.microsoft.com",
    "ring.com", "fw-updates.ring.com", "device-metrics-us.amazon.com",
    "sonos.com", "update-services.sonos.com", "samsung.com", "api.smartthings.com",
    "whatsapp.net", "instagram.com", "cdn.jsdelivr.net", "wikipedia.org",
    "nintendo.net", "ctest.cdn.nintendo.net", "epson.com", "pool.ntp.org",
)

# (domain, blocklist that catches it) — recognisable ad and telemetry endpoints.
BLOCKED_DOMAINS: tuple[tuple[str, str], ...] = (
    ("doubleclick.net", "oisd_small"),
    ("googleadservices.com", "oisd_small"),
    ("www.google-analytics.com", "oisd_small"),
    ("adservice.google.com", "oisd_small"),
    ("graph.facebook.com", "hagezi_pro"),
    ("app-measurement.com", "hagezi_pro"),
    ("ads.tiktok.com", "hagezi_pro"),
    ("analytics.tiktok.com", "hagezi_pro"),
    ("sb.scorecardresearch.com", "oisd_small"),
    ("mobile.pipe.aria.microsoft.com", "hagezi_pro"),
    ("settings-win.data.microsoft.com", "hagezi_pro"),
    ("unityads.unity3d.com", "oisd_small"),
    ("api2.branch.io", "hagezi_pro"),
    ("ib.adnxs.com", "oisd_small"),
    ("static.criteo.net", "oisd_small"),
    ("cdn.taboola.com", "oisd_small"),
    ("widgets.outbrain.com", "oisd_small"),
    ("samsung-ads.com", "hagezi_pro"),
    ("log-config.samsungqbe.com", "hagezi_pro"),
    ("firebaselogging-pa.googleapis.com", "hagezi_pro"),
)

# The untrusted camera's own traffic. Lens (SPEC addendum B) is demoed by pointing a phone at
# this device, and "Talking to" is the section that makes the x-ray idea land — so the one device
# the demo is built around must not have an empty one. These rows are additive: they are NOT drawn
# from DNS_TOTAL_QUERIES, so every share, block rate and narrated figure elsewhere is unchanged.
# Reserved .example TLD (RFC 2606) throughout, so nobody real is being accused.
CAMERA_ALLOWED_DOMAINS: tuple[str, ...] = (
    "device-gateway.ipcam-vendor.example",
    "ntp.ipcam-vendor.example",
    "fw-update.ipcam-vendor.example",
)
CAMERA_BLOCKED_DOMAINS: tuple[tuple[str, str], ...] = (
    ("telemetry-collect.ipcam-vendor.example", "hagezi_pro"),
    ("stats.device-analytics.example", "oisd_small"),
)
#: The beacon that makes the point: an outdated camera quietly talking to a sinkholed host.
CAMERA_THREAT_DOMAIN = "cam-relay-node.example"

# Reserved .example TLD (RFC 2606): can never be registered, so nobody real is being accused.
MALICIOUS_DOMAINS: tuple[tuple[str, str, str], ...] = (
    # (domain, client, why)
    ("secure-appleid-verify.example", "192.168.1.32", "phishing kit reported by 12 engines"),
    ("cdn-update-delivery.example", "192.168.1.35", "malware distribution host (ThreatFox)"),
    (CAMERA_THREAT_DOMAIN, CAMERA_IP, "botnet relay node (URLhaus)"),
)

DENY_OVERRIDE_DOMAIN = "log-config.samsungqbe.com"
ALLOW_OVERRIDE_DOMAIN = "fw-updates.ring.com"

DNS_CLIENT_WEIGHTS: tuple[tuple[str, float, float], ...] = (
    # (client ip, share of traffic, share of that client's traffic that is blocked)
    ("192.168.1.40", 0.19, 0.47),   # smart TV: the worst offender
    ("192.168.1.32", 0.16, 0.34),   # Ellie's iPhone
    ("192.168.1.20", 0.14, 0.22),   # HOME-PC
    ("192.168.1.35", 0.12, 0.41),   # kitchen tablet
    ("192.168.1.30", 0.10, 0.24),   # Dad's iPhone
    ("192.168.1.31", 0.09, 0.23),   # Mum's iPhone
    ("192.168.1.21", 0.07, 0.18),   # MacBook Air
    ("192.168.1.41", 0.04, 0.10),   # Sonos kitchen
    ("192.168.1.60", 0.04, 0.08),   # Ring doorbell
    ("192.168.1.81", 0.03, 0.14),   # Echo
    ("192.168.1.22", 0.02, 0.16),   # MacBook Pro
)

# The rolling 24 h window keeps sliding between `seed_demo.py` and `capture.py`, and the
# older end of it drops out at roughly three queries a minute, so the seed has to overshoot
# the number the video says out loud. 2,660 seeded measures ~2,610 by the time the shots are
# taken, which is what script.DNS_QUERIES_24H_SPOKEN ("about twenty-six hundred") claims.
DNS_TOTAL_QUERIES = 2660


# --------------------------------------------------------------------------- writing


def _write_many(conn: sqlite3.Connection, sql: str, rows: Sequence[Sequence[Any]], counts: Counts,
                table: str) -> None:
    if not rows:
        return
    hdb.writemany(conn, sql, rows)
    counts.note(table, len(rows))


def seed_settings(conn: sqlite3.Connection, counts: Counts) -> None:
    """Config overrides live in the demo database itself (defaults < config.toml < settings).

    This is what keeps the video independent of whatever is in the author's real ``config.toml``:
    the SSID, the LAN range, the public IP and the DNS setup all come from here.
    """
    values: dict[str, Any] = {
        "general.name": "Home SOC",
        "web.host": "127.0.0.1",
        "web.port": 8787,
        "web.token": "",                     # no login wall in the capture
        "web.refresh_seconds": 15,
        "network.cidr": LAN_CIDR,
        "network.gateway": GATEWAY_IP,
        "network.exclude": [],
        "scan.use_nmap": True,
        "scan.nmap_top_ports": 1000,
        "scan.nmap_timing": "T3",
        "scan.version_detection": True,
        "scan.gentle_top_ports": 100,
        "scan.per_host_timeout_sec": 120,
        "scan.max_parallel_hosts": 8,
        "scan.scan_gateway": True,
        "dns.enabled": True,
        "dns.listen": "0.0.0.0",
        # 53, the shipped default in config.example.toml. The capture harness never binds the
        # resolver at all — capture.py starts the dashboard with `homesoc serve`, which passes
        # with_dns=False whatever the config says, and fakes the three "running" indicators with
        # RESOLVER_RUNNING_JS — so the port here is only ever a rendered string. It must therefore
        # be the port a reader should actually use: README's troubleshooting section tells them to
        # avoid 5353 and 5355 (mDNS and LLMNR), so a screenshot showing 5353 would model the one
        # setup the docs warn against.
        "dns.port": 53,
        # 1.1.1.2 is Cloudflare's malware-blocking resolver — the same pair config.example.toml
        # ships with, and what the architecture slide names. Do not "simplify" this to 1.1.1.1.
        "dns.upstreams": ["1.1.1.2", "9.9.9.9"],
        "dns.doh_upstream": "https://cloudflare-dns.com/dns-query",
        "dns.block_mode": "null",
        "dns.cache_max_entries": 20000,
        "dns.lists": list(DNS_ACTIVE_LISTS),
        "dns.log_queries": True,
        "dns.log_retention_days": 14,
        # A syntactically valid but entirely fictional key. It is never echoed back (settings.html
        # renders secrets as a "set" badge), and without it the /dns card reads
        # "VirusTotal today: 37 / 400 (no key)" — a counter that could not exist with no key.
        # Written as a repeated word rather than a literal 64-hex string so secret scanners
        # (GitHub secret scanning, gitleaks, truffleHog) have nothing to match on.
        "dns.virustotal_api_key": "deadbeef" * 8,
        "dns.virustotal_daily_budget": 400,
        "dns.urlhaus_auth_key": "",
        "dns.reputation_min_malicious_votes": 3,
        "dns.reputation_ttl_hours": 168,
        "notify.min_severity": "high",
        "notify.ntfy_url": "",
        "notify.discord_webhook": "",
        "notify.webhook_url": "",
        "notify.windows_toast": True,
        "notify.digest_hour": 8,
        # No schedule.* overrides. The narration and the architecture slide both quote the
        # shipped defaults (discovery 10 min, services + vulns 24 h, host 6 h, exposure 12 h,
        # feeds 6 h), so the Settings page must show those defaults rather than a set of
        # invented overrides that contradict the voice twenty seconds later. JOBS and
        # SCAN_CADENCE below are derived from the same numbers.
    }

    defender_status = {
        "AntivirusEnabled": True,
        "AMServiceEnabled": True,
        "AMRunningMode": "Normal",
        "RealTimeProtectionEnabled": True,
        "BehaviorMonitorEnabled": True,
        "IoavProtectionEnabled": True,
        # api.host_data reads this with `a or b`, so a literal 0 renders as "?"; the signatures
        # really are a day old here, which is well inside the 3-day threshold.
        "AntivirusSignatureAge": 1,
        "AntivirusSignatureVersion": "1.441.708.0",
        "AntivirusSignatureLastUpdated": iso_ago(hours=26.2),
        "AMEngineVersion": "1.1.25080.3",
        "AMProductVersion": "4.18.25080.5",
        "IsTamperProtected": False,
        "MAPSReporting": 2,
        "PUAProtection": 1,
        "QuickScanAge": 0,
        # The Host page prints these verbatim, so store the readable form PowerShell's
        # ConvertTo-Json produces for a local DateTime rather than a 27-character ISO stamp.
        "QuickScanEndTime": ago(hours=11.5).strftime("%Y-%m-%d %H:%M"),
        "FullScanAge": 6,
        "FullScanEndTime": ago(days=6.1).strftime("%Y-%m-%d %H:%M"),
        "NISEnabled": True,
        "ComputerID": HOST_NAME,
    }
    updates_status = {
        "pending": [
            {"title": "2026-09 Cumulative Update for Windows 11 Version 25H2 for x64-based Systems",
             "kb": "KB5069122", "severity": "Important", "size_mb": 812},
            {"title": "Windows Malicious Software Removal Tool x64 - September 2026",
             "kb": "KB890830", "severity": "Moderate", "size_mb": 62},
            {"title": "Intel - System - 10.1.42.9", "kb": "", "severity": "Recommended", "size_mb": 4},
        ],
        "hotfix": {"last_id": "KB5065426", "last_installed": iso_ago(days=9.0)[:10]},
        "os": {"caption": "Windows 11 Home", "build": "26200.6584", "version": "25H2"},
        "history": {"last_cumulative_date": iso_ago(days=9.0)[:10],
                    "last_cumulative_title": "2026-08 Cumulative Update (KB5065426)"},
    }
    posture_status = {
        "listeners": [
            {"port": 135, "proto": "tcp", "address": "0.0.0.0", "pid": 1128, "process": "svchost.exe (RpcSs)"},
            {"port": 139, "proto": "tcp", "address": "192.168.1.20", "pid": 4, "process": "System"},
            {"port": 445, "proto": "tcp", "address": "0.0.0.0", "pid": 4, "process": "System"},
            {"port": 5040, "proto": "tcp", "address": "127.0.0.1", "pid": 6120, "process": "svchost.exe (CDPSvc)"},
            {"port": 8787, "proto": "tcp", "address": "127.0.0.1", "pid": 9042, "process": "python.exe (homesoc serve)"},
            {"port": 53, "proto": "udp", "address": "0.0.0.0", "pid": 9042, "process": "python.exe (homesoc dns)"},
        ],
        "hotfix": {"last_id": "KB5065426", "last_installed": iso_ago(days=9.0)[:10]},
    }
    wifi_status = {
        "ssid": SSID, "interface": "Wi-Fi", "authentication": "WPA2-Personal",
        "cipher": "CCMP", "band": "5 GHz", "channel": 44, "signal": "82%",
    }
    exposure_status = {
        "public_ip": PUBLIC_IP, "asn": "AS64496 Example Broadband", "country": "GB",
        "open_ports": [], "vulns": [], "checked_at": iso_ago(hours=9.4),
        "upnp_mappings": [
            {"protocol": "TCP", "external_port": 8443, "internal_client": CAMERA_IP,
             "internal_port": 80, "description": "IPCam Web"},
            {"protocol": "UDP", "external_port": 3074, "internal_client": "192.168.1.80",
             "internal_port": 3074, "description": "Nintendo Switch"},
            {"protocol": "TCP", "external_port": 32400, "internal_client": "192.168.1.22",
             "internal_port": 32400, "description": "Plex Media Server"},
        ],
    }

    values.update({
        "defender.status_json": jdump(defender_status),
        "defender.threats_json": jdump([
            {"name": "Trojan:Win32/Wacatac.B!ml",
             "detail": r"file: C:\Users\home\Downloads\invoice_2026_08.pdf.exe",
             "seen": ago(days=12.2).strftime("%Y-%m-%d %H:%M"), "action": "Quarantined"},
        ]),
        "defender.checked_at": iso_ago(hours=5.2),
        "updates.status_json": jdump(updates_status),
        "updates.last_hotfix": f"KB5065426 ({iso_ago(days=9.0)[:10]})",
        "host.posture_json": jdump(posture_status),
        "wifi.status_json": jdump(wifi_status),
        "exposure.status_json": jdump(exposure_status),
        "exposure.public_ip": PUBLIC_IP,
        f"vt.budget.{NOW.strftime('%Y-%m-%d')}": "37",
    })

    rows = [(k, hdb._setting_text(v), iso_ago(hours=1.0)) for k, v in values.items()]
    _write_many(
        conn,
        "INSERT INTO settings(key, value, updated_at) VALUES(?,?,?) "
        "ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at",
        rows, counts, "settings",
    )


def seed_feeds(conn: sqlite3.Connection, counts: Counts) -> None:
    rows = [
        (name, url, kind, f'W/"{RNG.getrandbits(48):012x}"',
         iso_ago(hours=updated_h), iso_ago(hours=checked_h), iso_ago(hours=updated_h),
         "ok", size, entries, None, 1)
        for name, url, kind, entries, size, checked_h, updated_h in FEEDS
    ]
    _write_many(
        conn,
        "INSERT INTO feeds(name, url, kind, etag, last_modified, last_checked, last_updated, "
        "status, bytes, entries, error, enabled) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
        rows, counts, "feeds",
    )


def seed_devices(conn: sqlite3.Connection, counts: Counts) -> dict[str, int]:
    ids: dict[str, int] = {}
    for spec in DEVICES:
        ids[spec.key] = hdb.write(
            conn,
            "INSERT INTO devices(mac, ip, hostname, vendor, kind, nickname, trusted, notes, "
            "first_seen, last_seen, online, last_service_scan, mdns_services) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (spec.mac, spec.ip, spec.hostname, spec.vendor, spec.kind, spec.nickname,
             1 if spec.trusted else 0, spec.notes,
             iso_ago(days=spec.first_seen_days), iso_ago(minutes=spec.last_seen_minutes),
             1 if spec.online else 0, iso_ago(hours=2.4),
             jdump(list(spec.mdns)) if spec.mdns else None),
        )
    counts.note("devices", len(ids))
    return ids


def seed_sightings(conn: sqlite3.Connection, ids: dict[str, int], counts: Counts) -> None:
    """Seven days of discovery hits, so every device page has a presence strip."""
    rows: list[tuple[Any, ...]] = []
    for spec in DEVICES:
        device_id = ids[spec.key]
        # One sighting every ~2 hours while the device was around.
        for step in range(84):
            hours_back = step * 2.0 + RNG.uniform(-0.4, 0.4)
            if hours_back > spec.first_seen_days * 24:
                break
            if not spec.online and hours_back < spec.last_seen_minutes / 60.0:
                continue
            if spec.kind in ("phone", "tablet", "computer") and RNG.random() < 0.22:
                continue  # people take these out of the house
            rows.append((device_id, spec.ip, iso_ago(hours=hours_back),
                         "arp" if RNG.random() < 0.7 else "tcp"))
    _write_many(
        conn,
        "INSERT INTO device_sightings(device_id, ip, seen_at, method) VALUES(?,?,?,?)",
        rows, counts, "device_sightings",
    )


def seed_services(conn: sqlite3.Connection, ids: dict[str, int],
                  counts: Counts) -> dict[tuple[str, int], int]:
    service_ids: dict[tuple[str, int], int] = {}
    n = 0
    for spec in DEVICES:
        for svc in spec.services:
            row_id = hdb.write(
                conn,
                "INSERT INTO services(device_id, port, proto, state, name, product, version, "
                "extrainfo, cpe, tunnel, first_seen, last_seen) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                (ids[spec.key], svc.port, svc.proto, svc.state, svc.name, svc.product, svc.version,
                 svc.extrainfo, svc.cpe, svc.tunnel,
                 iso_ago(days=min(spec.first_seen_days, 120.0)), iso_ago(hours=2.4)),
            )
            service_ids.setdefault((spec.key, svc.port), row_id)
            n += 1
    counts.note("services", n)
    return service_ids


def seed_vulns(conn: sqlite3.Connection, ids: dict[str, int],
               service_ids: dict[tuple[str, int], int], counts: Counts) -> None:
    rows = [
        (ids[v.device_key], service_ids.get((v.device_key, v.port)), v.cve, v.source,
         1 if v.kev else 0, v.cvss, v.epss, v.title, v.published, v.matched_on, v.remediation,
         iso_ago(days=v.first_seen_days), iso_ago(hours=2.3))
        for v in VULNS
    ]
    _write_many(
        conn,
        "INSERT INTO vulns(device_id, service_id, cve, source, kev, cvss, epss, title, published, "
        "matched_on, remediation, first_seen, last_seen) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
        rows, counts, "vulns",
    )


def seed_host_checks(conn: sqlite3.Connection, counts: Counts) -> None:
    checked = iso_ago(hours=5.2)
    rows = [(cid, status, value, expected, checked, 1 if needs_admin else 0)
            for cid, status, value, expected, needs_admin in HOST_CHECKS]
    _write_many(
        conn,
        "INSERT INTO host_checks(check_id, status, value, expected, checked_at, needs_admin) "
        "VALUES(?,?,?,?,?,?)",
        rows, counts, "host_checks",
    )


def seed_software(conn: sqlite3.Connection, counts: Counts) -> None:
    seen = iso_ago(hours=14.4)
    rows = [(name, version, available, "winget", package_id, seen)
            for name, version, available, package_id in SOFTWARE]
    _write_many(
        conn,
        "INSERT INTO software(name, version, available, source, publisher, seen_at) "
        "VALUES(?,?,?,?,?,?)",
        rows, counts, "software",
    )


def seed_persistence(conn: sqlite3.Connection, counts: Counts) -> None:
    rows = [(kind, name, command, location, iso_ago(days=first_days), iso_ago(hours=5.2),
             1 if baseline else 0)
            for kind, name, command, location, baseline, first_days in PERSISTENCE]
    _write_many(
        conn,
        "INSERT INTO persistence(kind, name, command, location, first_seen, last_seen, baseline) "
        "VALUES(?,?,?,?,?,?,?)",
        rows, counts, "persistence",
    )


def seed_file_checks(conn: sqlite3.Connection, counts: Counts) -> None:
    rows = [(sha, path, size, iso_ago(days=days), verdict, source, detail)
            for sha, path, size, days, verdict, source, detail in FILE_CHECKS]
    _write_many(
        conn,
        "INSERT INTO file_checks(sha256, path, size, first_seen, verdict, source, detail) "
        "VALUES(?,?,?,?,?,?,?)",
        rows, counts, "file_checks",
    )


# --------------------------------------------------------------------------- findings


class _Draft:
    """The shape ``catalog.render`` / ``engine.dedupe_key`` expect from a scanner."""

    def __init__(self, spec: FindingSpec) -> None:
        self.finding_id = spec.finding_id
        self.subject = spec.subject
        self.evidence = dict(spec.evidence)
        self.severity = spec.severity
        self.detail = None


def validate_findings(specs: Iterable[FindingSpec]) -> list[str]:
    """Every ID must exist and every placeholder must resolve, or the video shows 'unknown'."""
    problems: list[str] = []
    for spec in specs:
        if catalog.get(spec.finding_id) is None:
            problems.append(f"{spec.finding_id}: not in the catalog")
            continue
        missing = catalog.unresolved_placeholders(spec.finding_id, spec.evidence, spec.subject)
        if missing:
            problems.append(f"{spec.finding_id} ({spec.subject}): unresolved {missing}")
        title, detail = catalog.render(_Draft(spec))
        if "{" in title or "{" in (detail or ""):
            problems.append(f"{spec.finding_id}: unfilled brace in {title!r}")
    return problems


def seed_findings(conn: sqlite3.Connection, ids: dict[str, int], counts: Counts) -> None:
    events: list[tuple[Any, ...]] = []
    n = 0
    for spec in ALL_FINDINGS:
        draft = _Draft(spec)
        title, detail = catalog.render(draft)
        if spec.detail:
            detail = spec.detail
        severity = catalog.severity_for(draft)
        key = fengine.dedupe_key(draft)
        first_seen = ago(days=spec.first_seen_days)
        device_id = ids[spec.device_key] if spec.device_key else None

        if spec.status == "resolved":
            resolved = first_seen + timedelta(hours=spec.resolved_after_hours or 12.0)
            last_seen, resolved_at = resolved, iso(resolved)
        else:
            last_seen, resolved_at = ago(hours=2.3), None

        occurrences = spec.occurrences or 1
        row_id = hdb.write(
            conn,
            "INSERT INTO findings(finding_id, subject, dedupe_key, severity, title, detail, "
            "evidence, status, source, first_seen, last_seen, resolved_at, occurrences, device_id) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (spec.finding_id, spec.subject, key, severity, title, detail, jdump(spec.evidence),
             spec.status, spec.source, iso(first_seen), iso(last_seen), resolved_at,
             occurrences, device_id),
        )
        n += 1

        events.append((row_id, "opened", iso(first_seen), None))
        if spec.status == "resolved":
            events.append((row_id, spec.how, resolved_at,
                           spec.note or ("verified by rescan" if spec.how == "auto_resolved" else None)))
        elif spec.status in ("acknowledged", "suppressed"):
            at = (ago(days=spec.status_changed_days) if spec.status_changed_days is not None
                  else first_seen + timedelta(hours=RNG.uniform(3.0, 30.0)))
            events.append((row_id, spec.status, iso(at), spec.note))
        elif spec.reopened_days is not None:
            gone = first_seen + timedelta(days=(spec.first_seen_days - spec.reopened_days) / 2.0)
            events.append((row_id, "auto_resolved", iso(gone), "verified by rescan"))
            events.append((row_id, "reopened", iso_ago(days=spec.reopened_days),
                           "seen again after a Windows feature update"))

    counts.note("findings", n)
    _write_many(
        conn,
        "INSERT INTO finding_events(finding_row_id, event, at, note) VALUES(?,?,?,?)",
        events, counts, "finding_events",
    )


# --------------------------------------------------------------------------- scans / jobs / events


def seed_scans(conn: sqlite3.Connection, counts: Counts) -> None:
    summaries: dict[str, dict[str, Any]] = {
        "discovery": {"devices": 18, "online": 17, "new": 0},
        "services": {"hosts": 17, "services": 38, "findings": 12},
        "vulns": {"services": 38, "cves": 7, "kev": 1},
        "host": {"checks": len(HOST_CHECKS), "fail": 9, "needs_admin": 2},
        "exposure": {"public_ports": 0, "upnp_mappings": 3, "findings": 2},
        "feeds": {"feeds": len(FEEDS), "updated": 4, "bytes": 8_314_112},
        "files": {"files": 4, "new": 0, "malicious": 0},
    }
    durations = {"discovery": 4.7, "services": 96.4, "vulns": 11.2, "host": 38.9,
                 "exposure": 9.8, "feeds": 27.6, "files": 6.1}
    rows: list[tuple[Any, ...]] = []
    for kind, every_hours, max_rows in SCAN_CADENCE:
        step = 0
        while True:
            hours_back = step * every_hours + (0.15 if kind != "discovery" else 0.05)
            if hours_back > SCAN_HISTORY_DAYS * 24:
                break
            if max_rows and step >= max_rows:
                break
            step += 1
            started = ago(hours=hours_back)
            took = durations[kind] * RNG.uniform(0.82, 1.24)
            summary = dict(summaries[kind])
            if kind == "discovery" and hours_back < 84:
                summary["new"] = 1 if 78 < hours_back < 84 else 0
            failed = kind == "exposure" and 200 < hours_back < 230
            error = "upstream lookup timed out after 20 s" if failed else None
            rows.append((
                kind, iso(started), iso(started + timedelta(seconds=took)),
                "error" if failed else "ok",
                None if failed else jdump(summary),
                error,
            ))
    rows.sort(key=lambda r: r[1])  # scans_list orders by id DESC; insert oldest-first
    _write_many(
        conn,
        "INSERT INTO scans(kind, started_at, finished_at, status, summary, error) VALUES(?,?,?,?,?,?)",
        rows, counts, "scans",
    )


def seed_jobs(conn: sqlite3.Connection, counts: Counts) -> None:
    rows = [
        (name, iso_ago(hours=last_h), "ok", duration,
         iso(ago(hours=last_h) + timedelta(hours=every_h)), runs, failures,
         last_error if failures else None)
        for name, every_h, duration, runs, failures, last_h, last_error in JOBS
    ]
    _write_many(
        conn,
        "INSERT INTO jobs(name, last_run, last_status, last_duration_sec, next_run, runs, failures, "
        "last_error) VALUES(?,?,?,?,?,?,?,?)",
        rows, counts, "jobs",
    )


def seed_events(conn: sqlite3.Connection, counts: Counts) -> None:
    rows: list[tuple[Any, ...]] = []

    def event(hours: float, level: str, source: str, message: str, data: dict | None = None) -> None:
        rows.append((iso_ago(hours=hours), level, source, message, jdump(data) if data else None))

    # Recent, so the overview's "latest events" card is full.
    event(0.10, "info", "scheduler", "discovery finished in 4.7 s (18 devices, 17 online)")
    event(0.35, "info", "scheduler", "score recorded", {"score": "see metrics"})
    event(0.36, "info", "dnsfilter", "hourly rollup written", {"rows": 11})
    event(0.9, "warning", "dnsfilter", "blocked a known-malicious domain for 192.168.1.32",
          {"domain": "secure-appleid-verify.example", "reason": "reputation"})
    event(2.3, "info", "vulns.matcher", "matched 38 services against KEV, NVD and EPSS: 7 CVEs, 1 KEV")
    event(2.4, "info", "scanners.ports", "service scan of 17 hosts finished in 96 s")
    event(3.4, "info", "feeds", "updated urlhaus (2,146 entries), threatfox (1,089 entries)")
    event(5.2, "info", "scanners.host_windows", "posture scan: 9 failing checks, 2 need administrator")
    event(5.2, "info", "defender", "Defender status read: real-time protection on, signatures 0 days old")
    event(6.2, "info", "feeds", "kev catalogue is current (1,367 entries)")
    event(9.4, "warning", "scanners.exposure",
          "UPnP mapping found: WAN 8443 -> 192.168.1.142:80 (IPCam Web)")
    event(11.5, "info", "defender", "quick scan finished, nothing found")
    event(14.4, "info", "scanners.files", "hashed 4 files in Downloads, nothing new")
    event(19.0, "warning", "dnsfilter", "blocked a known-malicious domain for 192.168.1.32",
          {"domain": "secure-appleid-verify.example", "reason": "reputation"})
    event(20.4, "info", "housekeeping", "purged 41,208 dns_queries rows older than 14 days")
    event(26.0, "warning", "dnsfilter", "blocked a known-malicious domain for 192.168.1.35",
          {"domain": "cdn-update-delivery.example", "reason": "reputation"})
    event(38.0, "info", "notify", "digest sent to 1 channel")
    event(48.0, "info", "scanners.discovery", "new device on the network: 192.168.1.142")
    event(74.0, "warning", "scanners.ports", "Telnet is open on 192.168.1.142:23")
    event(81.6, "info", "scanners.discovery", "new device on the network: 192.168.1.142")
    event(214.0, "error", "scanners.exposure", "InternetDB lookup failed: upstream lookup timed out after 20 s")
    event(220.0, "info", "findings", "CVE-2023-1389 matched the router and is in the CISA KEV catalogue")
    event(24 * 12.2, "warning", "defender",
          r"quarantined Trojan:Win32/Wacatac.B!ml in C:\Users\home\Downloads\invoice_2026_08.pdf.exe",
          {"threat": "Trojan:Win32/Wacatac.B!ml", "action": "Quarantined"})
    event(24 * 12.4, "info", "scanners.files", "new download flagged by VirusTotal: 41/72 engines")
    event(24 * 18.0, "info", "findings", "3 findings auto-resolved after a rescan")
    event(24 * 27.5, "warning", "defender", "real-time protection is off")

    # telemetry_events and the overview's "latest events" card order by id DESC, so the rows have
    # to go in oldest-first or the newest event ends up at the bottom of the list.
    rows.sort(key=lambda r: r[0])
    _write_many(
        conn,
        "INSERT INTO events(ts, level, source, message, data) VALUES(?,?,?,?,?)",
        rows, counts, "events",
    )


def seed_notifications(conn: sqlite3.Connection, counts: Counts) -> None:
    items: tuple[tuple[float, str, str, str, str | None], ...] = (
        (0.9, "ntfy", "high: 192.168.1.32 tried to reach a malicious domain", "ok", None),
        (9.4, "ntfy", "high: UPnP port mapping WAN 8443 -> 192.168.1.142:80", "ok", None),
        (38.0, "ntfy", "Daily digest: 32 open findings, score 13", "ok", None),
        (74.0, "windows_toast", "critical: Telnet open on 192.168.1.142:23", "ok", None),
        (74.0, "ntfy", "critical: Telnet open on 192.168.1.142:23", "ok", None),
        (24 * 9.2, "ntfy", "critical: Known exploited vulnerability CVE-2023-1389 on 192.168.1.1", "ok", None),
        (24 * 12.2, "ntfy", "critical: Malicious file in Downloads", "ok", None),
        (24 * 12.2, "discord", "critical: Malicious file in Downloads", "error",
         "HTTP 429 from the webhook (rate limited)"),
        (24 * 27.5, "ntfy", "critical: Defender real-time protection is off", "ok", None),
    )
    rows = [(iso_ago(hours=h), channel, subject, status, error)
            for h, channel, subject, status, error in items]
    _write_many(
        conn,
        "INSERT INTO notifications(ts, channel, subject, status, error) VALUES(?,?,?,?,?)",
        rows, counts, "notifications",
    )


# --------------------------------------------------------------------------- metrics


def seed_metrics(conn: sqlite3.Connection, final_score: int, counts: Counts) -> None:
    """Thirty days of hourly score samples ending exactly at the live score.

    The curve rises — this household has been working the list — with a visible step up at each
    remediation, so the sparkline and the summary page tell the same story.
    """
    resolutions = sorted(
        (spec.first_seen_days - (spec.resolved_after_hours or 0.0) / 24.0)
        for spec in RESOLVED
    )  # days before now, newest last
    start = max(3.0, final_score - 12.0)
    rows: list[tuple[Any, ...]] = []
    for hour in range(30 * 24, -1, -1):
        days_back = hour / 24.0
        fraction = 1.0 - (days_back / 30.0)
        value = start + (final_score - start) * (fraction ** 0.85)
        # A remediation that has already happened at this point in history nudges the line up.
        done = sum(1 for r in resolutions if r >= days_back)
        value += 0.35 * done - 0.35 * len(resolutions) * fraction
        value += math.sin(hour / 7.0) * 0.4
        rows.append((iso_ago(hours=hour), "score", round(max(1.0, min(100.0, value)), 1), None))
    rows[-1] = (iso_ago(hours=0), "score", float(final_score), None)

    # These two series are what /telemetry offers as ground truth, so their newest sample has to
    # equal what every other page reports. Both are anchored on the rows actually seeded rather
    # than on an independent random walk, and both move like a household rather than like noise:
    # phones and the tablet drop off Wi-Fi overnight, and the backlog falls as findings are fixed.
    online_now = int(conn.execute("SELECT count(*) FROM devices WHERE online=1").fetchone()[0])
    open_now = int(conn.execute("SELECT count(*) FROM findings WHERE status='open'").fetchone()[0])

    for hour in range(7 * 24, -1, -1):
        hour_of_day = (NOW - timedelta(hours=hour)).hour
        if 1 <= hour_of_day < 6:          # everyone asleep, phones off Wi-Fi
            online = online_now - 3
        elif hour_of_day in (0, 6, 7, 23):  # the shoulders of the night
            online = online_now - 1
        else:
            online = online_now
        # a device dropping off for one sample now and then, but rarely: the point of the
        # series is that a viewer can see the house go to sleep, not that it looks busy
        if hour > 1 and RNG.random() < 0.06:
            online -= 1
        rows.append((iso_ago(hours=hour), "devices.online", float(max(1, online)), None))

    for day in range(30, -1, -1):
        # a month ago the backlog was ~14 higher; it comes down to exactly today's open count
        value = open_now + day // 2 + (RNG.randint(0, 1) if day else 0)
        rows.append((iso_ago(days=day), "findings.open", float(value), None))
    for hour in range(24, -1, -1):
        rows.append((iso_ago(hours=hour), "host.checks_fail", 9.0, None))
    for name, _every, duration, _runs, _fail, _last, _err in JOBS[:6]:
        for step in range(24):
            rows.append((iso_ago(hours=step * 2.0 + 0.2), "job.duration",
                         round(duration * RNG.uniform(0.8, 1.25), 2), jdump({"job": name})))

    _write_many(
        conn, "INSERT INTO metrics(ts, name, value, tags) VALUES(?,?,?,?)", rows, counts, "metrics"
    )


# --------------------------------------------------------------------------- DNS


def _diurnal_weight(hour_of_day: int) -> float:
    """Household traffic: quiet at 04:00, busy at 20:00."""
    return 0.35 + 0.65 * (1.0 + math.cos((hour_of_day - 20) / 24.0 * 2 * math.pi)) / 2.0


def seed_dns(conn: sqlite3.Connection, counts: Counts) -> None:
    """Twenty-four hours of resolver traffic: quiet allows, bursty blocks.

    Blocks are generated as *bursts* — one client hammering one tracker inside one hour — rather
    than uniformly at random, because that is what real ad traffic looks like (an app opens, it
    fires twenty beacons) and because the activity feed groups DNS blocks by
    (client, registrable domain, hour). Random blocks produce four hundred "Blocked 1 request to…"
    rows that bury every other kind of event; bursts produce a few dozen readable ones.
    """
    clients = [c for c, _, _ in DNS_CLIENT_WEIGHTS]
    weights = [w for _, w, _ in DNS_CLIENT_WEIGHTS]
    block_bias = {c: b for c, _, b in DNS_CLIENT_WEIGHTS}
    qtypes = ("A", "A", "A", "AAAA", "AAAA", "HTTPS", "PTR", "TXT")

    hour_weights = [_diurnal_weight((NOW - timedelta(hours=h)).hour) for h in range(24)]
    total_weight = sum(hour_weights)
    rows: list[tuple[Any, ...]] = []

    # --- allowed and cached traffic, spread over every client -----------------------------
    allowed_total = int(DNS_TOTAL_QUERIES * 0.70)
    for hours_back in range(24):
        share = hour_weights[hours_back] / total_weight
        for _ in range(max(8, int(allowed_total * share))):
            client = RNG.choices(clients, weights)[0]
            domain = RNG.choice(ALLOWED_DOMAINS)
            cached = RNG.random() < 0.35
            rows.append((
                iso_ago(hours=hours_back, minutes=RNG.uniform(0, 60)), client, domain,
                RNG.choice(qtypes), "cache" if cached else "allow", "default",
                round(RNG.uniform(0.2, 1.1) if cached else RNG.uniform(6.0, 48.0), 2),
            ))

    # --- blocked traffic, in bursts -------------------------------------------------------
    # Each client keeps to a handful of trackers, the way a real device does: the TV talks to
    # Samsung's ad endpoints, the phones to app-measurement and Branch, and so on.
    favourites: dict[str, list[tuple[str, str]]] = {}
    for index, client in enumerate(clients):
        picks = [BLOCKED_DOMAINS[(index * 3 + step) % len(BLOCKED_DOMAINS)] for step in range(4)]
        favourites[client] = picks
    # Weight by traffic share *times* block bias, so a device that barely uses the network never
    # ends up with a 60% block rate in the top-clients table.
    block_clients = [c for c, _, bias in DNS_CLIENT_WEIGHTS if bias >= 0.14]
    block_weights = [w * b for _, w, b in DNS_CLIENT_WEIGHTS if b >= 0.14]

    blocked_total = int(DNS_TOTAL_QUERIES * 0.275)
    per_hour = blocked_total / 24.0
    for hours_back in range(24):
        budget = max(4, int(per_hour * hour_weights[hours_back] * 24.0 / total_weight))
        while budget > 0:
            client = RNG.choices(block_clients, block_weights)[0]
            domain, source = RNG.choice(favourites[client])
            hits = min(budget, RNG.randint(6, 22))
            budget -= hits
            start_minute = RNG.uniform(0, 52)
            for hit in range(hits):
                rows.append((
                    iso_ago(hours=hours_back, minutes=start_minute + hit * RNG.uniform(0.05, 0.4)),
                    client, domain, RNG.choice(qtypes), "block", f"list:{source}",
                    round(RNG.uniform(0.1, 0.6), 2),
                ))

    # The TV's manual deny, so the overrides table visibly does something.
    for hours_back in (1.4, 5.6, 9.1, 13.7, 18.2, 21.8):
        for hit in range(RNG.randint(5, 11)):
            rows.append((iso_ago(hours=hours_back, minutes=hit * 0.7), "192.168.1.40",
                         DENY_OVERRIDE_DOMAIN, "A", "block", "override:deny",
                         round(RNG.uniform(0.1, 0.4), 2)))
    for hours_back in (1.2, 4.8, 10.4, 16.9, 22.1):
        rows.append((iso_ago(hours=hours_back), "192.168.1.60", ALLOW_OVERRIDE_DOMAIN, "A",
                     "allow", "override:allow", round(RNG.uniform(8.0, 30.0), 2)))

    # --- the two reputation blocks the video points at ------------------------------------
    # A phishing page tapped a few times on one phone, and a malware host beaconing all day from
    # the tablet. Each of these rows becomes its own "Blocked a known-malicious domain" feed item.
    for hours_back in (0.9, 6.4, 6.5, 19.0, 19.1):
        rows.append((iso_ago(hours=hours_back), "192.168.1.32", MALICIOUS_DOMAINS[0][0], "A",
                     "block", "reputation", round(RNG.uniform(0.1, 0.5), 2)))
    for step in range(18):
        rows.append((iso_ago(hours=0.6 + step * 1.3), "192.168.1.35", MALICIOUS_DOMAINS[1][0], "A",
                     "block", "reputation", round(RNG.uniform(0.1, 0.5), 2)))

    # --- the untrusted camera (Lens demo subject, SPEC addendum B) -------------------------
    # Additive, so no other client's share moves. A cheap camera behaves exactly like this:
    # a steady NTP/keep-alive heartbeat to its vendor, a telemetry endpoint the block lists
    # already know about, and — the reason anyone cares — a beacon to a sinkholed relay.
    for hours_back in range(24):
        for _ in range(RNG.randint(2, 5)):
            rows.append((
                iso_ago(hours=hours_back, minutes=RNG.uniform(0, 60)), CAMERA_IP,
                RNG.choice(CAMERA_ALLOWED_DOMAINS), RNG.choice(("A", "A", "AAAA")),
                "cache" if RNG.random() < 0.3 else "allow", "default",
                round(RNG.uniform(0.2, 40.0), 2),
            ))
    for hours_back in range(0, 24, 2):
        domain, source = CAMERA_BLOCKED_DOMAINS[(hours_back // 2) % len(CAMERA_BLOCKED_DOMAINS)]
        for hit in range(RNG.randint(4, 9)):
            rows.append((
                iso_ago(hours=hours_back, minutes=hit * RNG.uniform(0.2, 0.9)), CAMERA_IP, domain,
                "A", "block", f"list:{source}", round(RNG.uniform(0.1, 0.6), 2),
            ))
    for step in range(14):
        rows.append((iso_ago(hours=0.3 + step * 1.7), CAMERA_IP, CAMERA_THREAT_DOMAIN, "A",
                     "block", "reputation", round(RNG.uniform(0.1, 0.5), 2)))

    # --- the newest minutes -----------------------------------------------------------------
    # dns_log() orders by id DESC and the rows below are inserted in timestamp order, so these
    # are the first rows on the live query log — the shot scene 10 holds for its last ten
    # seconds, in the scene whose entire subject is blocking. Everything above is generated
    # with a start-minute drawn uniformly from the hour, which left the top of the log as a
    # column of ALLOW / default and not one block in frame. These put both kinds of block
    # (a public list, and a sinkholed malicious domain) at the top where the eye lands.
    recent: tuple[tuple[float, str, str, str, str], ...] = (
        (0.4, "192.168.1.35", MALICIOUS_DOMAINS[1][0], "block", "reputation"),
        (0.8, "192.168.1.31", BLOCKED_DOMAINS[0][0], "block", f"list:{BLOCKED_DOMAINS[0][1]}"),
        (1.1, "192.168.1.31", BLOCKED_DOMAINS[0][0], "block", f"list:{BLOCKED_DOMAINS[0][1]}"),
        (1.6, "192.168.1.40", DENY_OVERRIDE_DOMAIN, "block", "override:deny"),
        (2.2, "192.168.1.32", MALICIOUS_DOMAINS[0][0], "block", "reputation"),
        (2.9, "192.168.1.40", BLOCKED_DOMAINS[1][0], "block", f"list:{BLOCKED_DOMAINS[1][1]}"),
        (3.4, "192.168.1.40", BLOCKED_DOMAINS[1][0], "block", f"list:{BLOCKED_DOMAINS[1][1]}"),
    )
    for minutes, client, domain, action, reason in recent:
        rows.append((iso_ago(hours=0, minutes=minutes), client, domain, "A", action, reason,
                     round(RNG.uniform(0.1, 0.6), 2)))

    rows.sort(key=lambda r: r[0])
    _write_many(
        conn,
        "INSERT INTO dns_queries(ts, client, qname, qtype, action, reason, ms) VALUES(?,?,?,?,?,?,?)",
        rows, counts, "dns_queries",
    )

    hourly = hdb.query(
        conn,
        "SELECT substr(ts,1,13) || ':00' AS hour, client, COUNT(*) AS total, "
        "SUM(CASE WHEN action='block' THEN 1 ELSE 0 END) AS blocked FROM dns_queries "
        "GROUP BY hour, client",
    )
    _write_many(
        conn,
        "INSERT INTO dns_hourly(hour, client, total, blocked) VALUES(?,?,?,?) "
        "ON CONFLICT(hour, client) DO UPDATE SET total=excluded.total, blocked=excluded.blocked",
        [(r["hour"], r["client"], int(r["total"]), int(r["blocked"])) for r in hourly],
        counts, "dns_hourly",
    )

    _write_many(
        conn,
        "INSERT INTO dns_overrides(domain, action, note, created_at) VALUES(?,?,?,?)",
        [
            (ALLOW_OVERRIDE_DOMAIN, "allow", "Doorbell firmware updates stalled while this was blocked.",
             iso_ago(days=17.0)),
            (DENY_OVERRIDE_DOMAIN, "deny", "TV viewing-data collection; blocked on purpose.",
             iso_ago(days=9.0)),
            ("api2.branch.io", "deny", "Deep-link tracker used by three apps on the phones.",
             iso_ago(days=4.0)),
        ],
        counts, "dns_overrides",
    )

    reputation = [
        ("secure-appleid-verify.example", "virustotal", "malicious", 12, 3, iso_ago(hours=0.9),
         jdump({"harmless": 41, "malicious": 12, "suspicious": 3, "undetected": 18})),
        ("cdn-update-delivery.example", "threatfox", "malicious", 9, 5, iso_ago(hours=3.2),
         jdump({"ioc_type": "domain", "malware": "unknown", "confidence": 75})),
        ("tracking.example", "virustotal", "suspicious", 1, 6, iso_ago(hours=8.0),
         jdump({"harmless": 52, "malicious": 1, "suspicious": 6, "undetected": 15})),
        ("open.spotify.com", "virustotal", "harmless", 0, 0, iso_ago(hours=11.0),
         jdump({"harmless": 68, "malicious": 0, "suspicious": 0, "undetected": 6})),
        ("gateway.icloud.com", "virustotal", "harmless", 0, 0, iso_ago(hours=13.0),
         jdump({"harmless": 70, "malicious": 0, "suspicious": 0, "undetected": 4})),
        ("fw-updates.ring.com", "virustotal", "harmless", 0, 0, iso_ago(hours=16.5),
         jdump({"harmless": 66, "malicious": 0, "suspicious": 0, "undetected": 8})),
        ("nflxvideo.net", "virustotal", "harmless", 0, 0, iso_ago(hours=21.0),
         jdump({"harmless": 64, "malicious": 0, "suspicious": 0, "undetected": 9})),
    ]
    _write_many(
        conn,
        "INSERT INTO reputation(domain, source, verdict, malicious, suspicious, checked_at, raw) "
        "VALUES(?,?,?,?,?,?,?)",
        reputation, counts, "reputation",
    )


# --------------------------------------------------------------------------- orchestration


def _guard_target(path: Path) -> None:
    resolved = path.resolve()
    if resolved == REAL_DATA_DIR or REAL_DATA_DIR in resolved.parents:
        raise SystemExit(
            f"refusing to write inside the real data directory: {resolved}\n"
            "The demo database must live under video/demo_data/."
        )


def _remove_db(path: Path) -> None:
    for suffix in ("", "-wal", "-shm", "-journal"):
        candidate = Path(str(path) + suffix)
        if candidate.exists():
            candidate.unlink()
            logger.info("removed %s", candidate.name)


def build(path: Path, *, force: bool) -> dict[str, Any]:
    _guard_target(path)
    if path.exists():
        if not force:
            raise SystemExit(f"{path} already exists — pass --force to rebuild it.")
        _remove_db(path)
    path.parent.mkdir(parents=True, exist_ok=True)

    problems = validate_findings(ALL_FINDINGS)
    if problems:
        raise SystemExit("finding specs are invalid:\n  " + "\n  ".join(problems))

    counts = Counts()
    conn = hdb.connect(path)  # init_schema runs here, so the schema is always the product's own
    try:
        seed_settings(conn, counts)
        seed_feeds(conn, counts)
        ids = seed_devices(conn, counts)
        seed_sightings(conn, ids, counts)
        service_ids = seed_services(conn, ids, counts)
        seed_vulns(conn, ids, service_ids, counts)
        seed_host_checks(conn, counts)
        seed_software(conn, counts)
        seed_persistence(conn, counts)
        seed_file_checks(conn, counts)
        seed_findings(conn, ids, counts)
        seed_scans(conn, counts)
        seed_jobs(conn, counts)
        seed_events(conn, counts)
        seed_notifications(conn, counts)
        seed_dns(conn, counts)

        score = scoremod.security_score(conn)
        seed_metrics(conn, score, counts)
        report = _report(conn, counts, score)
    finally:
        # Fold the write-ahead log back into the file so the shipped database is one self-contained
        # artefact that capture.py (or anyone) can copy without losing rows.
        try:
            conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        except sqlite3.Error:  # nothing to checkpoint after a failed build
            logger.debug("wal checkpoint skipped", exc_info=True)
        conn.close()
    return report


def _report(conn: sqlite3.Connection, counts: Counts, score: int) -> dict[str, Any]:
    from homesoc.web import summary as summarymod

    data = summarymod.build_summary(conn, days=30)
    totals = data["totals"]
    return {
        "score": score,
        "grade": scoremod.grade(score),
        "rows": dict(sorted(counts.rows.items())),
        "findings_open": totals["open"],
        "findings_resolved": totals["resolved"],
        "findings_acknowledged": totals["acknowledged"],
        "findings_suppressed": totals["suppressed"],
        "remediation_rate": totals["remediation_rate"],
        "median_hours_to_fix": data["time_to_remediate"]["median_hours"],
        "dns_block_rate": data["coverage"]["dns"]["block_rate"],
        "dns_queries_24h": data["coverage"]["dns"]["queries_24h"],
        "kev_matches": data["coverage"]["kev_matches"],
        "breakdown": [(b["title"], b["count"], b["gain"]) for b in data.get("score", {}).get("breakdown", [])],
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--force", action="store_true", help="rebuild the database if it exists")
    parser.add_argument("--out", type=Path, default=DEMO_DB, help=f"target database (default: {DEMO_DB})")
    parser.add_argument("--quiet", action="store_true", help="only print the final summary line")
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.WARNING if args.quiet else logging.INFO,
        format="%(levelname)s %(name)s: %(message)s",
    )
    report = build(args.out, force=args.force)

    print(f"wrote {args.out}")
    for table, n in report["rows"].items():
        print(f"  {table:<18} {n:>7,}")
    print(f"  score              {report['score']}/100 ({report['grade']})")
    print(f"  findings           {report['findings_open']} open · "
          f"{report['findings_acknowledged']} acknowledged · {report['findings_suppressed']} suppressed · "
          f"{report['findings_resolved']} resolved")
    print(f"  remediation rate   {report['remediation_rate'] * 100:.1f}%  "
          f"(median time to fix {report['median_hours_to_fix']} h)")
    print(f"  dns 24 h           {report['dns_queries_24h']:,} queries · "
          f"{report['dns_block_rate'] * 100:.1f}% blocked")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
