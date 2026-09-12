"""Offline tests for the findings catalog, engine, score and notification payload builders."""
from __future__ import annotations

import base64
import sqlite3
import sys
from dataclasses import dataclass, field
from types import SimpleNamespace

import pytest

from homesoc.findings import catalog, engine, score
from homesoc.notify import channels

try:  # P1 may not be present while packages are built in parallel
    from homesoc.models import FindingDraft
except ImportError:  # pragma: no cover

    @dataclass
    class FindingDraft:  # type: ignore[no-redef]
        finding_id: str
        subject: str
        evidence: dict = field(default_factory=dict)
        detail: str | None = None
        severity: str | None = None
        device_id: int | None = None


_LOCAL_SCHEMA = """
CREATE TABLE IF NOT EXISTS devices(id INTEGER PRIMARY KEY, mac TEXT UNIQUE, ip TEXT, hostname TEXT,
  vendor TEXT, nickname TEXT, trusted INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS findings(
  id INTEGER PRIMARY KEY, finding_id TEXT NOT NULL, subject TEXT NOT NULL, dedupe_key TEXT NOT NULL UNIQUE,
  severity TEXT NOT NULL, title TEXT NOT NULL, detail TEXT, evidence TEXT, status TEXT NOT NULL DEFAULT 'open',
  source TEXT NOT NULL, first_seen TEXT NOT NULL, last_seen TEXT NOT NULL, resolved_at TEXT,
  occurrences INTEGER NOT NULL DEFAULT 1, device_id INTEGER REFERENCES devices(id));
CREATE TABLE IF NOT EXISTS finding_events(
  id INTEGER PRIMARY KEY, finding_row_id INTEGER NOT NULL REFERENCES findings(id), event TEXT NOT NULL,
  at TEXT NOT NULL, note TEXT);
CREATE TABLE IF NOT EXISTS metrics(id INTEGER PRIMARY KEY, ts TEXT NOT NULL, name TEXT NOT NULL, value REAL NOT NULL, tags TEXT);
CREATE TABLE IF NOT EXISTS notifications(id INTEGER PRIMARY KEY, ts TEXT NOT NULL, channel TEXT NOT NULL,
  subject TEXT NOT NULL, status TEXT NOT NULL, error TEXT);
"""


@pytest.fixture
def conn() -> sqlite3.Connection:
    try:
        from homesoc import db

        c = db.connect(":memory:")
        db.init_schema(c)
    except (ImportError, AttributeError, TypeError):
        c = sqlite3.connect(":memory:", check_same_thread=False)
        c.row_factory = sqlite3.Row
        c.executescript(_LOCAL_SCHEMA)
    return c


# ---------------------------------------------------------------------------------------- catalog
SPEC_IDS = (
    [f"WIN-DEF-{i:03d}" for i in range(1, 15)]
    + ["WIN-FW-001", "WIN-FW-002"]
    + [f"WIN-UPD-{i:03d}" for i in range(1, 5)]
    + [f"WIN-ACC-{i:03d}" for i in range(1, 6)]
    + [f"WIN-NET-{i:03d}" for i in range(1, 7)]
    + [f"WIN-SYS-{i:03d}" for i in range(1, 9)]
    + ["WIN-PER-001", "WIN-PER-002", "WIN-PER-003", "AV-FILE-001", "AV-FILE-002"]
    + ["POSIX-FW-001", "POSIX-UPD-001", "POSIX-SSH-001", "POSIX-ENC-001", "POSIX-NET-001"]
    + ["NET-DEV-001", "NET-DEV-002", "NET-DEV-003"]
    + [f"NET-SVC-{i:03d}" for i in range(1, 13)]
    + [f"NET-VUL-{i:03d}" for i in range(1, 5)]
    + ["NET-WAN-001", "NET-WAN-002", "NET-WAN-003", "NET-RTR-002"]
    + [f"NET-WIFI-{i:03d}" for i in range(1, 5)]
    + [f"NET-DNS-{i:03d}" for i in range(1, 7)]
    + ["SOC-FEED-001", "SOC-FEED-002", "SOC-SYS-001", "SOC-SYS-002", "SOC-SYS-003", "SOC-SYS-004"]
)

SPEC_SEVERITY = {
    "WIN-DEF-001": "critical", "WIN-DEF-003": "high", "WIN-DEF-013": "info", "WIN-FW-001": "critical",
    "WIN-UPD-002": "high", "WIN-ACC-001": "medium", "WIN-NET-001": "high", "WIN-SYS-002": "high",
    "AV-FILE-001": "critical", "NET-SVC-001": "critical", "NET-SVC-007": "high", "NET-VUL-001": "critical",
    "NET-WAN-003": "high", "NET-WIFI-001": "critical", "NET-DNS-004": "high", "SOC-SYS-003": "high",
}


def test_catalog_contains_every_spec_id():
    missing = [i for i in SPEC_IDS if catalog.get(i) is None]
    assert not missing, missing
    assert len(catalog.CATALOG) >= len(SPEC_IDS)


@pytest.mark.parametrize("fid", SPEC_IDS)
def test_catalog_entries_are_complete(fid):
    spec = catalog.get(fid)
    assert spec.id == fid
    assert spec.severity in catalog.SEVERITIES
    assert spec.title and spec.rationale and spec.category
    assert isinstance(spec.remediation, list) and spec.remediation
    assert all(isinstance(s, str) and s for s in spec.remediation)
    assert all(r.startswith("https://") for r in spec.refs)


@pytest.mark.parametrize("fid,sev", sorted(SPEC_SEVERITY.items()))
def test_catalog_severities_match_spec(fid, sev):
    assert catalog.get(fid).severity == sev


# Evidence exactly as the real emitter builds it, so a catalog placeholder that does not match the
# scanner's key shows up here instead of on the user's dashboard as "unknown". Each entry is
# (subject, evidence) and names the module that produces it.
_MAC = "aa:bb:cc:dd:ee:01"
_DEV = f"device:{_MAC}"


def _svc(port, **extra):
    """scanners.services._draft evidence."""
    ev = {"ip": "192.168.1.50", "hostname": "printer", "vendor": "Epson", "port": port,
          "proto": "tcp", "service": "telnet", "product": "BusyBox telnetd", "version": "1.3",
          "extrainfo": ""}
    ev.update(extra)
    return f"{_DEV}:{port}", ev


def _vuln(fid_extra):
    """vulns.matcher evidence (shared prefix)."""
    ev = {"product": "lighttpd", "version": "1.4.69", "matched_on": "cpe:/a:lighttpd:lighttpd",
          "ip": "192.168.1.254", "port": 80}
    ev.update(fid_extra)
    return f"{_DEV}:80", ev


EMITTER_EVIDENCE: dict[str, tuple[str, dict]] = {
    # --- scanners/defender.py
    "WIN-DEF-001": ("host", {"AntivirusEnabled": False, "AMServiceEnabled": True, "AMRunningMode": "Normal"}),
    "WIN-DEF-002": ("host", {"RealTimeProtectionEnabled": False, "DisableRealtimeMonitoring": True}),
    "WIN-DEF-003": ("host", {"age_days": 5, "last_updated": "2026-09-01", "version": "1.435.1"}),
    "WIN-DEF-004": ("host", {"IsTamperProtected": False}),
    "WIN-DEF-005": ("host", {"MAPSReporting": 0}),
    "WIN-DEF-006": ("host", {"PUAProtection": 0}),
    "WIN-DEF-007": ("host", {"full_scan_age_days": None, "quick_scan_age_days": 0, "last_full_scan": None}),
    "WIN-DEF-008": ("host", {"EnableControlledFolderAccess": 0}),
    "WIN-DEF-009": ("host", {"EnableNetworkProtection": 0}),
    "WIN-DEF-010": ("host", {"rules": [], "actions": []}),
    "WIN-DEF-011": ("host", {"key": "Trojan:Win32/Wacatac", "threat_name": "Trojan:Win32/Wacatac",
                             "path": r"C:\Users\me\Downloads\x.exe", "severity": "Severe",
                             "action": "quarantine", "detected_at": "2026-09-01T10:00:00Z"}),
    "WIN-DEF-012": ("host", {"state": "stopped", "AMServiceEnabled": False, "AMRunningMode": "Unknown",
                             "engine": "1.1.24", "platform": "4.18"}),
    "WIN-DEF-013": ("host", {"VerifiedAndReputablePolicyState": 0}),
    "WIN-DEF-014": ("host", {"SubmitSamplesConsent": 2, "CloudBlockLevel": 0}),
    # --- scanners/host_windows.py
    "WIN-FW-001": ("host", {"profile": "Public", "key": "Public"}),
    "WIN-FW-002": ("host", {"profile": "Public, Private", "profiles": ["Public", "Private"]}),
    "WIN-ACC-001": ("host", {"user": "alex", "administrators": ["alex", "Administrator"]}),
    "WIN-ACC-002": ("host", {"name": "Administrator", "last_logon": None}),
    "WIN-ACC-003": ("host", {"name": "Guest"}),
    "WIN-ACC-004": ("host", {"user": "alex", "password_stored": True}),
    "WIN-ACC-005": ("host", {"EnableLUA": 0, "ConsentPromptBehaviorAdmin": 0}),
    "WIN-NET-001": ("host", {"EnableSMB1Protocol": True}),
    "WIN-NET-002": ("host", {"fDenyTSConnections": 0, "nla": False}),
    "WIN-NET-003": ("host", {"RequireSecuritySignature": False, "EnableSecuritySignature": True}),
    "WIN-NET-004": ("host", {"EnableMulticast": None}),
    "WIN-NET-005": ("host", {"port": "5985", "services": ["WinRM"], "winrm": {"status": "Running"},
                             "remote_registry": {"status": "Stopped"}}),
    "WIN-NET-006": ("host", {"port": 7777, "address": "0.0.0.0", "process": "node.exe", "key": "7777"}),
    "WIN-SYS-001": ("host", {"secure_boot": "False", "registry": 0}),
    "WIN-SYS-002": ("host", {"volumes": [{"mount": "C:", "protection": "Off"}]}),
    "WIN-SYS-003": ("host", {"vbs_status": 2, "services_running": [0]}),
    "WIN-SYS-004": ("host", {"RunAsPPL": None}),
    "WIN-SYS-005": ("host", {"state": "Enabled"}),
    "WIN-SYS-006": ("host", {"SmartScreenEnabled": "Off", "policy_EnableSmartScreen": 0}),
    "WIN-SYS-007": ("host", {"InactivityTimeoutSecs": 0, "ScreenSaveActive": False,
                             "ScreenSaverIsSecure": False, "ScreenSaveTimeOut": 0, "display_off_ac_sec": 0}),
    "WIN-SYS-008": ("host", {"tpm": {"present": False}, "pnp": []}),
    # --- scanners/updates.py
    "WIN-UPD-001": ("host", {"count": 3, "titles": ["2026-08 Cumulative Update"], "kbs": ["KB5041585"],
                             "important": True, "ignored_defender_intel": 1}),
    "WIN-UPD-002": ("host", {"last": "2026-07-16", "days": 53, "title": "2026-07 Cumulative Update",
                             "source": "windows update history", "build": "26100"}),
    "WIN-UPD-003": ("host", {"key": "obsproject.obsstudio", "name": "OBS Studio", "id": "OBSProject.OBSStudio",
                             "version": "30.0.2", "available": "31.1.2", "source": "winget",
                             "publisher": "OBS", "high_risk": False, "winget": 'winget upgrade --id "OBS Studio"'}),
    "WIN-UPD-004": ("host", {"key": "oracle.javaruntimeenvironment", "name": "Java 8", "id": "Oracle.JavaRuntimeEnvironment",
                             "version": "8.0.401", "available": "8.0.461", "source": "winget",
                             "publisher": "Oracle", "high_risk": True, "winget": None}),
    # --- scanners/persistence.py
    "WIN-PER-001": ("host", {"kind": "run_key", "name": "ExampleSync", "location": r"HKCU\...\Run",
                             "command": r"C:\Program Files\ExampleSync\sync.exe", "first_seen": "2026-09-01",
                             "key": "run_key:HKCU:ExampleSync"}),
    "WIN-PER-002": ("host", {"kind": "scheduled_task", "name": "UpdaterTask", "location": r"\Vendor",
                             "command": "updater.exe", "first_seen": "2026-09-01", "key": "t"}),
    "WIN-PER-003": ("host", {"kind": "service", "name": "VendorSvc", "location": "services",
                             "command": "svc.exe", "first_seen": "2026-09-01", "key": "s"}),
    # --- scanners/files.py
    "AV-FILE-001": ("host", {"path": r"C:\Users\me\Downloads\setup.exe", "sha256": "ab" * 32, "size": 1024,
                             "vt_url": "https://www.virustotal.com/gui/file/" + "ab" * 32}),
    "AV-FILE-002": ("host", {"path": r"C:\Users\me\Downloads\tool.exe", "sha256": "cd" * 32, "size": 2048,
                             "vt_url": "https://www.virustotal.com/gui/file/" + "cd" * 32}),
    # --- scanners/host_posix.py + updates.posix
    "POSIX-FW-001": ("host", {"detail": "ufw inactive"}),
    "POSIX-UPD-001": ("host", {"count": 12, "manager": "apt", "packages": ["curl", "openssl"]}),
    "POSIX-SSH-001": ("host", {"PermitRootLogin": "yes"}),
    "POSIX-ENC-001": ("host", {"detail": "no LUKS device"}),
    "POSIX-NET-001": ("host", {"port": 8080, "address": "0.0.0.0", "process": "python3"}),
    # --- scanners/discovery.py
    "NET-DEV-001": (_DEV, {"ip": "192.168.1.77", "hostname": "laptop.lan", "vendor": "Apple",
                           "first_seen": "2026-09-01", "mac": _MAC, "method": "arp", "baseline": False}),
    "NET-DEV-002": (_DEV, {"ip": "192.168.1.78", "hostname": None, "mac": _MAC, "reason": "randomized_mac"}),
    "NET-DEV-003": (_DEV, {"ip": "192.168.1.79", "hostname": "tablet.lan", "last_seen": "2026-07-01",
                           "name": "tablet.lan", "days": 30}),
    # --- scanners/services.py
    "NET-SVC-001": _svc(23),
    "NET-SVC-002": _svc(21),
    "NET-SVC-003": _svc(445),
    "NET-SVC-004": _svc(3389),
    "NET-SVC-005": _svc(80, device_kind="router"),
    "NET-SVC-006": _svc(1900),
    "NET-SVC-007": _svc(3306),
    "NET-SVC-008": _svc(9100),
    "NET-SVC-009": _svc(161, community="public"),
    "NET-SVC-010": _svc(554),
    "NET-SVC-011": _svc(22, product="OpenSSH", version="7.4"),
    "NET-SVC-012": (_DEV, {"ip": "192.168.1.50", "hostname": "printer.lan", "vendor": "Example Print Systems",
                           "exposed": [{"port": 80, "banner": "Example Printer EX-1200 Series"}]}),
    # --- vulns/matcher.py
    "NET-VUL-001": _vuln({"key": "CVE-2024-1", "cve": "CVE-2024-1", "verdict": "confirmed",
                          "kev_max_version": "1.4.70", "vulnerability_name": "n", "date_added": "d",
                          "due_date": "d", "ransomware": "Known", "required_action": "patch"}),
    "NET-VUL-002": _vuln({"key": "CVE-2024-2", "cve": "CVE-2024-2", "verdict": "possible",
                          "kev_max_version": None, "vulnerability_name": "n", "date_added": "d",
                          "due_date": "d", "ransomware": "Unknown", "required_action": "patch"}),
    "NET-VUL-003": _vuln({"count": 7, "max_cvss": 9.8, "top": [{"cve": "CVE-2024-3", "cvss": 9.8}],
                          "threshold": 7.0}),
    "NET-VUL-004": _vuln({"cves": [{"cve": "CVE-2024-4", "epss": 0.91, "source": "kev"}], "threshold": 0.5}),
    # --- scanners/exposure.py
    "NET-WAN-001": ("wan", {"key": "443", "port": 443, "public_ip": "203.0.113.9",
                            "source": "internetdb", "hostnames": []}),
    "NET-WAN-002": ("wan", {"public_ip": "203.0.113.9", "vulns": ["CVE-2024-5", "CVE-2024-6"],
                            "cpes": [], "ports": [443], "source": "internetdb"}),
    "NET-WAN-003": ("wan", {"key": "TCP/25565", "remote_host": "", "external_port": 25565, "protocol": "TCP",
                            "internal_port": 25565, "internal_client": "192.168.1.42", "enabled": True,
                            "description": "Minecraft", "lease_duration": 0, "index": 0}),
    "NET-RTR-002": ("wan", {"key": "192.168.1.254", "igd_ip": "192.168.1.254",
                            "location": "http://192.168.1.254:5000/rootDesc.xml", "server": "Example-Router/1.0"}),
    # --- scanners/wifi.py
    **{fid: ("wifi", {"key": "Wi-Fi", "ssid": "HomeNet", "bssid": "00:11:22:00:00:01",
                      "authentication": "WPA2-Personal", "cipher": "CCMP", "band": "5 GHz",
                      "channel": 44, "interface": "Wi-Fi"})
       for fid in ("NET-WIFI-001", "NET-WIFI-002", "NET-WIFI-003", "NET-WIFI-004")},
    # --- dnsfilter/server.py + reputation.py
    "NET-DNS-001": ("dns", {"clients_24h": 1, "listen": "0.0.0.0", "port": 53, "ip": "192.168.1.105"}),
    "NET-DNS-002": ("dns", {"listen": "0.0.0.0", "port": 53, "error": "[WinError 10048]",
                            "reason": "port 53 in use"}),
    "NET-DNS-003": ("dns", {"lists": ["oisd_small"], "status": [{"name": "oisd_small"}], "age_days": 9}),
    "NET-DNS-004": ("dns:192.168.1.42", {"key": "bad.example", "domain": "bad.example",
                                         "qname": "www.bad.example", "client": "192.168.1.42",
                                         "verdict": "malicious", "malicious": 7, "suspicious": 1,
                                         "source": "virustotal", "checked_at": "2026-09-06T10:00:00Z"}),
    "NET-DNS-005": ("dns", {"failing_seconds": 120, "ok": False, "consecutive_failures": 9,
                            "last_error": "timeout", "last_upstream": "1.1.1.2", "upstreams": ["1.1.1.2"]}),
    "NET-DNS-006": ("dns", {"listen": "0.0.0.0", "port": 53}),
    # --- cli.soc_health_drafts / feeds.updater.health_findings / host_windows
    "SOC-FEED-001": ("feed:kev", {"key": "kev", "name": "kev", "error": "HTTP 500",
                                  "last_updated": "2026-09-01T00:00:00Z", "error_since": "2026-09-02T00:00:00Z",
                                  "hours": 72}),
    "SOC-FEED-002": ("feed:kev", {"last_updated": "2026-09-01T00:00:00Z", "hours": 72}),
    "SOC-SYS-001": ("host", {"hint": "install nmap or set scan.use_nmap=false", "method": "python"}),
    "SOC-SYS-002": ("host", {"is_admin": False, "skipped": "WIN-SYS-002, WIN-SYS-008",
                             "skipped_ids": ["WIN-SYS-002", "WIN-SYS-008"],
                             "project_root": r"C:\Users\me\Home_SOC", "user": "me"}),
    "SOC-SYS-003": ("host", {"host": "0.0.0.0", "port": 8787}),
    "SOC-SYS-004": ("job:discovery", {"key": "discovery", "job": "discovery", "failures": 4,
                                      "consecutive_failures": 4, "last_error": "no route to host",
                                      "last_run": "2026-09-06T10:00:00Z"}),
}

# The same finding IDs raised by a *second* emitter with a different evidence shape; both must render.
SECOND_EMITTER_EVIDENCE: dict[str, tuple[str, dict]] = {
    # feeds.updater.health_findings knows the feed and the error but not the age in hours.
    "SOC-FEED-001": ("feed:oisd_small", {"feed": "oisd_small", "url": "https://example.invalid/list.txt",
                                         "last_updated": None, "error": "timeout"}),
    "SOC-FEED-002": ("feed:kev", {"last_updated": None, "status": "error"}),
}


def test_every_spec_id_has_representative_evidence():
    """A new catalog ID must arrive with a sample of what its scanner actually emits."""
    assert not [fid for fid in SPEC_IDS if fid not in EMITTER_EVIDENCE]


def _assert_clean_render(fid, subject, evidence):
    assert catalog.unresolved_placeholders(fid, evidence, subject) == [], (
        f"{fid}: catalog placeholders its emitter does not supply -> the title would say 'unknown'"
    )
    title, detail = catalog.render(FindingDraft(fid, subject, dict(evidence)))
    steps = catalog.render_remediation(fid, dict(evidence), subject)
    for text, where in [(title, "title"), (detail, "detail")] + [(s, "remediation") for s in steps]:
        # Evidence lists/dicts must reach the user as prose, never as a Python repr.
        assert "['" not in text and "{'" not in text, f"{fid} {where} leaked a Python literal: {text}"
        assert "None" not in title, f"{fid} title rendered a None: {title}"
        assert where != "remediation" or text.strip(), f"{fid} produced an empty remediation step"
    # A templated title must actually change when the evidence is there - catches an emitter whose
    # keys drift in a way the subject fields or a default happen to paper over.
    if _title_fields(fid) & set(evidence):
        bare, _ = catalog.render(FindingDraft(fid, subject, {}))
        assert bare != title, f"{fid} title ignores its evidence: {title}"
    return title, detail, steps


def _title_fields(fid):
    import string

    return {f for _, f, _, _ in string.Formatter().parse(catalog.get(fid).title) if f}


@pytest.mark.parametrize("fid", SPEC_IDS)
def test_catalog_renders_real_emitter_evidence_without_placeholders(fid):
    subject, evidence = EMITTER_EVIDENCE[fid]
    _assert_clean_render(fid, subject, dict(evidence))


@pytest.mark.parametrize("fid", sorted(SECOND_EMITTER_EVIDENCE))
def test_catalog_renders_second_emitter_evidence(fid):
    subject, evidence = SECOND_EMITTER_EVIDENCE[fid]
    _assert_clean_render(fid, subject, dict(evidence))


def test_unresolved_placeholders_flags_a_drifted_evidence_key():
    """The regression this guards: SOC-SYS-004 templated {job} while the emitter sent {key}."""
    assert catalog.unresolved_placeholders("SOC-SYS-004", {"key": "discovery", "failures": 3}, "job:discovery") == []
    assert catalog.unresolved_placeholders("SOC-SYS-004", {}, "host") == ["failures", "job"]
    title, _ = catalog.render(FindingDraft("SOC-SYS-004", "job:discovery", {"consecutive_failures": 4}))
    assert title == "Scheduled job 'discovery' keeps failing (4 times)"


def test_container_evidence_renders_as_prose_not_python():
    title, _ = catalog.render(FindingDraft("SOC-SYS-002", "host", {"skipped": ["WIN-SYS-002", "WIN-SYS-008"]}))
    assert "WIN-SYS-002, WIN-SYS-008" in title and "[" not in title
    title, _ = catalog.render(FindingDraft("WIN-FW-002", "host", {"profiles": ["Public", "Private"]}))
    assert "Public, Private" in title
    long_list = catalog.render(FindingDraft("NET-WAN-002", "wan", {"vulns": [f"CVE-2024-{i}" for i in range(9)]}))[0]
    assert "and 3 more" in long_list


def test_remediation_offers_a_command_line_alternative_for_host_findings():
    """The click-path is for the dashboard reader; the command is what a user can paste."""
    needs_cli = [s for s in catalog.CATALOG.values()
                 if s.category in ("defender", "firewall", "updates", "accounts", "host-network", "system")]
    assert needs_cli
    missing = [s.id for s in needs_cli
               if not any(w in step for step in s.remediation
                          for w in ("PowerShell", "powershell", "winget", "Run:", "run: "))]
    assert not missing, missing


def test_render_interpolates_evidence_and_tolerates_missing_keys():
    d = FindingDraft("NET-SVC-001", "device:aa:bb:cc:dd:ee:ff:23", {"ip": "192.168.1.50"})
    title, detail = catalog.render(d)
    assert title == "Telnet open on 192.168.1.50:23"      # port derived from the subject
    assert "Telnet" in detail
    d2 = FindingDraft("NET-VUL-001", "device:aa:bb:cc:dd:ee:ff", {"cve": "CVE-2024-1"})
    title2, _ = catalog.render(d2)
    assert "CVE-2024-1" in title2 and "unknown" in title2  # missing {ip}/{product} do not raise
    steps = catalog.render_remediation("NET-VUL-001", {"cve": "CVE-2024-1"})
    assert any("CVE-2024-1" in s for s in steps)


def test_render_survives_braces_in_evidence_and_unknown_ids():
    d = FindingDraft("WIN-PER-001", "host", {"name": "weird {thing}", "key": "x"})
    title, _ = catalog.render(d)
    assert "weird {thing}" in title
    unknown = FindingDraft("XYZ-999", "host", {"a": 1})
    title, detail = catalog.render(unknown)
    assert "XYZ-999" in title and '"a": 1' in detail


def test_severity_for_prefers_draft_override():
    assert catalog.severity_for(FindingDraft("WIN-UPD-001", "host", severity="high")) == "high"
    assert catalog.severity_for(FindingDraft("WIN-UPD-001", "host")) == "medium"
    assert catalog.severity_for(FindingDraft("WIN-UPD-001", "host", severity="bogus")) == "medium"


# ----------------------------------------------------------------------------------------- engine
def _events(conn, row_id):
    return [r["event"] for r in conn.execute("SELECT event FROM finding_events WHERE finding_row_id=? ORDER BY id", (row_id,))]


def test_dedupe_key_uses_evidence_key():
    assert engine.dedupe_key(FindingDraft("A", "host")) == "A|host"
    assert engine.dedupe_key(FindingDraft("A", "host", {"key": "Trojan:Win32/X"})) == "A|host|Trojan:Win32/X"
    assert engine.dedupe_key(FindingDraft("A", "host", {"key": ""})) == "A|host"


def test_apply_new_then_update_then_reopen(conn):
    d = FindingDraft("WIN-DEF-002", "host", {"x": 1})
    r1 = engine.apply(conn, [d], "host")
    assert len(r1.new) == 1 and r1.updated == 0
    row = r1.new[0]
    assert row["status"] == "open" and row["occurrences"] == 1 and row["severity"] == "critical"
    assert row["evidence"] == {"x": 1} and row["category"] == "defender" and row["remediation"]
    assert _events(conn, row["id"]) == ["opened"]

    r2 = engine.apply(conn, [FindingDraft("WIN-DEF-002", "host", {"x": 2})], "host")
    assert r2.updated == 1 and not r2.new and not r2.reopened
    again = engine.list_findings(conn)[0]
    assert again["occurrences"] == 2 and again["evidence"] == {"x": 2}

    engine.set_status(conn, row["id"], "resolved", "fixed it")
    assert engine.list_findings(conn, status="resolved")[0]["resolved_at"]
    r3 = engine.apply(conn, [d], "host")
    assert len(r3.reopened) == 1 and r3.reopened[0]["status"] == "open" and r3.reopened[0]["resolved_at"] is None
    assert _events(conn, row["id"]) == ["opened", "resolved", "reopened"]


def test_acknowledged_persists_and_suppressed_stays_suppressed(conn):
    d = FindingDraft("NET-DEV-001", "device:aa:bb:cc:dd:ee:01", {"ip": "10.0.0.5"})
    row = engine.apply(conn, [d], "discovery").new[0]
    engine.set_status(conn, row["id"], "acknowledged")
    engine.apply(conn, [d], "discovery")
    assert engine.list_findings(conn)[0]["status"] == "acknowledged"

    engine.set_status(conn, row["id"], "suppressed", "it's my TV")
    r = engine.apply(conn, [d], "discovery")
    cur = engine.list_findings(conn)[0]
    assert cur["status"] == "suppressed" and cur["occurrences"] == 3 and r.updated == 1
    assert _events(conn, row["id"]) == ["opened", "acknowledged", "suppressed"]


def test_scope_auto_resolves_only_matching_source_and_subject(conn):
    a = FindingDraft("NET-SVC-001", "device:aa:bb:cc:dd:ee:01:23", {"ip": "10.0.0.5"})
    b = FindingDraft("NET-SVC-002", "device:aa:bb:cc:dd:ee:01:21", {"ip": "10.0.0.5"})
    other_dev = FindingDraft("NET-SVC-001", "device:aa:bb:cc:dd:ee:02:23", {"ip": "10.0.0.6"})
    other_src = FindingDraft("WIN-FW-001", "host", {"profile": "Public"})
    engine.apply(conn, [a, b, other_dev], "services")
    engine.apply(conn, [other_src], "host")

    r = engine.apply(conn, [a], "services", scope="device:aa:bb:cc:dd:ee:01")
    assert [x["finding_id"] for x in r.resolved] == ["NET-SVC-002"]
    assert r.updated == 1
    by_key = {x["dedupe_key"]: x for x in engine.list_findings(conn)}
    assert by_key[engine.dedupe_key(b)]["status"] == "resolved"
    assert by_key[engine.dedupe_key(other_dev)]["status"] == "open"
    assert by_key[engine.dedupe_key(other_src)]["status"] == "open"
    assert _events(conn, by_key[engine.dedupe_key(b)]["id"]) == ["opened", "auto_resolved"]

    # nothing reported for the whole source scope -> everything from that source resolves
    r = engine.apply(conn, [], "services", scope="device:")
    assert sorted(x["subject"] for x in r.resolved) == ["device:aa:bb:cc:dd:ee:01:23", "device:aa:bb:cc:dd:ee:02:23"]
    assert engine.list_findings(conn, subject_prefix="host")[0]["status"] == "open"  # other source untouched


def test_scope_does_not_touch_suppressed(conn):
    d = FindingDraft("NET-SVC-001", "device:aa:bb:cc:dd:ee:01:23", {"ip": "10.0.0.5"})
    row = engine.apply(conn, [d], "services").new[0]
    engine.set_status(conn, row["id"], "suppressed")
    r = engine.apply(conn, [], "services", scope="device:")
    assert not r.resolved
    assert engine.list_findings(conn)[0]["status"] == "suppressed"


def test_duplicate_keys_in_one_batch_count_once(conn):
    d = FindingDraft("WIN-FW-001", "host", {"profile": "Public", "key": "Public"})
    r = engine.apply(conn, [d, d], "host")
    assert len(r.new) == 1 and r.updated == 0
    assert engine.list_findings(conn)[0]["occurrences"] == 1


def test_severity_override_and_refresh(conn):
    engine.apply(conn, [FindingDraft("WIN-UPD-001", "host", {"count": 3})], "host")
    assert engine.list_findings(conn)[0]["severity"] == "medium"
    engine.apply(conn, [FindingDraft("WIN-UPD-001", "host", {"count": 4}, severity="high")], "host")
    assert engine.list_findings(conn)[0]["severity"] == "high"


def test_set_status_validation(conn):
    with pytest.raises(KeyError):
        engine.set_status(conn, 12345, "resolved")
    row = engine.apply(conn, [FindingDraft("WIN-DEF-001", "host")], "host").new[0]
    with pytest.raises(ValueError):
        engine.set_status(conn, row["id"], "closed")
    engine.set_status(conn, row["id"], "resolved")
    engine.set_status(conn, row["id"], "open", "manual reopen")
    assert _events(conn, row["id"]) == ["opened", "resolved", "reopened"]
    assert engine.events(conn, row["id"])[0]["note"] == "manual reopen"


def test_list_and_counts(conn):
    engine.apply(
        conn,
        [
            FindingDraft("WIN-DEF-001", "host"),
            FindingDraft("WIN-DEF-006", "host"),
            FindingDraft("NET-DEV-001", "device:aa:bb:cc:dd:ee:01", {"ip": "1.2.3.4"}),
        ],
        "host",
    )
    rows = engine.list_findings(conn)
    assert [r["severity"] for r in rows] == ["critical", "medium", "low"]
    assert len(engine.list_findings(conn, severity="low")) == 1
    assert len(engine.list_findings(conn, subject_prefix="device:")) == 1
    assert len(engine.list_findings(conn, limit=2)) == 2
    c = engine.counts(conn)
    assert set(c) == set(engine.STATUSES)
    assert c["open"] == {"critical": 1, "high": 0, "medium": 1, "low": 1, "info": 0}
    assert c["resolved"]["critical"] == 0


# --------------------------------------------------------------------------------------- baseline
_T0 = "2099-01-01T00:00:00Z"


def _device(conn, mac, ip="192.168.1.9", hostname=None, trusted=0):
    cols = {r[1] for r in conn.execute("PRAGMA table_info(devices)")}
    extra = ", first_seen, last_seen" if "first_seen" in cols else ""
    values = ", ?, ?" if extra else ""
    params = [mac, ip, hostname, trusted] + ([_T0, _T0] if extra else [])
    return int(conn.execute(
        f"INSERT INTO devices(mac, ip, hostname, trusted{extra}) VALUES (?,?,?,?{values})", params
    ).lastrowid)


def _new_device_finding(conn, mac, device_id, status="open"):
    conn.execute(
        "INSERT INTO findings(finding_id, subject, dedupe_key, severity, title, status, source, first_seen,"
        " last_seen, device_id) VALUES ('NET-DEV-001',?,?,'medium','New device','" + status + "','discovery',"
        "'2099-01-01T00:00:00Z','2099-01-01T00:00:00Z',?)",
        (f"device:{mac}", f"NET-DEV-001|device:{mac}", device_id),
    )
    conn.commit()


def _established_network(conn, count=23):
    """The state that breaks an existing install: every owned device flagged as new."""
    for i in range(count):
        mac = f"aa:bb:cc:00:{i:02x}:01"
        _new_device_finding(conn, mac, _device(conn, mac, f"192.168.1.{20 + i}", f"thing{i}"))
    conn.commit()


def test_baseline_trusts_every_device_and_closes_their_new_device_findings(conn):
    _established_network(conn, 23)
    assert score.security_score(conn) < 100
    before = score.security_score(conn)

    result = engine.baseline_devices(conn)

    assert result.devices_total == 23 and len(result.trusted) == 23 and result.already_trusted == []
    assert len(result.resolved) == 23 and result.dry_run is False
    assert conn.execute("SELECT COUNT(*) FROM devices WHERE trusted=1").fetchone()[0] == 23
    assert conn.execute("SELECT COUNT(*) FROM findings WHERE status='open'").fetchone()[0] == 0
    assert conn.execute("SELECT COUNT(*) FROM findings WHERE resolved_at IS NOT NULL").fetchone()[0] == 23
    assert score.security_score(conn) > before


def test_baseline_writes_a_clear_event_on_every_finding_it_closes(conn):
    _established_network(conn, 2)
    engine.baseline_devices(conn)
    notes = conn.execute("SELECT event, note FROM finding_events").fetchall()
    assert [tuple(r) for r in notes] == [("resolved", engine.BASELINE_NOTE)] * 2
    assert engine.BASELINE_NOTE == "accepted as part of the baseline inventory"


def test_baseline_dry_run_changes_nothing(conn):
    _established_network(conn, 5)
    result = engine.baseline_devices(conn, dry_run=True)
    assert result.dry_run is True and len(result.trusted) == 5 and len(result.resolved) == 5
    assert conn.execute("SELECT COUNT(*) FROM devices WHERE trusted=1").fetchone()[0] == 0
    assert conn.execute("SELECT COUNT(*) FROM findings WHERE status='open'").fetchone()[0] == 5
    assert conn.execute("SELECT COUNT(*) FROM finding_events").fetchone()[0] == 0


def test_baseline_is_idempotent_and_reports_devices_already_trusted(conn):
    _established_network(conn, 3)
    engine.baseline_devices(conn)
    again = engine.baseline_devices(conn)
    assert again.trusted == [] and len(again.already_trusted) == 3 and again.resolved == []


def test_baseline_can_close_the_findings_without_touching_the_trusted_flag(conn):
    _established_network(conn, 3)
    result = engine.baseline_devices(conn, trust_all=False)
    assert result.trusted == [] and len(result.resolved) == 3
    assert conn.execute("SELECT COUNT(*) FROM devices WHERE trusted=1").fetchone()[0] == 0


def test_baseline_also_closes_acknowledged_rows_and_leaves_other_findings_alone(conn):
    mac = "aa:bb:cc:00:99:01"
    device_id = _device(conn, mac)
    _new_device_finding(conn, mac, device_id, status="acknowledged")
    _seed(conn, "NET-DEV-002", "info", 1)
    _seed(conn, "WIN-UPD-003", "low", 2)
    result = engine.baseline_devices(conn)
    assert len(result.resolved) == 1
    still_open = conn.execute(
        "SELECT finding_id, COUNT(*) FROM findings WHERE status='open' GROUP BY 1").fetchall()
    assert [tuple(r) for r in still_open] == [("NET-DEV-002", 1), ("WIN-UPD-003", 2)]


def test_baseline_closes_a_finding_whose_device_row_is_gone(conn):
    """A device deleted from the inventory must not leave an unclosable 'new device' row."""
    conn.execute(
        "INSERT INTO findings(finding_id, subject, dedupe_key, severity, title, status, source, first_seen,"
        " last_seen) VALUES ('NET-DEV-001','device:de:ad:be:ef:00:01','k','medium','New device','open',"
        "'discovery','2099-01-01T00:00:00Z','2099-01-01T00:00:00Z')")
    conn.commit()
    result = engine.baseline_devices(conn)
    assert result.devices_total == 0 and len(result.resolved) == 1


def test_trusting_one_device_later_resolves_only_its_new_device_finding(conn):
    _established_network(conn, 3)
    device_id = int(conn.execute("SELECT id FROM devices ORDER BY id").fetchone()[0])
    resolved = engine.trust_device(conn, device_id)
    assert len(resolved) == 1 and resolved[0]["status"] == "resolved"
    assert conn.execute("SELECT trusted FROM devices WHERE id=?", (device_id,)).fetchone()[0] == 1
    assert conn.execute("SELECT COUNT(*) FROM findings WHERE status='open'").fetchone()[0] == 2
    assert engine.events(conn, int(resolved[0]["id"]))[0]["note"] == engine.TRUST_NOTE


def test_untrusting_a_device_does_not_reopen_anything(conn):
    _established_network(conn, 1)
    device_id = int(conn.execute("SELECT id FROM devices").fetchone()[0])
    engine.trust_device(conn, device_id)
    assert engine.trust_device(conn, device_id, trusted=False) == []
    assert conn.execute("SELECT trusted FROM devices WHERE id=?", (device_id,)).fetchone()[0] == 0
    assert conn.execute("SELECT COUNT(*) FROM findings WHERE status='resolved'").fetchone()[0] == 1


def test_trust_device_rejects_an_unknown_device(conn):
    with pytest.raises(KeyError):
        engine.trust_device(conn, 4242)


def test_a_device_trusted_before_its_finding_arrives_is_still_matched_by_subject(conn):
    """Older rows can carry a NULL device_id; the subject still identifies the device."""
    mac = "aa:bb:cc:11:22:33"
    device_id = _device(conn, mac)
    conn.execute(
        "INSERT INTO findings(finding_id, subject, dedupe_key, severity, title, status, source, first_seen,"
        " last_seen) VALUES ('NET-DEV-001',?,?,'medium','New device','open','discovery',"
        "'2099-01-01T00:00:00Z','2099-01-01T00:00:00Z')", (f"device:{mac}", f"NET-DEV-001|device:{mac}"))
    conn.commit()
    assert len(engine.new_device_findings(conn, device_id)) == 1
    assert len(engine.trust_device(conn, device_id)) == 1


def test_device_label_prefers_the_friendliest_name():
    assert engine.device_label({"nickname": "Kitchen TV", "hostname": "tv", "ip": "1.2.3.4"}) == "Kitchen TV"
    assert engine.device_label({"hostname": "tv", "ip": "1.2.3.4"}) == "tv"
    assert engine.device_label({"ip": "1.2.3.4", "mac": "aa"}) == "1.2.3.4"
    assert engine.device_label({"id": 7}) == "device 7"


# ------------------------------------------------------------------------------------------ score
def _seed(conn, finding_id, severity, count, status="open"):
    """Insert `count` findings of one type directly (bypassing the catalog's severity rules)."""
    start = conn.execute("SELECT COUNT(*) FROM findings WHERE finding_id=?", (finding_id,)).fetchone()[0]
    for i in range(start, start + count):
        conn.execute(
            "INSERT INTO findings(finding_id, subject, dedupe_key, severity, title, status, source,"
            " first_seen, last_seen) VALUES (?,?,?,?,?,?,'test','2099-01-01T00:00:00Z','2099-01-01T00:00:00Z')",
            (finding_id, f"subject:{i}", f"{finding_id}|{i}", severity, f"{finding_id} number {i}", status),
        )
    conn.commit()


def test_empty_database_is_a_hundred_and_an_a(conn):
    assert score.security_score(conn) == 100 and score.grade(100) == "A"
    assert score.score_breakdown(conn) == []
    assert score.score_detail(conn)["score"] == 100


def test_grade_bands(conn):
    assert [score.grade(s) for s in (100, 80, 79, 65, 64, 50, 35, 34, 0)] == [
        "A", "A", "B", "B", "C", "C", "D", "F", "F"]


def test_a_pile_of_one_finding_type_costs_at_most_twice_the_first(conn):
    """26 'outdated app' rows are one problem, not 26 (the defect that pinned the score to 0)."""
    _seed(conn, "WIN-UPD-003", "low", 1)
    one = 100 - score.security_score(conn)
    _seed(conn, "WIN-UPD-003", "low", 25)
    many = 100 - score.security_score(conn)
    assert conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0] == 26
    assert many < 2 * one + 1           # a whole pile costs less than twice a single one
    assert score.security_score(conn) >= 95    # low-severity hygiene must not tank the score
    # and the raw penalty is capped at exactly 2 x the first occurrence's weight
    assert score.group_penalty([(score.WEIGHTS["low"], 26)]) <= 2 * score.WEIGHTS["low"] + 1e-9


def test_the_authors_real_distribution_is_informative_not_pinned_to_zero(conn):
    """70 open findings measured on the author's machine: the old formula returned 0/F."""
    _seed(conn, "NET-DEV-001", "medium", 22)
    _seed(conn, "WIN-UPD-003", "low", 18)
    _seed(conn, "NET-DEV-002", "info", 8)
    _seed(conn, "WIN-UPD-004", "high", 5)
    for fid in ("NET-VUL-004", "WIN-UPD-002"):
        _seed(conn, fid, "high", 1)
    for fid in ("NET-VUL-003", "WIN-ACC-001", "WIN-UPD-001"):
        _seed(conn, fid, "medium", 1)
    for fid in ("WIN-DEF-007", "WIN-DEF-008", "WIN-DEF-009", "WIN-DEF-010",
                "WIN-NET-003", "WIN-NET-004", "WIN-SYS-003", "WIN-SYS-007"):
        _seed(conn, fid, "low", 1)
    for fid in ("NET-WIFI-002", "SOC-SYS-002", "WIN-DEF-013", "WIN-DEF-014"):
        _seed(conn, fid, "info", 1)
    assert conn.execute("SELECT COUNT(*) FROM findings WHERE status='open'").fetchone()[0] == 70
    value = score.security_score(conn)
    assert 25 < value < 55 and score.grade(value) in ("D", "C")


def test_criticals_still_tank_the_score(conn):
    _seed(conn, "NET-WAN-001", "critical", 1)
    value = score.security_score(conn)
    assert value <= score.CEILING_ONE_CRITICAL and score.grade(value) == "F"
    _seed(conn, "NET-VUL-001", "critical", 1)
    assert score.security_score(conn) <= score.CEILING_MANY_CRITICAL


def test_one_open_high_forbids_an_a(conn):
    _seed(conn, "WIN-UPD-002", "high", 1)
    value = score.security_score(conn)
    assert value == score.CEILING_ANY_HIGH and score.grade(value) == "B"


def test_acknowledged_costs_less_and_suppressed_costs_nothing(conn):
    _seed(conn, "WIN-ACC-001", "medium", 4)
    open_score = score.security_score(conn)
    conn.execute("UPDATE findings SET status='acknowledged'")
    conn.commit()
    ack_score = score.security_score(conn)
    assert open_score < ack_score < 100
    conn.execute("UPDATE findings SET status='suppressed'")
    conn.commit()
    assert score.security_score(conn) == 100
    conn.execute("UPDATE findings SET status='resolved'")
    conn.commit()
    assert score.security_score(conn) == 100 and score.score_breakdown(conn) == []


def test_fixing_the_top_item_raises_the_score(conn):
    _seed(conn, "WIN-UPD-004", "high", 5)
    _seed(conn, "NET-DEV-001", "medium", 22)
    _seed(conn, "WIN-UPD-003", "low", 18)
    before = score.security_score(conn)
    top = score.score_breakdown(conn)[0]
    assert top["finding_id"] == "WIN-UPD-004" and top["count"] == 5 and top["score_gain"] > 0
    conn.execute("UPDATE findings SET status='resolved' WHERE finding_id=?", (top["finding_id"],))
    conn.commit()
    after = score.security_score(conn)
    assert after == before + top["score_gain"] and after > before


def test_breakdown_shape_titles_and_order(conn):
    _seed(conn, "NET-DEV-001", "medium", 22)
    _seed(conn, "WIN-SYS-007", "low", 1)
    _seed(conn, "WIN-ACC-001", "medium", 2, status="acknowledged")
    _seed(conn, "NET-DEV-002", "info", 5)          # weight 0 -> costs nothing
    rows = score.score_breakdown(conn)
    by_id = {r["finding_id"]: r for r in rows}
    assert set(by_id) == {"NET-DEV-001", "WIN-SYS-007", "WIN-ACC-001", "NET-DEV-002"}
    assert {"finding_id", "title", "count", "penalty"} <= set(rows[0])
    assert [r["penalty"] for r in rows] == sorted((r["penalty"] for r in rows), reverse=True)
    # a group of many uses the catalog title with the per-instance details stripped out
    assert by_id["NET-DEV-001"]["title"] == "New device on the network"
    assert by_id["NET-DEV-001"]["count"] == 22 and by_id["NET-DEV-001"]["open"] == 22
    # a single finding keeps its own concrete title
    assert by_id["WIN-SYS-007"]["title"] == "WIN-SYS-007 number 0"
    assert by_id["WIN-ACC-001"]["acknowledged"] == 2 and by_id["WIN-ACC-001"]["open"] == 0
    assert by_id["NET-DEV-002"]["penalty"] == 0.0 and by_id["NET-DEV-002"]["score_gain"] == 0


def test_generic_title_strips_per_instance_details():
    assert score.generic_title("NET-DEV-001") == "New device on the network"
    assert score.generic_title("WIN-UPD-003") == "Outdated app"
    assert score.generic_title("NET-VUL-001") == "Known exploited vulnerability"
    assert score.generic_title("NET-WAN-001") == "Port is open to the internet on your public IP"
    assert score.generic_title("WIN-DEF-001") == "Windows Defender antivirus is disabled"
    assert score.generic_title("NO-SUCH-ID", "fallback title") == "fallback title"
    assert score.generic_title("NO-SUCH-ID") == "NO-SUCH-ID"


def test_score_detail_matches_the_parts(conn):
    _seed(conn, "WIN-UPD-004", "high", 3)
    detail = score.score_detail(conn)
    assert detail["score"] == score.security_score(conn)
    assert detail["grade"] == score.grade(detail["score"])
    assert detail["breakdown"] == score.score_breakdown(conn)
    assert detail["open_high"] == 3 and detail["open_critical"] == 0 and detail["penalty"] > 0


def test_score_survives_a_database_without_a_findings_table():
    bare = sqlite3.connect(":memory:")
    bare.row_factory = sqlite3.Row
    assert score.security_score(bare) == 100 and score.score_breakdown(bare) == []
    assert score.trend(bare) == []


def test_score_lifecycle_through_the_engine(conn):
    engine.apply(conn, [FindingDraft("WIN-DEF-001", "host"), FindingDraft("WIN-DEF-006", "host")], "host")
    with_critical = score.security_score(conn)
    assert with_critical <= score.CEILING_ONE_CRITICAL
    row = engine.list_findings(conn, severity="critical")[0]
    engine.set_status(conn, row["id"], "resolved")
    assert score.security_score(conn) > with_critical


def test_trend_reads_score_metric(conn):
    conn.execute("INSERT INTO metrics(ts, name, value) VALUES ('2099-01-01T01:00:00Z', 'score', 80)")
    conn.execute("INSERT INTO metrics(ts, name, value) VALUES ('2099-01-01T05:00:00Z', 'score', 90)")
    conn.execute("INSERT INTO metrics(ts, name, value) VALUES ('2099-01-02T01:00:00Z', 'score', 70)")
    conn.execute("INSERT INTO metrics(ts, name, value) VALUES ('2099-01-02T01:00:00Z', 'other', 1)")
    conn.commit()
    assert score.trend(conn, days=365 * 200) == [["2099-01-01", 90], ["2099-01-02", 70]]
    assert score.record_score(conn) == 100
    assert conn.execute("SELECT COUNT(*) FROM metrics WHERE name='score'").fetchone()[0] == 4


# ----------------------------------------------------------------------------------------- notify
def _cfg(**kw):
    base = dict(min_severity="high", ntfy_url="", discord_webhook="", webhook_url="", windows_toast=False, digest_hour=8)
    base.update(kw)
    return SimpleNamespace(notify=SimpleNamespace(**base))


class FakePoster:
    def __init__(self, fail: set[str] | None = None):
        self.calls: list[dict] = []
        self.fail = fail or set()

    def __call__(self, url, *, json=None, data=None, headers=None):
        self.calls.append({"url": url, "json": json, "data": data, "headers": headers})
        return (False, "boom") if url in self.fail else (True, None)


def test_ntfy_payload_priority_and_headers():
    p = channels.build_ntfy("Title", "body", "critical")
    assert p["headers"]["Priority"] == "5" and p["headers"]["Title"] == "Title" and "homesoc" in p["headers"]["Tags"]
    assert p["data"] == b"body"
    assert channels.build_ntfy("t", "b", "high")["headers"]["Priority"] == "4"
    assert channels.build_ntfy("t", "b", "medium")["headers"]["Priority"] == "3"
    assert channels.build_ntfy("t", "b", "info")["headers"]["Priority"] == "3"
    assert channels.build_ntfy("Café", "b", "info")["headers"]["Title"].isascii()


def test_discord_and_webhook_payload_shapes():
    findings = [{"id": 1, "finding_id": "WIN-DEF-001", "subject": "host", "severity": "critical", "title": "AV off", "remediation": ["x"]}]
    d = channels.build_discord("Subj", "Body", "critical", findings)
    assert d["content"] == "**Subj**"
    assert d["embeds"][0]["description"] == "Body" and d["embeds"][0]["color"] == 0xE5484D
    assert "1 finding" in d["embeds"][0]["title"]
    w = channels.build_webhook("Subj", "Body", "high", findings)
    assert w["subject"] == "Subj" and w["body"] == "Body" and w["severity"] == "high"
    assert w["findings"] == [{"id": 1, "finding_id": "WIN-DEF-001", "subject": "host", "severity": "critical", "title": "AV off"}]


def test_transport_errors_never_carry_the_webhook_secret(monkeypatch):
    """The Discord token and the ntfy topic live in the URL path, and errors reach homesoc.log
    and the notifications table, so nothing derived from the URL may survive into them."""
    requests = pytest.importorskip("requests")
    discord = "https://discord.com/api/webhooks/1234567890/S3CR3T-token_value"
    ntfy = "https://ntfy.sh/my-secret-topic-9x"

    def raise_connection_error(url, **kw):
        raise requests.ConnectionError(
            "HTTPSConnectionPool(host='discord.com', port=443): Max retries exceeded with url: "
            "/api/webhooks/1234567890/S3CR3T-token_value (Caused by NewConnectionError)"
        )

    monkeypatch.setattr(requests, "post", raise_connection_error)
    for url, secret in ((discord, "S3CR3T-token_value"), (ntfy, "my-secret-topic-9x")):
        ok, err = channels._default_poster(url, json={})
        assert ok is False and secret not in err and url not in err
    assert channels._default_poster(discord, json={})[1] == "ConnectionError talking to discord.com"

    class Response:
        status_code = 404
        text = "unknown webhook /api/webhooks/1234567890/S3CR3T-token_value"

    monkeypatch.setattr(requests, "post", lambda url, **kw: Response())
    ok, err = channels._default_poster(discord, json={})
    assert ok is False and "404" in err and "S3CR3T-token_value" not in err


def test_runner_reports_a_failed_toast_instead_of_claiming_success():
    """A toast Windows refuses to show must not be recorded as 'sent'."""
    ok, err = channels._default_runner([sys.executable, "-c", "import sys; sys.stderr.write('nope'); sys.exit(3)"])
    assert ok is False and "nope" in err
    ok, err = channels._default_runner([sys.executable, "-c", "pass"])
    assert ok is True and err is None
    ok, err = channels._default_runner(["homesoc-no-such-binary-xyz"])
    assert ok is False and err


def test_toast_script_escapes_xml_and_encodes():
    xml = channels.build_toast_xml("A <b> & 'c' \"d\"", "line")
    assert "<b>" not in xml and "&lt;b&gt;" in xml and "&apos;c&apos;" in xml and "&quot;d&quot;" in xml
    script = channels.build_toast_script("x'y", "$(calc)")
    assert "x'y" not in script and "x&apos;y" in script
    assert "ToastNotificationManager" in script
    # Windows silently drops toasts raised under an AppUserModelID nothing registered, and Home SOC
    # registers none (make-autostart.ps1 writes a plain Startup shortcut). Borrow PowerShell's own
    # AUMID, which Windows always has, so the toast is actually displayed.
    assert f"CreateToastNotifier('{channels.TOAST_APP_ID}')" in script
    assert channels.TOAST_APP_ID.endswith(r"\WindowsPowerShell\v1.0\powershell.exe")
    assert "Home SOC" not in channels.TOAST_APP_ID
    # A failure must surface as a non-zero exit, not a silent "sent".
    assert "$ErrorActionPreference = 'Stop'" in script
    argv = channels.build_toast_argv("t", "b")
    assert argv[0] == "powershell" and "-EncodedCommand" in argv and "-NonInteractive" in argv
    decoded = base64.b64decode(argv[-1]).decode("utf-16-le")
    assert decoded == channels.build_toast_script("t", "b") and "ToastGeneric" in decoded


def test_notify_new_findings_filters_and_batches(conn):
    poster = FakePoster()
    cfg = _cfg(ntfy_url="https://ntfy.example/t", discord_webhook="https://discord.example/w", webhook_url="https://hook.example")
    new = [
        {"id": 1, "finding_id": "WIN-DEF-006", "subject": "host", "severity": "low", "title": "PUA off"},
        {"id": 2, "finding_id": "WIN-DEF-001", "subject": "host", "severity": "critical", "title": "AV off"},
        {"id": 3, "finding_id": "WIN-FW-002", "subject": "host", "severity": "high", "title": "Inbound allow"},
    ]
    res = channels.notify_new_findings(cfg, conn, new, poster=poster)
    assert res == {"ntfy": True, "discord": True, "webhook": True}
    assert len(poster.calls) == 3  # one message per channel, not per finding
    ntfy = poster.calls[0]
    assert ntfy["headers"]["Priority"] == "5"
    assert b"AV off" in ntfy["data"] and b"Inbound allow" in ntfy["data"] and b"PUA off" not in ntfy["data"]
    hook = poster.calls[2]["json"]
    assert [f["id"] for f in hook["findings"]] == [2, 3] and hook["severity"] == "critical"
    assert "2 new critical findings" in hook["subject"]
    rows = conn.execute("SELECT channel, status FROM notifications ORDER BY id").fetchall()
    assert [(r["channel"], r["status"]) for r in rows] == [("ntfy", "sent"), ("discord", "sent"), ("webhook", "sent")]


def test_notify_below_threshold_sends_nothing(conn):
    poster = FakePoster()
    cfg = _cfg(ntfy_url="https://ntfy.example/t", min_severity="critical")
    assert channels.notify_new_findings(cfg, conn, [{"severity": "high", "title": "x"}], poster=poster) == {}
    assert poster.calls == []


def test_failed_channel_does_not_block_others_and_is_recorded(conn):
    poster = FakePoster(fail={"https://discord.example/w"})
    cfg = _cfg(ntfy_url="https://ntfy.example/t", discord_webhook="https://discord.example/w")
    res = channels.send(cfg, conn, "s", "b", severity="high", poster=poster)
    assert res == {"ntfy": True, "discord": False}
    row = conn.execute("SELECT status, error FROM notifications WHERE channel='discord'").fetchone()
    assert row["status"] == "error" and row["error"] == "boom"


def test_toast_uses_runner_only_on_windows(conn, monkeypatch):
    calls = []

    def runner(argv):
        calls.append(argv)
        return True, None

    cfg = _cfg(windows_toast=True)
    monkeypatch.setattr(channels.sys, "platform", "win32")
    assert channels.test_channels(cfg, conn, poster=FakePoster(), runner=runner) == {"toast": True}
    assert calls and calls[0][0] == "powershell"
    monkeypatch.setattr(channels.sys, "platform", "linux")
    assert channels.test_channels(cfg, conn, poster=FakePoster(), runner=runner) == {}


def test_send_with_nothing_configured_records_nothing(conn):
    assert channels.send(_cfg(), conn, "s", "b", poster=FakePoster()) == {}
    assert conn.execute("SELECT COUNT(*) FROM notifications").fetchone()[0] == 0


def test_digest_contents(conn):
    engine.apply(conn, [FindingDraft("WIN-DEF-001", "host"), FindingDraft("WIN-DEF-006", "host")], "host")
    subject, body, top = channels.build_digest(conn)
    assert "score 34" in subject and "2 open findings" in subject
    assert "critical 1" in body and "low 1" in body and "[CRITICAL]" in body
    assert [t["finding_id"] for t in top] == ["WIN-DEF-001", "WIN-DEF-006"]
    poster = FakePoster()
    res = channels.send_digest(_cfg(webhook_url="https://hook.example"), conn, poster=poster)
    assert res == {"webhook": True} and poster.calls[0]["json"]["severity"] == "critical"
    assert channels.send_digest(_cfg(webhook_url="https://hook.example", digest_hour=-1), conn, poster=poster) == {}
