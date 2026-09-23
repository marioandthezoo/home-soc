"""Offline tests for the host / AV work package (P4): posture JSON -> checks/findings, Defender status
and threat normalisation, winget table parsing, persistence baselining and file hash checks.

No PowerShell or network is used; the probes' JSON is replaced by fixtures under
tests/fixtures/posture/ and the VirusTotal call is stubbed.
"""

from __future__ import annotations

import dataclasses
import json
import os
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from homesoc import db
from homesoc.config import Config
from homesoc.models import FindingDraft, HostCheck
from homesoc.scanners import defender, files, host_posix, host_windows, persistence, updates
from homesoc.scanners.host_windows import Collector, PsResult

FIXTURES = Path(__file__).parent / "fixtures" / "posture"

# Every WIN-* ID the posture probe alone can answer (WIN-UPD-001/003/004 come from updates.py,
# WIN-PER-* from persistence.py, WIN-DEF-011 is present but derived from the probe's detections).
POSTURE_IDS = {
    *(f"WIN-DEF-{n:03d}" for n in range(1, 15)),
    "WIN-FW-001", "WIN-FW-002",
    "WIN-UPD-002",
    *(f"WIN-ACC-{n:03d}" for n in range(1, 6)),
    *(f"WIN-NET-{n:03d}" for n in range(1, 7)),
    *(f"WIN-SYS-{n:03d}" for n in range(1, 9)),
}


@pytest.fixture
def posture() -> dict:
    return json.loads((FIXTURES / "win_nonadmin.json").read_text(encoding="utf-8"))


@pytest.fixture
def defender_status() -> dict:
    return json.loads((FIXTURES / "defender_status.json").read_text(encoding="utf-8"))


@pytest.fixture
def conn(tmp_path: Path):
    c = db.connect(tmp_path / "test.db")
    yield c
    c.close()


@pytest.fixture
def cfg() -> Config:
    return Config()


def _by_id(checks: list[HostCheck]) -> dict[str, HostCheck]:
    out = {c.check_id: c for c in checks}
    assert len(out) == len(checks), "duplicate check IDs"
    return out


def _findings(drafts: list[FindingDraft], fid: str) -> list[FindingDraft]:
    return [d for d in drafts if d.finding_id == fid]


# ------------------------------------------------------------------ host_windows: posture fixture


class TestPostureEvaluation:
    def test_every_posture_check_id_present(self, posture, cfg):
        checks, findings, summary = host_windows.evaluate(posture, cfg)
        ids = _by_id(checks)
        assert POSTURE_IDS <= set(ids)
        assert all(c.status in ("pass", "fail", "warn", "unknown", "needs_admin") for c in checks)
        assert all(d.subject == "host" for d in findings)
        assert summary["is_admin"] is False
        assert summary["total"] == len(checks)

    def test_ground_truth_verdicts(self, posture, cfg):
        checks, findings, _ = host_windows.evaluate(posture, cfg)
        ids = _by_id(checks)
        expected = {
            "WIN-DEF-001": "pass", "WIN-DEF-002": "pass", "WIN-DEF-003": "pass", "WIN-DEF-004": "pass",
            "WIN-DEF-005": "pass", "WIN-DEF-006": "pass", "WIN-DEF-007": "fail", "WIN-DEF-008": "fail",
            "WIN-DEF-009": "fail", "WIN-DEF-010": "pass", "WIN-DEF-011": "pass", "WIN-DEF-012": "pass",
            "WIN-DEF-013": "fail", "WIN-DEF-014": "fail",
            "WIN-FW-001": "pass", "WIN-FW-002": "pass",
            "WIN-ACC-001": "fail", "WIN-ACC-002": "pass", "WIN-ACC-003": "pass", "WIN-ACC-004": "pass", "WIN-ACC-005": "pass",
            "WIN-NET-001": "pass", "WIN-NET-002": "pass", "WIN-NET-003": "fail", "WIN-NET-004": "fail",
            "WIN-NET-005": "pass", "WIN-NET-006": "fail",
            "WIN-SYS-001": "pass", "WIN-SYS-002": "needs_admin", "WIN-SYS-003": "fail", "WIN-SYS-004": "pass",
            "WIN-SYS-005": "needs_admin", "WIN-SYS-006": "pass", "WIN-SYS-007": "fail", "WIN-SYS-008": "needs_admin",
            "WIN-UPD-002": "fail",
        }
        mismatches = {k: (v, ids[k].status) for k, v in expected.items() if ids[k].status != v}
        assert not mismatches
        # findings exist exactly for fail/warn checks (per-subject ones may repeat)
        failing = {k for k, c in ids.items() if c.status in ("fail", "warn")}
        emitted = {d.finding_id for d in findings} - {"SOC-SYS-002"}
        assert emitted == failing

    def test_needs_admin_rows_and_soc_sys_002(self, posture, cfg):
        checks, findings, _ = host_windows.evaluate(posture, cfg)
        ids = _by_id(checks)
        for cid in ("WIN-SYS-002", "WIN-SYS-008", "WIN-SYS-005"):
            assert ids[cid].needs_admin is True
        assert "PnP" in (ids["WIN-SYS-008"].value or "")
        soc = _findings(findings, "SOC-SYS-002")
        assert len(soc) == 1
        assert {"WIN-SYS-002", "WIN-SYS-008", "WIN-SYS-005"} <= set(soc[0].evidence["skipped"])
        assert soc[0].evidence["is_admin"] is False

    def test_secure_boot_registry_fallback(self, posture, cfg):
        checks, _, _ = host_windows.evaluate(posture, cfg)
        sb = _by_id(checks)["WIN-SYS-001"]
        assert sb.status == "pass" and "registry" in (sb.value or "")
        posture["secure_boot_registry"] = 0
        checks, findings, _ = host_windows.evaluate(posture, cfg)
        assert _by_id(checks)["WIN-SYS-001"].status == "fail"
        assert _findings(findings, "WIN-SYS-001")

    def test_unusual_listeners_only_lan_reachable(self, posture, cfg):
        checks, findings, _ = host_windows.evaluate(posture, cfg)
        net6 = _findings(findings, "WIN-NET-006")
        assert [d.evidence["key"] for d in net6] == ["65001"]
        assert net6[0].evidence["process"] == "node"
        assert "65001" in (_by_id(checks)["WIN-NET-006"].value or "")

    def test_admin_user_is_a_finding(self, posture, cfg):
        _, findings, _ = host_windows.evaluate(posture, cfg)
        acc = _findings(findings, "WIN-ACC-001")
        assert len(acc) == 1 and acc[0].evidence["user"] == "LAPTOP-HOME\\daily"
        posture["admins"]["current_is_admin_member"] = False
        checks, findings, _ = host_windows.evaluate(posture, cfg)
        assert _by_id(checks)["WIN-ACC-001"].status == "pass"
        assert not _findings(findings, "WIN-ACC-001")

    def test_firewall_per_profile_and_inbound_allow(self, posture, cfg):
        posture["firewall"] = [
            {"name": "Domain", "enabled": True, "default_inbound": "Block"},
            {"name": "Private", "enabled": True, "default_inbound": "Allow"},
            {"name": "Public", "enabled": False, "default_inbound": 2},
        ]
        checks, findings, _ = host_windows.evaluate(posture, cfg)
        ids = _by_id(checks)
        assert ids["WIN-FW-001"].status == "fail" and ids["WIN-FW-002"].status == "fail"
        assert [d.evidence["key"] for d in _findings(findings, "WIN-FW-001")] == ["Public"]
        assert _findings(findings, "WIN-FW-002")[0].evidence["profiles"] == ["Private"]
        posture["firewall"] = "ACCESS_DENIED"
        checks, _, _ = host_windows.evaluate(posture, cfg)
        assert _by_id(checks)["WIN-FW-001"].status == "needs_admin"

    def test_rdp_without_nla_escalates(self, posture, cfg):
        posture["rdp"] = {"fDenyTSConnections": 0, "UserAuthentication": 0}
        _, findings, _ = host_windows.evaluate(posture, cfg)
        rdp = _findings(findings, "WIN-NET-002")
        assert len(rdp) == 1 and rdp[0].severity == "high"
        posture["rdp"] = {"fDenyTSConnections": 0, "UserAuthentication": 1}
        _, findings, _ = host_windows.evaluate(posture, cfg)
        assert _findings(findings, "WIN-NET-002")[0].severity is None

    def test_scalar_sections_are_tolerated(self, posture, cfg):
        """PowerShell unrolls one-element arrays; evaluation must not choke on a scalar."""
        posture["dns"] = {"interface": "Wi-Fi", "servers": ["192.168.1.254"]}
        posture["listeners"] = posture["listeners"][0]
        posture["bitlocker"] = {"mount": "C:", "protection": "On", "status": "FullyEncrypted"}
        checks, _, _ = host_windows.evaluate(posture, cfg)
        ids = _by_id(checks)
        assert ids["WIN-SYS-002"].status == "pass"
        assert ids["WIN-NET-006"].status == "pass"

    def test_defender_section_denied(self, posture, cfg):
        posture["defender"] = "ACCESS_DENIED"
        checks, _, _ = host_windows.evaluate(posture, cfg)
        ids = _by_id(checks)
        assert all(ids[c].status == "needs_admin" for c in defender.STATUS_CHECK_IDS)


class TestHostWindowsRun:
    def test_run_writes_host_checks_and_settings(self, posture, cfg, conn, monkeypatch):
        monkeypatch.setattr(host_windows, "is_windows", lambda: True)
        monkeypatch.setattr(host_windows, "run_ps_json", lambda script, *, timeout, args=(): PsResult(posture, duration_sec=1.0))
        seen: list[str] = []
        result = host_windows.run(cfg, conn, progress=seen.append)
        assert result.error is None and result.kind == "host"
        rows = db.query(conn, "SELECT check_id, status, needs_admin FROM host_checks")
        assert {r["check_id"] for r in rows} >= POSTURE_IDS
        assert any(r["needs_admin"] == 1 for r in rows)
        assert db.get_setting(conn, "host.posture_json")
        assert result.summary["fail"] > 0 and seen
        # second run upserts (PK) rather than duplicating
        host_windows.run(cfg, conn)
        assert len(db.query(conn, "SELECT 1 FROM host_checks")) == len(rows)

    def test_run_probe_failure_is_reported_not_raised(self, cfg, conn, monkeypatch):
        monkeypatch.setattr(host_windows, "is_windows", lambda: True)
        monkeypatch.setattr(host_windows, "run_ps_json", lambda *a, **k: PsResult(None, error="boom"))
        result = host_windows.run(cfg, conn)
        assert result.error == "boom" and result.findings == []

    def test_run_disabled_by_config(self, cfg, conn, monkeypatch):
        monkeypatch.setattr(host_windows, "is_windows", lambda: True)
        off = dataclasses.replace(cfg, host=dataclasses.replace(cfg.host, posture=False))
        assert host_windows.run(off, conn).summary["skipped"] == "host.posture disabled"

    def test_run_defers_to_windows_update_history_for_win_upd_002(self, posture, cfg, conn, monkeypatch):
        """The hotfix list and the WU history must never publish opposite WIN-UPD-002 verdicts."""
        monkeypatch.setattr(host_windows, "is_windows", lambda: True)
        monkeypatch.setattr(host_windows, "run_ps_json", lambda script, *, timeout, args=(): PsResult(posture, duration_sec=1.0))
        assert db.one(conn, "SELECT 1 AS x") is not None
        fresh = (datetime.now(timezone.utc) - timedelta(days=2)).strftime("%Y-%m-%dT%H:%M:%SZ")
        db.set_setting(conn, "updates.status_json", json.dumps({"history": {"last_cumulative_date": fresh}}))
        result = host_windows.run(cfg, conn)
        assert db.one(conn, "SELECT status FROM host_checks WHERE check_id='WIN-UPD-002'")["status"] == "pass"
        assert not _findings(result.findings, "WIN-UPD-002")

    def test_run_tolerates_unusable_updates_setting(self, posture, cfg, conn, monkeypatch):
        monkeypatch.setattr(host_windows, "is_windows", lambda: True)
        monkeypatch.setattr(host_windows, "run_ps_json", lambda script, *, timeout, args=(): PsResult(posture, duration_sec=1.0))
        db.set_setting(conn, "updates.status_json", "{not json")
        result = host_windows.run(cfg, conn)
        assert result.error is None
        assert db.one(conn, "SELECT status FROM host_checks WHERE check_id='WIN-UPD-002'")["status"] == "fail"


class TestSkippedChecks:
    def test_renders_as_text_but_stays_a_list(self):
        s = host_windows.SkippedChecks(["WIN-SYS-002", "WIN-SYS-008"])
        assert "skipped: {skipped}".format(skipped=s) == "skipped: WIN-SYS-002, WIN-SYS-008"
        assert list(s) == ["WIN-SYS-002", "WIN-SYS-008"] and json.loads(json.dumps(s)) == list(s)
        assert str(host_windows.SkippedChecks()) == "nothing"

    def test_soc_sys_002_title_has_no_python_repr(self, posture, cfg):
        from homesoc.findings import catalog

        _, findings, _ = host_windows.evaluate(posture, cfg)
        title = catalog.render(_findings(findings, "SOC-SYS-002")[0])[0]
        assert "[" not in title and "WIN-SYS-002, WIN-SYS-005, WIN-SYS-008" in title


class TestHelpers:
    def test_extract_json_skips_noise(self):
        assert host_windows.extract_json('WARNING: x\n{"a": 1}\n') == {"a": 1}
        assert host_windows.extract_json("nothing here") is None
        assert host_windows.extract_json("") is None

    def test_truthy_and_as_list(self):
        assert host_windows.truthy("True") is True and host_windows.truthy("False") is False
        assert host_windows.truthy(None) is None and host_windows.truthy(1) is True
        assert host_windows.as_list(None) == [] and host_windows.as_list("ACCESS_DENIED") == []
        assert host_windows.as_list({"a": 1}) == [{"a": 1}] and host_windows.as_list([1]) == [1]

    def test_collector_summary(self):
        c = Collector()
        c.ok("A"); c.fail("B", "v", "e"); c.denied("C"); c.warn("D", "v", "e"); c.unknown("E")
        s = c.summary()
        assert (s["total"], s["pass"], s["fail"], s["warn"], s["needs_admin"], s["unknown"]) == (5, 1, 1, 1, 1, 1)
        assert c.skipped == ["C"]
        assert {d.finding_id for d in c.findings} == {"B", "D"}


# ------------------------------------------------------------------ defender


class TestDefender:
    def test_status_fixture(self, defender_status):
        checks, findings = defender.evaluate_status(defender_status)
        ids = _by_id(checks)
        assert ids["WIN-DEF-001"].status == "pass" and ids["WIN-DEF-002"].status == "pass"
        assert ids["WIN-DEF-003"].status == "pass" and "1 days" in ids["WIN-DEF-003"].value
        assert ids["WIN-DEF-007"].status == "fail" and ids["WIN-DEF-007"].value == "never"
        assert ids["WIN-DEF-010"].status == "fail"  # no ASR rules
        assert ids["WIN-DEF-013"].status == "fail"  # Smart App Control off
        assert ids["WIN-DEF-014"].status == "fail"  # CloudBlockLevel 0
        assert ids["WIN-DEF-012"].status == "pass"
        assert set(defender.STATUS_CHECK_IDS) | {"WIN-DEF-013"} == set(ids)
        assert {d.finding_id for d in findings} == {"WIN-DEF-007", "WIN-DEF-008", "WIN-DEF-009", "WIN-DEF-010", "WIN-DEF-013", "WIN-DEF-014"}

    def test_disabled_and_audit_states(self, defender_status):
        st = dict(defender_status, AntivirusEnabled=False, RealTimeProtectionEnabled=False, AntivirusSignatureAge=9,
                  IsTamperProtected=False, MAPSReporting=0, PUAProtection=2, AMRunningMode="SxS Passive Mode")
        checks, _ = defender.evaluate_status(st)
        ids = _by_id(checks)
        assert ids["WIN-DEF-001"].status == "fail" and ids["WIN-DEF-002"].status == "fail"
        assert ids["WIN-DEF-003"].status == "fail" and ids["WIN-DEF-004"].status == "fail"
        assert ids["WIN-DEF-005"].status == "fail" and ids["WIN-DEF-006"].status == "warn"
        assert ids["WIN-DEF-012"].status == "pass"  # passive mode is a healthy state

    def test_status_error_paths(self):
        checks, _ = defender.evaluate_status({"error": "ACCESS_DENIED"})
        assert all(c.status == "needs_admin" for c in checks)
        checks, findings = defender.evaluate_status({"error": "ERROR: module missing"})
        assert all(c.status == "unknown" for c in checks) and not findings

    def test_normalize_threats_collapses_events(self):
        raw = {
            "detections": [{"threat_id": "2147", "threat_name": "Trojan:Win32/Evil", "detected_at": "2026-09-01T10:00:00Z",
                            "path": "C:\\Users\\x\\Downloads\\bad.exe", "action_success": True, "process": "chrome.exe"}],
            "events": [
                {"event_id": 1116, "time": "2026-09-01T10:00:01Z", "threat_name": "Trojan:Win32/Evil", "path": "C:\\Users\\x\\Downloads\\bad.exe", "action": "Quarantine", "severity": "Severe"},
                {"event_id": 1117, "time": "2026-09-01T10:00:05Z", "threat_name": "Trojan:Win32/Evil", "path": "c:\\users\\x\\downloads\\BAD.EXE", "action": "Quarantine", "severity": "Severe"},
                {"event_id": 5001, "time": "2026-09-02T08:00:00Z", "message": "Real-time protection is disabled."},
                {"event_id": 1006, "time": "2026-08-20T00:00:00Z", "threat_name": "PUA:Win32/Bundler", "path": "D:\\setup.exe"},
            ],
        }
        items = defender.normalize_threats(raw)
        kinds = [(i["kind"], i["threat_name"]) for i in items]
        assert kinds == [("threat", "Trojan:Win32/Evil"), ("protection_change", "Defender event 5001"), ("threat", "PUA:Win32/Bundler")]
        evil = items[0]
        assert evil["detected_at"] == "2026-09-01T10:00:05Z" and evil["event_id"] == 1117 and evil["severity"] == "Severe"
        assert evil["process"] == "chrome.exe" and evil["threat_id"] == "2147"
        check, findings = defender.evaluate_threats(items)
        assert check.status == "fail" and "2 threat" in check.value
        assert [d.finding_id for d in findings] == ["WIN-DEF-011", "WIN-DEF-011"]
        assert len({d.evidence["key"] for d in findings}) == 2

    def test_no_threats_is_pass(self):
        check, findings = defender.evaluate_threats([])
        assert check.status == "pass" and findings == []

    def test_mpcmdrun_path_prefers_program_files_then_newest_platform(self, tmp_path, monkeypatch):
        monkeypatch.setattr(defender, "is_windows", lambda: True)
        pf = tmp_path / "pf"
        pd = tmp_path / "pd"
        monkeypatch.setenv("ProgramFiles", str(pf))
        monkeypatch.setenv("ProgramData", str(pd))
        assert defender.mpcmdrun_path() is None
        plat = pd / "Microsoft" / "Windows Defender" / "Platform"
        for ver in ("4.18.25010.1-0", "4.18.26080.3-0"):
            (plat / ver).mkdir(parents=True)
            (plat / ver / "MpCmdRun.exe").write_bytes(b"")
        assert defender.mpcmdrun_path().parent.name == "4.18.26080.3-0"
        assert defender.mpcmdrun_path({"AMProductVersion": "4.18.25010.1"}).parent.name == "4.18.25010.1-0"
        (pf / "Windows Defender").mkdir(parents=True)
        (pf / "Windows Defender" / "MpCmdRun.exe").write_bytes(b"")
        assert defender.mpcmdrun_path().parent == pf / "Windows Defender"

    def test_run_persists_status_json(self, defender_status, cfg, conn, monkeypatch):
        monkeypatch.setattr(defender, "is_windows", lambda: True)
        monkeypatch.setattr(defender, "status", lambda cfg=None: defender_status)
        monkeypatch.setattr(defender, "_threats_raw", lambda cfg=None, days=30: {"detections": [], "events": [], "activity": {}})
        result = defender.run(cfg, conn)
        assert result.error is None
        assert json.loads(db.get_setting(conn, "defender.status_json"))["AMProductVersion"] == defender_status["AMProductVersion"]
        assert db.one(conn, "SELECT status FROM host_checks WHERE check_id='WIN-DEF-011'")["status"] == "pass"
        assert result.summary["threats"] == 0 and result.summary["signature_age_days"] == 1

    def test_run_keeps_last_good_status_when_the_probe_fails(self, defender_status, cfg, conn, monkeypatch):
        """One failed probe must not blank the AV panel; it records an error alongside the old data."""
        monkeypatch.setattr(defender, "is_windows", lambda: True)
        monkeypatch.setattr(defender, "status", lambda cfg=None: defender_status)
        monkeypatch.setattr(defender, "_threats_raw", lambda cfg=None, days=30: {"activity": {"last_signature_update": "2026-09-06T11:04:04Z"}})
        defender.run(cfg, conn)
        monkeypatch.setattr(defender, "status", lambda cfg=None: {"error": "ERROR: module missing"})
        result = defender.run(cfg, conn)
        assert result.error == "ERROR: module missing"
        assert json.loads(db.get_setting(conn, "defender.status_json"))["AntivirusEnabled"] is True
        assert "module missing" in db.get_setting(conn, "defender.status_error")
        assert json.loads(db.get_setting(conn, "defender.activity_json"))["last_signature_update"] == "2026-09-06T11:04:04Z"


class TestDefenderActivity:
    def test_normalize_activity_from_probe(self):
        act = defender.normalize_activity({
            "days": 30,
            "activity": {"last_scan_started": "2026-09-04T19:00:45Z", "last_scan_finished": "2026-09-04T19:03:51Z",
                         "last_scan_type": "Antimalware", "last_signature_update": "2026-09-07T15:57:38Z",
                         "last_signature_version": "1.459.97.0", "last_signature_failure": None,
                         "last_signature_failure_reason": "", "config_changes": "151", "scans": 26,
                         "signature_updates": "96"},
            "errors": {"get_mpthreatdetection": "ACCESS_DENIED"},
        })
        assert act["config_changes"] == 151 and act["signature_updates"] == 96 and act["scans"] == 26
        assert act["last_signature_version"] == "1.459.97.0" and act["last_signature_failure_reason"] is None
        assert act["errors"] == {"get_mpthreatdetection": "ACCESS_DENIED"} and act["days"] == 30

    def test_normalize_activity_on_empty_probe(self):
        act = defender.normalize_activity({})
        assert act["config_changes"] == 0 and act["last_scan_finished"] is None and act["errors"] == {}

    def test_housekeeping_events_are_never_counted_as_threats(self):
        """A signature-update event carries no threat name; it must not raise WIN-DEF-011."""
        items = defender.normalize_threats({"events": [
            {"event_id": 2000, "time": "2026-09-07T15:57:38Z", "message": "Signature updated."},
            {"event_id": 1116, "time": "2026-09-07T16:00:00Z", "threat_name": "Trojan:Win32/Evil", "path": "C:\\a.exe"},
        ]})
        assert [i["kind"] for i in items] == ["protection_change", "threat"]
        check, findings = defender.evaluate_threats(items)
        assert check.status == "fail" and len(findings) == 1


class TestDefenderActions:
    @pytest.fixture(autouse=True)
    def _reset(self, monkeypatch, tmp_path):
        monkeypatch.setattr(defender, "_SCAN_THREAD", None, raising=False)
        monkeypatch.setattr(defender, "_UPDATE_THREAD", None, raising=False)
        defender._UPDATE_STATE.update(defender._blank_action_state())
        defender._SCAN_STATE.update(defender._blank_action_state())
        yield
        defender._UPDATE_STATE.update(defender._blank_action_state())
        defender._SCAN_STATE.update(defender._blank_action_state())

    def test_update_is_started_in_the_background_and_polled(self, monkeypatch, tmp_path):
        exe = tmp_path / "MpCmdRun.exe"
        exe.write_bytes(b"")
        monkeypatch.setattr(defender, "mpcmdrun_path", lambda status_info=None: exe)
        gate = threading.Event()
        calls: list[list[str]] = []

        def fake_run(argv, timeout):
            calls.append(list(argv))
            gate.wait(5)
            return 0, "signature update finished", ""

        monkeypatch.setattr(defender, "_run_mpcmdrun", fake_run)
        started = time.monotonic()
        assert defender.trigger_signature_update(None) is True
        assert time.monotonic() - started < 2.0, "the trigger must not wait for MpCmdRun"
        st = defender.update_status()
        assert st["running"] is True and st["available"] is True and st["ok"] is None
        # A second click must not stack another MpCmdRun process.
        assert defender.trigger_signature_update(None) is True
        gate.set()
        for _ in range(100):
            if not defender.update_running():
                break
            time.sleep(0.05)
        assert calls == [["-SignatureUpdate"]]
        done = defender.update_status()
        assert done["running"] is False and done["ok"] is True and done["rc"] == 0
        assert done["started_at"] and done["finished_at"] and "signature update finished" in done["message"]

    def test_failure_is_recorded_not_raised(self, monkeypatch, tmp_path):
        exe = tmp_path / "MpCmdRun.exe"
        exe.write_bytes(b"")
        monkeypatch.setattr(defender, "mpcmdrun_path", lambda status_info=None: exe)
        monkeypatch.setattr(defender, "_run_mpcmdrun", lambda argv, timeout: (_ for _ in ()).throw(OSError("boom")))
        assert defender.trigger_signature_update(None) is True
        for _ in range(100):
            if not defender.update_running():
                break
            time.sleep(0.05)
        st = defender.update_status()
        assert st["running"] is False and st["ok"] is False and "boom" in st["message"]

    def test_missing_mpcmdrun_reports_unavailable(self, monkeypatch):
        monkeypatch.setattr(defender, "mpcmdrun_path", lambda status_info=None: None)
        assert defender.trigger_signature_update(None) is False
        assert defender.trigger_quick_scan(None) is False
        assert defender.update_status()["available"] is False
        assert defender.quick_scan_status()["available"] is False

    def test_synchronous_update_records_the_same_state(self, monkeypatch, tmp_path):
        exe = tmp_path / "MpCmdRun.exe"
        exe.write_bytes(b"")
        monkeypatch.setattr(defender, "mpcmdrun_path", lambda status_info=None: exe)
        monkeypatch.setattr(defender, "_run_mpcmdrun", lambda argv, timeout: (1, "", "update failed"))
        assert defender.update_signatures(None) is False
        st = defender.update_status()
        assert st["ok"] is False and st["rc"] == 1 and "update failed" in st["message"]


# ------------------------------------------------------------------ updates / winget


class TestWinget:
    @pytest.fixture
    def rows(self):
        return updates.parse_winget_upgrade((FIXTURES / "winget_upgrade.txt").read_text(encoding="utf-8"))

    def test_parses_both_tables_and_skips_noise(self, rows):
        assert len(rows) == 28
        ids = [r["id"] for r in rows]
        assert ids[0] == "Acme.NotesDesktop" and "Microsoft.Edge" in ids and "Example.WideName" in ids
        assert all(r["source"] == "winget" for r in rows)
        assert not any("upgrades available" in r["name"] for r in rows)

    def test_fixed_width_slicing_keeps_versions_with_spaces(self, rows):
        by_id = {r["id"]: r for r in rows}
        java = by_id["Oracle.JavaRuntimeEnvironment"]
        assert (java["name"], java["version"], java["available"]) == ("Java 8 Update 481", "8.0.4810.10", "8.0.5030.1")
        vs = by_id["Microsoft.VisualStudio.2022.Community"]
        assert vs["version"] == "< 17.14.37" and vs["available"] == "17.14.39"
        vc = by_id["Microsoft.VCRedist.2015+.x64"]
        assert vc["name"].startswith("Microsoft Visual C++ v14 Redistributable (x64)")
        wide = by_id["Example.WideName"]
        assert wide["version"] == "1.0" and wide["available"] == "1.1"

    def test_high_risk_classification(self):
        assert updates.is_high_risk("Java 8 Update 481", "Oracle.JavaRuntimeEnvironment")
        assert updates.is_high_risk("Google Chrome", "Google.Chrome")
        assert updates.is_high_risk("Microsoft Edge", "Microsoft.Edge")
        assert updates.is_high_risk("7-Zip 24.08 (x64)", "7zip.7zip")
        assert updates.is_high_risk("Notepad++ (64-bit x64)", "Notepad++.Notepad++")
        assert updates.is_high_risk("Python 3.14.6 (64-bit)", "Python.Python.3.14")
        assert not updates.is_high_risk("GitHub CLI", "GitHub.cli")
        assert not updates.is_high_risk("Windows PC Health Check", "Microsoft.WindowsPCHealthCheck")
        assert not updates.is_high_risk("Knowledge Base", "Acme.Knowledgeable")

    def test_software_findings_split(self, rows):
        c = Collector()
        updates.software_findings(rows, c)
        ids = _by_id(c.checks)
        assert ids["WIN-UPD-003"].status == "fail" and ids["WIN-UPD-004"].status == "fail"
        risky = {d.evidence["key"] for d in _findings(c.findings, "WIN-UPD-004")}
        plain = {d.evidence["key"] for d in _findings(c.findings, "WIN-UPD-003")}
        assert {"Oracle.JavaRuntimeEnvironment", "Google.Chrome", "Microsoft.Edge", "7zip.7zip", "Python.Python.3.14"} <= risky
        assert "Git.Git" in plain and not (risky & plain)
        assert len(risky) + len(plain) == 28

    def test_write_software_upserts_and_prunes(self, rows, conn):
        assert updates.write_software(conn, rows, "winget") == 28
        assert db.one(conn, "SELECT COUNT(*) AS n FROM software WHERE source='winget'")["n"] == 28
        row = db.one(conn, "SELECT * FROM software WHERE name='Git'")
        assert row["publisher"] == "Git.Git" and row["available"] == "2.55.0.3"
        time.sleep(1.1)  # seen_at has whole-second resolution; the prune compares against it
        updates.write_software(conn, rows[:3], "winget")
        assert db.one(conn, "SELECT COUNT(*) AS n FROM software WHERE source='winget'")["n"] == 3

    def test_parse_empty_and_garbage(self):
        assert updates.parse_winget_upgrade("") == []
        assert updates.parse_winget_upgrade("No installed package found matching input criteria.\n") == []


class TestWindowsUpdate:
    NOW = datetime(2026, 9, 4, 12, 0, tzinfo=timezone.utc)

    def _data(self, pending, last_cum="2026-07-16T02:00:00Z"):
        return {
            "pending": pending, "pending_error": None,
            "hotfix": {"count": 4, "last_id": "KB5101650", "last_description": "Security Update", "last_installed": "2026-07-16"},
            "history": {"last_cumulative_title": "2026-07 Cumulative Update for Windows 11 (KB5101650)", "last_cumulative_date": last_cum},
            "os": {"build": "26200"},
        }

    def test_defender_intel_only_is_not_pending(self):
        c = Collector()
        updates.windows_update_findings(self._data([{"title": "Security Intelligence Update for Microsoft Defender Antivirus - KB2267602 (Version 1.459.51.0)", "kb": "KB2267602"}]), c, now=self.NOW)
        ids = _by_id(c.checks)
        assert ids["WIN-UPD-001"].status == "pass"
        assert ids["WIN-UPD-002"].status == "fail" and "50 days" in ids["WIN-UPD-002"].value
        assert _findings(c.findings, "WIN-UPD-002")[0].evidence["source"] == "windows update history"

    def test_pending_security_update_is_high(self):
        c = Collector()
        updates.windows_update_findings(self._data([{"title": "2026-09 Cumulative Update for Windows 11 Version 25H2 (KB5109999)", "kb": "KB5109999"}, {"title": "Contoso - Firmware - 1.2", "kb": ""}]), c, now=self.NOW)
        f = _findings(c.findings, "WIN-UPD-001")
        assert len(f) == 1 and f[0].severity == "high" and f[0].evidence["count"] == 2

    def test_pending_driver_only_is_default_severity_and_recent_cumulative_passes(self):
        c = Collector()
        updates.windows_update_findings(self._data([{"title": "Contoso - Firmware - 1.2", "kb": ""}], last_cum="2026-08-30T00:00:00Z"), c, now=self.NOW)
        ids = _by_id(c.checks)
        assert _findings(c.findings, "WIN-UPD-001")[0].severity is None
        assert ids["WIN-UPD-002"].status == "pass"

    def test_search_denied_maps_to_needs_admin(self):
        c = Collector()
        data = self._data([])
        data["pending_error"] = "ACCESS_DENIED"
        updates.windows_update_findings(data, c, now=self.NOW)
        assert _by_id(c.checks)["WIN-UPD-001"].status == "needs_admin"

    def test_run_windows_wires_everything(self, cfg, conn, monkeypatch):
        monkeypatch.setattr(updates, "is_windows", lambda: True)
        monkeypatch.setattr(updates, "run_ps_json", lambda script, *, timeout, args=(): PsResult(self._data([]), duration_sec=1.0))
        text = (FIXTURES / "winget_upgrade.txt").read_text(encoding="utf-8")
        monkeypatch.setattr(updates, "winget_upgrades", lambda: (updates.parse_winget_upgrade(text), None))
        result = updates.run(cfg, conn)
        assert result.error is None and result.summary["outdated_apps"] == 28
        ids = {r["check_id"] for r in db.query(conn, "SELECT check_id FROM host_checks")}
        assert {"WIN-UPD-001", "WIN-UPD-002", "WIN-UPD-003", "WIN-UPD-004"} <= ids
        assert db.get_setting(conn, "updates.status_json")

    def test_run_without_winget(self, cfg, conn, monkeypatch):
        monkeypatch.setattr(updates, "is_windows", lambda: True)
        monkeypatch.setattr(updates, "run_ps_json", lambda *a, **k: PsResult(self._data([]), duration_sec=1.0))
        monkeypatch.setattr(updates, "winget_upgrades", lambda: ([], "winget not found"))
        result = updates.run(cfg, conn, quick=True)
        assert "winget not found" in (result.error or "")
        assert db.one(conn, "SELECT status FROM host_checks WHERE check_id='WIN-UPD-003'")["status"] == "unknown"


# ------------------------------------------------------------------ persistence


RAW_PERSISTENCE = {
    "run_keys": [
        {"hive": "HKCU", "key": "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", "name": "NoteSync", "command": "\"C:\\Users\\daily\\AppData\\Local\\NoteSync\\NoteSync.Desktop.exe\""},
        {"hive": "HKCU", "key": "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", "name": "com.squirrel.Teams.Teams", "command": "C:\\Users\\daily\\AppData\\Local\\Microsoft\\Teams\\Update.exe --processStart Teams.exe"},
    ],
    "startup": [{"scope": "user", "folder": "C:\\Users\\daily\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup", "name": "Logitech . Product Registration.lnk", "target": "C:\\Program Files (x86)\\Logitech\\Ereg\\eReg.exe", "arguments": "/remind"}],
    "tasks": [{"name": "BackupJob", "path": "\\", "author": "LAPTOP-HOME\\daily", "state": "Ready", "command": "C:\\Python3\\python.exe C:\\tools\\backup.py", "run_level": "Limited"}],
    "services": [{"name": "AdobeARMservice", "display": "Adobe Acrobat Update Service", "path": "\"C:\\Program Files (x86)\\Common Files\\Adobe\\ARM\\1.0\\armsvc.exe\"", "start_mode": "Auto", "state": "Running", "source": "wmi"}],
    "errors": {},
}


class TestPersistence:
    def test_normalize(self):
        entries = persistence.normalize(RAW_PERSISTENCE)
        assert [e.kind for e in entries] == ["run_key", "run_key", "startup_folder", "scheduled_task", "service"]
        lnk = entries[2]
        assert lnk.location.endswith("Startup") and lnk.command == "C:\\Program Files (x86)\\Logitech\\Ereg\\eReg.exe /remind"
        assert entries[3].extra["author"] == "LAPTOP-HOME\\daily"
        assert len({e.key for e in entries}) == 5

    def test_first_run_is_baseline_then_new_entries_alert(self, conn, cfg):
        entries = persistence.normalize(RAW_PERSISTENCE)
        rec = persistence.reconcile(conn, entries)
        assert rec.baseline_run and rec.new == [] and rec.reemit == []
        assert db.one(conn, "SELECT COUNT(*) AS n FROM persistence WHERE baseline=1")["n"] == 5
        assert db.get_setting(conn, "persistence.baseline_at")

        raw2 = json.loads(json.dumps(RAW_PERSISTENCE))
        raw2["run_keys"].append({"hive": "HKCU", "key": "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", "name": "Updater", "command": "C:\\Users\\daily\\AppData\\Roaming\\upd.exe"})
        raw2["tasks"].append({"name": "OneDriveSync", "path": "\\", "author": "daily", "state": "Ready", "command": "wscript.exe C:\\Users\\Public\\x.vbs"})
        raw2["services"].append({"name": "svc_evil", "display": "Evil", "path": "C:\\Temp\\e.exe", "start_mode": "Auto", "state": "Running", "source": "wmi"})
        entries2 = persistence.normalize(raw2)
        rec2 = persistence.reconcile(conn, entries2)
        assert not rec2.baseline_run and {e.name for e in rec2.new} == {"Updater", "OneDriveSync", "svc_evil"}
        assert rec2.known == 5 and len(rec2.reemit) == 3
        c = Collector()
        persistence.build_findings(rec2.reemit, {}, c, {e.key: e for e in entries2})
        ids = _by_id(c.checks)
        assert (ids["WIN-PER-001"].status, ids["WIN-PER-002"].status, ids["WIN-PER-003"].status) == ("fail", "fail", "fail")
        keys = {d.finding_id: d.evidence["key"] for d in c.findings}
        assert keys["WIN-PER-001"].startswith("run_key:HKCU:") and keys["WIN-PER-001"].endswith(":Updater")
        assert keys["WIN-PER-002"] == "scheduled_task:\\:OneDriveSync" and keys["WIN-PER-003"] == "service:services:svc_evil"
        assert _findings(c.findings, "WIN-PER-002")[0].evidence["author"] == "daily"

        # third run, nothing new: the un-baselined rows still re-emit inside the window
        rec3 = persistence.reconcile(conn, entries2)
        assert rec3.new == [] and len(rec3.reemit) == 3
        # ...until they are accepted
        assert persistence.promote_to_baseline(conn) >= 0
        assert persistence.reconcile(conn, entries2).reemit == []

    def test_baseline_disabled_never_alerts(self, conn):
        persistence.reconcile(conn, persistence.normalize(RAW_PERSISTENCE))
        raw2 = json.loads(json.dumps(RAW_PERSISTENCE))
        raw2["run_keys"].append({"hive": "HKLM", "key": "HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", "name": "X", "command": "x.exe"})
        rec = persistence.reconcile(conn, persistence.normalize(raw2), baseline_enabled=False)
        assert rec.baseline_run and rec.new == [] and rec.reemit == []

    def test_denied_sections_map_to_needs_admin(self):
        c = Collector()
        persistence.build_findings([], {"tasks": "ACCESS_DENIED", "services": "ERROR: wmi"}, c)
        ids = _by_id(c.checks)
        assert ids["WIN-PER-001"].status == "pass" and ids["WIN-PER-002"].status == "needs_admin" and ids["WIN-PER-003"].status == "pass"

    def test_run_end_to_end(self, cfg, conn, monkeypatch):
        monkeypatch.setattr(persistence, "is_windows", lambda: True)
        monkeypatch.setattr(persistence, "collect", lambda cfg=None: RAW_PERSISTENCE)
        r1 = persistence.run(cfg, conn)
        assert r1.summary["baseline_run"] and r1.findings == [] and r1.summary["entries"] == 5
        raw2 = json.loads(json.dumps(RAW_PERSISTENCE))
        raw2["startup"].append({"scope": "common", "folder": "C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp", "name": "evil.lnk", "target": "C:\\Temp\\e.exe"})
        monkeypatch.setattr(persistence, "collect", lambda cfg=None: raw2)
        r2 = persistence.run(cfg, conn)
        assert [d.finding_id for d in r2.findings] == ["WIN-PER-001"] and r2.summary["new"] == 1
        assert db.one(conn, "SELECT baseline FROM persistence WHERE name='evil.lnk'")["baseline"] == 0

    def test_run_all_sections_failed_does_not_baseline(self, cfg, conn, monkeypatch):
        monkeypatch.setattr(persistence, "is_windows", lambda: True)
        monkeypatch.setattr(persistence, "collect", lambda cfg=None: {"run_keys": [], "startup": [], "tasks": [], "services": [], "errors": {"tasks": "ACCESS_DENIED"}})
        r = persistence.run(cfg, conn)
        assert r.error and db.one(conn, "SELECT COUNT(*) AS n FROM persistence")["n"] == 0


# ------------------------------------------------------------------ files


class TestFiles:
    @pytest.fixture
    def downloads(self, tmp_path: Path) -> Path:
        d = tmp_path / "Downloads"
        (d / "sub").mkdir(parents=True)
        (d / "fresh.exe").write_bytes(b"MZ" + b"\x00" * 100)
        (d / "sub" / "doc.pdf").write_bytes(b"%PDF fresh")
        old = d / "old.zip"
        old.write_bytes(b"PK old")
        past = time.time() - 3 * 86400
        os.utime(old, (past, past))
        (d / "partial.crdownload").write_bytes(b"x")
        (d / "empty.txt").write_bytes(b"")
        return d

    def _cfg(self, cfg: Config, downloads: Path, key: str = "") -> Config:
        return dataclasses.replace(cfg, host=dataclasses.replace(cfg.host, files_dirs=(str(downloads),)), dns=dataclasses.replace(cfg.dns, virustotal_api_key=key))

    def test_candidate_files_window_size_and_skips(self, downloads):
        found = {p.name for p in files.candidate_files([downloads])}
        assert found == {"fresh.exe", "doc.pdf"}
        assert files.candidate_files([downloads], max_bytes=50) == [downloads / "sub" / "doc.pdf"] or {p.name for p in files.candidate_files([downloads], max_bytes=50)} == {"doc.pdf"}
        assert files.candidate_files([downloads / "missing"]) == []

    def test_no_key_records_unchecked_without_findings(self, cfg, conn, downloads, monkeypatch):
        monkeypatch.setattr(files, "vt_fetch", lambda *a, **k: pytest.fail("must not call VirusTotal without a key"))
        result = files.run(self._cfg(cfg, downloads), conn)
        assert result.kind == "files" and result.findings == [] and result.summary["hashed"] == 2
        rows = db.query(conn, "SELECT verdict, source FROM file_checks")
        assert len(rows) == 2 and all(r["verdict"] == "unchecked" and r["source"] is None for r in rows)

    def test_lookup_verdicts_and_findings(self, cfg, conn, downloads, monkeypatch):
        sha_fresh = files.sha256_of(downloads / "fresh.exe")
        calls: list[str] = []

        def fake_fetch(api_key, sha256, timeout=15):
            calls.append(sha256)
            assert api_key == "k"
            if sha256 == sha_fresh:
                return 200, {"data": {"attributes": {"last_analysis_stats": {"malicious": 12, "suspicious": 1, "harmless": 0, "undetected": 50}, "type_description": "Win32 EXE", "names": ["bad.exe"], "popular_threat_classification": {"suggested_threat_label": "trojan.agent"}}}}
            return 404, None

        monkeypatch.setattr(files, "vt_fetch", fake_fetch)
        monkeypatch.setattr(files, "get_budget", lambda cfg, conn: files.LocalBudget(conn, 10))
        result = files.run(self._cfg(cfg, downloads, "k"), conn)
        assert len(calls) == 2 and result.summary["looked_up"] == 2 and result.summary["malicious"] == 1
        assert [d.finding_id for d in result.findings] == ["AV-FILE-001"]
        f = result.findings[0]
        assert f.evidence["key"] == sha_fresh and f.evidence["threat_label"] == "trojan.agent" and f.evidence["stats"]["malicious"] == 12
        verdicts = {r["path"].split(os.sep)[-1]: r["verdict"] for r in db.query(conn, "SELECT path, verdict FROM file_checks")}
        assert verdicts == {"fresh.exe": "malicious", "doc.pdf": "unknown"}
        # second run: cached verdicts, no new lookups, finding still emitted
        calls.clear()
        result2 = files.run(self._cfg(cfg, downloads, "k"), conn)
        assert calls == [] and result2.summary["cached"] == 2 and [d.finding_id for d in result2.findings] == ["AV-FILE-001"]

    def test_suspicious_verdict_and_budget_exhaustion(self, cfg, conn, downloads, monkeypatch):
        monkeypatch.setattr(files, "vt_fetch", lambda *a, **k: (200, {"data": {"attributes": {"last_analysis_stats": {"malicious": 1, "suspicious": 0}}}}))
        monkeypatch.setattr(files, "get_budget", lambda cfg, conn: files.LocalBudget(conn, 1))
        result = files.run(self._cfg(cfg, downloads, "k"), conn)
        assert result.summary["looked_up"] == 1 and result.summary["budget_exhausted"] == 1
        assert [d.finding_id for d in result.findings] == ["AV-FILE-002"]
        assert db.get_setting(conn, "vt.budget." + datetime.now(timezone.utc).strftime("%Y-%m-%d")) == "1"

    def test_verdict_thresholds(self):
        assert files.verdict_from_stats({"malicious": 0, "suspicious": 0}, 2) == "clean"
        assert files.verdict_from_stats({"malicious": 1, "suspicious": 0}, 2) == "suspicious"
        assert files.verdict_from_stats({"malicious": 2, "suspicious": 0}, 2) == "malicious"
        assert files.verdict_from_stats(None, 2) == "unknown"

    def test_local_budget_rate_limit(self, conn):
        b = files.LocalBudget(conn, 100, per_minute=2)
        assert b.try_acquire(now=0.0) and b.try_acquire(now=1.0) and not b.try_acquire(now=2.0)
        assert b.try_acquire(now=61.0) and b.remaining_today() == 97

    def test_disabled_by_config(self, cfg, conn, downloads):
        off = dataclasses.replace(cfg, host=dataclasses.replace(cfg.host, files_check=False))
        assert files.run(off, conn).summary["skipped"]


class TestVirusTotalFetch:
    """vt_fetch talks to a third party: the body must be capped, never read unbounded."""

    def _fake_requests(self, monkeypatch, *, status: int, body: bytes):
        import sys
        import types

        class FakeResponse:
            status_code = status

            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False

            def iter_content(self, chunk):
                for i in range(0, len(body), chunk):
                    yield body[i:i + chunk]

        captured: dict[str, object] = {}

        class FakeSession:
            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False

            def get(self, url, headers=None, timeout=None, stream=False, allow_redirects=True):
                captured.update(url=url, timeout=timeout, stream=stream, headers=headers or {},
                                allow_redirects=allow_redirects)
                return FakeResponse()

        module = types.SimpleNamespace(Session=FakeSession, RequestException=Exception)
        monkeypatch.setitem(sys.modules, "requests", module)
        return captured

    def test_small_body_is_parsed_with_timeout_and_streaming(self, monkeypatch):
        captured = self._fake_requests(monkeypatch, status=200, body=json.dumps({"data": {"id": "x"}}).encode())
        assert files.vt_fetch("k", "a" * 64) == (200, {"data": {"id": "x"}})
        assert captured["stream"] is True and captured["timeout"] == files.VT_TIMEOUT_SEC
        assert captured["headers"]["x-apikey"] == "k"
        assert captured["allow_redirects"] is False

    def test_oversized_body_is_refused(self, monkeypatch):
        self._fake_requests(monkeypatch, status=200, body=b"{" + b"a" * (files.VT_MAX_BODY_BYTES + 1024))
        assert files.vt_fetch("k", "b" * 64) == (200, None)

    def test_non_200_short_circuits(self, monkeypatch):
        self._fake_requests(monkeypatch, status=404, body=b"")
        assert files.vt_fetch("k", "c" * 64) == (404, None)


class TestPosixDoesNotDuplicateUpdates:
    def test_run_leaves_updates_to_its_own_step(self, cfg, conn, monkeypatch):
        """cli.scan_host already runs scanners.updates; running it here too double-scanned."""
        monkeypatch.setattr(host_posix, "is_windows", lambda: False)
        monkeypatch.setattr(host_posix, "firewall_state", lambda: ("active", "ufw"))
        monkeypatch.setattr(host_posix, "sshd_root_login", lambda: (None, "no sshd_config"))
        monkeypatch.setattr(host_posix, "disk_encrypted", lambda: (True, "FileVault is On"))
        monkeypatch.setattr(host_posix, "listeners", lambda: [])
        monkeypatch.setattr(updates, "posix_pending", lambda: pytest.fail("host_posix must not run the updates scanner"))
        result = host_posix.run(cfg, conn)
        assert result.error is None
        ids = {r["check_id"] for r in db.query(conn, "SELECT check_id FROM host_checks")}
        assert "POSIX-FW-001" in ids and "POSIX-UPD-001" not in ids


# ------------------------------------------------------------------ host_posix


class TestPosix:
    def test_evaluate_facts(self, cfg):
        facts = {
            "firewall": ("inactive", "ufw.conf ENABLED=no"),
            "sshd": ("yes", "sshd_config"),
            "encryption": (True, "FileVault is On."),
            "listeners": [{"port": 22, "address": "0.0.0.0", "process": "sshd"}, {"port": 5432, "address": "0.0.0.0", "process": "postgres"}, {"port": 6379, "address": "127.0.0.1", "process": "redis"}, {"port": 8787, "address": "0.0.0.0", "process": "python"}],
        }
        c = host_posix.evaluate(facts, cfg)
        ids = _by_id(c.checks)
        assert (ids["POSIX-FW-001"].status, ids["POSIX-SSH-001"].status, ids["POSIX-ENC-001"].status, ids["POSIX-NET-001"].status) == ("fail", "fail", "pass", "fail")
        assert [d.evidence["key"] for d in _findings(c.findings, "POSIX-NET-001")] == ["5432"]
        facts.update(firewall=("needs_admin", "pfctl requires root"), sshd=(None, "no sshd_config"), encryption=(None, "n/a"))
        ids = _by_id(host_posix.evaluate(facts, cfg).checks)
        assert ids["POSIX-FW-001"].status == "needs_admin" and ids["POSIX-SSH-001"].status == "unknown" and ids["POSIX-ENC-001"].status == "unknown"

    def test_run_refuses_on_windows(self, cfg, conn, monkeypatch):
        monkeypatch.setattr(host_posix, "is_windows", lambda: True)
        assert host_posix.run(cfg, conn).error
