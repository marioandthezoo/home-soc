"""Second security round, scanners area: regression tests that encode each reproduced exploit.

1. A hijacked (repointed) existing autostart entry was written over the baseline silently.
2. The persistence probe hid any scheduled task claiming a Microsoft author, and any service whose
   path merely started with the Windows folder name.
3. An unreviewed new autostart entry auto-resolved after 7 days while still present.
4. The VirusTotal file lookup followed redirects and forwarded the x-apikey header.
5. A VirusTotal "unknown" verdict was cached forever, so a fresh sample was never re-checked.

Everything runs against the temporary database from conftest (HOMESOC_DATA in tmp_path) or
in-memory data; the only sockets are throwaway HTTP servers on 127.0.0.1 that are shut down.
"""

from __future__ import annotations

import dataclasses
import http.server
import json
import platform
import socketserver
import subprocess
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from homesoc import db
from homesoc.findings import engine
from homesoc.scanners import files, persistence
from homesoc.scanners.host_windows import PS_DIR, Collector

RUN_KEY = "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"
ONEDRIVE = "\"C:\\Program Files\\Microsoft OneDrive\\OneDrive.exe\" /background"
EVIL = "C:\\Users\\m\\AppData\\Roaming\\evil.exe"


def _raw(run_cmd: str = ONEDRIVE, *, tasks=None, services=None, windir=None) -> dict:
    raw = {
        "run_keys": [{"hive": "HKCU", "key": RUN_KEY, "name": "OneDrive", "command": run_cmd}],
        "startup": [],
        "tasks": tasks if tasks is not None else [{"name": "BackupJob", "path": "\\", "author": "me", "command": "C:\\Python3\\python.exe C:\\tools\\backup.py"}],
        "services": services or [],
        "errors": {},
    }
    if windir is not None:
        raw["windir"] = windir
    return raw


def _scan(conn, raw: dict):
    entries = persistence.normalize(raw)
    rec = persistence.reconcile(conn, entries)
    c = Collector()
    persistence.build_findings(rec.reemit, {}, c, {e.key: e for e in entries})
    return rec, c


def _checks(c: Collector) -> dict[str, str]:
    return {k.check_id: k.status for k in c.checks}


def _set_first_seen(conn, name: str, days_ago: float) -> None:
    ts = (datetime.now(timezone.utc) - timedelta(days=days_ago)).strftime("%Y-%m-%dT%H:%M:%SZ")
    db.write(conn, "UPDATE persistence SET first_seen = ? WHERE name = ?", (ts, name))


# ------------------------------------------------------------------ 1. hijacked existing entry


class TestChangedCommandIsReported:
    def test_repointed_run_value_raises_win_per_001_with_old_command(self, conn):
        _scan(conn, _raw())  # baseline
        rec, c = _scan(conn, _raw(EVIL))
        assert [e.name for e in rec.changed] == ["OneDrive"] and rec.new == []
        assert _checks(c)["WIN-PER-001"] == "fail"
        (f,) = c.findings
        assert f.finding_id == "WIN-PER-001"
        assert f.evidence["change"] == "modified"
        assert f.evidence["previous_command"] == ONEDRIVE and f.evidence["command"] == EVIL
        assert f.evidence["key"] == f"run_key:{RUN_KEY}:OneDrive:changed:{persistence.command_digest(EVIL)}"
        row = db.one(conn, "SELECT command, baseline FROM persistence WHERE name='OneDrive'")
        assert row["baseline"] == 0 and row["command"] == EVIL

    def test_changed_task_action_raises_win_per_002(self, conn):
        _scan(conn, _raw())
        hijacked = [{"name": "BackupJob", "path": "\\", "author": "me", "command": "powershell.exe -enc AAAA"}]
        _, c = _scan(conn, _raw(tasks=hijacked))
        assert [(f.finding_id, f.evidence["previous_command"]) for f in c.findings] == [("WIN-PER-002", "C:\\Python3\\python.exe C:\\tools\\backup.py")]

    def test_change_keeps_alerting_until_accepted_and_keeps_first_previous(self, conn):
        _scan(conn, _raw())
        _scan(conn, _raw(EVIL))
        _, c = _scan(conn, _raw(EVIL))  # next run, nothing new: still reported
        assert [f.evidence["previous_command"] for f in c.findings] == [ONEDRIVE]
        _, c = _scan(conn, _raw(EVIL + " --again"))  # a second change: new key, original previous kept
        (f,) = c.findings
        assert f.evidence["previous_command"] == ONEDRIVE and f.evidence["key"].endswith(persistence.command_digest(EVIL + " --again"))
        assert persistence.accept_entry(conn, "run_key", RUN_KEY, "OneDrive") is True
        _, c = _scan(conn, _raw(EVIL + " --again"))
        assert c.findings == [] and _checks(c)["WIN-PER-001"] == "pass"
        assert db.get_setting(conn, persistence.CHANGES_SETTING) in ("{}", None)

    def test_promote_to_baseline_accepts_changes(self, conn):
        _scan(conn, _raw())
        _scan(conn, _raw(EVIL))
        persistence.promote_to_baseline(conn)
        _, c = _scan(conn, _raw(EVIL))
        assert c.findings == []

    def test_reverting_to_the_accepted_command_restores_the_baseline(self, conn):
        _scan(conn, _raw())
        _scan(conn, _raw(EVIL))
        rec, c = _scan(conn, _raw(ONEDRIVE))
        assert rec.changed == [] and c.findings == []
        assert db.one(conn, "SELECT baseline FROM persistence WHERE name='OneDrive'")["baseline"] == 1

    def test_hijack_opens_a_new_finding_even_if_the_new_entry_finding_was_suppressed(self, conn):
        _scan(conn, _raw())
        extra = _raw()
        extra["run_keys"].append({"hive": "HKCU", "key": RUN_KEY, "name": "Tool", "command": "C:\\Tools\\tool.exe"})
        _, c = _scan(conn, extra)
        applied = engine.apply(conn, c.findings, "persistence", scope="host")
        engine.set_status(conn, int(applied.new[0]["id"]), "suppressed")
        extra["run_keys"][1]["command"] = EVIL
        _, c = _scan(conn, extra)
        applied = engine.apply(conn, c.findings, "persistence", scope="host")
        assert [f["evidence"]["previous_command"] for f in applied.new] == ["C:\\Tools\\tool.exe"]

    def test_version_folder_bump_and_unreadable_command_are_not_changes(self, conn):
        v1 = "C:\\Users\\m\\AppData\\Local\\Discord\\app-1.0.9003\\Discord.exe --start"
        v2 = "C:\\Users\\m\\AppData\\Local\\Discord\\app-1.0.9004\\Discord.exe --start"
        _scan(conn, _raw(v1))
        rec, c = _scan(conn, _raw(v2))
        assert rec.changed == [] and c.findings == []
        assert db.one(conn, "SELECT command FROM persistence WHERE name='OneDrive'")["command"] == v2
        raw = _raw()
        raw["run_keys"][0]["command"] = None  # probe could not read it: keep the stored command
        rec, c = _scan(conn, raw)
        assert rec.changed == [] and c.findings == []
        assert db.one(conn, "SELECT command FROM persistence WHERE name='OneDrive'")["command"] == v2

    def test_argument_changes_are_changes(self):
        fp = persistence.command_fingerprint
        assert fp("C:\\x\\agent.exe --server 10.0.0.5") != fp("C:\\x\\agent.exe --server 203.0.113.9")
        assert fp("\\\\10.0.0.5\\s\\a.exe") != fp("\\\\10.0.0.6\\s\\a.exe")
        assert fp('"C:\\Program Files\\A\\a.exe"  /x') == fp('"c:\\program files\\a\\A.EXE" /x')

    def test_alerting_disabled_still_just_updates(self, conn):
        _scan(conn, _raw())
        rec = persistence.reconcile(conn, persistence.normalize(_raw(EVIL)), baseline_enabled=False)
        assert rec.changed == [] and rec.reemit == []


# ------------------------------------------------------------------ 2. probe filters


WINDIR = "C:\\Windows"
MS = "CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US"
WHCP = "CN=Microsoft Windows Hardware Compatibility Publisher, O=Microsoft Corporation, L=Redmond, S=Washington, C=US"


def _svc(path: str, exe: str | None = None, signer: str | None = MS, name: str = "svc") -> dict:
    if exe is None:
        exe = persistence.split_command(path)[0]
    return {"name": name, "display": name, "path": path, "exe": exe, "signer": signer, "start_mode": "Auto", "state": "Running", "source": "wmi"}


class TestServiceClassification:
    @pytest.mark.parametrize("path", [
        "C:\\WindowsUpdate\\svc.exe",                                  # prefix without separator
        "\"C:\\Windows\\Temp\\x.exe\"",                                 # user-writable subfolder
        "C:\\Windows\\Tasks\\x.exe",
        "C:\\Windows\\System32\\spool\\drivers\\color\\x.exe",
        "C:\\Windows\\System32\\rundll32.exe C:\\Users\\x\\evil.dll,Run",  # LOLBin with foreign args
        "C:\\Windows\\System32\\rundll32.exe shell32.dll,Control_RunDLL",  # any LOLBin
        "C:\\Windows\\System32\\svchost.exe -k x -p C:\\Users\\x\\a.dll",  # foreign path in args
        "C:\\Windows\\System32\\svchost.exe -k %APPDATA%\\x",
        "C:\\Windows\\System32\\svchost.exe -k ..\\..\\Users\\x\\y",
        "C:\\Windows\\System32\\..\\..\\Users\\x\\evil.exe",
    ])
    def test_hostile_paths_are_not_windows(self, path):
        assert persistence.is_windows_service(_svc(path), WINDIR) is False

    def test_unsigned_or_mismatched_signature_is_not_windows(self):
        assert persistence.is_windows_service(_svc("C:\\Windows\\System32\\evilsvc.exe", signer=None), WINDIR) is False
        assert persistence.is_windows_service(_svc("C:\\Windows\\System32\\evilsvc.exe", signer="CN=Evil, O=Evil Ltd"), WINDIR) is False
        # signature reported for a different file than the one the command line runs
        assert persistence.is_windows_service(_svc("C:\\Windows\\System32\\evil.exe", exe="C:\\Windows\\System32\\svchost.exe"), WINDIR) is False
        # older probe: no windir / no signer fields -> listed, never hidden
        assert persistence.is_windows_service(_svc("C:\\Windows\\System32\\svchost.exe -k netsvcs"), None) is False
        legacy = {"name": "x", "path": "C:\\Windows\\System32\\svchost.exe -k netsvcs", "source": "wmi"}
        assert persistence.is_windows_service(legacy, WINDIR) is False

    @pytest.mark.parametrize("path,signer", [
        ("C:\\WINDOWS\\system32\\svchost.exe -k netsvcs -p", MS),
        ("C:\\WINDOWS\\System32\\svchost.exe -k LocalServiceNetworkRestricted -p -s DusmSvc", MS),
        ("C:\\WINDOWS\\system32\\SearchIndexer.exe /Embedding", MS),
        ("\"C:\\WINDOWS\\system32\\lsass.exe\"", MS),
        ("C:\\WINDOWS\\System32\\DriverStore\\FileRepository\\nv.inf_amd64_1\\Display.NvContainer\\NVDisplay.Container.exe -arg <ExeDir>\\arguments.txt", WHCP),
    ])
    def test_real_windows_services_stay_filtered(self, path, signer):
        assert persistence.is_windows_service(_svc(path, signer=signer), "C:\\WINDOWS") is True

    def test_normalize_lists_hostile_services_and_drops_windows_ones(self):
        services = [
            _svc("C:\\WINDOWS\\system32\\svchost.exe -k netsvcs -p", name="Schedule"),
            _svc("C:\\WindowsUpdate\\svc.exe", name="fake1"),
            _svc("C:\\Windows\\System32\\rundll32.exe C:\\Users\\x\\evil.dll,Run", name="fake2"),
            {"name": "evt", "path": "C:\\Windows\\Temp\\x.exe", "source": "eventlog7045"},
        ]
        names = {e.name for e in persistence.normalize(_raw(services=services, windir="C:\\WINDOWS")) if e.kind == "service"}
        assert names == {"fake1", "fake2", "evt"}

    def test_probe_does_not_filter_on_task_author_or_path_prefix(self):
        script = (PS_DIR / "persistence.ps1").read_text(encoding="utf-8")
        code = "\n".join(line for line in script.splitlines() if not line.lstrip().startswith("#"))
        assert "$t.Author -like" not in code and "Author -like" not in code
        assert "StartsWith($winDir" not in code
        assert "windir = " in code and "signer = $signer" in code

    def test_microsoft_author_task_reaches_the_inventory(self, conn):
        _scan(conn, _raw())
        tasks = [
            {"name": "BackupJob", "path": "\\", "author": "me", "command": "C:\\Python3\\python.exe C:\\tools\\backup.py"},
            {"name": "OneDrive Updater", "path": "\\", "author": "Microsoft Corporation", "command": "C:\\Users\\Public\\evil.exe"},
        ]
        _, c = _scan(conn, _raw(tasks=tasks))
        assert [f.evidence["name"] for f in c.findings] == ["OneDrive Updater"]

    @pytest.mark.slow
    @pytest.mark.skipif(platform.system() != "Windows", reason="runs the real read-only probe")
    def test_real_probe_reports_windir_and_signers(self):
        out = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", str(PS_DIR / "persistence.ps1")],
            capture_output=True, timeout=180, check=False,
        )
        raw = json.loads(out.stdout.decode("utf-8-sig").strip().splitlines()[-1])
        assert raw.get("windir")
        wmi = [s for s in raw.get("services") or [] if s.get("source") == "wmi"]
        if wmi:  # WMI can be denied; then the event-log fallback is used and nothing is filtered
            assert all("exe" in s and "signer" in s for s in wmi)
            svchost = [s for s in wmi if "svchost.exe" in str(s.get("path")).lower()]
            assert svchost
            if not any(s.get("signer") for s in svchost):
                # Some machines cannot verify catalog signatures at all (GitHub's Windows runners
                # report every signature as not valid). The product then lists and baselines these
                # services rather than trusting them, which is the safe direction and is covered by
                # the fixture tests above; there is nothing further to assert about this machine.
                assert not any(persistence.is_windows_service(s, raw["windir"]) for s in svchost)
                pytest.skip("this machine cannot verify Authenticode signatures; unsigned services stay listed")
            assert all(persistence.is_windows_service(s, raw["windir"]) for s in svchost)


# ------------------------------------------------------------------ 3. no auto-resolve while present


class TestUnreviewedEntryNeverAutoResolves:
    def test_new_task_still_present_after_12_days_stays_open(self, conn):
        _scan(conn, _raw())
        tasks = [
            {"name": "BackupJob", "path": "\\", "author": "me", "command": "C:\\Python3\\python.exe C:\\tools\\backup.py"},
            {"name": "Updater", "path": "\\", "author": "x", "command": "C:\\Users\\Public\\u.exe"},
        ]
        _, c = _scan(conn, _raw(tasks=tasks))
        day0 = engine.apply(conn, c.findings, "persistence", scope="host")
        assert [f["finding_id"] for f in day0.new] == ["WIN-PER-002"]
        _set_first_seen(conn, "Updater", 12)
        rec, c = _scan(conn, _raw(tasks=tasks))
        assert [r["name"] for r in rec.reemit] == ["Updater"] and _checks(c)["WIN-PER-002"] == "fail"
        day12 = engine.apply(conn, c.findings, "persistence", scope="host")
        assert day12.resolved == [] and day12.new == [] and day12.updated == 1
        assert db.one(conn, "SELECT status FROM findings WHERE finding_id='WIN-PER-002'")["status"] == "open"

    def test_entry_that_disappears_does_resolve(self, conn):
        _scan(conn, _raw())
        tasks = [{"name": "Updater", "path": "\\", "author": "x", "command": "C:\\Users\\Public\\u.exe"}]
        _, c = _scan(conn, _raw(tasks=tasks))
        engine.apply(conn, c.findings, "persistence", scope="host")
        _, c = _scan(conn, _raw(tasks=[]))
        assert engine.apply(conn, c.findings, "persistence", scope="host").resolved

    def test_run_end_to_end_after_eight_days(self, cfg, conn, monkeypatch):
        tasks = [{"name": "Updater", "path": "\\", "author": "x", "command": "C:\\Users\\Public\\u.exe"}]
        monkeypatch.setattr(persistence, "is_windows", lambda: True)
        monkeypatch.setattr(persistence, "collect", lambda cfg=None: _raw(tasks=[]))
        persistence.run(cfg, conn)
        monkeypatch.setattr(persistence, "collect", lambda cfg=None: _raw(tasks=tasks))
        engine.apply(conn, persistence.run(cfg, conn).findings, "persistence", scope="host")
        _set_first_seen(conn, "Updater", 8)
        r = persistence.run(cfg, conn)
        assert [f.finding_id for f in r.findings] == ["WIN-PER-002"]
        assert not engine.apply(conn, r.findings, "persistence", scope="host").resolved


# ------------------------------------------------------------------ 4. VirusTotal redirects


class _Recorder(http.server.BaseHTTPRequestHandler):
    seen: list[dict] = []
    location = ""

    def log_message(self, *args):  # keep test output quiet
        pass

    def do_GET(self):  # noqa: N802 - http.server API
        type(self).seen.append({"host": self.headers.get("Host"), "x-apikey": self.headers.get("x-apikey"), "path": self.path})
        if self.location:
            self.send_response(302)
            self.send_header("Location", self.location)
            self.send_header("Content-Length", "0")
            self.end_headers()
        else:
            body = b'{"data": {"attributes": {"last_analysis_stats": {"malicious": 0}}}}'
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)


def _server(handler_cls):
    srv = socketserver.TCPServer(("127.0.0.1", 0), handler_cls)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    return srv


class TestVirusTotalNoRedirects:
    def test_api_key_is_not_forwarded_across_a_redirect(self, monkeypatch):
        collector = type("Collector", (_Recorder,), {"seen": [], "location": ""})
        redirector = type("Redirector", (_Recorder,), {"seen": [], "location": ""})
        s2 = _server(collector)
        s1 = _server(redirector)
        try:
            redirector.location = f"http://localhost:{s2.server_address[1]}/collect"
            monkeypatch.setattr(files, "VT_FILE_URL", f"http://127.0.0.1:{s1.server_address[1]}/api/v3/files/{{sha256}}")
            code, body = files.vt_fetch("SECRET-VT-KEY", "0" * 64, timeout=5)
            assert code == 302 and body is None
            assert collector.seen == []  # the redirect target never saw a request, let alone the key
            assert len(redirector.seen) == 1
            monkeypatch.setattr(files, "vt_fetch", lambda *a, **k: (302, None))
            assert files.lookup_hash("k", "0" * 64, 2)[0] == files.VERDICT_UNCHECKED
        finally:
            for srv in (s1, s2):
                srv.shutdown()
                srv.server_close()

    def test_normal_answer_still_parsed(self, monkeypatch):
        ok = type("Ok", (_Recorder,), {"seen": [], "location": ""})
        srv = _server(ok)
        try:
            monkeypatch.setattr(files, "VT_FILE_URL", f"http://127.0.0.1:{srv.server_address[1]}/api/v3/files/{{sha256}}")
            code, body = files.vt_fetch("k", "1" * 64, timeout=5)
            assert code == 200 and body["data"]["attributes"]["last_analysis_stats"] == {"malicious": 0}
            assert ok.seen[0]["x-apikey"] == "k"
        finally:
            srv.shutdown()
            srv.server_close()

    def test_session_is_used_with_redirects_disabled(self, monkeypatch):
        import sys
        import types

        seen: dict = {}

        class Resp:
            status_code = 301

            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False

        class Session:
            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False

            def get(self, url, **kwargs):
                seen.update(kwargs)
                return Resp()

        monkeypatch.setitem(sys.modules, "requests", types.SimpleNamespace(Session=Session, RequestException=Exception))
        assert files.vt_fetch("k", "2" * 64) == (301, None)
        assert seen["allow_redirects"] is False and seen["stream"] is True


# ------------------------------------------------------------------ 5. unknown / clean re-check


class TestProvisionalVerdictsAreRechecked:
    @pytest.fixture
    def downloads(self, tmp_path: Path) -> Path:
        d = tmp_path / "dl"
        d.mkdir()
        (d / "payload.exe").write_bytes(b"MZ fresh sample")
        return d

    def _cfg(self, cfg, downloads):
        return dataclasses.replace(cfg, host=dataclasses.replace(cfg.host, files_dirs=(str(downloads),)), dns=dataclasses.replace(cfg.dns, virustotal_api_key="k"))

    def _age(self, conn, hours: float) -> None:
        for r in db.query(conn, "SELECT sha256, detail FROM file_checks"):
            detail = json.loads(r["detail"]) if r["detail"] else {}
            detail["checked_at"] = (datetime.now(timezone.utc) - timedelta(hours=hours)).strftime("%Y-%m-%dT%H:%M:%SZ")
            db.write(conn, "UPDATE file_checks SET detail = ? WHERE sha256 = ?", (json.dumps(detail), r["sha256"]))

    def test_unknown_becomes_malicious_on_recheck(self, cfg, conn, downloads, monkeypatch):
        answers = [(404, None)]
        calls: list[str] = []

        def fetch(api_key, sha256, timeout=15):
            calls.append(sha256)
            return answers[-1]

        monkeypatch.setattr(files, "vt_fetch", fetch)
        monkeypatch.setattr(files, "get_budget", lambda cfg, conn: files.LocalBudget(conn, 50, per_minute=50))
        r1 = files.run(self._cfg(cfg, downloads), conn)
        assert r1.summary["looked_up"] == 1 and r1.findings == []
        assert db.one(conn, "SELECT verdict FROM file_checks")["verdict"] == "unknown"

        answers.append((200, {"data": {"attributes": {"last_analysis_stats": {"malicious": 40}}}}))
        r2 = files.run(self._cfg(cfg, downloads), conn)  # too soon: cached, no lookup
        assert r2.summary["cached"] == 1 and len(calls) == 1

        self._age(conn, 7)
        r3 = files.run(self._cfg(cfg, downloads), conn)
        assert len(calls) == 2 and [d.finding_id for d in r3.findings] == ["AV-FILE-001"]
        assert db.one(conn, "SELECT verdict FROM file_checks")["verdict"] == "malicious"

        self._age(conn, 24 * 30)
        files.run(self._cfg(cfg, downloads), conn)
        assert len(calls) == 2  # a detection is final

    def test_unknown_backoff_doubles_and_clean_rechecks_after_days(self):
        def row(verdict, hours, attempts=None):
            d = {"checked_at": (datetime.now(timezone.utc) - timedelta(hours=hours)).strftime("%Y-%m-%dT%H:%M:%SZ")}
            if attempts:
                d["attempts"] = attempts
            return {"verdict": verdict, "detail": json.dumps(d), "first_seen": d["checked_at"]}

        assert files.recheck_due(None) is True
        assert files.recheck_due({"verdict": "unchecked"}) is True
        assert files.recheck_due(row("malicious", 10_000)) is False
        assert files.recheck_due(row("unknown", 5)) is False and files.recheck_due(row("unknown", 7)) is True
        assert files.recheck_due(row("unknown", 7, attempts=2)) is False and files.recheck_due(row("unknown", 13, attempts=2)) is True
        assert files.recheck_due(row("unknown", 24 * 6, attempts=50)) is False and files.recheck_due(row("unknown", 24 * 8, attempts=50)) is True
        assert files.recheck_due(row("clean", 24)) is False and files.recheck_due(row("clean", 24 * 4)) is True
        legacy = {"verdict": "unknown", "detail": None, "first_seen": "2026-01-01T00:00:00Z"}
        assert files.recheck_due(legacy) is True

    def test_failed_recheck_keeps_the_known_verdict(self, cfg, conn, downloads, monkeypatch):
        answers = [(404, None)]
        monkeypatch.setattr(files, "vt_fetch", lambda *a, **k: answers[-1])
        monkeypatch.setattr(files, "get_budget", lambda cfg, conn: files.LocalBudget(conn, 50, per_minute=50))
        files.run(self._cfg(cfg, downloads), conn)
        self._age(conn, 7)
        answers.append((0, None))  # network failure on the re-check
        files.run(self._cfg(cfg, downloads), conn)
        row = db.one(conn, "SELECT verdict, source, detail FROM file_checks")
        assert row["verdict"] == "unknown" and row["source"] == "virustotal" and row["detail"]
        assert files.recheck_due(dict(row)) is True  # still due, retried next run

    def test_attempts_are_counted(self, cfg, conn, downloads, monkeypatch):
        monkeypatch.setattr(files, "vt_fetch", lambda *a, **k: (404, None))
        monkeypatch.setattr(files, "get_budget", lambda cfg, conn: files.LocalBudget(conn, 50, per_minute=50))
        files.run(self._cfg(cfg, downloads), conn)
        self._age(conn, 7)
        files.run(self._cfg(cfg, downloads), conn)
        assert json.loads(db.one(conn, "SELECT detail FROM file_checks")["detail"])["attempts"] == 2
