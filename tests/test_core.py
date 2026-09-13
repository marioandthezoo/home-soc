"""Tests for the core package: paths, util, models, db, config, scheduler, cli."""

from __future__ import annotations

import json
import re
import sqlite3
import sys
import threading
import time
import tomllib
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from homesoc import cli, config, db, models, paths, scheduler, util
from homesoc.models import FindingDraft, ScanResult

ISO_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")


# ------------------------------------------------------------------ paths


def test_paths_follow_environment(data_dir: Path, tmp_path: Path) -> None:
    assert paths.data_dir() == data_dir and data_dir.is_dir()
    assert paths.feeds_dir() == data_dir / "feeds" and paths.feeds_dir().is_dir()
    assert paths.logs_dir() == data_dir / "logs"
    assert paths.db_path() == data_dir / "homesoc.db"
    assert paths.config_path() == tmp_path / "config.toml"
    assert (paths.project_root() / "pyproject.toml").is_file()


# ------------------------------------------------------------------- util


def test_utcnow_iso_round_trip() -> None:
    now = util.utcnow_iso()
    assert ISO_RE.match(now)
    parsed = util.parse_iso(now)
    assert parsed is not None and parsed.tzinfo is not None
    assert util.to_iso(parsed) == now
    assert util.iso_ago(hours=1) < now  # string order == time order


@pytest.mark.parametrize(
    "text, expected",
    [
        ("2026-01-02T03:04:05Z", datetime(2026, 1, 2, 3, 4, 5, tzinfo=timezone.utc)),
        ("2026-01-02T03:04:05+00:00", datetime(2026, 1, 2, 3, 4, 5, tzinfo=timezone.utc)),
        ("2026-01-02T05:04:05+02:00", datetime(2026, 1, 2, 3, 4, 5, tzinfo=timezone.utc)),
        ("2026-01-02 03:04:05", datetime(2026, 1, 2, 3, 4, 5, tzinfo=timezone.utc)),
        ("2026-01-02", datetime(2026, 1, 2, tzinfo=timezone.utc)),
        ("garbage", None),
        ("", None),
        (None, None),
    ],
)
def test_parse_iso_variants(text, expected) -> None:
    assert util.parse_iso(text) == expected


def test_human_age() -> None:
    now = datetime(2026, 9, 4, 12, 0, 0, tzinfo=timezone.utc)
    assert util.human_age(None) == "never"
    assert util.human_age(now - timedelta(seconds=10), now) == "just now"
    assert util.human_age(now - timedelta(minutes=5), now) == "5 min ago"
    assert util.human_age(now - timedelta(hours=3), now) == "3 h ago"
    assert util.human_age(now - timedelta(days=2, hours=5), now) == "2 d ago"
    assert util.human_age(now + timedelta(hours=1), now) == "in 1 h"


def test_run_cmd_captures_output_without_shell() -> None:
    rc, out, err = util.run_cmd([sys.executable, "-c", "import sys; print(sys.argv[1])", "a && echo b"], timeout=20)
    assert rc == 0 and out.strip() == "a && echo b" and err == ""


def test_run_cmd_timeout_and_missing() -> None:
    rc, _, err = util.run_cmd([sys.executable, "-c", "import time; time.sleep(5)"], timeout=0.5)
    assert rc == util.RC_TIMEOUT and "timeout" in err
    rc, _, err = util.run_cmd(["definitely-not-a-real-binary-xyz"], timeout=1)
    assert rc == util.RC_NOT_FOUND and "not found" in err


def test_safe_json_loads() -> None:
    assert util.safe_json_loads('{"a": 1}') == {"a": 1}
    assert util.safe_json_loads('﻿{"a": 1}') == {"a": 1}
    assert util.safe_json_loads(b'[1, 2]') == [1, 2]
    assert util.safe_json_loads("not json", default={}) == {}
    assert util.safe_json_loads(None, default=[]) == []
    assert json.loads(util.json_dumps({"b": Path("x"), "a": 1})) == {"a": 1, "b": "x"}


def test_platform_flags_exclusive() -> None:
    assert sum((util.is_windows(), util.is_macos(), util.is_linux())) == 1


def test_default_network_helpers() -> None:
    import ipaddress

    ip = ipaddress.ip_address(util.default_interface_ip())
    net = ipaddress.ip_network(util.default_cidr())
    assert net.prefixlen == 24
    if not str(ip).startswith("127."):
        assert ip in net
    gw = util.default_gateway()
    assert isinstance(ipaddress.ip_address(gw), ipaddress.IPv4Address)


def test_gateway_parsers(monkeypatch: pytest.MonkeyPatch) -> None:
    route_print = """
===========================================================================
Active Routes:
Network Destination        Netmask          Gateway       Interface  Metric
          0.0.0.0          0.0.0.0    192.168.1.254    192.168.1.105     35
          0.0.0.0          0.0.0.0       10.0.0.1         10.0.0.5     50
        127.0.0.0        255.0.0.0         On-link         127.0.0.1    331
"""
    monkeypatch.setattr(util, "run_cmd", lambda *a, **k: (0, route_print, ""))
    assert util._gateway_windows() == "192.168.1.254"
    monkeypatch.setattr(util, "run_cmd", lambda *a, **k: (0, '[{"dst":"default","gateway":"10.1.1.1"}]', ""))
    assert util._gateway_linux() == "10.1.1.1"
    monkeypatch.setattr(util, "run_cmd", lambda *a, **k: (0, "   route to: default\n  gateway: 10.2.2.2\n", ""))
    assert util._gateway_macos() == "10.2.2.2"
    monkeypatch.setattr(util, "run_cmd", lambda *a, **k: (1, "", "boom"))
    assert util._gateway_windows() is None and util._gateway_linux() is None and util._gateway_macos() is None


def test_atomic_write_text(tmp_path: Path) -> None:
    target = tmp_path / "sub" / "file.txt"
    util.atomic_write_text(target, "hello")
    assert target.read_text(encoding="utf-8") == "hello"
    assert [p.name for p in target.parent.iterdir()] == ["file.txt"]


# ----------------------------------------------------------------- models


def test_severity_order_and_drafts() -> None:
    assert list(models.SEVERITY_ORDER) == ["critical", "high", "medium", "low", "info"]
    assert models.SEVERITY_ORDER["critical"] < models.SEVERITY_ORDER["info"]
    assert models.severity_rank("HIGH") == 1 and models.severity_rank("bogus") == 5 and models.severity_rank(None) == 5
    a, b = FindingDraft("X-1", "host"), FindingDraft("X-1", "host")
    a.evidence["k"] = 1
    assert b.evidence == {}  # default_factory: no shared dict
    result = ScanResult("discovery", [a], {"hosts_total": 1})
    assert result.ok and result.to_dict()["findings"][0]["finding_id"] == "X-1"
    assert not ScanResult("x", [], {}, error="nope").ok
    dev = models.Device(None, "aa:bb:cc:dd:ee:ff", "10.0.0.2", None, None, None, "t", "t", True)
    assert dev.subject == "device:aa:bb:cc:dd:ee:ff" and dev.trusted is False


# --------------------------------------------------------------------- db


def test_schema_has_every_table(conn: sqlite3.Connection) -> None:
    names = {r["name"] for r in db.query(conn, "SELECT name FROM sqlite_master WHERE type = 'table'")}
    assert set(db.TABLES) <= names
    assert db.schema_version(conn) == db.SCHEMA_VERSION
    db.init_schema(conn)  # idempotent
    # One row per applied migration, and calling init_schema again adds none.
    assert db.query(conn, "SELECT COUNT(*) AS n FROM schema_migrations")[0]["n"] == len(db.MIGRATIONS)
    assert conn.execute("PRAGMA foreign_keys").fetchone()[0] == 1
    assert conn.execute("PRAGMA journal_mode").fetchone()[0] == "wal"


def test_schema_columns_match_spec(memory_conn: sqlite3.Connection) -> None:
    def cols(table: str) -> list[str]:
        return [r["name"] for r in memory_conn.execute(f"PRAGMA table_info({table})")]

    assert cols("findings") == ["id", "finding_id", "subject", "dedupe_key", "severity", "title", "detail", "evidence",
                                "status", "source", "first_seen", "last_seen", "resolved_at", "occurrences", "device_id"]
    assert cols("devices") == ["id", "mac", "ip", "hostname", "vendor", "kind", "nickname", "trusted", "notes",
                               "first_seen", "last_seen", "online", "last_service_scan", "mdns_services"]
    assert cols("jobs") == ["name", "last_run", "last_status", "last_duration_sec", "next_run", "runs", "failures", "last_error"]
    assert cols("dns_queries") == ["id", "ts", "client", "qname", "qtype", "action", "reason", "ms"]
    assert cols("feeds") == ["name", "url", "kind", "etag", "last_modified", "last_checked", "last_updated", "status",
                             "bytes", "entries", "error", "enabled"]
    indexes = {r["name"] for r in memory_conn.execute("SELECT name FROM sqlite_master WHERE type = 'index'")}
    assert {"idx_devices_ip", "idx_findings_status_severity", "idx_events_ts", "idx_metrics_name_ts",
            "idx_dns_queries_ts", "idx_dns_queries_action_ts", "idx_sightings_device_seen"} <= indexes


def test_settings_round_trip(memory_conn: sqlite3.Connection) -> None:
    c = memory_conn
    assert db.get_setting(c, "missing") is None and db.get_setting(c, "missing", "d") == "d"
    db.set_setting(c, "k", "v")
    db.set_setting(c, "k", "v2")
    assert db.get_setting(c, "k") == "v2"
    db.set_setting(c, "flag", True)
    db.set_setting(c, "ports", [80, 443])
    db.set_setting(c, "n", 5)
    assert db.get_setting(c, "flag") == "true" and db.get_setting(c, "ports") == "[80,443]" and db.get_setting(c, "n") == "5"
    assert db.settings_with_prefix(c, "k") == {"k": "v2"}
    db.delete_setting(c, "k")
    assert db.get_setting(c, "k") is None


def test_write_events_metrics_and_fk(memory_conn: sqlite3.Connection) -> None:
    c = memory_conn
    now = util.utcnow_iso()
    row_id = db.write(c, "INSERT INTO devices(mac, ip, first_seen, last_seen) VALUES (?, ?, ?, ?)", ("aa", "1.1.1.1", now, now))
    assert row_id == 1
    db.writemany(c, "INSERT INTO device_sightings(device_id, ip, seen_at, method) VALUES (?, ?, ?, ?)",
                 [(1, "1.1.1.1", now, "arp"), (1, "1.1.1.1", now, "tcp")])
    assert db.one(c, "SELECT COUNT(*) AS n FROM device_sightings")["n"] == 2
    with pytest.raises(sqlite3.IntegrityError):
        db.write(c, "INSERT INTO device_sightings(device_id, ip, seen_at, method) VALUES (?, ?, ?, ?)", (999, "x", now, "arp"))
    db.record_event(c, "INFO", "test", "hello", {"a": 1})
    db.record_metric(c, "score", 87, {"x": "y"})
    event = db.one(c, "SELECT * FROM events")
    assert event["level"] == "info" and json.loads(event["data"]) == {"a": 1} and ISO_RE.match(event["ts"])
    metric = db.one(c, "SELECT * FROM metrics")
    assert metric["name"] == "score" and metric["value"] == 87.0
    sid = db.scan_start(c, "discovery")
    db.scan_finish(c, sid, "ok", {"hosts": 3})
    assert list(db.last_scans(c)) == ["discovery"]
    assert db.purge_older_than(c, "events", "ts", util.iso_ago(hours=-1)) == 1
    with pytest.raises(ValueError):
        db.purge_older_than(c, "sqlite_master", "ts", now)
    with db.transaction(c):
        c.execute("INSERT INTO events(ts, level, source, message) VALUES (?, 'info', 't', 'm')", (now,))
    assert db.table_counts(c)["events"] == 1


def test_concurrent_writes_are_serialised(conn: sqlite3.Connection) -> None:
    def worker() -> None:
        for _ in range(50):
            db.record_metric(conn, "t", 1.0)

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert db.one(conn, "SELECT COUNT(*) AS n FROM metrics")["n"] == 400


# ----------------------------------------------------------------- config


def test_example_file_is_in_sync_with_defaults() -> None:
    example = paths.project_root() / "config.example.toml"
    assert example.read_text(encoding="utf-8") == config.EXAMPLE_TOML
    assert tomllib.loads(example.read_text(encoding="utf-8")) == config.DEFAULTS
    for section in config.SECTIONS:
        assert set(config.DEFAULTS[section]) == {f.name for f in __import__("dataclasses").fields(config.SECTION_TYPES[section])}


def test_defaults_and_write_example(tmp_path: Path) -> None:
    cfg = config.load(path=tmp_path / "none.toml")
    assert cfg.web.port == 8787 and cfg.dns.enabled is False and cfg.dns.upstreams == ("1.1.1.2", "9.9.9.9")
    assert cfg.network.discovery_ports[0] == 80 and cfg.vulns.min_cvss_report == 7.0
    assert cfg.source_path is None
    target = tmp_path / "example.toml"
    config.write_example(target)
    loaded = config.load(path=target)
    assert loaded.to_dict() == cfg.to_dict() and loaded.source_path == str(target)
    assert cfg.get("schedule.discovery_minutes") == 10 and cfg.flat()["dns.port"] == 53


def test_toml_then_settings_override_merge(conn: sqlite3.Connection, tmp_path: Path) -> None:
    toml_path = Path(paths.config_path())
    toml_path.write_text('[web]\nport = 9999\ntoken = "abc"\n[dns]\nenabled = true\nbogus = 1\n[nosuch]\nx = 1\n', encoding="utf-8")
    cfg = config.load(conn)
    assert cfg.web.port == 9999 and cfg.web.token == "abc" and cfg.dns.enabled is True
    config.set_override(conn, "web.port", "9000")
    config.set_override(conn, "network.exclude", "192.168.1.5, 192.168.1.6")
    config.set_override(conn, "network.discovery_ports", "[22, 80]")
    config.set_override(conn, "dns.enabled", "no")
    db.set_setting(conn, "exposure.public_ip", "1.2.3.4")  # foreign settings key must be ignored
    db.set_setting(conn, "web.refresh_seconds", "not-a-number")  # bad override must not break load
    cfg = config.load(conn)
    assert cfg.web.port == 9000 and cfg.network.exclude == ("192.168.1.5", "192.168.1.6")
    assert cfg.network.discovery_ports == (22, 80) and cfg.dns.enabled is False and cfg.web.refresh_seconds == 15
    assert set(config.overrides(conn)) == {"web.port", "network.exclude", "network.discovery_ports", "dns.enabled", "web.refresh_seconds"}
    config.clear_override(conn, "web.port")
    assert config.load(conn).web.port == 9999


def test_set_override_validates() -> None:
    c = db.connect(":memory:")
    with pytest.raises(ValueError):
        config.set_override(c, "web.port", "abc")
    with pytest.raises(ValueError):
        config.set_override(c, "nosuch.key", "1")
    with pytest.raises(ValueError):
        config.set_override(c, "dns.enabled", "maybe")
    config.set_override(c, "web.token", "s3cret")
    assert config.redacted(config.load(c, path=Path("nope.toml")))["web"]["token"] == "***"
    assert config.coerce("scan.max_parallel_hosts", 2.0) == 2 and config.coerce("host.files_dirs", ["a"]) == ("a",)


def test_with_overrides_and_helpers(cfg: config.Config) -> None:
    changed = config.with_overrides(cfg, {"dns.port": 5353, "web.host": "0.0.0.0"})
    assert changed.dns.port == 5353 and changed.web.exposed and not cfg.web.exposed
    with pytest.raises(KeyError):
        config.with_overrides(cfg, {"dns.nope": 1})
    net = config.with_overrides(cfg, {"network.cidr": "10.0.0.0/24", "network.gateway": "10.0.0.1", "network.exclude": ["10.0.0.9"]}).network
    assert net.resolved_cidr() == "10.0.0.0/24" and net.resolved_gateway() == "10.0.0.1" and net.is_excluded("10.0.0.9")
    assert net.is_fragile_vendor("Sonos, Inc.") and not net.is_fragile_vendor("Nokia") and not net.is_fragile_vendor(None)
    assert cfg.network.resolved_cidr().endswith("/24")


# -------------------------------------------------------------- scheduler


def _wait_until(pred, timeout: float = 5.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if pred():
            return True
        time.sleep(0.02)
    return pred()


def test_scheduler_run_now_and_no_overlap(cfg: config.Config, conn: sqlite3.Connection) -> None:
    calls: list[float] = []
    gate = threading.Event()

    def slow() -> None:
        calls.append(time.time())
        gate.wait(5)

    sched = scheduler.Scheduler(cfg, conn, [scheduler.Job("slow", 0, slow), scheduler.Job("never", 0, lambda: None)])
    sched.start()
    try:
        assert sched.run_now("unknown") is False
        assert sched.run_now("slow") is True
        assert _wait_until(lambda: sched.is_running("slow"))
        assert sched.run_now("slow") is False  # already running -> no overlap
        gate.set()
        assert _wait_until(lambda: not sched.is_running("slow"))
        assert sched.run_now("slow", wait=True, timeout=5) is True
        assert len(calls) == 2
        status = {j["name"]: j for j in sched.status()}
        assert status["slow"]["runs"] == 2 and status["slow"]["last_status"] == "ok" and status["slow"]["next_run"] is None
        assert status["never"]["runs"] == 0 and status["never"]["manual_only"]
        row = db.one(conn, "SELECT * FROM jobs WHERE name = 'slow'")
        assert row["runs"] == 2 and row["last_status"] == "ok" and row["last_duration_sec"] is not None
        assert db.one(conn, "SELECT COUNT(*) AS n FROM metrics WHERE name = 'job.duration'")["n"] == 2
        assert db.one(conn, "SELECT COUNT(*) AS n FROM events WHERE source = 'scheduler'")["n"] == 2
    finally:
        gate.set()
        sched.stop()
    assert not sched.running


def test_scheduler_failures_and_interval(cfg: config.Config, conn: sqlite3.Connection) -> None:
    ticks: list[int] = []

    def bad() -> None:
        raise RuntimeError("boom")

    jobs = [scheduler.Job("bad", 0, bad), scheduler.Job("tick", 3600, lambda: ticks.append(1)),
            scheduler.Job("later", 3600, lambda: ticks.append(2), run_at_start=False),
            scheduler.Job("digest", 86400, lambda: None, run_at_start=False, at_hour=3)]
    sched = scheduler.Scheduler(cfg, conn, jobs)
    sched.start()
    try:
        assert _wait_until(lambda: ticks == [1])  # run_at_start job ran once
        for _ in range(scheduler.FAILING_REPEATEDLY):
            assert sched.run_now("bad", wait=True, timeout=5)
        status = {j["name"]: j for j in sched.status()}
        assert status["bad"]["failures"] == 3 and status["bad"]["consecutive_failures"] == 3
        assert status["bad"]["failing_repeatedly"] and "RuntimeError: boom" in status["bad"]["last_error"]
        assert [j["name"] for j in sched.failing_jobs()] == ["bad"]
        assert status["later"]["runs"] == 0 and status["later"]["next_run"] > util.utcnow_iso()
        digest_next = util.parse_iso(status["digest"]["next_run"])
        assert digest_next is not None and 0 < (digest_next - datetime.now(timezone.utc)).total_seconds() <= 86400
        assert digest_next.astimezone().hour == 3 and digest_next.astimezone().minute == 0
        assert db.one(conn, "SELECT level FROM events WHERE message LIKE 'job bad error%'")["level"] == "error"
    finally:
        sched.stop()
    # History survives a restart, and run_now works inline when no worker thread is alive.
    again = scheduler.Scheduler(cfg, conn, [scheduler.Job("bad", 0, bad)])
    assert again.status()[0]["failures"] == 3
    assert again.run_now("bad") is True and again.status()[0]["failures"] == 4


# -------------------------------------------------------------------- cli


def test_parser_and_exit_codes(data_dir: Path) -> None:
    parser = cli.build_parser()
    args = parser.parse_args(["scan", "--quick", "--only", "discovery,host"])
    assert args.command == "scan" and args.quick and args.only == "discovery,host"
    assert parser.parse_args(["defender", "--quick-scan"]).quick_scan
    assert parser.parse_args(["dns-test", "example.com"]).domain == "example.com"
    assert cli.main([]) == cli.EXIT_USAGE
    assert cli.main(["defender"]) == cli.EXIT_USAGE
    assert cli.main(["scan", "--only", "bogus"]) == cli.EXIT_USAGE
    assert cli.main(["--version"]) == 0


def test_lazy_import_missing_package(monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture) -> None:
    monkeypatch.setitem(cli.MODULES, "ghost", ("homesoc.no_such_package.mod", "run"))
    monkeypatch.setattr(cli, "_UNAVAILABLE", set())
    with caplog.at_level("WARNING"):
        assert cli._lazy("ghost") is None
        assert cli._lazy("ghost") is None
    assert sum("homesoc.no_such_package.mod is not available" in r.message for r in caplog.records) == 1
    assert cli._lazy("apply") is None or callable(cli._lazy("apply"))


def test_init_status_findings_export(data_dir: Path, capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    assert cli.main(["init", "--no-feeds"]) == 0
    assert paths.config_path().is_file() and paths.db_path().is_file()
    created = paths.config_path().read_text(encoding="utf-8")
    assert cli.main(["init", "--no-feeds"]) == 0  # idempotent; keeps the config
    assert paths.config_path().read_text(encoding="utf-8") == created
    assert cli.main(["status"]) == 0
    out = capsys.readouterr().out
    assert "score: 100 (A)" in out and "devices: 0 online / 0 total" in out
    assert cli.main(["findings"]) == 0 and "no findings" in capsys.readouterr().out

    conn = db.connect()
    now = util.utcnow_iso()
    db.write(conn, "INSERT INTO findings(finding_id, subject, dedupe_key, severity, title, status, source, first_seen, last_seen)"
                   " VALUES ('NET-SVC-001', 'device:aa:443', 'k1', 'critical', 'Telnet open', 'open', 'services', ?, ?)", (now, now))
    db.write(conn, "INSERT INTO findings(finding_id, subject, dedupe_key, severity, title, status, source, first_seen, last_seen)"
                   " VALUES ('WIN-FW-001', 'host', 'k2', 'high', 'Firewall off', 'resolved', 'host', ?, ?)", (now, now))
    conn.close()
    assert cli.main(["findings", "--status", "open"]) == 0
    out = capsys.readouterr().out
    assert "NET-SVC-001" in out and "WIN-FW-001" not in out
    assert cli.main(["status"]) == 0
    out = capsys.readouterr().out
    # One open critical caps the score at 34 however clean the rest is (findings.score ceilings),
    # and the resolved firewall finding costs nothing.
    assert "score: 34 (F)" in out
    assert "costing the most points:" in out and "NET-SVC-001" in out
    report = tmp_path / "report.json"
    assert cli.main(["export", "--out", str(report)]) == 0
    data = json.loads(report.read_text(encoding="utf-8"))
    assert {"generated_at", "version", "score", "score_breakdown", "counts", "findings", "devices", "vulns"} <= set(data)
    assert len(data["findings"]) == 2 and data["score"] == 34
    assert [b["finding_id"] for b in data["score_breakdown"]] == ["NET-SVC-001"]


def test_fallbacks_and_grade(memory_conn: sqlite3.Connection) -> None:
    assert cli.fallback_score(memory_conn) == 100 and cli.fallback_counts(memory_conn) == {}
    assert [cli.grade(s) for s in (95, 80, 79, 65, 50, 35, 34)] == ["A", "A", "B", "B", "C", "D", "F"]


def _seed(conn: sqlite3.Connection, finding_id: str, severity: str, n: int, status: str = "open") -> None:
    now = util.utcnow_iso()
    for i in range(n):
        db.write(conn, "INSERT INTO findings(finding_id, subject, dedupe_key, severity, title, status, source,"
                       " first_seen, last_seen) VALUES (?,?,?,?,?,?,'test',?,?)",
                 (finding_id, f"s{i}", f"{finding_id}|{i}", severity, "t", status, now, now))


def test_fallback_score_matches_the_real_score_module(memory_conn: sqlite3.Connection) -> None:
    """cli keeps its own copy of the formula for when findings.score is missing; it must agree."""
    from homesoc.findings import score as score_module

    _seed(memory_conn, "WIN-UPD-003", "low", 18)
    _seed(memory_conn, "NET-DEV-001", "medium", 22)
    _seed(memory_conn, "WIN-UPD-004", "high", 5)
    _seed(memory_conn, "NET-DEV-002", "info", 8)
    _seed(memory_conn, "WIN-ACC-001", "medium", 1, status="acknowledged")
    _seed(memory_conn, "WIN-SYS-007", "low", 1, status="suppressed")
    assert cli.fallback_score(memory_conn) == score_module.security_score(memory_conn)
    _seed(memory_conn, "NET-WAN-001", "critical", 2)
    assert cli.fallback_score(memory_conn) == score_module.security_score(memory_conn)


def test_baseline_command_trusts_devices_and_closes_new_device_findings(
    data_dir: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """The recovery path for an install that already flooded: `homesoc baseline`."""
    assert cli.main(["init", "--no-feeds"]) == 0
    capsys.readouterr()
    conn = db.connect()
    now = util.utcnow_iso()
    for i in range(3):
        mac = f"aa:bb:cc:00:00:0{i}"
        device_id = db.write(conn, "INSERT INTO devices(mac, ip, hostname, first_seen, last_seen, online)"
                                   " VALUES (?,?,?,?,?,1)", (mac, f"192.168.1.{10 + i}", f"thing{i}", now, now))
        db.write(conn, "INSERT INTO findings(finding_id, subject, dedupe_key, severity, title, status, source,"
                       " first_seen, last_seen, device_id) VALUES ('NET-DEV-001',?,?,'medium','New device','open',"
                       "'discovery',?,?,?)", (f"device:{mac}", f"NET-DEV-001|device:{mac}", now, now, device_id))
    conn.close()

    assert cli.main(["baseline", "--dry-run"]) == 0
    out = capsys.readouterr().out
    assert "devices known: 3" in out and "would trust: 3" in out and "would close: 3" in out
    assert "nothing was written" in out
    conn = db.connect()
    assert db.one(conn, "SELECT COUNT(*) AS n FROM devices WHERE trusted=1")["n"] == 0
    assert db.one(conn, "SELECT COUNT(*) AS n FROM findings WHERE status='open'")["n"] == 3
    conn.close()

    assert cli.main(["baseline", "--trust-all"]) == 0
    out = capsys.readouterr().out
    assert "trusted: 3" in out and "closed: 3" in out and "score:" in out
    conn = db.connect()
    assert db.one(conn, "SELECT COUNT(*) AS n FROM devices WHERE trusted=1")["n"] == 3
    assert db.one(conn, "SELECT COUNT(*) AS n FROM findings WHERE status='resolved'")["n"] == 3
    assert db.one(conn, "SELECT COUNT(*) AS n FROM events WHERE source='baseline'")["n"] == 1
    conn.close()

    # Running it again is a no-op, not a second round of writes.
    assert cli.main(["baseline"]) == 0
    out = capsys.readouterr().out
    assert "already trusted: 3" in out and "closed: 0" in out


def test_baseline_reports_cleanly_when_the_findings_package_is_missing(
    data_dir: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    assert cli.main(["init", "--no-feeds"]) == 0
    capsys.readouterr()
    monkeypatch.setattr(cli, "_lazy", lambda name: None)
    assert cli.main(["baseline"]) == cli.EXIT_ERROR
    assert "not available" in capsys.readouterr().out


class _FakeApplied:
    def __init__(self, new):
        self.new, self.reopened, self.resolved, self.updated = new, [], ["x"], 2


def _fake_engine(monkeypatch: pytest.MonkeyPatch) -> dict:
    calls: dict = {"apply": [], "notify": []}

    def fake_apply(conn, drafts, source, *, scope=None):
        calls["apply"].append((source, scope, [d.finding_id for d in drafts]))
        return _FakeApplied([{"finding_id": d.finding_id, "severity": "high"} for d in drafts])

    def fake_notify(cfg, conn, new):
        calls["notify"].append(len(new))

    real = cli._lazy

    def lazy(name):
        if name == "apply":
            return fake_apply
        if name == "notify_new_findings":
            return fake_notify
        if name in ("security_score", "counts", "list_findings"):
            return None
        return real(name)

    monkeypatch.setattr(cli, "_lazy", lazy)
    return calls


def test_run_step_records_scan_and_applies(cfg: config.Config, conn: sqlite3.Connection, monkeypatch: pytest.MonkeyPatch) -> None:
    calls = _fake_engine(monkeypatch)
    good = lambda: ScanResult("host", [FindingDraft("WIN-FW-001", "host", {"profile": "Public"})], {"checks": 3})  # noqa: E731
    warn = lambda: ScanResult("updates", [], {}, error="winget missing")  # noqa: E731

    def crash() -> None:
        raise RuntimeError("kaboom")

    result = cli.run_step(cfg, conn, "host", [("host", good, "host"), ("updates", warn, "host"), ("defender", crash, "host"), ("persistence", None, "host")])
    assert result["status"] == "partial"
    assert result["summary"]["host"]["findings"] == {"new": 1, "reopened": 0, "resolved": 1, "updated": 2}
    assert result["summary"]["persistence"] == {"skipped": "module unavailable"}
    assert "kaboom" in result["summary"]["defender"]["error"] and result["summary"]["updates"]["error"] == "winget missing"
    # The successful part keeps its scope; the FAILED part must hand the engine scope=None, or
    # "winget is missing" would auto-resolve every open WIN-UPD-* finding on this host.
    assert calls["apply"] == [("host", "host", ["WIN-FW-001"]), ("updates", None, [])]
    assert calls["notify"] == [1]
    scan = db.one(conn, "SELECT * FROM scans WHERE kind = 'host'")
    assert scan["status"] == "partial" and "kaboom" in scan["error"] and json.loads(scan["summary"])["host"]["checks"] == 3
    assert cli.run_step(cfg, conn, "files", [("files", None, None)])["status"] == "skipped"
    assert cli.run_step(cfg, conn, "wifi", [("wifi", crash, "host")])["status"] == "error"


def test_effective_scope_never_resolves_from_a_scan_that_did_not_look() -> None:
    """Auto-resolve is "we looked and it is gone", never "we did not look"."""
    full = ScanResult("host", [], {"checks": 12})
    assert cli.effective_scope(full, "host") == "host"
    # a failed / timed-out scanner
    assert cli.effective_scope(ScanResult("host", [], {}, error="posture.ps1: timeout after 240s"), "host") is None
    # a scanner that says it only got part way
    assert cli.effective_scope(ScanResult("services", [], {"partial": True}), "device:") is None
    # nothing to scan: laptop on a VPN, no device inside the /24; devices all asleep
    assert cli.effective_scope(ScanResult("services", [], {"targets": []}), "device:") is None
    assert cli.effective_scope(ScanResult("discovery", [], {"hosts_scanned": 0}), "device:") is None
    # a scanner that reports exactly what it covered wins over the blanket prefix
    covered = ScanResult("services", [], {"scopes": ["device:aa:bb", "device:cc:dd"], "targets": ["1", "2"]})
    assert cli.effective_scope(covered, "device:") == ["device:aa:bb", "device:cc:dd"]
    assert cli.effective_scope(ScanResult("services", [], {"scopes": []}), "device:") == []


def test_run_scan_without_sibling_packages(cfg: config.Config, conn: sqlite3.Connection, monkeypatch: pytest.MonkeyPatch) -> None:
    """Every scanner missing must yield skipped steps and a recorded 'full' scan, never an exception."""
    monkeypatch.setattr(cli, "_lazy", lambda name: None)
    result = cli.run_scan(cfg, conn, cli.SCAN_STEPS)
    assert result["status"] == "ok" and set(result["steps"]) == set(cli.SCAN_STEPS)
    kinds = {r["kind"] for r in db.query(conn, "SELECT kind FROM scans")}
    assert {"full", "discovery", "services", "vulns", "host", "exposure", "wifi", "files"} <= kinds
    assert cli.run_feeds(cfg, conn) == {}
    cli.dns_rollup(cfg, conn)  # no dnsfilter package, no queries: must not raise
    cli.send_digest(cfg, conn)


def test_soc_health_drafts(cfg: config.Config, conn: sqlite3.Connection, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(util, "which", lambda name: None)
    exposed = config.with_overrides(cfg, {"web.host": "0.0.0.0"})
    old, recent = util.iso_ago(hours=72), util.iso_ago(hours=1)
    db.writemany(conn, "INSERT INTO feeds(name, url, kind, status, last_checked, last_updated, error, enabled) VALUES (?, ?, ?, ?, ?, ?, ?, ?)", [
        ("kev", "u", "kev", "error", recent, old, "503", 1),
        ("oui", "u", "oui", "updated", recent, recent, None, 1),
        # never succeeded, and has been failing since before the 48 h window -> a real finding
        ("dead", "u", "hosts", "error", recent, None, "timeout", 1),
        # never succeeded either, but only started failing an hour ago: an offline first start
        # must NOT raise a finding per feed the moment the first fetch fails (spec §7/§9: > 48 h)
        ("just_started", "u", "hosts", "error", recent, None, "timeout", 1),
        ("disabled", "u", "hosts", "error", recent, None, "x", 0),
        ("fresh_fail", "u", "hosts", "error", recent, recent, "x", 1),
    ])
    # feeds.updater stamps this on the first error of a run of failures and clears it on success.
    db.set_setting(conn, "feeds.error_since.dead", old)
    db.set_setting(conn, "feeds.error_since.just_started", recent)

    class FakeSched:
        def failing_jobs(self):
            return [{"name": "exposure", "consecutive_failures": 3, "last_error": "e", "last_run": recent}]

    drafts = cli.soc_health_drafts(exposed, conn, FakeSched())
    ids = sorted((d.finding_id, d.subject) for d in drafts)
    assert ids == [("SOC-FEED-001", "feed:dead"), ("SOC-FEED-001", "feed:kev"), ("SOC-FEED-002", "feed:kev"),
                   ("SOC-SYS-001", "host"), ("SOC-SYS-003", "host"), ("SOC-SYS-004", "job:exposure")]

    # Every placeholder the catalog templates use must be present in the evidence, or the user
    # reads "Scheduled job 'unknown' keeps failing (unknown times)".
    by_id = {(d.finding_id, d.subject): d for d in drafts}
    job_draft = by_id[("SOC-SYS-004", "job:exposure")]
    assert job_draft.evidence["job"] == "exposure" and job_draft.evidence["failures"] == 3
    assert by_id[("SOC-FEED-001", "feed:dead")].evidence["hours"] >= 48
    assert by_id[("SOC-FEED-002", "feed:kev")].evidence["hours"] >= 48
    assert all("unknown" not in str(v) for d in drafts for v in d.evidence.values())

    calls = _fake_engine(monkeypatch)
    totals = cli.apply_soc_health(exposed, conn, FakeSched())
    assert totals["new"] == 6 and [c[1] for c in calls["apply"]] == ["host", "job:", "feed:"]
    monkeypatch.setattr(util, "which", lambda name: "/usr/bin/nmap")
    assert not [d for d in cli.soc_health_drafts(cfg, conn, None) if d.finding_id.startswith("SOC-SYS")]


def test_soc_drafts_render_without_unknown_placeholders(cfg: config.Config, conn: sqlite3.Connection,
                                                        monkeypatch: pytest.MonkeyPatch) -> None:
    """The evidence keys core emits must be the ones the catalog templates interpolate.

    These are exactly the findings a non-expert reads when something is broken; a mismatch used
    to render "Scheduled job 'unknown' keeps failing (unknown times)".
    """
    catalog = pytest.importorskip("homesoc.findings.catalog")
    monkeypatch.setattr(util, "which", lambda name: None)
    exposed = config.with_overrides(cfg, {"web.host": "0.0.0.0"})
    old = util.iso_ago(hours=72)
    db.writemany(conn, "INSERT INTO feeds(name, url, kind, status, last_checked, last_updated, error, enabled)"
                       " VALUES (?, 'u', ?, 'error', ?, ?, 'HTTP 503', 1)",
                 [("kev", "kev", util.iso_ago(hours=1), old), ("openphish", "hosts", util.iso_ago(hours=1), old)])

    class FakeSched:
        def failing_jobs(self):
            return [{"name": "exposure", "consecutive_failures": 4, "last_error": "timeout", "last_run": old}]

    drafts = cli.soc_health_drafts(exposed, conn, FakeSched())
    assert {d.finding_id for d in drafts} == {"SOC-SYS-001", "SOC-SYS-003", "SOC-SYS-004", "SOC-FEED-001", "SOC-FEED-002"}
    for draft in drafts:
        needed = catalog.placeholders(draft.finding_id)
        supplied = set(draft.evidence) | {"subject", "mac", "ip", "port", "name", "client", "domain", "host", "job"}
        missing = {p for p in needed if p not in supplied}
        assert not missing, f"{draft.finding_id} evidence is missing {sorted(missing)} used by the catalog"
        title, detail = catalog.render(draft)
        for text in (title, detail, *catalog.render_remediation(draft.finding_id, draft.evidence, draft.subject)):
            rendered = str(text)
            assert "unknown" not in rendered.lower(), f"{draft.finding_id} renders a placeholder as 'unknown': {text}"
            # a literal "{field}" left behind means the template named something nobody supplies
            # (remediation text may contain other braces, e.g. a PowerShell snippet, so be precise)
            for field in needed:
                assert "{" + field + "}" not in rendered, f"{draft.finding_id} left {{{field}}} unfilled: {text}"


def test_offline_first_start_does_not_flood_feed_findings(cfg: config.Config, conn: sqlite3.Connection,
                                                          monkeypatch: pytest.MonkeyPatch) -> None:
    """A fresh install with no connectivity: every feed fails once. Nothing has been failing for
    48 h yet, so the user must see zero SOC-FEED findings, not one per feed."""
    monkeypatch.setattr(util, "which", lambda name: "/usr/bin/nmap")
    now = util.utcnow_iso()
    names = [f"list{i}" for i in range(14)] + ["kev"]
    db.writemany(conn, "INSERT INTO feeds(name, url, kind, status, last_checked, last_updated, error, enabled)"
                       " VALUES (?, 'u', 'hosts', 'error', ?, NULL, 'connection refused', 1)",
                 [(name, now) for name in names])
    for name in names:
        db.set_setting(conn, f"feeds.error_since.{name}", now)
    assert cli.soc_health_drafts(cfg, conn, None) == []
    # Two days later the same failures are real news.
    for name in names:
        db.set_setting(conn, f"feeds.error_since.{name}", util.iso_ago(hours=50))
    later = cli.soc_health_drafts(cfg, conn, None)
    assert sorted(d.finding_id for d in later) == ["SOC-FEED-001"] * 15 + ["SOC-FEED-002"]


def test_build_jobs(cfg: config.Config, conn: sqlite3.Connection) -> None:
    names = [j.name for j in cli.build_jobs(cfg, conn)]
    assert names[:2] == ["feeds", "discovery"] and names.index("services") < names.index("vulns")
    assert {"feeds", "discovery", "services", "host", "exposure", "vulns", "files", "dns_rollup", "digest", "score", "quick", "full"} <= set(names)
    jobs = {j.name: j for j in cli.build_jobs(cfg, conn)}
    assert jobs["discovery"].interval_sec == 600 and jobs["files"].interval_sec == 86400
    assert jobs["digest"].at_hour == 8 and not jobs["digest"].run_at_start and jobs["quick"].manual_only
    no_digest = cli.build_jobs(config.with_overrides(cfg, {"notify.digest_hour": -1}), conn)
    assert "digest" not in [j.name for j in no_digest]
    sched = scheduler.Scheduler(cfg, conn, cli.build_jobs(cfg, conn))
    assert len(sched.status()) == len(names)


def test_runtime_without_web_or_dns(cfg: config.Config, conn: sqlite3.Connection, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(cli, "_lazy", lambda name: None)
    rt = cli.Runtime(cfg, conn)
    rt.start(with_scheduler=True, with_dns=True)
    assert rt.scheduler is not None and rt.scheduler.running and rt.dns_server is None
    rt.stop()
    assert not rt.scheduler.running
    assert cli._serve_forever(rt, "127.0.0.1", 0) == cli.EXIT_ERROR


def test_build_jobs_manual_only_keeps_names_without_timetable(cfg: config.Config, conn: sqlite3.Connection) -> None:
    """`serve` starts the scheduler this way: every job exists for run_now, none is ever scheduled."""
    timetable = {j.name for j in cli.build_jobs(cfg, conn)}
    manual = cli.build_jobs(cfg, conn, manual_only=True)
    assert {j.name for j in manual} == timetable
    assert all(j.manual_only and not j.run_at_start and j.at_hour is None for j in manual)
    sched = scheduler.Scheduler(cfg, conn, manual)
    sched.start()
    try:
        assert all(s["next_run"] is None for s in sched.status())
    finally:
        sched.stop()


def test_housekeeping_purges_old_telemetry(cfg: config.Config, conn: sqlite3.Connection) -> None:
    """The database must not grow forever: db.purge_older_than has to be wired to a real job."""
    ancient, now = util.iso_ago(days=400), util.utcnow_iso()
    db.writemany(conn, "INSERT INTO metrics(ts, name, value) VALUES (?, 'dns.qps', 1.0)", [(ancient,)] * 5)
    db.record_metric(conn, "score", 90.0)
    db.writemany(conn, "INSERT INTO events(ts, level, source, message) VALUES (?, 'info', 't', 'old')", [(ancient,)] * 3)
    db.record_event(conn, "info", "t", "fresh")
    db.writemany(conn, "INSERT INTO notifications(ts, channel, subject, status) VALUES (?, 'ntfy', 's', 'ok')", [(ancient,)] * 2)
    db.write(conn, "INSERT INTO scans(kind, started_at, status) VALUES ('discovery', ?, 'ok')", (ancient,))
    device = db.write(conn, "INSERT INTO devices(mac, ip, first_seen, last_seen) VALUES ('aa', '10.0.0.2', ?, ?)", (ancient, now))
    db.writemany(conn, "INSERT INTO device_sightings(device_id, ip, seen_at, method) VALUES (?, '10.0.0.2', ?, 'arp')",
                 [(device, ancient), (device, ancient), (device, ancient)])
    row = db.write(conn, "INSERT INTO findings(finding_id, subject, dedupe_key, severity, title, status, source,"
                         " first_seen, last_seen, resolved_at) VALUES ('WIN-FW-001', 'host', 'k', 'high', 't',"
                         " 'resolved', 'host', ?, ?, ?)", (ancient, ancient, ancient))
    db.writemany(conn, "INSERT INTO finding_events(finding_row_id, event, at) VALUES (?, 'created', ?)", [(row, ancient)])

    purged = cli.housekeeping(cfg, conn)
    assert purged["metrics"] == 5 and purged["events"] == 3 and purged["notifications"] == 2
    assert purged["scans"] == 1 and purged["finding_events"] == 1
    # The last sighting of each device survives: the Devices page needs "last seen".
    assert purged["device_sightings"] == 2
    assert db.one(conn, "SELECT COUNT(*) AS n FROM device_sightings")["n"] == 1
    assert db.one(conn, "SELECT COUNT(*) AS n FROM metrics WHERE name = 'score'")["n"] == 1
    assert db.one(conn, "SELECT COUNT(*) AS n FROM events WHERE message = 'fresh'")["n"] == 1
    assert "housekeeping" in [j.name for j in cli.build_jobs(cfg, conn)]
    assert cli.housekeeping(cfg, conn)["metrics"] == 0  # idempotent, nothing left to purge


# ------------------------------------------------------- addendum A4: report / feed


def test_emit_survives_a_console_that_cannot_encode(capsys: pytest.CaptureFixture[str],
                                                    monkeypatch: pytest.MonkeyPatch) -> None:
    """`report` is full of em dashes; a stock cp437 Windows console must not turn that into a
    UnicodeEncodeError traceback."""
    import io

    class Cp437Stdout(io.StringIO):
        encoding = "cp437"

        def write(self, s: str) -> int:
            s.encode(self.encoding)  # raises UnicodeEncodeError exactly like the real console
            return super().write(s)

    stream = Cp437Stdout()
    monkeypatch.setattr(sys, "stdout", stream)
    cli.emit("Home SOC — security report")
    assert stream.getvalue().rstrip("\n").startswith("Home SOC ")
    assert "—" not in stream.getvalue()


def test_parse_since() -> None:
    assert cli.parse_since(None) is None and cli.parse_since("  ") is None
    assert cli.parse_since("2026-01-02T03:04:05Z") == "2026-01-02T03:04:05Z"
    assert cli.parse_since("24h") < util.utcnow_iso()
    assert cli.parse_since("30m") > cli.parse_since("7d") > cli.parse_since("2w")
    with pytest.raises(ValueError):
        cli.parse_since("yesterday")


def _fake_web_module(monkeypatch: pytest.MonkeyPatch, name: str, **attrs) -> None:
    """Install a stand-in homesoc.web.<name>; the real one is written by another package."""
    import types

    module = types.ModuleType(f"homesoc.web.{name}")
    for key, value in attrs.items():
        setattr(module, key, value)
    monkeypatch.setitem(sys.modules, f"homesoc.web.{name}", module)


def test_report_command_md_and_json(data_dir: Path, monkeypatch: pytest.MonkeyPatch,
                                    capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    seen: list[dict] = []
    _fake_web_module(
        monkeypatch, "summary",
        remediation_report_markdown=lambda conn, *, days=30: (seen.append({"md": days}), "# Home SOC report\n\n1. Turn it on\n")[1],
        remediation_report_json=lambda conn, *, days=30: (seen.append({"json": days}), {"schema_version": 1, "window_days": days})[1],
    )
    assert cli.main(["report"]) == 0
    assert "# Home SOC report" in capsys.readouterr().out and seen[-1] == {"md": 30}

    assert cli.main(["report", "--format", "json", "--days", "7"]) == 0
    assert json.loads(capsys.readouterr().out) == {"schema_version": 1, "window_days": 7}

    out = tmp_path / "report.md"
    assert cli.main(["report", "--out", str(out)]) == 0
    assert "Turn it on" in out.read_text(encoding="utf-8") and str(out) in capsys.readouterr().out


def test_feed_command_filters_and_prints(data_dir: Path, monkeypatch: pytest.MonkeyPatch,
                                         capsys: pytest.CaptureFixture[str]) -> None:
    seen: dict = {}

    def build_feed(conn, *, since=None, kinds=None, limit=200, **rest):
        seen.update(since=since, kinds=kinds, limit=limit)
        return ([{"ts": "2026-09-06T10:00:00Z", "kind": "finding_new", "severity": "high",
                  "title": "Telnet is open on printer", "detail": "192.168.1.74:23"}], 3)

    _fake_web_module(monkeypatch, "feed", build_feed=build_feed)
    assert cli.main(["feed", "--limit", "1", "--kinds", "finding_new, dns_threat", "--since", "24h"]) == 0
    out = capsys.readouterr().out
    assert "Telnet is open on printer" in out and "192.168.1.74:23" in out and "2 older item(s)" in out
    assert seen["limit"] == 1 and seen["kinds"] == {"finding_new", "dns_threat"} and seen["since"] < util.utcnow_iso()

    assert cli.main(["feed", "--since", "yesterday"]) == cli.EXIT_USAGE
    assert "cannot read --since" in capsys.readouterr().out

    _fake_web_module(monkeypatch, "feed", build_feed=lambda conn, **kw: ([], 0))
    assert cli.main(["feed"]) == 0 and "no activity yet" in capsys.readouterr().out


def test_report_and_feed_explain_a_missing_web_package(data_dir: Path, monkeypatch: pytest.MonkeyPatch,
                                                       capsys: pytest.CaptureFixture[str]) -> None:
    """The web package is optional/parallel-developed: fail with a sentence, never a traceback."""
    monkeypatch.setattr(cli, "_web_helper", lambda module, func: None)
    assert cli.main(["report"]) == cli.EXIT_ERROR
    assert "not available in this install" in capsys.readouterr().out
    assert cli.main(["feed"]) == cli.EXIT_ERROR
    assert "not available in this install" in capsys.readouterr().out


# ------------------------------------------------------------------ DNS runtime


def test_start_dns_reports_a_port_conflict_instead_of_pretending(cfg: config.Config, conn: sqlite3.Connection,
                                                                 monkeypatch: pytest.MonkeyPatch) -> None:
    class Refuses:
        last_error = "port 53 already in use"
        running = False

        def __init__(self, *_a, **_k) -> None:
            self.starts = 0

        def start(self) -> bool:
            self.starts += 1
            self.running = self.starts > 1  # binds on the second attempt
            return self.running

        def stop(self) -> None:
            self.running = False

    real = cli._lazy
    monkeypatch.setattr(cli, "_lazy", lambda name: Refuses if name == "DnsServer" else real(name))
    rt = cli.Runtime(cfg, conn)
    assert rt.start_dns() is False              # a refused bind is a failure, not a success
    assert rt.retry_dns() is True               # ... and the retry job heals it
    assert rt.retry_dns() is True               # already running: no needless re-bind
    assert rt.dns_server.starts == 2
    assert "dns_retry" in [j.name for j in cli.build_jobs(cfg, conn)]


def test_cmd_dns_exits_error_when_it_cannot_bind(data_dir: Path, monkeypatch: pytest.MonkeyPatch,
                                                 capsys: pytest.CaptureFixture[str]) -> None:
    monkeypatch.setattr(cli.Runtime, "start_dns", lambda self: False)
    assert cli.main(["dns", "--port", "5399"]) == cli.EXIT_ERROR
    out = capsys.readouterr().out
    assert "could not be started" in out and "listening" not in out


def test_abort_stale_scans_closes_running_rows(conn: sqlite3.Connection) -> None:
    stale = db.scan_start(conn, "services")
    done = db.scan_start(conn, "discovery")
    db.scan_finish(conn, done, "ok", {"hosts_total": 1})
    assert db.abort_stale_scans(conn) == 1
    row = db.one(conn, "SELECT status, finished_at, error FROM scans WHERE id = ?", (stale,))
    assert row["status"] == "aborted" and row["finished_at"] and "stopped" in row["error"]
    assert db.one(conn, "SELECT status FROM scans WHERE id = ?", (done,))["status"] == "ok"
    assert db.abort_stale_scans(conn) == 0
