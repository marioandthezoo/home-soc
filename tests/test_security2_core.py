"""Second security round, core fixes: each test encodes one reproduced exploit.

1. ``serve --host 0.0.0.0`` (or ``run`` with a LAN-facing web.host) with an empty web.token bound
   the dashboard to the network after a log warning, so any LAN host could read the network map,
   rewrite DNS upstreams and webhooks on the Settings page, set its own web.token and pair Lens.
2. A hand-picked short token (``"1234"``) was accepted for a LAN bind; the global guess budget
   brute-forces a 4-digit PIN in about a day.
3. SOC-SYS-003 read ``config.toml`` rather than where the server was really bound, so a ``scan``
   in a second terminal resolved the finding while ``serve --host 0.0.0.0`` was up.
4. The scheduled daily digest built its lines by hand and skipped the notify sanitiser, so a
   stored title with LF / U+2028 / U+202E forged a "[CRITICAL] ..." line in every channel.

No socket is opened: the dashboard server factory is replaced, and Flask's test client stands in
for a LAN browser.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any

import pytest

from homesoc import cli, config, db, util

LAN_CLIENT = {"REMOTE_ADDR": "192.168.1.66"}


# --------------------------------------------------------------------------- harness


@pytest.fixture
def served(monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    """Run the CLI's serve/run paths without a socket, a scheduler thread or signal handlers."""
    seen: dict[str, Any] = {"binds": []}

    class _FakeServer:
        def serve_forever(self) -> None:
            seen["served"] = True

    def fake_make(app, host, port, *, ssl_context=None):
        seen["binds"].append((host, port, ssl_context is not None))
        seen["app"] = app
        return _FakeServer()

    monkeypatch.setattr(cli, "make_dashboard_server", fake_make)
    monkeypatch.setattr(cli.Runtime, "start", lambda self, **kwargs: None)
    monkeypatch.setattr(cli, "_install_signal_handlers", lambda: None)
    monkeypatch.setattr(util, "default_interface_ip", lambda: "192.168.1.105")
    return seen


def _fake_tls(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(cli, "ensure_lens_cert", lambda cfg, host=None: (Path("c.pem"), Path("k.pem")))
    monkeypatch.setattr(cli, "build_tls_context", lambda cert, key: object())
    monkeypatch.setattr(cli, "lens_cert_fingerprint", lambda cert: "AA:BB")


def _write_config(data_dir: Path, text: str) -> None:
    import os

    Path(os.environ["HOMESOC_CONFIG"]).write_text(text, encoding="utf-8")


def _stored_token(data_dir: Path) -> str | None:
    conn = db.connect()
    try:
        return config.overrides(conn).get("web.token")
    finally:
        conn.close()


def _lan_get(app: Any, path: str, token: str | None = None) -> int:
    headers = {"X-Token": token} if token else {}
    with app.test_client() as client:
        return client.get(path, headers=headers, environ_base=LAN_CLIENT).status_code


# ------------------------------------------------------------------ is_loopback_host


@pytest.mark.parametrize("host", ["127.0.0.1", "127.0.0.2", "::1", "[::1]", "localhost", "LocalHost", " 127.0.0.1 "])
def test_loopback_hosts_are_not_exposed(host: str) -> None:
    assert config.is_loopback_host(host) is True
    assert config.Web(host=host).exposed is False


@pytest.mark.parametrize("host", ["", "0.0.0.0", "::", "[::]", "192.168.1.105", "fe80::1%eth0", "homesoc-pc",
                                  "127.0.0.1.attacker.example", "::ffff:192.168.1.5"])
def test_everything_else_counts_as_exposed(host: str) -> None:
    assert config.is_loopback_host(host) is False
    assert config.Web(host=host).exposed is True


def test_lan_bind_problem() -> None:
    assert config.lan_bind_problem(config.Web(host="127.0.0.1", token="")) is None
    assert config.lan_bind_problem(config.Web(host="127.0.0.1", token="1234")) is None
    assert config.lan_bind_problem(config.Web(host="0.0.0.0", token="")) == "no-token"
    assert config.lan_bind_problem(config.Web(host="0.0.0.0", token="1234")) == "weak-token"
    assert config.lan_bind_problem(config.Web(host="0.0.0.0", token="x" * config.MIN_TOKEN_LENGTH)) is None


# ------------------------------------------------- finding 1: no token on the LAN


@pytest.mark.parametrize("host", ["0.0.0.0", "::", "192.168.1.105", "homesoc-pc"])
def test_serve_on_the_lan_without_a_token_generates_and_persists_one(
    host: str, data_dir: Path, served: dict[str, Any], capsys
) -> None:
    assert cli.main(["serve", "--host", host, "--port", "18443"]) == cli.EXIT_OK
    assert served["binds"] == [(host, 18443, False)]
    token = _stored_token(data_dir)
    assert token and len(token) >= 32, "a strong token is stored so it survives restarts"
    out = capsys.readouterr().out
    assert "had no web.token" in out and f"/login?token={token}" in out
    # The exploit: a LAN host with no token read the device list. Now it is turned away.
    app = served["app"]
    assert _lan_get(app, "/api/devices") == 401
    assert _lan_get(app, "/api/settings") == 401
    assert _lan_get(app, "/api/devices", token) == 200


def test_the_generated_token_is_reused_on_the_next_start(data_dir: Path, served: dict[str, Any], capsys) -> None:
    assert cli.main(["serve", "--host", "0.0.0.0", "--port", "18443"]) == cli.EXIT_OK
    first = _stored_token(data_dir)
    capsys.readouterr()
    assert cli.main(["serve", "--host", "0.0.0.0", "--port", "18443"]) == cli.EXIT_OK
    assert _stored_token(data_dir) == first
    assert "had no web.token" not in capsys.readouterr().out


def test_serve_with_tls_on_the_lan_is_covered_too(
    data_dir: Path, served: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    _fake_tls(monkeypatch)
    assert cli.main(["serve", "--tls", "--host", "0.0.0.0", "--port", "18443"]) == cli.EXIT_OK
    assert served["binds"] == [("0.0.0.0", 18443, True)]
    assert _stored_token(data_dir)
    assert _lan_get(served["app"], "/api/map") == 401


@pytest.mark.parametrize("web_host", ["0.0.0.0", ""])
def test_run_with_a_lan_web_host_in_config_toml(
    web_host: str, data_dir: Path, served: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    _fake_tls(monkeypatch)
    _write_config(data_dir, f'[web]\nhost = "{web_host}"\nport = 18443\ntoken = ""\n')
    assert cli.main(["run", "--tls"]) == cli.EXIT_OK
    assert served["binds"] == [(web_host, 18443, True)]
    assert _stored_token(data_dir)
    assert _lan_get(served["app"], "/api/devices") == 401


def test_run_with_a_settings_page_web_host(data_dir: Path, served: dict[str, Any]) -> None:
    conn = db.connect()
    try:
        config.set_override(conn, "web.host", "0.0.0.0")
    finally:
        conn.close()
    assert cli.main(["run"]) == cli.EXIT_OK
    token = _stored_token(data_dir)
    assert token
    assert _lan_get(served["app"], "/api/devices") == 401
    assert _lan_get(served["app"], "/api/devices", token) == 200


def test_the_scheduler_and_app_see_the_generated_token(
    cfg: config.Config, conn: sqlite3.Connection, capsys
) -> None:
    exposed = config.with_overrides(cfg, {"web.host": "0.0.0.0"})
    checked = cli.enforce_bind_policy(exposed, conn)
    assert checked is not None and checked.web.token
    assert config.load(conn).web.token == checked.web.token
    # SOC-SYS-003 no longer fires: the dashboard has a credential.
    assert "SOC-SYS-003" not in {d.finding_id for d in cli.soc_health_drafts(checked, conn, None)}


@pytest.mark.parametrize("host", ["127.0.0.1", "::1", "[::1]", "localhost", "127.0.0.2"])
def test_loopback_without_a_token_behaves_as_before(
    host: str, data_dir: Path, served: dict[str, Any], capsys
) -> None:
    assert cli.main(["serve", "--host", host, "--port", "18443"]) == cli.EXIT_OK
    assert served["binds"] == [(host, 18443, False)]
    assert _stored_token(data_dir) is None
    out = capsys.readouterr().out
    assert "had no web.token" not in out and "/login?token=" not in out


def test_serve_forever_refuses_a_tokenless_lan_bind_whoever_calls_it(
    cfg: config.Config, conn: sqlite3.Connection, served: dict[str, Any]
) -> None:
    for host in ("0.0.0.0", "::", "", "192.168.1.105"):
        rt = cli.Runtime(config.with_overrides(cfg, {"web.host": host}), conn)
        assert cli._serve_forever(rt, host, 0) == cli.EXIT_USAGE
    # The rt.cfg host is not what decides: the address actually being bound is.
    assert cli._serve_forever(cli.Runtime(cfg, conn), "0.0.0.0", 0) == cli.EXIT_USAGE
    assert served["binds"] == []
    assert db.get_setting(conn, cli.BIND_SETTING) is None, "a refused bind is not recorded as the bind"
    assert cli._serve_forever(cli.Runtime(cfg, conn), "127.0.0.1", 0) == cli.EXIT_OK


@pytest.mark.parametrize("setup", ["lens_token", "override", "previous_bind"])
def test_signs_of_prior_open_use_are_reported(
    setup: str, cfg: config.Config, conn: sqlite3.Connection, capsys
) -> None:
    if setup == "lens_token":
        db.lens_mint_token(conn, label="attacker phone")
    elif setup == "override":
        config.set_override(conn, "notify.webhook_url", "https://hook.attacker.example/x")
    else:
        cli.record_bind_state(conn, "0.0.0.0", 8443)
    assert cli.enforce_bind_policy(config.with_overrides(cfg, {"web.host": "0.0.0.0"}), conn) is not None
    out = capsys.readouterr().out
    assert "may already have been open" in out
    assert "python -m homesoc lens revoke --all" in out and "python -m homesoc config overrides" in out


def test_a_clean_first_exposure_does_not_cry_wolf(cfg: config.Config, conn: sqlite3.Connection, capsys) -> None:
    assert cli.enforce_bind_policy(config.with_overrides(cfg, {"web.host": "0.0.0.0"}), conn) is not None
    assert "may already have been open" not in capsys.readouterr().out


# ------------------------------------------------- finding 2: short token on the LAN


def test_a_short_token_on_the_lan_is_refused(data_dir: Path, served: dict[str, Any], capsys) -> None:
    _write_config(data_dir, '[web]\ntoken = "1234"\n')
    assert cli.main(["serve", "--host", "0.0.0.0", "--port", "18443"]) == cli.EXIT_USAGE
    assert served["binds"] == []
    out = capsys.readouterr().out
    assert "only 4 characters" in out and "secrets.token_urlsafe" in out
    assert "/login?token=1234" not in out
    assert _stored_token(data_dir) is None, "the owner's own token is not silently replaced"


def test_a_short_token_set_on_the_settings_page_is_refused_for_run(data_dir: Path, served: dict[str, Any]) -> None:
    conn = db.connect()
    try:
        config.set_override(conn, "web.host", "0.0.0.0")
        config.set_override(conn, "web.token", "hunter2")
    finally:
        conn.close()
    assert cli.main(["run"]) == cli.EXIT_USAGE
    assert served["binds"] == []


def test_a_short_token_is_refused_by_the_last_line_guard(cfg: config.Config, conn: sqlite3.Connection,
                                                         served: dict[str, Any]) -> None:
    rt = cli.Runtime(config.with_overrides(cfg, {"web.host": "0.0.0.0", "web.token": "1234"}), conn)
    assert cli._serve_forever(rt, "0.0.0.0", 0) == cli.EXIT_USAGE
    assert served["binds"] == []


def test_a_short_token_on_loopback_still_starts(data_dir: Path, served: dict[str, Any]) -> None:
    _write_config(data_dir, '[web]\ntoken = "1234"\n')
    assert cli.main(["serve", "--port", "18443"]) == cli.EXIT_OK
    assert served["binds"] == [("127.0.0.1", 18443, False)]


def test_a_strong_token_on_the_lan_is_kept(data_dir: Path, served: dict[str, Any], capsys) -> None:
    strong = "s" * 24
    _write_config(data_dir, f'[web]\ntoken = "{strong}"\n')
    assert cli.main(["serve", "--host", "0.0.0.0", "--port", "18443"]) == cli.EXIT_OK
    assert _stored_token(data_dir) is None
    assert "had no web.token" not in capsys.readouterr().out
    assert _lan_get(served["app"], "/api/devices", strong) == 200


# ------------------------------------------------- finding 3: SOC-SYS-003 on the real bind


def test_soc_sys_003_follows_the_recorded_bind(cfg: config.Config, conn: sqlite3.Connection) -> None:
    assert cfg.web.host == "127.0.0.1" and not cfg.web.token
    assert "SOC-SYS-003" not in {d.finding_id for d in cli.soc_health_drafts(cfg, conn, None)}
    # `serve --host 0.0.0.0 --port 8443` records where it really listens; config still says loopback.
    cli.record_bind_state(conn, "0.0.0.0", 8443)
    drafts = {d.finding_id: d for d in cli.soc_health_drafts(cfg, conn, None)}
    assert "SOC-SYS-003" in drafts
    assert drafts["SOC-SYS-003"].evidence == {"host": "0.0.0.0", "port": 8443}
    # SOC-LENS-001 had the same blind spot.
    lens_on = config.with_overrides(cfg, {"lens.enabled": True})
    lens = {d.finding_id: d for d in cli.soc_health_drafts(lens_on, conn, None)}
    assert lens["SOC-LENS-001"].evidence["host"] == "0.0.0.0"
    # And back on loopback both go quiet.
    cli.record_bind_state(conn, "127.0.0.1", 8787)
    ids = {d.finding_id for d in cli.soc_health_drafts(lens_on, conn, None)}
    assert "SOC-SYS-003" not in ids and "SOC-LENS-001" not in ids


# ------------------------------------------------- finding 4: digest through the sanitiser


FORGED_TITLE = "Telnet open on cam\n[CRITICAL] Router admin password changed from 203.0.113.9 ‮evil"


def test_scheduled_digest_is_sanitised(cfg: config.Config, conn: sqlite3.Connection,
                                       monkeypatch: pytest.MonkeyPatch) -> None:
    channels = pytest.importorskip("homesoc.notify.channels")
    now = util.utcnow_iso()
    db.write(conn, "INSERT INTO findings(finding_id, subject, dedupe_key, severity, title, status, source, "
                   "first_seen, last_seen) VALUES ('NET-SVC-001', ?, 'k1', 'high', ?, 'open', 'test', ?, ?)",
             ("device:1\ncam‮", FORGED_TITLE, now, now))
    posted: list[dict[str, Any]] = []

    def poster(url: str, *, json: Any = None, data: Any = None, headers: dict | None = None):
        posted.append({"url": url, "json": json, "data": data})
        return True, None

    monkeypatch.setattr(channels, "_default_poster", poster)
    monkeypatch.setattr(channels, "_default_runner", lambda argv: (True, None))
    notify = config.with_overrides(cfg, {
        "notify.ntfy_url": "https://ntfy.example.invalid/t", "notify.discord_webhook": "https://discord.example.invalid/w",
        "notify.webhook_url": "https://hook.example.invalid/x", "notify.windows_toast": False,
    })
    cli.send_digest(notify, conn)
    assert len(posted) == 3
    texts = []
    for item in posted:
        if item["data"] is not None:
            texts.append(item["data"].decode("utf-8"))
        payload = item["json"] or {}
        if "embeds" in payload:
            texts.append(payload["embeds"][0]["description"])
        if "body" in payload:
            texts.append(payload["body"])
            assert payload["findings"], "the webhook receives the slimmed finding list"
            for f in payload["findings"]:
                texts.extend([f.get("title", ""), f.get("subject", "")])
    assert texts
    for text in texts:
        for line in text.splitlines():
            assert not line.lstrip("\\").startswith("[CRITICAL"), f"forged line reached a channel: {text!r}"
        assert "‮" not in text and " " not in text
    assert any("Router admin password changed" in t for t in texts), "the title is still delivered, on one line"
