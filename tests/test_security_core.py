"""Regression tests for the core-area findings of the 2026-09 security review.

Each test encodes the proof of concept from the review and asserts that it now fails:

* one idle TCP connection froze the HTTPS dashboard and Lens (TLS handshake inside accept());
* the database, its WAL and the logs were created readable by every local account;
* LAN-controlled banners and mDNS names reached the terminal with their escape sequences intact.
"""

from __future__ import annotations

import datetime as _dt
import logging
import os
import socket
import ssl
import stat
import threading
import time
from pathlib import Path

import pytest

from homesoc import cli, db, paths, util

POSIX_ONLY = pytest.mark.skipif(os.name == "nt", reason="POSIX file modes")
WINDOWS_ONLY = pytest.mark.skipif(os.name != "nt", reason="Windows ACLs")

# The payload from the review: clear screen, home cursor, retitle the window, a disguised OSC 8
# link, an OSC 52 clipboard write, a bare carriage return and a one-byte C1 CSI.
HOSTILE = ("220 \x1b[2J\x1b[H\x1b]0;Home SOC\x07\x1b]8;;https://evil.example\x07model CAM-1234"
           "\x1b]8;;\x07 \x1b]52;c;ZWNobyBwd25lZA==\x07 ready\rFAKE\x9b31m\x00")
RAW_CONTROLS = ("\x1b", "\x07", "\x9b", "\x00", "\r")


# --------------------------------------------------------------------------- TLS accept loop


def _self_signed(tmp_path: Path) -> tuple[Path, Path]:
    crypto = pytest.importorskip("cryptography")
    del crypto
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = _dt.datetime.now(_dt.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name).issuer_name(name).public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - _dt.timedelta(minutes=5)).not_valid_after(now + _dt.timedelta(days=1))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False)
        .sign(key, hashes.SHA256())
    )
    cert_path, key_path = tmp_path / "cert.pem", tmp_path / "key.pem"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                           serialization.NoEncryption()))
    return cert_path, key_path


def _hello_app(environ, start_response):
    body = f"ok {environ['wsgi.url_scheme']}".encode()
    start_response("200 OK", [("Content-Type", "text/plain"), ("Content-Length", str(len(body)))])
    return [body]


class _Running:
    def __init__(self, ssl_context=None) -> None:
        self.server = cli.make_dashboard_server(_hello_app, "127.0.0.1", 0, ssl_context=ssl_context)
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, kwargs={"poll_interval": 0.05},
                                       daemon=True)

    def __enter__(self) -> _Running:
        self.thread.start()
        return self

    def __exit__(self, *exc) -> None:
        self.server.shutdown()
        self.thread.join(timeout=5)


def _client_context() -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    return context


def _https_get(port: int, timeout: float = 5.0) -> tuple[str, str]:
    with socket.create_connection(("127.0.0.1", port), timeout=timeout) as raw:
        with _client_context().wrap_socket(raw, server_hostname="localhost") as tls:
            version = str(tls.version())
            tls.sendall(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            chunks = []
            while True:
                data = tls.recv(4096)
                if not data:
                    break
                chunks.append(data)
            return b"".join(chunks).decode("latin-1"), version


def _http_get(port: int, timeout: float = 5.0) -> str:
    with socket.create_connection(("127.0.0.1", port), timeout=timeout) as sock:
        sock.sendall(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        chunks = []
        while True:
            data = sock.recv(4096)
            if not data:
                break
            chunks.append(data)
        return b"".join(chunks).decode("latin-1")


def _closed_by_peer(sock: socket.socket, within: float) -> bool:
    sock.settimeout(within)
    try:
        return sock.recv(1) == b""
    except (ConnectionResetError, ConnectionAbortedError):
        return True
    except TimeoutError:
        return False


def test_idle_tcp_connection_no_longer_freezes_the_https_listener(tmp_path: Path) -> None:
    cert, key = _self_signed(tmp_path)
    with _Running(cli.build_tls_context(cert, key)) as running:
        body, _version = _https_get(running.port)
        assert "200 OK" in body and "ok https" in body  # baseline, and the handler sees https
        idle = socket.create_connection(("127.0.0.1", running.port))  # never sends a ClientHello
        partial = socket.create_connection(("127.0.0.1", running.port))
        partial.sendall(b"\x16\x03\x01")  # three bytes of a TLS record header, then silence
        try:
            time.sleep(0.2)  # let the accept loop pick both up
            started = time.monotonic()
            body, _version = _https_get(running.port, timeout=5.0)  # was: handshake timed out
            assert "200 OK" in body and time.monotonic() - started < 3.0
            body, _version = _https_get(running.port, timeout=5.0)
            assert "200 OK" in body
        finally:
            idle.close()
            partial.close()


def test_stalled_handshake_is_dropped_after_the_timeout(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(cli, "TLS_HANDSHAKE_TIMEOUT", 0.5)
    cert, key = _self_signed(tmp_path)
    with _Running(cli.build_tls_context(cert, key)) as running:
        idle = socket.create_connection(("127.0.0.1", running.port))
        try:
            assert _closed_by_peer(idle, within=5.0)
        finally:
            idle.close()


@pytest.mark.filterwarnings("ignore::DeprecationWarning")  # the TLS 1.1 client is the point
def test_tls_floor_is_tls12(tmp_path: Path) -> None:
    cert, key = _self_signed(tmp_path)
    context = cli.build_tls_context(cert, key)
    assert context.minimum_version >= ssl.TLSVersion.TLSv1_2
    with _Running(context) as running:
        _body, version = _https_get(running.port)
        assert version in ("TLSv1.2", "TLSv1.3")
        old = _client_context()
        try:
            old.minimum_version = ssl.TLSVersion.TLSv1
            old.maximum_version = ssl.TLSVersion.TLSv1_1
        except (ValueError, ssl.SSLError):
            return  # this OpenSSL cannot even speak TLS 1.1
        with socket.create_connection(("127.0.0.1", running.port), timeout=5) as raw:
            with pytest.raises((ssl.SSLError, ConnectionError, OSError)):
                with old.wrap_socket(raw, server_hostname="localhost"):
                    pass


def test_plain_http_still_serves_and_idle_connections_are_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(cli, "CONNECTION_IDLE_TIMEOUT", 0.5)
    with _Running() as running:
        assert "ok http" in _http_get(running.port)
        idle = socket.create_connection(("127.0.0.1", running.port))
        try:
            assert "ok http" in _http_get(running.port)  # plain accept() never waited on a peer
            assert _closed_by_peer(idle, within=5.0)  # and a silent client no longer holds a thread forever
        finally:
            idle.close()


def test_serve_forever_uses_the_handshake_safe_server(
    cfg, conn, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """`serve --tls` must never go back to app.run(ssl_context=...), which handshakes in accept()."""
    cert, key = _self_signed(tmp_path)
    monkeypatch.setattr(cli, "ensure_lens_cert", lambda cfg, host=None: (cert, key))
    monkeypatch.setattr(cli, "lens_cert_fingerprint", lambda cert: "AA:BB")
    seen: dict = {}

    class _FakeServer:
        def serve_forever(self) -> None:
            seen["served"] = True

    def fake_make(app, host, port, *, ssl_context=None):
        seen.update(host=host, port=port, ssl_context=ssl_context)
        return _FakeServer()

    monkeypatch.setattr(cli, "make_dashboard_server", fake_make)
    rt = cli.Runtime(cfg, conn)
    assert cli._serve_forever(rt, "127.0.0.1", 0, tls=True) == cli.EXIT_OK
    assert seen["served"] and isinstance(seen["ssl_context"], ssl.SSLContext)
    assert seen["ssl_context"].minimum_version >= ssl.TLSVersion.TLSv1_2


def test_serve_forever_reports_a_failed_bind(cfg, conn, monkeypatch: pytest.MonkeyPatch) -> None:
    def fail(*args, **kwargs):
        raise SystemExit(1)  # what Werkzeug does when the port is taken

    monkeypatch.setattr(cli, "make_dashboard_server", fail)
    assert cli._serve_forever(cli.Runtime(cfg, conn), "127.0.0.1", 0) == cli.EXIT_ERROR


# ------------------------------------------------------------------------ file permissions


def _mode(path: Path) -> int:
    return stat.S_IMODE(path.stat().st_mode)


@POSIX_ONLY
def test_new_install_is_private_to_the_owner(data_dir: Path) -> None:
    previous = os.umask(0o022)  # the common default the review ran with
    try:
        conn = db.connect()
        db.set_setting(conn, "notify.discord_webhook", "https://discord.com/api/webhooks/1/SECRET")
        db.set_setting(conn, "web.token", "SUPERSECRETTOKEN")
        cli.setup_logging("INFO")
        logging.getLogger("homesoc.test").warning("hello")
        assert not _mode(paths.data_dir()) & 0o077
        assert not _mode(paths.logs_dir()) & 0o077
        for suffix in ("", "-wal", "-shm"):
            candidate = Path(f"{paths.db_path()}{suffix}")
            if candidate.exists():
                assert not _mode(candidate) & 0o077, candidate
        assert not _mode(paths.logs_dir() / "homesoc.log") & 0o077
        conn.close()
    finally:
        os.umask(previous)


@POSIX_ONLY
def test_existing_world_readable_install_is_tightened_on_start(data_dir: Path) -> None:
    previous = os.umask(0o022)
    try:
        conn = db.connect()
        conn.close()
        logs = paths.logs_dir()
        (logs / "homesoc.log").write_text("old\n", encoding="utf-8")
        (logs / "homesoc.log.1").write_text("older\n", encoding="utf-8")
        for path in (data_dir, logs):
            os.chmod(path, 0o755)
        for path in (paths.db_path(), logs / "homesoc.log", logs / "homesoc.log.1"):
            os.chmod(path, 0o644)
        paths._SECURED.discard(str(data_dir))  # a fresh process start

        conn = db.connect()
        cli.setup_logging("INFO")
        assert _mode(data_dir) == 0o700 and _mode(logs) == 0o700
        assert _mode(paths.db_path()) == 0o600
        assert _mode(logs / "homesoc.log") == 0o600 and _mode(logs / "homesoc.log.1") == 0o600
        conn.close()
    finally:
        os.umask(previous)


@POSIX_ONLY
def test_main_sets_an_owner_only_umask(data_dir: Path) -> None:
    previous = os.umask(0o022)
    try:
        cli.main(["status"])
        current = os.umask(0o022)
        assert current & 0o077 == 0o077
    finally:
        os.umask(previous)


@POSIX_ONLY
def test_permissions_are_left_alone_on_a_folder_that_is_not_ours(tmp_path: Path, monkeypatch) -> None:
    shared = tmp_path / "shared"
    shared.mkdir()
    (shared / "someone-elses-file.txt").write_text("x", encoding="utf-8")
    os.chmod(shared, 0o755)
    monkeypatch.setenv(paths.ENV_DATA, str(shared))
    paths.data_dir()
    assert _mode(shared) == 0o755


def test_restrict_path_only_removes_bits(tmp_path: Path) -> None:
    target = tmp_path / "f"
    target.write_text("x", encoding="utf-8")
    assert paths.restrict_path(target) is True
    if os.name != "nt":
        os.chmod(target, 0o640)
        paths.restrict_path(target)
        assert _mode(target) == 0o600
        os.chmod(target, 0o400)
        paths.restrict_path(target)
        assert _mode(target) == 0o400  # never widened


def _fake_run_cmd(calls: list[list[str]]):
    def run(args, timeout, cwd=None, **kwargs):
        argv = [str(a) for a in args]
        calls.append(argv)
        if argv[0].lower().endswith("whoami.exe"):
            return 0, '"host\\owner","S-1-5-21-1-2-3-1001"\n', ""
        return 0, "processed 1 files", ""
    return run


def test_windows_data_dir_outside_the_profile_gets_an_owner_only_acl(tmp_path: Path, monkeypatch) -> None:
    """C:\\HomeSOC-data inherits 'Authenticated Users: Modify' from C:\\; it must not keep it."""
    calls: list[list[str]] = []
    monkeypatch.setattr(util, "run_cmd", _fake_run_cmd(calls))
    profile = tmp_path / "profile"
    profile.mkdir()
    outside = tmp_path / "HomeSOC-data"
    outside.mkdir()
    monkeypatch.setenv("USERPROFILE", str(profile))
    assert paths._restrict_windows_acl(outside) is True
    icacls = [c for c in calls if c[0].lower().endswith("icacls.exe")]
    assert len(icacls) == 1
    argv = icacls[0]
    assert argv[1] == str(outside) and "/inheritance:r" in argv
    grants = [argv[i + 1] for i, a in enumerate(argv) if a == "/grant:r"]
    assert grants == ["*S-1-5-21-1-2-3-1001:(OI)(CI)F", "*S-1-5-18:(OI)(CI)F", "*S-1-5-32-544:(OI)(CI)F"]


def test_windows_acl_untouched_inside_the_profile(tmp_path: Path, monkeypatch) -> None:
    calls: list[list[str]] = []
    monkeypatch.setattr(util, "run_cmd", _fake_run_cmd(calls))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    inside = tmp_path / "Home_SOC" / "data"
    inside.mkdir(parents=True)
    assert paths._restrict_windows_acl(inside) is True
    assert calls == []


@WINDOWS_ONLY
def test_windows_data_dir_hook_skips_foreign_folders(tmp_path: Path, monkeypatch) -> None:
    calls: list[list[str]] = []
    monkeypatch.setattr(util, "run_cmd", _fake_run_cmd(calls))
    monkeypatch.setenv("USERPROFILE", str(tmp_path / "profile"))
    foreign = tmp_path / "foreign"
    foreign.mkdir()
    (foreign / "not-home-soc.txt").write_text("x", encoding="utf-8")
    monkeypatch.setenv(paths.ENV_DATA, str(foreign))
    paths.data_dir()
    assert calls == []
    ours = tmp_path / "fresh-data"
    monkeypatch.setenv(paths.ENV_DATA, str(ours))
    paths.data_dir()  # empty and new: made private
    assert any(c[0].lower().endswith("icacls.exe") and c[1] == str(ours) for c in calls)


# ------------------------------------------------------------------------ terminal escapes


def test_terminal_safe_neutralises_every_control_but_keeps_layout() -> None:
    cleaned = util.terminal_safe(HOSTILE + "\n\tnext line\r\n")
    for control in RAW_CONTROLS:
        assert control not in cleaned
    assert "\\x1b]52;c;" in cleaned and "\\x9b" in cleaned  # visible, so the user sees the attempt
    assert cleaned.endswith("\n\tnext line\n")
    assert util.terminal_safe("Café — 192.168.1.5 ✓") == "Café — 192.168.1.5 ✓"


def test_emit_writes_no_raw_escape_sequences(capsys: pytest.CaptureFixture[str]) -> None:
    cli.emit(HOSTILE)
    out = capsys.readouterr().out
    for control in RAW_CONTROLS:
        assert control not in out
    assert out.endswith("\n") and "model CAM-1234" in out


def test_findings_and_baseline_commands_do_not_pass_device_escapes_to_the_terminal(
    data_dir: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """The review's PoC: a banner-borne title and an mDNS hostname, printed by the CLI."""
    assert cli.main(["init", "--no-feeds"]) == 0
    conn = db.connect()
    now = util.utcnow_iso()
    device_id = db.write(conn, "INSERT INTO devices(mac, ip, hostname, first_seen, last_seen, online)"
                               " VALUES (?,?,?,?,?,1)",
                         ("aa:bb:cc:00:00:77", "192.168.1.77", "cam\x1b]52;c;ZWNobyBwd25lZA==\x07", now, now))
    db.write(conn, "INSERT INTO findings(finding_id, subject, dedupe_key, severity, title, status, source,"
                   " first_seen, last_seen, device_id) VALUES ('NET-SVC-012', 'device:aa:bb:cc:00:00:77', 'k1',"
                   " 'low', ?, 'open', 'services', ?, ?, ?)",
             (f"Device 192.168.1.77 advertises its hardware model on the network ({HOSTILE})", now, now, device_id))
    conn.close()
    capsys.readouterr()
    assert cli.main(["findings"]) == 0
    assert cli.main(["baseline", "--dry-run"]) == 0
    out = capsys.readouterr().out
    assert "NET-SVC-012" in out
    for control in RAW_CONTROLS:
        assert control not in out


def test_log_lines_do_not_carry_device_escapes(data_dir: Path, capsys: pytest.CaptureFixture[str]) -> None:
    cli.setup_logging("INFO")
    logging.getLogger("homesoc.scanners.test").warning("IGD at %s", "http://x/\x1b]0;pwned\x07")
    for handler in logging.getLogger().handlers:
        handler.flush()
    err = capsys.readouterr().err
    assert "IGD at" in err and "\x1b" not in err and "\x07" not in err
    text = (paths.logs_dir() / "homesoc.log").read_text(encoding="utf-8")
    assert "IGD at" in text and "\x1b" not in text and "\x07" not in text


def test_tracebacks_keep_their_line_breaks(data_dir: Path, capsys: pytest.CaptureFixture[str]) -> None:
    cli.setup_logging("INFO")
    try:
        raise RuntimeError("boom")
    except RuntimeError:
        logging.getLogger("homesoc.test").exception("failed")
    err = capsys.readouterr().err
    assert "Traceback (most recent call last):\n" in err and "RuntimeError: boom" in err


def test_lens_pairing_label_drops_c1_controls(memory_conn) -> None:
    """A leaked pairing code's label reaches `lens tokens`; the one-byte C1 CSI must not survive."""
    minted = db.lens_mint_token(memory_conn, label="phone\x9b31m\x1b]0;x\x07")
    assert minted["label"] == "phone31m]0;x"
