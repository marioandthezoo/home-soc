"""Notification channels.

Payload builders are pure functions and the HTTP/PowerShell side is injected (`poster`, `runner`)
so every channel is unit-testable offline. Each attempt is recorded in the `notifications` table
so the dashboard can show that alerts actually went out.
"""
from __future__ import annotations

import base64
import logging
import sqlite3
import subprocess
import sys
import threading
from datetime import datetime, timezone
from typing import Any, Callable, Iterable
from urllib.parse import urlsplit
from xml.sax.saxutils import escape as _xml_escape

logger = logging.getLogger(__name__)

SEVERITY_RANK: dict[str, int] = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
NTFY_PRIORITY: dict[str, int] = {"critical": 5, "high": 4}
DISCORD_COLOR: dict[str, int] = {
    "critical": 0xE5484D, "high": 0xF76B15, "medium": 0xFFB224, "low": 0x46A758, "info": 0x3E63DD,
}
# SPEC-GAP: the spec names app id "Home SOC", but Windows silently discards toasts whose
# AppUserModelID is not registered (no Start-menu shortcut carries it). PowerShell's own AUMID is
# always registered, so toasts raised through it are actually displayed (this is what BurntToast does).
TOAST_APP_ID = "{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\\WindowsPowerShell\\v1.0\\powershell.exe"
HTTP_TIMEOUT = 10
TOAST_TIMEOUT = 20
MAX_BODY_CHARS = 3500          # Discord embed description limit is 4096; keep headroom
MAX_TOAST_CHARS = 200
MAX_LISTED_FINDINGS = 10

# poster(url, *, json=None, data=None, headers=None) -> (ok, error)
Poster = Callable[..., tuple[bool, str | None]]
# runner(argv) -> (ok, error)
Runner = Callable[[list[str]], tuple[bool, str | None]]

try:  # pragma: no cover
    from homesoc.db import write as _write
except ImportError:  # pragma: no cover
    _lock = threading.Lock()

    def _write(conn: sqlite3.Connection, sql: str, params: Iterable[Any] = ()) -> int:
        with _lock:
            cur = conn.execute(sql, tuple(params))
            conn.commit()
            return int(cur.lastrowid or 0)

try:  # pragma: no cover
    from homesoc.util import utcnow_iso as _now
except ImportError:  # pragma: no cover

    def _now() -> str:
        return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


# --- config access ---------------------------------------------------------------------------------
def _cfg(cfg: Any, key: str, default: Any = None) -> Any:
    """Read cfg.notify.<key> from a dataclass or a plain dict so tests can pass a SimpleNamespace."""
    section = getattr(cfg, "notify", None)
    if section is None and isinstance(cfg, dict):
        section = cfg.get("notify")
    if section is None:
        return default
    if isinstance(section, dict):
        return section.get(key, default)
    return getattr(section, key, default)


def _rank(severity: str | None) -> int:
    return SEVERITY_RANK.get(str(severity or "info").lower(), 0)


def _max_severity(findings: list[dict]) -> str:
    best = "info"
    for f in findings:
        if _rank(f.get("severity")) > _rank(best):
            best = str(f.get("severity"))
    return best


def _truncate(text: str, limit: int) -> str:
    return text if len(text) <= limit else text[: limit - 1] + "…"


# --- payload builders (pure) ----------------------------------------------------------------------
def format_findings_body(findings: list[dict]) -> str:
    lines = []
    for f in findings[:MAX_LISTED_FINDINGS]:
        lines.append(f"[{str(f.get('severity', 'info')).upper()}] {f.get('title', f.get('finding_id', '?'))}  ({f.get('subject', '')})")
    if len(findings) > MAX_LISTED_FINDINGS:
        lines.append(f"... and {len(findings) - MAX_LISTED_FINDINGS} more")
    return "\n".join(lines)


def _slim(findings: list[dict] | None) -> list[dict]:
    """Only the fields a receiver needs; keeps webhook payloads small and free of remediation prose."""
    keys = ("id", "finding_id", "subject", "severity", "title", "status", "first_seen", "last_seen", "occurrences")
    return [{k: f.get(k) for k in keys if k in f} for f in (findings or [])]


def build_ntfy(subject: str, body: str, severity: str) -> dict:
    sev = str(severity).lower()
    tags = {"critical": "rotating_light", "high": "warning", "medium": "mag", "low": "information_source"}.get(sev, "shield")
    return {
        "data": _truncate(body, MAX_BODY_CHARS).encode("utf-8"),
        "headers": {
            "Title": _truncate(subject.encode("ascii", "replace").decode("ascii"), 250),
            "Priority": str(NTFY_PRIORITY.get(sev, 3)),
            "Tags": f"{tags},homesoc",
        },
    }


def build_discord(subject: str, body: str, severity: str, findings: list[dict] | None = None) -> dict:
    sev = str(severity).lower()
    return {
        "content": _truncate(f"**{subject}**", 1900),
        "embeds": [
            {
                "title": _truncate(f"{sev.upper()} - {len(findings or [])} finding(s)" if findings else sev.upper(), 250),
                "description": _truncate(body, MAX_BODY_CHARS),
                "color": DISCORD_COLOR.get(sev, DISCORD_COLOR["info"]),
            }
        ],
    }


def build_webhook(subject: str, body: str, severity: str, findings: list[dict] | None = None) -> dict:
    return {
        "subject": subject,
        "body": body,
        "severity": str(severity).lower(),
        "findings": _slim(findings),
        "source": "homesoc",
        "ts": _now(),
    }


def build_toast_xml(subject: str, body: str) -> str:
    """Toast XML with every user-controlled string escaped; finding titles carry device names and banners."""
    title = _xml_escape(_truncate(subject, 100), {'"': "&quot;", "'": "&apos;"})
    text = _xml_escape(_truncate(body, MAX_TOAST_CHARS), {'"': "&quot;", "'": "&apos;"})
    return (
        '<toast><visual><binding template="ToastGeneric">'
        f"<text>{title}</text><text>{text}</text>"
        "</binding></visual></toast>"
    )


def build_toast_script(subject: str, body: str) -> str:
    """PowerShell (5.1, WinRT-capable) that shows a toast without any module installed.

    ``$ErrorActionPreference = 'Stop'`` matters: without it a WinRT failure is a non-terminating
    error, powershell.exe still exits 0 and Home SOC records the notification as sent while the
    user saw nothing. With it, the runner sees exit 1 plus the message on stderr.
    """
    xml = build_toast_xml(subject, body)
    # After XML escaping no single quote remains, so a single-quoted PS literal is injection-safe;
    # doubling is kept as belt-and-braces.
    xml_ps = xml.replace("'", "''")
    app_id = TOAST_APP_ID.replace("'", "''")
    return (
        "$ErrorActionPreference = 'Stop'; "
        "[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType=WindowsRuntime] | Out-Null; "
        "[Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom.XmlDocument, ContentType=WindowsRuntime] | Out-Null; "
        "$x = New-Object Windows.Data.Xml.Dom.XmlDocument; "
        f"$x.LoadXml('{xml_ps}'); "
        "$t = [Windows.UI.Notifications.ToastNotification]::new($x); "
        f"[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier('{app_id}').Show($t); "
        "exit 0"
    )


def build_toast_argv(subject: str, body: str) -> list[str]:
    """-EncodedCommand sidesteps every cmd/PowerShell quoting rule; the script is UTF-16LE base64."""
    encoded = base64.b64encode(build_toast_script(subject, body).encode("utf-16-le")).decode("ascii")
    return ["powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-EncodedCommand", encoded]


# --- transports ------------------------------------------------------------------------------------
def _default_poster(url: str, *, json: Any = None, data: Any = None, headers: dict | None = None) -> tuple[bool, str | None]:
    try:
        import requests
    except ImportError:  # pragma: no cover
        return False, "requests not installed"
    try:
        resp = requests.post(url, json=json, data=data, headers=headers, timeout=HTTP_TIMEOUT)
    except requests.RequestException as exc:
        # Never str(exc): requests embeds the full URL (Discord token, ntfy secret topic) in
        # connection errors, and this string ends up in homesoc.log and the notifications table.
        return False, f"{type(exc).__name__} talking to {_safe_host(url)}"
    if 200 <= resp.status_code < 300:
        return True, None
    return False, f"HTTP {resp.status_code}: {_scrub(resp.text[:200], url)}"


def _safe_host(url: str) -> str:
    try:
        return urlsplit(url).hostname or "webhook"
    except ValueError:
        return "webhook"


def _scrub(text: str, url: str) -> str:
    """Remove the webhook URL (and its path, which is the secret) from any text we keep."""
    try:
        parts = urlsplit(url)
    except ValueError:
        return text
    for secret in (url, parts.path):
        if secret and len(secret) > 3:
            text = text.replace(secret, "***")
    return text


def _default_runner(argv: list[str]) -> tuple[bool, str | None]:
    try:
        proc = subprocess.run(argv, capture_output=True, text=True, timeout=TOAST_TIMEOUT, check=False)
    except (OSError, subprocess.SubprocessError) as exc:
        return False, f"{type(exc).__name__}: {exc}"[:500]
    if proc.returncode == 0:
        return True, None
    return False, (proc.stderr or proc.stdout or f"exit {proc.returncode}").strip()[:500]


def _record(conn: sqlite3.Connection | None, channel: str, subject: str, ok: bool, error: str | None) -> None:
    if conn is None:
        return
    try:
        _write(
            conn,
            "INSERT INTO notifications(ts, channel, subject, status, error) VALUES (?,?,?,?,?)",
            (_now(), channel, subject[:200], "sent" if ok else "error", error),
        )
    except sqlite3.Error as exc:  # table missing before P1 init; never let bookkeeping block an alert
        logger.debug("could not record notification: %s", exc)


def configured_channels(cfg: Any) -> dict[str, bool]:
    return {
        "ntfy": bool(_cfg(cfg, "ntfy_url", "")),
        "discord": bool(_cfg(cfg, "discord_webhook", "")),
        "webhook": bool(_cfg(cfg, "webhook_url", "")),
        "toast": bool(_cfg(cfg, "windows_toast", True)) and sys.platform == "win32",
    }


def send(
    cfg: Any,
    conn: sqlite3.Connection | None,
    subject: str,
    body: str,
    *,
    severity: str = "info",
    findings: list[dict] | None = None,
    poster: Poster | None = None,
    runner: Runner | None = None,
) -> dict[str, bool]:
    """Deliver to every configured channel; a failing channel never stops the others."""
    post = poster or _default_poster
    run = runner or _default_runner
    results: dict[str, bool] = {}
    enabled = configured_channels(cfg)

    if enabled["ntfy"]:
        payload = build_ntfy(subject, body, severity)
        ok, err = post(str(_cfg(cfg, "ntfy_url")), data=payload["data"], headers=payload["headers"])
        results["ntfy"] = _finish(conn, "ntfy", subject, ok, err)
    if enabled["discord"]:
        ok, err = post(str(_cfg(cfg, "discord_webhook")), json=build_discord(subject, body, severity, findings))
        results["discord"] = _finish(conn, "discord", subject, ok, err)
    if enabled["webhook"]:
        ok, err = post(str(_cfg(cfg, "webhook_url")), json=build_webhook(subject, body, severity, findings))
        results["webhook"] = _finish(conn, "webhook", subject, ok, err)
    if enabled["toast"]:
        ok, err = run(build_toast_argv(subject, body))
        results["toast"] = _finish(conn, "toast", subject, ok, err)
    return results


def _finish(conn, channel: str, subject: str, ok: bool, err: str | None) -> bool:
    if ok:
        logger.info("notification sent via %s: %s", channel, subject)
    else:
        logger.warning("notification via %s failed: %s", channel, err)
    _record(conn, channel, subject, ok, err)
    return bool(ok)


def filter_by_min_severity(cfg: Any, findings: list[dict]) -> list[dict]:
    threshold = _rank(_cfg(cfg, "min_severity", "high"))
    return [f for f in findings if _rank(f.get("severity")) >= threshold]


def notify_new_findings(
    cfg: Any,
    conn: sqlite3.Connection | None,
    new: list[dict],
    *,
    poster: Poster | None = None,
    runner: Runner | None = None,
) -> dict[str, bool]:
    """One batched message per scan so a noisy first run does not produce fifty toasts."""
    selected = filter_by_min_severity(cfg, new or [])
    if not selected:
        return {}
    selected.sort(key=lambda f: -_rank(f.get("severity")))
    severity = _max_severity(selected)
    subject = f"Home SOC: {len(selected)} new {severity} finding" + ("s" if len(selected) != 1 else "")
    body = format_findings_body(selected)
    return send(cfg, conn, subject, body, severity=severity, findings=selected, poster=poster, runner=runner)


def test_channels(cfg: Any, conn: sqlite3.Connection | None, *, poster: Poster | None = None, runner: Runner | None = None) -> dict[str, bool]:
    return send(
        cfg, conn, "Home SOC test notification",
        "If you can read this, notifications are working.", severity="info", poster=poster, runner=runner,
    )


# --- daily digest ----------------------------------------------------------------------------------
def build_digest(conn: sqlite3.Connection) -> tuple[str, str, list[dict]]:
    """(subject, body, top findings): open counts by severity plus the five worst open findings."""
    from homesoc.findings import engine, score

    c = engine.counts(conn).get("open", {})
    total = sum(c.values())
    s = score.security_score(conn)
    top = engine.list_findings(conn, status="open", limit=5)
    subject = f"Home SOC daily digest: score {s} ({score.grade(s)}), {total} open finding" + ("s" if total != 1 else "")
    parts = [
        f"Score {s}/100 grade {score.grade(s)}",
        "Open: " + ", ".join(f"{sev} {c.get(sev, 0)}" for sev in ("critical", "high", "medium", "low", "info")),
    ]
    if top:
        parts.append("Top open findings:")
        parts.append(format_findings_body(top))
    else:
        parts.append("No open findings. Nice.")
    return subject, "\n".join(parts), top


def send_digest(cfg: Any, conn: sqlite3.Connection, *, poster: Poster | None = None, runner: Runner | None = None) -> dict[str, bool]:
    """Scheduler 'digest' job body; the scheduler decides *when* (digest_hour), this decides *what*."""
    if int(_cfg(cfg, "digest_hour", 8)) < 0:
        return {}
    subject, body, top = build_digest(conn)
    severity = _max_severity(top) if top else "info"
    return send(cfg, conn, subject, body, severity=severity, findings=top, poster=poster, runner=runner)
