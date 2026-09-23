"""Notification channels.

Payload builders are pure functions and the HTTP/PowerShell side is injected (`poster`, `runner`)
so every channel is unit-testable offline. Each attempt is recorded in the `notifications` table
so the dashboard can show that alerts actually went out.
"""
from __future__ import annotations

import base64
import logging
import re
import sqlite3
import subprocess
import sys
import threading
from datetime import datetime, timezone
from typing import Any, Callable, Iterable
from urllib.parse import urlsplit
from xml.sax.saxutils import escape as _xml_escape

from homesoc.util import INVISIBLE_TEXT, UNSAFE_TEXT

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
HTTP_WALL_CLOCK = 30
HTTP_MAX_ERROR_BODY = 4096
# Size budgets are in the unit each service actually counts, never in Python characters: a device
# chooses the text, and a 4-byte emoji is one character but four bytes. ntfy rejects (or turns into
# an "attachment.txt") any message over its 4096-byte limit; Discord caps an embed description at
# 4096 characters as counted by JavaScript, i.e. UTF-16 code units. Both leave headroom.
NTFY_MAX_BODY_BYTES = 3900
DISCORD_MAX_DESCRIPTION_UNITS = 4000
# The finding lines of one message share the ntfy budget minus this reserve (the digest header, the
# "... and N more" line, newlines). Each line gets an equal share in UTF-8 bytes (at least 370 with
# ten lines), so a few device-chosen titles full of emoji can neither push the rest of the batch
# out of the message nor, together, exceed the limit; a single finding keeps nearly the whole budget.
BODY_RESERVE_BYTES = 200
MAX_TOAST_CHARS = 200
MAX_LISTED_FINDINGS = 10
# Finding titles and subjects carry LAN-controlled text (hostnames, banners, the description a device
# gives its UPnP port mapping). A CR/LF in it would forge an extra "[CRITICAL] ..." line in the alert,
# so each is flattened to one line here even for rows stored before the catalog started doing so.
# Replaced by a space: C0/C1 controls, U+2028/2029, lone surrogates and the whole Unicode
# Bidi_Control set (including U+061C). Removed outright: every other Default_Ignorable_Code_Point.
# Both classes live in homesoc.util (safe_one_line) so device_text, these channels and the
# topology labels strip exactly the same set.
_UNSAFE_TEXT = UNSAFE_TEXT
_INVISIBLE_TEXT = INVISIBLE_TEXT
# Discord renders embed descriptions as Markdown: masked links [text](url), autolinks, <url>,
# mentions, spoilers. Every such metacharacter is backslash-escaped (Discord drops the backslash and
# shows the character) so device-chosen text can never become a disguised or clickable link.
_DISCORD_MARKDOWN = re.compile(r"([\\*_~`|<>\[\]()@:#])")
MAX_LINE_CHARS = 400

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


def _truncate_encoded(text: str, limit: int, encoding: str) -> str:
    """``text`` cut so its ``encoding`` form is at most ``limit`` bytes, on a code-point boundary.

    ``utf-8`` budgets ntfy's byte limit; ``utf-16-le`` (2 bytes per unit) budgets JavaScript's
    string length, which is what Discord counts. The ellipsis marking the cut is included.
    """
    raw = text.encode(encoding, "replace")
    if len(raw) <= limit:
        return text
    tail = "…".encode(encoding)
    cut = max(0, limit - len(tail))
    if encoding.startswith("utf-16"):
        cut -= cut % 2
    # "ignore" drops a code point split by the cut (a partial UTF-8 sequence, or the high half of
    # a UTF-16 surrogate pair) instead of producing mojibake.
    return raw[:cut].decode(encoding, "ignore") + "…"


def _one_line(value: Any, limit: int = MAX_LINE_CHARS) -> str:
    """One printable line: control, line-separator and bidi characters become spaces, and
    invisible (default-ignorable) characters are removed."""
    flat = _INVISIBLE_TEXT.sub("", _UNSAFE_TEXT.sub(" ", str(value)))
    return _truncate(flat, limit)


def escape_discord_markdown(text: str) -> str:
    return _DISCORD_MARKDOWN.sub(r"\\\1", text)


# --- payload builders (pure) ----------------------------------------------------------------------
def format_findings_body(findings: list[dict]) -> str:
    lines = []
    listed = findings[:MAX_LISTED_FINDINGS]
    line_budget = (NTFY_MAX_BODY_BYTES - BODY_RESERVE_BYTES) // max(1, len(listed))
    for f in listed:
        severity = _one_line(f.get("severity", "info"), 20).upper()
        title = _one_line(f.get("title", f.get("finding_id", "?")))
        line = f"[{severity}] {title}  ({_one_line(f.get('subject', ''), 200)})"
        lines.append(_truncate_encoded(line, line_budget, "utf-8"))
    if len(findings) > MAX_LISTED_FINDINGS:
        lines.append(f"... and {len(findings) - MAX_LISTED_FINDINGS} more")
    return "\n".join(lines)


def _slim(findings: list[dict] | None) -> list[dict]:
    """Only the fields a receiver needs; keeps webhook payloads small and free of remediation prose."""
    keys = ("id", "finding_id", "subject", "severity", "title", "status", "first_seen", "last_seen", "occurrences")
    return [
        {k: (_one_line(f[k]) if k in ("title", "subject") and isinstance(f[k], str) else f.get(k)) for k in keys if k in f}
        for f in (findings or [])
    ]


def build_ntfy(subject: str, body: str, severity: str) -> dict:
    sev = str(severity).lower()
    tags = {"critical": "rotating_light", "high": "warning", "medium": "mag", "low": "information_source"}.get(sev, "shield")
    return {
        "data": _truncate_encoded(body, NTFY_MAX_BODY_BYTES, "utf-8").encode("utf-8", "replace"),
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
                "description": _truncate_encoded(
                    escape_discord_markdown(body), 2 * DISCORD_MAX_DESCRIPTION_UNITS, "utf-16-le",
                ),
                "color": DISCORD_COLOR.get(sev, DISCORD_COLOR["info"]),
            }
        ],
        # Nothing in an alert may ping @everyone/@here, a role or a user.
        "allowed_mentions": {"parse": []},
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


#: Characters outside the XML 1.0 ``Char`` production. Escaping cannot represent them, so a
#: hostname carrying one (say ``cam\x0b``) would make LoadXml throw and the toast never appear.
_XML_INVALID = re.compile("[\x00-\x08\x0b\x0c\x0e-\x1f\ud800-\udfff\ufffe\uffff]")


def _xml_chars(value: str) -> str:
    return _XML_INVALID.sub("", value)


def build_toast_xml(subject: str, body: str) -> str:
    """Toast XML with every user-controlled string escaped; finding titles carry device names and banners."""
    title = _xml_escape(_xml_chars(_truncate(subject, 100)), {'"': "&quot;", "'": "&apos;"})
    text = _xml_escape(_xml_chars(_truncate(body, MAX_TOAST_CHARS)), {'"': "&quot;", "'": "&apos;"})
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
    # No alert text is ever spliced into the script as a string literal. PowerShell also ends a
    # single-quoted literal at U+2018..U+201B (typographic quotes), which XML escaping leaves
    # alone, so a device-chosen name such as a UPnP mapping description could close the literal
    # and run code as the owner. The XML travels as base64 (alphabet A-Z a-z 0-9 + / =, no quote
    # character of any kind) and is decoded inside PowerShell; every other part of the script
    # is a constant.
    xml_b64 = base64.b64encode(build_toast_xml(subject, body).encode("utf-8")).decode("ascii")
    return (
        "$ErrorActionPreference = 'Stop'; "
        "[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType=WindowsRuntime] | Out-Null; "
        "[Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom.XmlDocument, ContentType=WindowsRuntime] | Out-Null; "
        "$x = New-Object Windows.Data.Xml.Dom.XmlDocument; "
        f"$x.LoadXml([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('{xml_b64}'))); "
        "$t = [Windows.UI.Notifications.ToastNotification]::new($x); "
        f"[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier('{TOAST_APP_ID}').Show($t); "
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
    from homesoc.feeds.netguard import Watch

    # requests' timeout is per recv, so a server that drips its reply a byte at a time would hold
    # the scheduler thread; the watch shuts the connection down after HTTP_WALL_CLOCK seconds.
    # Only the first HTTP_MAX_ERROR_BODY bytes of an error reply are read, never the whole body.
    try:
        with Watch(lambda: HTTP_WALL_CLOCK, "notification"):
            resp = requests.post(url, json=json, data=data, headers=headers, timeout=HTTP_TIMEOUT, stream=True)
            try:
                if 200 <= resp.status_code < 300:
                    return True, None
                text = _read_error_body(resp)
            finally:
                close = getattr(resp, "close", None)
                if callable(close):
                    close()
    except (requests.RequestException, OSError) as exc:
        # Never str(exc): requests embeds the full URL (Discord token, ntfy secret topic) in
        # connection errors, and this string ends up in homesoc.log and the notifications table.
        return False, f"{type(exc).__name__} talking to {_safe_host(url)}"
    return False, f"HTTP {resp.status_code}: {_scrub(text[:200], url)}"


def _read_error_body(resp: Any) -> str:
    """At most HTTP_MAX_ERROR_BODY bytes of a streamed error reply, decoded leniently."""
    raw = getattr(resp, "raw", None)
    if raw is None or not callable(getattr(raw, "read", None)):
        return str(getattr(resp, "text", "") or "")[:HTTP_MAX_ERROR_BODY]
    data = raw.read(HTTP_MAX_ERROR_BODY, decode_content=True) or b""
    return data.decode(getattr(resp, "encoding", None) or "utf-8", "replace")


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
