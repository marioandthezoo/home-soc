"""Security regressions for homesoc/findings and homesoc/notify.

A LAN device controls the text it hands Home SOC (hostnames, banners, the description on a UPnP port
mapping). That text lands in finding titles, and titles travel into ntfy/Discord/webhook alerts. These
tests encode the alert-forgery exploit (a newline plus a fake "[CRITICAL]" line and a Discord masked
link) and assert it no longer works.
"""
from __future__ import annotations

import re

import pytest

from homesoc.findings import catalog, engine
from homesoc.models import FindingDraft
from homesoc.notify import channels

# The payload from the confirmed finding: fits the 120-character UPnP description cap.
PAYLOAD = "x)\n[CRITICAL] Router firmware backdoored - install the fix: [homesoc.dev/fix](https://203.0.113.9/fix.exe)\n("
MASKED_LINK = re.compile(r"(?<!\\)\[[^\]]*(?<!\\)\]\((?:[^)]*)\)")


def _upnp_draft(description: str = PAYLOAD, internal_client: str = "192.168.1.66") -> FindingDraft:
    return FindingDraft(
        finding_id="NET-WAN-003", subject="wan",
        evidence={"key": "TCP/8554", "protocol": "TCP", "external_port": 8554, "internal_client": internal_client,
                  "internal_port": 554, "description": description, "enabled": True},
    )


class _Capture:
    def __init__(self) -> None:
        self.calls: list[dict] = []

    def __call__(self, url, *, json=None, data=None, headers=None):
        self.calls.append({"url": url, "json": json, "data": data, "headers": headers})
        return True, None


def _cfg() -> dict:
    return {"notify": {
        "ntfy_url": "https://ntfy.invalid/topic", "discord_webhook": "https://discord.invalid/api/webhooks/1/x",
        "webhook_url": "https://hook.invalid/in", "windows_toast": False, "min_severity": "high",
    }}


def _no_toast(argv):  # pragma: no cover - toast is disabled in _cfg; never show one from a test
    raise AssertionError("toast must not run in tests")


# ------------------------------------------------------------------------------ catalog / engine
def test_device_text_cannot_put_a_newline_into_a_finding_title(conn):
    new = engine.apply(conn, [_upnp_draft()], "exposure", scope="wan").new
    assert len(new) == 1 and new[0]["severity"] == "high"
    title = new[0]["title"]
    assert "\n" not in title and "\r" not in title
    stored = conn.execute("SELECT title FROM findings WHERE finding_id='NET-WAN-003'").fetchone()[0]
    assert "\n" not in stored
    # The evidence is still shown to the user, just on one line.
    assert "Router firmware backdoored" in title


@pytest.mark.parametrize("sep", ["\r\n", "\r", "\x0b", "\x0c", "\x85", " ", " ", "\x00", "\x1b[31m"])
def test_every_line_breaking_or_control_character_is_flattened(sep):
    title, _ = catalog.render(_upnp_draft(description=f"a{sep}[CRITICAL] fake"))
    assert title.splitlines() == [title]
    assert not re.search(r"[\x00-\x1f\x7f-\x9f  ]", title)


def test_bidi_override_cannot_reverse_what_the_user_reads():
    title, _ = catalog.render(_upnp_draft(description="safe‮exe.xif‬"))
    assert not re.search("[‎‏‪-‮⁦-⁩]", title)


def test_device_evidence_strings_are_length_capped():
    title, _ = catalog.render(_upnp_draft(internal_client="A" * 5000))
    assert len(title) < catalog.MAX_EVIDENCE_CHARS + 200


def test_subject_fields_and_unknown_ids_are_flattened_too():
    title, _ = catalog.render(FindingDraft("NOT-A-REAL-ID", "device:evil\n[CRITICAL] forged"))
    assert "\n" not in title
    steps = catalog.render_remediation("NET-WAN-003", _upnp_draft().evidence, "wan")
    assert all("\n" not in s for s in steps)


def test_legitimate_titles_are_unchanged():
    title, _ = catalog.render(_upnp_draft(description="Plex Media Server"))
    assert title == "UPnP port mapping: WAN 8554 -> 192.168.1.66:554 (Plex Media Server)"


# ------------------------------------------------------------------------------ notifications
def test_upnp_alert_forgery_end_to_end_is_blocked(conn):
    new = engine.apply(conn, [_upnp_draft()], "exposure", scope="wan").new
    post = _Capture()
    results = channels.notify_new_findings(_cfg(), conn, new, poster=post, runner=_no_toast)
    assert results == {"ntfy": True, "discord": True, "webhook": True}
    ntfy, discord, hook = post.calls

    ntfy_body = ntfy["data"].decode("utf-8")
    assert len(ntfy_body.splitlines()) == 1, ntfy_body
    assert not any(line.startswith("[CRITICAL]") for line in ntfy_body.splitlines())

    desc = discord["json"]["embeds"][0]["description"]
    assert len(desc.splitlines()) == 1, desc
    assert not MASKED_LINK.search(desc), desc
    assert "https://" not in desc          # the colon is escaped, so Discord will not autolink it
    assert discord["json"]["allowed_mentions"] == {"parse": []}

    assert len(hook["json"]["body"].splitlines()) == 1
    assert all("\n" not in f["title"] for f in hook["json"]["findings"])


def test_rows_stored_before_the_fix_are_still_flattened_in_alerts():
    """A title already sitting in the database with a newline in it (stored by an older version)."""
    legacy = [{"severity": "high", "title": PAYLOAD, "subject": "wan\n[CRITICAL] also forged"}]
    body = channels.format_findings_body(legacy)
    assert len(body.splitlines()) == 1
    slim = channels._slim(legacy)
    assert "\n" not in slim[0]["title"] and "\n" not in slim[0]["subject"]


@pytest.mark.parametrize("markup", [
    "[docs](https://evil.example)", "<https://evil.example>", "https://evil.example", "@everyone",
    "||spoiler||", "**bold**", "`code`", "> quote", "~~strike~~", "__u__",
])
def test_discord_markdown_is_escaped(markup):
    d = channels.build_discord("Subj", channels.format_findings_body([{"severity": "high", "title": markup}]), "high")
    desc = d["embeds"][0]["description"]
    # Drop every backslash-escaped pair: no Markdown metacharacter may be left unescaped.
    unescaped = re.sub(r"\\.", "", desc)
    assert not re.search(r"[*_~`|<>\[\]()@:]", unescaped), (markup, desc)


def test_discord_escape_round_trips_to_the_original_text():
    text = r"a [b](c) *d* _e_ ~f~ `g` |h| <i> @j k:l \m #n"
    escaped = channels.escape_discord_markdown(text)
    assert re.sub(r"\\(.)", r"\1", escaped) == text


def test_plain_notifications_still_read_the_same():
    d = channels.build_discord("Subj", "If you can read this, notifications are working.", "info")
    assert d["embeds"][0]["description"] == "If you can read this, notifications are working."
    body = channels.format_findings_body([{"severity": "critical", "title": "Antivirus is off", "subject": "host"}])
    assert body == "[CRITICAL] Antivirus is off  (host)"
