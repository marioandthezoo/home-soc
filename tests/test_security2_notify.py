"""Second security round: regressions for homesoc/notify.

1. ntfy's message limit is 4096 *bytes*. The body used to be capped at 3500 *characters*, so a LAN
   device that opened UPnP port mappings with emoji descriptions pushed the high-severity alert
   about its own mappings past the limit (ntfy then drops it, or replaces it with an attachment).
2. The alert sanitizer missed U+061C ARABIC LETTER MARK (the last Bidi_Control character) and every
   zero-width / default-ignorable character, so a device name could carry invisible reordering or
   padding into Discord, ntfy, the webhook and the toast.
"""
from __future__ import annotations

import re
import unicodedata

import pytest

from homesoc.findings import catalog
from homesoc.models import FindingDraft
from homesoc.notify import channels

NTFY_LIMIT_BYTES = 4096
DISCORD_LIMIT_UNITS = 4096


class _Capture:
    def __init__(self) -> None:
        self.calls: list[dict] = []

    def __call__(self, url, *, json=None, data=None, headers=None):
        self.calls.append({"url": url, "json": json, "data": data, "headers": headers})
        return True, None


def _no_toast(argv):  # pragma: no cover - toast is disabled in the config; never show one
    raise AssertionError("toast must not run in tests")


def _cfg(**extra) -> dict:
    notify = {"ntfy_url": "https://ntfy.invalid/topic", "min_severity": "high", "windows_toast": False}
    notify.update(extra)
    return {"notify": notify}


def _mapping(i: int, description: str) -> dict:
    draft = FindingDraft(
        finding_id="NET-WAN-003", subject="wan",
        evidence={"key": f"TCP/{8000 + i}", "protocol": "TCP", "external_port": 8000 + i,
                  "internal_client": "192.168.1.66", "internal_port": 554,
                  "description": description, "enabled": True},
    )
    title = catalog.render(draft)[0]
    severity = catalog.severity_for(draft)
    return {"finding_id": "NET-WAN-003", "subject": "wan", "severity": severity, "title": title}


def _utf16_units(text: str) -> int:
    return len(text.encode("utf-16-le")) // 2


# ------------------------------------------------------------------ 1. byte budget, not characters
def test_emoji_upnp_descriptions_cannot_push_the_ntfy_body_past_its_byte_limit():
    """The exploit: ten mappings whose 120-character description is all 4-byte emoji (5439 bytes)."""
    new = [_mapping(i, "\U0001F6A8" * 120) for i in range(10)]
    post = _Capture()
    results = channels.notify_new_findings(_cfg(), None, new, poster=post, runner=_no_toast)
    assert results == {"ntfy": True}
    data = post.calls[0]["data"]
    assert len(data) <= channels.NTFY_MAX_BODY_BYTES < NTFY_LIMIT_BYTES, len(data)
    body = data.decode("utf-8")   # still valid UTF-8 after the cut
    lines = body.splitlines()
    # Every one of the ten alerts is still present, each naming its own port.
    assert len(lines) == 10
    for i, line in enumerate(lines):
        assert line.startswith("[HIGH] UPnP port mapping: WAN "), line
        assert f"WAN {8000 + i} -> 192.168.1.66:554" in line


@pytest.mark.parametrize("char", ["\U0001F6A8", "漢", "é", "\U0001F468‍\U0001F469"])
def test_no_batch_of_device_text_exceeds_ntfy_or_discord_limits(char):
    new = [_mapping(i, char * 400) for i in range(25)]
    body = channels.format_findings_body(new)
    ntfy = channels.build_ntfy("Home SOC: 25 new high findings", body, "high")
    assert len(ntfy["data"]) <= channels.NTFY_MAX_BODY_BYTES
    assert "... and 15 more" in ntfy["data"].decode("utf-8")
    desc = channels.build_discord("s", body, "high", new)["embeds"][0]["description"]
    assert _utf16_units(desc) <= channels.DISCORD_MAX_DESCRIPTION_UNITS < DISCORD_LIMIT_UNITS
    desc.encode("utf-8")          # no lone surrogate left by the cut


def test_discord_description_is_budgeted_in_utf16_units_after_markdown_escaping():
    # Markdown escaping doubles every metacharacter; astral characters count two units each.
    body = ("[\U0001F6A8](:)" * 2000)
    desc = channels.build_discord("s", body, "high")["embeds"][0]["description"]
    assert _utf16_units(desc) <= channels.DISCORD_MAX_DESCRIPTION_UNITS
    assert desc.endswith("…")
    desc.encode("utf-8")


def test_digest_style_body_with_header_lines_still_fits():
    top = [_mapping(i, "\U0001F6A8" * 120) for i in range(5)]
    body = "Score 40/100 grade F\nOpen: critical 0, high 5, medium 0, low 0, info 0\nTop open findings:\n"
    body += channels.format_findings_body(top)
    data = channels.build_ntfy("digest", body, "high")["data"]
    assert len(data) <= channels.NTFY_MAX_BODY_BYTES
    assert data.decode("utf-8").count("[HIGH]") == 5


def test_truncate_encoded_cuts_on_code_point_boundaries():
    for enc, limit in (("utf-8", 10), ("utf-8", 11), ("utf-16-le", 10), ("utf-16-le", 11)):
        out = channels._truncate_encoded("\U0001F6A8" * 10, limit, enc)
        assert len(out.encode(enc)) <= limit
        assert out.endswith("…")
        assert set(out[:-1]) <= {"\U0001F6A8"}
    assert channels._truncate_encoded("short", 100, "utf-8") == "short"


def test_short_and_ascii_alerts_are_unchanged():
    one = [{"severity": "critical", "title": "Antivirus is off", "subject": "host"}]
    assert channels.format_findings_body(one) == "[CRITICAL] Antivirus is off  (host)"
    assert channels.build_ntfy("t", "hello", "high")["data"] == b"hello"
    plex = _mapping(0, "Plex Media Server")
    assert channels.format_findings_body([plex]) == (
        "[HIGH] UPnP port mapping: WAN 8000 -> 192.168.1.66:554 (Plex Media Server)  (wan)"
    )
    # A single long ASCII finding is not cut to a tenth of the budget.
    long = [{"severity": "high", "title": "T" * 390, "subject": "s"}]
    assert "…" not in channels.format_findings_body(long)


def test_lone_surrogate_in_a_stored_title_does_not_abort_delivery():
    new = [{"severity": "high", "title": "cam\ud800x", "subject": "wan"}]
    post = _Capture()
    cfg = _cfg(discord_webhook="https://discord.invalid/api/webhooks/1/x")
    assert channels.notify_new_findings(cfg, None, new, poster=post, runner=_no_toast) == {
        "ntfy": True, "discord": True,
    }
    assert b"cam x" in post.calls[0]["data"]


# ------------------------------------------------------------------ 2. complete invisible-char set
BIDI_CONTROL = ["؜", "‎", "‏", "‪", "‫", "‬", "‭", "‮",
                "⁦", "⁧", "⁨", "⁩"]
INVISIBLE = ["­", "͏", "ᅟ", "ᅠ", "឴", "᠋", "᠎", "​",
             "‌", "‍", "⁠", "⁤", "ㅤ", "️", "﻿", "ﾠ",
             "\U000e0041", "\U000e0100"]


@pytest.mark.parametrize("ch", BIDI_CONTROL, ids=lambda c: f"U+{ord(c):04X}")
def test_every_bidi_control_is_removed_from_alerts(ch):
    assert unicodedata.bidirectional(ch) in {"AL", "L", "R", "LRE", "RLE", "PDF", "LRO", "RLO",
                                             "LRI", "RLI", "FSI", "PDI"}
    line = channels.format_findings_body([{"severity": "high", "title": f"cam{ch}01 at 192.168.1.9", "subject": "x"}])
    assert ch not in line
    assert "cam 01 at 192.168.1.9" in line


@pytest.mark.parametrize("ch", INVISIBLE, ids=lambda c: f"U+{ord(c):04X}")
def test_every_default_ignorable_character_is_removed_from_alerts(ch):
    item = {"severity": "high", "title": f"cam{ch}01", "subject": f"dev{ch}ice"}
    assert channels.format_findings_body([item]) == "[HIGH] cam01  (device)"
    slim = channels._slim([item])[0]
    assert slim["title"] == "cam01" and slim["subject"] == "device"


def test_alm_padded_name_reaches_no_channel_end_to_end():
    new = [_mapping(0, "front؜door​ㅤ﻿")]
    post = _Capture()
    cfg = _cfg(discord_webhook="https://discord.invalid/api/webhooks/1/x", webhook_url="https://hook.invalid/in")
    channels.notify_new_findings(cfg, None, new, poster=post, runner=_no_toast)
    bad = re.compile("[؜​ㅤ﻿]")
    ntfy, discord, hook = post.calls
    assert not bad.search(ntfy["data"].decode("utf-8"))
    assert not bad.search(discord["json"]["embeds"][0]["description"])
    assert not bad.search(hook["json"]["body"])
    assert not bad.search(hook["json"]["findings"][0]["title"])
    toast_xml = channels.build_toast_xml("s", channels.format_findings_body(new))
    assert not bad.search(toast_xml)


def test_legitimate_unicode_names_survive():
    for name in ("Café TV", "漢字カメラ", "مطبخ", "Kid's \U0001F3AE box"):
        item = {"severity": "high", "title": name, "subject": "x"}
        assert channels.format_findings_body([item]) == f"[HIGH] {name}  (x)"
