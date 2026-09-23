"""Security round three, docs: the token wording matches what cli.enforce_bind_policy() does.

Finding (deferred #14, low): README said to "keep a non-empty [web] token (Home SOC raises
SOC-SYS-003 if you don't)". Since round two an empty token on a non-loopback bind makes Home SOC
generate, store and print one, and a token under 16 characters makes it refuse to start. README
also offered a login-free dashboard without saying that any local program can then change every
setting, including where the dashboard listens.
"""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
README = ROOT / "README.md"
SECURITY = ROOT / "SECURITY.md"
WALKTHROUGH = ROOT / "docs" / "WALKTHROUGH.md"
LENS_SETUP = ROOT / "docs" / "LENS_SETUP.md"


def _flat(path: Path) -> str:
    """The file's text with line breaks folded into single spaces, for wrap-independent matching."""
    return re.sub(r"\s+", " ", path.read_text(encoding="utf-8"))


def test_readme_no_longer_says_empty_token_only_raises_a_finding():
    text = _flat(README)
    assert "raises `SOC-SYS-003` if you don't" not in text
    assert "keep a non-empty" not in text


def test_readme_describes_generated_and_refused_tokens():
    text = _flat(README)
    start = text.index('id="the-dashboard-from-my-phone-or-another-pc"')
    section = text[start:start + 1500]
    assert "makes a strong one, saves it in its database and prints the sign-in link" in section
    assert "shorter than 16 characters makes it refuse to start" in section


def test_readme_warns_that_no_token_lets_local_programs_change_settings():
    text = _flat(README)
    start = text.index("### Opening the dashboard")
    section = text[start:text.index("## A tour of the dashboard")]
    assert 'set it to `""`' in section
    assert "any program running on this computer can open the dashboard and change every setting except" in section
    assert "need a password" in section


def test_security_md_covers_loopback_without_a_token():
    text = _flat(SECURITY)
    assert "On loopback with an **empty** `web.token` there is no login at all" in text
    assert "can change every other setting" in text and "refuses to change" in text


def test_walkthrough_mentions_generated_token():
    text = _flat(WALKTHROUGH)
    assert "Home SOC insists on a real token" in text
    assert "shorter than 16 characters makes it refuse to start" in text


def test_docs_agree_with_code_on_min_length_and_generation():
    """The 16 in the docs is config.MIN_TOKEN_LENGTH, and the code really does generate a token."""
    from homesoc import cli, config

    assert config.MIN_TOKEN_LENGTH == 16
    src = Path(cli.__file__).read_text(encoding="utf-8")
    assert 'config.set_override(conn, "web.token", token)' in src
    for path in (README, SECURITY, WALKTHROUGH, LENS_SETUP):
        assert "16" in path.read_text(encoding="utf-8"), path.name


def test_readme_security_link_target_exists():
    assert "SECURITY.md#the-dashboard-binds-to-localhost" in _flat(README)
    assert "### The dashboard binds to localhost" in SECURITY.read_text(encoding="utf-8")
