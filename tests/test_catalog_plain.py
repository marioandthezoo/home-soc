"""The plain-language headline every catalog entry carries beside its technical title.

These guard three things: that no entry is missing one, that each renders cleanly from what its
emitter really sends (with the same SafeDict / one-line protection as the technical title), and
that none of them overclaims. The honesty rules are the point of the wording, so they are tested:

* the dependency map is never about connections, flows or traffic - Home SOC cannot see devices
  talking to each other (docs/SPEC_TOPOLOGY.md C1);
* EPSS is the chance a flaw is exploited *somewhere* in the next 30 days, never a "chance of attack"
  on this household;
* no plain title may claim the user is being or will be attacked or hacked.
"""
from __future__ import annotations

import re
import string

import pytest

import test_findings as findings_tests
from homesoc.findings import catalog

try:
    from homesoc.models import FindingDraft
except ImportError:  # pragma: no cover - models is always present in this tree
    FindingDraft = findings_tests.FindingDraft  # type: ignore[misc]

ALL_IDS = catalog.all_ids()

# Evidence exactly as each real emitter builds it. The shared table in test_findings covers the
# original SPEC IDs; these are the entries added later, taken from their emitters.
EXTRA_EVIDENCE: dict[str, tuple[str, dict]] = {
    # scanners/discovery.py _limit_new_devices
    "NET-DEV-004": ("network:192.168.1.0/24", {"count": 200, "added": 32, "skipped": 168, "added_last_24h": 40,
                                               "sample": ["192.168.1.10 02:00:00:00:00:10"]}),
    # topology/__init__.py _load_bearing_findings / _single_point_findings / _blocked_cloud_findings
    "NET-DEP-001": ("device:aa:bb:cc:dd:ee:01", {"name": "Living-room NAS", "dependents": 6, "threshold": 5,
                                                 "why": "it answers DNS for the house"}),
    "NET-DEP-002": ("device:aa:bb:cc:dd:ee:02", {"name": "Router", "outages": 3,
                                                 "dates": ["2026-09-01", "2026-09-10", "2026-09-18"],
                                                 "devices": 9, "affected": 9, "cycle_seconds": 600}),
    "NET-DEP-003": ("device:aa:bb:cc:dd:ee:03", {"key": "cam.example", "domain": "cam.example", "name": "Doorbell",
                                                 "blocked": 40, "failures": 40, "hours": 30, "label": "Example Cam"}),
    # cli.soc_health_drafts
    "SOC-LENS-001": ("host", {"host": "0.0.0.0", "port": 8787, "tls": False, "require_https": True,
                              "hint": "python -m homesoc lens cert --regenerate, then run with --tls"}),
}
EVIDENCE: dict[str, tuple[str, dict]] = {**findings_tests.EMITTER_EVIDENCE, **EXTRA_EVIDENCE}

# CORRECTION 1: the map (and anything else) never claims to see devices talking to each other.
_CONNECTION_WORDS = re.compile(r"\bconnect\w*|\btraffic\b|\bflows?\b|\btalk(?:s|ing)?\b|\bcommunicat\w*|\bpackets?\b",
                               re.IGNORECASE)
# CORRECTION 2 and the general no-overclaim rule.
_OVERCLAIMS = re.compile(
    r"chance of (?:an )?attack|attack chance|you (?:will|are going to) be (?:attacked|hacked)"
    r"|(?:being|been|will be) (?:attacked|hacked|breached)|\bhacked\b|\bguaranteed?\b",
    re.IGNORECASE,
)


def _fields(template: str) -> set[str]:
    return {f for _, f, _, _ in string.Formatter().parse(template) if f}


def _render(fid: str):
    subject, evidence = EVIDENCE[fid]
    return catalog.render(FindingDraft(fid, subject, dict(evidence)))


def test_every_catalog_entry_has_representative_evidence():
    assert not [fid for fid in ALL_IDS if fid not in EVIDENCE]


@pytest.mark.parametrize("fid", ALL_IDS)
def test_every_entry_has_its_own_plain_title(fid):
    spec = catalog.get(fid)
    assert spec.plain_title.strip(), f"{fid} has no plain title"
    assert spec.plain_title.strip() != spec.title.strip(), f"{fid} plain title just repeats the technical one"
    assert "\n" not in spec.plain_title and not spec.plain_title.endswith(".")
    # A headline, not a paragraph: it has to fit a list row and a phone screen.
    assert len(spec.plain_title) <= 110, f"{fid} plain title is too long: {spec.plain_title}"


@pytest.mark.parametrize("fid", ALL_IDS)
def test_plain_title_only_uses_placeholders_the_technical_title_uses(fid):
    """Same evidence contract as the technical title, so an emitter cannot satisfy one and not the other."""
    spec = catalog.get(fid)
    assert _fields(spec.plain_title) <= _fields(spec.title), (
        f"{fid} plain title needs evidence the technical title does not: "
        f"{sorted(_fields(spec.plain_title) - _fields(spec.title))}"
    )


@pytest.mark.parametrize("fid", ALL_IDS)
def test_plain_title_renders_from_real_evidence_with_no_leftovers(fid):
    subject, evidence = EVIDENCE[fid]
    assert catalog.unresolved_placeholders(fid, evidence, subject) == []
    rendered = _render(fid)
    title, _detail = rendered
    plain = rendered.plain_title
    assert plain, f"{fid} rendered an empty plain title"
    for leftover in ("{", "}", "unknown", "None", "['", "{'", "()", "''"):
        assert leftover not in plain, f"{fid} plain title has {leftover!r}: {plain}"
    assert plain != title, f"{fid} plain title renders identical to the technical title: {plain}"
    assert plain == catalog.render_plain_title(fid, dict(evidence), subject)
    # Where the plain title is templated, the evidence must actually reach it.
    if _fields(catalog.get(fid).plain_title) & set(evidence):
        assert plain != catalog.render_plain_title(fid, {}, "host"), f"{fid} plain title ignores its evidence"


@pytest.mark.parametrize("fid", ALL_IDS)
def test_plain_title_makes_no_forbidden_claim(fid):
    raw = catalog.get(fid).plain_title
    plain = _render(fid).plain_title
    for text in (raw, plain):
        assert not _CONNECTION_WORDS.search(text), f"{fid} talks about connections/traffic: {text}"
        assert not _OVERCLAIMS.search(text), f"{fid} overclaims: {text}"


def test_epss_wording_is_about_exploitation_anywhere_not_this_house():
    plain = catalog.get("NET-VUL-004").plain_title.lower()
    assert "exploited" in plain and "somewhere" in plain and "30 days" in plain
    assert "attack" not in plain


def test_dependency_findings_never_describe_observed_links():
    """NET-DEP-* are the only findings about the rest of the network; they may say 'depend',
    'offline around the same time' or 'look up', which Home SOC does observe or infer - never a link."""
    for fid in ("NET-DEP-001", "NET-DEP-002", "NET-DEP-003"):
        plain = _render(fid).plain_title
        assert not re.search(r"\blinks?\b|\bthrough\b|\bvia\b|\bsends?\b|\bpath\b", plain, re.IGNORECASE), plain
    # An association across discovery cycles, not a measured cause.
    assert "because of" not in catalog.get("NET-DEP-002").plain_title
    assert "with it" not in catalog.get("NET-DEP-002").plain_title


def test_dns_004_plain_title_does_not_claim_the_lookup_was_blocked():
    """The reputation check runs after the answer is sent, so the lookup that raised it went through."""
    plain = catalog.get("NET-DNS-004").plain_title.lower()
    assert "block" not in plain and "stopped" not in plain
    assert "was blocked, but" not in catalog.get("NET-DNS-004").rationale


# ------------------------------------------------------------------ the render() contract


def test_render_still_unpacks_as_title_and_detail():
    fid = "NET-SVC-001"
    rendered = _render(fid)
    title, detail = rendered
    assert len(rendered) == 2 and isinstance(rendered, tuple)
    assert rendered == (title, detail)
    assert rendered.title == title and rendered.detail == detail
    assert title == "Telnet open on 192.168.1.50:23"
    assert rendered.plain_title == catalog.get(fid).plain_title


def test_unknown_id_has_no_plain_title_so_callers_fall_back():
    rendered = catalog.render(FindingDraft("XYZ-999", "host", {"a": 1}))
    title, _ = rendered
    assert "XYZ-999" in title and rendered.plain_title == ""
    assert catalog.render_plain_title("XYZ-999", {}, "host") == ""
    assert catalog.render_why("XYZ-999") == ""


def test_render_why_is_the_existing_rationale_with_evidence_filled_in():
    subject, evidence = EVIDENCE["NET-DEP-001"]
    why = catalog.render_why("NET-DEP-001", evidence, subject)
    assert why.startswith(catalog.get("NET-DEP-001").rationale.split("{")[0])
    assert "{" not in why and "6 others" in why
    # For an entry with no placeholders it is the rationale verbatim.
    assert catalog.render_why("WIN-DEF-001") == catalog.get("WIN-DEF-001").rationale


def test_placeholders_include_the_plain_title():
    assert "ssid" in catalog.placeholders("NET-WIFI-001")
    assert catalog.unresolved_placeholders("NET-DEP-003", {}, "host") == ["domain", "failures", "name"]


# ------------------------------------------------------------------ same protection as the title


@pytest.mark.parametrize("sep", ["\n", "\r", " ", "‮", "\x1b"])
def test_device_controlled_text_cannot_break_or_reverse_the_plain_title(sep):
    evidence = {"name": f"Doorbell{sep}[CRITICAL] fake", "domain": "cam.example", "failures": 3}
    plain = catalog.render_plain_title("NET-DEP-003", evidence, "device:aa:bb")
    assert sep not in plain and "\n" not in plain
    assert plain.startswith("Doorbell ")


def test_plain_title_is_length_capped_like_the_title():
    plain = catalog.render_plain_title("WIN-PER-001", {"name": "A" * 5000}, "host")
    assert len(plain) < catalog.MAX_EVIDENCE_CHARS + 100


def test_braces_in_evidence_do_not_break_the_plain_title():
    plain = catalog.render_plain_title("WIN-PER-001", {"name": "weird {thing}"}, "host")
    assert plain.endswith("weird {thing}")


def test_missing_or_empty_evidence_reads_cleanly():
    """Best-effort evidence must not leave stray brackets or quotes in the friendly line."""
    assert catalog.render_plain_title("WIN-DEF-012", {"state": ""}, "host") == "Your antivirus is not running properly"
    assert catalog.render_plain_title("WIN-ACC-001", {"user": None}, "host") == (
        "You use an administrator account for everyday work")
    assert catalog.render_plain_title("NET-WIFI-003", {"ssid": ""}, "wifi") == (
        "Wi-Fi uses an old, weak kind of encryption")
    # Missing keys still resolve through the shared aliases rather than saying "unknown".
    assert catalog.render_plain_title("SOC-SYS-004", {"key": "discovery", "consecutive_failures": 4},
                                      "job:discovery") == (
        "Part of Home SOC's monitoring keeps failing: 'discovery' (4 times in a row)")
