"""Third security round, findings catalog: regression tests for the web-layer items round two deferred.

1. NET-DEP-003 and NET-DNS-004 stated as fact that a named device made a lookup, when Home SOC only
   matched the lookup's source address, which any LAN device can forge over UDP (deferred #6).
2. A hijacked, already-trusted autostart entry (evidence.change == "modified") was worded "New
   autostart entry" and told the owner to acknowledge it if they recognised the name (deferred #12).
3. catalog.one_line kept its own sanitiser, which missed U+061C, invisible characters and lone
   surrogates that util.safe_one_line removes; a surrogate then crashed the SQLite insert (deferred #9).
4. Query-log flooding by forged source addresses had no finding to raise (deferred #10): NET-DNS-007.

Everything is in-process: the catalog renderers, the persistence scanner's own build_findings, and
the findings engine against the temporary database from conftest. No sockets, no data/ or config.toml.
"""
from __future__ import annotations

import re
import string

import pytest

from homesoc import util
from homesoc.findings import catalog, engine, score
from homesoc.models import FindingDraft
from homesoc.scanners import persistence
from homesoc.scanners.host_windows import Collector

# Evidence as topology/__init__.py _blocked_cloud_findings builds it.
DEP3_EVIDENCE = {"key": "stalkerware-c2.example", "domain": "stalkerware-c2.example", "name": "Mum's iPhone",
                 "blocked": 40, "failures": 40, "hours": 30, "label": "stalkerware-c2.example",
                 "attributed_by": "source address"}
# Evidence as dnsfilter/reputation.py MaliciousFindingEmitter.emit builds it.
DNS4_EVIDENCE = {"key": "evil.example", "domain": "evil.example", "qname": "www.evil.example",
                 "client": "192.168.1.50", "verdict": "malicious", "malicious": 7, "suspicious": 1,
                 "source": "virustotal", "checked_at": "2026-09-22T10:00:00Z"}
# The evidence contract NET-DNS-007's emitter is asked to send (querylog._report_overflow's event data).
DNS7_EVIDENCE = {"not_logged": 5120, "sources_per_minute_limit": 4096,
                 "sample_sources": ["10.9.8.7", "172.16.4.4", "192.168.1.200"]}

# Words that assert the device itself acted, which an address match cannot support.
_DEVICE_AS_ACTOR = re.compile(r"^(?:Mum's iPhone|192\.168\.1\.50) (?:keeps|tried|looked)|\bThis device depends on\b"
                              r"|\btried to reach a malicious\b")


def _fields(template: str) -> set[str]:
    return {f for _, f, _, _ in string.Formatter().parse(template) if f}


# ------------------------------------------------------------------ 1. address, not device


class TestLookupFindingsNameTheAddressNotTheDevice:
    def test_dep_003_title_plain_title_and_why_say_what_was_seen(self):
        title, _ = catalog.render(FindingDraft("NET-DEP-003", "device:aa:bb:cc:dd:ee:06", dict(DEP3_EVIDENCE)))
        plain = catalog.render_plain_title("NET-DEP-003", dict(DEP3_EVIDENCE), "device:aa:bb:cc:dd:ee:06")
        why = catalog.render_why("NET-DEP-003", dict(DEP3_EVIDENCE), "device:aa:bb:cc:dd:ee:06")
        assert title.startswith("Lookups from Mum's iPhone's address keep trying to reach stalkerware-c2.example")
        assert "(40 lookups, every one blocked)" in title
        assert plain == ("Mum's iPhone, or something using its address, keeps looking up stalkerware-c2.example, "
                         "and web blocking stops it every time")
        assert why.startswith("Something using this device's address keeps asking for stalkerware-c2.example")
        assert "can fake its address" in why
        for text in (title, plain, why):
            assert not _DEVICE_AS_ACTOR.search(text), text

    def test_dns_004_names_the_address_and_asks_for_confirmation_before_a_reset(self):
        title, _ = catalog.render(FindingDraft("NET-DNS-004", "dns:192.168.1.50", dict(DNS4_EVIDENCE)))
        plain = catalog.render_plain_title("NET-DNS-004", dict(DNS4_EVIDENCE), "dns:192.168.1.50")
        why = catalog.render_why("NET-DNS-004", dict(DNS4_EVIDENCE), "dns:192.168.1.50")
        steps = catalog.render_remediation("NET-DNS-004", dict(DNS4_EVIDENCE), "dns:192.168.1.50")
        assert title == "Malicious domain looked up from 192.168.1.50: evil.example"
        assert plain == "Something on your network looked up a website known for malware or scams: evil.example"
        assert "A lookup from the address 192.168.1.50" in why and "can fake an address" in why
        assert "confirm which device made the lookup before you wipe or reset anything" in why
        # The confirmation step comes before any step that mentions a factory reset.
        confirm = next(i for i, s in enumerate(steps) if s.startswith("Confirm that device made the lookup"))
        reset = next(i for i, s in enumerate(steps) if "factory-reset" in s)
        assert confirm < reset and "only if you find other signs of trouble" in steps[reset]
        for text in (title, plain, why):
            assert not _DEVICE_AS_ACTOR.search(text), text
        # Still true to the timing: the first lookup was answered, so the plain line must not say "blocked".
        assert "block" not in plain.lower()

    def test_rewording_keeps_the_catalog_contracts(self):
        for fid in ("NET-DEP-003", "NET-DNS-004"):
            spec = catalog.get(fid)
            assert _fields(spec.plain_title) <= _fields(spec.title)
            assert len(spec.plain_title) <= 110 and spec.plain_title != spec.title
        assert catalog.unresolved_placeholders("NET-DEP-003", dict(DEP3_EVIDENCE), "device:aa:bb") == []
        assert catalog.unresolved_placeholders("NET-DNS-004", dict(DNS4_EVIDENCE), "dns:192.168.1.50") == []

    def test_generic_titles_stay_readable(self):
        # The score breakdown strips placeholders; a possessive must not be left dangling.
        assert "'s" not in score.generic_title("NET-DEP-003")
        assert score.generic_title("NET-DNS-004") == "Malicious domain looked up"


# ------------------------------------------------------------------ 2. changed autostart entries

RUN_KEY = "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"
ONEDRIVE = "\"C:\\Program Files\\Microsoft OneDrive\\OneDrive.exe\" /background"
EVIL = "C:\\Users\\Public\\x.exe"


def _raw(run_cmd: str = ONEDRIVE) -> dict:
    return {"run_keys": [{"hive": "HKCU", "key": RUN_KEY, "name": "OneDrive", "command": run_cmd}],
            "startup": [], "tasks": [], "services": [], "errors": {}}


def _hijack_drafts(conn):
    persistence.reconcile(conn, persistence.normalize(_raw()))  # first run: OneDrive becomes the baseline
    entries = persistence.normalize(_raw(EVIL))
    rec = persistence.reconcile(conn, entries)
    c = Collector()
    persistence.build_findings(rec.reemit, {}, c, {e.key: e for e in entries})
    return c.findings


class TestChangedAutostartIsWordedAsAChange:
    def test_real_scanner_hijack_renders_as_changed_with_was_and_now(self, conn):
        (draft,) = _hijack_drafts(conn)
        assert draft.finding_id == "WIN-PER-001" and draft.evidence["change"] == "modified"
        rendered = catalog.render(draft)
        assert rendered.title == "Autostart entry changed: OneDrive"
        assert rendered.plain_title == "A program that starts with Windows was changed: OneDrive"
        why = catalog.render_why(draft.finding_id, draft.evidence, draft.subject)
        assert f"Was: {ONEDRIVE}. Now: {EVIL}." in why
        steps = catalog.render_remediation(draft.finding_id, draft.evidence, draft.subject)
        assert steps[0].startswith("Check the new command, not just the name.")
        assert ONEDRIVE in steps[0] and EVIL in steps[0]
        assert "not enough to acknowledge" in steps[0]
        assert not any("If you recognise it" in s for s in steps)
        for text in (rendered.title, rendered.plain_title, why):
            assert not re.search(r"\bnew (?:program|autostart|entry)\b", text, re.IGNORECASE), text

    def test_stored_finding_carries_the_changed_wording(self, conn):
        drafts = _hijack_drafts(conn)
        result = engine.apply(conn, drafts, "host")
        (row,) = result.new
        assert row["title"] == "Autostart entry changed: OneDrive"
        assert row["remediation"][0].startswith("Check the new command, not just the name.")
        assert "Was: " in row["rationale"]

    @pytest.mark.parametrize("fid, title, plain", [
        ("WIN-PER-001", "Autostart entry changed: Svc", "A program that starts with Windows was changed: Svc"),
        ("WIN-PER-002", "Scheduled task changed: Svc", "A task that runs automatically was changed: Svc"),
        ("WIN-PER-003", "Auto-start service changed: Svc", "A background service was changed: Svc"),
    ])
    def test_all_three_kinds(self, fid, title, plain):
        ev = {"name": "Svc", "change": "modified", "previous_command": "C:\\a.exe", "command": "C:\\b.exe"}
        rendered = catalog.render(FindingDraft(fid, "host", ev))
        assert rendered.title == title and rendered.plain_title == plain
        assert catalog.unresolved_placeholders(fid, ev, "host") == []
        spec = catalog.spec_for(fid, ev)
        base = catalog.get(fid)
        assert (spec.severity, spec.category, spec.refs) == (base.severity, base.category, base.refs)
        assert _fields(spec.plain_title) <= _fields(spec.title) and len(spec.plain_title) <= 110

    def test_a_genuinely_new_entry_keeps_the_new_wording(self):
        ev = {"kind": "run_key", "name": "ExampleSync", "command": "C:\\sync.exe"}
        assert catalog.render(FindingDraft("WIN-PER-001", "host", ev)).title == "New autostart entry: ExampleSync"
        assert catalog.unresolved_placeholders("WIN-PER-001", ev, "host") == []

    def test_a_missing_previous_command_still_reads_as_a_sentence(self):
        ev = {"name": "OneDrive", "change": "modified", "previous_command": None, "command": EVIL}
        why = catalog.render_why("WIN-PER-001", ev, "host")
        assert "Was: (not recorded). Now: " in why and "unknown" not in why


# ------------------------------------------------------------------ 3. one sanitiser


class TestOneLineIsTheSharedSanitiser:
    @pytest.mark.parametrize("bad", ["\u061c", "\u200b", "\ufeff", "\u00ad", "\ud800", "\u202e", "\n", "\x1b"])
    def test_one_line_removes_what_util_removes(self, bad):
        text = f"model 1{bad}2345 NAS"
        assert catalog.one_line(text) == util.safe_one_line(text)
        assert bad not in catalog.one_line(text)

    def test_arabic_letter_mark_and_invisibles_never_reach_a_title(self):
        banner = "Host is not allowed - model 1\u061c2345 \u200bNAS\ufeff"
        title, _ = catalog.render(FindingDraft("NET-DEP-003", "device:aa:bb",
                                               {"name": f"Cam{banner}", "domain": "a.example", "failures": 7}))
        plain = catalog.render_plain_title("NET-DEP-003", {"name": f"Cam{banner}", "domain": "a.example",
                                                           "failures": 7}, "device:aa:bb")
        for text in (title, plain):
            assert not re.search("[\u061c\u200b\ufeff]", text), ascii(text)

    def test_length_cap_still_applies(self):
        assert len(catalog.one_line("A" * 5000, 300)) == 300

    def test_a_lone_surrogate_no_longer_aborts_the_insert(self, conn):
        draft = FindingDraft("WIN-PER-001", "host\ud800",
                             {"name": "Sync\ud800er", "key": "run_key:HKCU:Sync\udfffer", "command": "C:\\s.exe"},
                             detail="run_key 'Sync\ud800er' -> C:\\s.exe\nsecond line \u202e")
        rendered = catalog.render(draft)
        assert "\ud800" not in rendered.title and "\ud800" not in rendered.plain_title
        assert "\ud800" not in rendered.detail and "\u202e" not in rendered.detail
        assert rendered.detail.count("\n") == 1  # line breaks in a detail survive
        result = engine.apply(conn, [draft], "host")  # raised UnicodeEncodeError before
        (row,) = result.new
        assert row["title"] == "New autostart entry: Sync er"
        row["title"].encode("utf-8"), row["subject"].encode("utf-8"), row["dedupe_key"].encode("utf-8")
        # Same draft again updates the same row instead of opening a second one.
        again = engine.apply(conn, [draft], "host")
        assert again.new == [] and again.updated == 1


# ------------------------------------------------------------------ 4. NET-DNS-007


class TestQueryLogFloodFinding:
    def test_entry_exists_with_plain_honest_wording(self):
        spec = catalog.get("NET-DNS-007")
        assert spec is not None and spec.severity == "medium" and spec.category == "dns"
        assert spec.emits_per_subject is False
        assert spec.plain_title == "Something on your network seems to be faking addresses to flood web blocking's lookup log"
        assert _fields(spec.plain_title) <= _fields(spec.title) and len(spec.plain_title) <= 110

    def test_renders_from_the_documented_evidence(self):
        assert catalog.unresolved_placeholders("NET-DNS-007", dict(DNS7_EVIDENCE), "dns") == []
        title, _ = catalog.render(FindingDraft("NET-DNS-007", "dns", dict(DNS7_EVIDENCE)))
        assert title == ("DNS query log flooded by lookups from too many source addresses "
                         "(5120 not logged, limit 4096 a minute)")
        why = catalog.render_why("NET-DNS-007", dict(DNS7_EVIDENCE), "dns")
        assert "10.9.8.7, 172.16.4.4, 192.168.1.200" in why and "{" not in why
        steps = catalog.render_remediation("NET-DNS-007", dict(DNS7_EVIDENCE), "dns")
        assert any("Do not block the addresses listed here" in s for s in steps)

    def test_generic_titles_are_readable(self):
        assert score.generic_title("NET-DNS-007") == "DNS query log flooded by lookups from too many source addresses"
