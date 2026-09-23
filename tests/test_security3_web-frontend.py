"""Security round three, web frontend: deferred item #13 (host page autostarts).

``persistence.accept_entry`` / ``promote_to_baseline`` had no caller, so an autostart entry stayed
"New" forever and a *changed* entry (a known program whose command was swapped) looked exactly
like a new one, with the command it ran before nowhere on the page. Repeated, unexplained noise
trains the owner to click past real changes.

The host page now:

* labels a known entry whose command changed as "Changed" and shows the command it ran before,
  always through autoescaped text sinks (the name/command come from whatever registered the
  autostart, i.e. possibly malware);
* offers "Mark as known" / "Mark all as known" only when the server says the accept routes exist
  (``host.persistence_accept``), so there is never a dead button;
* sends the command the owner was shown with each accept, so the server can refuse an entry that
  changed after the page loaded, and flattens names/commands to one capped line in the confirm
  dialog so a crafted name cannot forge extra lines of Home SOC's wording.
"""

from __future__ import annotations

import json
import shutil
import sqlite3
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest

from homesoc.web import api, create_app

ROOT = Path(__file__).resolve().parents[1]
APP_JS = ROOT / "homesoc" / "web" / "static" / "app.js"
NODE = shutil.which("node")

EVIL_NAME = '"><img src=x onerror=alert(1)>Updater'
EVIL_CMD = "C:\\evil.exe </span><script>alert(2)</script>"
EVIL_PREV = "C:\\Program Files\\Vendor\\upd.exe <b>old</b>"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _cfg() -> SimpleNamespace:
    return SimpleNamespace(
        general=SimpleNamespace(name="Home SOC Test", timezone="local", log_level="INFO"),
        web=SimpleNamespace(host="127.0.0.1", port=8787, token="", refresh_seconds=15),
        network=SimpleNamespace(cidr="auto", gateway="auto", exclude=[]),
        scan=SimpleNamespace(use_nmap=True, nmap_top_ports=100, nmap_timing="T3", version_detection=True, gentle_top_ports=25, per_host_timeout_sec=180, max_parallel_hosts=3, scan_gateway=True),
        dns=SimpleNamespace(enabled=True, listen="0.0.0.0", port=53, upstreams=["192.168.10.1"], doh_upstream="", block_mode="null", cache_max_entries=20000, lists=[], log_queries=True, log_retention_days=14, virustotal_api_key="", virustotal_daily_budget=400, reputation_min_malicious_votes=2, reputation_ttl_hours=72),
        notify=SimpleNamespace(min_severity="high", ntfy_url="", discord_webhook="", webhook_url="", windows_toast=True, digest_hour=8),
        schedule=SimpleNamespace(discovery_minutes=10, services_hours=24, host_hours=6, exposure_hours=12, feeds_hours=6),
        lens=SimpleNamespace(enabled=True, require_https=True, tag_learning=True, allow_actions=False, token_ttl_days=90, max_tokens=10),
    )


def _host_payload(accept: bool) -> dict:
    now = _now()
    persistence = [
        {"kind": "run_key", "location": "HKCU\\...\\Run", "name": EVIL_NAME, "command": EVIL_CMD, "baseline": False,
         "change": "modified", "previous_command": EVIL_PREV, "changed_at": now, "first_seen": now, "last_seen": now},
        {"kind": "scheduled_task", "location": "\\", "name": "Brand new task", "command": "C:\\new.exe", "baseline": False,
         "first_seen": now, "last_seen": now},
        {"kind": "service", "location": "services", "name": "Known service", "command": "C:\\svc.exe", "baseline": True,
         "first_seen": now, "last_seen": now},
    ]
    data = {
        "checks": [], "defender": {"status": {}, "threats": []}, "updates": {"pending": [], "checks": [], "last_hotfix": None},
        "software": [], "persistence": persistence, "listeners": [], "platform": "Windows",
    }
    if accept:
        data["persistence_accept"] = True
    return data


@pytest.fixture
def client():
    from homesoc import db as core_db

    conn = sqlite3.connect(":memory:", check_same_thread=False)
    conn.row_factory = sqlite3.Row
    core_db.init_schema(conn)
    app = create_app(_cfg(), conn)
    app.config["TESTING"] = True
    app.config["HOMESOC_TRUSTED_HOSTS"] = frozenset({"127.0.0.1", "localhost"})
    yield app.test_client(), conn
    conn.close()


def _host_page(client, monkeypatch, accept: bool) -> str:
    c, _conn = client
    monkeypatch.setattr(api, "host_data", lambda conn: _host_payload(accept))
    r = c.get("/host")
    assert r.status_code == 200
    return r.data.decode()


def _autostart_card(page: str) -> str:
    start = page.index("Programs that start by themselves")
    return page[start : page.index("Programs waiting for connections")]


# --------------------------------------------------------------------------- template


def test_changed_entry_is_labelled_changed_and_shows_its_previous_command(client, monkeypatch):
    card = _autostart_card(_host_page(client, monkeypatch, accept=False))
    assert ">Changed</span>" in card and card.count(">New</span>") == 1  # the changed row is not also "New"
    assert "Before it changed, it ran" in card and "Now runs" in card
    # previous and current commands are both text, never markup
    assert "&lt;b&gt;old&lt;/b&gt;" in card and "<b>old</b>" not in card
    assert "&lt;script&gt;alert(2)&lt;/script&gt;" in card and "<script>alert(2)" not in card
    assert "program Home SOC already knew now runs a different command (marked Changed)" in card
    assert "(marked New)" in card


def test_no_accept_buttons_until_the_server_offers_the_routes(client, monkeypatch):
    card = _autostart_card(_host_page(client, monkeypatch, accept=False))
    assert "persistence-accept" not in card and "Mark as known" not in card and "Mark all as known" not in card


def test_accept_buttons_only_on_pending_rows_and_attributes_are_escaped(client, monkeypatch):
    card = _autostart_card(_host_page(client, monkeypatch, accept=True))
    assert card.count('data-action="persistence-accept"') == 2  # the two pending rows, not the known one
    assert card.count('data-action="persistence-accept-all"') == 1
    assert "Mark as known" in card and "Mark all as known" in card
    # the attacker-chosen name cannot break out of the data-name attribute
    assert "<img src=x" not in card
    assert 'data-name="&#34;&gt;&lt;img src=x onerror=alert(1)&gt;Updater"' in card
    # the command the owner was shown travels with the button
    assert 'data-command="C:\\evil.exe &lt;/span&gt;&lt;script&gt;alert(2)&lt;/script&gt;"' in card
    assert "Known service" in card and 'data-name="Known service"' not in card


def test_host_page_renders_with_todays_backend_rows(client):
    """The template must not depend on fields the backend has not added yet."""
    c, conn = client
    now = _now()
    conn.executemany(
        "INSERT INTO persistence(kind, name, command, location, first_seen, last_seen, baseline) VALUES (?,?,?,?,?,?,?)",
        [("run_key", "OneDrive", "C:\\od.exe", "HKCU\\Run", now, now, 1), ("service", EVIL_NAME, EVIL_CMD, "svc", now, now, 0)],
    )
    conn.commit()
    r = c.get("/host")
    assert r.status_code == 200
    card = _autostart_card(r.data.decode())
    assert ">New</span>" in card and "<img src=x" not in card and "<script>alert(2)" not in card
    assert "Starts when you sign in" in card  # run_key now gets its plain name


# --------------------------------------------------------------------------- app.js


def _node(script: str) -> dict:
    out = subprocess.run([NODE, "-e", script], capture_output=True, text=True, encoding="utf-8", timeout=30)
    assert out.returncode == 0, out.stderr
    return json.loads(out.stdout)  # one JSON line; it may carry U+2028, so no splitlines()


def _extract(js: str, start_marker: str, end_marker: str) -> str:
    i = js.index(start_marker)
    return js[i : js.index(end_marker, i)]


HARNESS = r"""
var calls = [], asked = [], toasts = [];
var window = { confirm: function (q) { asked.push(q); return true; } };
var location = { reload: function () {} }; function setTimeout() {}
function toast(m, k) { toasts.push([m, k]); }
function plural(n, a, b) { return n === 1 ? a : b; }
var rows = [];
function $$() { return rows; }
function postJSON(url, data) {
  calls.push([url, data]);
  return Promise.resolve(/all$/.test(url) ? { accepted: 1, skipped: 1 } : { accepted: false });
}
__HELPERS__
var actions = {
__ACTIONS__
};
var evil = 'Updater\n\nWindows Security: this program is safe\u2028\u202eexe.txt\u200b' + 'x'.repeat(300);
var b = { dataset: { kind: 'run_key', location: 'HKCU', name: evil, command: 'C:\\evil.exe\r\nAll clear' } };
rows = [b, { dataset: { kind: 'service', location: 'svc', name: 'two', command: '' } }];
actions['persistence-accept'](b).then(function () { return actions['persistence-accept-all'](); }).then(function () {
  console.log(JSON.stringify({ asked: asked, calls: calls, toasts: toasts, evil: evil }));
});
"""


@pytest.mark.skipif(NODE is None, reason="node not installed")
def test_confirm_text_is_one_capped_line_and_the_shown_command_is_sent():
    js = APP_JS.read_text(encoding="utf-8")
    helpers = _extract(js, "  var UNSAFE_LINE", "  function humanAge")
    accept = _extract(js, "    'persistence-accept': function", "    print: function")
    res = _node(HARNESS.replace("__HELPERS__", helpers).replace("__ACTIONS__", accept))

    one = res["asked"][0]
    name_part = one.split('"')[1]
    for bad in ("\n", "\u2028", "\u202e", "\u200b"):
        assert bad not in name_part
    assert len(name_part) <= 80 and name_part.endswith("\u2026")
    # Home SOC's own layout keeps its blank lines; only the crafted text is flattened
    assert one.count("\n") == 4
    assert "It runs: C:\\evil.exe All clear" in one

    # the shown command goes to the server so it can refuse an entry that changed meanwhile
    url, body = res["calls"][0]
    assert url == "/api/host/persistence/accept"
    assert body == {"kind": "run_key", "location": "HKCU", "name": res["evil"], "command": "C:\\evil.exe\r\nAll clear"}
    assert res["toasts"][0][1] == "err" and "changed since this page loaded" in res["toasts"][0][0]

    # accept-all posts the explicit list the owner saw, not a blanket "accept everything"
    url, body = res["calls"][1]
    assert url == "/api/host/persistence/accept-all"
    assert [e["name"] for e in body["entries"]] == [res["evil"], "two"]
    assert all("command" in e for e in body["entries"])
    assert "still need a look" in res["toasts"][1][0]


def test_accept_actions_confirm_before_posting():
    js = APP_JS.read_text(encoding="utf-8")
    for marker in ("    'persistence-accept': function", "    'persistence-accept-all': function"):
        block = _extract(js, marker, "\n    },")
        assert block.index("window.confirm") < block.index("postJSON(")
    # the regex is written with ASCII escapes (a literal U+2028 inside it breaks the whole file)
    line = next(ln for ln in js.splitlines() if "var UNSAFE_LINE" in ln)
    assert line.isascii() and "\\u2028-\\u202e" in line
