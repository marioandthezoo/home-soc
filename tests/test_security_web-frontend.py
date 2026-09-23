"""Security regressions for the web frontend (templates and static assets).

Two findings from the 2026-09 audit, each encoded as the exploit it describes:

1. Lens kept the full ``/api/lens/device`` payload (IP, MAC, vendor, CVEs, DNS history, the
   dependency map) in the phone's localStorage indefinitely, never cleared it on revocation, and
   rendered it from the ``offline`` event even on an unpaired phone. The cache is now a trimmed,
   24-hour snapshot that only exists while the phone holds a token.

2. The sticker sheet printed ``display_name`` under each QR code, which falls back to the
   hostname, LAN IP or MAC for any device without a nickname - breaking SPEC_LENS's "a photograph
   of a sticker reveals nothing about the network". The caption is now the nickname or the
   generic device kind, never an identifier.
"""

from __future__ import annotations

import json
import re
import shutil
import sqlite3
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest

from homesoc.web import create_app

ROOT = Path(__file__).resolve().parents[1]
STATIC = ROOT / "homesoc" / "web" / "static"
LENS_JS = STATIC / "lens.js"
NODE = shutil.which("node")

HOUR_MS = 60 * 60 * 1000

FULL_PAYLOAD = {
    "device": {
        "id": 7,
        "nickname": "",
        "hostname": "ring-doorbell-7f3a",
        "ip": "192.168.1.142",
        "mac": "aa:bb:cc:00:00:03",
        "vendor": "Ring LLC",
        "kind": "camera",
        "online": True,
        "trusted": False,
        "last_seen": "2026-09-22T10:00:00+00:00",
    },
    "posture": {"headline": "Telnet is open", "severity_counts": {"critical": 1, "high": 2}, "score_contribution": 12},
    "findings": [{"title": "Telnet exposed", "severity": "critical", "row_id": 3, "status": "open"}],
    "services": [
        {"port": 23, "proto": "tcp", "state": "open", "name": "telnet", "gloss": "Telnet", "risk": "critical"},
        {"port": 8080, "proto": "tcp", "state": "closed", "name": "http-alt"},
    ],
    "vulns": [{"cve": "CVE-2099-0001", "cvss": 9.8, "kev": True}],
    "dns": {"total": 10, "top_allowed": [{"domain": "secret-cloud.example", "count": 9}]},
    "deps": {"depends_on": [{"label": "nas.lan", "kind": "device"}]},
    "blast": {"headline": "2 devices unreachable"},
    "timeline": [{"ts": "2026-09-22T09:00:00+00:00", "title": "first seen"}],
    "actions": {"can_rescan": True},
}


# --------------------------------------------------------------------------- lens.js harness


def _run_lens(script: str) -> dict:
    """Evaluate lens.js in node with a stub DOM and localStorage, then run ``script``.

    lens.js is one IIFE; its storage helpers are reached by exposing them from inside the IIFE
    in this test copy only. ``PAGE`` is empty, so no app boots and no DOM beyond ``body`` is needed.
    """
    if not NODE:
        pytest.skip("node is not installed")
    source = LENS_JS.read_text(encoding="utf-8")
    cut = source.rindex("})();")
    hook = (
        "  globalThis.__lens = { cardSnapshot: cardSnapshot, saveCard: saveCard, readCachedCard: readCachedCard,"
        " forgetPairing: forgetPairing, TOKEN_KEY: TOKEN_KEY, CARD_KEY: CARD_KEY, IGNORE_KEY: IGNORE_KEY };\n"
    )
    instrumented = source[:cut] + hook + source[cut:]
    harness = (
        "const vm = require('vm');\n"
        "const data = {};\n"
        "const localStorage = { getItem: k => (k in data ? data[k] : null), setItem: (k, v) => { data[k] = String(v); },"
        " removeItem: k => { delete data[k]; } };\n"
        "const ctx = { document: { body: { dataset: { page: '' } } }, navigator: {}, window: {}, localStorage, JSON, Date, Math, Number, String, Boolean };\n"
        "ctx.globalThis = ctx;\n"
        "vm.createContext(ctx);\n"
        f"vm.runInContext({json.dumps(instrumented)}, ctx);\n"
        "const L = ctx.__lens;\n"
        "const out = {};\n"
        f"{script}\n"
        "out.storage = data;\n"
        "process.stdout.write(JSON.stringify(out));\n"
    )
    # Via stdin: the instrumented source is far longer than a Windows command line allows.
    proc = subprocess.run([NODE, "-"], input=harness, capture_output=True, text=True, encoding="utf-8", timeout=60)
    assert proc.returncode == 0, proc.stderr
    return json.loads(proc.stdout)


PAYLOAD_JS = json.dumps(FULL_PAYLOAD)


def test_cached_card_is_a_trimmed_snapshot_without_network_identifiers():
    out = _run_lens(
        f"localStorage.setItem(L.TOKEN_KEY, 'tok');\n"
        f"L.saveCard({PAYLOAD_JS}, 1000);\n"
        "out.raw = data[L.CARD_KEY];\n"
    )
    raw = out["raw"]
    assert raw, "a paired phone should still keep an offline card (B8)"
    for leaked in ("aa:bb:cc", "192.168.1.142", "Ring LLC", "CVE-2099", "secret-cloud", "nas.lan", "first seen", "Telnet exposed", "can_rescan"):
        assert leaked not in raw, leaked
    card = json.loads(raw)
    assert set(card) == {"v", "saved_at", "device", "posture", "services"}
    assert set(card["device"]) == {"id", "name", "kind", "online", "trusted", "last_seen"}
    assert card["device"]["name"] == "ring-doorbell-7f3a"   # the one name the card was headed with
    assert card["posture"]["headline"] == "Telnet is open"
    assert card["posture"]["severity_counts"] == {"critical": 1, "high": 2}
    assert [s["port"] for s in card["services"]] == [23]    # open ports only


def test_cached_card_expires_after_a_day_and_is_deleted():
    out = _run_lens(
        f"localStorage.setItem(L.TOKEN_KEY, 'tok');\n"
        f"L.saveCard({PAYLOAD_JS}, 1000);\n"
        f"out.fresh = L.readCachedCard(1000 + 23 * {HOUR_MS}) !== null;\n"
        f"out.stale = L.readCachedCard(1000 + 25 * {HOUR_MS});\n"
        "out.kept = L.CARD_KEY in data;\n"
    )
    assert out["fresh"] is True
    assert out["stale"] is None
    assert out["kept"] is False


def test_revoked_phone_cannot_read_the_cached_card():
    """The exploit: token cleared by the 401 path, phone put in airplane mode, card shown anyway."""
    out = _run_lens(
        f"localStorage.setItem(L.TOKEN_KEY, 'tok');\n"
        f"L.saveCard({PAYLOAD_JS}, 1000);\n"
        "localStorage.removeItem(L.TOKEN_KEY);\n"
        "out.card = L.readCachedCard(2000);\n"
        "out.kept = L.CARD_KEY in data;\n"
    )
    assert out["card"] is None
    assert out["kept"] is False


def test_forget_pairing_clears_token_card_and_ignore_list():
    out = _run_lens(
        f"localStorage.setItem(L.TOKEN_KEY, 'tok');\n"
        f"L.saveCard({PAYLOAD_JS}, 1000);\n"
        "localStorage.setItem(L.IGNORE_KEY, '[\"hs1:abc\"]');\n"
        "L.forgetPairing();\n"
    )
    assert out["storage"] == {}


def test_legacy_full_payload_left_by_an_older_version_is_purged_on_read():
    out = _run_lens(
        "localStorage.setItem(L.TOKEN_KEY, 'tok');\n"
        f"localStorage.setItem(L.CARD_KEY, JSON.stringify({PAYLOAD_JS}));\n"
        "out.card = L.readCachedCard(Date.now());\n"
        "out.kept = L.CARD_KEY in data;\n"
    )
    assert out["card"] is None
    assert out["kept"] is False


def test_unpaired_phone_never_writes_a_card():
    out = _run_lens(f"L.saveCard({PAYLOAD_JS}, 1000);\n")
    assert out["storage"] == {}


def test_every_path_that_drops_the_token_drops_the_card_too():
    source = LENS_JS.read_text(encoding="utf-8")
    # No raw payload write survives anywhere.
    assert "store(CARD_KEY, JSON.stringify(payload))" not in source
    # The only place TOKEN_KEY is removed is forgetPairing, which removes the card and ignore list.
    assert source.count("store(TOKEN_KEY, null)") == 1
    forget = source[source.index("function forgetPairing()") :]
    forget = forget[: forget.index("}") + 1]
    assert "store(CARD_KEY, null)" in forget and "store(IGNORE_KEY, null)" in forget
    # The 401 "revoked or expired" branch uses it.
    on_error = source[source.index("function onError(") : source.index("function cachedCard()")]
    unauth = on_error[on_error.index("err.status === 401") : on_error.index("err.status === 403")]
    assert "forgetPairing()" in unauth
    # Going offline on an unpaired phone keeps the pairing notice instead of rendering a card.
    offline = source[source.index("function goOffline()") : source.index("function unreachableNotice()")]
    assert offline.index("if (!token())") < offline.index("cachedCard()")
    # The unpaired boot purges whatever an earlier pairing left.
    boot = source[source.index("/* Boot. No token") :]
    boot = boot[: boot.index("startCamera();")]
    assert "forgetPairing()" in boot


# --------------------------------------------------------------------------- sticker captions


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


@pytest.fixture
def sticker_client():
    from homesoc import db as core_db

    conn = sqlite3.connect(":memory:", check_same_thread=False)
    conn.row_factory = sqlite3.Row
    core_db.init_schema(conn)
    now = _now()
    rows = [
        # (id, mac, ip, hostname, kind, nickname)
        (1, "aa:bb:cc:00:00:01", "192.168.1.142", None, None, None),                  # IP only
        (2, "aa:bb:cc:00:00:02", "192.168.1.143", "ring-doorbell-7f3a", "camera", None),  # hostname
        (3, "aa:bb:cc:00:00:03", None, None, None, None),                             # MAC only
        (4, "aa:bb:cc:00:00:04", "192.168.1.144", "hall-cam", "camera", "Hall camera"),  # nicknamed
    ]
    for dev_id, mac, ip, host, kind, nick in rows:
        conn.execute(
            "INSERT INTO devices(id, mac, ip, hostname, kind, nickname, trusted, first_seen, last_seen, online) "
            "VALUES(?,?,?,?,?,?,0,?,?,1)",
            (dev_id, mac, ip, host, kind, nick, now, now),
        )
    conn.commit()
    app = create_app(_cfg(), conn)
    app.config["TESTING"] = True
    app.config["HOMESOC_TRUSTED_HOSTS"] = frozenset({"127.0.0.1", "localhost"})
    yield app.test_client()
    conn.close()


def _captions(body: str) -> list[str]:
    return re.findall(r'<b class="label-name[^"]*">([^<]*)</b>', body)


@pytest.mark.parametrize("path", ["/lens/stickers", "/lens/stickers?which=all", "/lens/stickers?which=all&names=1&size=40mm"])
def test_sticker_captions_never_print_hostname_ip_or_mac(sticker_client, path):
    r = sticker_client.get(path)
    assert r.status_code == 200
    labels = r.data.decode()
    sheet = labels[labels.index('<div class="page">') :]
    for leaked in ("192.168.1.14", "aa:bb:cc", "ring-doorbell-7f3a", "hall-cam"):
        assert leaked not in sheet, leaked
    captions = _captions(sheet)
    assert "Hall camera" in captions            # an owner-chosen nickname is still printed
    assert "camera" in captions                 # no nickname: the generic kind, not the hostname


def test_sticker_names_off_still_prints_nothing(sticker_client):
    body = sticker_client.get("/lens/stickers?which=all&names=0").data.decode()
    assert _captions(body[body.index('<div class="page">') :]) == []
