"""Wi-Fi security check for the interface this host is connected on (SPEC 6.8).

We only ever ask the OS what network we are on and how it is secured; the
pre-shared key is never requested (no ``key=clear``), never parsed and never
stored.
"""

from __future__ import annotations

import json
import logging
import re
import time
from typing import TYPE_CHECKING, Any, Callable

from homesoc import db
from homesoc.models import FindingDraft, ScanResult
from homesoc.scanners import IS_LINUX, IS_MAC, IS_WINDOWS, run_command
from homesoc.util import utcnow_iso

if TYPE_CHECKING:
    import sqlite3

    from homesoc.config import Config

logger = logging.getLogger(__name__)

__all__ = ["run", "evaluate", "parse_netsh_interfaces", "parse_nmcli", "parse_airport"]

AIRPORT = "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport"

# netsh labels -> our keys.  Anything not listed (e.g. "Profile") is dropped.
_NETSH_KEYS = {
    "name": "interface", "description": "description", "state": "state", "ssid": "ssid",
    "ap bssid": "bssid", "bssid": "bssid", "band": "band", "channel": "channel", "radio type": "radio_type",
    "authentication": "authentication", "cipher": "cipher", "signal": "signal",
    "connected akm-cipher": "akm_cipher", "network type": "network_type",
}
_OPEN_AUTH = ("open", "none", "wep", "shared")


def _blank() -> dict[str, Any]:
    return {"interface": None, "state": None, "ssid": None, "bssid": None, "band": None, "channel": None,
            "radio_type": None, "authentication": None, "cipher": None, "signal": None}


def parse_netsh_interfaces(text: str) -> list[dict[str, Any]]:
    """Parse ``netsh wlan show interfaces``; one dict per interface block (keys in ``_NETSH_KEYS``)."""
    interfaces: list[dict[str, Any]] = []
    current: dict[str, Any] | None = None
    for raw in text.splitlines():
        line = raw.strip()
        if not line or " : " not in line and not line.endswith(":"):
            continue
        key, _, value = line.partition(":")
        key = key.strip().lower()
        value = value.strip()
        if key == "name":
            current = _blank()
            interfaces.append(current)
        if current is None:
            continue
        mapped = _NETSH_KEYS.get(key)
        if mapped:
            current[mapped] = value or None
    for iface in interfaces:
        iface["connected"] = (iface.get("state") or "").lower() == "connected"
    return interfaces


def parse_nmcli(text: str) -> list[dict[str, Any]]:
    """Parse ``nmcli -t -f ACTIVE,SSID,SECURITY dev wifi``; only the active row(s)."""
    out = []
    for line in text.splitlines():
        parts = line.rstrip("\n").split(":")
        if len(parts) < 3:
            continue
        active, ssid, security = parts[0], parts[1], ":".join(parts[2:])
        if active.strip().lower() != "yes":
            continue
        d = _blank()
        d.update({"interface": "wifi", "state": "connected", "connected": True, "ssid": ssid or None,
                  "authentication": security.strip() or "Open",
                  "cipher": "TKIP" if "WPA1" in security and "WPA2" not in security else None})
        out.append(d)
    return out


def parse_airport(text: str) -> dict[str, Any] | None:
    """Parse ``airport -I`` (older macOS); returns None when not associated."""
    kv: dict[str, str] = {}
    for line in text.splitlines():
        if ":" in line:
            k, _, v = line.strip().partition(":")
            kv[k.strip().lower()] = v.strip()
    ssid = kv.get("ssid")
    if not ssid:
        return None
    d = _blank()
    auth = kv.get("link auth", "")
    d.update({"interface": "en0", "state": "connected", "connected": True, "ssid": ssid,
              "bssid": kv.get("bssid"), "channel": kv.get("channel"),
              "authentication": auth or "Open", "signal": kv.get("agrctlrssi")})
    if "tkip" in auth.lower():
        d["cipher"] = "TKIP"
    return d


def evaluate(iface: dict[str, Any]) -> list[FindingDraft]:
    """NET-WIFI rules for one connected interface.

    WPS (NET-WIFI-004) is not observable from ``netsh``/``nmcli`` for the
    associated network, so it is intentionally never emitted here.
    """
    if not iface.get("connected") or not iface.get("ssid"):
        return []
    auth = (iface.get("authentication") or "").lower()
    cipher = (iface.get("cipher") or "").lower()
    evidence = {
        "key": iface.get("interface") or "wifi",
        "ssid": iface.get("ssid"), "bssid": iface.get("bssid"), "authentication": iface.get("authentication"),
        "cipher": iface.get("cipher"), "band": iface.get("band"), "channel": iface.get("channel"),
        "interface": iface.get("interface"),
    }
    drafts: list[FindingDraft] = []
    subject = "wifi"
    if any(auth.startswith(o) for o in _OPEN_AUTH) or "wep" in auth or "wep" in cipher or not auth:
        drafts.append(FindingDraft(finding_id="NET-WIFI-001", subject=subject, evidence=evidence))
        return drafts
    if "tkip" in cipher or re.search(r"\bwpa1?\b(?!\d)", auth) and "wpa2" not in auth and "wpa3" not in auth:
        drafts.append(FindingDraft(finding_id="NET-WIFI-003", subject=subject, evidence=evidence))
    if "wpa2" in auth and "wpa3" not in auth:
        drafts.append(FindingDraft(finding_id="NET-WIFI-002", subject=subject, evidence=evidence))
    return drafts


def _collect() -> tuple[list[dict[str, Any]], str, str | None]:
    """Returns (interfaces, method, error)."""
    if IS_WINDOWS:
        res = run_command(["netsh", "wlan", "show", "interfaces"], timeout=20)
        if res.missing or res.timed_out:
            return [], "netsh", res.err or "netsh unavailable"
        return parse_netsh_interfaces(res.out), "netsh", None
    if IS_LINUX:
        res = run_command(["nmcli", "-t", "-f", "ACTIVE,SSID,SECURITY", "dev", "wifi"], timeout=20)
        if not res.ok:
            return [], "nmcli", res.err.strip() or "nmcli unavailable"
        return parse_nmcli(res.out), "nmcli", None
    if IS_MAC:
        res = run_command([AIRPORT, "-I"], timeout=20)
        if res.ok:
            parsed = parse_airport(res.out)
            return ([parsed] if parsed else []), "airport", None
        res = run_command(["wdutil", "info"], timeout=20)
        if res.ok:
            parsed = parse_airport(res.out)
            return ([parsed] if parsed else []), "wdutil", None
        return [], "airport", res.err.strip() or "airport/wdutil unavailable"
    return [], "none", "unsupported platform"


def run(cfg: "Config", conn: "sqlite3.Connection", *, quick: bool = False,
        progress: Callable[[str], None] | None = None) -> ScanResult:
    """Inspect the active Wi-Fi association and emit NET-WIFI findings."""
    started = time.monotonic()
    if progress:
        progress("checking Wi-Fi security")
    findings: list[FindingDraft] = []
    summary: dict[str, Any] = {"connected": False, "ssid": None, "authentication": None, "cipher": None,
                               "band": None, "interfaces": [], "method": "", "duration_sec": 0.0}
    error: str | None = None
    try:
        interfaces, method, error = _collect()
        summary["method"] = method
        summary["interfaces"] = interfaces
        for iface in interfaces:
            if iface.get("connected"):
                summary.update({"connected": True, "ssid": iface.get("ssid"),
                                "authentication": iface.get("authentication"),
                                "cipher": iface.get("cipher"), "band": iface.get("band")})
                findings.extend(evaluate(iface))
        try:  # SPEC-GAP: no settings key defined for wifi; storing a snapshot for the dashboard
            db.set_setting(conn, "wifi.last_json", json.dumps({"checked_at": utcnow_iso(), **summary}, default=str))
        except Exception as exc:
            logger.debug("could not store wifi snapshot: %s", exc)
    except Exception as exc:
        logger.exception("wifi check failed")
        error = f"{type(exc).__name__}: {exc}"
    summary["duration_sec"] = round(time.monotonic() - started, 2)
    return ScanResult(kind="wifi", findings=findings, summary=summary, error=error)
