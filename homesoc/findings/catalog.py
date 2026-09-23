"""Findings catalog: the single source of truth for every finding ID Home SOC can emit.

Scanners only carry an ID plus evidence; everything a human needs (why it matters, how to fix it,
where to read more) lives here so the dashboard, notifications and CLI all say the same thing.
Remediation is written for a non-admin Windows 11 Home user first, with a PowerShell/CLI
alternative where one exists, because that is the environment it was built against
(see docs/TESTED_ENVIRONMENT.md).
"""
from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from string import Formatter
from typing import Any

logger = logging.getLogger(__name__)

SEVERITIES: tuple[str, ...] = ("critical", "high", "medium", "low", "info")

# Evidence values are scanner data, not display strings: a list of profiles, a list of CVE dicts, a
# list of skipped check IDs. Rendering them with str() leaks Python syntax into titles the user
# reads ("skipped: ['WIN-SYS-002']"), so containers get flattened before interpolation.
MAX_LISTED_VALUES = 6
# Evidence strings are often written by a LAN device (hostnames, mDNS/SSDP names, banners, the
# description a device gives its UPnP port mapping) and titles travel verbatim into ntfy/Discord/
# webhook alerts and the CLI. A newline in a device-chosen string would let it forge an extra
# "[CRITICAL] ..." line inside Home SOC's own alert, and bidi overrides can reverse what the user
# reads, so every string interpolated into a title is flattened to one line and length-capped.
MAX_EVIDENCE_CHARS = 300
_UNSAFE_TEXT = re.compile(r"[\x00-\x1f\x7f-\x9f\u2028\u2029\u200e\u200f\u202a-\u202e\u2066-\u2069]+")
# When a list holds dicts (matcher's [{"cve", "epss"}], services' [{"port", "banner"}]) the title
# wants one readable field per entry; these are tried in order.
_PREFERRED_FIELDS: tuple[str, ...] = (
    "cve", "banner", "threat_name", "name", "title", "domain", "ssid", "mount", "port", "id",
)

# A few IDs are raised by two emitters that do not carry the same evidence. Rather than render
# "unknown", the catalog knows the equivalent keys (and, where a second emitter genuinely cannot
# know the value, a truthful default).
_ALIASES: dict[str, tuple[str, ...]] = {
    # WIN-DEF-011 comes from defender.evaluate_threats as "threat_name"; WIN-PER-* uses "name".
    # "label" is what topology/graph.py calls a node's display string for the same idea.
    "name": ("threat_name", "feed", "job", "hostname", "nickname", "label"),
    # SOC-SYS-004 (cli.soc_health_drafts) carries both spellings; keep working if one is dropped.
    "job": ("key",),
    # NET-DEP-003 counts lookups that did not produce a usable answer; its emitter may call them
    # blocked (Home SOC's own filter sinkholed them) or failed (no upstream ever answered).
    "failures": ("consecutive_failures", "blocked", "failed", "failed_lookups"),
    # NET-WAN-001/002 (exposure) name the address "public_ip"; NET-DNS-001 uses "listen".
    "ip": ("public_ip", "internal_client", "listen"),
    "port": ("external_port",),
    # WIN-FW-002 (host_windows) reports every profile whose default action is Allow.
    "profile": ("profiles",),
    # --- topology (NET-DEP-*). The emitter names a device by its friendliest label; "name" above
    # already falls back to hostname/nickname, and the graph calls the same string "label".
    "dependents": ("dependent_count", "dependents_count", "weight"),
    # topology/__init__.py calls the co-dropped count "devices"; outages.py calls it "member_count".
    "affected": ("devices", "member_count", "members", "affected_count"),
    "outages": ("outage_count", "occurrences", "times"),
    "dates": ("outage_dates", "when", "observed_on"),
    "domain": ("qname", "endpoint", "registrable_domain"),
}
# Truthful stand-ins for placeholders a second emitter cannot supply.
# feeds.updater.health_findings only knows that the 48 h threshold was crossed, while
# cli.soc_health_drafts measures the real age; "48+" is accurate for both.
_PLACEHOLDER_DEFAULTS: dict[str, str] = {"hours": "48+"}


def one_line(text: Any, limit: int | None = None) -> str:
    """``text`` as a single printable line: control, line-separator and bidi characters become spaces."""
    flat = _UNSAFE_TEXT.sub(" ", str(text))
    if limit is not None and len(flat) > limit:
        flat = flat[: limit - 1] + "…"
    return flat


def _display(value: Any) -> Any:
    """Flatten an evidence value into something readable inside a sentence.

    Scalars other than bool and str pass through unchanged so ``json_evidence`` keeps its raw types;
    strings are made single-line (see ``one_line``) because they are frequently device-controlled.
    """
    if isinstance(value, str):
        return one_line(value, MAX_EVIDENCE_CHARS)
    if isinstance(value, bool):
        return "yes" if value else "no"
    if isinstance(value, (list, tuple, set, frozenset)):
        items = sorted(value, key=str) if isinstance(value, (set, frozenset)) else list(value)
        shown = [str(_display(v)) for v in items[:MAX_LISTED_VALUES]]
        text = ", ".join(s for s in shown if s)
        if len(items) > MAX_LISTED_VALUES:
            text += f", and {len(items) - MAX_LISTED_VALUES} more"
        return text
    if isinstance(value, dict):
        for field_name in _PREFERRED_FIELDS:
            candidate = value.get(field_name)
            if candidate not in (None, ""):
                return one_line(candidate, MAX_EVIDENCE_CHARS)
        return one_line(", ".join(f"{k}={v}" for k, v in list(value.items())[:4]), MAX_EVIDENCE_CHARS)
    return value


class SafeDict(dict):
    """Evidence dict for str.format_map that tolerates missing keys.

    Scanner evidence is best-effort (a banner may lack a version, a device may lack a hostname), and a
    rendering failure must never hide a security finding, so unknown placeholders render as text
    instead of raising KeyError. Known alternative spellings are resolved first so a second emitter
    for the same finding ID does not produce "unknown" in the title the user sees.
    """

    def __missing__(self, key: str) -> Any:
        for alias in _ALIASES.get(key, ()):
            value = self.get(alias)
            if value not in (None, ""):
                return value
        return _PLACEHOLDER_DEFAULTS.get(key, "unknown")


@dataclass(frozen=True)
class FindingSpec:
    id: str
    severity: str
    title: str
    rationale: str
    remediation: list[str] = field(default_factory=list)
    refs: list[str] = field(default_factory=list)
    category: str = "general"
    emits_per_subject: bool = True
    # The one line a non-technical reader understands, sitting beside ``title`` (which stays the
    # technical headline used by notifications, the CLI and the "Technical details" disclosure).
    # It may use only placeholders the technical title uses, and it follows the same honesty rules
    # as everything else here: nothing it says may be more certain than the evidence. "Why it
    # matters" is ``rationale``; there is deliberately no second, friendlier rationale to drift.
    plain_title: str = ""


# --- reusable reference URLs -------------------------------------------------------------------
_WINSEC = "https://support.microsoft.com/en-us/windows/stay-protected-with-windows-security-2ae0363d-0ada-c064-8b56-6a39afb6a963"
_DEF_OVERVIEW = "https://learn.microsoft.com/en-us/defender-endpoint/microsoft-defender-antivirus-windows"
_DEF_TAMPER = "https://learn.microsoft.com/en-us/defender-endpoint/prevent-changes-to-security-settings-with-tamper-protection"
_DEF_CLOUD = "https://learn.microsoft.com/en-us/defender-endpoint/enable-cloud-protection-microsoft-defender-antivirus"
_DEF_PUA = "https://learn.microsoft.com/en-us/defender-endpoint/detect-block-potentially-unwanted-apps-microsoft-defender-antivirus"
_DEF_CFA = "https://learn.microsoft.com/en-us/defender-endpoint/enable-controlled-folders"
_DEF_NP = "https://learn.microsoft.com/en-us/defender-endpoint/enable-network-protection"
_DEF_ASR = "https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-rules-reference"
_DEF_CLI = "https://learn.microsoft.com/en-us/defender-endpoint/command-line-arguments-microsoft-defender-antivirus"
_DEF_UPDATES = "https://www.microsoft.com/en-us/wdsi/defenderupdates"
_SET_MPPREF = "https://learn.microsoft.com/en-us/powershell/module/defender/set-mppreference"
_GET_MPSTATUS = "https://learn.microsoft.com/en-us/powershell/module/defender/get-mpcomputerstatus"
_SAC = "https://support.microsoft.com/en-us/topic/what-is-smart-app-control-285ea03d-fa88-4d56-882e-6698afdb7003"
_FW_ONOFF = "https://support.microsoft.com/en-us/windows/turn-microsoft-defender-firewall-on-or-off-ec0844f7-aebd-0583-67fe-601ecf5d774f"
_FW_DOCS = "https://learn.microsoft.com/en-us/windows/security/operating-system-security/network-security/windows-firewall/"
_SET_FWPROFILE = "https://learn.microsoft.com/en-us/powershell/module/netsecurity/set-netfirewallprofile"
_WU = "https://support.microsoft.com/en-us/windows/update-windows-3c5ae7fc-9fb6-9af1-1984-b5e0412c556a"
_RELEASE_HEALTH = "https://learn.microsoft.com/en-us/windows/release-health/"
_WINGET_UPGRADE = "https://learn.microsoft.com/en-us/windows/package-manager/winget/upgrade"
_LOCAL_ACCOUNTS = "https://learn.microsoft.com/en-us/windows/security/identity-protection/access-control/local-accounts"
_CREATE_ACCOUNT = "https://support.microsoft.com/en-us/windows/create-a-local-user-or-administrator-account-in-windows-20de74e0-ac7f-3502-a866-32915af2a34d"
_AUTOLOGON = "https://learn.microsoft.com/en-us/sysinternals/downloads/autologon"
_UAC = "https://learn.microsoft.com/en-us/windows/security/application-security/application-control/user-account-control/how-it-works"
_SMB1 = "https://learn.microsoft.com/en-us/windows-server/storage/file-server/troubleshoot/detect-enable-and-disable-smbv1-v2-v3"
_SMB_SIGN = "https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-signing-overview"
_RDP = "https://learn.microsoft.com/en-us/windows-server/remote/remote-desktop-services/clients/remote-desktop-allow-access"
_WINRM = "https://learn.microsoft.com/en-us/windows/win32/winrm/installation-and-configuration-for-windows-remote-management"
_SECURE_BOOT = "https://learn.microsoft.com/en-us/windows/security/operating-system-security/system-security/secure-the-windows-10-boot-process"
_DEVICE_ENC = "https://support.microsoft.com/en-us/windows/device-encryption-in-windows-cf7e2b6f-3e70-4882-9532-18633605b7df"
_HVCI = "https://learn.microsoft.com/en-us/windows/security/hardware-security/enable-virtualization-based-protection-of-code-integrity"
_LSA = "https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection"
_PSV2 = "https://devblogs.microsoft.com/powershell/windows-powershell-2-0-deprecation/"
_SMARTSCREEN = "https://learn.microsoft.com/en-us/windows/security/operating-system-security/virus-and-threat-protection/microsoft-defender-smartscreen/"
_SCREENSAVER = "https://support.microsoft.com/en-us/windows/change-your-screen-saver-settings-a9dc2a0c-dc8e-9161-d270-aaccc252082a"
_TPM = "https://learn.microsoft.com/en-us/windows/security/hardware-security/tpm/trusted-platform-module-overview"
_AUTORUNS = "https://learn.microsoft.com/en-us/sysinternals/downloads/autoruns"
_TASKSCHD = "https://learn.microsoft.com/en-us/windows/win32/taskschd/task-scheduler-start-page"
_VT = "https://docs.virustotal.com/"
_UFW = "https://help.ubuntu.com/community/UFW"
_MAC_FW = "https://support.apple.com/guide/mac-help/block-connections-to-your-mac-with-a-firewall-mh34041/mac"
_FILEVAULT = "https://support.apple.com/guide/mac-help/protect-data-on-your-mac-with-filevault-mh11785/mac"
_SSHD = "https://man.openbsd.org/sshd_config"
_OPENSSH_REL = "https://www.openssh.com/releasenotes.html"
_NSA_HOME = "https://media.defense.gov/2023/Feb/22/2003165170/-1/-1/0/CSI_BEST_PRACTICES_FOR_SECURING_YOUR_HOME_NETWORK.PDF"
_CISA_HOME = "https://www.cisa.gov/news-events/news/home-network-security"
_CISA_SOW = "https://www.cisa.gov/secure-our-world"
_CISA_KEV = "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
_CISA_SNMP = "https://www.cisa.gov/news-events/alerts/2017/06/05/reducing-risk-snmp-abuse"
_EPSS = "https://www.first.org/epss/"
_NVD = "https://nvd.nist.gov/vuln/search"
_SHODAN_IDB = "https://internetdb.shodan.io/"
_WIFI_SEC = "https://www.wi-fi.org/discover-wi-fi/security"
_REDIS_SEC = "https://redis.io/docs/latest/operate/oss_and_stack/management/security/"
_MYSQL_SEC = "https://dev.mysql.com/doc/refman/8.0/en/security-guidelines.html"
_NMAP_DL = "https://nmap.org/download.html"
_NPCAP = "https://npcap.com/"
_CF_DNS = "https://developers.cloudflare.com/1.1.1.1/setup/"
_QUAD9 = "https://quad9.net/"
_TAILSCALE_SERVE = "https://tailscale.com/kb/1312/serve"
_SECURE_CONTEXTS = "https://developer.mozilla.org/en-US/docs/Web/Security/Secure_Contexts"
_SPOF = "https://en.wikipedia.org/wiki/Single_point_of_failure"
_RFC2182 = "https://www.rfc-editor.org/rfc/rfc2182"
_FTC_IOT = "https://consumer.ftc.gov/articles/securing-your-internet-connected-devices-home"

# --- reusable click paths ------------------------------------------------------------------------
_OPEN_WINSEC = "Open Start, type 'Windows Security' and press Enter."
_OPEN_VTP = _OPEN_WINSEC + " Click 'Virus & threat protection'."
_OPEN_VTP_SETTINGS = _OPEN_VTP + " Under 'Virus & threat protection settings' click 'Manage settings'."
_OPEN_FIREWALL = _OPEN_WINSEC + " Click 'Firewall & network protection'."
_ROUTER_ADMIN = "Open your router's admin page (usually http://192.168.1.254 or http://192.168.1.1) in a browser and sign in with the password printed on the router label."
_ADMIN_NOTE = "This change needs an administrator: right-click PowerShell and choose 'Run as administrator' (you will get a UAC prompt)."
_REVIEW_DEVICE = "If you do not recognise the device, change your Wi-Fi password and reconnect only the devices you own."


def _spec(
    id: str,
    severity: str,
    title: str,
    plain_title: str,
    rationale: str,
    remediation: list[str],
    refs: list[str],
    category: str,
    per_subject: bool = True,
) -> FindingSpec:
    """One catalog entry. Every entry is written as: ID, severity, technical title, plain title, why."""
    assert severity in SEVERITIES, id
    assert plain_title and plain_title != title, id
    return FindingSpec(id, severity, title, rationale, list(remediation), list(refs), category, per_subject,
                       plain_title)


_SPECS: list[FindingSpec] = [
    # ------------------------------------------------------------------ Windows Defender (AV)
    _spec(
        "WIN-DEF-001", "critical", "Windows Defender antivirus is disabled",
        "Windows' built-in antivirus (Defender) is switched off — check another antivirus is protecting this computer",
        "Defender reports that it is switched off. Windows turns it off by itself when another antivirus is "
        "installed, so first check whether one is protecting this computer; if none is, any file you download or "
        "open runs unchecked, and ransomware and info-stealers rely on exactly this. Windows 11 Home ships "
        "Defender for free, so there is no reason to run without any antivirus.",
        [
            _OPEN_VTP,
            "If a banner says another antivirus is installed, decide which one you want; uninstall the other so "
            "Defender can take over (Settings > Apps > Installed apps > the product > Uninstall).",
            "Under 'Virus & threat protection settings' click 'Manage settings' and turn 'Real-time protection' On.",
            "If the switch is greyed out, check Settings > Accounts > Family for third-party or parental restrictions, "
            "and run a full scan from a clean rescue medium before trusting the PC.",
            "PowerShell (admin): Set-MpPreference -DisableRealtimeMonitoring $false",
        ],
        [_WINSEC, _DEF_OVERVIEW, _SET_MPPREF], "defender", False,
    ),
    _spec(
        "WIN-DEF-002", "critical", "Defender real-time protection is off",
        "Your antivirus is not checking files as they arrive",
        "Real-time protection is the part of Defender that stops malware the moment it lands on disk or runs; "
        "without it a scan only finds problems after the damage is done.",
        [
            _OPEN_VTP_SETTINGS,
            "Turn 'Real-time protection' On. If it turns itself back off, something is fighting Defender: run a full "
            "offline scan ('Scan options' > 'Microsoft Defender Antivirus (offline scan)').",
            "PowerShell (admin): Set-MpPreference -DisableRealtimeMonitoring $false",
        ],
        [_WINSEC, _SET_MPPREF], "defender", False,
    ),
    _spec(
        "WIN-DEF-003", "high", "Defender signatures are {age_days} days old",
        "Your antivirus's list of known threats is {age_days} days old",
        "Defender receives new detections several times a day; stale signatures miss this week's malware even "
        "though the antivirus looks 'on'.",
        [
            _OPEN_VTP + " Under 'Virus & threat protection updates' click 'Protection updates', then 'Check for updates'.",
            "If updates fail, open Settings > Windows Update > 'Check for updates' and reboot if asked.",
            "PowerShell: Update-MpSignature   (or: & \"$env:ProgramFiles\\Windows Defender\\MpCmdRun.exe\" -SignatureUpdate)",
        ],
        [_DEF_UPDATES, _DEF_CLI], "defender", False,
    ),
    _spec(
        "WIN-DEF-004", "medium", "Defender tamper protection is off",
        "Your antivirus settings are not locked against being switched off",
        "Tamper protection stops malware (or a bad script) from silently switching Defender off; it is a "
        "one-click safeguard that costs nothing.",
        [
            _OPEN_VTP_SETTINGS,
            "Scroll to 'Tamper Protection' and turn it On (accept the UAC prompt).",
            "There is no supported command line to change this setting; it must be enabled from Windows Security "
            "(that is the point of it - malware cannot script it either).",
            "PowerShell to confirm it took effect: Get-MpComputerStatus | Select-Object IsTamperProtected",
        ],
        [_DEF_TAMPER], "defender", False,
    ),
    _spec(
        "WIN-DEF-005", "medium", "Defender cloud-delivered protection is off",
        "Your antivirus is not asking Microsoft about brand-new files",
        "Cloud protection lets Defender ask Microsoft about brand-new files in milliseconds, catching threats "
        "hours before a signature update ships.",
        [
            _OPEN_VTP_SETTINGS,
            "Turn 'Cloud-delivered protection' On, and 'Automatic sample submission' On.",
            "PowerShell (admin): Set-MpPreference -MAPSReporting Advanced -SubmitSamplesConsent SendSafeSamples",
        ],
        [_DEF_CLOUD, _SET_MPPREF], "defender", False,
    ),
    _spec(
        "WIN-DEF-006", "low", "Defender PUA (potentially unwanted app) protection is off",
        "Adware and junk bundled into free installers are not being blocked",
        "PUA protection blocks adware, bundled toolbars and crypto-miners that hide inside 'free' installers; "
        "they are not classic viruses so plain antivirus lets them through.",
        [
            _OPEN_WINSEC + " Click 'App & browser control', then 'Reputation-based protection settings'.",
            "Turn 'Potentially unwanted app blocking' On and tick both 'Block apps' and 'Block downloads'.",
            "PowerShell (admin): Set-MpPreference -PUAProtection Enabled",
        ],
        [_DEF_PUA], "defender", False,
    ),
    _spec(
        "WIN-DEF-007", "low", "No Defender full scan in the last 30 days",
        "This computer has not had a full virus scan in the last 30 days",
        "Quick scans only look at common hiding spots; a periodic full scan checks every file, including old "
        "downloads and external drives.",
        [
            _OPEN_VTP + " Click 'Scan options', choose 'Full scan' and click 'Scan now' (leave the PC plugged in).",
            "PowerShell: Start-MpScan -ScanType FullScan   (or use the 'Quick scan' button on the Home SOC host page)",
        ],
        [_DEF_CLI, _GET_MPSTATUS], "defender", False,
    ),
    _spec(
        "WIN-DEF-008", "low", "Defender controlled folder access is off",
        "Ransomware protection for your Documents and Pictures folders is off",
        "Controlled folder access stops unknown programs from rewriting Documents, Pictures and Desktop, which "
        "is exactly what ransomware does first.",
        [
            _OPEN_VTP_SETTINGS + " Scroll to 'Controlled folder access' and click 'Manage Controlled folder access'.",
            "Turn it On. If a trusted program is later blocked, click 'Allow an app through Controlled folder access'.",
            "PowerShell (admin): Set-MpPreference -EnableControlledFolderAccess Enabled",
        ],
        [_DEF_CFA], "defender", False,
    ),
    _spec(
        "WIN-DEF-009", "low", "Defender network protection is off",
        "Windows is not blocking known-dangerous websites for apps outside the browser",
        "Network protection blocks connections to known-malicious domains from any app, not just the browser; "
        "it complements the Home SOC DNS filter for this PC.",
        [
            "Network protection has no switch in the Windows Security app; it is a PowerShell setting.",
            "Open Start, type 'PowerShell', right-click and choose 'Run as administrator'.",
            "Run: Set-MpPreference -EnableNetworkProtection Enabled",
        ],
        [_DEF_NP], "defender", False,
    ),
    _spec(
        "WIN-DEF-010", "low", "No Defender attack surface reduction (ASR) rules configured",
        "Extra protection against booby-trapped documents and scripts is not set up",
        "ASR rules block the tricks most phishing malware uses (Office macros spawning programs, script "
        "droppers, credential theft from LSASS) and are free on Windows Home.",
        [
            "ASR rules are configured from an administrator PowerShell (Start > 'PowerShell' > Run as administrator).",
            "Start in audit mode to be safe: Set-MpPreference -AttackSurfaceReductionRules_Ids "
            "BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550,D4F940AB-401B-4EFC-AADC-AD5F3C50688A,"
            "9E6C4E1F-7D60-472F-BA1A-A39EF669E4B2 -AttackSurfaceReductionRules_Actions AuditMode,AuditMode,AuditMode",
            "After a week without false positives, re-run with 'Enabled' instead of 'AuditMode'.",
        ],
        [_DEF_ASR], "defender", False,
    ),
    _spec(
        "WIN-DEF-011", "high", "Defender detected a threat: {threat_name}",
        "Your antivirus caught a threat on this computer ({threat_name}): check it was removed",
        "Defender found and (usually) quarantined malware recently; you should confirm it was removed, find out "
        "how it arrived, and check nothing else came with it.",
        [
            _OPEN_VTP + " Click 'Protection history' and open the entry for '{threat_name}'.",
            "Confirm the status is 'Quarantined' or 'Removed'. If it says 'Allowed' and you do not recognise it, click "
            "the entry and choose 'Remove'.",
            "Run a full scan ('Scan options' > 'Full scan'), then change passwords you used on this PC if the threat "
            "was a stealer or trojan.",
            "PowerShell: Get-MpThreatDetection | Sort-Object InitialDetectionTime -Descending | Select-Object -First 10",
        ],
        [_WINSEC, _GET_MPSTATUS], "defender", True,
    ),
    _spec(
        "WIN-DEF-012", "high", "Defender service is unhealthy ({state})",
        "Your antivirus is not running properly ({state})",
        "The antivirus engine is not running or not reporting status; the PC may be unprotected even though "
        "nothing is visibly wrong.",
        [
            _OPEN_VTP + " and read any red or yellow banner; click 'Restart now' or 'Turn on' if offered.",
            "Reboot the PC once; if the problem persists open Settings > Windows Update and install all updates.",
            "PowerShell: Get-MpComputerStatus | Select-Object AMServiceEnabled, AntivirusEnabled, RealTimeProtectionEnabled",
            "If the service still will not start, run 'Scan options' > 'Microsoft Defender Antivirus (offline scan)'.",
        ],
        [_DEF_OVERVIEW, _GET_MPSTATUS], "defender", False,
    ),
    _spec(
        "WIN-DEF-013", "info", "Smart App Control is off",
        "Windows is not limiting this computer to apps with a good reputation",
        "Smart App Control only lets apps with a good reputation run, blocking most malware outright. It can "
        "only be enabled on a clean install of Windows 11, so this is informational if it is off.",
        [
            _OPEN_WINSEC + " Click 'App & browser control' > 'Smart App Control settings'.",
            "If the setting is available, turn it On (Evaluation mode is fine). Once it is off it can only be "
            "switched back on by resetting Windows (Settings > System > Recovery > Reset this PC), so leaving it "
            "off is a reasonable choice - the other Defender findings matter more.",
            "PowerShell to read the current state (0 = off, 1 = on, 2 = evaluation): Get-ItemPropertyValue "
            "'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\CI\\Policy' -Name VerifiedAndReputablePolicyState",
        ],
        [_SAC], "defender", False,
    ),
    _spec(
        "WIN-DEF-014", "info", "Defender cloud block level / sample submission is at the basic setting",
        "Your antivirus is on its gentlest setting for files it has not seen before",
        "A higher cloud block level makes Defender more aggressive on unknown files with little downside for a "
        "home user; sample submission helps it learn from new threats.",
        [
            _OPEN_VTP_SETTINGS + " Ensure 'Automatic sample submission' is On.",
            "PowerShell (admin): Set-MpPreference -CloudBlockLevel High -CloudExtendedTimeout 50",
        ],
        [_DEF_CLOUD, _SET_MPPREF], "defender", False,
    ),
    # ------------------------------------------------------------------ Firewall
    _spec(
        "WIN-FW-001", "critical", "Windows Firewall is disabled for the {profile} profile",
        "This computer's firewall is switched off on {profile} networks",
        "The firewall is the only thing stopping other devices (or a compromised gadget) on your network from "
        "reaching file shares and services on this PC.",
        [
            _OPEN_FIREWALL,
            "Click the network marked '(active)' or the '{profile} network' entry and turn 'Microsoft Defender Firewall' On.",
            "Repeat for Domain, Private and Public so all three say 'Firewall is on'.",
            "PowerShell (admin): Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True",
        ],
        [_FW_ONOFF, _SET_FWPROFILE], "firewall", True,
    ),
    _spec(
        "WIN-FW-002", "high", "Windows Firewall default inbound action is Allow ({profile})",
        "This computer's firewall lets other devices in unless told otherwise ({profile})",
        "With inbound 'allow' by default, every listening program on this PC is reachable from the network, "
        "which defeats the purpose of having a firewall.",
        [
            _OPEN_FIREWALL + " Click 'Advanced settings' (accept the UAC prompt).",
            "In the right pane click 'Windows Defender Firewall Properties'; on each profile tab set "
            "'Inbound connections' to 'Block (default)' and click OK.",
            "PowerShell (admin): Set-NetFirewallProfile -Profile Domain,Private,Public -DefaultInboundAction Block",
        ],
        [_FW_DOCS, _SET_FWPROFILE], "firewall", True,
    ),
    # ------------------------------------------------------------------ Updates
    _spec(
        "WIN-UPD-001", "medium", "{count} Windows updates are pending",
        "Windows has {count} updates waiting to install",
        "Most malware exploits bugs that were already fixed; installing the pending updates (especially security "
        "and cumulative ones) closes those doors.",
        [
            "Open Start > Settings > Windows Update and click 'Check for updates', then 'Download & install all'.",
            "Restart when prompted; check the page again after the restart in case a second round is waiting.",
            "PowerShell: Start-Process ms-settings:windowsupdate   (opens the same page)",
        ],
        [_WU, _RELEASE_HEALTH], "updates", False,
    ),
    _spec(
        "WIN-UPD-002", "high", "Last cumulative Windows update was {days} days ago",
        "Windows has not installed its monthly security update in {days} days",
        "Windows should receive a cumulative security update every month; going more than 45 days without one "
        "usually means updates are stuck or paused and known holes are open.",
        [
            "Open Start > Settings > Windows Update. If it shows 'Updates paused', click 'Resume updates'.",
            "Click 'Check for updates' and install everything, restarting as needed.",
            "If it keeps failing: Settings > System > Troubleshoot > Other troubleshooters > Windows Update > Run.",
            "PowerShell: Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 5",
        ],
        [_WU, _RELEASE_HEALTH], "updates", False,
    ),
    _spec(
        "WIN-UPD-003", "low", "Outdated app: {name} {version} (available {available})",
        "An app on this computer is out of date: {name}",
        "Old versions of everyday apps keep known bugs that drive-by downloads and malicious documents exploit; "
        "updating them is the cheapest fix there is.",
        [
            "Open Start > 'Microsoft Store' > Library (bottom-left) > 'Get updates' for Store apps.",
            "For everything else open Start, type 'Terminal', press Enter and run: winget upgrade --id \"{id}\"",
            "Or update all at once: winget upgrade --all --include-unknown",
        ],
        [_WINGET_UPGRADE], "updates", True,
    ),
    _spec(
        "WIN-UPD-004", "high", "Outdated high-risk app: {name} {version} (available {available})",
        "An app that attackers often target is out of date: {name}",
        "This program (browser, runtime, archiver, remote-access or media tool) is a favourite exploit target; "
        "running an old version is one of the most common ways home PCs get compromised.",
        [
            "Close the app, open Start, type 'Terminal', press Enter and run: winget upgrade --id \"{id}\"",
            "If winget cannot update it, open the app's own 'Help > Check for updates' menu or reinstall from the vendor site.",
            "If you no longer use the app (e.g. Java, old VNC/TeamViewer), uninstall it: Settings > Apps > Installed apps.",
        ],
        [_WINGET_UPGRADE, _CISA_KEV], "updates", True,
    ),
    # ------------------------------------------------------------------ Accounts
    _spec(
        "WIN-ACC-001", "medium", "Your daily account '{user}' is an Administrator",
        "You use an administrator account ('{user}') for everyday work",
        "Malware runs with the rights of the user who launched it; using a standard account for daily work means "
        "a bad click cannot install drivers, disable the antivirus or encrypt other users' files without a UAC prompt.",
        [
            "Open Start > Settings > Accounts > 'Other users' > 'Add account' and create a second, local account "
            "(choose 'I don't have this person's sign-in information' > 'Add a user without a Microsoft account').",
            "Click the new account > 'Change account type' > 'Administrator' (this becomes your admin account).",
            "Sign in to the new admin account once, then go to Settings > Accounts > Other users, select your daily "
            "account > 'Change account type' > 'Standard User'.",
            "Sign back in to your daily account; Windows will now ask for the admin password only when needed.",
            "PowerShell (admin): Remove-LocalGroupMember -Group Administrators -Member \"{user}\"",
        ],
        [_CREATE_ACCOUNT, _LOCAL_ACCOUNTS, _UAC], "accounts", False,
    ),
    _spec(
        "WIN-ACC-002", "high", "Built-in Administrator account is enabled",
        "The built-in Administrator account, which Windows keeps off, is switched on",
        "The built-in Administrator has no UAC prompts and a well-known name, making it the first account "
        "attackers try; Windows disables it by default for a reason.",
        [
            "Open Start, type 'PowerShell', right-click it and choose 'Run as administrator'.",
            "Run: Disable-LocalUser -Name Administrator",
            "Make sure you have another administrator account first (Settings > Accounts > Other users).",
        ],
        [_LOCAL_ACCOUNTS], "accounts", False,
    ),
    _spec(
        "WIN-ACC-003", "high", "Guest account is enabled",
        "The Guest account is on, so someone could sign in without a password",
        "The Guest account lets anyone on the network or at the keyboard sign in without a password and can be "
        "used as a foothold; it should stay disabled on Windows 11.",
        [
            "Open Start, type 'PowerShell', right-click it and choose 'Run as administrator'.",
            "Run: Disable-LocalUser -Name Guest",
        ],
        [_LOCAL_ACCOUNTS], "accounts", False,
    ),
    _spec(
        "WIN-ACC-004", "high", "Automatic logon is enabled",
        "This computer signs itself in with no password needed",
        "Autologon stores your password in the registry in a recoverable form and lets anyone who powers on the "
        "PC straight into your session; a stolen laptop is then fully open.",
        [
            "Press Win+R, type 'netplwiz' and press Enter.",
            "Tick 'Users must enter a user name and password to use this computer' and click OK. If the box is "
            "missing, open Settings > Accounts > Sign-in options and turn Windows Hello sign-in requirement On first.",
            "PowerShell (admin): Remove-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon' "
            "-Name DefaultPassword -ErrorAction SilentlyContinue; Set-ItemProperty "
            "'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon' -Name AutoAdminLogon -Value 0",
        ],
        [_AUTOLOGON], "accounts", False,
    ),
    _spec(
        "WIN-ACC-005", "high", "User Account Control (UAC) is off or set to never prompt",
        "Programs can take full control of this computer without asking you",
        "UAC is the prompt that stops a program from silently becoming administrator; with it off, any malware "
        "you run owns the whole machine immediately.",
        [
            "Open Start, type 'UAC' and choose 'Change User Account Control settings'.",
            "Move the slider to the top or second-from-top notch ('Always notify' or 'Notify me only when apps try "
            "to make changes') and click OK, then restart.",
            "PowerShell (admin): Set-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' "
            "-Name EnableLUA -Value 1; Set-ItemProperty (same key) -Name ConsentPromptBehaviorAdmin -Value 5",
        ],
        [_UAC], "accounts", False,
    ),
    # ------------------------------------------------------------------ Network services on the host
    _spec(
        "WIN-NET-001", "high", "SMBv1 file sharing protocol is enabled",
        "This computer still has the outdated file-sharing method ransomware worms spread through",
        "SMBv1 is the 30-year-old protocol WannaCry and NotPetya spread through; nothing modern needs it and "
        "Microsoft removes it by default.",
        [
            "Open Start, type 'Turn Windows features on or off' and press Enter (accept UAC).",
            "Untick 'SMB 1.0/CIFS File Sharing Support' (and all its sub-items), click OK and restart.",
            "PowerShell (admin): Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart",
        ],
        [_SMB1], "host-network", False,
    ),
    _spec(
        "WIN-NET-002", "medium", "Remote Desktop is enabled (Network Level Authentication: {nla})",
        "Remote Desktop is on: this computer accepts remote sign-ins from the network",
        "Remote Desktop exposes a password login to the network; it is constantly brute-forced, and without "
        "Network Level Authentication an attacker can probe it before even entering a password.",
        [
            "If you do not use Remote Desktop: open Start > Settings > System > Remote Desktop and turn it Off.",
            "If you do use it: keep it On, expand the entry and tick 'Require devices to use Network Level "
            "Authentication to connect', and use a long password or a Microsoft account with 2-step verification.",
            "Never forward port 3389 on your router; use a VPN (Tailscale/WireGuard) or the Remote Desktop app "
            "via a cloud relay instead.",
            "PowerShell (admin): Set-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server' "
            "-Name fDenyTSConnections -Value 1",
        ],
        [_RDP], "host-network", False,
    ),
    _spec(
        "WIN-NET-003", "low", "SMB signing is not required",
        "Shared-folder transfers on this computer are not protected against tampering",
        "Without SMB signing, a device on the same Wi-Fi can tamper with or relay file-sharing traffic; requiring "
        "it is a small hardening step with no visible cost at home.",
        [
            "Open Start, type 'PowerShell', right-click and choose 'Run as administrator'.",
            "Run: Set-SmbServerConfiguration -RequireSecuritySignature $true -Force; "
            "Set-SmbClientConfiguration -RequireSecuritySignature $true -Force",
            "Note: Windows 11 24H2 already requires signing for the client by default; older NAS boxes may need a firmware update.",
        ],
        [_SMB_SIGN], "host-network", False,
    ),
    _spec(
        "WIN-NET-004", "low", "LLMNR name resolution is enabled",
        "This computer uses an old name-lookup method attackers on your network can abuse to capture password data",
        "LLMNR lets any device on the LAN answer 'who is FILESERVER?'; attackers use it to capture password "
        "hashes from a mistyped share name. Home networks resolve names fine without it.",
        [
            "Windows Home has no Group Policy editor, so use the registry.",
            "Open Start, type 'PowerShell', right-click and choose 'Run as administrator', then run: "
            "New-Item 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient' -Force | Out-Null; "
            "Set-ItemProperty 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient' -Name EnableMulticast -Value 0",
            "Restart the PC for the change to take effect.",
        ],
        [_NSA_HOME], "host-network", False,
    ),
    _spec(
        "WIN-NET-005", "medium", "WinRM / Remote Registry is listening on the network ({port})",
        "Windows remote management is open to the network (port {port})",
        "WinRM (5985/5986) and Remote Registry let anyone with your password run commands or edit the registry "
        "remotely; home PCs almost never need them switched on.",
        [
            "Open Start, type 'PowerShell', right-click and choose 'Run as administrator'.",
            "Run: Disable-PSRemoting -Force; Stop-Service WinRM; Set-Service WinRM -StartupType Disabled",
            "Then: Stop-Service RemoteRegistry; Set-Service RemoteRegistry -StartupType Disabled",
        ],
        [_WINRM], "host-network", True,
    ),
    _spec(
        "WIN-NET-006", "low", "Unusual program listening on the LAN: port {port} ({process})",
        "An unexpected program ({process}) is open to other devices on port {port}",
        "A program accepting connections from the network is an entry point; if you did not install it "
        "deliberately, it deserves a look.",
        [
            "Open Start, type 'Resource Monitor', press Enter, open the 'Network' tab and expand 'Listening Ports' "
            "to see which program owns port {port}.",
            "If it is something you installed (game launcher, media server, sync tool) you can ignore or suppress this finding.",
            "If unknown, uninstall the program (Settings > Apps > Installed apps) or block it: Windows Security > "
            "'Firewall & network protection' > 'Allow an app through firewall' and untick it.",
            "PowerShell: Get-NetTCPConnection -State Listen -LocalPort {port} | Select-Object OwningProcess; "
            "Get-Process -Id <pid>",
        ],
        [_FW_DOCS, _NSA_HOME], "host-network", True,
    ),
    # ------------------------------------------------------------------ System
    _spec(
        "WIN-SYS-001", "medium", "Secure Boot is off",
        "Secure Boot, which stops hidden malware loading before Windows, is off",
        "Secure Boot stops rootkits from loading before Windows starts; with it off, a bootkit can hide from "
        "every antivirus.",
        [
            "Open Start > Settings > System > Recovery > 'Advanced startup' > 'Restart now'.",
            "Choose Troubleshoot > Advanced options > UEFI Firmware Settings > Restart.",
            "In the firmware find 'Secure Boot' (usually under Boot or Security), set it to Enabled, save and exit.",
            "PowerShell (admin) to verify: Confirm-SecureBootUEFI",
        ],
        [_SECURE_BOOT], "system", False,
    ),
    _spec(
        "WIN-SYS-002", "high", "BitLocker / device encryption is off",
        "This computer's drive is not encrypted: if it is stolen, every file can be read",
        "If the laptop is lost or stolen, an unencrypted drive gives up every file, saved password and browser "
        "session to whoever plugs it into another PC.",
        [
            "Open Start > Settings > Privacy & security > 'Device encryption' and turn it On (sign in with a "
            "Microsoft account so the recovery key is backed up to https://account.microsoft.com/devices/recoverykey).",
            "If 'Device encryption' is not listed, Windows Home cannot use BitLocker; enable Secure Boot and TPM in "
            "firmware (see WIN-SYS-001 / WIN-SYS-008) and check again, or upgrade to Windows Pro.",
            "PowerShell (admin) to check: Get-BitLockerVolume | Select-Object MountPoint, ProtectionStatus",
        ],
        [_DEVICE_ENC], "system", False,
    ),
    _spec(
        "WIN-SYS-003", "low", "Virtualization-based security / memory integrity (HVCI) is not running",
        "Memory integrity, which keeps bad drivers out of Windows, is not running",
        "Memory integrity keeps malicious drivers out of the Windows kernel, one of the few places antivirus "
        "cannot see. It is free on hardware that supports it.",
        [
            _OPEN_WINSEC + " Click 'Device security' > 'Core isolation details'.",
            "Turn 'Memory integrity' On and restart. If Windows lists incompatible drivers, update or remove them first.",
            "PowerShell (admin): Set-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\Scenarios\\HypervisorEnforcedCodeIntegrity' "
            "-Name Enabled -Value 1",
        ],
        [_HVCI], "system", False,
    ),
    _spec(
        "WIN-SYS-004", "medium", "LSA protection (RunAsPPL) is off",
        "Your sign-in details held in memory are not protected from theft",
        "LSA holds your logon credentials in memory; without protection, tools like Mimikatz can dump them once "
        "they run as admin.",
        [
            _OPEN_WINSEC + " Click 'Device security' > 'Core isolation details' and turn 'Local Security Authority protection' On.",
            "Restart the PC.",
            "PowerShell (admin): Set-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa' -Name RunAsPPL -Value 2",
        ],
        [_LSA], "system", False,
    ),
    _spec(
        "WIN-SYS-005", "low", "Windows PowerShell 2.0 engine is enabled",
        "An old version of PowerShell that malware uses to stay unseen is still installed",
        "PowerShell 2.0 has no script logging or AMSI antivirus hooks, so malware launches it on purpose to run "
        "unseen; nothing modern needs it.",
        [
            "Open Start, type 'Turn Windows features on or off' and press Enter (accept UAC).",
            "Expand 'Windows PowerShell 2.0', untick it and click OK.",
            "PowerShell (admin): Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root -NoRestart",
        ],
        [_PSV2], "system", False,
    ),
    _spec(
        "WIN-SYS-006", "medium", "SmartScreen is off",
        "Windows will not warn you before you run a risky download",
        "SmartScreen warns before running downloaded programs and visiting known phishing pages; it is the "
        "layer that catches the 'invoice.exe' a user double-clicks.",
        [
            _OPEN_WINSEC + " Click 'App & browser control' > 'Reputation-based protection settings'.",
            "Turn On 'Check apps and files', 'SmartScreen for Microsoft Edge' and 'Phishing protection'.",
            "PowerShell (admin): Set-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer' "
            "-Name SmartScreenEnabled -Value Warn",
        ],
        [_SMARTSCREEN], "system", False,
    ),
    _spec(
        "WIN-SYS-007", "low", "Screen lock is not enforced",
        "This computer does not lock itself when you walk away",
        "An unlocked PC left on the desk exposes email, banking sessions and saved passwords to anyone walking "
        "by; an automatic lock after a few minutes costs nothing.",
        [
            "Open Start > Settings > Accounts > Sign-in options and set 'If you've been away, when should Windows "
            "require you to sign in again?' to a short interval (e.g. 5 or 15 minutes).",
            "Then Settings > System > Power & battery > 'Screen and sleep' and set 'Turn my screen off after' to 10 minutes.",
            "Get in the habit of pressing Win+L when you step away.",
            "PowerShell: Set-ItemProperty 'HKCU:\\Control Panel\\Desktop' -Name ScreenSaveTimeOut -Value 600; "
            "Set-ItemProperty 'HKCU:\\Control Panel\\Desktop' -Name ScreenSaverIsSecure -Value 1",
        ],
        [_SCREENSAVER], "system", False,
    ),
    _spec(
        "WIN-SYS-008", "low", "TPM is absent or not ready",
        "This computer's security chip is missing or not ready",
        "The TPM chip stores encryption keys and Windows Hello secrets in hardware; without it BitLocker, "
        "Secure Boot attestation and passkeys are weaker or unavailable.",
        [
            "Press Win+R, type 'tpm.msc' and press Enter to read the TPM status.",
            "If it says 'Compatible TPM cannot be found', restart into firmware (Settings > System > Recovery > "
            "Advanced startup) and enable 'TPM', 'PTT' (Intel) or 'fTPM' (AMD) under Security.",
            "PowerShell (admin): Get-Tpm",
        ],
        [_TPM], "system", False,
    ),
    # ------------------------------------------------------------------ Persistence
    _spec(
        "WIN-PER-001", "medium", "New autostart entry: {name}",
        "A new program was set to start with Windows: {name}",
        "Programs that start with Windows are how malware survives a reboot; a new entry that appeared since the "
        "last check should be something you installed on purpose.",
        [
            "Open Start > Settings > Apps > Startup and look for '{name}'. If you recognise it, leave it (or turn it "
            "off if you do not need it at startup) and acknowledge this finding.",
            "If unknown: press Ctrl+Shift+Esc, open the 'Startup apps' tab, right-click the entry > 'Open file "
            "location' and check the file's publisher (right-click > Properties > Details).",
            "Right-click the file > 'Scan with Microsoft Defender', then disable the entry (right-click > Disable) "
            "and uninstall the program.",
            "PowerShell: Get-ItemProperty HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run; "
            "Get-ItemProperty HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        ],
        [_AUTORUNS], "persistence", True,
    ),
    _spec(
        "WIN-PER-002", "medium", "New scheduled task: {name}",
        "A new task was set to run automatically: {name}",
        "Scheduled tasks are a favourite way for malware and unwanted updaters to run silently in the "
        "background; new non-Microsoft tasks deserve a quick look.",
        [
            "Open Start, type 'Task Scheduler' and press Enter; find '{name}' in the Task Scheduler Library.",
            "Open the 'Actions' tab to see what it runs. If you recognise it, acknowledge this finding.",
            "If unknown, right-click the task > Disable, then locate and scan the program it runs.",
            "PowerShell: Get-ScheduledTask -TaskName \"{name}\" | Get-ScheduledTaskInfo; "
            "(Get-ScheduledTask -TaskName \"{name}\").Actions",
        ],
        [_TASKSCHD, _AUTORUNS], "persistence", True,
    ),
    _spec(
        "WIN-PER-003", "medium", "New auto-start service: {name}",
        "A new background service was added: {name}",
        "A Windows service runs with high privileges before anyone logs in; a new one that is not from "
        "Microsoft or a driver you installed is a classic malware foothold.",
        [
            "Press Win+R, type 'services.msc' and press Enter; find '{name}' and open its Properties to see the "
            "'Path to executable'.",
            "If you installed the related software (VPN, printer, game anti-cheat), acknowledge this finding.",
            "If unknown: set 'Startup type' to Disabled, click Stop, then scan the executable with Defender and "
            "uninstall the program.",
            "PowerShell: Get-CimInstance Win32_Service -Filter \"Name='{name}'\" | Select-Object Name, StartMode, PathName",
        ],
        [_AUTORUNS], "persistence", True,
    ),
    # ------------------------------------------------------------------ AV file checks
    _spec(
        "AV-FILE-001", "critical", "Malicious file in Downloads: {path}",
        "Several antivirus engines say a file in your Downloads is malware: do not open it",
        "A file you downloaded recently is flagged as malware by multiple antivirus engines; if it has been "
        "opened, the PC may already be compromised.",
        [
            "Do NOT open the file. Open Windows Security > 'Virus & threat protection' > 'Scan options' > 'Full scan' > 'Scan now'.",
            "Delete the file: open File Explorer, go to Downloads, right-click '{path}' > Delete, then empty the Recycle Bin.",
            "If you already ran it: disconnect from Wi-Fi, run the 'Microsoft Defender Antivirus (offline scan)', and "
            "change your important passwords from a different device.",
            "Look up the hash for details: https://www.virustotal.com/gui/file/{sha256}",
        ],
        [_VT, _WINSEC], "files", True,
    ),
    _spec(
        "AV-FILE-002", "medium", "Suspicious file in Downloads: {path}",
        "A few antivirus engines are wary of a file in your Downloads",
        "A few antivirus engines flag this download; it may be a false positive on an installer bundle, but "
        "check where it came from before opening it.",
        [
            "Right-click '{path}' in Downloads and choose 'Scan with Microsoft Defender'.",
            "Check the report at https://www.virustotal.com/gui/file/{sha256} and read which engines flagged it and why.",
            "If you did not intentionally download it from a source you trust, delete it.",
        ],
        [_VT], "files", True,
    ),
    # ------------------------------------------------------------------ POSIX hosts
    _spec(
        "POSIX-FW-001", "high", "Host firewall is inactive",
        "This computer's firewall is switched off",
        "Without a host firewall, every listening service on this machine is reachable by any device on the "
        "network, including a compromised smart TV or a guest's phone.",
        [
            "Ubuntu/Debian: sudo ufw default deny incoming; sudo ufw default allow outgoing; sudo ufw enable",
            "macOS: Apple menu > System Settings > Network > Firewall > turn On (and enable 'Block all incoming "
            "connections' if you do not share anything).",
            "Fedora: sudo systemctl enable --now firewalld",
        ],
        [_UFW, _MAC_FW], "posix", False,
    ),
    _spec(
        "POSIX-UPD-001", "medium", "{count} system updates pending",
        "This computer has {count} system updates waiting to install",
        "Unpatched packages are the most common way Linux and macOS machines get compromised; the fix is one "
        "command away.",
        [
            "Ubuntu/Debian: sudo apt update && sudo apt upgrade -y",
            "macOS: Apple menu > System Settings > General > Software Update, or: sudo softwareupdate -ia; brew upgrade",
            "Fedora: sudo dnf upgrade --refresh",
        ],
        [_CISA_SOW], "posix", False,
    ),
    _spec(
        "POSIX-SSH-001", "high", "SSH allows root login",
        "Remote logins can go straight to the all-powerful root account",
        "Root login over SSH gives brute-force bots a guaranteed username to attack; disabling it and using "
        "sudo from a normal user removes half the attack.",
        [
            "Edit the SSH server config: sudo nano /etc/ssh/sshd_config",
            "Set 'PermitRootLogin no' (and ideally 'PasswordAuthentication no' once you have SSH keys set up), save.",
            "Restart SSH: sudo systemctl restart ssh   (macOS: sudo launchctl kickstart -k system/com.openssh.sshd)",
        ],
        [_SSHD], "posix", False,
    ),
    _spec(
        "POSIX-ENC-001", "medium", "Disk is not encrypted",
        "This computer's disk is not encrypted: if it is stolen, every file can be read",
        "A lost or stolen laptop with an unencrypted disk exposes every file and saved credential; full-disk "
        "encryption makes the drive useless without your password.",
        [
            "macOS: Apple menu > System Settings > Privacy & Security > FileVault > Turn On (store the recovery key safely).",
            "Linux: encryption (LUKS) is normally chosen during installation; back up and reinstall with 'Encrypt "
            "the new installation', or encrypt your home directory with ecryptfs/fscrypt as an interim step.",
        ],
        [_FILEVAULT], "posix", False,
    ),
    _spec(
        "POSIX-NET-001", "low", "Unusual service listening on the network: port {port} ({process})",
        "An unexpected program ({process}) is open to other devices on port {port}",
        "A network-facing service you did not knowingly start is an entry point; confirm what it is and bind "
        "it to localhost or firewall it if it does not need LAN access.",
        [
            "Linux: sudo ss -ltnp | grep ':{port}'   macOS: sudo lsof -iTCP:{port} -sTCP:LISTEN",
            "If the program only needs local access, configure it to listen on 127.0.0.1 instead of 0.0.0.0.",
            "Otherwise block the port: sudo ufw deny {port}/tcp   (macOS: use the Firewall settings).",
        ],
        [_NSA_HOME], "posix", True,
    ),
    # ------------------------------------------------------------------ Devices
    _spec(
        "NET-DEV-001", "medium", "New device on the network: {ip} ({vendor})",
        "A device Home SOC has not seen before joined your network",
        "Every device on your Wi-Fi can reach every other device; an unknown one may be a neighbour using your "
        "Wi-Fi, a forgotten gadget with default passwords, or an intruder.",
        [
            "Open the Home SOC Devices page and identify it by IP {ip}, hostname '{hostname}' and vendor '{vendor}'. "
            "Check phones/laptops/TVs/plugs in the house that were just connected.",
            "If it is yours, give it a nickname and tick 'Trusted' so it is not reported again.",
            _REVIEW_DEVICE,
            "Also check the router's connected-devices list for the same MAC, and consider enabling the router's "
            "guest network for smart-home gadgets.",
        ],
        [_NSA_HOME, _CISA_HOME], "devices", True,
    ),
    _spec(
        "NET-DEV-002", "info", "Device with unknown vendor or randomized MAC: {ip}",
        "Home SOC cannot tell who made this device, so it may not recognise it next time",
        "Phones and laptops now randomise their Wi-Fi address for privacy, so this is usually harmless, but it "
        "means the inventory cannot recognise the device across reconnects.",
        [
            "Check whether the device is a phone/laptop you own (it will reconnect with a new MAC each time).",
            "To make it recognisable, turn off 'Private/Random Wi-Fi address' for your home network on that "
            "device (iOS: Wi-Fi > (i) > Private Wi-Fi Address; Android: network details > Privacy > Use device MAC).",
            "Then mark it Trusted on the Devices page.",
        ],
        [_NSA_HOME], "devices", True,
    ),
    _spec(
        "NET-DEV-003", "info", "Trusted device '{name}' has been offline for {days} days",
        "'{name}' has not been seen on your network for {days} days",
        "A trusted device that has not been seen for a month is probably gone; keeping it trusted means a new "
        "device with the same address would be silently accepted.",
        [
            "Open the Devices page and check whether you still own the device.",
            "If it is gone (sold, replaced), untick 'Trusted' or delete it from the inventory.",
        ],
        [], "devices", True,
    ),
    _spec(
        "NET-DEV-004", "high", "{count} new devices appeared in one network scan",
        "{count} new devices appeared at once: one gadget may be misbehaving",
        "A home network gains a device now and then, not dozens at once. A burst like this usually means one "
        "device is answering for many addresses with made-up hardware (MAC) addresses, which is how a "
        "compromised gadget floods or spoofs the network. Home SOC added {added} of them and held the other "
        "{skipped} back so the inventory stays usable.",
        [
            "Open the Devices page, sort by 'first seen' and look at the newest entries: many unknown devices "
            "with random-looking MAC addresses on one IP range point at a single misbehaving device.",
            "Examples of the addresses involved: {sample}.",
            "Unplug or power off recently added gadgets one at a time (cameras, plugs, TV boxes) and run a "
            "discovery scan after each; when the burst stops you have found the culprit.",
            "Keep that device off the network, or move it to the router's guest/IoT network, and update or "
            "factory-reset it before reconnecting.",
        ],
        [_NSA_HOME], "devices", True,
    ),
    # ------------------------------------------------------------------ Services on LAN devices
    _spec(
        "NET-SVC-001", "critical", "Telnet open on {ip}:{port}",
        "This device offers an old way to log in that has no encryption",
        "Telnet sends passwords in clear text and is the main way IoT botnets (Mirai and friends) take over "
        "cameras, routers and DVRs; nothing made in the last decade needs it.",
        [
            "Identify the device on the Devices page ({vendor}, '{hostname}').",
            "Log in to its web admin page and disable Telnet (often under Administration > Access / Services / Remote Management); enable SSH or HTTPS instead if remote access is needed.",
            "If the device cannot disable Telnet, update its firmware, change the admin password, and move it to the router's guest/IoT network.",
            "Verify: nmap -p {port} {ip}   (should show closed/filtered)",
        ],
        [_NSA_HOME, _CISA_HOME], "lan-services", True,
    ),
    _spec(
        "NET-SVC-002", "high", "FTP open on {ip}:{port}",
        "This device offers file transfer with no encryption",
        "FTP sends usernames and passwords unencrypted across the Wi-Fi and is frequently left with anonymous "
        "access enabled on NAS boxes and printers.",
        [
            "Open the device's admin page and turn off FTP (look under File Services / Sharing / Protocols).",
            "Use SFTP, SMB with a password, or the device's cloud sync instead.",
            "If FTP must stay on: disable anonymous login, set a strong password and restrict it to the LAN.",
        ],
        [_NSA_HOME], "lan-services", True,
    ),
    _spec(
        "NET-SVC-003", "medium", "SMB file sharing on non-Windows device {ip}:{port}",
        "This device shares files on your network: check who can open them",
        "A NAS, TV or camera exposing SMB may have guest access or an old vulnerable Samba build; file shares "
        "are what ransomware encrypts first.",
        [
            "Open the device's admin page and check the file-sharing settings: disable guest/anonymous access and SMBv1, require a password.",
            "Update the device firmware, and if sharing is not needed, turn the service off.",
            "On the Home SOC Devices page mark the device Trusted once reviewed.",
        ],
        [_SMB1, _NSA_HOME], "lan-services", True,
    ),
    _spec(
        "NET-SVC-004", "medium", "Remote desktop (RDP/VNC) exposed on {ip}:{port}",
        "This device offers remote control of its screen to the network",
        "Remote-control services are brute-forced constantly; VNC in particular often has no password or a "
        "trivial one, giving full control of the device.",
        [
            "On the device, disable remote desktop / VNC if not needed (Windows: Settings > System > Remote Desktop; macOS: System Settings > General > Sharing > Screen Sharing).",
            "If needed, set a long password, enable NLA/encryption, and never forward the port on the router.",
        ],
        [_RDP], "lan-services", True,
    ),
    _spec(
        "NET-SVC-005", "low", "HTTP admin interface without HTTPS on {ip}:{port}",
        "This device's admin page sends your password unencrypted when you sign in",
        "Logging in to a router or gadget over plain HTTP sends the admin password in clear text over Wi-Fi.",
        [
            "In the device's admin page look for an 'HTTPS only' / 'Secure web access' option and enable it.",
            "Otherwise only manage the device from a wired or trusted connection and keep its firmware updated.",
        ],
        [_NSA_HOME], "lan-services", True,
    ),
    _spec(
        "NET-SVC-006", "medium", "UPnP / SSDP control port open on {ip}:{port}",
        "This device answers UPnP requests from any device on your network",
        "UPnP (Plug and Play) is designed to let programs on the network change a device's settings, such as "
        "opening ports, without a password; on a router that can let malware open holes to the internet. Home "
        "SOC saw the UPnP port answer; it did not test what the device allows.",
        [
            _ROUTER_ADMIN,
            "Find 'UPnP' (often under Advanced > NAT/Gaming or Firewall) and disable it; set up manual port forwards only for what you really need.",
            "For other devices (TVs, speakers) UPnP discovery is normal; suppress this finding if you accept it.",
        ],
        [_NSA_HOME, _CISA_HOME], "lan-services", True,
    ),
    _spec(
        "NET-SVC-007", "high", "Database port open on {ip}:{port} ({product})",
        "A database on this device is open to the network",
        "Databases like MySQL, Redis and MongoDB often ship without a password; exposed on the LAN they hand "
        "over all their data to anyone who connects.",
        [
            "On the host, configure the database to listen only on 127.0.0.1 (MySQL: bind-address=127.0.0.1; Redis: bind 127.0.0.1 and requirepass; MongoDB: net.bindIp).",
            "Set a strong password / enable authentication and restart the service.",
            "Block the port in the host firewall (Windows: Windows Security > Firewall > Advanced settings > Inbound rule).",
        ],
        [_REDIS_SEC, _MYSQL_SEC], "lan-services", True,
    ),
    _spec(
        "NET-SVC-008", "low", "Printer raw port / IPP without authentication on {ip}:{port}",
        "Any device on your network can reach this printer's print port, which may not ask for a password",
        "Raw port 9100 and unauthenticated IPP let anyone on the network print, read the job queue or, on some "
        "models, change settings and firmware.",
        [
            "Open the printer's web page (http://{ip}) and set an administrator password under Settings / Security.",
            "Disable unused protocols (Raw 9100, FTP, Telnet, SNMP v1/v2) if the printer offers it and keep IPP/AirPrint.",
            "Update the printer firmware and consider moving it to the guest/IoT network.",
        ],
        [_NSA_HOME], "lan-services", True,
    ),
    _spec(
        "NET-SVC-009", "medium", "SNMP with default community on {ip}",
        "This device's settings can be read with a factory-default password",
        "SNMP with the 'public' community string reveals the device's configuration, connected clients and "
        "sometimes lets an attacker change settings.",
        [
            "Open the device's admin page and disable SNMP, or switch to SNMPv3 with a password.",
            "If SNMP v1/v2c must stay, change the community strings from 'public'/'private' to something random.",
        ],
        [_CISA_SNMP], "lan-services", True,
    ),
    _spec(
        "NET-SVC-010", "medium", "RTSP camera stream exposed on {ip}:{port}",
        "This camera's video-stream service can be reached from your network (it may still ask for a password)",
        "Camera streams with no or default passwords are indexed by public sites; if this one has no password, "
        "anyone on the network (or the internet, if forwarded) can watch. Home SOC saw the stream port; it did "
        "not test whether it asks for a password.",
        [
            "Open the camera's app or web page and set a unique strong password; disable RTSP if you only use the app.",
            "Ensure the router does NOT forward this port to the internet (check NET-WAN findings).",
            "Move cameras to the guest/IoT network and update their firmware.",
        ],
        [_CISA_HOME, _NSA_HOME], "lan-services", True,
    ),
    _spec(
        "NET-SVC-011", "low", "Outdated SSH server on {ip}:{port} ({product} {version})",
        "This device runs an old remote-login server, which usually means old firmware",
        "Old SSH builds carry known vulnerabilities and weak ciphers; on routers and NAS boxes it usually "
        "means the whole firmware is old.",
        [
            "Update the device's firmware / operating system (routers: admin page > Firmware update; Linux: sudo apt update && sudo apt upgrade).",
            "If SSH is not used, disable it in the device settings.",
        ],
        [_OPENSSH_REL], "lan-services", True,
    ),
    _spec(
        "NET-SVC-012", "info", "Device {ip} advertises its hardware model on the network ({exposed})",
        "This device announces its exact model to every device on your network",
        "Broadcasting the exact model helps attackers pick the right exploit; it is normal for smart-home "
        "gear and only worth noting.",
        [
            "Nothing to fix; use the model name to check the vendor site for firmware updates.",
            "Mark the device Trusted on the Devices page.",
        ],
        [], "lan-services", True,
    ),
    # ------------------------------------------------------------------ Vulnerabilities
    _spec(
        "NET-VUL-001", "critical", "Known exploited vulnerability {cve} on {ip} ({product} {version})",
        "This device runs software with a flaw attackers are known to have used in real attacks",
        "This flaw is on CISA's list of flaws attackers are known to have used; devices on the affected version "
        "are a common target for automated attacks. Home SOC matched it from the version the device reports.",
        [
            "Read the entry: https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext={cve}",
            "Update the device's firmware or the affected software ({product}) to a fixed version from the vendor.",
            "If no fix exists, disable the affected service or replace the device; at minimum block it from the internet and move it to the guest network.",
        ],
        [_CISA_KEV, _NVD], "vulns", True,
    ),
    _spec(
        "NET-VUL-002", "high", "Possible known-exploited vulnerability {cve} on {ip} ({product})",
        "This device may run software with a flaw attackers are known to have used in real attacks",
        "The software matches a CISA KEV entry but the version could not be confirmed; assume it is vulnerable "
        "until the vendor says otherwise.",
        [
            "Check the device's firmware / software version in its admin page and compare it with the fixed version in the KEV entry: https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext={cve}",
            "Update to the latest firmware; if already current, acknowledge this finding.",
        ],
        [_CISA_KEV], "vulns", True,
    ),
    _spec(
        "NET-VUL-003", "medium", "{count} known CVEs (max CVSS {max_cvss}) for {product} {version} on {ip}",
        "Software on this device matches {count} published security flaws",
        "The service version on this device has published vulnerabilities rated high or critical; an update "
        "closes them all at once.",
        [
            "Update the device firmware or the software ({product}) to the newest version.",
            "Review the CVEs: https://nvd.nist.gov/vuln/search/results?query={product}+{version}",
            "If updates are unavailable, disable the service or restrict it to the devices that need it.",
        ],
        [_NVD], "vulns", True,
    ),
    _spec(
        "NET-VUL-004", "high", "Exploitation likely in the wild: {cves} on {ip}",
        "Software on this device has flaws likely to be exploited somewhere in the next 30 days",
        "EPSS estimates the chance a CVE is exploited somewhere in the wild within 30 days (it says nothing "
        "about whether this home is targeted); above 50% it is among the flaws most likely to be exploited "
        "soon, so these come before the rest of the backlog.",
        [
            "Update {product} {version} on {ip} (port {port}) as a priority - device admin page > Firmware update, "
            "or the vendor's download page for software.",
            "Look each CVE up at https://nvd.nist.gov/vuln/search and check the EPSS score at https://www.first.org/epss/",
            "If no fix exists, block the device from the internet on the router and move it to the guest network.",
        ],
        [_EPSS, _NVD], "vulns", True,
    ),
    # ------------------------------------------------------------------ WAN exposure
    _spec(
        "NET-WAN-001", "critical", "Port {port} is open to the internet on your public IP",
        "An internet-wide scanner found port {port} open on your home internet address",
        "Something on your network is reachable from the whole internet; bots scan every public IP many times "
        "a day and will find and attack it.",
        [
            _ROUTER_ADMIN,
            "Look under Firewall / NAT / Port Forwarding / 'Pinholes' / DMZ and remove the rule for port {port} (and any DMZ host).",
            "Disable UPnP on the router so devices cannot re-open ports.",
            "If you need remote access, use a VPN (WireGuard/Tailscale) instead of forwarding ports.",
            "Re-check from outside: https://internetdb.shodan.io/{public_ip}",
        ],
        [_SHODAN_IDB, _NSA_HOME], "wan", True,
    ),
    _spec(
        "NET-WAN-002", "critical", "Internet-facing vulnerabilities reported for your public IP: {vulns}",
        "Internet-wide scanners list known flaws on your home internet address",
        "Shodan has fingerprinted an exposed service on your public IP with known vulnerabilities; this is the "
        "most likely way your network gets breached.",
        [
            "Identify the exposed service (the NET-WAN-001 findings list the open ports). " + _ROUTER_ADMIN,
            "Under Firewall / NAT / Port Forwarding remove the rule that exposes it (and any DMZ host), then save.",
            "Update the router's firmware (admin page > Firmware / Software update) and restart it.",
            "Look the CVEs up at https://nvd.nist.gov/vuln/search and re-check the exposure at "
            "https://internetdb.shodan.io/{public_ip}",
        ],
        [_SHODAN_IDB, _CISA_KEV], "wan", True,
    ),
    _spec(
        "NET-WAN-003", "high", "UPnP port mapping: WAN {external_port} -> {internal_client}:{internal_port} ({description})",
        "A device opened port {external_port} on your router to the internet by itself",
        "A device on your network opened a hole in the router by itself; games and consoles do this, but so "
        "does malware.",
        [
            "Check whether {internal_client} is a console/PC that needs the port (game hosting); otherwise remove the mapping.",
            _ROUTER_ADMIN,
            "Disable UPnP (Advanced > NAT / Firewall / UPnP) and delete existing mappings; add manual forwards only if truly needed.",
        ],
        [_NSA_HOME], "wan", True,
    ),
    _spec(
        "NET-RTR-002", "medium", "Router has UPnP (IGD) enabled",
        "Your router lets devices open doors to the internet without asking",
        "With UPnP on, any program on any device can open ports on your router without asking; turning it "
        "off stops malware from exposing your network.",
        [
            _ROUTER_ADMIN,
            "Find 'UPnP' (Advanced > NAT/Gaming, Firewall, or Home Network) and set it to Off; save and reboot the router.",
            "If a console complains about NAT type, add a manual port forward for that console only.",
        ],
        [_NSA_HOME, _CISA_HOME], "wan", False,
    ),
    # ------------------------------------------------------------------ Wi-Fi
    _spec(
        "NET-WIFI-001", "critical", "Wi-Fi '{ssid}' is open or uses WEP",
        "Anyone nearby can get onto Wi-Fi '{ssid}': it is open or uses broken encryption",
        "Open and WEP networks let anyone nearby read your traffic and join your LAN; WEP can be cracked "
        "in minutes.",
        [
            _ROUTER_ADMIN,
            "Under Wireless / Wi-Fi security choose 'WPA2-Personal (AES)' or 'WPA3/WPA2 mixed' and set a long passphrase (12+ characters).",
            "Reconnect your devices with the new passphrase.",
        ],
        [_WIFI_SEC, _NSA_HOME], "wifi", False,
    ),
    _spec(
        "NET-WIFI-002", "info", "Wi-Fi '{ssid}' uses WPA2 without WPA3",
        "Wi-Fi '{ssid}' could use the newer, stronger security setting",
        "WPA2 is still acceptable, but WPA3 protects against offline password guessing; enable it if your "
        "router and devices support it.",
        [
            _ROUTER_ADMIN,
            "Under Wireless security choose 'WPA3/WPA2 mixed' (transition mode) so old devices keep working.",
        ],
        [_WIFI_SEC], "wifi", False,
    ),
    _spec(
        "NET-WIFI-003", "high", "Wi-Fi '{ssid}' uses TKIP encryption",
        "Wi-Fi '{ssid}' uses an old, weak kind of encryption",
        "TKIP is a 2003 stop-gap cipher with known attacks; modern devices support AES (CCMP) and it also "
        "slows your network down.",
        [
            _ROUTER_ADMIN,
            "Under Wireless security set the encryption to 'AES' / 'CCMP' only (not 'TKIP' or 'TKIP+AES') and save.",
        ],
        [_WIFI_SEC], "wifi", False,
    ),
    _spec(
        "NET-WIFI-004", "info", "WPS appears to be enabled on '{ssid}'",
        "Wi-Fi '{ssid}' seems to have WPS on, a join-by-PIN feature whose PIN can be guessed",
        "WPS PIN mode can be brute-forced in hours on many routers, bypassing your Wi-Fi password entirely.",
        [
            _ROUTER_ADMIN,
            "Under Wireless > WPS set it to Off / Disabled and save; connect new devices with the passphrase instead.",
        ],
        [_WIFI_SEC, _NSA_HOME], "wifi", False,
    ),
    # ------------------------------------------------------------------ DNS filter
    _spec(
        "NET-DNS-001", "info", "Devices are not using the Home SOC DNS filter",
        "Most devices are not using Home SOC's web blocking yet",
        "The filter only protects devices that send their DNS queries to this PC; right now almost nobody "
        "does, so ads and malicious domains are not being blocked LAN-wide.",
        [
            _ROUTER_ADMIN,
            "Under LAN / DHCP settings set the primary DNS server to this PC's IP ({ip}) and save; devices pick it up when they reconnect.",
            "Give this PC a static IP or DHCP reservation on the router so the address does not change.",
            "Right-click scripts/enable-lan-dns.ps1 > 'Run with PowerShell' as administrator: it allows inbound DNS in the Windows firewall and prints the router steps for you.",
        ],
        [_CF_DNS, _QUAD9], "dns", False,
    ),
    _spec(
        "NET-DNS-002", "high", "DNS resolver is not running ({reason})",
        "Web blocking is not running ({reason})",
        "If devices point at this PC for DNS and the resolver is down, they lose internet access; if another "
        "program holds port 53, the filter cannot start.",
        [
            "Check what is using the port: PowerShell: Get-NetUDPEndpoint -LocalPort 53; Get-Process -Id <OwningProcess>",
            "Stop the conflicting program (often a leftover Docker/WSL DNS or another ad-blocker) or change 'dns.port' in config.toml.",
            "Restart Home SOC and check the DNS page shows 'running'.",
        ],
        [], "dns", False,
    ),
    _spec(
        "NET-DNS-003", "medium", "DNS blocklists are stale ({age_days} days)",
        "Web blocking's lists of bad sites are {age_days} days old",
        "Malicious domains change daily; with old lists the filter misses this week's phishing and malware sites.",
        [
            "Open the Home SOC Overview page and click 'Update feeds'; check the Feeds table for errors.",
            "If updates fail, verify the PC has internet access and that no proxy blocks the list URLs.",
            "CLI: python -m homesoc update --force",
        ],
        [], "dns", False,
    ),
    _spec(
        "NET-DNS-004", "high", "{client} tried to reach a malicious domain: {domain}",
        "A device looked up a website known for malware or scams: {domain}",
        # The reputation check runs after the answer has gone out (it must never delay a lookup, and
        # only lookups that were answered are checked), so the lookup that raised this finding was
        # NOT blocked; the domain is blocked from then on (dnsfilter/server.py _on_malicious).
        "A device on your network asked for a domain known for malware, phishing or botnet control. The check "
        "runs after the answer is sent, so that first lookup went through; Home SOC blocks the domain from then "
        "on, but the device may already be infected or a user clicked a phishing link.",
        [
            "Identify the device {client} on the Devices page.",
            "If it is a PC: run a full Defender scan and check recent downloads; if a phone/IoT device: update it, review installed apps, or factory-reset it.",
            "Look at the DNS query log for that client to see what else it contacted; check the domain at https://www.virustotal.com/gui/domain/{domain}",
            "If it is a false positive, add an 'allow' override on the DNS page.",
        ],
        [_VT, _CISA_HOME], "dns", True,
    ),
    _spec(
        "NET-DNS-005", "high", "DNS upstream resolvers are unreachable",
        "Web blocking cannot reach its outside lookup services, so devices using it may lose internet",
        "The filter cannot answer queries it does not have cached, so devices using it are losing internet access.",
        [
            "Check the PC's own internet connection and that outbound UDP port 53 is not blocked by a VPN or firewall.",
            "Try: nslookup example.com 1.1.1.2   and   nslookup example.com 9.9.9.9",
            "If a VPN is active, add its DNS server to 'dns.upstreams' in config.toml, or enable 'doh_upstream'.",
        ],
        [_CF_DNS, _QUAD9], "dns", False,
    ),
    _spec(
        "NET-DNS-006", "info", "Resolver is bound to the LAN but no firewall rule allows DNS in",
        "Web blocking is running, but the firewall keeps other devices from using it",
        "Other devices cannot reach the filter until Windows Firewall allows inbound UDP/TCP 53; the resolver "
        "is running but only this PC benefits.",
        [
            "Right-click scripts/enable-lan-dns.ps1 > 'Run with PowerShell' (accept the UAC prompt).",
            "PowerShell (admin): New-NetFirewallRule -DisplayName \"Home SOC DNS\" -Direction Inbound -Protocol UDP -LocalPort 53 -Action Allow -Profile Private",
        ],
        [_FW_DOCS], "dns", False,
    ),
    # ------------------------------------------------------------------ Dependencies / blast radius
    # These three are the only findings whose evidence is about *the rest of the network* rather
    # than the subject device. Their wording has to survive the feature's defining limit: Home SOC
    # has no packet visibility, so it never knows that two devices talk to each other. Every claim
    # below is either something it watched (a DNS query, an advertisement, devices dropping in the
    # same discovery cycle) or something the shape of the network forces (everything reaches the
    # internet through the gateway). Nothing here may read as "we saw traffic".
    _spec(
        "NET-DEP-001", "info", "{name} has become load-bearing: {dependents} devices now depend on it",
        "{name} has quietly become important: {dependents} devices now depend on it",
        "Nothing is wrong with this device. The point is that it quietly grew important: the dependency map "
        "now counts {dependents} others whose network path or whose services run through it, which is more than "
        "the threshold in your settings. A box that started as 'the thing in the cupboard' is now the thing that "
        "takes half the house with it when it reboots — and because that happens slowly, nobody notices until "
        "the evening it fails and the failure looks like five unrelated problems at once.",
        [
            "Open the Map page (/map) and click {name}. The side panel names every device that depends on it and "
            "says, in one sentence, what the house loses if it stops — that sentence is the thing worth knowing.",
            "Check the confidence marks on its edges before you act on them: solid means Home SOC watched it "
            "happen, dashed means it follows from the network's shape, dotted means it is only assumed. "
            "Dotted edges are a prompt to check, not a fact.",
            "If this device now carries several roles at once (router and DNS and file shares and a smart-home "
            "hub), consider moving one of them somewhere else. Splitting roles is what turns a total outage into "
            "a partial one.",
            "Give it a nickname on the Devices page so it is recognisable in an outage, and note where it is "
            "physically plugged in. During a failure you want to know which box and which socket, not which IP.",
            "If it must stay this important, treat it accordingly: mains-filtered or UPS-backed power, a shelf "
            "with airflow, and firmware updates you actually apply.",
        ],
        [_SPOF, _NSA_HOME, _CISA_HOME], "topology", True,
    ),
    _spec(
        "NET-DEP-002", "medium",
        "{name} is a single point of failure: {affected} devices have gone offline with it on {outages} separate occasions",
        "{affected} devices have gone offline around the same time as {name}, on {outages} occasions",
        "This one is not modelled, it is remembered. On {dates}, {affected} devices dropped off the network in the "
        "same discovery cycle as {name} and came back with it. Home SOC only says this after watching it happen at "
        "least twice, so it is a pattern rather than a coincidence. There is nothing to patch here: the finding is "
        "that the house has no second path for whatever this device provides, and that when it next fails you will "
        "spend the first twenty minutes rebooting the wrong things.",
        [
            "Read the blast radius first: open the Map page (/map), click {name}, and note the sentence and the "
            "list of what goes with it. That list is your outage checklist. The dates this already happened on: "
            "{dates}.",
            "Write that checklist down somewhere that works when the network does not — a card taped inside the "
            "cupboard door, or a note in your phone: 'if the internet, printing or music stops, check {name} first', "
            "with the room it is in. A troubleshooting list that lives behind the failing device is useless.",
            "Now remove the single point where you can. If this device is the resolver, put a public resolver "
            "(1.1.1.1 or 9.9.9.9) in the router's *secondary* DNS field so a failure degrades into unfiltered "
            "internet instead of no internet — and know the honest caveat: clients fail over slowly and "
            "inconsistently, so a secondary softens an outage, it does not erase it.",
            "If it is the only route to the internet, your redundancy is a phone hotspot you have actually tested "
            "once, not a second router you have never configured.",
            "Split the roles it carries. A spare Raspberry Pi running the DNS resolver is the cheapest version of "
            "this: it removes DNS from the list of things that die with this device, and it makes the map far "
            "richer, because every device's lookups become visible. docs/TOPOLOGY.md has the details; the Map "
            "page links to it.",
            "Check the boring physical causes before buying anything: the power strip it shares, a failing PSU, a "
            "hot shelf, a half-seated cable. Repeated whole-group outages are far more often power than firmware.",
            "Rehearse it once on a quiet afternoon: unplug it for two minutes and note what actually stops. Where "
            "reality and the map disagree, trust reality — Home SOC cannot see traffic between devices, so the map "
            "is the floor of what depends on this, never the ceiling.",
        ],
        [_SPOF, _RFC2182, _CF_DNS, _QUAD9, _NSA_HOME], "topology", True,
    ),
    _spec(
        "NET-DEP-003", "info",
        "{name} keeps trying to reach {domain} and never gets through ({failures} lookups, every one blocked)",
        "{name} keeps trying to look up {domain}, and web blocking stops it every time",
        "This device depends on {domain} for something, and across the whole window every single lookup was blocked "
        "and not one was ever answered. The device will not tell you that. Cameras, doorbells, plugs, televisions and "
        "speakers route their features through a vendor's cloud, and when that path is cut they usually keep their "
        "lights on and go quiet: the app still lists the device, but notifications stop arriving, recordings stop "
        "uploading, schedules stop firing, or it quietly stops fetching its own firmware updates. Often that is "
        "exactly what you wanted — a television's advertising endpoints belong on a blocklist. Sometimes it is a "
        "feature you believe you still have. This finding is how you get to decide which, instead of finding out in "
        "six months.",
        [
            "Decide first whether you want this connection at all. If {domain} is analytics or advertising for a "
            "device that works perfectly well without it, this is the filter doing its job: nothing to fix.",
            "If the device is meant to use it, open the DNS page (/dns), filter the query log to this device and "
            "search for {domain}. The 'reason' column names the blocklist that matched.",
            "Check it from this computer too:  python -m homesoc dns-test {domain}   — it prints the policy decision "
            "and the upstream's answer, which separates 'we blocked it' from 'it is genuinely gone'.",
            "To let it through, add an 'allow' override for {domain} on the DNS page, then power-cycle the device so "
            "it retries instead of sitting on a cached failure.",
            "Then actually test the feature that depends on it — press the doorbell, ask for a recording, check the "
            "notification reaches your phone. Nothing else is going to tell you whether it came back.",
            "If the endpoint is gone for good (a discontinued product, a vendor that shut the service down), that is "
            "worth knowing on its own: the device will probably never get another firmware update, which changes how "
            "much you should trust it on the main network rather than on a guest/IoT one.",
        ],
        [_FTC_IOT, _CISA_HOME], "topology", True,
    ),
    # ------------------------------------------------------------------ SOC health
    _spec(
        "SOC-FEED-001", "medium", "Feed '{name}' has been failing for {hours} hours",
        "Home SOC could not update its '{name}' threat list for {hours} hours",
        "Without fresh threat-intel feeds the DNS filter and vulnerability matching slowly go blind.",
        [
            "Open the Overview page > Feeds table and read the error for '{name}'.",
            "Check internet access; if the source URL has moved, disable the feed in settings and open an issue.",
            "CLI: python -m homesoc update --feeds {name} --force",
        ],
        [], "soc", True,
    ),
    _spec(
        "SOC-FEED-002", "medium", "CISA KEV catalog is stale ({hours} hours)",
        "Home SOC's list of flaws criminals are exploiting is {hours} hours old",
        "The KEV list is what turns 'a CVE exists' into 'criminals are exploiting this now'; a stale copy means "
        "new critical alerts are missed.",
        [
            "Click 'Update feeds' on the Overview page, or run: python -m homesoc update --feeds kev --force",
            "If it keeps failing, verify https://www.cisa.gov is reachable from this PC.",
        ],
        [_CISA_KEV], "soc", False,
    ),
    _spec(
        "SOC-SYS-001", "info", "nmap is not installed; using the built-in Python scanner",
        "Home SOC is using its basic scanner, so it cannot tell software versions",
        "The fallback scanner finds open ports but cannot identify product versions, so vulnerability matching "
        "is much weaker.",
        [
            "Download nmap from https://nmap.org/download.html and install it (Npcap is optional; connect scans work without it).",
            "Restart Home SOC; the Scans page should show 'nmap' as the method.",
        ],
        [_NMAP_DL, _NPCAP], "soc", False,
    ),
    _spec(
        "SOC-SYS-002", "info", "Home SOC is not running as administrator; skipped: {skipped}",
        "Some checks were skipped because Home SOC is not running as administrator",
        "Some checks (Secure Boot, TPM, BitLocker, Security event log) need elevation; they show as 'needs admin' "
        "rather than pass/fail.",
        [
            "This is fine for daily use. To run those checks once: open Start, type 'PowerShell', right-click it and choose 'Run as administrator'.",
            "In that window run:  cd \"{project_root}\"",
            "Then run:  .venv\\Scripts\\python.exe -m homesoc scan --only host   (if there is no .venv folder, use: python -m homesoc scan --only host)",
            "The results appear on the dashboard's Host posture page; Home SOC itself keeps running without administrator rights.",
        ],
        [], "soc", False,
    ),
    _spec(
        "SOC-SYS-003", "high", "Dashboard is reachable from the LAN without a token",
        "Anyone on your Wi-Fi can open this dashboard without an access code",
        "Anyone on your Wi-Fi could open the dashboard, read your findings and device list, and trigger scans "
        "or change settings.",
        [
            "Open config.toml and set web.token to a long random string (PowerShell: -join ((48..57)+(97..122) | Get-Random -Count 32 | ForEach-Object {{[char]$_}})).",
            "Or set web.host back to \"127.0.0.1\" if you only use the dashboard on this PC.",
            "Restart Home SOC; open http://<this-pc>:8787/login?token=<your token> on other devices.",
            # Lens deliberately binds to the LAN, so "go back to 127.0.0.1" is not advice a Lens
            # user can follow; setting web.token is, and it is the fix that covers both.
            "If you use Lens on your phone, keep web.host on the LAN address and set web.token: your phone signs in "
            "with its own paired Lens token (python -m homesoc lens pair), not with this one.",
        ],
        [], "soc", False,
    ),
    _spec(
        "SOC-LENS-001", "medium", "Lens is reachable on the LAN over plain HTTP",
        "Lens on your phone is not set up with encryption, so it cannot be used safely",
        # The consequence depends on lens.require_https, so this says which is which rather than
        # asserting the worse one. With the shipped default (true) nothing crosses the network
        # at all — Lens refuses every plain-HTTP request from anything but this PC — and claiming
        # otherwise would contradict this entry's own last fix step.
        "Lens is bound to the LAN and Home SOC is not serving TLS. While lens.require_https is true (the "
        "default) Lens refuses every plain-HTTP request from anything but this PC, so the phone cannot pair "
        "or show anything: Lens is simply unusable until you start with --tls. If you turn require_https off "
        "to get past that, the pairing code, the phone's long-lived token and everything Lens shows — your "
        "device list, open ports, vulnerabilities and the domains each device talks to — cross the Wi-Fi in "
        "clear text where anyone on it can read and reuse them. Phone browsers also refuse camera access on a "
        "plain-HTTP page, so scanning never works either way. Either way the fix is the same: serve it over TLS.",
        [
            "Install the certificate builder once:  pip install cryptography   (Home SOC runs fine without it; only TLS needs it).",
            "Create a certificate that covers this PC and its LAN address:  python -m homesoc lens cert --regenerate --hosts <this-pc>,192.168.1.10",
            "Start Home SOC with TLS:  python -m homesoc serve --tls --host 0.0.0.0 --port 8443   (the startup log prints the certificate fingerprint).",
            "On the phone open https://<this-pc>:8443/lens, compare the fingerprint with the one in the log, and accept it once.",
            "Easier alternative with a certificate the phone already trusts: run Home SOC behind Tailscale Serve (see docs/LENS_SETUP.md), then no warning appears at all.",
            "Leave lens.require_https = true in config.toml — it is the only thing stopping the pairing code and the phone's token from crossing the network in clear text; set lens.enabled = false if you are not using Lens.",
        ],
        [_TAILSCALE_SERVE, _SECURE_CONTEXTS], "soc", False,
    ),
    _spec(
        "SOC-SYS-004", "medium", "Scheduled job '{job}' keeps failing ({failures} times)",
        "Part of Home SOC's monitoring keeps failing: '{job}' ({failures} times in a row)",
        "A job that fails repeatedly means part of the monitoring is silently not happening.",
        [
            "Open the Telemetry page > Jobs table and read the last error for '{job}'.",
            "Check data/logs/homesoc.log for the traceback; common causes are a missing tool, no internet, or a permissions issue.",
        ],
        [], "soc", True,
    ),
]

CATALOG: dict[str, FindingSpec] = {s.id: s for s in _SPECS}
assert len(CATALOG) == len(_SPECS), "duplicate finding IDs in catalog"


def get(finding_id: str) -> FindingSpec | None:
    return CATALOG.get(finding_id)


def all_ids() -> list[str]:
    return sorted(CATALOG)


def by_category() -> dict[str, list[FindingSpec]]:
    out: dict[str, list[FindingSpec]] = {}
    for spec in CATALOG.values():
        out.setdefault(spec.category, []).append(spec)
    return out


def _subject_fields(subject: str) -> dict[str, str]:
    """Derive placeholder values from the subject so templates work even with thin evidence.

    Subjects follow "kind:identifier[:port]"; a scanner that forgets to put the MAC or port in
    evidence still gets a readable title.
    """
    parts = subject.split(":")
    fields: dict[str, str] = {"subject": subject}
    if not parts:
        return fields
    kind = parts[0]
    if kind == "device" and len(parts) >= 2:
        # MACs contain colons, so re-join the middle and treat a trailing pure number as the port.
        rest = parts[1:]
        if len(rest) > 1 and rest[-1].isdigit():
            fields["port"] = rest[-1]
            rest = rest[:-1]
        fields["mac"] = ":".join(rest)
    elif kind == "dns" and len(parts) >= 2:
        fields["client"] = ":".join(parts[1:])
    elif kind == "feed" and len(parts) >= 2:
        fields["name"] = parts[1]
    elif kind == "job" and len(parts) >= 2:
        fields["job"] = ":".join(parts[1:])
    elif kind == "wifi" and len(parts) >= 2:
        fields["interface"] = ":".join(parts[1:])
    return fields


def _clean_evidence(evidence: Any) -> dict[str, Any]:
    """Evidence as display values: None becomes empty, containers become readable text.

    Scalars are left untouched so ``json_evidence`` still shows the raw types for unknown IDs.
    """
    if not isinstance(evidence, dict):
        return {}
    return {str(k): ("" if v is None else _display(v)) for k, v in evidence.items()}


def _fmt(template: str, values: SafeDict) -> str:
    try:
        return template.format_map(values)
    except (ValueError, IndexError, AttributeError, TypeError):
        # A stray brace inside evidence text must not break rendering.
        return template


class Rendered(tuple):
    """``render()``'s result: still exactly the 2-tuple ``(title, detail)`` every caller unpacks,
    with the plain-language headline riding along as ``.plain_title``.

    A third tuple element would break ``title, detail = catalog.render(d)`` everywhere, so the
    friendly line is an attribute instead. It is "" for an ID the catalog does not know, which
    tells the caller to fall back to the technical title rather than inventing wording.
    """

    plain_title: str

    def __new__(cls, title: str, detail: str, plain_title: str = "") -> "Rendered":
        obj = super().__new__(cls, (title, detail))
        obj.plain_title = plain_title
        return obj

    @property
    def title(self) -> str:
        return self[0]

    @property
    def detail(self) -> str:
        return self[1]


# Evidence is best-effort, so a placeholder can be present but empty ("({state})" -> "()"). The
# technical title keeps that as-is (it is data), but the plain line is read by people who should not
# have to parse an empty pair of brackets or quotes.
_EMPTY_QUOTES = re.compile(r"\s*(?:'\s*'|“\s*”)")
_EMPTY_PARENS = re.compile(r"\s*\(\s*\)")


def _values(evidence: Any, subject: str) -> SafeDict:
    values = SafeDict(_clean_evidence(_subject_fields(subject)))
    values.update(_clean_evidence(evidence))
    return values


def _plain(spec: FindingSpec, values: SafeDict) -> str:
    text = one_line(_fmt(spec.plain_title, values))
    text = _EMPTY_PARENS.sub("", _EMPTY_QUOTES.sub("", text))
    return re.sub(r"\s{2,}", " ", text).strip()


def render(draft: Any) -> Rendered:
    """Return (title, detail) for a FindingDraft-like object using the catalog templates.

    The result also carries ``.plain_title`` (see ``Rendered``); unpacking it as a pair still works.
    """
    spec = get(getattr(draft, "finding_id", ""))
    subject = str(getattr(draft, "subject", "") or "")
    values = _values(getattr(draft, "evidence", None), subject)
    if spec is None:
        # SPEC-GAP: unknown IDs are tolerated (logged) so a typo in a scanner does not drop the finding.
        logger.warning("finding id %s is not in the catalog", getattr(draft, "finding_id", "?"))
        title = one_line(f"{getattr(draft, 'finding_id', 'UNKNOWN')} on {subject}")
        detail = getattr(draft, "detail", None) or json_evidence(values)
        return Rendered(title, detail)
    # The title is always one line whatever the template or evidence holds: notifications and the
    # CLI print one finding per line.
    title = one_line(_fmt(spec.title, values))
    detail = getattr(draft, "detail", None) or _fmt(spec.rationale, values)
    return Rendered(title, detail, _plain(spec, values))


def render_plain_title(finding_id: str, evidence: dict[str, Any] | None = None, subject: str = "") -> str:
    """The plain-language headline for a stored finding (``finding_id`` + evidence + subject).

    Same interpolation and the same SafeDict/one-line protection as the technical title. Returns ""
    for an unknown ID so the caller shows the technical title instead.
    """
    spec = get(finding_id)
    if spec is None:
        return ""
    return _plain(spec, _values(evidence, subject))


def render_why(finding_id: str, evidence: dict[str, Any] | None = None, subject: str = "") -> str:
    """"Why it matters" for a stored finding: the catalog rationale with evidence filled in.

    A few rationales carry placeholders (NET-DEP-*, NET-DEV-004), so the raw ``spec.rationale`` is
    not display-ready on its own. Returns "" for an unknown ID.
    """
    spec = get(finding_id)
    if spec is None:
        return ""
    return _fmt(spec.rationale, _values(evidence, subject))


def render_remediation(finding_id: str, evidence: dict[str, Any] | None, subject: str = "") -> list[str]:
    """Remediation steps with evidence interpolated, for the dashboard detail view."""
    spec = get(finding_id)
    if spec is None:
        return []
    values = _values(evidence, subject)
    return [_fmt(step, values) for step in spec.remediation]


def placeholders(finding_id: str) -> set[str]:
    """Every ``{field}`` name used by this ID's title, plain title and remediation steps."""
    spec = get(finding_id)
    if spec is None:
        return set()
    names: set[str] = set()
    for template in [spec.title, spec.plain_title, *spec.remediation]:
        try:
            parsed = Formatter().parse(template)
            names.update(f for _, f, _, _ in parsed if f)
        except ValueError:  # a stray brace in the template itself
            continue
    return names


def unresolved_placeholders(finding_id: str, evidence: dict[str, Any] | None, subject: str = "") -> list[str]:
    """Placeholders this evidence cannot fill, i.e. the ones that would render as "unknown".

    Scanners and the catalog are edited by different people; when an emitter renames an evidence
    key the only symptom is a title like "Scheduled job 'unknown' keeps failing". This is the
    check that turns that into a test failure instead.
    """
    values = SafeDict(_subject_fields(subject))
    values.update(_clean_evidence(evidence))
    missing = []
    for name in sorted(placeholders(finding_id)):
        if values.get(name) not in (None, "") or name in _PLACEHOLDER_DEFAULTS:
            continue
        if any(values.get(alias) not in (None, "") for alias in _ALIASES.get(name, ())):
            continue
        missing.append(name)
    return missing


def severity_for(draft: Any) -> str:
    """Draft severity wins (scanners escalate, e.g. WIN-UPD-001 -> high); otherwise the catalog default."""
    sev = getattr(draft, "severity", None)
    if sev in SEVERITIES:
        return sev
    spec = get(getattr(draft, "finding_id", ""))
    return spec.severity if spec else "medium"


def json_evidence(values: dict[str, Any]) -> str:
    import json

    try:
        return json.dumps({k: v for k, v in values.items() if k != "subject"}, sort_keys=True, default=str)
    except (TypeError, ValueError):
        return str(values)
