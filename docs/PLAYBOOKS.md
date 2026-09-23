# Remediation playbooks

Every issue Home SOC can report, what it means for a home network, and exactly how to fix it.

There are **92 findings** in the catalog. A scanner never writes its own wording: it emits a
finding ID plus evidence, and everything you read below — the title, the reason it matters, the
numbered steps, the links — comes from `homesoc/findings/catalog.py`. That is why the dashboard,
the terminal (`python -m homesoc findings`), the exported report (`python -m homesoc report`) and
this page always say the same thing. **This document is generated from that file** — the entries
below, the summary table and the "needs administrator" lists are rendered from the catalog, the
scanner modules and the non-admin posture fixture. Do not edit the finding entries by hand; if a
step here differs from your dashboard, the dashboard is right and this page needs regenerating.

Nothing in a playbook is done for you. Home SOC observes and explains; you decide and click.

## Contents

- [How findings work](#how-findings-work)
- [Severity levels](#severity-levels)
- [The security score](#the-security-score)
- [Checks that need administrator rights](#checks-that-need-administrator-rights)
- [Every finding at a glance](#every-finding-at-a-glance)
- [Microsoft Defender antivirus](#microsoft-defender-antivirus) — `WIN-DEF-001`, `WIN-DEF-002`, `WIN-DEF-003`, `WIN-DEF-004`, `WIN-DEF-005`, `WIN-DEF-006`, `WIN-DEF-007`, `WIN-DEF-008`, `WIN-DEF-009`, `WIN-DEF-010`, `WIN-DEF-011`, `WIN-DEF-012`, `WIN-DEF-013`, `WIN-DEF-014`
- [Windows Firewall](#windows-firewall) — `WIN-FW-001`, `WIN-FW-002`
- [Updates and outdated software](#updates-and-outdated-software) — `WIN-UPD-001`, `WIN-UPD-002`, `WIN-UPD-003`, `WIN-UPD-004`
- [Accounts and sign-in](#accounts-and-sign-in) — `WIN-ACC-001`, `WIN-ACC-002`, `WIN-ACC-003`, `WIN-ACC-004`, `WIN-ACC-005`
- [Network services on this PC](#network-services-on-this-pc) — `WIN-NET-001`, `WIN-NET-002`, `WIN-NET-003`, `WIN-NET-004`, `WIN-NET-005`, `WIN-NET-006`
- [System hardening](#system-hardening) — `WIN-SYS-001`, `WIN-SYS-002`, `WIN-SYS-003`, `WIN-SYS-004`, `WIN-SYS-005`, `WIN-SYS-006`, `WIN-SYS-007`, `WIN-SYS-008`
- [Autostart and persistence](#autostart-and-persistence) — `WIN-PER-001`, `WIN-PER-002`, `WIN-PER-003`
- [Downloaded files](#downloaded-files) — `AV-FILE-001`, `AV-FILE-002`
- [Linux and macOS hosts](#linux-and-macos-hosts) — `POSIX-ENC-001`, `POSIX-FW-001`, `POSIX-NET-001`, `POSIX-SSH-001`, `POSIX-UPD-001`
- [Devices on your network](#devices-on-your-network) — `NET-DEV-001`, `NET-DEV-002`, `NET-DEV-003`, `NET-DEV-004`
- [Services exposed by devices on the LAN](#services-exposed-by-devices-on-the-lan) — `NET-SVC-001`, `NET-SVC-002`, `NET-SVC-003`, `NET-SVC-004`, `NET-SVC-005`, `NET-SVC-006`, `NET-SVC-007`, `NET-SVC-008`, `NET-SVC-009`, `NET-SVC-010`, `NET-SVC-011`, `NET-SVC-012`
- [Known vulnerabilities (CVE / KEV / EPSS)](#known-vulnerabilities-cve--kev--epss) — `NET-VUL-001`, `NET-VUL-002`, `NET-VUL-003`, `NET-VUL-004`
- [Internet-facing exposure](#internet-facing-exposure) — `NET-RTR-002`, `NET-WAN-001`, `NET-WAN-002`, `NET-WAN-003`
- [Wi-Fi security](#wi-fi-security) — `NET-WIFI-001`, `NET-WIFI-002`, `NET-WIFI-003`, `NET-WIFI-004`
- [DNS filter](#dns-filter) — `NET-DNS-001`, `NET-DNS-002`, `NET-DNS-003`, `NET-DNS-004`, `NET-DNS-005`, `NET-DNS-006`
- [Home SOC's own health](#home-socs-own-health) — `SOC-FEED-001`, `SOC-FEED-002`, `SOC-SYS-001`, `SOC-SYS-002`, `SOC-SYS-003`, `SOC-SYS-004`

---

## How findings work

A finding is not an event log line. It is a **problem that exists until it stops existing**, and it
carries a small lifecycle so that a rescan can tell you something new instead of repeating itself.

### One problem, one row

Scanners are stateless: every service scan re-reports the Telnet port on your printer. The findings
engine collapses those repeats into a single row using a *dedupe key* — the finding ID plus the
subject it is about (`host`, `device:aa:bb:cc:dd:ee:ff`, `device:<mac>:23`, `wan`, `wifi`,
`feed:kev`, `job:discovery`), plus one more identifier when a single subject can have several
distinct instances of the same problem (one autostart entry, one CVE, one threat name).

A repeat sighting bumps `occurrences` and refreshes `last_seen` and the evidence. It does not create
a second row and it does not re-notify you. `first_seen` therefore tells you how long the problem
has really been there.

### The four statuses

| Status | What it means | How a finding gets there |
|---|---|---|
| **open** | The problem is present and nobody has decided anything about it. | The default when a finding is first seen, and when a resolved finding comes back. |
| **acknowledged** | "I have seen this, I am not fixing it right now." | You click Acknowledge. It leaves the open list but keeps costing you a quarter of its severity in the security score — the risk did not go away just because you looked at it. |
| **resolved** | The problem is fixed. | Either you click Resolve, or the agent stops seeing it and auto-resolves it (below). Resolved findings stop counting against the score. |
| **suppressed** | "This is fine on my network, stop telling me." | You click Suppress. A suppressed finding keeps updating `last_seen` in the background but never resurfaces, never notifies, and never counts against the score — and, importantly, a rescan will not undo your decision. |

Every transition is written to a `finding_events` row (`opened`, `acknowledged`, `resolved`,
`suppressed`, `reopened`, `auto_resolved`), which is what the Feed page and the "time to remediate"
statistics on the Summary page are built from.

### Auto-resolve, and why it is the good kind of "fixed"

When a scan finishes, it tells the engine which part of the world it just looked at — its *scope*.
A host scan owns `host`; a service scan owns the specific devices it actually finished; the WAN
scan owns `wan`. Any finding from that same source, inside that scope, that the scan **did not**
report this time is closed automatically with an `auto_resolved` event.

That is a meaningfully different statement from clicking Resolve:

- **`marked fixed`** (manual) means *you* said it was fixed. Nobody checked.
- **`verified by rescan`** (auto) means Home SOC went and looked again, in the same place, with the
  same check, and the problem was no longer there.

The Summary page and the exported report label every remediated finding with one of those two
badges for exactly this reason. When you fix something, the honest move is to run the relevant scan
again and let it auto-resolve, rather than resolving it by hand.

Three details worth knowing:

- **Auto-resolve is scoped, not global.** A discovery scan cannot resolve a Defender finding. If a
  scan fails or never runs, its findings simply stay open — silence is never read as good news.
- **A device that was merely asleep does not lose your decision.** If a finding you had
  *acknowledged* auto-resolves and then comes back on the next scan, it returns as *acknowledged*,
  not as a fresh unread problem.
- **Suppressed findings are never auto-resolved.** A user decision is not something a rescan gets to
  undo.

If a resolved problem reappears, the row is **reopened** (with a `reopened` event) rather than
duplicated — so the history of a recurring issue stays in one place.

### Where you interact with them

- Dashboard: `/findings` (filter, expand, Acknowledge / Resolve / Suppress / Reopen) and `/summary`
  (the "still open — what to do next" worklist, with these same steps inline).
- Terminal: `python -m homesoc findings --status open --severity high`
- Report: `python -m homesoc report --days 30 --format md` writes a standalone document containing
  the open worklist with its full remediation steps.

## Severity levels

Severity answers "how bad is this if it is real", not "how likely is it". Home SOC uses five levels.

| Severity | Meaning for a home network | Typical examples |
|---|---|---|
| **critical** | Actively dangerous right now. Something is either exploitable from outside your home, or your last line of defence is off. Fix today. | `WIN-DEF-001` antivirus disabled, `NET-VUL-001` a service matching a CISA KEV entry, `NET-WAN-001` a port open to the internet, `NET-SVC-001` Telnet on a LAN device |
| **high** | A real hole that a competent attacker, or ordinary malware, would use. Fix this week. | `WIN-SYS-002` no disk encryption, `WIN-ACC-003` Guest account enabled, `NET-WAN-003` a UPnP port mapping, `NET-DNS-004` a device reached a known-malicious domain |
| **medium** | Weakens your defences or increases the blast radius of some other mistake. Worth scheduling. | `WIN-DEF-004` tamper protection off, `WIN-PER-001` a new autostart entry, `NET-DEV-001` an unfamiliar device joined |
| **low** | Hardening. Nothing is broken; the machine could be a bit harder to attack. | `WIN-SYS-005` PowerShell v2 still enabled, `WIN-UPD-003` an outdated app, `NET-SVC-008` an open printer port |
| **info** | Context, not a problem. Recorded so the timeline is complete. | `SOC-SYS-002` not running as administrator, `NET-WIFI-002` WPA2 without WPA3, `NET-DEV-002` a randomized MAC address |

Two things to keep in mind:

- **The catalog severity is a default.** Three findings are re-graded from their own evidence at
  scan time — pending updates become `high` when a security or cumulative update is waiting, RDP
  becomes `high` when Network Level Authentication is off, and every device found by the very first
  discovery run is `info` because that run is an inventory, not an intrusion. These are marked with
  an asterisk in the table below.
- **`info` never costs you score points.** It exists so the Feed reads as a complete story.

## The security score

The number on the Overview gauge is worth understanding, because it is what tells you whether the
work you did this weekend actually moved anything. It is computed in `homesoc/findings/score.py`,
in four steps.

**Step 1 — every unfixed finding is worth points, scaled by how you have treated it.**

| Severity | Base points | | Status | Multiplier |
|---|---|---|---|---|
| critical | 30 |   | open | × 1.0 |
| high | 12 |   | acknowledged | × 0.25 |
| medium | 5 |   | resolved | × 0 |
| low | 1.5 |   | suppressed | × 0 |
| info | 0 |   | | |

Acknowledging is a quarter-price snooze, not an erasure: the risk is still real, so it still costs
something. Suppressing and resolving cost nothing at all, and `info` findings are free in every
status.

**Step 2 — repeats of the same finding get cheaper, fast.** Twenty-six "outdated app" rows are one
problem, not twenty-six. Within a single finding ID the rows are sorted worst-first and each
successive one costs half the previous one, capped at twice the first:

```
penalty(id) = w + w/2 + w/4 + w/8 + ...   (never more than 2 × w)
```

One outdated app costs 1.5 penalty points; twenty-six of them cost 3. Twenty-two open findings of
the same medium type cost 10 rather than 110.

**Step 3 — the total penalty is halved into a score, never subtracted.**

```
score = 100 × 0.5 ** (total_penalty / 60)
```

Every 60 penalty points halves what is left: 0 → 100, 60 → 50, 120 → 25. Because it is a curve and
not a subtraction, the score can never get stuck at zero, and fixing *anything* always moves it.

**Step 4 — critical and high findings hit explicit ceilings.** Arithmetic alone would let a machine
with one serious hole and otherwise perfect hygiene look fine, so the ceilings override it:

- one open **critical** caps the score at **34** — an F, whatever else is clean;
- two or more open criticals cap it at **20**;
- any open **high** caps it at **79**, so an A always means "nothing high or critical is open".

**Grades:** A ≥ 80, B ≥ 65, C ≥ 50, D ≥ 35, F below 35.

A few practical consequences:

- A single open medium costs 6 points (94, an A). A single open high pins you to 79 (a B) no matter
  how clean everything else is. A single open critical pins you to 34 (an F).
- **You can see what is costing you.** `python -m homesoc status` prints a "costing the most
  points" list, and `/api/summary` carries the same `score_breakdown`: one row per finding type
  with the points it costs and, more usefully, how far the score would actually rise if you cleared
  that whole type — ceilings included. Work the biggest gain, not the longest list.
- A brand-new install with no `findings` table yet reports **100**. That is "nothing has been
  scanned", not "nothing is wrong".

The score is sampled once an hour by the `score` scheduler job into the `metrics` table, which is
what draws the 30-day sparkline on Overview and the trend line on `/summary`. The trend keeps one
point per day (that day's last sample), so a day the agent was not running has no point rather than
a zero.

---

## Checks that need administrator rights

Home SOC is built to run as a normal user — that is how it runs on the machine it was developed on. A handful of Windows checks read data that Windows only shows to an elevated process. When one of those is refused, Home SOC records the check with the status **`needs_admin`** instead of guessing. `needs_admin` is not a pass and not a fail: it means *not measured*. It never subtracts from your security score, and the Host posture page shows it with its own badge.

On the reference machine (Windows 11 Home, standard user, UAC on) these three came back as `needs_admin` — the PowerShell behind them (`Get-BitLockerVolume`, `Get-WindowsOptionalFeature`, `Get-Tpm`) is refused to a non-elevated process:

- **`WIN-SYS-002`** — BitLocker / device encryption is off
- **`WIN-SYS-005`** — Windows PowerShell 2.0 engine is enabled
- **`WIN-SYS-008`** — TPM is absent or not ready

These checks normally answer fine as a standard user, but they are *also* written to degrade to `needs_admin` rather than invent a failure if their probe is ever refused (Defender is readable without elevation on the reference machine, for example, but a managed PC can lock it down):

- `WIN-ACC-001` — Your daily account '{user}' is an Administrator
- `WIN-ACC-002` — Built-in Administrator account is enabled
- `WIN-ACC-003` — Guest account is enabled
- `WIN-DEF-001` — Windows Defender antivirus is disabled
- `WIN-DEF-002` — Defender real-time protection is off
- `WIN-DEF-003` — Defender signatures are {age_days} days old
- `WIN-DEF-004` — Defender tamper protection is off
- `WIN-DEF-005` — Defender cloud-delivered protection is off
- `WIN-DEF-006` — Defender PUA (potentially unwanted app) protection is off
- `WIN-DEF-007` — No Defender full scan in the last 30 days
- `WIN-DEF-008` — Defender controlled folder access is off
- `WIN-DEF-009` — Defender network protection is off
- `WIN-DEF-010` — No Defender attack surface reduction (ASR) rules configured
- `WIN-DEF-012` — Defender service is unhealthy ({state})
- `WIN-DEF-014` — Defender cloud block level / sample submission is at the basic setting
- `WIN-FW-001` — Windows Firewall is disabled for the {profile} profile
- `WIN-FW-002` — Windows Firewall default inbound action is Allow ({profile})
- `WIN-NET-001` — SMBv1 file sharing protocol is enabled
- `WIN-NET-003` — SMB signing is not required
- `WIN-NET-006` — Unusual program listening on the LAN: port {port} ({process})
- `WIN-SYS-001` — Secure Boot is off (`Confirm-SecureBootUEFI` itself is refused to a standard user, but Home SOC reads the Secure Boot state from the registry instead, so this normally still answers)
- `WIN-SYS-003` — Virtualization-based security / memory integrity (HVCI) is not running
- `WIN-UPD-002` — Last cumulative Windows update was {days} days ago

Beyond these, the Windows **Security** event log is unreadable without elevation, so anything that would depend on it is simply not attempted; Defender's own Operational log, the System log and the PowerShell Operational log are all readable as a standard user.

Every non-elevated run also raises `SOC-SYS-002`, an informational finding that lists exactly which check IDs were skipped and gives the command to run them once in an elevated PowerShell window. Running elevated is optional; Home SOC keeps working without it.

## Every finding at a glance

Home SOC's catalog contains **92 findings**. Titles containing `{something}` are templates: the scanner's evidence is substituted in when the finding is raised, so what you see on the dashboard reads "Defender signatures are 9 days old". The severity column is the catalog default; three findings are re-graded at runtime and are marked with an asterisk. The last column is the scan that produces the finding, with **needs admin** for the three checks that are refused to a standard user and *may need admin* for the ones that can degrade to `needs_admin`.

| ID | Severity | Title | Category | Emitted by | Scan |
|---|---|---|---|---|---|
| [`WIN-DEF-001`](#win-def-001) | critical | Windows Defender antivirus is disabled | Microsoft Defender antivirus | `scanners/defender.py` | `host` · *may need admin* |
| [`WIN-DEF-002`](#win-def-002) | critical | Defender real-time protection is off | Microsoft Defender antivirus | `scanners/defender.py` | `host` · *may need admin* |
| [`WIN-DEF-003`](#win-def-003) | high | Defender signatures are {age_days} days old | Microsoft Defender antivirus | `scanners/defender.py` | `host` · *may need admin* |
| [`WIN-DEF-011`](#win-def-011) | high | Defender detected a threat: {threat_name} | Microsoft Defender antivirus | `scanners/defender.py` | `host` |
| [`WIN-DEF-012`](#win-def-012) | high | Defender service is unhealthy ({state}) | Microsoft Defender antivirus | `scanners/defender.py` | `host` · *may need admin* |
| [`WIN-DEF-004`](#win-def-004) | medium | Defender tamper protection is off | Microsoft Defender antivirus | `scanners/defender.py` | `host` · *may need admin* |
| [`WIN-DEF-005`](#win-def-005) | medium | Defender cloud-delivered protection is off | Microsoft Defender antivirus | `scanners/defender.py` | `host` · *may need admin* |
| [`WIN-DEF-006`](#win-def-006) | low | Defender PUA (potentially unwanted app) protection is off | Microsoft Defender antivirus | `scanners/defender.py` | `host` · *may need admin* |
| [`WIN-DEF-007`](#win-def-007) | low | No Defender full scan in the last 30 days | Microsoft Defender antivirus | `scanners/defender.py` | `host` · *may need admin* |
| [`WIN-DEF-008`](#win-def-008) | low | Defender controlled folder access is off | Microsoft Defender antivirus | `scanners/defender.py` | `host` · *may need admin* |
| [`WIN-DEF-009`](#win-def-009) | low | Defender network protection is off | Microsoft Defender antivirus | `scanners/defender.py` | `host` · *may need admin* |
| [`WIN-DEF-010`](#win-def-010) | low | No Defender attack surface reduction (ASR) rules configured | Microsoft Defender antivirus | `scanners/defender.py` | `host` · *may need admin* |
| [`WIN-DEF-013`](#win-def-013) | info | Smart App Control is off | Microsoft Defender antivirus | `scanners/defender.py`, `scanners/host_windows.py` | `host` |
| [`WIN-DEF-014`](#win-def-014) | info | Defender cloud block level / sample submission is at the basic setting | Microsoft Defender antivirus | `scanners/defender.py` | `host` · *may need admin* |
| [`WIN-FW-001`](#win-fw-001) | critical | Windows Firewall is disabled for the {profile} profile | Windows Firewall | `scanners/host_windows.py` | `host` · *may need admin* |
| [`WIN-FW-002`](#win-fw-002) | high | Windows Firewall default inbound action is Allow ({profile}) | Windows Firewall | `scanners/host_windows.py` | `host` · *may need admin* |
| [`WIN-UPD-002`](#win-upd-002) | high | Last cumulative Windows update was {days} days ago | Updates and outdated software | `scanners/host_windows.py`, `scanners/updates.py` | `host` · *may need admin* |
| [`WIN-UPD-004`](#win-upd-004) | high | Outdated high-risk app: {name} {version} (available {available}) | Updates and outdated software | `findings/score.py`, `scanners/updates.py`, `vulns/matcher.py` | `?`, `host`, `vulns` |
| [`WIN-UPD-001`](#win-upd-001) | medium \* | {count} Windows updates are pending | Updates and outdated software | `scanners/updates.py` | `host` |
| [`WIN-UPD-003`](#win-upd-003) | low | Outdated app: {name} {version} (available {available}) | Updates and outdated software | `scanners/updates.py`, `vulns/matcher.py` | `host`, `vulns` |
| [`WIN-ACC-002`](#win-acc-002) | high | Built-in Administrator account is enabled | Accounts and sign-in | `scanners/host_windows.py` | `host` · *may need admin* |
| [`WIN-ACC-003`](#win-acc-003) | high | Guest account is enabled | Accounts and sign-in | `scanners/host_windows.py` | `host` · *may need admin* |
| [`WIN-ACC-004`](#win-acc-004) | high | Automatic logon is enabled | Accounts and sign-in | `scanners/host_windows.py` | `host` |
| [`WIN-ACC-005`](#win-acc-005) | high | User Account Control (UAC) is off or set to never prompt | Accounts and sign-in | `scanners/host_windows.py` | `host` |
| [`WIN-ACC-001`](#win-acc-001) | medium | Your daily account '{user}' is an Administrator | Accounts and sign-in | `scanners/host_windows.py` | `host` · *may need admin* |
| [`WIN-NET-001`](#win-net-001) | high | SMBv1 file sharing protocol is enabled | Network services on this PC | `scanners/host_windows.py` | `host` · *may need admin* |
| [`WIN-NET-002`](#win-net-002) | medium \* | Remote Desktop is enabled (Network Level Authentication: {nla}) | Network services on this PC | `scanners/host_windows.py` | `host` |
| [`WIN-NET-005`](#win-net-005) | medium | WinRM / Remote Registry is listening on the network ({port}) | Network services on this PC | `scanners/host_windows.py` | `host` |
| [`WIN-NET-003`](#win-net-003) | low | SMB signing is not required | Network services on this PC | `scanners/host_windows.py` | `host` · *may need admin* |
| [`WIN-NET-004`](#win-net-004) | low | LLMNR name resolution is enabled | Network services on this PC | `scanners/host_windows.py` | `host` |
| [`WIN-NET-006`](#win-net-006) | low | Unusual program listening on the LAN: port {port} ({process}) | Network services on this PC | `scanners/host_windows.py` | `host` · *may need admin* |
| [`WIN-SYS-002`](#win-sys-002) | high | BitLocker / device encryption is off | System hardening | `scanners/host_windows.py` | `host` · **needs admin** |
| [`WIN-SYS-001`](#win-sys-001) | medium | Secure Boot is off | System hardening | `scanners/host_windows.py` | `host` · *may need admin* |
| [`WIN-SYS-004`](#win-sys-004) | medium | LSA protection (RunAsPPL) is off | System hardening | `scanners/host_windows.py` | `host` |
| [`WIN-SYS-006`](#win-sys-006) | medium | SmartScreen is off | System hardening | `scanners/host_windows.py` | `host` |
| [`WIN-SYS-003`](#win-sys-003) | low | Virtualization-based security / memory integrity (HVCI) is not running | System hardening | `scanners/host_windows.py` | `host` · *may need admin* |
| [`WIN-SYS-005`](#win-sys-005) | low | Windows PowerShell 2.0 engine is enabled | System hardening | `scanners/host_windows.py` | `host` · **needs admin** |
| [`WIN-SYS-007`](#win-sys-007) | low | Screen lock is not enforced | System hardening | `scanners/host_windows.py` | `host` |
| [`WIN-SYS-008`](#win-sys-008) | low | TPM is absent or not ready | System hardening | `scanners/host_windows.py` | `host` · **needs admin** |
| [`WIN-PER-001`](#win-per-001) | medium | New autostart entry: {name} | Autostart and persistence | `scanners/persistence.py` | `host` |
| [`WIN-PER-002`](#win-per-002) | medium | New scheduled task: {name} | Autostart and persistence | `scanners/persistence.py` | `host` |
| [`WIN-PER-003`](#win-per-003) | medium | New auto-start service: {name} | Autostart and persistence | `scanners/persistence.py` | `host` |
| [`AV-FILE-001`](#av-file-001) | critical | Malicious file in Downloads: {path} | Downloaded files | `scanners/files.py` | `files` |
| [`AV-FILE-002`](#av-file-002) | medium | Suspicious file in Downloads: {path} | Downloaded files | `scanners/files.py` | `files` |
| [`POSIX-FW-001`](#posix-fw-001) | high | Host firewall is inactive | Linux and macOS hosts | `scanners/host_posix.py` | `host` |
| [`POSIX-SSH-001`](#posix-ssh-001) | high | SSH allows root login | Linux and macOS hosts | `scanners/host_posix.py` | `host` |
| [`POSIX-ENC-001`](#posix-enc-001) | medium | Disk is not encrypted | Linux and macOS hosts | `scanners/host_posix.py` | `host` |
| [`POSIX-UPD-001`](#posix-upd-001) | medium | {count} system updates pending | Linux and macOS hosts | `scanners/updates.py` | `host` |
| [`POSIX-NET-001`](#posix-net-001) | low | Unusual service listening on the network: port {port} ({process}) | Linux and macOS hosts | `scanners/host_posix.py` | `host` |
| [`NET-DEV-001`](#net-dev-001) | medium \* | New device on the network: {ip} ({vendor}) | Devices on your network | `findings/engine.py`, `scanners/discovery.py` | `?`, `discovery` |
| [`NET-DEV-002`](#net-dev-002) | info | Device with unknown vendor or randomized MAC: {ip} | Devices on your network | `scanners/discovery.py` | `discovery` |
| [`NET-DEV-003`](#net-dev-003) | info | Trusted device '{name}' has been offline for {days} days | Devices on your network | `cli.py`, `scanners/discovery.py` | `any run`, `discovery` |
| [`NET-DEV-004`](#net-dev-004) | high | {count} new devices appeared in one network scan | Devices on your network | `scanners/discovery.py` | `discovery` |
| [`NET-SVC-001`](#net-svc-001) | critical | Telnet open on {ip}:{port} | Services exposed by devices on the LAN | `scanners/services.py` | `services` |
| [`NET-SVC-002`](#net-svc-002) | high | FTP open on {ip}:{port} | Services exposed by devices on the LAN | `scanners/services.py` | `services` |
| [`NET-SVC-007`](#net-svc-007) | high | Database port open on {ip}:{port} ({product}) | Services exposed by devices on the LAN | `scanners/services.py` | `services` |
| [`NET-SVC-003`](#net-svc-003) | medium | SMB file sharing on non-Windows device {ip}:{port} | Services exposed by devices on the LAN | `scanners/services.py` | `services` |
| [`NET-SVC-004`](#net-svc-004) | medium | Remote desktop (RDP/VNC) exposed on {ip}:{port} | Services exposed by devices on the LAN | `scanners/services.py` | `services` |
| [`NET-SVC-006`](#net-svc-006) | medium | UPnP / SSDP control port open on {ip}:{port} | Services exposed by devices on the LAN | `scanners/services.py` | `services` |
| [`NET-SVC-009`](#net-svc-009) | medium | SNMP with default community on {ip} | Services exposed by devices on the LAN | `scanners/services.py` | `services` |
| [`NET-SVC-010`](#net-svc-010) | medium | RTSP camera stream exposed on {ip}:{port} | Services exposed by devices on the LAN | `scanners/services.py` | `services` |
| [`NET-SVC-005`](#net-svc-005) | low | HTTP admin interface without HTTPS on {ip}:{port} | Services exposed by devices on the LAN | `scanners/services.py` | `services` |
| [`NET-SVC-008`](#net-svc-008) | low | Printer raw port / IPP without authentication on {ip}:{port} | Services exposed by devices on the LAN | `scanners/services.py` | `services` |
| [`NET-SVC-011`](#net-svc-011) | low | Outdated SSH server on {ip}:{port} ({product} {version}) | Services exposed by devices on the LAN | `scanners/services.py` | `services` |
| [`NET-SVC-012`](#net-svc-012) | info | Device {ip} advertises its hardware model on the network ({exposed}) | Services exposed by devices on the LAN | `scanners/services.py` | `services` |
| [`NET-VUL-001`](#net-vul-001) | critical | Known exploited vulnerability {cve} on {ip} ({product} {version}) | Known vulnerabilities (CVE / KEV / EPSS) | `vulns/matcher.py` | `vulns` |
| [`NET-VUL-002`](#net-vul-002) | high | Possible known-exploited vulnerability {cve} on {ip} ({product}) | Known vulnerabilities (CVE / KEV / EPSS) | `vulns/matcher.py` | `vulns` |
| [`NET-VUL-004`](#net-vul-004) | high | Exploitation likely in the wild: {cves} on {ip} | Known vulnerabilities (CVE / KEV / EPSS) | `vulns/matcher.py` | `vulns` |
| [`NET-VUL-003`](#net-vul-003) | medium | {count} known CVEs (max CVSS {max_cvss}) for {product} {version} on {ip} | Known vulnerabilities (CVE / KEV / EPSS) | `vulns/matcher.py` | `vulns` |
| [`NET-WAN-001`](#net-wan-001) | critical | Port {port} is open to the internet on your public IP | Internet-facing exposure | `scanners/exposure.py` | `exposure` |
| [`NET-WAN-002`](#net-wan-002) | critical | Internet-facing vulnerabilities reported for your public IP: {vulns} | Internet-facing exposure | `scanners/exposure.py` | `exposure` |
| [`NET-WAN-003`](#net-wan-003) | high | UPnP port mapping: WAN {external_port} -> {internal_client}:{internal_port} ({description}) | Internet-facing exposure | `scanners/exposure.py` | `exposure` |
| [`NET-RTR-002`](#net-rtr-002) | medium | Router has UPnP (IGD) enabled | Internet-facing exposure | `scanners/exposure.py` | `exposure` |
| [`NET-WIFI-001`](#net-wifi-001) | critical | Wi-Fi '{ssid}' is open or uses WEP | Wi-Fi security | `scanners/wifi.py` | `wifi` |
| [`NET-WIFI-003`](#net-wifi-003) | high | Wi-Fi '{ssid}' uses TKIP encryption | Wi-Fi security | `scanners/wifi.py` | `wifi` |
| [`NET-WIFI-002`](#net-wifi-002) | info | Wi-Fi '{ssid}' uses WPA2 without WPA3 | Wi-Fi security | `scanners/wifi.py` | `wifi` |
| [`NET-WIFI-004`](#net-wifi-004) | info | WPS appears to be enabled on '{ssid}' | Wi-Fi security | _reserved, never emitted_ | — |
| [`NET-DNS-002`](#net-dns-002) | high | DNS resolver is not running ({reason}) | DNS filter | `dnsfilter/server.py` | `dns` |
| [`NET-DNS-004`](#net-dns-004) | high | {client} tried to reach a malicious domain: {domain} | DNS filter | `dnsfilter/reputation.py` | `dns` |
| [`NET-DNS-005`](#net-dns-005) | high | DNS upstream resolvers are unreachable | DNS filter | `dnsfilter/server.py` | `dns` |
| [`NET-DNS-003`](#net-dns-003) | medium | DNS blocklists are stale ({age_days} days) | DNS filter | `dnsfilter/server.py` | `dns` |
| [`NET-DNS-001`](#net-dns-001) | info | Devices are not using the Home SOC DNS filter | DNS filter | `dnsfilter/server.py` | `dns` |
| [`NET-DNS-006`](#net-dns-006) | info | Resolver is bound to the LAN but no firewall rule allows DNS in | DNS filter | `dnsfilter/server.py` | `dns` |
| [`SOC-SYS-003`](#soc-sys-003) | high | Dashboard is reachable from the LAN without a token | Home SOC's own health | `cli.py` | `any run` |
| [`SOC-FEED-001`](#soc-feed-001) | medium | Feed '{name}' has been failing for {hours} hours | Home SOC's own health | `cli.py`, `feeds/updater.py` | `any run`, `feeds` |
| [`SOC-FEED-002`](#soc-feed-002) | medium | CISA KEV catalog is stale ({hours} hours) | Home SOC's own health | `cli.py`, `feeds/updater.py` | `any run`, `feeds` |
| [`SOC-SYS-004`](#soc-sys-004) | medium | Scheduled job '{job}' keeps failing ({failures} times) | Home SOC's own health | `cli.py` | `any run` |
| [`SOC-SYS-001`](#soc-sys-001) | info | nmap is not installed; using the built-in Python scanner | Home SOC's own health | `cli.py` | `any run` |
| [`SOC-SYS-002`](#soc-sys-002) | info | Home SOC is not running as administrator; skipped: {skipped} | Home SOC's own health | `scanners/host_windows.py` | `host` |

\* re-graded at runtime: `NET-DEV-001` is lowered to `info` for every device found by the very first (baseline) discovery run — see `scanners/discovery.py`; `WIN-NET-002` is raised to `high` when Network Level Authentication is off — see `scanners/host_windows.py`; `WIN-UPD-001` is raised to `high` when a pending update's title looks like a security or cumulative update — see `scanners/updates.py`.

---

## Microsoft Defender antivirus

Windows 11 Home already ships a capable antivirus. These playbooks are about making sure it is switched on, up to date, and using the protections that are off by default.

### WIN-DEF-001

**Windows Defender antivirus is disabled**  
Severity `critical` · category `defender` · raised at most once — it has a single subject

Emitted by `scanners/defender.py` (Defender status and threat history).  
Degrades to `needs_admin` rather than pass/fail if its probe is refused.  

**Why it matters.** With no antivirus running, any file you download or open runs unchecked; ransomware and info-stealers rely on exactly this. Windows 11 Home ships Defender for free, so there is no reason to run without it.

**How to fix it**

1. Open Start, type 'Windows Security' and press Enter. Click 'Virus & threat protection'.
2. If a banner says another antivirus is installed, decide which one you want; uninstall the other so Defender can take over (Settings > Apps > Installed apps > the product > Uninstall).
3. Under 'Virus & threat protection settings' click 'Manage settings' and turn 'Real-time protection' On.
4. If the switch is greyed out, check Settings > Accounts > Family for third-party or parental restrictions, and run a full scan from a clean rescue medium before trusting the PC.
5. PowerShell (admin): Set-MpPreference -DisableRealtimeMonitoring $false

**Read more**

- <https://support.microsoft.com/en-us/windows/stay-protected-with-windows-security-2ae0363d-0ada-c064-8b56-6a39afb6a963>
- <https://learn.microsoft.com/en-us/defender-endpoint/microsoft-defender-antivirus-windows>
- <https://learn.microsoft.com/en-us/powershell/module/defender/set-mppreference>

### WIN-DEF-002

**Defender real-time protection is off**  
Severity `critical` · category `defender` · raised at most once — it has a single subject

Emitted by `scanners/defender.py` (Defender status and threat history).  
Degrades to `needs_admin` rather than pass/fail if its probe is refused.  

**Why it matters.** Real-time protection is the part of Defender that stops malware the moment it lands on disk or runs; without it a scan only finds problems after the damage is done.

**How to fix it**

1. Open Start, type 'Windows Security' and press Enter. Click 'Virus & threat protection'. Under 'Virus & threat protection settings' click 'Manage settings'.
2. Turn 'Real-time protection' On. If it turns itself back off, something is fighting Defender: run a full offline scan ('Scan options' > 'Microsoft Defender Antivirus (offline scan)').
3. PowerShell (admin): Set-MpPreference -DisableRealtimeMonitoring $false

**Read more**

- <https://support.microsoft.com/en-us/windows/stay-protected-with-windows-security-2ae0363d-0ada-c064-8b56-6a39afb6a963>
- <https://learn.microsoft.com/en-us/powershell/module/defender/set-mppreference>

### WIN-DEF-003

**Defender signatures are {age_days} days old**  
Severity `high` · category `defender` · raised at most once — it has a single subject

Emitted by `scanners/defender.py` (Defender status and threat history).  
Degrades to `needs_admin` rather than pass/fail if its probe is refused.  

**Why it matters.** Defender receives new detections several times a day; stale signatures miss this week's malware even though the antivirus looks 'on'.

**How to fix it**

1. Open Start, type 'Windows Security' and press Enter. Click 'Virus & threat protection'. Under 'Virus & threat protection updates' click 'Protection updates', then 'Check for updates'.
2. If updates fail, open Settings > Windows Update > 'Check for updates' and reboot if asked.
3. PowerShell: Update-MpSignature   (or: & "$env:ProgramFiles\Windows Defender\MpCmdRun.exe" -SignatureUpdate)

**Read more**

- <https://www.microsoft.com/en-us/wdsi/defenderupdates>
- <https://learn.microsoft.com/en-us/defender-endpoint/command-line-arguments-microsoft-defender-antivirus>

### WIN-DEF-004

**Defender tamper protection is off**  
Severity `medium` · category `defender` · raised at most once — it has a single subject

Emitted by `scanners/defender.py` (Defender status and threat history).  
Degrades to `needs_admin` rather than pass/fail if its probe is refused.  

**Why it matters.** Tamper protection stops malware (or a bad script) from silently switching Defender off; it is a one-click safeguard that costs nothing.

**How to fix it**

1. Open Start, type 'Windows Security' and press Enter. Click 'Virus & threat protection'. Under 'Virus & threat protection settings' click 'Manage settings'.
2. Scroll to 'Tamper Protection' and turn it On (accept the UAC prompt).
3. There is no supported command line to change this setting; it must be enabled from Windows Security (that is the point of it - malware cannot script it either).
4. PowerShell to confirm it took effect: Get-MpComputerStatus | Select-Object IsTamperProtected

**Read more**

- <https://learn.microsoft.com/en-us/defender-endpoint/prevent-changes-to-security-settings-with-tamper-protection>

### WIN-DEF-005

**Defender cloud-delivered protection is off**  
Severity `medium` · category `defender` · raised at most once — it has a single subject

Emitted by `scanners/defender.py` (Defender status and threat history).  
Degrades to `needs_admin` rather than pass/fail if its probe is refused.  

**Why it matters.** Cloud protection lets Defender ask Microsoft about brand-new files in milliseconds, catching threats hours before a signature update ships.

**How to fix it**

1. Open Start, type 'Windows Security' and press Enter. Click 'Virus & threat protection'. Under 'Virus & threat protection settings' click 'Manage settings'.
2. Turn 'Cloud-delivered protection' On, and 'Automatic sample submission' On.
3. PowerShell (admin): Set-MpPreference -MAPSReporting Advanced -SubmitSamplesConsent SendSafeSamples

**Read more**

- <https://learn.microsoft.com/en-us/defender-endpoint/enable-cloud-protection-microsoft-defender-antivirus>
- <https://learn.microsoft.com/en-us/powershell/module/defender/set-mppreference>

### WIN-DEF-006

**Defender PUA (potentially unwanted app) protection is off**  
Severity `low` · category `defender` · raised at most once — it has a single subject

Emitted by `scanners/defender.py` (Defender status and threat history).  
Degrades to `needs_admin` rather than pass/fail if its probe is refused.  

**Why it matters.** PUA protection blocks adware, bundled toolbars and crypto-miners that hide inside 'free' installers; they are not classic viruses so plain antivirus lets them through.

**How to fix it**

1. Open Start, type 'Windows Security' and press Enter. Click 'App & browser control', then 'Reputation-based protection settings'.
2. Turn 'Potentially unwanted app blocking' On and tick both 'Block apps' and 'Block downloads'.
3. PowerShell (admin): Set-MpPreference -PUAProtection Enabled

**Read more**

- <https://learn.microsoft.com/en-us/defender-endpoint/detect-block-potentially-unwanted-apps-microsoft-defender-antivirus>

### WIN-DEF-007

**No Defender full scan in the last 30 days**  
Severity `low` · category `defender` · raised at most once — it has a single subject

Emitted by `scanners/defender.py` (Defender status and threat history).  
Degrades to `needs_admin` rather than pass/fail if its probe is refused.  

**Why it matters.** Quick scans only look at common hiding spots; a periodic full scan checks every file, including old downloads and external drives.

**How to fix it**

1. Open Start, type 'Windows Security' and press Enter. Click 'Virus & threat protection'. Click 'Scan options', choose 'Full scan' and click 'Scan now' (leave the PC plugged in).
2. PowerShell: Start-MpScan -ScanType FullScan   (or use the 'Quick scan' button on the Home SOC host page)

**Read more**

- <https://learn.microsoft.com/en-us/defender-endpoint/command-line-arguments-microsoft-defender-antivirus>
- <https://learn.microsoft.com/en-us/powershell/module/defender/get-mpcomputerstatus>

### WIN-DEF-008

**Defender controlled folder access is off**  
Severity `low` · category `defender` · raised at most once — it has a single subject

Emitted by `scanners/defender.py` (Defender status and threat history).  
Degrades to `needs_admin` rather than pass/fail if its probe is refused.  

**Why it matters.** Controlled folder access stops unknown programs from rewriting Documents, Pictures and Desktop, which is exactly what ransomware does first.

**How to fix it**

1. Open Start, type 'Windows Security' and press Enter. Click 'Virus & threat protection'. Under 'Virus & threat protection settings' click 'Manage settings'. Scroll to 'Controlled folder access' and click 'Manage Controlled folder access'.
2. Turn it On. If a trusted program is later blocked, click 'Allow an app through Controlled folder access'.
3. PowerShell (admin): Set-MpPreference -EnableControlledFolderAccess Enabled

**Read more**

- <https://learn.microsoft.com/en-us/defender-endpoint/enable-controlled-folders>

### WIN-DEF-009

**Defender network protection is off**  
Severity `low` · category `defender` · raised at most once — it has a single subject

Emitted by `scanners/defender.py` (Defender status and threat history).  
Degrades to `needs_admin` rather than pass/fail if its probe is refused.  

**Why it matters.** Network protection blocks connections to known-malicious domains from any app, not just the browser; it complements the Home SOC DNS filter for this PC.

**How to fix it**

1. Network protection has no switch in the Windows Security app; it is a PowerShell setting.
2. Open Start, type 'PowerShell', right-click and choose 'Run as administrator'.
3. Run: Set-MpPreference -EnableNetworkProtection Enabled

**Read more**

- <https://learn.microsoft.com/en-us/defender-endpoint/enable-network-protection>

### WIN-DEF-010

**No Defender attack surface reduction (ASR) rules configured**  
Severity `low` · category `defender` · raised at most once — it has a single subject

Emitted by `scanners/defender.py` (Defender status and threat history).  
Degrades to `needs_admin` rather than pass/fail if its probe is refused.  

**Why it matters.** ASR rules block the tricks most phishing malware uses (Office macros spawning programs, script droppers, credential theft from LSASS) and are free on Windows Home.

**How to fix it**

1. ASR rules are configured from an administrator PowerShell (Start > 'PowerShell' > Run as administrator).
2. Start in audit mode to be safe: Set-MpPreference -AttackSurfaceReductionRules_Ids BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550,D4F940AB-401B-4EFC-AADC-AD5F3C50688A,9E6C4E1F-7D60-472F-BA1A-A39EF669E4B2 -AttackSurfaceReductionRules_Actions AuditMode,AuditMode,AuditMode
3. After a week without false positives, re-run with 'Enabled' instead of 'AuditMode'.

**Read more**

- <https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-rules-reference>

### WIN-DEF-011

**Defender detected a threat: {threat_name}**  
Severity `high` · category `defender` · raised once per affected subject

Emitted by `scanners/defender.py` (Defender status and threat history).  

**Why it matters.** Defender found and (usually) quarantined malware recently; you should confirm it was removed, find out how it arrived, and check nothing else came with it.

**How to fix it**

1. Open Start, type 'Windows Security' and press Enter. Click 'Virus & threat protection'. Click 'Protection history' and open the entry for '{threat_name}'.
2. Confirm the status is 'Quarantined' or 'Removed'. If it says 'Allowed' and you do not recognise it, click the entry and choose 'Remove'.
3. Run a full scan ('Scan options' > 'Full scan'), then change passwords you used on this PC if the threat was a stealer or trojan.
4. PowerShell: Get-MpThreatDetection | Sort-Object InitialDetectionTime -Descending | Select-Object -First 10

**Read more**

- <https://support.microsoft.com/en-us/windows/stay-protected-with-windows-security-2ae0363d-0ada-c064-8b56-6a39afb6a963>
- <https://learn.microsoft.com/en-us/powershell/module/defender/get-mpcomputerstatus>

### WIN-DEF-012

**Defender service is unhealthy ({state})**  
Severity `high` · category `defender` · raised at most once — it has a single subject

Emitted by `scanners/defender.py` (Defender status and threat history).  
Degrades to `needs_admin` rather than pass/fail if its probe is refused.  

**Why it matters.** The antivirus engine is not running or not reporting status; the PC may be unprotected even though nothing is visibly wrong.

**How to fix it**

1. Open Start, type 'Windows Security' and press Enter. Click 'Virus & threat protection'. and read any red or yellow banner; click 'Restart now' or 'Turn on' if offered.
2. Reboot the PC once; if the problem persists open Settings > Windows Update and install all updates.
3. PowerShell: Get-MpComputerStatus | Select-Object AMServiceEnabled, AntivirusEnabled, RealTimeProtectionEnabled
4. If the service still will not start, run 'Scan options' > 'Microsoft Defender Antivirus (offline scan)'.

**Read more**

- <https://learn.microsoft.com/en-us/defender-endpoint/microsoft-defender-antivirus-windows>
- <https://learn.microsoft.com/en-us/powershell/module/defender/get-mpcomputerstatus>

### WIN-DEF-013

**Smart App Control is off**  
Severity `info` · category `defender` · raised at most once — it has a single subject

Emitted by `scanners/defender.py` (Defender status and threat history), `scanners/host_windows.py` (Windows posture probe).  

**Why it matters.** Smart App Control only lets apps with a good reputation run, blocking most malware outright. It can only be enabled on a clean install of Windows 11, so this is informational if it is off.

**How to fix it**

1. Open Start, type 'Windows Security' and press Enter. Click 'App & browser control' > 'Smart App Control settings'.
2. If the setting is available, turn it On (Evaluation mode is fine). Once it is off it can only be switched back on by resetting Windows (Settings > System > Recovery > Reset this PC), so leaving it off is a reasonable choice - the other Defender findings matter more.
3. PowerShell to read the current state (0 = off, 1 = on, 2 = evaluation): Get-ItemPropertyValue 'HKLM:\SYSTEM\CurrentControlSet\Control\CI\Policy' -Name VerifiedAndReputablePolicyState

**Read more**

- <https://support.microsoft.com/en-us/topic/what-is-smart-app-control-285ea03d-fa88-4d56-882e-6698afdb7003>

### WIN-DEF-014

**Defender cloud block level / sample submission is at the basic setting**  
Severity `info` · category `defender` · raised at most once — it has a single subject

Emitted by `scanners/defender.py` (Defender status and threat history).  
Degrades to `needs_admin` rather than pass/fail if its probe is refused.  

**Why it matters.** A higher cloud block level makes Defender more aggressive on unknown files with little downside for a home user; sample submission helps it learn from new threats.

**How to fix it**

1. Open Start, type 'Windows Security' and press Enter. Click 'Virus & threat protection'. Under 'Virus & threat protection settings' click 'Manage settings'. Ensure 'Automatic sample submission' is On.
2. PowerShell (admin): Set-MpPreference -CloudBlockLevel High -CloudExtendedTimeout 50

**Read more**

- <https://learn.microsoft.com/en-us/defender-endpoint/enable-cloud-protection-microsoft-defender-antivirus>
- <https://learn.microsoft.com/en-us/powershell/module/defender/set-mppreference>

---

## Windows Firewall

The firewall decides which of your PC's services other machines can reach. On a home network the correct answer is almost always "none unless you asked for it".

### WIN-FW-001

**Windows Firewall is disabled for the {profile} profile**  
Severity `critical` · category `firewall` · raised once per affected subject

Emitted by `scanners/host_windows.py` (Windows posture probe).  
Degrades to `needs_admin` rather than pass/fail if its probe is refused.  

**Why it matters.** The firewall is the only thing stopping other devices (or a compromised gadget) on your network from reaching file shares and services on this PC.

**How to fix it**

1. Open Start, type 'Windows Security' and press Enter. Click 'Firewall & network protection'.
2. Click the network marked '(active)' or the '{profile} network' entry and turn 'Microsoft Defender Firewall' On.
3. Repeat for Domain, Private and Public so all three say 'Firewall is on'.
4. PowerShell (admin): Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True

**Read more**

- <https://support.microsoft.com/en-us/windows/turn-microsoft-defender-firewall-on-or-off-ec0844f7-aebd-0583-67fe-601ecf5d774f>
- <https://learn.microsoft.com/en-us/powershell/module/netsecurity/set-netfirewallprofile>

### WIN-FW-002

**Windows Firewall default inbound action is Allow ({profile})**  
Severity `high` · category `firewall` · raised once per affected subject

Emitted by `scanners/host_windows.py` (Windows posture probe).  
Degrades to `needs_admin` rather than pass/fail if its probe is refused.  

**Why it matters.** With inbound 'allow' by default, every listening program on this PC is reachable from the network, which defeats the purpose of having a firewall.

**How to fix it**

1. Open Start, type 'Windows Security' and press Enter. Click 'Firewall & network protection'. Click 'Advanced settings' (accept the UAC prompt).
2. In the right pane click 'Windows Defender Firewall Properties'; on each profile tab set 'Inbound connections' to 'Block (default)' and click OK.
3. PowerShell (admin): Set-NetFirewallProfile -Profile Domain,Private,Public -DefaultInboundAction Block

**Read more**

- <https://learn.microsoft.com/en-us/windows/security/operating-system-security/network-security/windows-firewall/>
- <https://learn.microsoft.com/en-us/powershell/module/netsecurity/set-netfirewallprofile>

---

## Updates and outdated software

Most real-world compromises use a bug that was patched months ago. These findings track Windows itself and the apps installed alongside it.

### WIN-UPD-001

**{count} Windows updates are pending**  
Severity `medium` · category `updates` · raised at most once — it has a single subject

Emitted by `scanners/updates.py` (Windows Update and winget).  
Severity is raised to `high` when a pending update's title looks like a security or cumulative update — see `scanners/updates.py`.  

**Why it matters.** Most malware exploits bugs that were already fixed; installing the pending updates (especially security and cumulative ones) closes those doors.

**How to fix it**

1. Open Start > Settings > Windows Update and click 'Check for updates', then 'Download & install all'.
2. Restart when prompted; check the page again after the restart in case a second round is waiting.
3. PowerShell: Start-Process ms-settings:windowsupdate   (opens the same page)

**Read more**

- <https://support.microsoft.com/en-us/windows/update-windows-3c5ae7fc-9fb6-9af1-1984-b5e0412c556a>
- <https://learn.microsoft.com/en-us/windows/release-health/>

### WIN-UPD-002

**Last cumulative Windows update was {days} days ago**  
Severity `high` · category `updates` · raised at most once — it has a single subject

Emitted by `scanners/host_windows.py` (Windows posture probe), `scanners/updates.py` (Windows Update and winget).  
Degrades to `needs_admin` rather than pass/fail if its probe is refused.  

**Why it matters.** Windows should receive a cumulative security update every month; going more than 45 days without one usually means updates are stuck or paused and known holes are open.

**How to fix it**

1. Open Start > Settings > Windows Update. If it shows 'Updates paused', click 'Resume updates'.
2. Click 'Check for updates' and install everything, restarting as needed.
3. If it keeps failing: Settings > System > Troubleshoot > Other troubleshooters > Windows Update > Run.
4. PowerShell: Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 5

**Read more**

- <https://support.microsoft.com/en-us/windows/update-windows-3c5ae7fc-9fb6-9af1-1984-b5e0412c556a>
- <https://learn.microsoft.com/en-us/windows/release-health/>

### WIN-UPD-003

**Outdated app: {name} {version} (available {available})**  
Severity `low` · category `updates` · raised once per affected subject

Emitted by `scanners/updates.py` (Windows Update and winget), `vulns/matcher.py` (KEV/NVD/EPSS matcher).  

**Why it matters.** Old versions of everyday apps keep known bugs that drive-by downloads and malicious documents exploit; updating them is the cheapest fix there is.

**How to fix it**

1. Open Start > 'Microsoft Store' > Library (bottom-left) > 'Get updates' for Store apps.
2. For everything else open Start, type 'Terminal', press Enter and run: winget upgrade --id "{id}"
3. Or update all at once: winget upgrade --all --include-unknown

**Read more**

- <https://learn.microsoft.com/en-us/windows/package-manager/winget/upgrade>

### WIN-UPD-004

**Outdated high-risk app: {name} {version} (available {available})**  
Severity `high` · category `updates` · raised once per affected subject

Emitted by `findings/score.py`, `scanners/updates.py` (Windows Update and winget), `vulns/matcher.py` (KEV/NVD/EPSS matcher).  

**Why it matters.** This program (browser, runtime, archiver, remote-access or media tool) is a favourite exploit target; running an old version is one of the most common ways home PCs get compromised.

**How to fix it**

1. Close the app, open Start, type 'Terminal', press Enter and run: winget upgrade --id "{id}"
2. If winget cannot update it, open the app's own 'Help > Check for updates' menu or reinstall from the vendor site.
3. If you no longer use the app (e.g. Java, old VNC/TeamViewer), uninstall it: Settings > Apps > Installed apps.

**Read more**

- <https://learn.microsoft.com/en-us/windows/package-manager/winget/upgrade>
- <https://www.cisa.gov/known-exploited-vulnerabilities-catalog>

---

## Accounts and sign-in

Who can change the machine, and how hard it is for a program to do it silently.

### WIN-ACC-001

**Your daily account '{user}' is an Administrator**  
Severity `medium` · category `accounts` · raised at most once — it has a single subject

Emitted by `scanners/host_windows.py` (Windows posture probe).  
Degrades to `needs_admin` rather than pass/fail if its probe is refused.  

**Why it matters.** Malware runs with the rights of the user who launched it; using a standard account for daily work means a bad click cannot install drivers, disable the antivirus or encrypt other users' files without a UAC prompt.

**How to fix it**

1. Open Start > Settings > Accounts > 'Other users' > 'Add account' and create a second, local account (choose 'I don't have this person's sign-in information' > 'Add a user without a Microsoft account').
2. Click the new account > 'Change account type' > 'Administrator' (this becomes your admin account).
3. Sign in to the new admin account once, then go to Settings > Accounts > Other users, select your daily account > 'Change account type' > 'Standard User'.
4. Sign back in to your daily account; Windows will now ask for the admin password only when needed.
5. PowerShell (admin): Remove-LocalGroupMember -Group Administrators -Member "{user}"

**Read more**

- <https://support.microsoft.com/en-us/windows/create-a-local-user-or-administrator-account-in-windows-20de74e0-ac7f-3502-a866-32915af2a34d>
- <https://learn.microsoft.com/en-us/windows/security/identity-protection/access-control/local-accounts>
- <https://learn.microsoft.com/en-us/windows/security/application-security/application-control/user-account-control/how-it-works>

### WIN-ACC-002

**Built-in Administrator account is enabled**  
Severity `high` · category `accounts` · raised at most once — it has a single subject

Emitted by `scanners/host_windows.py` (Windows posture probe).  
Degrades to `needs_admin` rather than pass/fail if its probe is refused.  

**Why it matters.** The built-in Administrator has no UAC prompts and a well-known name, making it the first account attackers try; Windows disables it by default for a reason.

**How to fix it**

1. Open Start, type 'PowerShell', right-click it and choose 'Run as administrator'.
2. Run: Disable-LocalUser -Name Administrator
3. Make sure you have another administrator account first (Settings > Accounts > Other users).

**Read more**

- <https://learn.microsoft.com/en-us/windows/security/identity-protection/access-control/local-accounts>

### WIN-ACC-003

**Guest account is enabled**  
Severity `high` · category `accounts` · raised at most once — it has a single subject

Emitted by `scanners/host_windows.py` (Windows posture probe).  
Degrades to `needs_admin` rather than pass/fail if its probe is refused.  

**Why it matters.** The Guest account lets anyone on the network or at the keyboard sign in without a password and can be used as a foothold; it should stay disabled on Windows 11.

**How to fix it**

1. Open Start, type 'PowerShell', right-click it and choose 'Run as administrator'.
2. Run: Disable-LocalUser -Name Guest

**Read more**

- <https://learn.microsoft.com/en-us/windows/security/identity-protection/access-control/local-accounts>

### WIN-ACC-004

**Automatic logon is enabled**  
Severity `high` · category `accounts` · raised at most once — it has a single subject

Emitted by `scanners/host_windows.py` (Windows posture probe).  

**Why it matters.** Autologon stores your password in the registry in a recoverable form and lets anyone who powers on the PC straight into your session; a stolen laptop is then fully open.

**How to fix it**

1. Press Win+R, type 'netplwiz' and press Enter.
2. Tick 'Users must enter a user name and password to use this computer' and click OK. If the box is missing, open Settings > Accounts > Sign-in options and turn Windows Hello sign-in requirement On first.
3. PowerShell (admin): Remove-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name DefaultPassword -ErrorAction SilentlyContinue; Set-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name AutoAdminLogon -Value 0

**Read more**

- <https://learn.microsoft.com/en-us/sysinternals/downloads/autologon>

### WIN-ACC-005

**User Account Control (UAC) is off or set to never prompt**  
Severity `high` · category `accounts` · raised at most once — it has a single subject

Emitted by `scanners/host_windows.py` (Windows posture probe).  

**Why it matters.** UAC is the prompt that stops a program from silently becoming administrator; with it off, any malware you run owns the whole machine immediately.

**How to fix it**

1. Open Start, type 'UAC' and choose 'Change User Account Control settings'.
2. Move the slider to the top or second-from-top notch ('Always notify' or 'Notify me only when apps try to make changes') and click OK, then restart.
3. PowerShell (admin): Set-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name EnableLUA -Value 1; Set-ItemProperty (same key) -Name ConsentPromptBehaviorAdmin -Value 5

**Read more**

- <https://learn.microsoft.com/en-us/windows/security/application-security/application-control/user-account-control/how-it-works>

---

## Network services on this PC

Services this PC offers to the rest of the LAN. Every open port is a door; these findings are about the doors you did not mean to leave open.

### WIN-NET-001

**SMBv1 file sharing protocol is enabled**  
Severity `high` · category `host-network` · raised at most once — it has a single subject

Emitted by `scanners/host_windows.py` (Windows posture probe).  
Degrades to `needs_admin` rather than pass/fail if its probe is refused.  

**Why it matters.** SMBv1 is the 30-year-old protocol WannaCry and NotPetya spread through; nothing modern needs it and Microsoft removes it by default.

**How to fix it**

1. Open Start, type 'Turn Windows features on or off' and press Enter (accept UAC).
2. Untick 'SMB 1.0/CIFS File Sharing Support' (and all its sub-items), click OK and restart.
3. PowerShell (admin): Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart

**Read more**

- <https://learn.microsoft.com/en-us/windows-server/storage/file-server/troubleshoot/detect-enable-and-disable-smbv1-v2-v3>

### WIN-NET-002

**Remote Desktop is enabled (Network Level Authentication: {nla})**  
Severity `medium` · category `host-network` · raised at most once — it has a single subject

Emitted by `scanners/host_windows.py` (Windows posture probe).  
Severity is raised to `high` when Network Level Authentication is off — see `scanners/host_windows.py`.  

**Why it matters.** Remote Desktop exposes a password login to the network; it is constantly brute-forced, and without Network Level Authentication an attacker can probe it before even entering a password.

**How to fix it**

1. If you do not use Remote Desktop: open Start > Settings > System > Remote Desktop and turn it Off.
2. If you do use it: keep it On, expand the entry and tick 'Require devices to use Network Level Authentication to connect', and use a long password or a Microsoft account with 2-step verification.
3. Never forward port 3389 on your router; use a VPN (Tailscale/WireGuard) or the Remote Desktop app via a cloud relay instead.
4. PowerShell (admin): Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -Name fDenyTSConnections -Value 1

**Read more**

- <https://learn.microsoft.com/en-us/windows-server/remote/remote-desktop-services/clients/remote-desktop-allow-access>

### WIN-NET-003

**SMB signing is not required**  
Severity `low` · category `host-network` · raised at most once — it has a single subject

Emitted by `scanners/host_windows.py` (Windows posture probe).  
Degrades to `needs_admin` rather than pass/fail if its probe is refused.  

**Why it matters.** Without SMB signing, a device on the same Wi-Fi can tamper with or relay file-sharing traffic; requiring it is a small hardening step with no visible cost at home.

**How to fix it**

1. Open Start, type 'PowerShell', right-click and choose 'Run as administrator'.
2. Run: Set-SmbServerConfiguration -RequireSecuritySignature $true -Force; Set-SmbClientConfiguration -RequireSecuritySignature $true -Force
3. Note: Windows 11 24H2 already requires signing for the client by default; older NAS boxes may need a firmware update.

**Read more**

- <https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-signing-overview>

### WIN-NET-004

**LLMNR name resolution is enabled**  
Severity `low` · category `host-network` · raised at most once — it has a single subject

Emitted by `scanners/host_windows.py` (Windows posture probe).  

**Why it matters.** LLMNR lets any device on the LAN answer 'who is FILESERVER?'; attackers use it to capture password hashes from a mistyped share name. Home networks resolve names fine without it.

**How to fix it**

1. Windows Home has no Group Policy editor, so use the registry.
2. Open Start, type 'PowerShell', right-click and choose 'Run as administrator', then run: New-Item 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' -Force | Out-Null; Set-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' -Name EnableMulticast -Value 0
3. Restart the PC for the change to take effect.

**Read more**

- <https://media.defense.gov/2023/Feb/22/2003165170/-1/-1/0/CSI_BEST_PRACTICES_FOR_SECURING_YOUR_HOME_NETWORK.PDF>

### WIN-NET-005

**WinRM / Remote Registry is listening on the network ({port})**  
Severity `medium` · category `host-network` · raised once per affected subject

Emitted by `scanners/host_windows.py` (Windows posture probe).  

**Why it matters.** WinRM (5985/5986) and Remote Registry let anyone with your password run commands or edit the registry remotely; home PCs almost never need them switched on.

**How to fix it**

1. Open Start, type 'PowerShell', right-click and choose 'Run as administrator'.
2. Run: Disable-PSRemoting -Force; Stop-Service WinRM; Set-Service WinRM -StartupType Disabled
3. Then: Stop-Service RemoteRegistry; Set-Service RemoteRegistry -StartupType Disabled

**Read more**

- <https://learn.microsoft.com/en-us/windows/win32/winrm/installation-and-configuration-for-windows-remote-management>

### WIN-NET-006

**Unusual program listening on the LAN: port {port} ({process})**  
Severity `low` · category `host-network` · raised once per affected subject

Emitted by `scanners/host_windows.py` (Windows posture probe).  
Degrades to `needs_admin` rather than pass/fail if its probe is refused.  

**Why it matters.** A program accepting connections from the network is an entry point; if you did not install it deliberately, it deserves a look.

**How to fix it**

1. Open Start, type 'Resource Monitor', press Enter, open the 'Network' tab and expand 'Listening Ports' to see which program owns port {port}.
2. If it is something you installed (game launcher, media server, sync tool) you can ignore or suppress this finding.
3. If unknown, uninstall the program (Settings > Apps > Installed apps) or block it: Windows Security > 'Firewall & network protection' > 'Allow an app through firewall' and untick it.
4. PowerShell: Get-NetTCPConnection -State Listen -LocalPort {port} | Select-Object OwningProcess; Get-Process -Id <pid>

**Read more**

- <https://learn.microsoft.com/en-us/windows/security/operating-system-security/network-security/windows-firewall/>
- <https://media.defense.gov/2023/Feb/22/2003165170/-1/-1/0/CSI_BEST_PRACTICES_FOR_SECURING_YOUR_HOME_NETWORK.PDF>

---

## System hardening

Boot-time and kernel-level protections. Several of these can only be read with administrator rights and will show as "needs admin" on a normal run.

### WIN-SYS-001

**Secure Boot is off**  
Severity `medium` · category `system` · raised at most once — it has a single subject

Emitted by `scanners/host_windows.py` (Windows posture probe).  
Degrades to `needs_admin` rather than pass/fail if its probe is refused.  

**Why it matters.** Secure Boot stops rootkits from loading before Windows starts; with it off, a bootkit can hide from every antivirus.

**How to fix it**

1. Open Start > Settings > System > Recovery > 'Advanced startup' > 'Restart now'.
2. Choose Troubleshoot > Advanced options > UEFI Firmware Settings > Restart.
3. In the firmware find 'Secure Boot' (usually under Boot or Security), set it to Enabled, save and exit.
4. PowerShell (admin) to verify: Confirm-SecureBootUEFI

**Read more**

- <https://learn.microsoft.com/en-us/windows/security/operating-system-security/system-security/secure-the-windows-10-boot-process>

### WIN-SYS-002

**BitLocker / device encryption is off**  
Severity `high` · category `system` · raised at most once — it has a single subject

Emitted by `scanners/host_windows.py` (Windows posture probe).  
**Needs administrator rights**: without elevation this is recorded as `needs_admin` (not measured) rather than pass or fail.  

**Why it matters.** If the laptop is lost or stolen, an unencrypted drive gives up every file, saved password and browser session to whoever plugs it into another PC.

**How to fix it**

1. Open Start > Settings > Privacy & security > 'Device encryption' and turn it On (sign in with a Microsoft account so the recovery key is backed up to https://account.microsoft.com/devices/recoverykey).
2. If 'Device encryption' is not listed, Windows Home cannot use BitLocker; enable Secure Boot and TPM in firmware (see WIN-SYS-001 / WIN-SYS-008) and check again, or upgrade to Windows Pro.
3. PowerShell (admin) to check: Get-BitLockerVolume | Select-Object MountPoint, ProtectionStatus

**Read more**

- <https://support.microsoft.com/en-us/windows/device-encryption-in-windows-cf7e2b6f-3e70-4882-9532-18633605b7df>

### WIN-SYS-003

**Virtualization-based security / memory integrity (HVCI) is not running**  
Severity `low` · category `system` · raised at most once — it has a single subject

Emitted by `scanners/host_windows.py` (Windows posture probe).  
Degrades to `needs_admin` rather than pass/fail if its probe is refused.  

**Why it matters.** Memory integrity keeps malicious drivers out of the Windows kernel, one of the few places antivirus cannot see. It is free on hardware that supports it.

**How to fix it**

1. Open Start, type 'Windows Security' and press Enter. Click 'Device security' > 'Core isolation details'.
2. Turn 'Memory integrity' On and restart. If Windows lists incompatible drivers, update or remove them first.
3. PowerShell (admin): Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity' -Name Enabled -Value 1

**Read more**

- <https://learn.microsoft.com/en-us/windows/security/hardware-security/enable-virtualization-based-protection-of-code-integrity>

### WIN-SYS-004

**LSA protection (RunAsPPL) is off**  
Severity `medium` · category `system` · raised at most once — it has a single subject

Emitted by `scanners/host_windows.py` (Windows posture probe).  

**Why it matters.** LSA holds your logon credentials in memory; without protection, tools like Mimikatz can dump them once they run as admin.

**How to fix it**

1. Open Start, type 'Windows Security' and press Enter. Click 'Device security' > 'Core isolation details' and turn 'Local Security Authority protection' On.
2. Restart the PC.
3. PowerShell (admin): Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name RunAsPPL -Value 2

**Read more**

- <https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection>

### WIN-SYS-005

**Windows PowerShell 2.0 engine is enabled**  
Severity `low` · category `system` · raised at most once — it has a single subject

Emitted by `scanners/host_windows.py` (Windows posture probe).  
**Needs administrator rights**: without elevation this is recorded as `needs_admin` (not measured) rather than pass or fail.  

**Why it matters.** PowerShell 2.0 has no script logging or AMSI antivirus hooks, so malware launches it on purpose to run unseen; nothing modern needs it.

**How to fix it**

1. Open Start, type 'Turn Windows features on or off' and press Enter (accept UAC).
2. Expand 'Windows PowerShell 2.0', untick it and click OK.
3. PowerShell (admin): Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root -NoRestart

**Read more**

- <https://devblogs.microsoft.com/powershell/windows-powershell-2-0-deprecation/>

### WIN-SYS-006

**SmartScreen is off**  
Severity `medium` · category `system` · raised at most once — it has a single subject

Emitted by `scanners/host_windows.py` (Windows posture probe).  

**Why it matters.** SmartScreen warns before running downloaded programs and visiting known phishing pages; it is the layer that catches the 'invoice.exe' a user double-clicks.

**How to fix it**

1. Open Start, type 'Windows Security' and press Enter. Click 'App & browser control' > 'Reputation-based protection settings'.
2. Turn On 'Check apps and files', 'SmartScreen for Microsoft Edge' and 'Phishing protection'.
3. PowerShell (admin): Set-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer' -Name SmartScreenEnabled -Value Warn

**Read more**

- <https://learn.microsoft.com/en-us/windows/security/operating-system-security/virus-and-threat-protection/microsoft-defender-smartscreen/>

### WIN-SYS-007

**Screen lock is not enforced**  
Severity `low` · category `system` · raised at most once — it has a single subject

Emitted by `scanners/host_windows.py` (Windows posture probe).  

**Why it matters.** An unlocked PC left on the desk exposes email, banking sessions and saved passwords to anyone walking by; an automatic lock after a few minutes costs nothing.

**How to fix it**

1. Open Start > Settings > Accounts > Sign-in options and set 'If you've been away, when should Windows require you to sign in again?' to a short interval (e.g. 5 or 15 minutes).
2. Then Settings > System > Power & battery > 'Screen and sleep' and set 'Turn my screen off after' to 10 minutes.
3. Get in the habit of pressing Win+L when you step away.
4. PowerShell: Set-ItemProperty 'HKCU:\Control Panel\Desktop' -Name ScreenSaveTimeOut -Value 600; Set-ItemProperty 'HKCU:\Control Panel\Desktop' -Name ScreenSaverIsSecure -Value 1

**Read more**

- <https://support.microsoft.com/en-us/windows/change-your-screen-saver-settings-a9dc2a0c-dc8e-9161-d270-aaccc252082a>

### WIN-SYS-008

**TPM is absent or not ready**  
Severity `low` · category `system` · raised at most once — it has a single subject

Emitted by `scanners/host_windows.py` (Windows posture probe).  
**Needs administrator rights**: without elevation this is recorded as `needs_admin` (not measured) rather than pass or fail.  

**Why it matters.** The TPM chip stores encryption keys and Windows Hello secrets in hardware; without it BitLocker, Secure Boot attestation and passkeys are weaker or unavailable.

**How to fix it**

1. Press Win+R, type 'tpm.msc' and press Enter to read the TPM status.
2. If it says 'Compatible TPM cannot be found', restart into firmware (Settings > System > Recovery > Advanced startup) and enable 'TPM', 'PTT' (Intel) or 'fTPM' (AMD) under Security.
3. PowerShell (admin): Get-Tpm

**Read more**

- <https://learn.microsoft.com/en-us/windows/security/hardware-security/tpm/trusted-platform-module-overview>

---

## Autostart and persistence

How a program arranges to start again after a reboot. Legitimate software does this too, so Home SOC records a baseline on its first run and only alerts on what is new after that.

### WIN-PER-001

**New autostart entry: {name}**  
Severity `medium` · category `persistence` · raised once per affected subject

Emitted by `scanners/persistence.py` (autostart baseline).  

**Why it matters.** Programs that start with Windows are how malware survives a reboot; a new entry that appeared since the last check should be something you installed on purpose.

**How to fix it**

1. Open Start > Settings > Apps > Startup and look for '{name}'. If you recognise it, leave it (or turn it off if you do not need it at startup) and acknowledge this finding.
2. If unknown: press Ctrl+Shift+Esc, open the 'Startup apps' tab, right-click the entry > 'Open file location' and check the file's publisher (right-click > Properties > Details).
3. Right-click the file > 'Scan with Microsoft Defender', then disable the entry (right-click > Disable) and uninstall the program.
4. PowerShell: Get-ItemProperty HKCU:\Software\Microsoft\Windows\CurrentVersion\Run; Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Run

**Read more**

- <https://learn.microsoft.com/en-us/sysinternals/downloads/autoruns>

### WIN-PER-002

**New scheduled task: {name}**  
Severity `medium` · category `persistence` · raised once per affected subject

Emitted by `scanners/persistence.py` (autostart baseline).  

**Why it matters.** Scheduled tasks are a favourite way for malware and unwanted updaters to run silently in the background; new non-Microsoft tasks deserve a quick look.

**How to fix it**

1. Open Start, type 'Task Scheduler' and press Enter; find '{name}' in the Task Scheduler Library.
2. Open the 'Actions' tab to see what it runs. If you recognise it, acknowledge this finding.
3. If unknown, right-click the task > Disable, then locate and scan the program it runs.
4. PowerShell: Get-ScheduledTask -TaskName "{name}" | Get-ScheduledTaskInfo; (Get-ScheduledTask -TaskName "{name}").Actions

**Read more**

- <https://learn.microsoft.com/en-us/windows/win32/taskschd/task-scheduler-start-page>
- <https://learn.microsoft.com/en-us/sysinternals/downloads/autoruns>

### WIN-PER-003

**New auto-start service: {name}**  
Severity `medium` · category `persistence` · raised once per affected subject

Emitted by `scanners/persistence.py` (autostart baseline).  

**Why it matters.** A Windows service runs with high privileges before anyone logs in; a new one that is not from Microsoft or a driver you installed is a classic malware foothold.

**How to fix it**

1. Press Win+R, type 'services.msc' and press Enter; find '{name}' and open its Properties to see the 'Path to executable'.
2. If you installed the related software (VPN, printer, game anti-cheat), acknowledge this finding.
3. If unknown: set 'Startup type' to Disabled, click Stop, then scan the executable with Defender and uninstall the program.
4. PowerShell: Get-CimInstance Win32_Service -Filter "Name='{name}'" | Select-Object Name, StartMode, PathName

**Read more**

- <https://learn.microsoft.com/en-us/sysinternals/downloads/autoruns>

---

## Downloaded files

Hash lookups for files that recently appeared in your Downloads folder. Home SOC sends the SHA-256 hash to VirusTotal, never the file itself.

### AV-FILE-001

**Malicious file in Downloads: {path}**  
Severity `critical` · category `files` · raised once per affected subject

Emitted by `scanners/files.py` (Downloads file checks).  

**Why it matters.** A file you downloaded recently is flagged as malware by multiple antivirus engines; if it has been opened, the PC may already be compromised.

**How to fix it**

1. Do NOT open the file. Open Windows Security > 'Virus & threat protection' > 'Scan options' > 'Full scan' > 'Scan now'.
2. Delete the file: open File Explorer, go to Downloads, right-click '{path}' > Delete, then empty the Recycle Bin.
3. If you already ran it: disconnect from Wi-Fi, run the 'Microsoft Defender Antivirus (offline scan)', and change your important passwords from a different device.
4. Look up the hash for details: https://www.virustotal.com/gui/file/{sha256}

**Read more**

- <https://docs.virustotal.com/>
- <https://support.microsoft.com/en-us/windows/stay-protected-with-windows-security-2ae0363d-0ada-c064-8b56-6a39afb6a963>

### AV-FILE-002

**Suspicious file in Downloads: {path}**  
Severity `medium` · category `files` · raised once per affected subject

Emitted by `scanners/files.py` (Downloads file checks).  

**Why it matters.** A few antivirus engines flag this download; it may be a false positive on an installer bundle, but check where it came from before opening it.

**How to fix it**

1. Right-click '{path}' in Downloads and choose 'Scan with Microsoft Defender'.
2. Check the report at https://www.virustotal.com/gui/file/{sha256} and read which engines flagged it and why.
3. If you did not intentionally download it from a source you trust, delete it.

**Read more**

- <https://docs.virustotal.com/>

---

## Linux and macOS hosts

The equivalent host checks when Home SOC runs on Linux or macOS instead of Windows.

### POSIX-ENC-001

**Disk is not encrypted**  
Severity `medium` · category `posix` · raised at most once — it has a single subject

Emitted by `scanners/host_posix.py` (Linux/macOS posture).  

**Why it matters.** A lost or stolen laptop with an unencrypted disk exposes every file and saved credential; full-disk encryption makes the drive useless without your password.

**How to fix it**

1. macOS: Apple menu > System Settings > Privacy & Security > FileVault > Turn On (store the recovery key safely).
2. Linux: encryption (LUKS) is normally chosen during installation; back up and reinstall with 'Encrypt the new installation', or encrypt your home directory with ecryptfs/fscrypt as an interim step.

**Read more**

- <https://support.apple.com/guide/mac-help/protect-data-on-your-mac-with-filevault-mh11785/mac>

### POSIX-FW-001

**Host firewall is inactive**  
Severity `high` · category `posix` · raised at most once — it has a single subject

Emitted by `scanners/host_posix.py` (Linux/macOS posture).  

**Why it matters.** Without a host firewall, every listening service on this machine is reachable by any device on the network, including a compromised smart TV or a guest's phone.

**How to fix it**

1. Ubuntu/Debian: sudo ufw default deny incoming; sudo ufw default allow outgoing; sudo ufw enable
2. macOS: Apple menu > System Settings > Network > Firewall > turn On (and enable 'Block all incoming connections' if you do not share anything).
3. Fedora: sudo systemctl enable --now firewalld

**Read more**

- <https://help.ubuntu.com/community/UFW>
- <https://support.apple.com/guide/mac-help/block-connections-to-your-mac-with-a-firewall-mh34041/mac>

### POSIX-NET-001

**Unusual service listening on the network: port {port} ({process})**  
Severity `low` · category `posix` · raised once per affected subject

Emitted by `scanners/host_posix.py` (Linux/macOS posture).  

**Why it matters.** A network-facing service you did not knowingly start is an entry point; confirm what it is and bind it to localhost or firewall it if it does not need LAN access.

**How to fix it**

1. Linux: sudo ss -ltnp | grep ':{port}'   macOS: sudo lsof -iTCP:{port} -sTCP:LISTEN
2. If the program only needs local access, configure it to listen on 127.0.0.1 instead of 0.0.0.0.
3. Otherwise block the port: sudo ufw deny {port}/tcp   (macOS: use the Firewall settings).

**Read more**

- <https://media.defense.gov/2023/Feb/22/2003165170/-1/-1/0/CSI_BEST_PRACTICES_FOR_SECURING_YOUR_HOME_NETWORK.PDF>

### POSIX-SSH-001

**SSH allows root login**  
Severity `high` · category `posix` · raised at most once — it has a single subject

Emitted by `scanners/host_posix.py` (Linux/macOS posture).  

**Why it matters.** Root login over SSH gives brute-force bots a guaranteed username to attack; disabling it and using sudo from a normal user removes half the attack.

**How to fix it**

1. Edit the SSH server config: sudo nano /etc/ssh/sshd_config
2. Set 'PermitRootLogin no' (and ideally 'PasswordAuthentication no' once you have SSH keys set up), save.
3. Restart SSH: sudo systemctl restart ssh   (macOS: sudo launchctl kickstart -k system/com.openssh.sshd)

**Read more**

- <https://man.openbsd.org/sshd_config>

### POSIX-UPD-001

**{count} system updates pending**  
Severity `medium` · category `posix` · raised at most once — it has a single subject

Emitted by `scanners/updates.py` (Windows Update and winget).  

**Why it matters.** Unpatched packages are the most common way Linux and macOS machines get compromised; the fix is one command away.

**How to fix it**

1. Ubuntu/Debian: sudo apt update && sudo apt upgrade -y
2. macOS: Apple menu > System Settings > General > Software Update, or: sudo softwareupdate -ia; brew upgrade
3. Fedora: sudo dnf upgrade --refresh

**Read more**

- <https://www.cisa.gov/secure-our-world>

---

## Devices on your network

The inventory side: what is connected to your network, and what changed.

### NET-DEV-001

**New device on the network: {ip} ({vendor})**  
Severity `medium` · category `devices` · raised once per affected subject

Emitted by `findings/engine.py`, `scanners/discovery.py` (device discovery).  
Severity is lowered to `info` for every device found by the very first (baseline) discovery run — see `scanners/discovery.py`.  

**Why it matters.** Every device on your Wi-Fi can reach every other device; an unknown one may be a neighbour using your Wi-Fi, a forgotten gadget with default passwords, or an intruder.

**How to fix it**

1. Open the Home SOC Devices page and identify it by IP {ip}, hostname '{hostname}' and vendor '{vendor}'. Check phones/laptops/TVs/plugs in the house that were just connected.
2. If it is yours, give it a nickname and tick 'Trusted' so it is not reported again.
3. If you do not recognise the device, change your Wi-Fi password and reconnect only the devices you own.
4. Also check the router's connected-devices list for the same MAC, and consider enabling the router's guest network for smart-home gadgets.

**If you have a pile of these at once.** A first install on an established house raises one of these
per device, and clicking Trusted twenty-three times is not a good use of an evening. Once you have
looked over the Devices page and recognise everything on it, accept the whole inventory in one go:

```
python -m homesoc baseline --dry-run    # list what would be trusted and closed
python -m homesoc baseline              # tick Trusted on every known device, close their NET-DEV-001 rows
```

Each closed row keeps an audit trail in `finding_events` ("accepted as part of the baseline
inventory"), the `NET-DEV-002` info rows are left alone, and re-running it is a no-op. Any device
that joins *after* the baseline raises a fresh `NET-DEV-001` at full `medium` severity, which is the
point of doing it.

**Read more**

- <https://media.defense.gov/2023/Feb/22/2003165170/-1/-1/0/CSI_BEST_PRACTICES_FOR_SECURING_YOUR_HOME_NETWORK.PDF>
- <https://www.cisa.gov/news-events/news/home-network-security>

### NET-DEV-002

**Device with unknown vendor or randomized MAC: {ip}**  
Severity `info` · category `devices` · raised once per affected subject

Emitted by `scanners/discovery.py` (device discovery).  

**Why it matters.** Phones and laptops now randomise their Wi-Fi address for privacy, so this is usually harmless, but it means the inventory cannot recognise the device across reconnects.

**How to fix it**

1. Check whether the device is a phone/laptop you own (it will reconnect with a new MAC each time).
2. To make it recognisable, turn off 'Private/Random Wi-Fi address' for your home network on that device (iOS: Wi-Fi > (i) > Private Wi-Fi Address; Android: network details > Privacy > Use device MAC).
3. Then mark it Trusted on the Devices page.

**Read more**

- <https://media.defense.gov/2023/Feb/22/2003165170/-1/-1/0/CSI_BEST_PRACTICES_FOR_SECURING_YOUR_HOME_NETWORK.PDF>

### NET-DEV-003

**Trusted device '{name}' has been offline for {days} days**  
Severity `info` · category `devices` · raised once per affected subject

Emitted by `cli.py` (Home SOC self-checks), `scanners/discovery.py` (device discovery).  

**Why it matters.** A trusted device that has not been seen for a month is probably gone; keeping it trusted means a new device with the same address would be silently accepted.

**How to fix it**

1. Open the Devices page and check whether you still own the device.
2. If it is gone (sold, replaced), untick 'Trusted' or delete it from the inventory.

### NET-DEV-004

**{count} new devices appeared in one network scan**
Severity `high` · category `devices` · raised once per affected subject

Emitted by `scanners/discovery.py` (device discovery).

**Why it matters.** A home network gains a device now and then, not dozens at once. A burst like this usually means one device is answering for many addresses with made-up hardware (MAC) addresses, which is how a compromised gadget floods or spoofs the network. After the first scan, Home SOC adds at most 32 new devices per scan and 256 per day, and holds the rest back so the inventory stays usable.

**How to fix it**

1. Open the Devices page, sort by 'first seen' and look at the newest entries: many unknown devices with random-looking MAC addresses on one IP range point at a single misbehaving device.
2. Unplug or power off recently added gadgets one at a time (cameras, plugs, TV boxes) and run a discovery scan after each; when the burst stops you have found the culprit.
3. Keep that device off the network, or move it to the router's guest/IoT network, and update or factory-reset it before reconnecting.

---

## Services exposed by devices on the LAN

Ports and services found on other devices during a service scan. Home users rarely choose these settings themselves - they come from factory defaults on printers, cameras, routers and NAS boxes.

### NET-SVC-001

**Telnet open on {ip}:{port}**  
Severity `critical` · category `lan-services` · raised once per affected subject

Emitted by `scanners/services.py` (LAN service rules).  

**Why it matters.** Telnet sends passwords in clear text and is the main way IoT botnets (Mirai and friends) take over cameras, routers and DVRs; nothing made in the last decade needs it.

**How to fix it**

1. Identify the device on the Devices page ({vendor}, '{hostname}').
2. Log in to its web admin page and disable Telnet (often under Administration > Access / Services / Remote Management); enable SSH or HTTPS instead if remote access is needed.
3. If the device cannot disable Telnet, update its firmware, change the admin password, and move it to the router's guest/IoT network.
4. Verify: nmap -p {port} {ip}   (should show closed/filtered)

**Read more**

- <https://media.defense.gov/2023/Feb/22/2003165170/-1/-1/0/CSI_BEST_PRACTICES_FOR_SECURING_YOUR_HOME_NETWORK.PDF>
- <https://www.cisa.gov/news-events/news/home-network-security>

### NET-SVC-002

**FTP open on {ip}:{port}**  
Severity `high` · category `lan-services` · raised once per affected subject

Emitted by `scanners/services.py` (LAN service rules).  

**Why it matters.** FTP sends usernames and passwords unencrypted across the Wi-Fi and is frequently left with anonymous access enabled on NAS boxes and printers.

**How to fix it**

1. Open the device's admin page and turn off FTP (look under File Services / Sharing / Protocols).
2. Use SFTP, SMB with a password, or the device's cloud sync instead.
3. If FTP must stay on: disable anonymous login, set a strong password and restrict it to the LAN.

**Read more**

- <https://media.defense.gov/2023/Feb/22/2003165170/-1/-1/0/CSI_BEST_PRACTICES_FOR_SECURING_YOUR_HOME_NETWORK.PDF>

### NET-SVC-003

**SMB file sharing on non-Windows device {ip}:{port}**  
Severity `medium` · category `lan-services` · raised once per affected subject

Emitted by `scanners/services.py` (LAN service rules).  

**Why it matters.** A NAS, TV or camera exposing SMB may have guest access or an old vulnerable Samba build; file shares are what ransomware encrypts first.

**How to fix it**

1. Open the device's admin page and check the file-sharing settings: disable guest/anonymous access and SMBv1, require a password.
2. Update the device firmware, and if sharing is not needed, turn the service off.
3. On the Home SOC Devices page mark the device Trusted once reviewed.

**Read more**

- <https://learn.microsoft.com/en-us/windows-server/storage/file-server/troubleshoot/detect-enable-and-disable-smbv1-v2-v3>
- <https://media.defense.gov/2023/Feb/22/2003165170/-1/-1/0/CSI_BEST_PRACTICES_FOR_SECURING_YOUR_HOME_NETWORK.PDF>

### NET-SVC-004

**Remote desktop (RDP/VNC) exposed on {ip}:{port}**  
Severity `medium` · category `lan-services` · raised once per affected subject

Emitted by `scanners/services.py` (LAN service rules).  

**Why it matters.** Remote-control services are brute-forced constantly; VNC in particular often has no password or a trivial one, giving full control of the device.

**How to fix it**

1. On the device, disable remote desktop / VNC if not needed (Windows: Settings > System > Remote Desktop; macOS: System Settings > General > Sharing > Screen Sharing).
2. If needed, set a long password, enable NLA/encryption, and never forward the port on the router.

**Read more**

- <https://learn.microsoft.com/en-us/windows-server/remote/remote-desktop-services/clients/remote-desktop-allow-access>

### NET-SVC-005

**HTTP admin interface without HTTPS on {ip}:{port}**  
Severity `low` · category `lan-services` · raised once per affected subject

Emitted by `scanners/services.py` (LAN service rules).  

**Why it matters.** Logging in to a router or gadget over plain HTTP sends the admin password in clear text over Wi-Fi.

**How to fix it**

1. In the device's admin page look for an 'HTTPS only' / 'Secure web access' option and enable it.
2. Otherwise only manage the device from a wired or trusted connection and keep its firmware updated.

**Read more**

- <https://media.defense.gov/2023/Feb/22/2003165170/-1/-1/0/CSI_BEST_PRACTICES_FOR_SECURING_YOUR_HOME_NETWORK.PDF>

### NET-SVC-006

**UPnP / SSDP control port open on {ip}:{port}**  
Severity `medium` · category `lan-services` · raised once per affected subject

Emitted by `scanners/services.py` (LAN service rules).  

**Why it matters.** UPnP lets any program on the network reconfigure the device without a password; on a router that means malware can open holes to the internet.

**How to fix it**

1. Open your router's admin page (usually http://192.168.1.254 or http://192.168.1.1) in a browser and sign in with the password printed on the router label.
2. Find 'UPnP' (often under Advanced > NAT/Gaming or Firewall) and disable it; set up manual port forwards only for what you really need.
3. For other devices (TVs, speakers) UPnP discovery is normal; suppress this finding if you accept it.

**Read more**

- <https://media.defense.gov/2023/Feb/22/2003165170/-1/-1/0/CSI_BEST_PRACTICES_FOR_SECURING_YOUR_HOME_NETWORK.PDF>
- <https://www.cisa.gov/news-events/news/home-network-security>

### NET-SVC-007

**Database port open on {ip}:{port} ({product})**  
Severity `high` · category `lan-services` · raised once per affected subject

Emitted by `scanners/services.py` (LAN service rules).  

**Why it matters.** Databases like MySQL, Redis and MongoDB often ship without a password; exposed on the LAN they hand over all their data to anyone who connects.

**How to fix it**

1. On the host, configure the database to listen only on 127.0.0.1 (MySQL: bind-address=127.0.0.1; Redis: bind 127.0.0.1 and requirepass; MongoDB: net.bindIp).
2. Set a strong password / enable authentication and restart the service.
3. Block the port in the host firewall (Windows: Windows Security > Firewall > Advanced settings > Inbound rule).

**Read more**

- <https://redis.io/docs/latest/operate/oss_and_stack/management/security/>
- <https://dev.mysql.com/doc/refman/8.0/en/security-guidelines.html>

### NET-SVC-008

**Printer raw port / IPP without authentication on {ip}:{port}**  
Severity `low` · category `lan-services` · raised once per affected subject

Emitted by `scanners/services.py` (LAN service rules).  

**Why it matters.** Raw port 9100 and unauthenticated IPP let anyone on the network print, read the job queue or, on some models, change settings and firmware.

**How to fix it**

1. Open the printer's web page (http://{ip}) and set an administrator password under Settings / Security.
2. Disable unused protocols (Raw 9100, FTP, Telnet, SNMP v1/v2) if the printer offers it and keep IPP/AirPrint.
3. Update the printer firmware and consider moving it to the guest/IoT network.

**Read more**

- <https://media.defense.gov/2023/Feb/22/2003165170/-1/-1/0/CSI_BEST_PRACTICES_FOR_SECURING_YOUR_HOME_NETWORK.PDF>

### NET-SVC-009

**SNMP with default community on {ip}**  
Severity `medium` · category `lan-services` · raised once per affected subject

Emitted by `scanners/services.py` (LAN service rules).  

**Why it matters.** SNMP with the 'public' community string reveals the device's configuration, connected clients and sometimes lets an attacker change settings.

**How to fix it**

1. Open the device's admin page and disable SNMP, or switch to SNMPv3 with a password.
2. If SNMP v1/v2c must stay, change the community strings from 'public'/'private' to something random.

**Read more**

- <https://www.cisa.gov/news-events/alerts/2017/06/05/reducing-risk-snmp-abuse>

### NET-SVC-010

**RTSP camera stream exposed on {ip}:{port}**  
Severity `medium` · category `lan-services` · raised once per affected subject

Emitted by `scanners/services.py` (LAN service rules).  

**Why it matters.** Camera streams with no or default passwords are indexed by public sites; anyone on the network (or the internet, if forwarded) can watch.

**How to fix it**

1. Open the camera's app or web page and set a unique strong password; disable RTSP if you only use the app.
2. Ensure the router does NOT forward this port to the internet (check NET-WAN findings).
3. Move cameras to the guest/IoT network and update their firmware.

**Read more**

- <https://www.cisa.gov/news-events/news/home-network-security>
- <https://media.defense.gov/2023/Feb/22/2003165170/-1/-1/0/CSI_BEST_PRACTICES_FOR_SECURING_YOUR_HOME_NETWORK.PDF>

### NET-SVC-011

**Outdated SSH server on {ip}:{port} ({product} {version})**  
Severity `low` · category `lan-services` · raised once per affected subject

Emitted by `scanners/services.py` (LAN service rules).  

**Why it matters.** Old SSH builds carry known vulnerabilities and weak ciphers; on routers and NAS boxes it usually means the whole firmware is old.

**How to fix it**

1. Update the device's firmware / operating system (routers: admin page > Firmware update; Linux: sudo apt update && sudo apt upgrade).
2. If SSH is not used, disable it in the device settings.

**Read more**

- <https://www.openssh.com/releasenotes.html>

### NET-SVC-012

**Device {ip} advertises its hardware model on the network ({exposed})**  
Severity `info` · category `lan-services` · raised once per affected subject

Emitted by `scanners/services.py` (LAN service rules).  

**Why it matters.** Broadcasting the exact model helps attackers pick the right exploit; it is normal for smart-home gear and only worth noting.

**How to fix it**

1. Nothing to fix; use the model name to check the vendor site for firmware updates.
2. Mark the device Trusted on the Devices page.

---

## Known vulnerabilities (CVE / KEV / EPSS)

Where a service's product and version are matched against CISA KEV, NVD and EPSS. These are the findings that say "this exact software has a known, published hole".

### NET-VUL-001

**Known exploited vulnerability {cve} on {ip} ({product} {version})**  
Severity `critical` · category `vulns` · raised once per affected subject

Emitted by `vulns/matcher.py` (KEV/NVD/EPSS matcher).  

**Why it matters.** This CVE is on CISA's Known Exploited Vulnerabilities list, meaning criminals are actively using it right now; devices running the affected version get taken over automatically.

**How to fix it**

1. Read the entry: https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext={cve}
2. Update the device's firmware or the affected software ({product}) to a fixed version from the vendor.
3. If no fix exists, disable the affected service or replace the device; at minimum block it from the internet and move it to the guest network.

**Read more**

- <https://www.cisa.gov/known-exploited-vulnerabilities-catalog>
- <https://nvd.nist.gov/vuln/search>

### NET-VUL-002

**Possible known-exploited vulnerability {cve} on {ip} ({product})**  
Severity `high` · category `vulns` · raised once per affected subject

Emitted by `vulns/matcher.py` (KEV/NVD/EPSS matcher).  

**Why it matters.** The software matches a CISA KEV entry but the version could not be confirmed; assume it is vulnerable until the vendor says otherwise.

**How to fix it**

1. Check the device's firmware / software version in its admin page and compare it with the fixed version in the KEV entry: https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext={cve}
2. Update to the latest firmware; if already current, acknowledge this finding.

**Read more**

- <https://www.cisa.gov/known-exploited-vulnerabilities-catalog>

### NET-VUL-003

**{count} known CVEs (max CVSS {max_cvss}) for {product} {version} on {ip}**  
Severity `medium` · category `vulns` · raised once per affected subject

Emitted by `vulns/matcher.py` (KEV/NVD/EPSS matcher).  

**Why it matters.** The service version on this device has published vulnerabilities rated high or critical; an update closes them all at once.

**How to fix it**

1. Update the device firmware or the software ({product}) to the newest version.
2. Review the CVEs: https://nvd.nist.gov/vuln/search/results?query={product}+{version}
3. If updates are unavailable, disable the service or restrict it to the devices that need it.

**Read more**

- <https://nvd.nist.gov/vuln/search>

### NET-VUL-004

**Exploitation likely in the wild: {cves} on {ip}**  
Severity `high` · category `vulns` · raised once per affected subject

Emitted by `vulns/matcher.py` (KEV/NVD/EPSS matcher).  

**Why it matters.** EPSS estimates the chance a CVE is exploited in the wild within 30 days; above 50% it is effectively being used by attackers now, so these come before the rest of the backlog.

**How to fix it**

1. Update {product} {version} on {ip} (port {port}) as a priority - device admin page > Firmware update, or the vendor's download page for software.
2. Look each CVE up at https://nvd.nist.gov/vuln/search and check the EPSS score at https://www.first.org/epss/
3. If no fix exists, block the device from the internet on the router and move it to the guest network.

**Read more**

- <https://www.first.org/epss/>
- <https://nvd.nist.gov/vuln/search>

---

## Internet-facing exposure

What the internet can see of your home, checked from the outside via your public IP.

### NET-RTR-002

**Router has UPnP (IGD) enabled**  
Severity `medium` · category `wan` · raised at most once — it has a single subject

Emitted by `scanners/exposure.py` (WAN exposure probe).  

**Why it matters.** With UPnP on, any program on any device can open ports on your router without asking; turning it off stops malware from exposing your network.

**How to fix it**

1. Open your router's admin page (usually http://192.168.1.254 or http://192.168.1.1) in a browser and sign in with the password printed on the router label.
2. Find 'UPnP' (Advanced > NAT/Gaming, Firewall, or Home Network) and set it to Off; save and reboot the router.
3. If a console complains about NAT type, add a manual port forward for that console only.

**Read more**

- <https://media.defense.gov/2023/Feb/22/2003165170/-1/-1/0/CSI_BEST_PRACTICES_FOR_SECURING_YOUR_HOME_NETWORK.PDF>
- <https://www.cisa.gov/news-events/news/home-network-security>

### NET-WAN-001

**Port {port} is open to the internet on your public IP**  
Severity `critical` · category `wan` · raised once per affected subject

Emitted by `scanners/exposure.py` (WAN exposure probe).  

**Why it matters.** Something on your network is reachable from the whole internet; bots scan every public IP many times a day and will find and attack it.

**How to fix it**

1. Open your router's admin page (usually http://192.168.1.254 or http://192.168.1.1) in a browser and sign in with the password printed on the router label.
2. Look under Firewall / NAT / Port Forwarding / 'Pinholes' / DMZ and remove the rule for port {port} (and any DMZ host).
3. Disable UPnP on the router so devices cannot re-open ports.
4. If you need remote access, use a VPN (WireGuard/Tailscale) instead of forwarding ports.
5. Re-check from outside: https://internetdb.shodan.io/{public_ip}

**Read more**

- <https://internetdb.shodan.io/>
- <https://media.defense.gov/2023/Feb/22/2003165170/-1/-1/0/CSI_BEST_PRACTICES_FOR_SECURING_YOUR_HOME_NETWORK.PDF>

### NET-WAN-002

**Internet-facing vulnerabilities reported for your public IP: {vulns}**  
Severity `critical` · category `wan` · raised once per affected subject

Emitted by `scanners/exposure.py` (WAN exposure probe).  

**Why it matters.** Shodan has fingerprinted an exposed service on your public IP with known vulnerabilities; this is the most likely way your network gets breached.

**How to fix it**

1. Identify the exposed service (the NET-WAN-001 findings list the open ports). Open your router's admin page (usually http://192.168.1.254 or http://192.168.1.1) in a browser and sign in with the password printed on the router label.
2. Under Firewall / NAT / Port Forwarding remove the rule that exposes it (and any DMZ host), then save.
3. Update the router's firmware (admin page > Firmware / Software update) and restart it.
4. Look the CVEs up at https://nvd.nist.gov/vuln/search and re-check the exposure at https://internetdb.shodan.io/{public_ip}

**Read more**

- <https://internetdb.shodan.io/>
- <https://www.cisa.gov/known-exploited-vulnerabilities-catalog>

### NET-WAN-003

**UPnP port mapping: WAN {external_port} -> {internal_client}:{internal_port} ({description})**  
Severity `high` · category `wan` · raised once per affected subject

Emitted by `scanners/exposure.py` (WAN exposure probe).  

**Why it matters.** A device on your network opened a hole in the router by itself; games and consoles do this, but so does malware.

**How to fix it**

1. Check whether {internal_client} is a console/PC that needs the port (game hosting); otherwise remove the mapping.
2. Open your router's admin page (usually http://192.168.1.254 or http://192.168.1.1) in a browser and sign in with the password printed on the router label.
3. Disable UPnP (Advanced > NAT / Firewall / UPnP) and delete existing mappings; add manual forwards only if truly needed.

**Read more**

- <https://media.defense.gov/2023/Feb/22/2003165170/-1/-1/0/CSI_BEST_PRACTICES_FOR_SECURING_YOUR_HOME_NETWORK.PDF>

---

## Wi-Fi security

The encryption protecting the air between your devices and your router.

### NET-WIFI-001

**Wi-Fi '{ssid}' is open or uses WEP**  
Severity `critical` · category `wifi` · raised at most once — it has a single subject

Emitted by `scanners/wifi.py` (Wi-Fi check).  

**Why it matters.** Open and WEP networks let anyone nearby read your traffic and join your LAN; WEP can be cracked in minutes.

**How to fix it**

1. Open your router's admin page (usually http://192.168.1.254 or http://192.168.1.1) in a browser and sign in with the password printed on the router label.
2. Under Wireless / Wi-Fi security choose 'WPA2-Personal (AES)' or 'WPA3/WPA2 mixed' and set a long passphrase (12+ characters).
3. Reconnect your devices with the new passphrase.

**Read more**

- <https://www.wi-fi.org/discover-wi-fi/security>
- <https://media.defense.gov/2023/Feb/22/2003165170/-1/-1/0/CSI_BEST_PRACTICES_FOR_SECURING_YOUR_HOME_NETWORK.PDF>

### NET-WIFI-002

**Wi-Fi '{ssid}' uses WPA2 without WPA3**  
Severity `info` · category `wifi` · raised at most once — it has a single subject

Emitted by `scanners/wifi.py` (Wi-Fi check).  

**Why it matters.** WPA2 is still acceptable, but WPA3 protects against offline password guessing; enable it if your router and devices support it.

**How to fix it**

1. Open your router's admin page (usually http://192.168.1.254 or http://192.168.1.1) in a browser and sign in with the password printed on the router label.
2. Under Wireless security choose 'WPA3/WPA2 mixed' (transition mode) so old devices keep working.

**Read more**

- <https://www.wi-fi.org/discover-wi-fi/security>

### NET-WIFI-003

**Wi-Fi '{ssid}' uses TKIP encryption**  
Severity `high` · category `wifi` · raised at most once — it has a single subject

Emitted by `scanners/wifi.py` (Wi-Fi check).  

**Why it matters.** TKIP is a 2003 stop-gap cipher with known attacks; modern devices support AES (CCMP) and it also slows your network down.

**How to fix it**

1. Open your router's admin page (usually http://192.168.1.254 or http://192.168.1.1) in a browser and sign in with the password printed on the router label.
2. Under Wireless security set the encryption to 'AES' / 'CCMP' only (not 'TKIP' or 'TKIP+AES') and save.

**Read more**

- <https://www.wi-fi.org/discover-wi-fi/security>

### NET-WIFI-004

**WPS appears to be enabled on '{ssid}'**  
Severity `info` · category `wifi` · raised at most once — it has a single subject

Reserved in the catalog but never emitted: `netsh` and `nmcli` do not report the WPS state of the network you are associated with, so Home SOC would have to guess. Check it on the router instead — the steps below are still the right ones.  

**Why it matters.** WPS PIN mode can be brute-forced in hours on many routers, bypassing your Wi-Fi password entirely.

**How to fix it**

1. Open your router's admin page (usually http://192.168.1.254 or http://192.168.1.1) in a browser and sign in with the password printed on the router label.
2. Under Wireless > WPS set it to Off / Disabled and save; connect new devices with the passphrase instead.

**Read more**

- <https://www.wi-fi.org/discover-wi-fi/security>
- <https://media.defense.gov/2023/Feb/22/2003165170/-1/-1/0/CSI_BEST_PRACTICES_FOR_SECURING_YOUR_HOME_NETWORK.PDF>

---

## DNS filter

The state of Home SOC's own LAN-wide DNS filter, and what it caught.

### NET-DNS-001

**Devices are not using the Home SOC DNS filter**  
Severity `info` · category `dns` · raised at most once — it has a single subject

Emitted by `dnsfilter/server.py` (DNS resolver).  

**Why it matters.** The filter only protects devices that send their DNS queries to this PC; right now almost nobody does, so ads and malicious domains are not being blocked LAN-wide.

**How to fix it**

1. Open your router's admin page (usually http://192.168.1.254 or http://192.168.1.1) in a browser and sign in with the password printed on the router label.
2. Under LAN / DHCP settings set the primary DNS server to this PC's IP ({ip}) and save; devices pick it up when they reconnect.
3. Give this PC a static IP or DHCP reservation on the router so the address does not change.
4. Right-click scripts/enable-lan-dns.ps1 > 'Run with PowerShell' as administrator: it allows inbound DNS in the Windows firewall and prints the router steps for you.

**Read more**

- <https://developers.cloudflare.com/1.1.1.1/setup/>
- <https://quad9.net/>

### NET-DNS-002

**DNS resolver is not running ({reason})**  
Severity `high` · category `dns` · raised at most once — it has a single subject

Emitted by `dnsfilter/server.py` (DNS resolver).  

**Why it matters.** If devices point at this PC for DNS and the resolver is down, they lose internet access; if another program holds port 53, the filter cannot start.

**How to fix it**

1. Check what is using the port: PowerShell: Get-NetUDPEndpoint -LocalPort 53; Get-Process -Id <OwningProcess>
2. Stop the conflicting program (often a leftover Docker/WSL DNS or another ad-blocker) or change 'dns.port' in config.toml.
3. Restart Home SOC and check the DNS page shows 'running'.

### NET-DNS-003

**DNS blocklists are stale ({age_days} days)**  
Severity `medium` · category `dns` · raised at most once — it has a single subject

Emitted by `dnsfilter/server.py` (DNS resolver).  

**Why it matters.** Malicious domains change daily; with old lists the filter misses this week's phishing and malware sites.

**How to fix it**

1. Open the Home SOC Overview page and click 'Update feeds'; check the Feeds table for errors.
2. If updates fail, verify the PC has internet access and that no proxy blocks the list URLs.
3. CLI: python -m homesoc update --force

### NET-DNS-004

**{client} tried to reach a malicious domain: {domain}**  
Severity `high` · category `dns` · raised once per affected subject

Emitted by `dnsfilter/reputation.py` (DNS reputation worker).  

**Why it matters.** A device on your network asked for a domain known for malware, phishing or botnet control. The request was blocked, but the device may already be infected or a user clicked a phishing link.

**How to fix it**

1. Identify the device {client} on the Devices page.
2. If it is a PC: run a full Defender scan and check recent downloads; if a phone/IoT device: update it, review installed apps, or factory-reset it.
3. Look at the DNS query log for that client to see what else it contacted; check the domain at https://www.virustotal.com/gui/domain/{domain}
4. If it is a false positive, add an 'allow' override on the DNS page.

**Read more**

- <https://docs.virustotal.com/>
- <https://www.cisa.gov/news-events/news/home-network-security>

### NET-DNS-005

**DNS upstream resolvers are unreachable**  
Severity `high` · category `dns` · raised at most once — it has a single subject

Emitted by `dnsfilter/server.py` (DNS resolver).  

**Why it matters.** The filter cannot answer queries it does not have cached, so devices using it are losing internet access.

**How to fix it**

1. Check the PC's own internet connection and that outbound UDP port 53 is not blocked by a VPN or firewall.
2. Try: nslookup example.com 1.1.1.2   and   nslookup example.com 9.9.9.9
3. If a VPN is active, add its DNS server to 'dns.upstreams' in config.toml, or enable 'doh_upstream'.

**Read more**

- <https://developers.cloudflare.com/1.1.1.1/setup/>
- <https://quad9.net/>

### NET-DNS-006

**Resolver is bound to the LAN but no firewall rule allows DNS in**  
Severity `info` · category `dns` · raised at most once — it has a single subject

Emitted by `dnsfilter/server.py` (DNS resolver).  

**Why it matters.** Other devices cannot reach the filter until Windows Firewall allows inbound UDP/TCP 53; the resolver is running but only this PC benefits.

**How to fix it**

1. Right-click scripts/enable-lan-dns.ps1 > 'Run with PowerShell' (accept the UAC prompt).
2. PowerShell (admin): New-NetFirewallRule -DisplayName "Home SOC DNS" -Direction Inbound -Protocol UDP -LocalPort 53 -Action Allow -Profile Private

**Read more**

- <https://learn.microsoft.com/en-us/windows/security/operating-system-security/network-security/windows-firewall/>

---

## Home SOC's own health

Home SOC checking on itself, so a silently broken component does not look like a clean bill of health.

### SOC-FEED-001

**Feed '{name}' has been failing for {hours} hours**  
Severity `medium` · category `soc` · raised once per affected subject

Emitted by `cli.py` (Home SOC self-checks), `feeds/updater.py` (feed updater).  

**Why it matters.** Without fresh threat-intel feeds the DNS filter and vulnerability matching slowly go blind.

**How to fix it**

1. Open the Overview page > Feeds table and read the error for '{name}'.
2. Check internet access; if the source URL has moved, disable the feed in settings and open an issue.
3. CLI: python -m homesoc update --feeds {name} --force

### SOC-FEED-002

**CISA KEV catalog is stale ({hours} hours)**  
Severity `medium` · category `soc` · raised at most once — it has a single subject

Emitted by `cli.py` (Home SOC self-checks), `feeds/updater.py` (feed updater).  

**Why it matters.** The KEV list is what turns 'a CVE exists' into 'criminals are exploiting this now'; a stale copy means new critical alerts are missed.

**How to fix it**

1. Click 'Update feeds' on the Overview page, or run: python -m homesoc update --feeds kev --force
2. If it keeps failing, verify https://www.cisa.gov is reachable from this PC.

**Read more**

- <https://www.cisa.gov/known-exploited-vulnerabilities-catalog>

### SOC-SYS-001

**nmap is not installed; using the built-in Python scanner**  
Severity `info` · category `soc` · raised at most once — it has a single subject

Emitted by `cli.py` (Home SOC self-checks).  

**Why it matters.** The fallback scanner finds open ports but cannot identify product versions, so vulnerability matching is much weaker.

**How to fix it**

1. Download nmap from https://nmap.org/download.html and install it (Npcap is optional; connect scans work without it).
2. Restart Home SOC; the Scans page should show 'nmap' as the method.

**Read more**

- <https://nmap.org/download.html>
- <https://npcap.com/>

### SOC-SYS-002

**Home SOC is not running as administrator; skipped: {skipped}**  
Severity `info` · category `soc` · raised at most once — it has a single subject

Emitted by `scanners/host_windows.py` (Windows posture probe).  

**Why it matters.** Some checks (Secure Boot, TPM, BitLocker, Security event log) need elevation; they show as 'needs admin' rather than pass/fail.

**How to fix it**

1. This is fine for daily use. To run those checks once: open Start, type 'PowerShell', right-click it and choose 'Run as administrator'.
2. In that window run:  cd "{project_root}"
3. Then run:  .venv\Scripts\python.exe -m homesoc scan --only host   (if there is no .venv folder, use: python -m homesoc scan --only host)
4. The results appear on the dashboard's Host posture page; Home SOC itself keeps running without administrator rights.

### SOC-SYS-003

**Dashboard is reachable from the LAN without a token**  
Severity `high` · category `soc` · raised at most once — it has a single subject

Emitted by `cli.py` (Home SOC self-checks).  

**Why it matters.** Anyone on your Wi-Fi could open the dashboard, read your findings and device list, and trigger scans or change settings.

**How to fix it**

1. Open config.toml and set web.token to a long random string (PowerShell: -join ((48..57)+(97..122) | Get-Random -Count 32 | ForEach-Object {[char]$_})).
2. Or set web.host back to "127.0.0.1" if you only use the dashboard on this PC.
3. Restart Home SOC; open http://<this-pc>:8787/login?token=<your token> on other devices.

### SOC-SYS-004

**Scheduled job '{job}' keeps failing ({failures} times)**  
Severity `medium` · category `soc` · raised once per affected subject

Emitted by `cli.py` (Home SOC self-checks).  

**Why it matters.** A job that fails repeatedly means part of the monitoring is silently not happening.

**How to fix it**

1. Open the Telemetry page > Jobs table and read the last error for '{job}'.
2. Check data/logs/homesoc.log for the traceback; common causes are a missing tool, no internet, or a permissions issue.
