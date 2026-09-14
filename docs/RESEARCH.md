# Home SOC — Research

**Why this tool is built the way it is.**
Last revised 2026-09-07. Every claim about the outside world carries a numbered reference to a page that was actually
fetched while writing this (see §8). Every claim about Home SOC itself carries a file path you can open and check.

This document is for a curious home user, not a security professional. It explains what actually protects a house full
of laptops, phones, printers and smart plugs; how the professional tools work under the hood; what free data exists to
build on; and then — the part that matters — how each of those findings turned into a specific decision in this
codebase, including the decisions that came out badly the first time and had to be changed.

Where a source could not be retrieved, that is stated instead of guessed at. Nothing here is cited from memory.

---

## 1. Executive summary — the ten things that actually protect a home

In priority order. The ordering is not arbitrary: it puts the things that stop the most common real attacks
(credential theft, phishing, ransomware, unpatched internet-facing software) above the things that are technically
interesting but rarely the way a home gets hurt.

1. **Install updates, everywhere, promptly.** Operating system, browser, and the third-party apps nobody thinks about
   (Java, Adobe, 7-Zip, VLC, PuTTY). Every authority in §6 lists this in its top handful — NCSC calls updates "vital
   security updates" [33], CISA makes "update software" one of four core behaviours [34]. CISA's KEV catalogue exists
   precisely because a small set of already-patched flaws keeps being exploited in the wild [26].
2. **A unique password per account, kept in a password manager, and MFA on the accounts that unlock the others.**
   Start with email: NCSC's reasoning is that "cyber criminals can use your email to access many of your personal
   accounts" [33]. CISA's framing of MFA is that even with your password, an attacker "won't be able to meet the
   second step requirement" [34].
3. **Leave the built-in antivirus on — and leave cloud-delivered protection, automatic sample submission and tamper
   protection on with it.** Those three settings are what turn Defender from a signature scanner into a
   block-at-first-sight system that can make a verdict on a never-before-seen file in seconds [2]; tamper protection is
   what stops malware from switching the whole thing off [7].
4. **Back up, to something that is not always plugged in.** NCSC: back up "to an external hard drive or a cloud-based
   storage system" [33]. An always-mounted backup drive is just more files for ransomware to encrypt.
5. **Secure the router.** It is the one device on your network that is exposed to the internet 24/7. Change the default
   admin password, apply firmware updates, turn off remote/WAN administration, and remove UPnP port mappings you did
   not deliberately create.
6. **Use WPA3, or WPA2 with AES/CCMP, and put the smart devices on a separate SSID.** Segmentation means a compromised
   video doorbell cannot reach your laptop's file shares.
7. **Do not spend your day logged in as an administrator.** Keep UAC and SmartScreen on. Most malware needs you to
   click through a prompt; a standard account makes that prompt a real decision instead of a formality.
8. **Filter DNS for the whole house.** One setting on the router protects every device, including the ones that will
   never run security software — the TV, the thermostat, the guest's phone. See §4.
9. **Turn off legacy protocols and services you are not using.** SMBv1, Telnet, plain FTP, RDP reachable from the LAN,
   printer admin pages served over unencrypted HTTP. These are the findings that show up on almost every home network.
10. **Encrypt the disk and lock the screen.** This is the one that protects you from the mundane threat — a stolen
    laptop — rather than the exciting one.

There is an eleventh item that is really a precondition for all of them: **know what is on your network and what state
it is in.** You cannot patch a device you forgot you owned. That inventory-and-posture job is what Home SOC does; it
does not try to replace items 1–10, it tries to tell you which of them you have not actually done.

---

## 2. How antivirus works today

The mental model most people have — "a list of virus fingerprints, updated daily" — describes about 1995. Modern
endpoint antivirus is a stack of layered detectors, and the signature file is now the offline fallback rather than the
main event.

### 2.1 Signatures and definition updates

**Microsoft Defender** ships three separately-versioned things: the *platform* (the engine host, monthly, KB4052623),
the *engine* (monthly, shipped alongside intelligence updates), and *security intelligence* updates (KB2267602),
which are pushed on a configurable schedule throughout the day [3]. Defender also downloads "dynamic security
intelligence updates" that supplement, rather than replace, the regular ones [3]. Updates can arrive from Windows
Update, WSUS, a UNC file share, or directly from the command line via
`MpCmdRun.exe -SignatureUpdate` — and can be rolled back with `MpCmdRun.exe -RemoveDefinitions -All` or
`-RevertPlatform` if a bad definition breaks something [3]. Microsoft's own framing is that in 2015 Defender "moved
away from using a static signature-based engine to a model that uses predictive technologies" [1].

**ClamAV** is the open-source counterexample and is worth understanding because its format is legible. Its databases
are distributed as digitally-signed CVD containers, fetched by the `freshclam` daemon [8]. Inside are two families:
hash-based signatures (`.hdb`/`.hsb` for whole-file hashes, `.mdb`/`.msb` for PE-section hashes) and body-based
signatures that match byte sequences rather than hashes (`.ndb` extended signatures, `.ldb` logical signatures,
`.cbc` bytecode). It also natively loads `.yara` rule files and carries phishing-URL databases (`.pdb`/`.gdb`/`.wdb`)
[8]. That split — "is this exact file known bad" versus "does this file contain a known-bad pattern" — is the
fundamental division in all signature engines.

**YARA** is the lingua franca for the second kind. A rule has three parts: optional `meta`, a `strings` section, and a
boolean `condition`. Strings can be hexadecimal byte sequences with wildcards and jumps, text strings with modifiers
(`nocase`, `wide`, `xor`, `base64`), or regular expressions [9]. It is deliberately close to C syntax so an analyst can
write one in a few minutes during an incident.

### 2.2 Everything that is not a signature

- **Heuristics and static machine learning.** Features extracted from a file without running it — imports, section
  entropy, string sets, structural oddities — fed to a classifier. Microsoft describes Defender's version as "anomaly
  detection, a layer of protection for malware that doesn't fit any predefined pattern," monitoring process creation
  and internet-downloaded files [1].
- **Emulation and sandboxing.** The engine runs the sample in an emulator to get past packing and obfuscation, then
  applies signatures to what comes out. Microsoft's AMSI documentation walks through this arms race explicitly:
  signature → string concatenation to break the signature → engine emulates concatenation → Base64 encoding → engine
  emulates Base64 → algorithmic XOR obfuscation, at which point "we're generally past what antivirus engines will
  emulate or detect" [4].
- **AMSI (the Antimalware Scan Interface)** is the answer to that dead end. Instead of trying to out-emulate the
  obfuscator, Windows lets the *scripting host itself* hand the final, de-obfuscated code to the registered AV engine
  just before execution: "a malicious script might go through several passes of de-obfuscation... it ultimately needs
  to supply the scripting engine with plain, un-obfuscated code" [4]. PowerShell, VBScript, JScript and Office VBA all
  call it, and any application can. For Office macros the VBA runtime keeps a circular buffer of Win32/COM/VBA calls
  and, when a high-risk trigger fires, halts execution and passes the buffer to AMSI for a verdict [4].
- **Cloud reputation and block-at-first-sight.** When Defender sees an executable or non-PE file (JS, VBS, macro) that
  came from the internet zone and it has not seen before, it hashes it and queries the cloud backend. If the cloud
  cannot decide, "Microsoft Defender Antivirus locks the file and uploads a copy to the cloud" for deeper analysis;
  the file is held from running for a configurable timeout while that happens. Microsoft's claim is that this "can
  reduce the response time for new malware from hours to seconds" [2]. The feature requires exactly three things:
  cloud protection on, sample submission set to automatic, and up-to-date definitions [2]. In PowerShell terms,
  `MAPSReporting` = 2, `SubmitSamplesConsent` = 1 or 3, `DisableBlockAtFirstSeen` = False [2]. **This is the single
  most under-configured setting on home machines**, because "Automatic sample submission" sounds like telemetry and
  people turn it off.
- **Behaviour monitoring.** Watching what a process does after it starts, rather than what it looks like before.
  Microsoft: Defender "can also stop threats based on their behaviors and process trees even when the threat has
  started execution. A common example of these kinds of attacks is fileless malware" [1].
- **Ransomware-specific protections.** Controlled Folder Access (only allow-listed apps may write to Documents,
  Pictures, etc.), attack surface reduction rules, and network protection. Tamper protection is bundled into
  Microsoft's "built-in protection" ransomware guard-rails [7].
- **Tamper protection.** With it on, virus & threat protection, real-time protection, behaviour monitoring, IOAV,
  cloud protection, security intelligence updates, automatic remediation and archive scanning cannot be turned off,
  and exclusions cannot be modified — even by an administrator [7]. `Get-MpComputerStatus` reports it as
  `IsTamperProtected` [7]. On an unmanaged home device it is toggled in the Windows Security app [7].

### 2.3 What independent lab testing actually measures

Marketing quotes lab scores without saying what was scored. The three labs measure genuinely different things.

- **AV-TEST** scores three axes — Protection, Performance, Usability. Protection is split into the real-world test
  (fresh, live attacks) and detection against the "AV-TEST reference set" of prevalent known malware. Performance is
  measured through everyday scenarios: "launching websites, downloading programs." Usability is the false-alarm axis.
  They analyse "more than 3 million potentially malicious files, websites and emails every day" [10].
- **AV-Comparatives' Real-World Protection Test** is the closest thing to a fair fight. It uses live malicious URLs
  found by their own crawlers, tests the *whole product* (not just the scanner) with "unrestricted cloud access
  throughout the test," and pairs the protection score with two separate false-positive runs: about 1,000 popular
  domains checked for wrongly-blocked sites, and about 100 clean applications downloaded from developer sites and
  installed to catch wrongly-blocked files [11]. The false-positive half is the important half: a product that blocks
  everything scores 100% on protection and is useless.
- **SE Labs** goes further toward emulating an attacker: "full attack chain testing, replicating the latest methods
  used by attackers in the real world," and separately rates detection versus protection, plus incident-response and
  forensic capability in its newer PIVOT test [12].

**The practical takeaway for a home user:** the top ten consumer products all score within a couple of percentage
points of each other on protection. The differences that matter at home are false positives, system impact, and
whether the thing is actually turned on and updating. Which is a configuration problem, not a product-choice problem —
and configuration problems are checkable by a script.

---

## 3. How EDR agents work

EDR ("endpoint detection and response") is the layer above antivirus: it records what happened, so that a human or a
detection rule can reconstruct an attack, rather than only trying to block files.

### 3.1 The four hooks a Windows EDR agent uses

1. **Kernel notification callbacks.** The kernel offers registration points for process creation, thread creation,
   image (DLL/driver) load and object handle operations. An agent registers, and gets called synchronously with the
   details. This is how an EDR sees `winword.exe` spawning `powershell.exe` before it happens.
2. **File system minifilter drivers.** File I/O is intercepted through the Filter Manager (`FltMgr.sys`), a
   system-supplied kernel driver. A minifilter "attaches to the file system stack indirectly, by registering with
   *FltMgr* for the I/O operations that the minifilter driver chooses to filter" [15]. Ordering between filters is
   fixed by *altitude*: on the way down, pre-operation callbacks run highest altitude first; on the way back up,
   post-operation callbacks run in reverse [15]. Antivirus real-time scanning, ransomware canaries and file-integrity
   monitoring all live here.
3. **ETW, and ETW-TI.** Event Tracing for Windows is the general telemetry bus; the Threat-Intelligence provider
   (ETW-TI) is a restricted channel carrying the events attackers care about — memory allocation into remote
   processes, suspicious handle opens — and is only readable by a process running as a protected anti-malware service.
4. **AMSI**, as described in §2.2, for script and in-memory content [4].

### 3.2 Protected processes and tamper resistance

An EDR agent's own service is the obvious target: it is "the single point of failure to disable protection on a
system" [14]. Windows 8.1 introduced the *system protected process* model to fix that. A vendor with an Early Launch
Anti-Malware (ELAM) driver embeds a resource section listing the certificate hashes used to sign their user-mode
service; at boot the OS extracts and validates it, and the service can then launch as PPL (protected process light,
anti-malware level) [14]. Once running, "other non-protected processes on the system won't be able to inject threads,
and they won't be allowed to write into the virtual memory of the protected process," only code signed by Windows or
by the vendor's own certificate may load into it, and even administrators cannot stop the service — only a handful of
`sc` verbs are permitted [14]. Notably, a set of scripting DLLs (`scrobj.dll`, `scrrun.dll`, `jscript.dll`,
`jscript9.dll`, `vbscript.dll`) is forbidden inside a protected process [14]. Sysmon uses exactly this mechanism: it
"runs as a protected process, thus disallowing a wide range of user mode interactions" [13].

### 3.3 The July 2024 CrowdStrike outage, and what it changed

On 19 July 2024, CrowdStrike shipped Channel File 291 to Falcon sensors on Windows. The file's IPC Template Type
carried 21 fields while the Content Interpreter expected 20 inputs, and "a runtime array bounds check was missing for
Content Interpreter input fields on Channel File 291" [5]. The resulting out-of-bounds read happened inside a
kernel-mode driver, so it was not a crashed application — it was a bugcheck. Machines blue-screened worldwide, and
because the sensor loaded at boot, many needed manual recovery [5].

The industry consequence is the part that matters here. Microsoft's Windows Resiliency Initiative includes a private
preview — opened to Microsoft Virus Initiative partners in July 2025 — of a **Windows endpoint security platform that
lets antivirus and endpoint protection products run outside the kernel, in user mode, "just as apps do"** [6]. The
stated goal is that a fault in a security product takes down the security product rather than the operating system
[6].

**The lesson for a project like this one is blunt:** kernel-mode security code is a liability that only makes sense
when the security benefit is large and the engineering budget is enormous. Neither is true for a home tool. Home SOC
has no driver, no kernel component, and no boot-start anything (see §7.1).

### 3.4 The open-source EDR pieces a home user could actually run

None of these is a drop-in EDR, but together they cover most of the ground:

- **Sysmon** (Microsoft Sysinternals) — a service plus a boot-start driver that writes richly-detailed events to
  `Applications and Services Logs/Microsoft/Windows/Sysmon/Operational` [13]. It logs process creation with the full
  command line of both the process and its parent, hashes images (MD5/SHA1/SHA256/IMPHASH), and adds a ProcessGUID so
  events correlate even after PID reuse [13]. It does not analyse anything and does not hide itself [13]. Installing
  it requires administrator rights.
- **Wazuh** — agent + server + indexer + dashboard, providing log analysis, file integrity monitoring, vulnerability
  detection, security configuration assessment, and agentless monitoring of routers and firewalls over syslog or SSH
  [18]. Powerful, and a genuinely heavy install for a house.
- **osquery** — exposes the operating system as SQL tables: "Each concept becomes a SQL table, like processes, or
  sockets, the filesystem" [17]. Security-relevant tables include `processes`, `process_open_sockets`,
  `process_open_files` and filesystem metadata, and you can join across them — correlating process execution with open
  sockets to spot command-and-control traffic [17].
- **Velociraptor** — DFIR at scale. Its query language (VQL) and reusable "artifacts" are pushed *to* the endpoint and
  parsed there, rather than shipping raw data centrally [19]. It runs client-server, as an offline collector binary
  that produces an encrypted ZIP, or against a disk image [19].

**Sysmon event IDs worth watching at home:** 1 (process create, with full command line), 3 (network connection —
disabled by default), 7 (image load — very noisy, filter it), 8 (CreateRemoteThread, i.e. code injection), 10
(ProcessAccess — the LSASS credential-theft signal), 11 (file create, ideal for Startup folders and Downloads), 12/13
(registry key/value create and set — Run keys), 22 (DNS query, per-process), and 25 (ProcessTampering: hollowing and
"herpaderping") [13].

**Windows Security log event IDs worth watching:** 1102 audit log cleared (Microsoft rates this medium-to-high
criticality; it is a classic anti-forensics move), 4719 audit policy changed (high), 4624/4625 logon success/failure,
4672 special privileges assigned to a new logon, 4688 new process created, 4697 attempt to install a service,
4698–4702 scheduled task created/deleted/enabled/disabled/updated, 4720 user account created, and 4732 member added to
a security-enabled local group (i.e. someone was made a local administrator) [16]. Microsoft warns that many of these
require audit policy to be configured explicitly — "many audit-related Group Policy Objects (GPO) set to **Not
Configured** by default" — so their absence proves nothing [16]. And on Windows 11 Home without elevation, the Security
log cannot be read at all (see §7.7).

---

## 4. Network defences

### 4.1 IDS / IPS

**Suricata** is "a high performance Network IDS, IPS and Network Security Monitoring engine," GPLv2, maintained by the
non-profit OISF [20]. **Snort** shares the rule dialect; **Zeek** takes a different approach, producing structured
protocol logs rather than alerts. All three need to see the traffic, which on a home network means either a managed
switch with a mirror port, or running the sensor on the router itself. On a typical ISP-supplied residential gateway
there is no facility for either.

There is a deeper problem: most home traffic is TLS. A signature IDS watching encrypted flows is reduced to SNI names,
IP addresses and JA3-style fingerprints — which is, roughly, the same information a DNS filter already has, obtained
far more cheaply.

**CrowdSec** is the interesting modern variant: an open-source engine that parses logs with behavioural scenarios and
then hands decisions to "bouncers" that enforce blocks at the firewall, web server or reverse proxy [21]. Its
distinguishing feature is crowdsourcing — participants share detected attacker IPs and the validated set is
redistributed to everyone [21]. It is excellent on an internet-facing server. On a home LAN with no exposed services
there is very little log for it to read.

### 4.2 DNS filtering — the highest-leverage home control

DNS filtering wins at home for one structural reason: **it protects devices that cannot run software.** The TV, the
thermostat, the printer, the guest's phone. One change on the router covers all of them.

- **Pi-hole** documents three ways to point clients at it: set the DNS server in the router's DHCP settings
  ("preferred"); run Pi-hole's own DHCP server after disabling the router's; or configure each device by hand. The
  second option exists precisely for the case where "your router doesn't support DNS customization" [22]. It also
  flags the failure mode honestly: if the filtering resolver dies, "your host loses DNS resolution" [22].
- **AdGuard Home** is the same idea with encrypted-transport support built in — DNS-over-HTTPS, DNS-over-TLS,
  DNSCrypt and DNS-over-QUIC — plus its own DHCP server, parental controls and safe search, under GPL-3.0 [23].
- **NextDNS** is the hosted equivalent (no local device to maintain, a monthly query allowance on the free tier).
- **Cloudflare** publishes filtered resolvers as plain IPs: `1.1.1.2` / `1.0.0.2` block malicious content, `1.1.1.3` /
  `1.0.0.3` block malware plus adult content, each with IPv6 equivalents. When a domain matches, "Cloudflare returns
  0.0.0.0" [24].
- **Quad9's** `9.9.9.9` provides malware blocking plus DNSSEC validation without logging personal data;
  `9.9.9.10` is the unfiltered variant "for experts only"; `9.9.9.11` adds EDNS Client Subnet [25].

Note the design convergence: Cloudflare's filtered resolver answers blocked names with `0.0.0.0` [24] rather than
NXDOMAIN, because a null answer fails fast and predictably in clients that retry aggressively on NXDOMAIN.

### 4.3 Router built-ins and segmentation

Consumer routers ship with a firewall that blocks unsolicited inbound traffic by default; the risk is what gets
punched through it. **UPnP** lets any device on the LAN open an inbound port on the WAN without asking anyone — which
is exactly what a compromised device would do. Guest SSIDs and "IoT network" features on newer routers provide
client-isolated segmentation for free, and NSA's home-network guidance and NIST's consumer-IoT profile both point in
this direction (§6).

---

## 5. Free threat-intelligence and vulnerability data — and what may be redistributed

This section matters more than it sounds. An open-source tool that bundles someone else's data can quietly commit a
licence violation on behalf of every user who installs it. The rule Home SOC follows is: **ship no data; fetch it at
runtime from the publisher, record the licence, and require the user's own key for anything metered.**

| Source | What it gives | Cost / key | Redistribution by an OSS tool |
|---|---|---|---|
| **CISA KEV** | ~1,695 CVEs known to be exploited in the wild, "the authoritative source"; CSV, JSON and JSON Schema downloads [26] | Free, no key [26] | US Government work — the freest thing in this table. Home SOC still fetches it live rather than vendoring it, so it is never stale. |
| **NVD 2.0 API** | CVE records, CVSS, CPE matching | Free; an API key raises the rate limit | Per-CVE lookups only; bulk mirroring is impolite and slow |
| **FIRST EPSS** | "a data-driven machine-learning model that estimates the probability that a published CVE will be exploited in the wild in the next 30 days," 0–1 score plus percentile, published daily for every CVE, available as CSV, API and GitHub [27] | Free | Free for non-commercial use with attribution |
| **abuse.ch (URLhaus, ThreatFox, Feodo)** | Live malware-distribution URLs, IOCs, botnet C2 IPs; datasets as CSV, DNS blocklists, IDS rulesets and ClamAV signatures [29] | Free under "fair use," **but the API now requires an Auth-Key obtained from the abuse.ch Authentication Portal** [29] | Community API is free of charge; commercial use points at a paid API [29] |
| **HaGeZi Pro** | ~224,011 domains — ads, trackers, telemetry, phishing, malware, scams, cryptojacking — in Adblock, DNSMasq, wildcard-asterisk, wildcard-domains ("onlydomains") and RPZ formats [30] | Free | **GPL-3.0** [30] — fetch at runtime, do not vendor into an MIT repo |
| **oisd** | Ads, app ads, phishing, malvertising, malware, spyware, ransomware, cryptojacking; big/small/NSFW variants, with a deliberate policy of *not* blocking torrents, shopping, social, news-satire or gambling [31] | Free | The oisd site does not state an explicit licence on its front page [31] — see the caveat below |
| **VirusTotal (public API v3)** | File, URL and domain reputation across many engines | Free key; **500 requests/day and 4 requests/minute** [28] | **Must not** be used in commercial products or services, and must not be used in business workflows that do not contribute new files; multiple accounts to evade the quota are prohibited [28] |
| **Google Safe Browsing** | URL reputation | Requires a Google Cloud API key | *Not quoted here.* Google's Safe Browsing developer documentation would not render for our fetcher (repeated empty/404 responses), so no quota or terms figures are cited, and Home SOC does not integrate it at all. |

Two honest caveats about this table:

- **oisd's licence.** `homesoc/feeds/registry.py` records oisd's licence note as "CC BY-SA 4.0". The oisd homepage as
  fetched on 2026-09-07 does not state a licence [31]. The note may be right and simply documented elsewhere on the
  site, but as of this writing it is unverified from a primary source. Flagged in §7.9.
- **URLhaus keys.** abuse.ch's API documentation now states plainly: "In order to interact with the URLhaus API, you
  need to obtain an `Auth-Key` first" [29]. Home SOC has a `dns.urlhaus_auth_key` config key
  (`config.example.toml`), so the plumbing exists — but the reputation path treats URLhaus as a *keyless* second
  source, and the plain blocklist downloads are unauthenticated. That is a real-world dependency worth watching.
- **NVD's published rate limits.** `nvd.nist.gov/developers/*` is a client-rendered application that returns only a
  shell to a plain HTTP fetcher, so the limits are not cited to a fetched page here. The limits Home SOC actually
  implements are in `homesoc/vulns/enrich.py`: `RateLimiter.for_key()` returns 50 requests per 30-second window with
  an API key and 5 without.

---

## 6. Authoritative home-security guidance, distilled

Four bodies publish guidance aimed at (or usable by) households. They agree with each other far more than they
disagree, which is itself informative.

**NCSC (UK) — Top tips for staying secure online** [33]. Six items: a strong, separate password on your *email*
account, because "cyber criminals can use your email to access many of your personal accounts, leaving you vulnerable
to identity theft"; three random words as a password construction method; two-step verification; installing OS and app
updates, which "contain vital security updates to help protect your devices from cyber criminals"; using a password
manager; and backing up important data "to an external hard drive or a cloud-based storage system" [33].

**CISA (US) — Secure Our World** [34]. Four core behaviours: enable multi-factor authentication, recognise and report
phishing, use strong passwords (with a password manager), and update software promptly, because "flaws in software can
give criminals access to files or accounts." On MFA specifically, CISA's argument is that with a second factor an
attacker who has your password "won't be able to meet the second step requirement to access your accounts," and it
names three acceptable methods: codes by text/email, authenticator apps rotating every thirty seconds, and biometrics
[34].

**CISA — Known Exploited Vulnerabilities catalogue** [26]. Not household guidance, but the operational expression of
"patch the right things first": a curated list of vulnerabilities actually exploited in the wild, free to anyone,
published as CSV and JSON [26].

**NIST — IR 8425, "Profile of the IoT Core Baseline for Consumer IoT Products"** (September 2022) [35]. Written for
manufacturers, but it is the best available checklist for judging a smart device before you buy it. It "documents the
consumer profile of NIST's IoT core baseline and identifies cybersecurity capabilities commonly needed for the
consumer IoT sector," applies to products for home or personal use, and deliberately phrases requirements "as
cybersecurity outcomes that are intended to apply to the entire IoT product" rather than as prescriptive
implementations [35]. Practically: does the thing have unique credentials out of the box, can it be updated, can you
tell whether it has been updated, and can you factory-reset it before disposal.

**NSA.** NSA publishes a Cybersecurity Information Sheet, *Best Practices for Securing Your Home Network*, whose
themes (modern and updated OS, secured and updated routing devices, WPA3/WPA2, wireless segmentation, password
managers, MFA, regular reboots to clear non-persistent implants, offline backups) are widely reported. Both
`nsa.gov` and `media.defense.gov` returned HTTP 403 to our fetcher on 2026-09-07, so **no claim in this document is
attributed to the NSA CSI**, and it is not in the source list.

**Where the four sources converge:** updates, unique passwords in a manager, MFA on email first, offline backups, and
router/Wi-Fi hygiene. That convergence is exactly the ordering in §1 — the priority list is not this project's
opinion, it is the intersection of four national guidance documents.

---

## 7. How this shaped Home SOC

This is the section that ties research to code. Each subsection names the conclusion, then the concrete decision, then
the file where you can check it.

### 7.1 Why it integrates Microsoft Defender instead of shipping a detection engine

**The research says:** modern protection value comes from cloud reputation, block-at-first-sight, behaviour monitoring
and tamper resistance [1][2][7] — capabilities that require a signed ELAM driver, PPL registration [14], a minifilter
[15], and a global cloud backend. It also says that when a security vendor with enormous resources gets a kernel
content update wrong, the machine bugchecks [5], and that Microsoft's response is to move endpoint security *out* of
the kernel entirely [6]. And it says the top consumer AV products are separated by fractions of a percent on
protection [10][11][12] — the differences that bite at home are false positives and misconfiguration.

**So Home SOC ships no detection engine.** It has no driver, no minifilter, no PPL service, no signature format of its
own. What it ships is an *auditor of the AV you already have*, in `homesoc/scanners/defender.py`:

- `status()` reads `Get-MpComputerStatus` and a subset of `Get-MpPreference`.
- `threats(days=30)` merges `Get-MpThreatDetection` with Defender/Operational event IDs
  `1006, 1007, 1116, 1117, 1118, 1119, 5001, 5010, 5012`, collapsing the several events a single detection produces
  (`normalize_threats`) into one row.
- `trigger_quick_scan()` and `trigger_signature_update()` shell out to `MpCmdRun.exe -Scan -ScanType 1` and
  `MpCmdRun.exe -SignatureUpdate` — the same documented entry points Microsoft describes [3] — on a guarded background
  thread, so the dashboard polls rather than blocking. `mpcmdrun_path()` looks in `%ProgramFiles%\Windows Defender`
  first and then the newest `%ProgramData%\Microsoft\Windows Defender\Platform\<ver>\` folder, matching Microsoft's
  own documented location logic [3].
- The constant `NEVER_SCANNED = 4294967295` exists because `Get-MpComputerStatus` reports uint32-max when a scan has
  never run — which is exactly what the author's machine reports for a *full* scan.

The fourteen `WIN-DEF-*` findings in `homesoc/findings/catalog.py` then encode the settings the lab methodologies and
Microsoft's own docs say actually matter: `WIN-DEF-001/002` AV or real-time protection off (critical), `003`
signatures more than 3 days old, `004` tamper protection off [7], `005` cloud-delivered protection off — which is
half of the block-at-first-sight precondition [2] — `006` PUA protection, `008` controlled folder access, `009`
network protection, `010` no ASR rules, `011` a threat detected in the last 30 days, `013` Smart App Control off, and
`014` sample submission or cloud block level left at basic, which is the *other* half of block-at-first-sight [2].

That last pair is the whole justification for this design. On the author's machine, Defender is on, real-time
protection is on, tamper protection is on and signatures are one day old — but `CloudBlockLevel=0`, Controlled Folder
Access is off, Network Protection is off, and a full scan has never run. A second AV engine would have added nothing.
Telling the user about those four settings adds something real.

### 7.2 Why discovery is ARP-first

**The measurement:** on the test /24, `nmap -sn <cidr>` took **50 seconds and found 2 hosts out of 17**
(`docs/TESTED_ENVIRONMENT.md`). A Python TCP-connect sweep of 14 ports × 254 hosts at 128 threads took **11.5 s**; reading
the Windows neighbour table immediately afterwards returned **17 hosts with MAC addresses in 0.04 s**.

**The explanation is in nmap's own manual.** On a local Ethernet segment nmap normally discovers hosts with ARP
requests, which "require root/privileged access" — raw packet capture, i.e. a working Npcap on Windows. For a
non-privileged user nmap falls back to a workaround where "only SYN packets are sent (using a `connect` call) to ports
80 and 443" [32]. On a home network full of devices that listen on neither port — printers on 9100, Apple devices on
62078/7000, a Sonos on 1400 — two ports out of 65,535 finds almost nothing. The author's machine has nmap installed
but Npcap broken, so it runs connect-only. 2 of 17 is exactly the predicted result, not a fluke.

**So `homesoc/scanners/discovery.py` inverts the order.** It reads the OS neighbour table first —
`Get-NetNeighbor -AddressFamily IPv4` filtered to `Reachable`, `Stale`, `Permanent`, `Delay`, `Probe` and converted to
JSON, with `arp -a` as fallback (`parse_arp_a`), `ip -j neigh` on Linux (`parse_ip_neigh`) — then runs its own
threaded TCP-connect sweep over `network.discovery_ports` to *provoke* ARP entries, then re-reads the table. The
default port list is deliberately device-shaped rather than server-shaped:
`80, 443, 22, 445, 139, 8080, 62078, 7000, 9100, 1900, 5353, 8443, 3389, 23, 21, 53` (`config.example.toml`), with
`discovery_threads = 128` and `discovery_timeout = 0.4` — the settings that produced 11.5 s.

This also gives Home SOC something nmap's unprivileged mode cannot: a **MAC address per device**, which is a stable
identity across DHCP lease changes, and which feeds OUI vendor lookup from the Wireshark `manuf` file and
locally-administered-bit detection for randomised MACs (`is_randomized_mac`, finding `NET-DEV-002`).

nmap is not discarded — `homesoc/scanners/ports.py` still uses it for what unprivileged nmap is genuinely excellent
at: service and version detection on a known IP (`build_nmap_command` emits `-sT -sV --version-light -T3`, never
`-O`, `-sU` or `--script`). Measured at 17 s on the router, returning `Unbound 1.18.0` and `lighttpd 1.4.69` with
CPEs. When nmap is missing, `python_scan()` plus `grab_banner()` covers the same ground more crudely, and
`SOC-SYS-001` tells the user what they are missing. Vendors matching `network.fragile_vendors` get the gentle profile
(`gentle_top_ports`, no `-sV`) because a printer that jams on a port scan is a worse outcome than a missing banner.

### 7.3 Why the DNS sinkhole is embedded rather than a separate service

**The research says** DNS filtering is the highest-leverage home control because it covers devices that can never run
an agent (§4.2), and that the standard deployments assume you can either change the router's DHCP DNS setting or run
your own DHCP server [22].

**The measurement says** neither is available here. A typical ISP-supplied gateway serves DHCP and DNS itself and
offers no setting to advertise a custom LAN DNS server (`docs/TESTED_ENVIRONMENT.md`). Pi-hole's documented fallback for
exactly this case is to take over DHCP [22] — which on a household's only router is a genuinely risky thing to ask a
non-expert to do.

**It also says the technical barrier is lower than expected:** binding UDP *and* TCP port 53 on `0.0.0.0` works
**without administrator rights** on Windows 11 Home; nothing else was listening on 53; a minimal dnslib forwarder
answered blocked names in ~1 ms and forwarded to `1.1.1.2` in **~13 ms** (`docs/TESTED_ENVIRONMENT.md`).

**So the resolver is inside the same process** (`homesoc/dnsfilter/server.py`, started by `python -m homesoc run` when
`dns.enabled`), not a Docker container, not a separate service, not a second machine. Consequences:

- No admin required to *run* it. Admin is needed only for the optional inbound firewall rule, which is isolated in
  `scripts/enable-lan-dns.ps1` — one script, clearly labelled, that the user may decline.
- The query log, the blocklists, the findings and the dashboard share one SQLite database, so
  "which client asked for this malicious domain" is a join, not a log-shipping problem. `NET-DNS-004` fires per
  client+domain.
- Upstream defaults follow the research directly: `dns.upstreams = ["1.1.1.2", "9.9.9.9"]` — Cloudflare's
  malware-blocking resolver [24] and Quad9's malware-blocking, DNSSEC-validating resolver [25] — so even a name that
  slips past the local lists gets a second opinion. `doh_upstream` points at `https://cloudflare-dns.com/dns-query`
  for the case where UDP is interfered with; ground truth notes Quad9's DoH GET/JSON returned 505, so the
  implementation uses wire-format POST or plain UDP for Quad9.
- `dns.block_mode = "null"` answers blocked names with `0.0.0.0` / `::` at TTL 60 — the same behaviour Cloudflare's
  filtered resolver uses [24] — with `"nxdomain"` available for people who prefer it.
- `homesoc/dnsfilter/policy.py` evaluates in a fixed order: overrides (allow, then deny) → a built-in never-block set
  (localhost, `*.local`, `*.arpa`, the upstreams' own names) → blocklists by exact and parent-suffix match →
  the reputation table → allow. The never-block set exists so a bad list entry can never make the tool unfixable from
  its own dashboard.
- Because it is LAN-facing, `server.py` carries an amplification guard: `RATE_LIMIT_QPS = 300` per client and
  `GLOBAL_RATE_LIMIT_QPS = 3000`.
- Pi-hole's own warning — that if the filtering resolver dies, "your host loses DNS resolution" [22] — is why a port
  conflict raises `NET-DNS-002` and logs, but **keeps the rest of the application running**, and why
  `NET-DNS-005` fires when every upstream fails.

The list defaults are chosen for what a home actually wants: `oisd_small` (measured 63k entries) plus `hagezi_pro`
(measured 224k, matching HaGeZi's published ~224,011 [30]) for ads and trackers, then `urlhaus`, `threatfox`,
`phishing_army` and `openphish` for actual threats. `oisd_big`, `stevenblack` and `adguard_dns` exist in the registry
but ship disabled — more overlap, more memory, more false positives, no more protection.

### 7.4 Why vulnerability matching is KEV-first with strict product+version gating

**The research says** KEV is the authoritative list of what is actually being exploited, is free, keyless and
downloadable as JSON [26]; EPSS gives a daily-updated probability of exploitation in the next 30 days for every CVE
[27]; and NVD gives depth at the cost of network round-trips under a rate limit.

**So `homesoc/vulns/matcher.py` orders the sources by cost and by signal**, and says so in its own docstring: KEV
first "because it is on disk and represents *actively exploited right now*"; NVD second "because it costs network time
and is bounded by a per-scan budget"; EPSS last "because it only annotates CVEs the first two already found."

**The gating is where the real lesson lives.** The first implementation matched KEV entries on product name alone. On
a single host it produced **386 unconfirmable "hits"** — every Microsoft/Windows KEV entry attaching itself to an SMB
service, every Apple entry to a Bonjour responder. Not one was actionable. A tool that opens with 386 critical alerts
about a fully-patched machine gets uninstalled the same afternoon, and rightly: AV-Comparatives' insistence on
measuring false positives alongside protection [11] applies just as hard to a vulnerability scanner as to an AV
engine.

The current matcher applies three gates:

1. **Version evidence promotes; its absence does not.** `_match_kev()` extracts every version mentioned in the KEV
   entry's `vulnerabilityName`, `shortDescription` and `notes`, takes the highest (`max_version`), and only calls a
   match *confirmed* (`NET-VUL-001`, critical) when the observed service version is `<=` it. Where the service version
   is **newer** than every version the advisory names, the entry is **dropped entirely**, with an explicit
   SPEC-GAP comment: the spec said to downgrade it to "possible", the code drops it, "because alerting critical on a
   patched router is the noise users disable the tool over."
2. **A cap on guesses.** Matches with no version evidence become `NET-VUL-002` ("possible", high) — but if one service
   accumulates more than `KEV_POSSIBLE_MAX = 20` of them, the product name matched a *family*, not a device, and the
   whole set is suppressed and reported in the scan summary instead. The code documents why 20 is the right number:
   on the September 2026 catalogue the only KEV products above that threshold are Microsoft/Windows (170),
   Apple/Multiple Products (53), Chromium V8 (40), Internet Explorer (36), Flash Player (33), Office (29),
   Linux/Kernel (28) and Win32k (25) — precisely the names nmap attaches from an OS guess rather than from a versioned
   banner. Everything a banner genuinely identifies (FortiOS 15, Zimbra 18, Pulse Connect Secure 9) stays under the
   cap and is still reported. **Confirmed, version-evidenced hits are never capped.**
3. **Vendor-word rejection.** `homesoc/feeds/registry.py` refuses matches where the query says nothing beyond the
   entry's vendor name (`_is_vendor_word_only`): "microsoft" against Microsoft/Windows, "apple" against Apple/Multiple
   Products.

NVD enrichment (`homesoc/vulns/enrich.py`) is deliberately budgeted rather than exhaustive: a `RateLimiter` of
5 requests / 30 s without a key and 50 with one, a per-scan time `Budget` that degrades to fewer findings rather than a
hung scan, `RESULTS_PER_PAGE = 50`, `TOP_N = 5` CVEs kept per service because the dashboard links out to NVD for the
rest, and `NVD_KEYWORD_MAX_TOTAL = 200` — a keyword search returning more than 200 hits means the version token
narrowed nothing, so the result cannot be attributed to this service and is discarded. EPSS then annotates whatever
survived, with `NET-VUL-004` at the 0.5 probability threshold — a coherent number precisely because EPSS is a
probability of exploitation in the next 30 days [27], not an abstract severity.

Only `min_cvss_report = 7.0` and above becomes a finding (`NET-VUL-003`), for the same anti-noise reason.

### 7.5 Why nothing requires administrator rights by default

**The measurement:** the environment it was built against is Windows 11 Home, non-admin, with UAC on.
`Register-ScheduledTask` fails with Access Denied. `Confirm-SecureBootUEFI`, `Get-Tpm` and `Get-BitLockerVolume` all
fail with Access Denied. The Security event log is unreadable. (`docs/TESTED_ENVIRONMENT.md`)

**The research reinforces it from the other direction:** the CrowdStrike outage is what happens when privileged
security code fails [5], and Microsoft is actively moving endpoint security out of the kernel so that a security
product's bug takes down only the security product [6].

**So the whole tool runs as a normal user**, and the places where that costs information are surfaced as information
rather than papered over:

- `host_checks.status` includes a distinct `needs_admin` state (`docs/SPEC.md` §4), so an unreadable check is never
  reported as a passing check *or* as a failure. `SOC-SYS-002` (info) lists exactly which checks were skipped, and the
  `/summary` report's `notes` array surfaces them ("Secure Boot could not be checked without administrator rights").
- The DNS resolver binds 53 without elevation (§7.3). Only the optional inbound firewall rule needs admin, and it
  lives in one clearly-labelled script.
- Autostart is a Startup-folder shortcut, because Scheduled Task registration needs elevation on this machine;
  `scripts/make-autostart.ps1 -Mode task` exists for people who have admin and want it.
- `python -m homesoc scan --only host` degrades: it reports what it could read and names what it could not.

This is a real trade-off, honestly stated: a non-admin tool cannot install Sysmon, cannot read the Security log, and
cannot verify BitLocker or Secure Boot. It can, however, be run by the person whose house it is, today, without
teaching them to elevate a Python script — and a tool that runs is worth more than a tool that would have seen more.

### 7.6 Why the dashboard is local-first

`web.host` defaults to `127.0.0.1` and `web.token` defaults to empty (`config.example.toml`); binding to `0.0.0.0`
without setting a token raises `SOC-SYS-003` (high). Every page sets `X-Frame-Options: DENY` and
`Content-Security-Policy: default-src 'self'`; there are no CDN assets, so the CSP is achievable rather than
aspirational; POSTs require an `X-Requested-With: fetch` header as a CSRF guard (`docs/SPEC.md` §15). A security tool
that adds a new listening service to the network has to be held to the standard it applies to everything else — the
same standard that produces `WIN-NET-006` ("unusual LAN listener") for everybody else's software.

### 7.7 Why there is no telemetry

There is no analytics endpoint, no crash reporting, no phone-home. The only outbound traffic is to the feed URLs in
`homesoc/feeds/registry.py`, the NVD API, `api.ipify.org`, Shodan InternetDB, the configured DNS upstreams, and — only
if the user supplies a key — VirusTotal. That last one is a licensing constraint as much as a privacy one:
VirusTotal's public API is 500 requests/day and 4/minute and "must not be used in commercial products or services"
[28], which is exactly why `dns.virustotal_api_key` is empty by default, why `virustotal_daily_budget` defaults to 400
rather than 500 (headroom against the daily cap), and why `homesoc/dnsfilter/reputation.py` implements a 4/minute
token bucket and a persisted daily counter. `homesoc/scanners/files.py` hashes files locally and looks up *hashes*
only — it never uploads a file.

### 7.8 Why the findings catalogue carries remediation, not just detection

Sysmon's documented limitation is instructive: it "does not provide analysis of the events it generates" [13].
Neither do most scanners. For a home user, an unexplained finding is worse than no finding, because it produces
anxiety without an action.

So every one of the ~92 IDs in `homesoc/findings/catalog.py` (1,501 lines for 92 findings — the remediation text is
most of the file) carries a `rationale`, a list of click-by-click `remediation` steps written for Windows 11 Home with
a PowerShell alternative where one exists, and `refs`. The `/summary` page and `python -m homesoc report --format md`
embed those steps directly in the open worklist, so the exported Markdown report is actionable by someone who has
never opened the dashboard (`docs/SPEC_ADDENDUM.md` §A3).

The lifecycle matters as much as the text. `findings.engine.apply(scope=...)` auto-resolves findings that were not
re-observed in a scan of the same scope, and the summary distinguishes `how: "auto"` (the agent re-scanned and the
problem was gone — the strongest possible evidence) from `how: "manual"` (a human ticked a box). That is why the
measured state on the author's machine is "71 findings found, 70 open": almost nothing has been fixed yet, and the
tool is honest about it rather than flattering.

### 7.9 Open questions this research raised

Three things surfaced while writing this that are worth someone's attention (all outside this document's files):

1. **oisd's licence note is unverified.** `homesoc/feeds/registry.py` records "oisd, CC BY-SA 4.0"; the oisd homepage
   as fetched does not state a licence [31].
2. **abuse.ch now requires an Auth-Key for API interaction** [29]. The blocklist file downloads still work
   unauthenticated (ground truth measured URLhaus hostfile at 12 KB, ThreatFox at 1.7 MB), but the reputation lookup
   path in `homesoc/dnsfilter/reputation.py` treats URLhaus as a keyless second source. Worth re-testing.
3. **oisd has been retiring HOSTS/DOMAINS syntax formats in favour of filter syntax** [31]. Home SOC already parses
   `small.oisd.nl` with the ABP-style `parse_adblock`, so it is on the right side of that change — but the `hosts`-kind
   feeds in the registry are the ones to watch if other publishers follow.

---

## 8. Sources

All fetched 2026-09-07 unless noted. Every one of these pages was actually retrieved; pages that could not be
retrieved are named in the body text and are deliberately absent from this list.

1. Microsoft, *Microsoft Defender Antivirus in Windows Overview* — https://learn.microsoft.com/en-us/defender-endpoint/microsoft-defender-antivirus-windows
2. Microsoft, *Configure block at first sight in Microsoft Defender Antivirus* — https://learn.microsoft.com/en-us/defender-endpoint/configure-block-at-first-sight-microsoft-defender-antivirus
3. Microsoft, *Microsoft Defender Antivirus security intelligence and product updates* — https://learn.microsoft.com/en-us/defender-endpoint/microsoft-defender-antivirus-updates
4. Microsoft, *How AMSI helps you defend against malware* — https://learn.microsoft.com/en-us/windows/win32/amsi/how-amsi-helps
5. CrowdStrike, *Channel File 291 Incident Root Cause Analysis* (6 August 2024) — https://www.crowdstrike.com/wp-content/uploads/2024/08/Channel-File-291-Incident-Root-Cause-Analysis-08.06.2024.pdf
6. Microsoft, *The Windows Resiliency Initiative: Building resilience for a future-ready enterprise* (26 June 2025) — https://blogs.windows.com/windowsexperience/2025/06/26/the-windows-resiliency-initiative-building-resilience-for-a-future-ready-enterprise/
7. Microsoft, *Protect security settings with tamper protection* — https://learn.microsoft.com/en-us/defender-endpoint/prevent-changes-to-security-settings-with-tamper-protection
8. Cisco Talos, *ClamAV Signatures* — https://docs.clamav.net/manual/Signatures.html
9. VirusTotal, *YARA — Writing YARA rules* — https://yara.readthedocs.io/en/stable/writingrules.html
10. AV-TEST, *Test procedures* — https://www.av-test.org/en/about-the-institute/test-procedures/
11. AV-Comparatives, *Real-World Protection Test methodology* — https://www.av-comparatives.org/real-world-protection-test-methodology/
12. SE Labs — https://selabs.uk/
13. Microsoft Sysinternals, *Sysmon* — https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon
14. Microsoft, *Protecting anti-malware services* (ELAM / protected process light) — https://learn.microsoft.com/en-us/windows/win32/services/protecting-anti-malware-services-
15. Microsoft, *Filter Manager Concepts* (minifilter drivers, altitudes) — https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/filter-manager-concepts
16. Microsoft, *Appendix L — Events to Monitor* — https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/appendix-l--events-to-monitor
17. osquery, *SQL as understood by osquery* — https://osquery.readthedocs.io/en/stable/introduction/sql/
18. Wazuh, *Components* — https://documentation.wazuh.com/current/getting-started/components/index.html
19. Velociraptor, *Overview* — https://docs.velociraptor.app/docs/overview/
20. OISF, *What is Suricata* — https://docs.suricata.io/en/latest/what-is-suricata.html
21. CrowdSec, *Introduction* — https://docs.crowdsec.net/docs/intro
22. Pi-hole, *Post-install — pointing clients at Pi-hole* — https://docs.pi-hole.net/main/post-install/
23. AdGuard, *AdGuard Home* — https://github.com/AdguardTeam/AdGuardHome
24. Cloudflare, *1.1.1.1 setup* (1.1.1.2 malware blocking, 1.1.1.3 malware + adult) — https://developers.cloudflare.com/1.1.1.1/setup/
25. Quad9, *Service addresses and features* — https://www.quad9.net/service/service-addresses-and-features/
26. CISA, *Known Exploited Vulnerabilities Catalog* — https://www.cisa.gov/known-exploited-vulnerabilities-catalog
27. FIRST, *Exploit Prediction Scoring System (EPSS)* — https://www.first.org/epss/
28. VirusTotal, *Public vs Premium API* — https://docs.virustotal.com/reference/public-vs-premium-api
29. abuse.ch, *URLhaus API* — https://urlhaus.abuse.ch/api/
30. HaGeZi, *DNS Blocklists* — https://github.com/hagezi/dns-blocklists
31. oisd — https://oisd.nl/
32. Nmap, *Host Discovery* (reference guide) — https://nmap.org/book/man-host-discovery.html
33. NCSC (UK), *Top tips for staying secure online* — https://www.ncsc.gov.uk/collection/top-tips-for-staying-secure-online
34. CISA, *Secure Our World — Turn on MFA* — https://www.cisa.gov/secure-our-world/turn-mfa
35. NIST, *IR 8425: Profile of the IoT Core Baseline for Consumer IoT Products* — https://csrc.nist.gov/pubs/ir/8425/final

**Internal references** (this repository, not external sources): `docs/SPEC.md`, `docs/SPEC_ADDENDUM.md`,
`docs/TESTED_ENVIRONMENT.md`, `config.example.toml`, `homesoc/scanners/discovery.py`, `homesoc/scanners/ports.py`,
`homesoc/scanners/defender.py`, `homesoc/vulns/matcher.py`, `homesoc/vulns/enrich.py`, `homesoc/feeds/registry.py`,
`homesoc/dnsfilter/server.py`, `homesoc/dnsfilter/policy.py`, `homesoc/dnsfilter/reputation.py`,
`homesoc/findings/catalog.py`.
