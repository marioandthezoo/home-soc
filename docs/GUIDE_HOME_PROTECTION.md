# How to actually protect a home computer and network

A practical, tiered plan for a normal house with a normal router.

This guide stands on its own. You do not need Home SOC — or any software — to follow it. Every item is
something you can do with the settings screens you already have. Where Home SOC *can* verify an item for
you, the item is tagged with the exact finding IDs it raises, so you can check the tool's work.

Read the reasoning, not just the instruction. Home networks differ enormously, and the reasoning is what
lets you adapt an item when your router's menu says something slightly different.

---

## Contents

1. [What you are actually defending against](#1-what-you-are-actually-defending-against)
2. [How to read the tags](#2-how-to-read-the-tags)
3. [DAY ONE — the seven things that block most real attacks](#3-day-one--the-seven-things-that-block-most-real-attacks)
4. [WEEK ONE — close the doors you left open](#4-week-one--close-the-doors-you-left-open)
5. [ADVANCED — depth, and defence that keeps working while you sleep](#5-advanced--depth-and-defence-that-keeps-working-while-you-sleep)
6. [DNS filtering: one change that protects every device](#6-dns-filtering-one-change-that-protects-every-device)
7. [IoT and camera hygiene](#7-iot-and-camera-hygiene)
8. [Phishing: the habits that matter](#8-phishing-the-habits-that-matter)
9. [Children's devices](#9-childrens-devices)
10. [What Home SOC can and cannot see](#10-what-home-soc-can-and-cannot-see)
11. [The 15-minute monthly routine](#11-the-15-minute-monthly-routine)
12. [One-page printable checklist](#12-one-page-printable-checklist)
13. [Sources](#13-sources)

---

## 1. What you are actually defending against

Almost nobody targets a specific house. What reaches a home network is opportunistic, and it arrives
through a small number of doors:

- **Phishing and fake login pages.** Someone in the house clicks a link, types a password into a page that
  looks right, and an attacker now owns an account. CISA's Secure Our World campaign puts "Recognize &
  Report Phishing" first for exactly this reason.
- **Reused and breached passwords.** A shop gets breached, the password list is published, and bots try
  that email-and-password pair on hundreds of other sites. The break-in requires no skill at all.
- **Unpatched software.** Automated scanners look for a known flaw with a public exploit. CISA calls
  regular software updates "one of the most effective steps you can take" for a home network.
- **Anything you accidentally published to the internet.** A port forward, a DMZ host, a UPnP mapping
  opened by a game or by malware, or a router's remote-administration page. Internet-wide scanners find
  every public IP many times a day.
- **A weak device on your own Wi-Fi.** A camera with a default password, a smart plug that stopped getting
  firmware in 2019, a TV. Once something on the LAN is compromised, it can reach everything else on the LAN.
- **Ransomware.** Usually arriving through one of the routes above, and it will encrypt anything it can
  write to — including the backup drive you left plugged in.

Every item in this guide maps back to one of those six. If an item does not reduce one of them, it is not
in the guide.

Two things follow from this list, and they shape the whole plan:

1. **Identity is the front door.** Your email account can reset almost every other account you own. It
   deserves more protection than your PC does.
2. **The router is the wall.** Nothing on your LAN is exposed to the internet unless the router lets it be.
   Most catastrophic home compromises start with a router setting, not with malware.

---

## 2. How to read the tags

Every item carries one of two tags.

> **Home SOC checks this automatically:** `WIN-FW-001`, `WIN-FW-002`

The tool raises those finding IDs when the item is wrong. The IDs are real and come from
`homesoc/findings/catalog.py`; you can look any of them up on the dashboard's Findings page or with
`python -m homesoc findings --status open`.

> **Manual — Home SOC cannot verify this.**

No scanner in the tool can see this. It is on you. These items are not less important — several of the
highest-value items in this guide are manual, because they live in your head, in your router's admin page,
or in a cupboard with a backup drive in it.

A few automatic checks carry a caveat: on Windows 11 Home, running as a normal user, some settings are
simply not readable without administrator rights. Home SOC says so out loud rather than guessing — it
raises `SOC-SYS-002` listing exactly which checks it skipped. Those items are tagged as automatic with the
caveat noted, because the check exists; it just needs elevation to run.

---

## 3. DAY ONE — the seven things that block most real attacks

Budget about ninety minutes. If you do nothing else in this guide, do these.

### 3.1 Turn automatic updates on, everywhere

**Why.** Most successful attacks on home machines use a flaw that was fixed months earlier. You are not
racing an attacker who discovered something new; you are racing a bot replaying something old. Updating
removes the whole class of attack rather than detecting it.

**Do it.**

- Windows: **Settings > Windows Update**. Install everything pending, then turn on **Get the latest updates
  as soon as they're available**. Reboot. A pending update that needs a restart is not installed.
- Also switch on **Receive updates for other Microsoft products** on the same screen — this is what keeps
  Office and other Microsoft apps patched.
- Phones and tablets: turn on automatic OS updates *and* automatic app updates. NCSC's smart-device
  guidance says the same thing about anything else in the house that has an update option: switch on
  automatic updates if the option exists, and install manual ones when prompted.
- Your browser: it updates itself, but only when you fully close it. Restart it once a week.
- Everything else (VPN clients, Java, VLC, PDF readers, drivers): these are the ones people forget. On
  Windows, `winget upgrade --all` from a normal PowerShell window will handle most of them.

> **Home SOC checks this automatically:** `WIN-UPD-001` (updates pending), `WIN-UPD-002` (last cumulative
> update is old), `WIN-UPD-003` and `WIN-UPD-004` (outdated apps, with high-risk apps split out),
> `POSIX-UPD-001` on a Mac or Linux box.
>
> Note what this actually measures: the *outcome*, not the toggle. Home SOC sees that you are behind; it
> cannot see whether the automatic-update switch is on. If the count stays at zero, the switch is working.

### 3.2 Confirm Microsoft Defender is on — including tamper protection

**Why.** Windows ships with a competent antivirus, and for a home machine you do not need to buy another
one. What matters is that it is actually running, that its definitions are fresh, and that malware cannot
switch it off. Tamper protection is the one that people miss: Microsoft describes it as protection against
attackers who "try to disable security features on devices", and with it on, real-time protection, cloud
protection and definition updates cannot be turned off by anything but you, deliberately, in the Windows
Security app.

**Do it.** Open Start, type **Windows Security**, press Enter. Go to **Virus & threat protection >
Manage settings** and confirm all of these are **On**:

- Real-time protection
- Cloud-delivered protection
- Automatic sample submission
- Tamper protection

Then go back and click **Check for updates** under **Virus & threat protection updates**.

If you installed a third-party antivirus at some point and stopped paying for it, uninstall it. A lapsed
antivirus does not fail loudly; it fails by leaving Defender switched off.

> **Home SOC checks this automatically:** `WIN-DEF-001` (antivirus disabled), `WIN-DEF-002` (real-time
> protection off), `WIN-DEF-003` (signatures stale), `WIN-DEF-004` (tamper protection off), `WIN-DEF-005`
> (cloud-delivered protection off), `WIN-DEF-012` (the Defender service itself is unhealthy), and
> `WIN-DEF-011` when Defender actually detects something.

### 3.3 Confirm the Windows Firewall is on for all three profiles

**Why.** The firewall is what stops other devices on the same network from reaching services running on
your PC. That matters more at home than people assume, because "other devices on the same network"
includes the TV, the printer, a guest's phone, and anything a neighbour is running on your Wi-Fi. CISA
recommends both a network firewall at the boundary and host-based firewalls on individual devices, for
this reason: the boundary firewall does nothing about a threat that is already inside.

**Do it.** **Windows Security > Firewall & network protection**. You will see three profiles — Domain,
Private, Public. All three should say **Firewall is on**. If any says otherwise, click it and switch it on.

Leave the default inbound behaviour alone: Windows blocks unsolicited inbound connections by default, and
that default is the whole point.

> **Home SOC checks this automatically:** `WIN-FW-001` (a profile is disabled), `WIN-FW-002` (the default
> inbound action is Allow rather than Block). `WIN-FW-002` needs administrator rights to read; without them
> Home SOC records it as skipped and reports that through `SOC-SYS-002` rather than pretending it passed.

### 3.4 Change the router's admin password, and turn off remote administration

**Why.** This is the single highest-leverage item in the guide and it takes five minutes. Whoever controls
the router controls DNS for the whole house, can open ports, and can watch traffic. Default and
label-printed credentials for consumer gateways are widely published. CISA's home network guidance is
explicit: change default log-in passwords and usernames, disable remote management, and change the default
SSID. The NSA's home network information sheet makes the same two points — enable strong authentication on
the router, and disable the ability to perform remote administration, making configuration changes only
from inside your own network.

**Do it.**

1. Open your router's admin page in a browser. On most home networks that is `http://192.168.1.1` or
   `http://192.168.0.1`; on AT&T/Nokia gateways it is `http://192.168.1.254`. If you do not know, the
   address is your default gateway — on Windows, run `ipconfig` and look at **Default Gateway**.
2. Sign in with the password on the router's label.
3. Change the **admin/device access password** to something long and unique, and store it in your password
   manager. This is not the Wi-Fi password; it is a separate one, and on many gateways people never change
   it. (On some carrier gateways the device access code cannot be changed. If so, note it and compensate
   with the rest of this section.)
4. Find **Remote management**, **Remote administration**, **Web access from WAN**, or **TR-069 / remote
   support** and turn off anything that lets the admin page be reached from the internet.
5. While you are here, change the **SSID** (network name) if it still contains your ISP's name, the router
   model, or your surname. Do **not** hide the SSID — NSA guidance notes that hiding it adds no real
   security and can cause compatibility problems.

> **Manual — Home SOC cannot verify this.** There is no finding for "the router password is still the
> default" or "remote administration is enabled", because verifying either would mean trying to log into
> your router, which the tool does not do.
>
> There is a partial safety net: if remote administration is on *and actually reachable from the internet*,
> the exposure scan will see the open port from outside and raise `NET-WAN-001`, and if the fingerprinted
> service has known vulnerabilities, `NET-WAN-002`. That catches the dangerous case, not the setting.

### 3.5 Wi-Fi: WPA3 if you can, WPA2 with AES if you cannot, and WPS off

**Why.** Encryption on the wireless link decides whether a person in a car outside can read your traffic
and join your LAN. The differences are real:

- **Open or WEP** — anyone nearby can read everything and join. WEP is broken and can be cracked in minutes.
- **WPA2 with TKIP** — TKIP is a 2003 stop-gap with known attacks, and it slows the network down. Never use it.
- **WPA2 with AES/CCMP** — still acceptable. Its weakness is that a passive listener can capture the
  handshake and then guess your passphrase offline, at whatever speed they can afford. Your passphrase
  length is the only thing standing in the way.
- **WPA3-Personal** — replaces that handshake with SAE. Wi-Fi Alliance describes SAE as providing "stronger
  protections for users against password guessing attempts by third parties", giving "more resilient,
  password-based authentication even when users choose passwords that fall short of typical complexity
  recommendations". In plain terms: an attacker has to guess online, against your router, one attempt at a
  time, instead of offline at a billion attempts a second.

**WPS** is a separate problem. Its PIN mode can be brute-forced on many routers, and that bypasses your
passphrase entirely no matter how long it is.

**Do it.** In the router admin page, under **Wireless / Wi-Fi security**:

- Set security to **WPA3-Personal**, or **WPA2/WPA3 mixed (transition)** if older devices need to connect.
  If WPA3 is not offered at all, choose **WPA2-Personal (AES)** — never "TKIP" or "TKIP+AES".
- Set a passphrase of at least 15–20 characters. Three or four random words is easy to type on a TV remote
  and far stronger than `Summer2026!`.
- Set **WPS** to **Off**.

> **Home SOC checks this automatically:** `NET-WIFI-001` (open or WEP), `NET-WIFI-002` (WPA2 without WPA3),
> `NET-WIFI-003` (TKIP), `NET-WIFI-004` (WPS appears to be enabled).
>
> `NET-WIFI-004` is a heuristic based on what the access point advertises, so treat it as "go and look"
> rather than proof. `NET-WIFI-002` is only informational — WPA2-AES is not a failure, it is a step below
> the best available.

### 3.6 Get a password manager, and give your email account a password nothing else uses

**Why.** You cannot remember sixty unique passwords, and every scheme you invent for generating them is a
pattern an attacker can learn once and reuse everywhere. A password manager is the only approach that
actually produces unique credentials at scale.

NIST's current digital identity guidelines back this up in a way that surprises people: verifiers "SHALL
NOT impose other composition rules (e.g., requiring mixtures of different character types) for passwords",
and "SHALL NOT require subscribers to change passwords periodically". Length and uniqueness are what
matter — not symbols, not quarterly rotation. NIST also says verifiers **SHALL** allow password managers
and autofill, and **SHOULD** permit pasting. Anyone who tells you a password manager is risky is arguing
against the standard.

Your email account is special. It is the reset path for everything else you own. NCSC's top tips lead with
"protect your email by using a strong and separate password" for that reason.

**Do it.**

1. Pick a password manager — the ones built into your browser or operating system are legitimate options,
   and NCSC explicitly endorses using browsers and apps to manage passwords. A dedicated cross-platform
   manager is better if you use more than one ecosystem.
2. Set its master password to three or four random words. Write that one down on paper and put it somewhere
   only you can reach. It is the one password you must never lose.
3. Change your **email** password first, to a long unique one generated by the manager.
4. Then work down the list: bank, phone carrier, cloud storage, government portals, shopping sites with a
   card saved. You do not have to do all of them today.

> **Manual — Home SOC cannot verify this.** Home SOC never sees your accounts or your passwords, and by
> design it never will. There is no finding ID for this, and any tool that claims to check it is asking you
> to hand over more than it should.

### 3.7 Turn on multi-factor authentication where it protects money or identity

**Why.** MFA is what makes a stolen password insufficient. It is the direct countermeasure to the breached-
password problem, and CISA lists "Turn on Multifactor Authentication" as one of its four core actions for
individuals and families.

Not all second factors are equal, and it is worth knowing why:

- **SMS codes** — better than nothing, and much better than nothing on an account that has none. Weak
  against SIM-swap attacks and against a convincing phishing page that asks you to type the code.
- **Authenticator app codes (TOTP)** — better. Still phishable: a fake login page can ask for the six
  digits and relay them in real time.
- **Passkeys / security keys** — the only genuinely phishing-resistant option. NIST notes that phishing
  resistance requires cryptographic authentication and explicitly excludes manually entered codes, because
  those are not bound to the site you are actually on. Microsoft describes passkeys as being "enforced by
  the browsers or operating systems to only be used for the appropriate service, rather than relying on
  human verification" — the browser simply will not release a passkey to a look-alike domain.

**Do it.** Turn MFA on, in this order: **email**, then **bank and payment apps**, then **cloud storage**,
then anything that stores a card. Where the site offers a **passkey**, use it — on Windows 11 you can
create and store one with Windows Hello (face, fingerprint or PIN) and Windows has a native passkey
management experience from version 22H2 onward.

Save the **recovery codes** each service gives you into your password manager. Losing your second factor
with no recovery code is a genuinely bad afternoon.

> **Manual — Home SOC cannot verify this.**

---

## 4. WEEK ONE — close the doors you left open

### 4.1 Stop using an administrator account for everyday work

**Why.** When you browse, read mail and install things as an administrator, anything that runs as you
inherits that power — it can disable security software, install drivers, and write to system directories
without ever showing you a prompt. As a standard user, that same code hits a wall and has to ask for an
administrator password it does not have. This is one of the largest reductions in blast radius available to
a home user, and it costs you a password prompt a few times a month.

**Do it.**

1. **Settings > Accounts > Other users > Add account**. Create a second local account, and use **Change
   account type** to make it an **Administrator**. Give it a strong password, stored in your manager.
   Verify you can sign into it before continuing.
2. Sign back into your normal account and change **its** type to **Standard user**.
3. From now on, when Windows asks for administrator credentials, type the second account's password.

While you are in accounts, check three related things:

- The built-in **Administrator** account should stay disabled.
- The **Guest** account should stay disabled.
- **Automatic logon** should be off — it means anyone who opens the lid is you.
- **User Account Control** should be at its default level, not "Never notify".

> **Home SOC checks this automatically:** `WIN-ACC-001` (your daily account is an Administrator),
> `WIN-ACC-002` (built-in Administrator enabled), `WIN-ACC-003` (Guest enabled), `WIN-ACC-004` (automatic
> logon enabled), `WIN-ACC-005` (UAC off or set to never prompt).

### 4.2 Turn on disk encryption and save the recovery key somewhere you will find it

**Why.** Every protection in this guide assumes the attacker is on the network. Encryption is for the
attacker who is holding your laptop. Without it, someone can pull the drive out, mount it on another
machine, and read every file plus every credential cached on it — none of your Windows passwords apply.
With it, the drive is a brick.

**Do it.** On Windows 11 Home the feature is called **Device encryption**: **Settings > Privacy & security
> Device encryption**. If the switch is not there, your hardware does not meet the requirements; **Windows
11 Pro** offers full BitLocker instead. On a Mac, turn on **FileVault** under **System Settings > Privacy &
Security**. On Linux, disk encryption (LUKS) is normally a choice made at install time.

**Then save the recovery key.** Print it, or store it in your password manager, or both. A recovery key
that exists only in the Microsoft account you cannot sign into is not a recovery key.

> **Home SOC checks this automatically:** `WIN-SYS-002` (BitLocker / device encryption is off),
> `POSIX-ENC-001` on Mac or Linux.
>
> Caveat: reading BitLocker state on Windows requires administrator rights. Run as a normal user, Home SOC
> reports the check as skipped via `SOC-SYS-002` rather than claiming your disk is encrypted.

### 4.3 Make the screen lock itself

**Why.** Unattended and unlocked is the most common way household devices get into the wrong hands, and it
is the one attack that requires no technical skill whatsoever. It also matters for encryption: full-disk
encryption protects a powered-off machine, not a logged-in one.

**Do it.**

- Windows: **Settings > Accounts > Sign-in options** and set **If you've been away, when should Windows
  require you to sign in again?** to **When PC wakes up from sleep**. Then **Settings > Personalization >
  Lock screen > Screen saver** and tick **On resume, display logon screen** with a wait of 5–10 minutes.
- Set up **Windows Hello** (face, fingerprint or PIN) so locking costs you nothing.
- Phones and tablets: a lock screen with biometrics, auto-lock at 1–2 minutes.

> **Home SOC checks this automatically:** `WIN-SYS-007` (screen lock is not enforced) on Windows. Phones
> and tablets are **Manual — Home SOC cannot verify this.**

### 4.4 Set up backups you would actually survive a ransomware attack with

**Why.** Backups are the only control that works after everything else has failed. But the version most
people have — a single external drive, permanently plugged in — is exactly the version ransomware defeats,
because the malware runs as you and can write to anything you can write to.

The rule is **3-2-1**, and it comes from CERT/US-CERT guidance: keep **3** copies of any important file
(one primary and two backups), on **2** different media types, with **1** copy stored offsite. NCSC adds
the detail that makes it work against ransomware: "When the removable media isn't in use, it's important
that you disconnect it. Viruses (and other types of malware, such as ransomware) can move to attached media
automatically."

**Do it.**

1. **Decide what matters.** NCSC's framing is the useful one: back up anything that would inconvenience you
   if you could no longer reach it. In practice: documents, photos, tax records, password manager export,
   the recovery keys from 4.2.
2. **Copy 1 — cloud, automatic.** OneDrive, iCloud, Google Drive or a dedicated backup service. Automatic
   is the point: NCSC notes you are more likely to have a recent copy and you do not have to remember.
   Be aware that a *sync* folder is not fully a backup — if a file is encrypted locally it syncs the
   encrypted version — so use a service with **version history** and know how to roll back.
3. **Copy 2 — external drive, disconnected.** Plug it in, run the backup, unplug it, put it in a drawer.
   Monthly is enough for most households. This is the copy that survives ransomware, because for 30 days
   out of 31 it is not attached to anything.
4. **Test a restore.** Once. Pick a file, delete it, get it back. An untested backup is a belief, not a backup.

Optionally, turn on Defender's **Controlled folder access** (see 5.2) so unknown programs cannot write into
Documents and Pictures in the first place.

> **Manual — Home SOC cannot verify this.** There is no backup finding in the catalog. Home SOC does not
> look at your files' backup state and has no way to know whether a drive in a drawer contains a good copy.

### 4.5 Update the router's firmware — and find out how old the router is

**Why.** Routers run a full operating system and get vulnerabilities like anything else, but almost nobody
patches them, and many stop receiving patches years before people stop using them. CISA lists updating
firmware regularly as core router security. An end-of-life router with a publicly known flaw is a
permanent, unfixable hole in the wall.

**Do it.**

1. In the admin page, find **Firmware / Software update** and apply anything pending. Reboot.
2. If there is an **automatic firmware update** option, turn it on.
3. Look up your model plus "end of life" or "end of support". If the manufacturer stopped issuing security
   updates, plan to replace it. A modern router with WPA3 and current firmware is one of the better
   security purchases available to a household — and it fixes item 3.5 at the same time.
4. If you rent a gateway from your ISP, ask them whether it still receives firmware updates. Many carrier
   gateways update themselves silently, which is fine, but you should know which situation you are in.

> **Manual — Home SOC cannot verify this.** Home SOC does not log into your router and does not track
> firmware versions or end-of-life dates.
>
> Partial safety net: if the router exposes a service to the internet and that service is fingerprinted
> with known vulnerabilities, `NET-WAN-002` will report it, and `NET-VUL-001` / `NET-VUL-002` will flag
> LAN-side services matched against the CISA Known Exploited Vulnerabilities catalog.

### 4.6 Turn off UPnP, and clear any port mappings it already created

**Why.** UPnP lets any program on any device open a hole in your router without asking you. It exists
because game consoles and video-calling apps wanted it. Malware wants it for the same reason. CISA lists
disabling UPnP alongside disabling WPS and remote management; NSA guidance says the same. NCSC's smart
camera advice tells people to disable UPnP and port forwarding on the router because "cyber criminals can
exploit these technologies to potentially access devices on your network".

**Do it.**

1. In the admin page, find **UPnP** (often under Advanced > NAT, Gaming, or Firewall) and set it to **Off**.
2. Find the list of existing **port mappings / port forwarding / pinholes** and delete everything you cannot
   personally explain. Then check the **DMZ** setting and make sure no host is in it.
3. If a console complains about NAT type afterwards, add one explicit port forward for that console only.
   That is a deliberate, documented hole, which is a completely different thing from an automatic one.
4. If you need to reach something at home from outside, use a VPN — WireGuard or Tailscale — rather than
   forwarding a port. NSA guidance recommends a VPN for exactly this kind of remote access.

> **Home SOC checks this automatically:** `NET-RTR-002` (router has UPnP/IGD enabled), `NET-WAN-003` (an
> active UPnP port mapping, showing which internal device opened it), `NET-SVC-006` (a UPnP/SSDP control
> port open on a device), `NET-WAN-001` (a port actually reachable from the internet on your public IP).
>
> Caveat worth knowing: `NET-RTR-002` is raised from SSDP discovery. A router that simply does not respond
> to SSDP looks the same as one with UPnP off. Absence of this finding is good news, not proof — check the
> setting yourself once.

### 4.7 Take an inventory of everything on your network

**Why.** You cannot secure a device you have forgotten about, and the average house has more of them than
the people in it can name. Every one of them can reach every other one. The forgotten ones — an old tablet,
a camera from a previous house, a smart plug — are the ones with default passwords and dead firmware.

**Do it.** Open the router's **connected devices / device list** page and write down every entry. For each,
answer: what is it, do we still use it, does it still get updates, and is its password still the default?

Then act:
- Devices you no longer use: unplug them and factory-reset before disposal. NCSC recommends a factory reset
  before selling or giving away any smart device.
- Devices you cannot identify: change your Wi-Fi passphrase and reconnect only the things you own. Anything
  that disappears was not yours.
- Devices you keep: they go on the IoT list in section 7.

Then ask the second question: what is each of them *running*? A device is not just present on your network,
it is offering services to it. A NAS sharing files without authentication, a printer accepting raw print
jobs, an old Raspberry Pi with a database bound to `0.0.0.0` — these are all reachable by anything else on
the LAN, including a compromised TV. Turn off sharing you do not use, and put a password on the sharing you
do.

> **Home SOC checks this automatically:** `NET-DEV-001` (a new device joined the network, with vendor and
> hostname), `NET-DEV-002` (unknown vendor or randomized MAC), `NET-DEV-003` (a device you marked as
> trusted has been offline for a long time). The Devices page keeps the running inventory for you.
>
> For what those devices are offering: `NET-SVC-003` (SMB file sharing on a non-Windows device),
> `NET-SVC-004` (RDP or VNC remote desktop exposed), `NET-SVC-007` (a database port open),
> `NET-SVC-008` (printer raw port or IPP without authentication), `NET-SVC-011` (an outdated SSH server),
> alongside the `NET-SVC-*` findings listed in section 7.

### 4.8 Deal with the passwords that are already breached

**Why.** Credential-stuffing does not need to guess. It replays known email-and-password pairs from past
breaches. If one of yours is on such a list and you reused it, the account is effectively already open.
This is why NIST requires verifiers to compare new passwords against blocklists of "known commonly used,
expected, or compromised passwords" — but you cannot rely on every site having done that.

**Do it.**

1. Run your password manager's built-in breach / weak / reused report. Every mainstream manager has one,
   and it checks against breach corpora without sending your actual passwords anywhere.
2. Fix in this order: **email**, anything holding money, anything holding a saved card, then the rest.
3. Where a service offers a **passkey**, switching to it retires the password problem for that account
   rather than moving it — there is no shared secret left for a breach to leak.
4. If an account you no longer use turns up, delete the account rather than fixing the password.

> **Manual — Home SOC cannot verify this.**

### 4.9 Turn off legacy protocols and remote access on the PC

**Why.** Windows still ships with compatibility features from the 1990s and 2000s. Each one is a service
listening on your LAN, which means each one is reachable by the TV, the printer, the guest phone and
anything that has compromised them. SMBv1 in particular is the protocol WannaCry used; LLMNR is what
credential-relay tools on a LAN feed on; an internet-reachable Remote Desktop is one of the classic
ransomware entry points.

**Do it.** These live in different places, and Home SOC will tell you which ones apply to your machine
rather than making you check all of them:

- **SMBv1** should be off. Check **Control Panel > Programs > Turn Windows features on or off** and untick
  **SMB 1.0/CIFS File Sharing Support** if present.
- **Remote Desktop** should be off unless you actively use it: **Settings > System > Remote Desktop**. If
  you do use it, never forward it to the internet — reach it over a VPN.
- **LLMNR**, **SMB signing**, **WinRM / Remote Registry** and any unexpected program listening on the LAN
  are the second tier; fix them once the first two are done.

> **Home SOC checks this automatically:** `WIN-NET-001` (SMBv1 enabled), `WIN-NET-002` (Remote Desktop
> enabled, and whether Network Level Authentication is on), `WIN-NET-003` (SMB signing not required),
> `WIN-NET-004` (LLMNR enabled), `WIN-NET-005` (WinRM / Remote Registry listening), `WIN-NET-006` (an
> unusual program listening on the LAN). On Mac and Linux: `POSIX-FW-001` (host firewall inactive),
> `POSIX-SSH-001` (SSH allows root login), `POSIX-NET-001` (unexpected listening service).

---

## 5. ADVANCED — depth, and defence that keeps working while you sleep

These are worth doing, but only after Day One and Week One. Depth on top of an unlocked front door is not
depth.

### 5.1 Separate the IoT devices from the computers

**Why.** The core problem with a flat home network is that a compromised smart bulb and your laptop are
peers. NSA's home network guidance recommends implementing wireless network segmentation for precisely
this reason: put the devices you cannot patch and cannot trust somewhere they cannot reach the devices
that hold your data.

**Do it.** In rough order of effort:

1. **Guest network.** Nearly every router has one, and on most it isolates clients from the main LAN. Move
   TVs, speakers, plugs, bulbs and cameras onto it. Check for a setting called **AP isolation** or **Allow
   guests to access local network** and make sure local access is *off*.
2. **A second SSID for IoT** if your router supports more than two networks — that keeps the guest network
   genuinely for guests.
3. **VLANs**, if you have a router that supports them. This is the real version, and it is a weekend project.

Practical caveat: some IoT devices need to talk to a phone on the main network to be set up or controlled
(casting, printer discovery, some smart-home hubs). Do the setup on the main network, then move the device,
and test. A few will not tolerate it — decide case by case whether the convenience is worth it.

> **Manual — Home SOC cannot verify this.** Home SOC scans the network it is on; it cannot tell you whether
> a guest network exists or whether client isolation is enabled on it. The Devices page does help you
> confirm the move worked: after segmenting, the IoT devices should stop appearing on the main network scan.

### 5.2 Turn on the Defender features that are off by default

**Why.** Defender's baseline is good. Several of its stronger features are off by default because they can
generate friction, and a home machine can usually absorb that friction happily.

**Do it.** In **Windows Security > Virus & threat protection > Manage settings**:

- **Controlled folder access** — blocks unknown programs from writing to Documents, Pictures, and similar.
  This is genuinely effective against ransomware. Expect to allow a few legitimate apps the first week.
- **Potentially unwanted app (PUA) blocking** — stops adware and bundleware that comes with free installers.
- **Cloud protection block level** — raising it above the basic setting trades a slightly higher
  false-positive rate for faster protection against brand-new files.

And elsewhere:

- **Network protection** — blocks connections to known-malicious domains and IPs at the OS level.
- **Attack surface reduction (ASR) rules** — targeted rules like "block Office applications from creating
  child processes". Powerful, and worth reading about before enabling.
- **Smart App Control** — strong, but it can only be turned on from a clean Windows install, so for most
  people this is a note for next time they reinstall.
- Run a **full scan** occasionally. Quick scans run constantly; a full scan looks at everything, and most
  machines have never had one.

> **Home SOC checks this automatically:** `WIN-DEF-006` (PUA protection off), `WIN-DEF-007` (no full scan in
> 30 days), `WIN-DEF-008` (controlled folder access off), `WIN-DEF-009` (network protection off),
> `WIN-DEF-010` (no ASR rules configured), `WIN-DEF-013` (Smart App Control off), `WIN-DEF-014` (cloud block
> level / sample submission at the basic setting). You can also kick off a scan with
> `python -m homesoc defender --quick-scan`.

### 5.3 Check the platform security features underneath Windows

**Why.** Secure Boot, the TPM, memory integrity and LSA protection defend the layer below the operating
system — the boot process, the credentials in memory, and the drivers that load. They stop the class of
attack that survives a reinstall or steals your password hashes out of RAM.

**Do it.** Open **Windows Security > Device security**:

- **Secure Boot** should be on. If it is off, it is a UEFI/BIOS setting, and turning it on may require
  converting the disk from MBR to GPT.
- **Memory integrity** (HVCI) — turn it on. If it refuses, it will name the incompatible driver; that
  driver is usually old and worth replacing anyway.
- **Security processor (TPM)** should be present and ready — it is what makes device encryption seamless.
- **LSA protection** should be on; on recent Windows 11 builds it is enabled by default.
- Disable the **Windows PowerShell 2.0** engine if it is still present. Nothing modern uses it, and its only
  real user is malware avoiding logging.

> **Home SOC checks this automatically:** `WIN-SYS-001` (Secure Boot off), `WIN-SYS-003` (memory integrity /
> HVCI not running), `WIN-SYS-004` (LSA protection off), `WIN-SYS-005` (PowerShell 2.0 enabled),
> `WIN-SYS-006` (SmartScreen off), `WIN-SYS-008` (TPM absent or not ready).
>
> Caveat: Secure Boot and TPM state cannot be read without administrator rights. Without elevation Home SOC
> lists them in `SOC-SYS-002` as skipped rather than guessing.

### 5.4 Watch what gets added to the machine

**Why.** Persistence is how malware survives a reboot, and it always leaves a trace: a Run key, a scheduled
task, or an auto-start service. Nothing legitimate adds one of these silently and often. A weekly glance at
"what changed" catches things that antivirus signatures missed.

**Do it.** **Settings > Apps > Startup** shows the easy cases. **Task Manager > Startup apps** shows the
same list with impact ratings. For the full picture, Microsoft's free **Autoruns** utility shows every
autostart location Windows has.

> **Home SOC checks this automatically:** `WIN-PER-001` (new autostart entry), `WIN-PER-002` (new scheduled
> task), `WIN-PER-003` (new auto-start service). These are baselined on the first scan — the first run
> records what is normal for your machine, and after that only *changes* are reported. That is what makes
> them useful rather than noisy.

### 5.5 Know what is exposed from the outside

**Why.** Everything above is about your side of the router. This is the question an attacker asks first:
what does this public IP answer on? Nothing on a properly configured home network should answer at all.

**Do it.** From outside your network — or with a tool that queries an external scan database — check what
ports your public IP has open. If anything answers, work back to which port forward, DMZ host or UPnP
mapping created it and remove it.

Then, when a service is found, the question becomes whether it is *known* to be exploited. That is what the
CISA Known Exploited Vulnerabilities catalog answers: it lists vulnerabilities with confirmed real-world
exploitation, which is a much sharper signal than a CVSS score. EPSS complements it with a probability that
a given CVE will be exploited in the next 30 days.

> **Home SOC checks this automatically:** `NET-WAN-001` (a port open to the internet), `NET-WAN-002`
> (internet-facing vulnerabilities reported for your public IP), `NET-VUL-001` (a KEV-listed vulnerability
> on a device), `NET-VUL-002` (a possible KEV match), `NET-VUL-003` (known CVEs for a product and version),
> `NET-VUL-004` (exploitation likely in the wild, from EPSS). Feed freshness is itself checked, by
> `SOC-FEED-001` and `SOC-FEED-002`.

### 5.6 Harden the tool itself

If you do run Home SOC, it is a service on your network and deserves the same scrutiny as anything else.
Keep the dashboard bound to `127.0.0.1` (the default `web.host` in `config.example.toml`), and if you change
`web.host` to `0.0.0.0` so you can open it from your phone, set `web.token` at the same time.

> **Home SOC checks this automatically:** `SOC-SYS-003` (the dashboard is reachable from the LAN without a
> token), `SOC-SYS-004` (a scheduled job keeps failing), `SOC-SYS-002` (checks skipped for lack of
> administrator rights), `SOC-SYS-001` (nmap missing, so the built-in Python scanner is being used).

---

## 6. DNS filtering: one change that protects every device

**Why.** Almost every connection starts with a DNS lookup. If you can refuse to answer lookups for known
malware, phishing and tracking domains, you break a huge amount of badness before a single packet reaches
it — and you do it for *every* device, including the ones you cannot install software on: the TV, the
thermostat, the kids' tablets, the guest's phone.

It is not a substitute for anything else in this guide. It is unusually good value because it is one change
that covers the whole house.

**Do it — three levels of ambition.**

1. **Change your router's upstream DNS** to a filtering resolver. Cloudflare's `1.1.1.2` blocks known
   malware domains; Quad9's `9.9.9.9` blocks malicious domains using threat intelligence. This is a
   two-minute change in the router's WAN/Internet settings and needs no other software.
2. **Set DNS per device** if your router will not let you change it. This is the common case on carrier
   gateways — many of them serve DHCP and DNS themselves and will not hand out a custom LAN DNS
   server. Set it manually on the machines that matter: on Windows, **Settings >
   Network & internet > Wi-Fi > Hardware properties > DNS server assignment > Edit**.
3. **Run your own filtering resolver** on the LAN. That is what Home SOC's DNS module does: it loads real
   blocklists (`oisd_small`, `hagezi_pro`, `urlhaus`, `threatfox`, `phishing_army`, `openphish` are the
   defaults in `config.example.toml`), answers blocked names locally, and forwards everything else to the
   upstreams in `dns.upstreams`. Set `dns.enabled = true` in `config.toml`, then point devices at this PC's
   IP — either via the router's DHCP settings, or per device where the router will not allow it.

   Two practicalities. The resolver needs the Windows firewall to allow inbound UDP/TCP 53, which needs
   administrator rights once — `scripts/enable-lan-dns.ps1` does it. And the PC now becomes infrastructure:
   if it sleeps, devices pointed at it lose name resolution. Set a second, public DNS server as the
   secondary on those devices, or keep the PC awake.

You can test any single domain against the policy without changing anything:
`python -m homesoc dns-test example.com`.

> **Home SOC checks this automatically:** `NET-DNS-001` (devices are not actually using the filter),
> `NET-DNS-002` (the resolver is not running, with the reason), `NET-DNS-003` (blocklists are stale),
> `NET-DNS-004` (a specific client tried to reach a known-malicious domain — this one is a real
> investigation lead, because it names the device), `NET-DNS-005` (upstream resolvers unreachable),
> `NET-DNS-006` (the resolver is bound to the LAN but the firewall does not allow DNS in).
>
> Changing your **router's** upstream DNS (level 1) is **Manual — Home SOC cannot verify this**; it can only
> see whether devices are sending queries to *its* resolver.

---

## 7. IoT and camera hygiene

Cameras and baby monitors deserve their own section because they are the devices where a compromise is most
personally invasive, and because they are the ones most often reachable from the internet by accident.

NCSC's guidance is direct: default passwords let criminals "access the camera remotely, and view live video
or images in your home".

**The rules, in order of importance:**

1. **Change the default password on every device, immediately, at setup.** NCSC's smart-device advice says
   that if a device comes with a default password, change it. Three random words is a good pattern for
   something you have to type on a phone.
2. **Turn on automatic updates** if the device has them; check manually for firmware twice a year if it does
   not.
3. **Turn off remote access you do not use.** NCSC: if you do not need to view camera footage over the
   internet, disable that feature. Same for any smart device — "if you don't need to access your smart
   device when you're away from your home Wi-Fi, then switch off the 'remote access' functionality."
4. **Never port-forward a camera.** If you want remote viewing, use the vendor's cloud relay with MFA on the
   account, or a VPN back into your house. A camera on a forwarded port will be found and catalogued by
   internet-wide scanners within days.
5. **Turn on 2-step verification on the vendor's app account** if it is offered. The account is usually a
   better target than the device.
6. **Put them on the IoT/guest network** (5.1).
7. **Point them somewhere you are comfortable with.** Not bedrooms, not bathrooms. Think about where an
   indoor camera can see, and whether you would be comfortable if the footage were public — because for a
   badly secured camera, that is the actual risk.
8. **Factory-reset before disposal or resale.** NCSC recommends this explicitly.
9. **Prefer devices from vendors that publish a support end date.** A cheap camera with no update policy is
   a permanent liability, not a bargain.

> **Home SOC checks this automatically, in part:** `NET-SVC-010` (an RTSP camera stream exposed on the LAN),
> `NET-SVC-001` (Telnet open — common on cheap IoT and always wrong), `NET-SVC-002` (FTP open),
> `NET-SVC-005` (an HTTP admin interface with no HTTPS), `NET-SVC-009` (SNMP with a default community
> string), `NET-SVC-012` (a device advertising its hardware model on the network), `NET-DEV-001` and
> `NET-DEV-002` for inventory, and `NET-WAN-001` if a camera has been exposed to the internet.
>
> **Manual — Home SOC cannot verify this:** whether you changed the device's password, whether its firmware
> is current, whether remote access is disabled in its app, and whether the vendor account has 2SV.

---

## 8. Phishing: the habits that matter

No configuration change fixes this one. Phishing is CISA's first core action for individuals and families
for a reason: it is the most common way malware and account compromise arrive, and it targets the person,
not the machine.

**Four habits that do most of the work:**

1. **Never act on urgency in a message.** The entire genre depends on making you move before you think.
   "Your account will be closed", "unusual sign-in", "your parcel is held", "your boss needs gift cards".
   The correct response to urgency is to slow down, not to speed up.
2. **Never follow a link to log in.** If a message says there is a problem with an account, open the app or
   type the address you already know. This single habit defeats nearly all credential phishing, because the
   attack requires you to arrive at *their* page.
3. **Treat attachments as guilty.** Especially anything asking you to "enable content", "enable macros", or
   run an installer to view a document. Scan it, and check where it came from, before opening it.
4. **Check the domain, not the display name.** The visible sender name is free to set. Look at what comes
   after the last dot before the first slash.

**Two structural helps:**

- **Passkeys make phishing much harder.** As Microsoft puts it, a passkey is enforced by the browser or
  operating system to be used only with the appropriate service "rather than relying on human verification".
  You cannot be tricked into giving one to a look-alike domain, because your browser will not offer it.
- **DNS filtering catches the ones you fall for.** If you do click, and the destination is on a phishing
  blocklist, the lookup fails and nothing loads.

**If you think you clicked:** change the password for that account from a *different* device, sign out all
sessions, check for new forwarding rules or recovery addresses on your email account, and run a full
antivirus scan. Do not wait to be sure.

> **Manual — Home SOC cannot verify this.** No tool can check your habits.
>
> It does catch consequences, which is the next best thing: `NET-DNS-004` (a device on your network tried to
> reach a known-malicious or phishing domain — this is often the first sign someone clicked something),
> `AV-FILE-001` (a malicious file in Downloads), `AV-FILE-002` (a suspicious file in Downloads),
> `WIN-DEF-011` (Defender detected a threat), and `WIN-PER-001` / `WIN-PER-002` / `WIN-PER-003` if something
> installed itself to survive a reboot.

---

## 9. Children's devices

The threat model here is different: less "nation-state actor", more accidental spending, age-inappropriate
content, contact from strangers, and a child installing something that turns the household laptop into a
problem.

The FTC's framing is the right one to start from: parental controls help, but "there's really no substitute
for talking with your kid about your family's rules and expectations", and the controls should be adjusted
as the child gets older.

**Do it.**

1. **Give each child their own standard (non-administrator) account** on any shared computer. This is the
   same principle as 4.1 and it solves several problems at once — they cannot install software silently,
   and their mistakes are contained to their profile.
2. **Use the platform's family tools** rather than third-party software. The FTC names the three that
   matter: **Microsoft Family Safety** for Windows and Xbox, **Apple's Family Sharing** for iPhone and iPad,
   and **Google's Family Link** for Chromebooks and Android. They cover screen time, app age limits, purchase
   approval and content filtering.
3. **Turn off in-app purchases** or require a password for every one. This is the most common concrete harm.
4. **Turn on automatic updates and use strong unique passwords on their accounts too** — the FTC advises
   both explicitly. Children's accounts are not lower-value targets; they are the same household.
5. **Put the router-level protections underneath.** DNS filtering (section 6) applies to every device
   including theirs, and it does not depend on the child not uninstalling something.
6. **Cover the camera on the shared laptop** when it is not in use, and talk about why.
7. **Agree the rules out loud.** What to do if a stranger messages them; that they will not be in trouble
   for telling you something went wrong. A child who is afraid of the consequences will hide the incident,
   which is the actual danger.

> **Manual — Home SOC cannot verify this.** Home SOC has no concept of users, ages, or parental controls.
>
> Two indirect helps: `WIN-ACC-001` will tell you if the account they use is an administrator, and
> `NET-DNS-004` will tell you if a device tried to reach a malicious domain, naming which device.

---

## 10. What Home SOC can and cannot see

Being clear about this is more useful than a longer feature list.

**It checks, on its own, without being asked:**

- Windows Defender configuration and health, Windows Firewall state, pending updates and outdated apps,
  account and UAC configuration, legacy protocols, platform security features, screen lock, and new
  autostart entries — 40-odd distinct `WIN-*` checks.
- Every device on the LAN, what ports they have open, what software those ports are running, and whether
  those versions match the CISA KEV catalog, NVD, or a high EPSS score.
- Wi-Fi encryption and WPS.
- Whether anything answers on your public IP.
- Whether devices are reaching known-malicious domains, if the DNS filter is in use.
- Its own health: stale feeds, failing jobs, an unprotected dashboard, checks skipped for lack of rights.

**It cannot see, and does not try to:**

- Anything inside your router's admin page: the admin password, remote administration, firmware version,
  end-of-life status, whether a guest network exists, or whether client isolation is on.
- Any of your accounts: passwords, MFA status, passkeys, breach exposure.
- Backups. Whether they exist, whether they work, whether the drive is disconnected.
- Your habits, your children's devices, or whether an IoT device's own password was changed.
- On Windows 11 Home without administrator rights: BitLocker/device encryption state, Secure Boot, TPM
  status, and the firewall's default inbound action. It reports these as skipped via `SOC-SYS-002` rather
  than passing them.

That division is the point of the tags in this guide. Roughly half the highest-value items here are manual,
and no tool changes that.

---

## 11. The 15-minute monthly routine

Same day each month. Set a recurring reminder. If something takes longer than the slot, write it down and
do it separately — the point of the routine is that it always gets done, not that everything gets fixed
inside it.

| Time | What | Where |
|---|---|---|
| 3 min | **Install updates.** Windows Update, phones, and `winget upgrade --all`. Reboot if asked. | Settings > Windows Update |
| 2 min | **Glance at the router's device list.** Anything you cannot name? | Router admin page |
| 2 min | **Check the router for firmware updates.** Apply and reboot if there is one. | Router admin page |
| 3 min | **Run the backup on the external drive, then unplug it.** Confirm the cloud backup shows a recent date. | External drive |
| 2 min | **Open your password manager's breach report.** Fix anything red, email first. | Password manager |
| 3 min | **Review new findings and act on the critical/high ones.** | Dashboard, or `python -m homesoc status` |

If you are running Home SOC, the last row is where the routine gets shorter over time, because the tool
watches continuously and you only look at what changed:

```
python -m homesoc status                              # score, counts, last scans, feeds, jobs
python -m homesoc findings --status open --severity high
python -m homesoc feed --since 30d --limit 50         # what happened on the network this month
python -m homesoc report --days 30                    # the full written summary, in Markdown
```

Or open the dashboard (`python -m homesoc run`, then `http://127.0.0.1:8787`) and read the **Summary** page,
which lists what was found, what has been fixed, and the remaining work with the remediation steps attached.

**Twice a year, additionally:** check firmware on cameras and IoT devices, re-read the router's port
forwarding list, test restoring one file from backup, and review who has access to your shared cloud
folders.

---

## 12. One-page printable checklist

Print this page. Tick things off. Pin it inside a cupboard door.

```
HOME SECURITY CHECKLIST                                    Date started: ____________

DAY ONE                                                                     Done
  [ ] Windows Update: all updates installed, automatic updates on
  [ ] Phones and tablets: automatic OS and app updates on
  [ ] Defender: real-time protection ON, cloud protection ON, TAMPER PROTECTION ON
  [ ] Windows Firewall: on for all three profiles
  [ ] Router admin password changed from the default, stored in password manager
  [ ] Router remote administration / WAN web access turned OFF
  [ ] Wi-Fi set to WPA3, or WPA2 with AES (never TKIP, never WEP, never open)
  [ ] Wi-Fi passphrase 15+ characters
  [ ] WPS turned OFF
  [ ] Password manager installed; master password written on paper and stored safely
  [ ] Email password changed to a long, unique one
  [ ] MFA turned on: email ____  bank ____  cloud storage ____
  [ ] MFA recovery codes saved in the password manager

WEEK ONE
  [ ] Daily account changed to Standard; separate Administrator account created
  [ ] Built-in Administrator disabled, Guest disabled, auto-logon off, UAC at default
  [ ] Disk encryption ON (Device encryption / BitLocker / FileVault)
  [ ] Encryption recovery key printed or saved outside the machine
  [ ] Screen lock on wake, 5-10 minutes; Windows Hello set up
  [ ] Backup copy 1: cloud, automatic, with version history
  [ ] Backup copy 2: external drive - backed up, then UNPLUGGED
  [ ] One file successfully restored from backup (tested, not assumed)
  [ ] Router firmware updated; automatic firmware update on if available
  [ ] Router model checked for end-of-life
  [ ] UPnP turned OFF; existing port mappings deleted; DMZ empty
  [ ] Every device on the router's device list identified and named
  [ ] Unused devices unplugged and factory-reset
  [ ] Password manager breach report run; flagged passwords changed
  [ ] SMBv1 off; Remote Desktop off (or VPN-only)

ADVANCED
  [ ] IoT and cameras moved to a guest / separate network, client isolation on
  [ ] Defender: controlled folder access, PUA blocking, network protection on
  [ ] Full Defender scan run at least once
  [ ] Secure Boot on, memory integrity on, TPM ready
  [ ] Startup / autostart entries reviewed
  [ ] Public IP checked from outside: nothing should answer
  [ ] DNS filtering in place (router upstream, per device, or own resolver)
  [ ] Cameras: default passwords changed, remote access off unless needed, 2SV on app
  [ ] Children: standard accounts, family safety tools, purchases require approval
  [ ] Household agreed: never log in via a link in a message

MONTHLY (15 minutes, day ___ of each month)
  [ ] Updates installed everywhere, reboot if asked
  [ ] Router device list checked for anything unfamiliar
  [ ] Router firmware checked
  [ ] External backup run, then unplugged; cloud backup date confirmed
  [ ] Password manager breach report checked
  [ ] New critical / high findings reviewed and acted on

TWICE A YEAR
  [ ] IoT and camera firmware checked
  [ ] Port forwarding list re-read
  [ ] Test restore from backup
  [ ] Shared cloud folder access reviewed
```

---

## 13. Sources

Every page below was fetched and read while writing this guide.

**Government and national cyber security agencies**

- CISA, *Home Network Security* — <https://www.cisa.gov/news-events/news/home-network-security>
  (router security: WPA3 with AES, change administrator passwords and default SSID, disable WPS, UPnP and
  remote management, update firmware; plus host firewalls, antivirus, strong passwords, backups, and
  phishing as the most common malware delivery vector)
- CISA, *Secure Our World* — <https://www.cisa.gov/secure-our-world>
  (the four core actions for individuals and families: recognise and report phishing, use strong passwords,
  turn on MFA, update software)
- CISA, *Known Exploited Vulnerabilities Catalog* — <https://www.cisa.gov/known-exploited-vulnerabilities-catalog>
- CISA, *#StopRansomware* — <https://www.cisa.gov/stopransomware/ransomware-101>
- CERT/US-CERT (Ruggiero and Heckathorn, Carnegie Mellon), *Data Backup Options* —
  <https://www.cisa.gov/sites/default/files/publications/data_backup_options.pdf>
  (the 3-2-1 rule: three copies, two media types, one stored offsite)
- CSIAC / DoD, *NSA Releases Best Practices for Securing Your Home Network* —
  <https://csiac.dtic.mil/articles/nsa-releases-best-practices-for-securing-your-home-network/>
  (securing routing devices, wireless network segmentation, confidentiality during telework). The NSA
  Cybersecurity Information Sheet itself is published at
  `https://media.defense.gov/2023/Feb/22/2003165170/-1/-1/0/CSI_BEST_PRACTICES_FOR_SECURING_YOUR_HOME_NETWORK.PDF`
  — that host refused automated retrieval while this guide was written, so the NSA recommendations quoted
  here are taken from the DoD article above and from the NSA press announcement it links to.
- NIST SP 800-63B, *Digital Identity Guidelines: Authentication and Authenticator Management* —
  <https://pages.nist.gov/800-63-4/sp800-63b/authenticators/>
  (no composition rules, no forced periodic changes, blocklists of compromised passwords, password managers
  and paste explicitly allowed, and what "phishing resistance" actually requires)
- NIST SP 800-46 Rev. 2, *Guide to Enterprise Telework, Remote Access, and BYOD Security* —
  <https://csrc.nist.gov/pubs/sp/800/46/r2/final>
  (the NIST publication covering security for devices working from home networks)
- UK NCSC, *Cyber security advice for you and your family* —
  <https://www.ncsc.gov.uk/section/advice-guidance/you-your-family>
- UK NCSC, *Top tips for staying secure online* —
  <https://www.ncsc.gov.uk/collection/top-tips-for-staying-secure-online>
  (strong separate password for email, updates, 2-step verification, password managers, backups, three
  random words)
- UK NCSC, *Backing up your data* —
  <https://www.ncsc.gov.uk/collection/top-tips-for-staying-secure-online/always-back-up-your-most-important-data>
  (disconnect removable backup media when not in use, because malware can move to attached media)
- UK NCSC, *Smart devices: using them safely in your home* —
  <https://www.ncsc.gov.uk/guidance/smart-devices-in-the-home>
  (change default passwords, automatic updates, disable remote access you do not need, turn on 2SV,
  factory-reset before disposal)
- UK NCSC, *Smart security cameras: using them safely in your home* —
  <https://www.ncsc.gov.uk/guidance/smart-security-cameras-using-them-safely-in-your-home>
  (disable remote viewing if unused; disable UPnP and port forwarding on the router)
- US FTC, *How To Use Parental Controls To Keep Your Kid Safer Online* —
  <https://consumer.ftc.gov/articles/how-use-parental-controls-keep-your-kid-safer-online>
  (Microsoft Family Safety, Apple Family Sharing, Google Family Link; no substitute for talking with your
  child)

**Vendor and industry documentation**

- Microsoft, *Windows security documentation* — <https://learn.microsoft.com/en-us/windows/security/>
  (the hardware, operating system, application and identity security features referenced throughout)
- Microsoft, *Windows 11 security book — Operating System security* —
  <https://learn.microsoft.com/en-us/windows/security/book/operating-system-security>
- Microsoft, *Protect security settings with tamper protection* —
  <https://learn.microsoft.com/en-us/defender-endpoint/prevent-changes-to-security-settings-with-tamper-protection>
  (what tamper protection locks down, and that home users manage it in the Windows Security app)
- Microsoft, *Support for passkeys in Windows* —
  <https://learn.microsoft.com/en-us/windows/security/identity-protection/passkeys/>
  (FIDO public-key authentication, Windows Hello, why passkeys resist phishing, native management from
  Windows 11 22H2)
- Wi-Fi Alliance, *Security* — <https://www.wi-fi.org/discover-wi-fi/security>
  (WPA3 is mandatory for Wi-Fi CERTIFIED devices; WPA3-Personal users "receive increased protections from
  password guessing attempts"; Wi-Fi Enhanced Open)
- Wi-Fi Alliance, *Wi-Fi Alliance introduces Wi-Fi CERTIFIED WPA3 security* —
  <https://www.wi-fi.org/news-events/newsroom/wi-fi-alliance-introduces-wi-fi-certified-wpa3-security>
  (SAE, and resilience even when passwords "fall short of typical complexity recommendations")

**Home SOC itself**

- Finding IDs in this guide come from `homesoc/findings/catalog.py`. Configuration keys come from
  `config.example.toml`. Commands were checked against `python -m homesoc --help`.
