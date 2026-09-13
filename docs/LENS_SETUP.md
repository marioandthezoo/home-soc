# Lens — point your phone at a device

Lens is a phone-sized web app that Home SOC serves itself. You point your phone's camera at
something in the house, Lens works out which device on your network it is, and draws everything
Home SOC knows about it over the live camera image: open ports, vulnerabilities, findings with
numbered fix steps, and the domains that device has been talking to.

It is the same data as the Devices page. The point is not new information, it is that you are
standing in front of the thing while you read it.

Lens is **off by default** and stays off until you make three deliberate decisions: let the
dashboard listen on the network instead of only on this PC, serve it over HTTPS, and pair a phone.
This guide walks through all three, and is honest about the part that is genuinely annoying — the
certificate.

> **About the transcripts.** Every command below was run and its output pasted in, against a
> throwaway data directory holding three invented devices. Three cosmetic substitutions were made
> so this document carries nobody's real network: the data directory is shown as `data\…` instead
> of the temporary path it really used, the machine's hostname is shown as `homesoc-pc`, and the
> dashboard token is a placeholder. Addresses, fingerprints, codes and timings are as printed. The
> one section that was *not* run here is [Tailscale](#5b-tailscale--a-genuinely-trusted-certificate),
> and it says so in a box of its own.

**Contents**

1. [What Lens is, and what it is not](#1-what-lens-is-and-what-it-is-not)
2. [What you need](#2-what-you-need)
3. [Turning it on](#3-turning-it-on)
4. [The certificate](#4-the-certificate)
5. [Choosing a transport](#5-choosing-a-transport)
6. [Opening the firewall port](#6-opening-the-firewall-port)
7. [Pairing a phone](#7-pairing-a-phone)
8. [Tag learning — why most devices never need a sticker](#8-tag-learning--why-most-devices-never-need-a-sticker)
9. [Printing the sticker sheet](#9-printing-the-sticker-sheet)
10. [Troubleshooting](#10-troubleshooting)
11. [Security](#11-security)
12. [Reference](#12-reference)

---

## 1. What Lens is, and what it is not

**The target is Chrome on Android.** That is the browser Lens was built and tested for, and the
only one where the whole thing works: camera, automatic scanning, and the card.

Everything else degrades instead of failing. Lens checks for the
[BarcodeDetector API](https://developer.mozilla.org/en-US/docs/Web/API/Barcode_Detection_API) and,
when it is missing, hides the scanning reticle, says so on screen —

> **This browser cannot scan codes.** Automatic scanning needs the BarcodeDetector API, which
> Chrome on Android provides. The camera still shows what you are pointing at, and the picker below
> identifies any device in one tap.

— and promotes **Pick manually** to the primary button. You never get a camera that silently does
nothing. The device list, the cards and every section in them work identically without a camera, so
Lens on a desktop browser is a perfectly good (if pointless) way to read your inventory.

**On iPhone, expect the picker, not the scanner.** Every browser on iOS uses WebKit, which does not
provide BarcodeDetector, so scanning will not start. Getting even that far means accepting a
certificate, which on iOS means installing a configuration profile and then enabling it under
Certificate Trust Settings. None of this has been tested. iOS is an explicit non-goal for this
version, and the guide does not pretend otherwise.

**There is no OCR.** Lens cannot read the model number printed on a label, or recognise what a
device looks like. Vendoring an OCR engine would break the project's no-external-assets rule.
Identification is by machine-readable code only:

- **a barcode the manufacturer already printed** on the device — Code 128, EAN, Data Matrix, QR,
  whatever is on the sticker on the back of the router or under the printer; or
- **a QR sticker Home SOC generated** for you, for things with no readable label; or
- **you tapping the device in a list**, which always works.

The first time Lens sees a code it does not recognise it asks which device it belongs to. You tap
once and it is learned forever. That is section 8, and it is the part that makes the whole idea
practical.

**No world-anchored 3D labels.** The card is a panel anchored to the bottom of the screen, over the
camera image. It does the same job.

---

## 2. What you need

| | |
|---|---|
| **A phone on the same Wi-Fi** | Chrome on Android for the full experience. Lens is LAN-only; nothing is exposed to the internet and nothing is relayed through a cloud. |
| **Home SOC listening on the network** | Not `127.0.0.1`. This is the decision that widens the attack surface from "this PC" to "everyone on the LAN", which is why it is deliberate. |
| **HTTPS** | Not optional, and not Home SOC being fussy: browsers only grant camera access to a [secure context](https://developer.mozilla.org/en-US/docs/Web/Security/Secure_Contexts). `localhost` is exempt, a LAN address is not. |
| **The `cryptography` package** | The one optional dependency in the project, imported lazily — Home SOC starts and runs completely normally without it, and nothing outside Lens notices. Inside Lens, though, everything that touches a certificate needs it: `lens cert`, `--tls`, `lens pair` **and the `/lens/pair` page**, which reads the certificate to show its fingerprint and mints no code when it cannot. Without `cryptography` a phone cannot be paired at all (unless you take the Tailscale route in §5b, which supplies the certificate itself). |
| **Administrator, once** | Only to add the inbound firewall rule. Nothing else about Lens needs elevation. |

Install the optional dependency:

```
python -m pip install cryptography
```

or, if you installed Home SOC as a package, `python -m pip install .[lens]` — the `lens` extra
contains exactly this one library.

---

## 3. Turning it on

Lens has its own config section. These are the real keys and their real defaults:

```toml
[lens]
enabled = false                    # master switch; when false /lens and /api/lens/* return 404
require_https = true               # refuse to serve Lens over plain HTTP (except from localhost)
tag_learning = true                # allow unknown codes to be bound to a device from the phone
allow_actions = false              # when true, a paired phone may trigger a rescan / acknowledge a finding
token_ttl_days = 90                # paired-phone tokens expire after this; 0 = never
max_tokens = 10                    # how many phones may be paired at once
```

You need, at minimum:

```toml
[web]
host = "0.0.0.0"                   # so the phone can reach it at all
port = 8443
token = "<keep the random one init generated>"

[lens]
enabled = true
```

**These keys are not on the Settings page, on purpose.** Every `[lens]` key lives in `config.toml`
and nowhere else, because turning Lens on is a network-exposure decision and not a checkbox you
should be able to hit by accident. Edit the file and restart Home SOC.

`lens.enabled` is read once, when the web app is built. Flipping it in the database does not
disable a server that is already running — and since the only way to change it is the file, a
restart is implied anyway. When Lens *is* switched off, everything disappears rather than merely
refusing: `/lens`, `/lens/claim`, `/lens/pair`, `/lens/stickers`, `/lens-sw.js` and all of
`/api/lens/*` answer **404**, while the rest of the dashboard is untouched.

Leave `[web] token` set — this is not optional advice. With Lens on, the dashboard is reachable
from the whole LAN, and with no token Home SOC authenticates nobody: anyone on the Wi-Fi can open
`/lens/pair`, read the pairing code off the screen and pair their own phone. The whole pairing
model assumes the dashboard token is set. See §11.

---

## 4. The certificate

Home SOC can generate its own. One command:

```
$ python -m homesoc lens cert --regenerate --hosts 192.168.1.105,homesoc.local
2026-09-13 15:39:22 INFO    homesoc.web.tls: generating Lens certificate (forced)
2026-09-13 15:39:22 INFO    homesoc.web.tls: wrote data\tls\cert.pem (2 name(s), 3 address(es), valid 825 days, SHA-256 B2:10:28:B3:1B:C5:AA:9D:7D:2C:8B:5C:48:19:C2:8F:9D:EE:DB:88:34:16:34:6C:86:68:D8:F8:BC:24:BD:25)
wrote data\tls\cert.pem
wrote data\tls\key.pem   (keep this file to yourself)
```

`--hosts` is optional — without it Home SOC covers this machine's hostname, `<hostname>.local` and
its LAN address automatically. To look at what you have:

```
$ python -m homesoc lens cert
certificate: data\tls\cert.pem
  fingerprint (SHA-256): B2:10:28:B3:1B:C5:AA:9D:7D:2C:8B:5C:48:19:C2:8F:9D:EE:DB:88:34:16:34:6C:86:68:D8:F8:BC:24:BD:25
  subject:  O=Home SOC,CN=homesoc.local
  covers:   homesoc.local, localhost, 192.168.1.105, 127.0.0.1, ::1
  valid:    2026-09-13T21:39:22Z .. 2028-12-16T22:39:22Z  (824 days left)
```

Things worth knowing about it:

- **It covers every name the phone might type.** By default: this machine's hostname,
  `<hostname>.local`, its LAN address, plus `localhost`, `127.0.0.1` and `::1`. `--hosts a,b`
  replaces that list, and is only meaningful together with `--regenerate` (on its own it prints
  *"--hosts only applies together with --regenerate"* and shows you the current certificate).
- **It regenerates itself when it stops fitting.** Starting with `--tls` checks that the existing
  certificate still covers the current address and is not near expiry; if not, it is replaced and
  the new fingerprint is logged. That is exactly what happens next in this walkthrough, because the
  `--hosts` list above deliberately left the machine's own name out:

  ```
  INFO homesoc.web.tls: generating Lens certificate (does not cover homesoc-pc, homesoc-pc.local)
  ```

  Move Home SOC to a new address and the certificate follows it. The corollary: **do not put a
  certificate from somewhere else into `data/tls/`** and expect it to survive — if it does not
  cover all of those names, the next `--tls` start replaces it with a fresh self-signed one.
- **It expires in 825 days** and is renewed automatically inside the last 30 (`tls.RENEW_WITHIN_DAYS`). The pairing page starts *warning* about the expiry earlier than that, at 14 days.
- **The key is `data/tls/key.pem`.** On Linux and macOS it is written `0600`. On Windows it simply
  inherits the ACL of the `data` directory — that is a real difference, not a chmod that quietly
  did nothing, so keep the data directory off shared drives.
- **Without `cryptography` installed**, nothing here works and the error says so, naming both the
  `pip install` and this document.

Then start Home SOC over HTTPS:

```
$ python -m homesoc serve --tls --host 0.0.0.0 --port 8443
2026-09-13 15:39:53 INFO    homesoc.scheduler: scheduler started with 15 jobs
2026-09-13 15:39:53 INFO    homesoc.web.tls: generating Lens certificate (does not cover homesoc-pc, homesoc-pc.local)
2026-09-13 15:39:53 INFO    homesoc.web.tls: wrote data\tls\cert.pem (3 name(s), 3 address(es), valid 825 days, SHA-256 5B:D3:C6:0C:...)
2026-09-13 15:39:53 INFO    homesoc.cli: HTTPS enabled with data\tls\cert.pem (SHA-256 5B:D3:C6:0C:...)
Certificate: data\tls\cert.pem
  SHA-256 fingerprint: 5B:D3:C6:0C:D5:43:04:4B:4A:55:9C:21:82:87:E1:0B:2B:07:1A:36:3A:3F:91:1E:E7:58:3E:B2:DC:12:85:22
  Self-signed: the phone warns once, then remembers. Check the fingerprint matches.
Dashboard: https://192.168.1.105:8443/login?token=<your-token>  (Ctrl-C to stop)
```

`--tls` works on `run` too — `python -m homesoc run --tls` — which is the normal mode (dashboard +
scheduler + resolver) and what you actually want day to day. `serve --tls` is the dashboard alone.

**Write that fingerprint down.** It is the only thing that tells a genuine certificate warning from
a machine-in-the-middle, and you are about to be asked to click through one.

---

## 5. Choosing a transport

There are two ways to give the phone an HTTPS connection it will accept. They trade convenience
against how much you have to trust your own judgement.

### 5a. Self-signed on your own LAN

This is the path Home SOC supports out of the box, and the one everything in section 4 set up.

On the phone, the first visit to `https://192.168.1.105:8443/lens` brings up Chrome's interstitial —
roughly:

> **Your connection is not private**
> Attackers might be trying to steal your information from 192.168.1.105 …
> `NET::ERR_CERT_AUTHORITY_INVALID`

1. Tap **Advanced**.
2. Tap **Proceed to 192.168.1.105 (unsafe)**.

**Read this before you tap.** That warning is not noise. It means the browser cannot tell whether
the thing answering on that address is your PC or something else that got there first. The only way
to actually know is to compare fingerprints: the pairing page shows the certificate's SHA-256 in
groups of four bytes, and Chrome will show you the certificate it actually received — tap the
warning icon next to the address, then the certificate entry, and read the SHA-256 at the bottom.
**If the two do not match exactly, stop.** Something else is answering, and
proceeding hands it your pairing code. If they match, you are making an informed decision about a
certificate you generated on a machine you own, on a network you control — which is a completely
reasonable thing to do, and quite different from clicking through the same warning on a public
Wi-Fi.

Chrome remembers the decision for that address, but not forever: a browser restart, a regenerated
certificate or a different address will all ask again.

**What clicking through costs you.** Verified in Chrome, not assumed:

- ✅ **The camera still works.** After proceeding, `window.isSecureContext` is `true` and
  `getUserMedia` returns a live stream. Lens is fully functional.
- ❌ **The service worker will not install.** Chrome refuses to register a service worker on an
  origin with an untrusted certificate (`An unknown error occurred when fetching the script.`), so
  the offline shell and "add to home screen" behaviour do not happen. Lens still works — it just
  reloads from the network every time and shows nothing when Home SOC is stopped. On a trusted
  certificate the same page registers its worker immediately.

**What does *not* work, so you do not waste an evening on it:** installing the Home SOC certificate
into Android's user CA store (*Settings → Security → More security settings → Encryption &
credentials → Install a certificate → CA certificate*). That importer wants a certificate
authority. Home SOC's certificate is an end-entity server certificate — you can check for yourself:

```
$ python -c "from cryptography import x509; c=x509.load_pem_x509_certificate(open('data/tls/cert.pem','rb').read()); print(c.extensions.get_extension_for_class(x509.BasicConstraints).value)"
<BasicConstraints(ca=False, path_length=None)>
```

`ca=False`. There is no CA here to trust. Home SOC does not run a private certificate authority,
and installing one on a phone is a much bigger trust decision than clicking through a single
warning — a user CA can vouch for *any* site, not just this one. If you want a certificate the
phone accepts without any warning at all, use the next option instead.

### 5b. Tailscale — a genuinely trusted certificate

[Tailscale](https://tailscale.com/kb/1312/serve) issues real, publicly trusted certificates for the
machines on your tailnet, so a phone that is also on the tailnet sees no warning at all, the
service worker installs, and Lens behaves like any normal website. That is the friction-free
version of this whole section.

> **Not tested here.** Everything else in this guide was run and its output pasted in. Tailscale is
> not installed on the machine Home SOC was built on, so the commands below come from Tailscale's
> own documentation rather than from a terminal here — and there are two things inside Home SOC
> that will get in the way. Both are listed below with their exact symptoms, because you will hit
> them before you hit anything Tailscale-specific.

The shape is `tailscale serve` in front of the dashboard, terminating TLS with the tailnet
certificate and proxying to Home SOC — see [Tailscale Serve](https://tailscale.com/kb/1312/serve)
for the current command syntax.

**Obstacle 1: the Host header allowlist.** Home SOC answers only to `Host` values it recognises —
loopback, its bind address, this machine's LAN address and hostname — because that allowlist is
what stops a DNS-rebinding page in your browser from talking to the dashboard. Anything else gets:

```
HTTP 400  {"ok": false, "error": "bad host header"}
```

A reverse proxy that forwards the original `Host` (the tailnet name) lands exactly there. The only
lever is `[web] host`, which is also what seeds the allowlist — and it accepts a name, not just an
address:

```toml
[web]
host = "your-pc.your-tailnet.ts.net"
```

Home SOC binds the address that name resolves to and adds the name to the allowlist. (Binding by
name is verified; that it is *enough* for Tailscale Serve is not.)

**Obstacle 2: the plain-HTTP refusal.** With TLS terminated by the proxy, Home SOC sees a plain
HTTP request and refuses to serve Lens to anything but a loopback peer (section 11). If the proxy
reaches Home SOC over loopback you are fine. If it reaches it over the tailnet address, you get:

```
HTTP 403  {"ok": false, "code": "https_required", ...}
```

and you would have to set `[lens] require_https = false` — which also flips the pairing page's QR to
an `http://` URL, so pair from the terminal instead:

```
python -m homesoc lens pair --host your-pc.your-tailnet.ts.net --port 443
```

which always builds an `https://` link from the arguments you give it. Note that `lens pair` insists
on a certificate existing even when it is not the one being served, so run
`python -m homesoc lens cert --regenerate` once to create a throwaway self-signed one.

If you get Tailscale working with Lens, that is worth an issue describing the configuration; a
`web.extra_hosts` key would make this a one-liner instead of a puzzle.

---

## 6. Opening the firewall port

On Windows the phone cannot reach port 8443 until you allow it. From an **elevated** PowerShell:

```
powershell -ExecutionPolicy Bypass -File scripts\enable-lens.ps1 -Port 8443
```

It adds one inbound TCP rule named "Home SOC Lens", **limited to the Private network profile** on
purpose: on a café or airport network Windows uses the Public profile and Lens becomes unreachable
without you doing anything. It then prints your LAN address and the remaining steps, and warns you
if the active profile is not Private (*Settings → Network → Wi-Fi → your network → Private*).

The script is idempotent — it removes any previous rule of that name before creating the new one,
so changing the port does not leave the old one open. To undo it:

```
powershell -ExecutionPolicy Bypass -File scripts\enable-lens.ps1 -Port 8443 -Remove
```

On Linux, allow the port however your distribution does it (`ufw allow 8443/tcp`, a firewalld rule,
or nothing at all if you have no host firewall).

---

## 7. Pairing a phone

Lens does **not** use the dashboard token. A paired phone gets its own token, scoped to what Lens
displays and revocable on its own, so handing a phone to a houseguest never means handing over the
dashboard password.

### From the dashboard (the usual way)

On the computer, open **`/lens/pair`** — for example `https://192.168.1.105:8443/lens/pair`. It is
a normal dashboard page behind the normal dashboard login, and it refuses to hand out a pairing
code until pairing can actually succeed. Each check is either OK or tells you exactly what to fix:

```
OK    Reachable from your phone      Listening on 0.0.0.0; phones should use 192.168.1.105.
OK    HTTPS certificate              Self-signed certificate in place, fingerprint below. Expires in 824 days.
OK    Served over HTTPS              This page arrived over HTTPS, so the phone camera will be allowed to start.
OK    Paired phones                  0 of 10 slots in use.
```

A failing check looks like this, and the fix is on the page rather than in a log:

```
Fix   Reachable from your phone      Home SOC is bound to 127.0.0.1, which only this computer can reach.
                                     • Set [web] host = "0.0.0.0" in config.toml (or Settings → web.host).
                                     • Restart Home SOC so the new binding takes effect (or start it once with:
                                       python -m homesoc serve --tls --host 0.0.0.0 --port 8443).
                                     • Run scripts/enable-lens.ps1 as administrator to open the port on the
                                       Private firewall profile.
```

When everything passes, the page shows a QR code, the link underneath it, and the certificate
fingerprint in readable groups:

```
https://192.168.1.105:8443/lens/claim#c=TS5HSZUX

Certificate fingerprint (SHA-256)
5B:D3:C6:0C : D5:43:04:4B : 4A:55:9C:21 : 82:87:E1:0B : 2B:07:1A:36 : 3A:3F:91:1E : E7:58:3E:B2 : DC:12:85:22

Compare this with the fingerprint the phone shows when it warns about the certificate.
They must match exactly. If they do not, stop: something else answered on that address.
```

Scan the square with the phone's ordinary camera app. Accept the certificate warning (section 5a,
and compare that fingerprint — the page tells you to choose *Advanced → Proceed*), and the claim
page exchanges the code for a token, stores it, and drops you into the viewfinder.

The pairing code is **8 characters, single-use, and valid for five minutes**. It travels in the URL
*fragment* (`#c=`), which browsers never send to a server, and the claim page strips it out of the
address bar the moment it has read it, so it does not linger in history or in a screenshot.
Reloading `/lens/pair` mints a fresh one.

### From the terminal

Same thing without a browser on the computer:

```
$ python -m homesoc lens pair --host 192.168.1.105 --port 8443
Pairing code: TMCGYKN9   (single use, valid 5 minutes)
Open on the phone: https://192.168.1.105:8443/lens/claim#c=TMCGYKN9

    ##############  ##    ######    ####  ##    ######  ##############
    ##          ##  ####  ##  ##    ##  ##        ####  ##          ##
    ##  ######  ##        ##          ##  ####          ##  ######  ##
    ...

Certificate SHA-256: 0F:3C:C3:8A:7D:BF:AA:B3:6E:2C:D1:A6:DE:35:B5:24:80:DC:EB:4B:BA:68:9F:35:4F:99:F1:BE:95:9F:CB:7E
The phone will warn that the certificate is not trusted. That is expected for a
self-signed certificate: check the fingerprint above matches the one the browser
shows, then continue. docs/LENS_SETUP.md also covers the Tailscale route, which
needs no warning at all.

The paired phone will be read-only (lens.allow_actions is false).

Serve it with: python -m homesoc run --tls   (listening on 192.168.1.105:8443)
```

The QR is drawn in the terminal itself. If your terminal has a dark background and the code will
not scan, add `--invert`. `--host` and `--port` default to wherever Home SOC last bound, which is
usually what you want; give them explicitly when the link should use a different name.

Like the page, it refuses early rather than handing you something useless:

```
$ python -m homesoc lens pair
Lens is switched off, so a pairing code would not work.
  Turn it on:  set [lens] enabled = true in C:\Users\you\Home_SOC\config.toml
               (or use the Settings page), then run this again.
```

(Ignore the Settings-page half of that hint: `[lens]` keys are deliberately not editable there.
Edit `config.toml` and restart.)

### Managing paired phones

```
$ python -m homesoc lens tokens
  id label                scopes     state     created      last seen    last ip
   1 Pixel in the hallway read       revoked   17 min ago   17 min ago   127.0.0.1
   2 Pixel in the hallway read       revoked   just now     never        -
   3 Pixel in the hallway read       active    just now     just now     127.0.0.1
   4 Ellie's phone        read       active    just now     just now     127.0.0.1

2 active of a maximum of 10 (lens.max_tokens)

$ python -m homesoc lens revoke 3
token 3 revoked

$ python -m homesoc lens revoke --all
revoked 1 token(s); every paired phone must pair again
```

Revoked and expired phones stay in the list with their state, so you can see what was paired and
when it last called in. (`last ip` reads `127.0.0.1` above because these test pairings were made on
the machine itself; a real phone shows its own LAN address, which is a quick way to spot a token
being used from somewhere you did not expect.)

Tokens expire after `lens.token_ttl_days` (90 by default; `0` means never) and there are at most
`lens.max_tokens` of them. When the slots are full, the pairing page fails its "Paired phones"
check and points at these commands. `revoke --all` also clears any outstanding pairing code.

---

## 8. Tag learning — why most devices never need a sticker

A *tag* is any code the camera can decode, mapped to one device. Lens does not care where the code
came from, which is the whole trick: **the barcode already printed on the device is good enough.**

Point the phone at the label on the back of the router. Lens decodes it, finds no match, and shows
a full-screen sheet:

- the decoded value, as plain text, so you can see what it actually read;
- **"Which device is this?"** with a ranked list — devices seen in the last ten minutes first, then
  devices with open findings, then untrusted or recently-new ones, then everything else
  alphabetically. Each row explains itself: *"camera, online, not marked trusted, first seen this
  week"*. The device you are standing in front of is almost always in the first three;
- a search box, for when it is not;
- **"Not a device — ignore this code"**, which records the code so Lens stops asking about the
  barcode on the back of the sofa.

Tap the device. That is it. Every future scan of that code resolves instantly and goes straight to
the card. A device can have several tags (the factory barcode *and* a printed sticker); each tag
belongs to exactly one device.

Set `[lens] tag_learning = false` to turn this off — unknown codes will then simply report
"unknown" with the picker, and the learn endpoint refuses with a message naming the key.

**Print stickers only for what is left**: the smart plug behind the sofa, the camera on the
bracket, anything whose label you cannot physically reach.

---

## 9. Printing the sticker sheet

Open **`/lens/stickers`** on the computer (dashboard login, same as the pairing page). Three
options along the top:

| Option | Choices | Default |
|---|---|---|
| **Label size** | Avery 5160 (2.625 × 1 in, 3 × 10 to a Letter page) or 40 mm square (4 × 6 to an A4 page) | Avery 5160 |
| **Devices** | Only devices that still need a sticker, or all devices | Only those that need one |
| **Nickname** | Print the nickname under each code, or not | On |

Press **Print…**. The print stylesheet sets exact millimetre geometry, drops the site chrome, and
avoids breaking a label across pages. Each label carries the QR, the nickname (if you asked for
it) and a small Home SOC mark.

Two things that matter in practice:

- **Minting is idempotent.** A device keeps the same code forever, so reprinting a sheet never
  invalidates a sticker already stuck to something. Print a fresh sheet whenever you like.
- **The codes are minted when the sheet is generated.** That means the default view ("only devices
  that still need a sticker") is empty the *second* time you open it — every device now has a code.
  The page says so and points at "All devices", which reprints exactly the same codes:

  > Nothing to print. Every device already has a code the camera can read — switch to All devices
  > to reprint.

A generated code looks like `hs1:RF2oh3-4dmj3hV-8Ig98QQ` — a prefix and 22 random URL-safe
characters. See section 11 for what that does and does not reveal.

---

## 10. Troubleshooting

### The camera does not start

Lens names the reason on screen rather than showing a dead rectangle.

- **"Camera permission was declined"** — you (or a previous visit) said no. Tap the padlock or ⓘ
  next to the address, set Camera to Allow, reload. Lens offers **Pick a device instead** in the
  meantime.
- **"No camera on this device"** — expected on a desktop browser. The device list is one tap away
  and shows the same information.
- **"The camera could not be started"** — another app is holding it. Close the camera app and tap
  **Try again**.
- **No app at all, just a page headed "Lens needs HTTPS"** — you reached it over plain HTTP. See
  [Lens answers 403 "needs HTTPS"](#lens-answers-403-needs-https) below.
- **The chip says `scanning unsupported`** — the camera works, but this browser has no
  BarcodeDetector (section 1). Use **Pick manually**; it is already the primary button.

### The certificate is refused

- **Chrome shows the warning every single visit.** The certificate does not cover the address you
  typed. `python -m homesoc lens cert` prints what it covers; regenerate with the address you
  actually use: `python -m homesoc lens cert --regenerate --hosts 192.168.1.105`. The pairing page
  raises the same thing as a warning: *"The certificate does not list 192.168.1.105; the phone will
  warn every visit."*
- **The fingerprints do not match.** Stop. Do not proceed. Something other than your PC is
  answering on that address. Check you typed the right address, and that nothing else is listening
  on that port.
- **`lens cert` fails entirely.** `cryptography` is not installed. The error prints both the
  `pip install` line and this document. Home SOC itself keeps working; only TLS is affected.
- **The phone says the certificate has expired.** Certificates are renewed automatically inside the
  last 30 days of their 825-day life, but only when Home SOC starts with `--tls`. Force it:
  `python -m homesoc lens cert --regenerate`, then restart.

### The phone cannot reach the host at all

Work down this list; each step rules out the one above it.

1. **Is Home SOC listening on the network?** `[web] host` must be `0.0.0.0`, not `127.0.0.1`. The
   startup line tells you: `Dashboard: https://192.168.1.105:8443/`. If it says `127.0.0.1`, the
   phone can never reach it.
2. **Is the firewall open?** Run `scripts\enable-lens.ps1 -Port 8443` elevated (section 6), and
   check the network profile is Private.
3. **Is the phone on the same network?** Guest Wi-Fi networks are usually isolated from the main
   one by design, and many routers have "AP isolation" or "client isolation" switched on, which
   blocks phone-to-PC traffic even on the same SSID.
4. **Is the address right?** Use the one the startup line printed, not the one you remember. A DHCP
   lease can move the PC to a new address, after which the certificate no longer matches either —
   consider a DHCP reservation for the machine running Home SOC.
5. **Did the PC go to sleep?** Home SOC only answers while the process is running.

### Lens answers 403 "needs HTTPS"

You reached Lens over plain HTTP from somewhere other than the machine it runs on. Home SOC refuses
that: the phone's token would cross the Wi-Fi in clear text, and the camera would not start anyway.
The phone sees a dark page headed **"Lens needs HTTPS"** with the fix on it, the API answers
`{"ok": false, "code": "https_required", ...}`.

Restart with `--tls` (section 4). `[lens] require_https = false` lifts the refusal, but the camera
still will not start — it buys you nothing except the device list.

Note that `/lens/pair` and `/lens/stickers` are deliberately *not* refused over HTTP: the pairing
page is where the explanation lives, and hiding it behind the problem it explains would be silly.

### Lens answers 404 everywhere

`[lens] enabled` is false — either you have not set it, or you set it and did not restart. The
dashboard itself keeps working normally; only the Lens routes vanish.

### Scanning does nothing

- **The chip in the corner says `scanning unsupported`**: this browser has no BarcodeDetector.
  Not fixable from here — use Chrome on Android, or the picker.
- **The reticle is there but nothing happens**: Lens decodes about five frames a second from a
  downscaled image, and needs the code reasonably square-on, filling a decent part of the frame, in
  enough light. Utility cupboards are dark; use the phone's torch. Glossy or curved labels defeat
  it — that is what stickers are for.
- **It decoded something, but the card did not open**: if you previously answered "Not a device"
  for that code, Lens stays quiet about it on purpose.
- **The chip says `not paired`**: the token expired, or was revoked (section 7). Pair again.

### The wrong device was matched

You tapped the wrong row when the code was learned. The phone deliberately has no "forget this"
button, and the endpoint behind one refuses a read-only phone with the same `actions_disabled`
403 the three actions get — unlearning is a destructive inventory change, and deleting a sticker
tag would make the next printed sheet disagree with the label already on the device. So it is
fixed from the computer, in two steps.

Find the code (read-only, safe while Home SOC is running):

```
$ python -c "import sqlite3; db=sqlite3.connect('file:data/homesoc.db?mode=ro', uri=True); [print(f'{k:8} {c}  ->  {n}') for c,k,n in db.execute('SELECT t.code, t.kind, d.nickname FROM lens_tags t LEFT JOIN devices d ON d.id=t.device_id ORDER BY t.id')]"
sticker  hs1:RF2oh3-4dmj3hV-8Ig98QQ  ->  Home router
sticker  hs1:mwzPoGwBdE4Ml9zuser3VQ  ->  Hallway camera
learned  0123456789012  ->  Study printer
```

Then unlearn it, using the dashboard token:

```
$ curl -k -X DELETE -H "X-Token: <your web.token>" -H "X-Requested-With: fetch" \
       https://192.168.1.105:8443/api/lens/tag/0123456789012
{"forgotten":true,"ok":true}
```

The next scan of that code asks again. (Both headers are required: the token authenticates you, and
`X-Requested-With: fetch` is the CSRF check every mutating dashboard call needs. A sticker code
deleted this way is re-minted with a *new* value the next time you generate a sheet, so the printed
label becomes dead — unlearn learned barcodes freely, but reprint after unlearning a sticker.)

### How to revoke a phone

```
$ python -m homesoc lens tokens          # find the id
$ python -m homesoc lens revoke 3        # one phone
$ python -m homesoc lens revoke --all    # every phone, and any outstanding pairing code
```

Revocation is immediate — the next request from that phone gets:

```
HTTP 401  {"ok": false, "code": "unpaired",
           "error": "This phone is not paired, or its access was revoked. Open the dashboard and pair it again."}
```

Lost or stolen phone: `revoke --all`, then re-pair the phones you still have. There is nothing to
change on the other phones' side beyond that, and the dashboard token is untouched.

---

## 11. Security

Lens widens Home SOC's reach from loopback to your LAN, so it is worth being precise about what it
actually grants.

### What a paired phone can do

- Read everything Lens displays about **your own devices**: identity, open ports and their
  plain-English gloss, matched CVEs, findings with their fix steps, the DNS domains that device has
  talked to in the window, and its recent timeline.
- Identify a code, and — while `lens.tag_learning` is true — bind an unknown code to a device or
  mark it "not a device".

That is genuinely a lot. Anyone holding a paired phone can enumerate your whole network. Treat a
pairing the way you would treat handing someone the dashboard password, and revoke phones you no
longer use.

### What a paired phone cannot do

- **Change anything, by default.** `lens.allow_actions` is `false`, so the `act` scope is never
  granted and the three actions (rescan a device, acknowledge a finding, set trusted) are refused:

  ```
  HTTP 403  {"ok": false, "code": "actions_disabled",
             "error": "Lens is read-only. Set lens.allow_actions = true in config.toml to allow actions."}
  ```

  Turn it on only if you want it; the footer of the card says which state you are in.
- **Reach the dashboard.** The Lens token is not the dashboard token and is not accepted anywhere
  else. The reverse holds in one direction only: **anything holding the dashboard token** can use
  the Lens API — from any host, not just this one, which is what makes `/lens/pair` and the
  `curl -k` unlearn call in §10 work. (With no `[web] token` set there is no dashboard credential
  at all, and the only requests treated as the owner's are the ones from this machine.)
- **Survive revocation, expiry, or `lens.enabled = false`.**

### How the token is handled

- 32 bytes from `secrets.token_urlsafe`, shown **once**, at pairing, and never again.
- Only its SHA-256 is stored, and comparisons use `secrets.compare_digest`.
- It travels in the `X-Lens-Token` header, never in a URL — so it cannot leak through browser
  history, a referrer, or the server's access log. For the same reason **identification is a POST**:
  no device id, name or code ever appears in a query string.
- It lives in the phone's `localStorage` under `homesoc.lens.token`. Clearing the site data
  unpairs that phone (the server-side token stays until you revoke it — do that too if the phone is
  gone).
- Pairing is rate-limited to **ten attempts an hour per source address**; the eleventh gets
  `HTTP 429` and an `events` row you will see on the Activity feed.
- Every Lens API response carries `Cache-Control: no-store`, and the page CSP stays
  `default-src 'self'` — no CDN, no external asset, no inline script.

### What the sticker QR encodes

An opaque random token and nothing else: `hs1:` followed by 22 URL-safe characters, generated
locally, meaningless outside your own database. **It does not contain** a MAC address, an IP
address, a hostname, a device name, your SSID, or a URL. A visitor who photographs a sticker — or
a stranger who sees one in the background of a photo you post — learns nothing about your network.

The only thing a sticker can reveal is what *you* chose to print next to it: the human-readable
nickname, which is optional ("Print the nickname under each code").

Learned tags are the manufacturer's own barcode, which was already printed on the device before
Home SOC existed.

### Home SOC tells you when this is set up badly

Two findings cover this, and they are about different things.

Finding **SOC-LENS-001** (medium) fires when Lens is enabled and reachable off this machine without
TLS: *"Lens is reachable on the LAN over plain HTTP."* Its remediation steps are the same ones as
section 4. What it costs you depends on `lens.require_https`: while that is `true` (the default)
Lens refuses to serve any plain-HTTP request from anything but this PC, so nothing crosses the
network — Lens is simply unusable from the phone until you start with `--tls`. Turn `require_https`
off and the refusal lifts, and then the phone's token and everything Lens shows really do cross the
Wi-Fi in the clear. The finding says both, because a finding that overstated the default case would
contradict its own last fix step ("leave `lens.require_https = true`"). Note that pairing is
refused over plain HTTP either way: `require_https = false` will serve a phone that is already
paired, but Home SOC will not mint a pairing code into a cleartext URL.

Finding **SOC-SYS-003** (high) fires when the dashboard is reachable from the LAN with no
`web.token`. That is the more severe of the two and the one to fix first: without the token,
`/lens/pair` is open to everyone on the Wi-Fi, so anyone can read a pairing code and pair
themselves. Lens's own token model cannot help — it is downstream of that page.

### Turning it all off

In order of increasing thoroughness:

```
python -m homesoc lens revoke --all     # every phone must pair again
```

```toml
[lens]
enabled = false                         # /lens and /api/lens/* return 404 after a restart
```

```toml
[web]
host = "127.0.0.1"                      # back to loopback-only; nothing on the LAN can reach anything
```

```
powershell -ExecutionPolicy Bypass -File scripts\enable-lens.ps1 -Port 8443 -Remove
```

Setting `lens.enabled` to false also invalidates any outstanding pairing code immediately, so a QR
left on a screen cannot be used afterwards. Deleting `data/tls/` removes the certificate and key;
it will be regenerated the next time you start with `--tls`.

---

## 12. Reference

### Config keys

| Key | Default | What it does |
|---|---|---|
| `lens.enabled` | `false` | Master switch. False ⇒ every Lens route answers 404. Read at startup; restart after changing it. |
| `lens.require_https` | `true` | Refuse to serve Lens over plain HTTP to anything but a loopback peer. |
| `lens.tag_learning` | `true` | Let a paired phone bind an unknown code to a device. |
| `lens.allow_actions` | `false` | Grant the `act` scope: rescan, acknowledge, set trusted. |
| `lens.token_ttl_days` | `90` | Paired-phone token lifetime. `0` = never expires. |
| `lens.max_tokens` | `10` | How many phones may be paired at once. |

None of these appear on the Settings page: they live in `config.toml`.

### Commands

| Command | What it does |
|---|---|
| `python -m homesoc serve --tls [--host H] [--port P]` | Dashboard over HTTPS, generating the certificate if needed. |
| `python -m homesoc run --tls` | Normal mode (dashboard + scheduler + resolver) over HTTPS. |
| `python -m homesoc lens pair [--host H] [--port P] [--invert]` | Print the pairing URL, an ASCII QR and the certificate fingerprint. |
| `python -m homesoc lens tokens` | List paired phones: label, scopes, state, created, last seen, last IP. |
| `python -m homesoc lens revoke <id>` / `--all` | Revoke one phone, or all of them. |
| `python -m homesoc lens cert [--regenerate] [--hosts a,b]` | Show or regenerate the certificate. |
| `scripts\enable-lens.ps1 -Port 8443 [-Remove]` | Add or remove the inbound firewall rule (needs administrator). |

### Pages

| Path | Auth | What it is |
|---|---|---|
| `/lens` | none (shell only) | The phone app: viewfinder, card, Devices tab. The page itself is a shell with no device data in it and is served to any LAN client; every call it then makes needs a Lens token. |
| `/lens/claim` | pairing code | Where the QR lands; exchanges the code for a token. |
| `/lens/pair` | dashboard | Preflight, QR and fingerprint. A desktop page — and the one Lens route that is still served over plain HTTP, because it is where the HTTPS problem is explained. |
| `/lens/stickers` | dashboard | The printable sheet. Also exempt from the HTTPS refusal. |

### Files

```
data/tls/cert.pem      the certificate  (fingerprint printed at startup)
data/tls/key.pem       its private key  (0600 on Linux/macOS; inherits the data ACL on Windows)
data/homesoc.db        lens_tokens (hashes only) and lens_tags (code → device)
```

### Related documents

- [README.md](../README.md#lens--point-your-phone-at-a-device) — the short version.
- [docs/WALKTHROUGH.md](WALKTHROUGH.md) — the full tour of Home SOC, with Lens in context.
- [docs/SPEC_LENS.md](SPEC_LENS.md) — the build contract this feature was written against.
- [SECURITY.md](../SECURITY.md) — the project's overall security posture and how to report an issue.
