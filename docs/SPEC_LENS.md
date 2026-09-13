# Home SOC — Spec Addendum B: Lens (point-your-phone-at-a-device viewer)

Normative extension of `docs/SPEC.md`. All existing rules still apply: **no external assets or CDNs**, CSP
`default-src 'self'`, escape everything, dependencies limited to `flask` + `requests` + `dnslib` + stdlib,
no telemetry, works offline.

## B1. What it is

**Lens** is a phone-sized web app served by Home SOC itself at `/lens`. You point your phone's camera at a device in
your home; Lens identifies which device on the network it is and renders everything Home SOC knows about it over the
live camera image — identity, open ports, vulnerabilities, findings with fix steps, and what that device has been
talking to on the internet.

Target: **Chrome on Android**. It must degrade to a usable (non-camera) device browser on anything else, including
desktop, rather than showing an error.

Explicit non-goals for v1: no OCR (vendoring an OCR engine violates the no-external-assets rule), no world-anchored
3D labels (a screen-anchored panel over the camera feed delivers the same value), no iOS-specific work.

## B2. The hard problem: which physical object is this?

Lens uses one mechanism — **visual tags** — fed by two sources, plus a manual fallback.

A *tag* is any machine-readable code the phone's camera can decode: a barcode already printed on the device's factory
label (Code 128, EAN, Data Matrix, QR — whatever the manufacturer used), or a QR sticker Home SOC generated. Both are
stored the same way.

**Tag learning.** When Lens decodes a code it does not recognise, it does not fail. It shows "New code — which device
is this?" with the device list, ranked as described in B6. The user taps once; the mapping is saved; every future scan
of that code resolves instantly. This means most devices need no sticker at all — the barcode already on the back of
the router or the bottom of the printer becomes its identifier.

**Printed stickers** cover devices with no readable label (smart plugs, cameras, anything already installed somewhere
awkward). Home SOC generates a printable sheet from the inventory.

**Privacy rule, non-negotiable:** a generated sticker QR encodes an **opaque random token**, never a MAC address, IP,
hostname or device name. A photograph of a sticker — or a visitor reading it — must reveal nothing about the network.
The sticker's human-readable caption may show the device nickname, because the owner chooses to print that.

**Manual pick** is always available from a persistent button, and always works.

## B3. Transport: HTTPS is required

Browsers grant `getUserMedia` only in a secure context. `localhost` is exempt; a LAN address is not. Lens therefore
requires HTTPS, which is new to this project.

`homesoc/web/tls.py`:
```python
def cert_paths() -> tuple[Path, Path]                 # data_dir()/"tls"/{cert.pem,key.pem}
def ensure_cert(hosts: list[str], *, days: int = 825, force: bool = False) -> tuple[Path, Path]
    """Generate a self-signed cert with subjectAltName covering every host/IP given.
    Uses the `cryptography` package when importable; otherwise raises TlsUnavailable with a message
    telling the user to `pip install cryptography` or run behind Tailscale (see docs)."""
def cert_fingerprint_sha256(cert: Path) -> str        # colon-separated uppercase hex, for the pairing screen
def cert_info(cert: Path) -> dict                     # {subject, sans, not_before, not_after, fingerprint, days_left}
class TlsUnavailable(RuntimeError): ...
```
`cryptography` is already an indirect dependency of nothing in this project, so add it to `requirements.txt` as an
**optional** extra: `pyproject.toml` gains `[project.optional-dependencies] lens = ["cryptography>=42"]`. Home SOC must
start and run normally without it; only `lens` features that need a cert fail, with a clear message.

New config section:
```toml
[lens]
enabled = false                # master switch; when false /lens and /api/lens/* return 404
require_https = true           # refuse to serve Lens over plain HTTP (except from localhost)
tag_learning = true            # allow unknown codes to be bound to a device from the phone
allow_actions = false          # when true, a paired phone may trigger a rescan / acknowledge a finding
token_ttl_days = 90            # paired-phone tokens expire after this; 0 = never
max_tokens = 10                # how many phones may be paired at once
```

New CLI + serve flags:
```
python -m homesoc serve --tls [--host 0.0.0.0] [--port 8443]
python -m homesoc run --tls
python -m homesoc lens pair            # prints the pairing URL and renders the QR as ASCII in the terminal
python -m homesoc lens tokens          # list paired phones (label, created, last seen, scopes)
python -m homesoc lens revoke <id>     # revoke one, or --all
python -m homesoc lens cert [--regenerate] [--hosts a,b]   # show or regenerate the certificate
```
`--tls` passes `ssl_context=(cert, key)` to the Flask server and logs the fingerprint at startup.
`scripts/enable-lens.ps1` (Windows, needs admin only for the firewall rule) opens the chosen TCP port on the Private
profile and prints the next steps. `docs/LENS_SETUP.md` documents the self-signed path **and** the friction-free
alternative: running Home SOC behind Tailscale Serve, which supplies a genuinely trusted certificate and needs no CA
installed on the phone.

## B4. Pairing and authentication

Lens does **not** reuse `web.token`. It has its own scoped, revocable tokens so a phone can be given read-only access
and revoked without changing the dashboard password.

New table `lens_tokens`:
```
id INTEGER PK, token_hash TEXT* UNIQUE, label TEXT*, scopes TEXT* DEFAULT 'read',
created_at TEXT*, last_seen_at TEXT, last_ip TEXT, expires_at TEXT, revoked_at TEXT
```
Only the SHA-256 of the token is stored. Scopes: `read` (everything Lens displays) and `act` (rescan a device,
acknowledge a finding, set trusted) — `act` is only granted when `lens.allow_actions` is true.

**Pairing flow.** The desktop dashboard gains `/lens/pair` (requires the normal dashboard auth). It:
1. checks `web.host` is not loopback-only and that a certificate exists, explaining exactly what to fix if not;
2. mints a single-use **pairing code** (short, 8 characters, valid 5 minutes, stored in `settings`);
3. renders a QR containing `https://<lan-host>:<port>/lens/claim#c=<pairing-code>` plus the certificate fingerprint
   in human-readable form beneath it.

The phone scans it with any camera app, opens the link, is warned once about the self-signed certificate, and lands on
`/lens/claim`, which POSTs the pairing code to `/api/lens/claim` and receives a long-lived token. The token is stored
in `localStorage` and sent as `X-Lens-Token` on every subsequent request. The pairing code is consumed on first use.

QR generation is **hand-rolled** in `homesoc/web/qr.py` — a small, dependency-free QR encoder (byte mode, error
correction level M, versions 1–10 are ample for these URLs) returning a matrix, with `to_svg()` and `to_ascii()`
renderers. No external library, no CDN. This module is pure and must be unit-tested against known-good fixtures.

Rate limiting: `/api/lens/claim` allows 10 attempts per hour per source IP, then refuses for an hour and writes an
`events` row. Every Lens request updates `last_seen_at`/`last_ip`.

## B5. Data model additions

```
lens_tags(id INTEGER PK, code TEXT* UNIQUE, kind TEXT*, device_id INTEGER REFERENCES devices(id),
          label TEXT, created_at TEXT*, created_by TEXT*, last_seen_at TEXT, scans INTEGER* DEFAULT 0)
```
`kind` ∈ {`sticker`, `learned`}. `code` is the decoded payload; for stickers it is the opaque token (`hs1:` + 22
url-safe base64 characters). A device may have several tags. A tag maps to exactly one device. Deleting a device sets
`device_id` NULL and the tag becomes unlearned rather than dangling.

```
lens_tokens(...)   # as in B4
```
Both tables are owned by the web package. `db.init_schema` creates them via a new migration; existing databases must
upgrade cleanly (this is the first real migration — prove it with a test that opens a v1 database and migrates it).

## B6. Identification API

`homesoc/web/lens.py`:
```python
@dataclass(frozen=True)
class Match:
    device_id: int | None
    confidence: str          # "exact" | "probable" | "ambiguous" | "unknown"
    via: str                 # "sticker" | "learned" | "manual"
    candidates: list[dict]   # ranked, for the picker; each {device_id, name, ip, kind, vendor, score, why}

def identify(conn, *, code: str | None = None, hint: dict | None = None) -> Match
def rank_candidates(conn, *, hint: dict | None = None, limit: int = 25) -> list[dict]
def learn_tag(conn, code: str, device_id: int, *, kind: str = "learned", label: str | None = None) -> int
def forget_tag(conn, code: str) -> bool
def mint_sticker_codes(conn, device_ids: list[int]) -> dict[int, str]   # idempotent: reuse an existing sticker tag
def lens_device(conn, device_id: int, *, hours: int = 24) -> dict       # the overlay payload, see B7
```

`rank_candidates` ordering, best first — this is what makes the manual picker short and usually correct:
1. devices currently online, seen in the last 10 minutes;
2. devices with open findings (you are probably pointing at something you were told about);
3. devices whose `kind` matches the `hint` (the phone may pass `{"kind": "printer"}` if the user filtered);
4. untrusted / recently-new devices;
5. everything else alphabetically by nickname then IP.
Each candidate carries a short `why` string ("online, 3 open findings") so the picker explains itself.

## B7. The overlay payload

`GET /api/lens/device/<id>?hours=24` → the single call the phone makes after identification. It must be one round
trip and small enough to feel instant on Wi-Fi.

```python
{
  "device": {"id","nickname","hostname","ip","mac","vendor","kind","trusted","online",
             "first_seen","last_seen","last_service_scan"},
  "posture": {"score_contribution": int,          # how many points this device costs the home score
              "severity_counts": {"critical":n,"high":n,"medium":n,"low":n,"info":n},
              "headline": str},                   # one sentence: "Two critical problems: Telnet is open and ..."
  "services": [{"port","proto","name","product","version","state","risk"}],   # risk: info|low|medium|high|critical
  "vulns":    [{"cve","kev":bool,"cvss","epss","title","service","remediation"}],
  "findings": [{"row_id","finding_id","severity","title","detail","status","first_seen","remediation":[str,...],
                "refs":[str,...]}],
  "dns":      {"enabled":bool,"window_hours":24,"total":n,"blocked":n,"block_rate":0.0,
               "top_allowed":[{"domain","count"}], "top_blocked":[{"domain","count","reason"}],
               "threats":[{"domain","count","reason","last_seen"}]},
  "timeline": [{"ts","kind","severity","title"}],   # last 20 feed items for this device
  "actions":  {"can_rescan":bool,"can_acknowledge":bool,"can_set_trusted":bool}
}
```
`dns` is keyed on the device's current IP against `dns_queries.client`, and must state honestly in `dns.note` when the
resolver is disabled or when the device's IP changed inside the window (so the figures may be partial).

Other endpoints:
- `POST /api/lens/claim` `{code}` → `{token, label, scopes, expires_at}`
- `POST /api/lens/identify` `{code?, hint?}` → the `Match` shape, plus `lens_device` inlined when confidence is `exact`
- `POST /api/lens/learn` `{code, device_id}` → `{ok, tag_id}` (refused unless `lens.tag_learning`)
- `DELETE /api/lens/tag/<code>` → unlearn
- `GET  /api/lens/devices` → the ranked candidate list for the picker
- `POST /api/lens/action` `{device_id, action, payload}` where action ∈ {`rescan`,`acknowledge`,`set_trusted`} —
  requires the `act` scope and `lens.allow_actions`; `rescan` calls the existing scheduler path, never a new one.
- `GET  /api/lens/health` → `{ok, https, version, dns_enabled, devices, paired_as}`

Every Lens endpoint: requires `X-Lens-Token` (or dashboard auth when hit from the desktop), returns 401 with a JSON
body the phone can render, and never leaks another home's data because there is only one home.

## B8. The phone interface

`/lens` is a single self-contained page (`homesoc/web/templates/lens.html` + `static/lens.js` + `static/lens.css`),
installable as a PWA (`static/manifest.webmanifest`, `static/sw.js` caching the shell so it opens instantly and shows
the last-seen device when the network drops). Designed for one-handed portrait use, dark by default, large touch
targets, readable in a dim utility cupboard.

**Viewfinder.** Full-bleed `getUserMedia` video (`facingMode: "environment"`). A scanning reticle. Decoding runs via
`BarcodeDetector` when available (Chrome on Android), polling frames at ~5 fps from a downscaled canvas to keep it
cheap. When `BarcodeDetector` is absent, the reticle is hidden, a clear note explains that automatic scanning is not
supported in this browser, and the manual picker becomes the primary path. Never leave the user staring at a camera
that silently does nothing.

**The card.** On identification the panel rises over the bottom two-thirds of the screen:
- header: nickname, kind icon, IP, vendor, online dot, trusted state;
- a one-line headline from `posture.headline` and a severity strip;
- collapsible sections in this order — **Problems** (findings, worst first, each expanding to numbered fix steps),
  **Exposed** (open ports with a plain-English gloss: "23 Telnet — remote control with no encryption"),
  **Vulnerabilities** (CVE, KEV badge, EPSS as "x% chance of exploitation in the next 30 days"),
  **Talking to** (top allowed and blocked domains, the block rate, any threat hits — the section that makes the
  x-ray idea land), **History** (the timeline);
- a footer with the actions permitted by scope.
Swipe down or tap the viewfinder to dismiss and scan again. A persistent "Pick manually" button. A "Devices" tab
listing everything, so Lens is useful even with the camera closed.

**Unknown code.** Full-screen sheet: the decoded value shown as raw text, "Which device is this?", the ranked picker,
and a "Not a device / ignore this code" option that records it so it is not asked about again.

Accessibility: every control reachable without the camera, text scalable, colour never the only signal (severity
carries a label as well as a hue), and a reduced-motion path.

## B9. Sticker sheet

`/lens/stickers` (dashboard auth) → a print-optimised HTML page. Options: which devices (default: all without a tag),
label size (Avery 5160-ish 2.625×1in, and a 40mm square), and whether to print the nickname. Each label: the QR (SVG
from `homesoc/web/qr.py`), the nickname, and a small "Home SOC" mark. `@media print` with exact millimetre sizing, no
headers, page-break-inside avoid. Minting is idempotent — reprinting a sheet must not invalidate stickers already
stuck to devices.

## B10. Security requirements

Lens widens the attack surface from loopback to the LAN, so:
- `lens.enabled` defaults to **false**; turning it on requires the user to choose a host binding and a certificate.
- Serving Lens over plain HTTP from a non-loopback address is refused while `lens.require_https` is true.
- Tokens: 32 bytes from `secrets.token_urlsafe`, stored only as SHA-256, compared with `secrets.compare_digest`,
  expiring per config, revocable individually or wholesale, and shown once at pairing and never again.
- Pairing codes are single-use, 5-minute, rate-limited, and invalidated when `lens.enabled` goes false.
- The `act` scope is off by default; without it Lens is strictly read-only.
- No device data in URLs or query strings (so nothing lands in logs or history) — identification is POST.
- Sticker payloads are opaque tokens, never network identifiers (B2).
- `Cache-Control: no-store` on every Lens API response; the service worker caches only the static shell.
- A new finding **SOC-LENS-001** (medium): "Lens is reachable on the LAN over plain HTTP" — emitted when
  `lens.enabled` and the bind host is non-loopback and TLS is off. Add it to the catalogue with real fix steps.
- The existing dashboard-exposure finding must account for Lens too, not contradict it.

## B11. Tests

Offline and deterministic, added to the web package's ownership:
- `homesoc/web/qr.py` against known-good matrices for several payload lengths and both renderers; round-trip decode is
  not required but the matrix must match fixtures byte for byte.
- Pairing: claim succeeds once, fails the second time, fails when expired, fails when rate-limited; token hashing;
  revocation; expiry; `max_tokens` enforcement.
- Identification: exact via sticker, exact via learned tag, unknown code returns ranked candidates, learning binds and
  then resolves, forgetting unbinds, a deleted device leaves the tag unlearned rather than dangling.
- `rank_candidates` ordering against a seeded database asserting the documented precedence.
- `lens_device` payload shape on a rich device and on a bare one; the `dns.note` honesty cases (resolver off, IP
  changed mid-window).
- Authorisation: every endpoint 401s without a token, `act` endpoints 403 without the scope and when
  `lens.allow_actions` is false; `lens.enabled=false` gives 404 everywhere.
- TLS: `ensure_cert` produces a parseable certificate with the expected SANs; `TlsUnavailable` is raised with a useful
  message when `cryptography` is absent (simulate by patching the import).
- Migration: a database created before this addendum upgrades and keeps its rows.
- Page render: `/lens`, `/lens/pair`, `/lens/claim`, `/lens/stickers` all 200 with an empty database and with demo data.
- XSS: a device whose nickname is `<img src=x onerror=alert(1)>` renders escaped everywhere in Lens.

## B12. Build partitioning

- **L1 transport + tokens**: `homesoc/web/tls.py`, `homesoc/web/qr.py`, `lens_tokens` schema + migration, pairing
  endpoints, CLI `lens` subcommands and `--tls`, `scripts/enable-lens.ps1`, config keys, `tests/test_lens_auth.py`.
- **L2 identification + payload**: `homesoc/web/lens.py`, `lens_tags` schema, identify/learn/forget/devices/device
  endpoints, `SOC-LENS-001` in the catalogue, `tests/test_lens_api.py`.
- **L3 phone app**: `templates/lens.html`, `templates/lens_pair.html`, `templates/lens_claim.html`,
  `templates/lens_stickers.html`, `static/lens.js`, `static/lens.css`, `static/manifest.webmanifest`, `static/sw.js`,
  `tests/test_lens_pages.py`.
- **L4 docs**: `docs/LENS_SETUP.md`, plus the Lens sections of `README.md` and `docs/WALKTHROUGH.md`.
