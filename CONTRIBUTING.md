# Contributing to Home SOC

Home SOC is a single-process home security agent: Python 3.12+, three pinned dependencies
(`flask`, `requests`, `dnslib`) and the standard library. No JavaScript build, no containers, no
services. If you can run `pytest`, you can contribute.

Read `docs/ARCHITECTURE.md` first — it explains the threads, the tables and the data flow that the
rest of this document assumes.

---

## 1. Getting set up

```sh
git clone <your fork>
cd Home_SOC

# Windows
python -m venv .venv
.venv\Scripts\activate

# Linux / macOS
python3 -m venv .venv
. .venv/bin/activate

python -m pip install --require-hashes -r requirements.txt
python -m pip install -e ".[dev]"
```

`requirements.txt` is a hash-locked lock of the runtime dependencies (the whole transitive closure
plus pip), generated with pip-compile; the command to regenerate it is in its header. It does not
contain `pytest`: the `[dev]` extra installs it (`pytest>=9.0.3`). The editable install also gives
you the `homesoc` console script, but `python -m homesoc ...` works either way.

Then create a data directory and a config:

```sh
python -m homesoc init --no-feeds     # schema + config.toml, no network
python -m homesoc status              # should print a score and empty tables
```

`init` writes `config.toml` with a freshly generated random `web.token`. **Never commit
`config.toml` or anything under `data/`** — they hold your API keys, your network inventory and your
DNS query log. `.gitignore` already excludes them; keep it that way.

To develop against a throwaway database instead of your real one, point the environment at a
different directory — every path in `homesoc/paths.py` re-reads the environment on each call:

```sh
HOMESOC_DATA=/tmp/homesoc-dev HOMESOC_CONFIG=/tmp/homesoc-dev/config.toml python -m homesoc status
```

`run.bat` and `run.sh` are the end-user launchers (venv → deps → `init` → `run`). Do not use them for
development; they reinstall dependencies whenever `requirements.txt` changes and then exec into
`run`.

Useful commands while working:

```
python -m homesoc scan --only discovery      # one scan step, no scheduler
python -m homesoc serve --port 8788          # dashboard only, jobs manual-only
python -m homesoc dns --port 5300            # resolver only, unprivileged port
python -m homesoc dns-test example.com       # policy decision + upstream answer
python -m homesoc feed --limit 20 --since 24h
python -m homesoc report --format md
python -m homesoc <command> --help           # always the authority on flags
```

---

## 2. Running the tests

The suite must stay green. From the repository root:

```sh
python -m pytest -q
```

Everything is offline and fixture-driven; a full run takes well under a minute. If a test needs the
network, it is marked and skipped.

| Command | What it does |
|---|---|
| `python -m pytest -q` | the default suite (offline, live tests skipped) |
| `python -m pytest -q -m "not slow"` | skips tests that spawn a subprocess interpreter |
| `python -m pytest -q --live` | **also** runs tests marked `live`, which hit the real network |
| `python -m pytest tests/test_dns.py -q` | one package's tests |
| `python -m pytest -q -k dedupe` | one test by name |

Two markers are declared in `pyproject.toml` and honoured by `tests/conftest.py`:

- **`live`** — touches the real network or the real feed URLs. Skipped unless you pass `--live`.
  The one existing live test (`tests/test_feeds.py`) additionally requires `HOMESOC_LIVE=1`, so a
  full opt-in run is:
  ```sh
  HOMESOC_LIVE=1 python -m pytest -q --live -m live
  ```
  Expect it to be slow, to fail when a mirror is down, and to download real blocklists. It is a
  smoke test for "are the URLs still right", not part of CI.
- **`slow`** — offline, but spawns an interpreter or a subprocess. Deselect with `-m "not slow"`.

### Fixtures you get for free

`tests/conftest.py` gives every test an isolated environment — `HOMESOC_DATA` points at a temporary
directory and `HOMESOC_CONFIG` at a file that does not exist, so no test can touch your real `data/`
or `config.toml`.

| Fixture | What it is |
|---|---|
| `data_dir` | a temporary `HOMESOC_DATA` (and a non-existent config path) |
| `conn` | a schema-initialised SQLite connection at the temporary `db_path()` |
| `memory_conn` | the same schema, in memory, for tests that never touch the filesystem |
| `cfg` | a default `Config` (no config file, no overrides) |
| `fixtures_dir` | `tests/fixtures/` |

Sample data lives in `tests/fixtures/{feeds,nmap,posture}/`. Add fixtures for the package you own.

Write tests that are deterministic and offline: no sleeping on real clocks, no real sockets except on
an ephemeral port with a fake upstream, no real HTTP (substitute the module's own seam —
`updater._http_get`, `channels._default_poster`, `reputation`'s injectable `session`).

---

## 3. Module map and ownership

Each package owns its directory *and* its test file. Change something outside your area only when the
change is genuinely cross-cutting, and say so in the pull request.

| Area | Files | Test file | Owns these tables |
|---|---|---|---|
| **core** | `homesoc/{__init__,__main__,cli,config,db,models,scheduler,util,paths}.py`, `config.example.toml`, `pyproject.toml`, `requirements.txt`, `run.bat`, `run.sh`, `scripts/*` | `tests/test_core.py`, `tests/conftest.py` | `schema_migrations`, `settings`, `events`, `metrics`, `jobs`, `scans` (and the whole DDL) |
| **feeds** | `homesoc/feeds/{registry,updater,parsers}.py` | `tests/test_feeds.py` | `feeds` |
| **network scanners** | `homesoc/scanners/{discovery,ports,nmap_xml,services,exposure,mdns_ssdp,wifi}.py` | `tests/test_network.py` | `devices`, `device_sightings`, `services` |
| **host + AV** | `homesoc/scanners/{host_windows,host_posix,defender,updates,persistence,files}.py`, `homesoc/scanners/ps/*.ps1` | `tests/test_host.py` | `host_checks`, `software`, `persistence`, `file_checks` |
| **vulns** | `homesoc/vulns/{matcher,cpe,enrich}.py` | `tests/test_vulns.py` | `vulns` |
| **findings + notify** | `homesoc/findings/{catalog,engine,score}.py`, `homesoc/notify/channels.py` | `tests/test_findings.py` | `findings`, `finding_events`, `notifications` |
| **dns** | `homesoc/dnsfilter/{server,policy,upstream,cache,querylog,reputation}.py` | `tests/test_dns.py` | `dns_queries`, `dns_hourly`, `dns_overrides`, `reputation` |
| **web** | `homesoc/web/{app,api,feed,summary}.py`, `templates/*.html`, `static/*` | `tests/test_web.py`, `tests/test_feed_summary.py` | nothing (read-mostly) |
| **docs** | `README.md`, `SECURITY.md`, `CONTRIBUTING.md`, `docs/*.md` | — | — |

`tests/test_smoke_regressions.py` belongs to no single area: it pins CLI-surface regressions that
have bitten before (for example that `scan --full` is accepted and that `--quick` and `--full` stay
mutually exclusive). Add to it when you fix a bug that a package-level test would not have caught.

### Import rules

These keep the packages from tangling:

- **Everyone** may import `homesoc.config`, `homesoc.db`, `homesoc.models`, `homesoc.util`,
  `homesoc.paths`.
- **Scanners** may import `homesoc.feeds.registry` (for OUI vendor lookups and blocklists).
- **vulns** may import `homesoc.feeds.registry`.
- **findings** imports nothing from scanners. It receives `FindingDraft` objects; it never goes and
  looks.
- **web** imports `homesoc.findings`, `homesoc.dnsfilter.querylog`, `homesoc.feeds.registry` and the
  read-only helpers of `homesoc.scanners.defender` — and imports them lazily, so the dashboard
  renders even when those packages have not run.
- **dnsfilter** imports only `homesoc.feeds.registry` and `homesoc.findings.engine`.
- **`homesoc/cli.py`** is the only module that knows about everything, and it does so through the
  `MODULES` table with `_lazy()`, so a missing or broken package logs one line and is skipped.

`homesoc/scanners/__init__.py` deliberately does **not** import its submodules — several of them
shell out to platform tools, and importing the package must stay side-effect free.

---

## 4. Recipe: add a finding to the catalog

Three files, in this order.

### Step 1 — the catalog entry

Everything a human reads lives in `homesoc/findings/catalog.py`. Add a `_spec(...)` call to the
`_SPECS` list, near its siblings:

```python
_spec(
    "NET-SVC-013", "medium", "MQTT broker on {ip} accepts connections without a password",
    "An open MQTT broker lets anything on your network read and publish messages for every smart "
    "device that uses it — including door locks and cameras.",
    [
        "Open the broker's configuration and set `allow_anonymous false`, then add a user and password.",
        "If you did not install this broker, find the device at {ip} on the Devices page and unplug it "
        "until you know what it is.",
        "PowerShell to confirm the port closed afterwards: Test-NetConnection {ip} -Port {port}",
    ],
    ["https://mosquitto.org/man/mosquitto-conf-5.html"],
    "lan-services",
),
```

The arguments are, in order: `id`, `severity`, `title`, `rationale`, `remediation`, `refs`,
`category`, and an optional `per_subject` flag.

Rules the tests enforce:

- `severity` must be one of `critical, high, medium, low, info`.
- `title`, `rationale`, `category` and at least one remediation step are required; every step must be
  a non-empty string.
- Every entry in `refs` must start with `https://`. **Only use URLs you have actually opened.**
- For the `defender`, `firewall`, `updates`, `accounts`, `host-network` and `system` categories, at
  least one remediation step must contain a command-line alternative (the word `PowerShell`,
  `powershell`, `winget`, or a `Run:` prefix). The click-path is for the dashboard reader; the
  command is what someone can paste.
- `{placeholders}` in the title and the steps are filled from the draft's evidence dict, plus fields
  derived from the subject (`mac`, `port`, `client`, `name`, `job`, `interface`). A placeholder no
  emitter supplies would render as the word "unknown" on someone's dashboard, which is why there is a
  test for it (step 3).

Write remediation for a non-admin Windows 11 Home user first: the exact menu path, then the command.
Keep the rationale to why it matters in plain words — no jargon, no scare quotes, no marketing.

### Step 2 — the emitter

A scanner emits a `FindingDraft` (`homesoc/models.py`). It never writes to the `findings` table:

```python
from homesoc.models import FindingDraft

drafts.append(FindingDraft(
    finding_id="NET-SVC-013",
    subject=f"device:{device.mac}:{port}",   # host | device:<mac>[:port] | wan | wifi | dns[:<client>] | feed:<name> | job:<name>
    evidence={"ip": device.ip, "port": port, "product": svc.product},
    device_id=device.id,
    # severity=...  only to escalate/de-escalate this instance away from the catalog default
    # detail=...    only to override the rendered rationale
))
```

Return them in the scanner's `ScanResult.findings`; `cli.apply_findings()` and
`findings.engine.apply()` do the rest.

Two things to get right:

- **Dedupe key.** A finding's identity is `finding_id | subject`, plus `| evidence["key"]` when one
  subject can legitimately hold several instances of the same problem (one CVE, one autostart entry,
  one threat name, one failing job). If you need several, set `evidence["key"]` to something stable.
- **Auto-resolve scope.** If your finding should disappear on its own once the problem is gone, the
  scan step that emits it must pass a `scope` covering its subjects, and the scanner must only report
  a complete run — see `cli.effective_scope()`. A partial or failed run resolves nothing, on purpose.

### Step 3 — the tests

In `tests/test_findings.py`:

1. add the ID to `SPEC_IDS`,
2. add an entry to `EMITTER_EVIDENCE` with `(subject, evidence)` **exactly as your emitter builds
   it** — not a hand-tuned dict that happens to fill every placeholder,
3. if the ID is normative, add it to `SPEC_SEVERITY`.

`test_every_spec_id_has_representative_evidence` will fail without step 2, and
`test_catalog_renders_real_emitter_evidence_without_placeholders` will fail if the catalog asks for a
key your scanner does not produce. That is the whole point: catalog drift is caught in CI, not on a
user's dashboard.

Then add a test in your own package's test file asserting the emitter produces the draft.

If you are only *changing* an existing finding's wording, step 1 is enough — but re-run
`python -m pytest tests/test_findings.py -q` before you push.

---

## 5. Recipe: add a definitions feed

### Step 1 — a parser (only if the format is new)

`homesoc/feeds/parsers.py` holds pure functions, each returning an **iterator** of normalised
entries. The existing ones cover most cases:

| Parser | Input | Yields |
|---|---|---|
| `parse_hosts` | `0.0.0.0 tracker.example` | domains |
| `parse_domains` | one plain domain per line | domains |
| `parse_adblock` | `\|\|domain^` | domains |
| `parse_wildcard` | `*.domain` | domains |
| `parse_urls` | full URLs (OpenPhish) | domains |
| `parse_ips` / `parse_feodo` | CIDRs / abuse.ch JSON | `ipaddress.IPv4Network` |
| `parse_kev` / `parse_epss` / `parse_oui` | the three definition formats | list / dict / dict |

If yours is genuinely new, add a function next to these. It must be pure (text in, iterator out), it
must skip comments and blank lines without raising, and it must tolerate a truncated file — the input
is bytes from the internet.

### Step 2 — the registry entry

Add a `_spec(...)` to the `FEEDS` tuple in `homesoc/feeds/registry.py`:

```python
_spec("example_list", "https://example.org/blocklist.txt",
      "domains", parsers.parse_domains, 12, "Example list, CC BY 4.0", enabled=True),
```

Arguments: `name`, `url`, `kind`, `parser`, default `hours`, `license_note`, and `enabled` (default
`True`; pass `enabled=False` for a heavy or opinionated list that should be opt-in).

- `kind` must be one of `kev, epss, oui, hosts, domains, adblock, ip, json`. Only
  `hosts`/`domains`/`adblock` are loadable by the DNS policy (`DOMAIN_KINDS`); only `ip` is loadable
  as an IP set.
- `license_note` is required and must be truthful. Check the feed's terms before adding it — several
  of the existing ones are non-commercial-use only, and that is recorded here.
- **The URL must be one you fetched yourself and saw return 200.** Do not copy a URL from a README.

### Step 3 — cadence and file extension

`updater.effective_hours()` maps a feed to a config key: `feeds.kev_hours`, `feeds.epss_hours`,
`feeds.oui_hours` by kind; `feeds.threatintel_hours` for names in the `_THREATINTEL` set in
`homesoc/feeds/updater.py`; `feeds.blocklists_hours` for everything else. If your feed is malware or
phishing intelligence, add its name to `_THREATINTEL`. If you introduced a new `kind`, add its file
extension to `_EXT` (the default is `.txt`).

### Step 4 — make it usable

- A DNS blocklist only takes effect when its name appears in `dns.lists`. Add it to the default list
  in `config.example.toml` (and the mirrored `EXAMPLE_TOML` string in `homesoc/config.py`) only if it
  should be on for everyone; otherwise document it as an opt-in.
- Nothing else needs wiring: `updater.update()` iterates `registry.FEEDS`, `_ensure_row()` creates the
  `feeds` row, and the dashboard's feed table, the freshness checks and `SOC-FEED-001` all pick it up
  automatically.

### Step 5 — tests

In `tests/test_feeds.py`, `test_registry_matches_spec_table` asserts that `registry.FEEDS` matches its
`SPEC_URLS` table exactly, so **adding a feed requires updating that table in the same commit.** Add a
small fixture file under `tests/fixtures/feeds/` and a parser test if you wrote a new parser. Do not
add a live network test; the one that exists is enough.

---

## 6. Recipe: add a scanner

Every scanner is a module in `homesoc/scanners/` exposing exactly one entry point:

```python
def run(cfg: Config, conn: sqlite3.Connection, *, quick: bool = False,
        progress: Callable[[str], None] | None = None) -> ScanResult:
```

### The contract

- **Write the tables you own**, using `db.write` / `db.writemany` / `db.transaction` with bound
  parameters. Never write `findings` — return drafts.
- **Return `ScanResult(kind, findings, summary, error)`**. `findings` is a list of `FindingDraft`;
  `summary` is a small JSON-serialisable dict; `error` is a string or `None`.
- **Never raise for an expected failure.** A missing tool, no administrator rights, a timeout, a
  device that did not answer — all of those set `ScanResult.error` and/or emit a `SOC-*` finding. The
  CLI catches anything you miss, but it will be logged as a crash.
- **Respect the configuration**: `cfg.network.exclude` is a list of IPs you must never port-scan, and
  `cfg.network.is_fragile_vendor(vendor)` marks devices that get the gentle profile only.
- **Honour `quick`.** A quick scan should cost seconds, not minutes — scan the gateway and a handful
  of recently-seen devices, not everything.
- **Call `progress("...")`** at meaningful milestones; the CLI logs it, the dashboard shows nothing
  yet, and it costs you nothing.
- **Signal completeness honestly.** `cli.effective_scope()` reads your summary to decide whether this
  run may auto-resolve findings it did not report. Set `summary["partial"] = True` when you did not
  finish; put the exact subjects you fully covered in `summary["scopes"]` (a list, e.g. one
  `device:<mac>` per completed device) when you can. Getting this wrong marks real problems as fixed.

### Wiring it into the CLI

`homesoc/cli.py`, in four places:

```python
# 1. the lazy-import table
MODULES = {
    ...
    "mything": ("homesoc.scanners.mything", "run"),
}

# 2. a scan step function
def scan_mything(cfg, conn, *, quick=False):
    call = _call_scanner("mything", cfg, conn, quick=quick, progress=_progress_logger("mything"))
    return run_step(cfg, conn, "mything", [("mything", call, "mything")])
    #                                       source     call   scope (must match your subjects)

# 3. the step registry — SCAN_STEPS is in execution order, QUICK_STEPS is the quick subset
SCAN_STEPS = ("discovery", "services", "vulns", "host", "exposure", "wifi", "files", "mything")
SCAN_FUNCS["mything"] = scan_mything

# 4. a scheduled job in build_jobs(), if it should run on a timer
Job("mything", hours(cfg.schedule.mything_hours), lambda: scan_mything(cfg, conn),
    description="What this scanner checks"),
```

Adding a config key means touching `config.example.toml`, the `EXAMPLE_TOML` string in
`homesoc/config.py` and the matching dataclass — all three, or `config.build()` will not know the
type to coerce to. If the key should be editable from the dashboard, add it to `EDITABLE_SETTINGS` in
`homesoc/web/api.py` (type `secret` for anything credential-shaped; secrets are never echoed back).

Any finding your scanner emits must already exist in the catalog — see §4.

### Shelling out

Use the shared helpers, never `subprocess` directly:

```python
from homesoc.scanners import run_command, powershell

res = run_command(["nmap", "-sT", "-oX", "-", ip], timeout=180)
if res.missing:  ...      # binary not on PATH
if res.timed_out: ...     # hard timeout hit
if res.ok:  parse(res.out)
```

Both `run_command` and `homesoc.util.run_cmd` take an **argv list**, pass `shell=False`, always carry
a timeout, hide the console window on Windows, and turn a missing binary or a timeout into a result
rather than an exception. Build the argv from constants plus validated values (an IP you parsed, an
int you clamped) — never from a user-supplied string.

### Tests

Add them to the test file for your area. Parse fixture output rather than running the real tool:
put a sample in `tests/fixtures/`, feed it to your parsing function, and assert on the drafts. If
your scanner cannot run on the developer's platform, it must return a clean `ScanResult` saying so,
and there should be a test for that path.

---

## 7. Code conventions

These are the conventions the existing code actually follows. There is no linter config in the
repository, so consistency is on you.

**Style**

- `from __future__ import annotations` at the top of every module.
- Type hints on every public function and dataclass field. Modern syntax: `str | None`,
  `list[dict]`, `dict[str, int]` — not `Optional`, not `typing.List`.
- 4-space indent; lines roughly up to 120 columns.
- `@dataclass` for records. `frozen=True` when the value should not change after construction
  (`Config` and its sections, `FindingSpec`, `FeedSpec`, `Decision`, `FeedItem`). Shared records live
  in `homesoc/models.py`; nothing in there touches the database.
- Many modules end with an explicit `__all__`; follow the file you are editing.

**Documentation in the code**

- Every module opens with a docstring that says *why* it exists and what the non-obvious design
  decision was — not a restatement of the function names. Look at `homesoc/scheduler.py` or
  `homesoc/dnsfilter/cache.py` for the tone.
- Where `docs/SPEC.md` is silent and you had to choose, leave a `# SPEC-GAP:` comment saying what you
  chose and why. Grep for it; there are plenty of examples.
- Comments explain the reasoning, not the mechanics. `# clamp to 1232 because that is the
  amplification factor` earns its line; `# increment i` does not.

**Logging and output**

- One module logger: `logger = logging.getLogger(__name__)`, at the top, after the imports.
- **Library code logs; the CLI prints.** Anything under `homesoc/` that is not `cli.py` should never
  call `print()`. The CLI uses `cli.emit()`, which survives a Windows console that cannot encode an
  em dash.
- Never log a secret. `config.SECRET_KEYS` lists them, `config.redacted()` masks them, and
  `notify.channels._scrub()` removes webhook URLs from stored error text.
- `db.record_event()` for things a user should see on `/telemetry`; `db.record_metric()` for numbers
  you want charted.

**Time and data**

- All stored timestamps are UTC ISO-8601 with a trailing `Z`, produced by `util.utcnow_iso()` (or
  `util.iso_ago(**delta)` for cutoffs). Local time is a display concern only.
- JSON goes into `TEXT` columns via `util.json_dumps()`; read it back with `util.safe_json_loads()`.

**Subprocesses**

- Always `run_command` / `run_cmd`; always an argv list; always a timeout. `shell=True`, `os.system`,
  `eval` and `exec` do not appear anywhere in this codebase and must not start now.

**Database**

- Bound parameters, always. If you need an identifier that cannot be bound, validate it against a
  known list first — `db.purge_older_than()` is the pattern.
- Writes through `db.write` / `db.writemany` / `db.transaction` so they take the shared lock. Reads
  through `db.query` / `db.one`.
- Schema changes go in `homesoc/db.py` as a new `(version, ddl)` entry in `MIGRATIONS`, never by
  editing `SCHEMA_V1` in place — someone already has that database.

**The dashboard**

- **No external assets. None.** The CSP is `default-src 'self'`, so a CDN script, a Google font or a
  remote image will simply not load. Everything lives in `homesoc/web/static/`.
- No inline `<script>`, no inline `style=`, no `onclick=` attributes — the same CSP forbids them.
  Wire behaviour up from `static/app.js`.
- Charts are drawn by `static/charts.js` with plain SVG. Do not add a charting library.
- Never build HTML by string concatenation. Jinja autoescapes; let it. Remember that hostnames,
  domains and banners come from the network and may contain anything.
- Every mutating request needs the `X-Requested-With: fetch` header (the CSRF guard) and sends JSON.

**Behaviour**

- Degrade, do not crash. A missing tool, a missing privilege or a missing network is a documented
  reduced mode with a clear message, not a traceback. This is the single most important convention in
  the project.

---

## 8. Pull requests

- One change per pull request; keep it inside your area (§3) unless the change is genuinely
  cross-cutting.
- `python -m pytest -q` passes, with new tests for new behaviour.
- No new runtime dependency. Three is the budget; if you truly need a fourth, open an issue and make
  the case first.
- Never invent a URL, a command, a config key or a finding ID. Check it against the code: run
  `python -m homesoc <cmd> --help`, grep the catalog, read `config.example.toml`.
- Do not commit `data/`, `config.toml`, `.venv/`, or anything with a key in it.
- If you touched anything security-relevant — auth, the CSP, the resolver, feed downloading,
  subprocess arguments — say so explicitly in the description and re-read `SECURITY.md` §3.
- Found a security bug? Do not open a PR for it in public. See `SECURITY.md` §1.

Home SOC is MIT licensed; contributions are accepted under the same licence.
