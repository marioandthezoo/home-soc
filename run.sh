#!/usr/bin/env sh
# Home SOC launcher (Linux/macOS): venv on first run, deps, init, run. No root needed.
#
# Every step's exit code is checked, so a too-old Python or an offline first run ends in one
# actionable sentence instead of a traceback. Pass --autostart (a LaunchAgent / systemd unit
# should) to keep it quiet: failures go to data/logs/launcher.log and nothing waits for input.
set -u
cd "$(dirname "$0")"

AUTOSTART=0
ARGS=""
for arg in "$@"; do
    if [ "$arg" = "--autostart" ]; then
        AUTOSTART=1
    else
        ARGS="$ARGS $arg"
    fi
done

LAUNCHLOG="$(pwd)/data/logs/launcher.log"
mkdir -p "$(dirname "$LAUNCHLOG")" 2>/dev/null || true

fail() {
    printf '[Home SOC] %s\n' "$1" >&2
    printf '[%s] %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$1" >> "$LAUNCHLOG" 2>/dev/null || true
    if [ "$AUTOSTART" -eq 0 ] && [ -t 0 ]; then
        printf 'Press Enter to close ... ' >&2
        read -r _dummy || true
    fi
    exit 1
}

min_version_ok() {   # $1 = interpreter command
    "$1" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 12) else 1)' >/dev/null 2>&1
}

if [ ! -x .venv/bin/python ]; then
    PY=""
    for candidate in python3 python; do
        if command -v "$candidate" >/dev/null 2>&1 && min_version_ok "$candidate"; then
            PY="$candidate"
            break
        fi
    done
    if [ -z "$PY" ]; then
        found="$(python3 --version 2>&1 || python --version 2>&1 || echo 'none on PATH')"
        fail "Python 3.12 or newer is required - found: $found. Install it (e.g. apt install python3.12 / brew install python@3.12) and run ./run.sh again."
    fi
    echo "[Home SOC] creating virtual environment ..."
    "$PY" -m venv .venv || fail "could not create the virtual environment in .venv - is the python venv module installed (apt install python3-venv)?"
fi

# shellcheck disable=SC1091
. .venv/bin/activate || fail ".venv exists but .venv/bin/activate failed - delete the .venv directory and run ./run.sh again."

min_version_ok python || fail "the .venv virtual environment runs $(python --version 2>&1), but Home SOC needs Python 3.12 or newer. Delete the .venv directory and run ./run.sh again."

# Dependencies only when requirements.txt actually changed: re-running pip at every login is
# slow and, offline, prints a wall of errors.
STAMP=".venv/.requirements.sha"
REQHASH=""
if command -v sha256sum >/dev/null 2>&1; then
    REQHASH="$(sha256sum requirements.txt 2>/dev/null | cut -d' ' -f1)"
elif command -v shasum >/dev/null 2>&1; then
    REQHASH="$(shasum -a 256 requirements.txt 2>/dev/null | cut -d' ' -f1)"
fi
OLDHASH=""
[ -f "$STAMP" ] && OLDHASH="$(cat "$STAMP" 2>/dev/null)"
if [ -z "$REQHASH" ] || [ "$REQHASH" != "$OLDHASH" ]; then
    echo "[Home SOC] installing dependencies ..."
    python -m pip install -r requirements.txt -q --disable-pip-version-check \
        || fail "dependency install failed - this usually means no internet connection. Connect and run ./run.sh again; see data/logs/launcher.log."
    [ -n "$REQHASH" ] && printf '%s\n' "$REQHASH" > "$STAMP"
fi

python -m homesoc init || fail "python -m homesoc init failed - see data/logs/homesoc.log for the reason."

# shellcheck disable=SC2086
exec python -m homesoc run $ARGS
