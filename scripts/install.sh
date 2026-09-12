#!/usr/bin/env sh
# Install Home SOC for the current user (Linux/macOS, no root): venv, deps, init.
# Usage: sh scripts/install.sh [--no-feeds]
set -e
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

PY=python3
command -v python3 >/dev/null 2>&1 || PY=python
if ! "$PY" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 12) else 1)' 2>/dev/null; then
    echo "Python 3.12 or newer is required (found: $("$PY" --version 2>&1))." >&2
    exit 1
fi

echo "[Home SOC] installing into $ROOT"
if [ ! -d .venv ]; then
    echo "[Home SOC] creating virtual environment ..."
    "$PY" -m venv .venv
fi
# shellcheck disable=SC1091
. .venv/bin/activate
echo "[Home SOC] installing dependencies ..."
python -m pip install -r requirements.txt -q --disable-pip-version-check
echo "[Home SOC] initialising ..."
python -m homesoc init "$@"
chmod +x run.sh 2>/dev/null || true

cat <<EOF

Done. Next steps:
  1. Start now:            ./run.sh
  2. Open the dashboard:   http://127.0.0.1:8787/
  3. Tune settings:        config.toml (or the dashboard's Settings page)
  4. Autostart (Linux, systemd user service):
       mkdir -p ~/.config/systemd/user
       printf '[Unit]\nDescription=Home SOC\nAfter=network-online.target\n\n[Service]\nWorkingDirectory=$ROOT\nExecStart=$ROOT/.venv/bin/python -m homesoc run\nRestart=on-failure\n\n[Install]\nWantedBy=default.target\n' > ~/.config/systemd/user/homesoc.service
       systemctl --user daemon-reload && systemctl --user enable --now homesoc
     Autostart (macOS): create a LaunchAgent that runs $ROOT/run.sh, or add run.sh to Login Items.
  5. LAN-wide DNS filter: binding port 53 needs root (or setcap on Linux); set dns.enabled = true and allow UDP/TCP 53 in the firewall.
EOF
