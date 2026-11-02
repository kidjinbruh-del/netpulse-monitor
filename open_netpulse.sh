#!/usr/bin/env bash
set -euo pipefail
root="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
cd "$root"
if [ ! -x "$root/.venv/bin/python" ]; then
  printf '%s\n' 'Run bash tools/install_linux.sh first.' >&2
  exit 1
fi
exec "$root/.venv/bin/python" "$root/tools/launch_netpulse.py" "$@"
