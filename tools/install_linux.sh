#!/usr/bin/env bash
set -euo pipefail
root="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
cd "$root"
python_bin="${NETPULSE_PYTHON:-python3}"
"$python_bin" -c 'import sys; assert sys.version_info >= (3,12), "Python 3.12+ required"'
if ! command -v ping >/dev/null || ! command -v ip >/dev/null; then
  printf '%s\n' 'Install network tools first: sudo apt-get install python3-venv iputils-ping iproute2' >&2
  exit 1
fi
"$python_bin" -m venv "$root/.venv"
"$root/.venv/bin/python" -m pip install --disable-pip-version-check -r "$root/requirements.txt"
"$root/.venv/bin/python" - "$root" <<'PY'
import json
import os
import sys
from pathlib import Path
root = Path(sys.argv[1])
config = root / 'config.json'
if not config.exists():
    with config.open('x', encoding='utf-8') as stream:
        os.chmod(config, 0o600)
        json.dump({'web_host':'127.0.0.1','web_port':8770,
                   'lan':{'auto_scan_min':0},'p2p':{'enabled':False},
                   'backup':{'dir':str(root/'backups'/'data')}}, stream, indent=2)
applications = Path(os.environ.get('XDG_DATA_HOME', str(Path.home()/'.local'/'share'))) / 'applications'
applications.mkdir(parents=True, exist_ok=True)
def quoted(value):
    return '"' + str(value).replace('\\','\\\\').replace('"','\\"').replace('`','\\`').replace('$','\\$').replace('%','%%') + '"'
desktop = ('[Desktop Entry]\nType=Application\nName=NetPulse\nComment=Local network operations dashboard\n'
           'Comment[ru]=Мониторинг сети и управление ИТ-инфраструктурой\nStartupNotify=false\n'
           'Exec='+quoted(root/'.venv'/'bin'/'python')+' '+quoted(root/'tools'/'launch_netpulse.py')+'\n'
           'Icon='+str(root/'netpulse'/'web'/'icon.svg')+'\nTerminal=false\nCategories=Network;\n')
(applications/'netpulse.desktop').write_text(desktop, encoding='utf-8')
unit_dir = Path(os.environ.get('XDG_CONFIG_HOME', str(Path.home()/'.config'))) / 'systemd' / 'user'
unit_dir.mkdir(parents=True, exist_ok=True)
def systemd(value):
    return '"' + str(value).replace('\\','\\\\').replace('"','\\"').replace('%','%%') + '"'
unit = ('[Unit]\nDescription=NetPulse local monitoring\nAfter=network.target\n\n[Service]\nType=simple\n'
        'WorkingDirectory='+str(root).replace('%','%%')+'\nExecStart='+systemd(root/'.venv'/'bin'/'python')+' -m netpulse\n'
        'Environment=NETPULSE_NO_BROWSER=1\nRestart=on-failure\nRestartSec=5\nUMask=0077\n\n[Install]\nWantedBy=default.target\n')
(unit_dir/'netpulse.service').write_text(unit, encoding='utf-8')
print('Installed:', applications/'netpulse.desktop')
print('Optional user service: systemctl --user daemon-reload && systemctl --user enable --now netpulse')
PY
printf '%s\n' 'Ready. Start: bash open_netpulse.sh (or --no-browser on a headless machine).'
