#!/usr/bin/env bash
# Linux Mint 22.x / Ubuntu 24.04 package-base installer. Run as your normal user.
set -euo pipefail
root="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
skip_packages=0
desktop=1
check_only=0
for argument in "$@"; do
  case "$argument" in
    --skip-system-packages) skip_packages=1 ;;
    --no-desktop) desktop=0 ;;
    --check) check_only=1 ;;
    --help)
      printf '%s\n' 'Usage: bash install_mint.sh [--check] [--skip-system-packages] [--no-desktop]'
      exit 0 ;;
    *) printf 'Unknown option: %s\n' "$argument" >&2; exit 2 ;;
  esac
done
if [ "$(id -u)" -eq 0 ]; then
  printf '%s\n' 'Run this installer as your normal desktop user. Only apt requests sudo.' >&2
  exit 1
fi
if [ ! -r /etc/os-release ]; then
  printf '%s\n' 'Cannot identify Linux distribution: /etc/os-release missing.' >&2
  exit 1
fi
. /etc/os-release
case "${ID:-}:${VERSION_ID:-}" in
  linuxmint:22|linuxmint:22.*) ;;
  ubuntu:24.04|ubuntu:24.04.*)
    printf '%s\n' 'Ubuntu 24.04 detected: testing/using the Linux Mint 22 package base.' ;;
  *)
    printf '%s\n' 'This installer targets Linux Mint 22.x (Ubuntu 24.04 base).'
    printf '%s\n' 'Mint 21.x / LMDE: use docs/LINUX.md with an already installed Python 3.12+; no PPA or system Python changes are made.' >&2
    exit 1 ;;
esac
printf 'Distribution: %s\n' "${PRETTY_NAME:-$ID}"
python_bin="${NETPULSE_PYTHON:-python3}"
if [ "$check_only" -eq 1 ]; then
  "$python_bin" -c 'import sys; assert sys.version_info >= (3,12), "Python 3.12+ required"; print("Python:", sys.version.split()[0])'
  for utility in ping ip; do
    command -v "$utility" >/dev/null || { printf 'Missing utility: %s\n' "$utility" >&2; exit 1; }
  done
  printf '%s\n' 'Preflight passed. No settings or packages changed.'
  exit 0
fi
if [ "$skip_packages" -eq 0 ]; then
  sudo apt-get update
  sudo apt-get install -y python3 python3-venv iputils-ping iproute2 xdg-utils xdg-user-dirs desktop-file-utils zenity
fi
NETPULSE_PYTHON="$python_bin" bash "$root/tools/install_linux.sh"
if [ "$desktop" -eq 1 ] && command -v xdg-user-dir >/dev/null; then
  desktop_dir="$(xdg-user-dir DESKTOP)"
  source_file="${XDG_DATA_HOME:-$HOME/.local/share}/applications/netpulse.desktop"
  # Disabled desktop directories may resolve to HOME: do not scatter launchers there.
  if [ -d "$desktop_dir" ] && [ "$desktop_dir" != "$HOME" ]; then
    install -m 755 "$source_file" "$desktop_dir/NetPulse.desktop"
    printf 'Desktop shortcut: %s\n' "$desktop_dir/NetPulse.desktop"
  fi
fi
if command -v update-desktop-database >/dev/null; then
  update-desktop-database "${XDG_DATA_HOME:-$HOME/.local/share}/applications"
fi
if command -v systemctl >/dev/null && [ -n "${DBUS_SESSION_BUS_ADDRESS:-}" ]; then
  if ! systemctl --user daemon-reload; then
    printf '%s\n' 'User service manager unavailable. Manual/menu launch is ready; reload the unit after desktop login.' >&2
  fi
fi
printf '\n%s\n' 'NetPulse is ready. Open NetPulse from the Mint menu or run: bash open_netpulse.sh'
printf '%s\n' 'On first desktop launch, Cinnamon/Nemo may ask you to allow launching the shortcut.'
