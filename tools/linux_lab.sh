#!/usr/bin/env bash
set -euo pipefail
root="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
python_bin="${NETPULSE_PYTHON:-$root/.venv/bin/python}"
report_dir="${NETPULSE_LAB_REPORT_DIR:-$root/test-results/linux-lab}"
mkdir -p "$report_dir"
if [ "$(id -u)" -ne 0 ]; then
  printf '%s\n' 'Run this disposable lab with sudo; only named network namespaces are changed.' >&2
  exit 1
fi
# Refuse to touch pre-existing namespaces owned by another lab/session.
if ip netns list | grep -Eq '^(netpulse-lab-client|netpulse-lab-peer)\b'; then
  printf '%s\n' 'NetPulse lab namespace already exists; refusing to replace it.' >&2
  exit 1
fi
client_created=0
peer_created=0
cleanup() {
  if [ "$client_created" -eq 1 ]; then ip netns delete netpulse-lab-client; fi
  if [ "$peer_created" -eq 1 ]; then ip netns delete netpulse-lab-peer; fi
}
trap cleanup EXIT
ip netns add netpulse-lab-client
client_created=1
ip netns add netpulse-lab-peer
peer_created=1
ip -n netpulse-lab-client link add eth-lab type veth peer name peer-lab
ip -n netpulse-lab-client link set peer-lab netns netpulse-lab-peer
ip -n netpulse-lab-client addr add 10.203.0.1/29 dev eth-lab
ip -n netpulse-lab-peer link set peer-lab address 02:00:00:00:00:02
ip -n netpulse-lab-peer addr add 10.203.0.2/29 dev peer-lab
ip -n netpulse-lab-client link set lo up
ip -n netpulse-lab-peer link set lo up
ip -n netpulse-lab-client link set eth-lab up
ip -n netpulse-lab-peer link set peer-lab up
ip -n netpulse-lab-client link add happ-xray type dummy
ip -n netpulse-lab-client addr add 172.19.0.1/30 dev happ-xray
ip -n netpulse-lab-client link set happ-xray up
ip netns exec netpulse-lab-client "$python_bin" "$root/tests/linux_smoke.py" --report "$report_dir/icmp.json"
ip netns exec netpulse-lab-peer sysctl -qw net.ipv4.icmp_echo_ignore_all=1
ip netns exec netpulse-lab-client "$python_bin" "$root/tests/linux_smoke.py" --arp-only --report "$report_dir/arp-only.json"
