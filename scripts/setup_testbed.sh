#!/usr/bin/env bash
# Isolate a Linux SUT or client host before a Custos measurement run.
# Locks cpufreq to performance, disables swap, and raises the listen backlog.
# Requires root. Safe to re-run; it does not reboot.

set -euo pipefail

if [[ "$(uname -s)" != "Linux" ]]; then
  echo "setup_testbed.sh: Linux only (found $(uname -s))" >&2
  exit 1
fi

if [[ "${EUID}" -ne 0 ]]; then
  echo "setup_testbed.sh: re-exec with sudo" >&2
  exec sudo -E "$0" "$@"
fi

echo "locking CPU frequency governor to performance"
if [[ -d /sys/devices/system/cpu ]]; then
  for gov in /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor; do
    [[ -w "${gov}" ]] || continue
    echo performance > "${gov}"
  done
fi

echo "disabling swap and setting vm.swappiness=0"
swapoff -a || true
sysctl -w vm.swappiness=0
sysctl -w net.core.somaxconn=8192
sysctl -w net.ipv4.tcp_max_syn_backlog=8192
sysctl -w net.core.netdev_max_backlog=8192

echo "dropping filesystem caches so RSS samples start from a cold page cache"
sync
echo 3 > /proc/sys/vm/drop_caches || true

echo "testbed isolation applied"
echo "  swappiness=$(cat /proc/sys/vm/swappiness)"
echo "  somaxconn=$(cat /proc/sys/net/core/somaxconn)"
