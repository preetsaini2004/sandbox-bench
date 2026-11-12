#!/usr/bin/env bash
# Revert the test VM to a snapshot (default: week3) and time it.
# Plan requirement: reset in under 60 s.
# week3 = clean + the injection harness, opencode and its nono profile. Reverting to
# `clean` (2026-11-06) wipes all of that, which happened once already.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/config.sh"

snap="${1:-week3}"
start="$(date +%s.%N)"
virsh snapshot-revert "$VM_NAME" "$snap" --running --force
ip="$(wait_for_ssh 120)" || { echo "error: VM not reachable after revert" >&2; exit 1; }
elapsed="$(awk -v s="$start" -v e="$(date +%s.%N)" 'BEGIN {printf "%.1f", e - s}')"
echo "reset to '$snap' in ${elapsed}s (ip $ip)"
awk -v t="$elapsed" 'BEGIN {exit !(t > 60)}' && echo "warning: slower than the 60 s target" >&2 || true
