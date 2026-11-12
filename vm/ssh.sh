#!/usr/bin/env bash
# ssh into the test VM. Usage: ./vm/ssh.sh [command...]   (user: bench; set VM_USER=agent for the unprivileged user)
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/config.sh"

ip="$(vm_ip)"; [[ -n "$ip" ]] || { echo "error: VM has no IP (is it running?)" >&2; exit 1; }
exec ssh "${SSH_OPTS[@]}" "${VM_USER:-bench}@$ip" "$@"
