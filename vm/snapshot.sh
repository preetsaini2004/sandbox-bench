#!/usr/bin/env bash
# Take (or replace) a named snapshot of the running VM. Usage: ./vm/snapshot.sh clean
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/config.sh"

snap="${1:?usage: snapshot.sh <name>}"
wait_for_ssh 60 >/dev/null || { echo "error: VM not reachable" >&2; exit 1; }
virsh snapshot-delete "$VM_NAME" "$snap" >/dev/null 2>&1 || true
virsh snapshot-create-as "$VM_NAME" "$snap" --description "${2:-$snap}"
virsh snapshot-list "$VM_NAME"
