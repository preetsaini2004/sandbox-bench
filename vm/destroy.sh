#!/usr/bin/env bash
# Delete the test VM, its snapshots and its disk (keeps the downloaded base image).
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/config.sh"

read -r -p "Delete VM $VM_NAME and its disk? [y/N] " ans
[[ "$ans" == "y" ]] || exit 1
virsh destroy "$VM_NAME" 2>/dev/null || true
virsh undefine "$VM_NAME" --snapshots-metadata 2>/dev/null || true
rm -f "$SBX_DIR/$VM_NAME.qcow2" "$SBX_DIR/$VM_NAME-seed.iso"
echo "removed $VM_NAME"
