#!/usr/bin/env bash
# Build the throwaway test VM once. Safe to re-run only after `./vm/destroy.sh`.
# Result: a running VM `sbx-test` and a snapshot called `base`.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/config.sh"

die() { echo "error: $*" >&2; exit 1; }

[[ -e /dev/kvm ]] || die "/dev/kvm missing: enable virtualization in the BIOS"
virsh uri >/dev/null || die "cannot reach libvirt ($LIBVIRT_DEFAULT_URI); is libvirtd running and are you in the libvirt group?"
[[ -d "$SBX_DIR" && -w "$SBX_DIR" ]] || die "$SBX_DIR missing or not writable. Run once:
  sudo install -d -o \"\$USER\" -g libvirt -m 775 $SBX_DIR"
virsh dominfo "$VM_NAME" >/dev/null 2>&1 && die "VM $VM_NAME already exists; run ./vm/destroy.sh first"

# libvirt's default NAT network must be up (VM needs internet for installs).
if [[ "$(virsh net-info default 2>/dev/null | awk '/^Active:/ {print $2}')" != "yes" ]]; then
  virsh net-start default
fi
virsh net-autostart default >/dev/null || true

# 1. Base image, checksum-verified.
base="$SBX_DIR/$UBUNTU_IMG"
if [[ ! -f "$base" ]]; then
  echo ">> downloading $UBUNTU_IMG"
  curl -fL --progress-bar -o "$base.part" "$UBUNTU_URL/$UBUNTU_IMG"
  want="$(curl -fsSL "$UBUNTU_URL/SHA256SUMS" | awk -v f="*$UBUNTU_IMG" '$2 == f {print $1}')"
  got="$(sha256sum "$base.part" | awk '{print $1}')"
  [[ -n "$want" && "$want" == "$got" ]] || { rm -f "$base.part"; die "checksum mismatch for $UBUNTU_IMG"; }
  mv "$base.part" "$base"
  echo "$want  $UBUNTU_IMG" > "$SBX_DIR/$UBUNTU_IMG.sha256"
fi

# 2. VM-only ssh key (never your real key).
if [[ ! -f "$SSH_KEY" ]]; then
  mkdir -p "$(dirname "$SSH_KEY")"; chmod 700 "$(dirname "$SSH_KEY")"
  ssh-keygen -q -t ed25519 -N "" -C "sbx-bench-vm-only" -f "$SSH_KEY"
fi

# 3. cloud-init seed.
tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
sed "s|__SSH_PUBKEY__|$(cat "$SSH_KEY.pub")|" "$VM_DIR/user-data.yaml" > "$tmp/user-data"
cloud-localds "$SBX_DIR/$VM_NAME-seed.iso" "$tmp/user-data"

# 4. Copy-on-write disk on top of the base image.
qemu-img create -q -f qcow2 -F qcow2 -b "$base" "$SBX_DIR/$VM_NAME.qcow2" "${VM_DISK_GB}G"

# 5. Define and start. BIOS boot (not UEFI) so internal snapshots work.
virt-install --name "$VM_NAME" --memory "$VM_RAM_MB" --vcpus "$VM_VCPUS" \
  --cpu host-passthrough --osinfo ubuntu24.04 --import \
  --disk "path=$SBX_DIR/$VM_NAME.qcow2,format=qcow2,bus=virtio" \
  --disk "path=$SBX_DIR/$VM_NAME-seed.iso,device=cdrom" \
  --network network=default --graphics none --noautoconsole

echo ">> waiting for ssh and cloud-init (first boot installs packages)"
ip="$(wait_for_ssh 300)" || die "VM did not become reachable over ssh"
ssh "${SSH_OPTS[@]}" "bench@$ip" 'cloud-init status --wait' || die "cloud-init failed; see: ./vm/ssh.sh 'cat /var/log/cloud-init-output.log'"

# 6. Baseline snapshot (before any targets are installed).
virsh snapshot-create-as "$VM_NAME" base --description "fresh Ubuntu 24.04, no targets"
echo ">> done. VM $VM_NAME at $ip, snapshot 'base' taken."
echo ">> next: install targets, then ./vm/snapshot.sh clean"
