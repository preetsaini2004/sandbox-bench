#!/usr/bin/env bash
# Shared settings for the throwaway test VM. Sourced by the other vm/*.sh scripts.
# Attacks run ONLY inside this VM, never on the host.

export LIBVIRT_DEFAULT_URI="qemu:///system"

VM_NAME="${VM_NAME:-sbx-test}"
VM_RAM_MB="${VM_RAM_MB:-6144}"     # host has 14 GB; leave room for the host
VM_VCPUS="${VM_VCPUS:-4}"
VM_DISK_GB="${VM_DISK_GB:-40}"

# One-time: `sudo install -d -o "$USER" -g libvirt -m 775 /var/lib/libvirt/images/sbx`
# libvirt's qemu user cannot read $HOME, so disks live under libvirt's image dir.
SBX_DIR="${SBX_DIR:-/var/lib/libvirt/images/sbx}"

UBUNTU_URL="https://cloud-images.ubuntu.com/noble/current"
UBUNTU_IMG="noble-server-cloudimg-amd64.img"

VM_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SSH_KEY="$VM_DIR/.ssh/id_ed25519"           # VM-only key, gitignored
SSH_OPTS=(-i "$SSH_KEY" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null
          -o LogLevel=ERROR -o ConnectTimeout=3 -o IdentitiesOnly=yes)

vm_ip() {
  # The lease record can expire while the VM keeps its address, so fall back to ARP.
  local src ip
  for src in lease arp; do
    ip="$(virsh domifaddr "$VM_NAME" --source "$src" 2>/dev/null \
      | awk '/ipv4/ {split($4, a, "/"); print a[1]; exit}')"
    [[ -n "$ip" ]] && { echo "$ip"; return 0; }
  done
  return 1
}

# Wait until ssh as the admin user works. Prints the IP. Returns 1 on timeout.
wait_for_ssh() {
  local timeout="${1:-180}" ip i
  for ((i = 0; i < timeout; i++)); do
    ip="$(vm_ip)"
    if [[ -n "$ip" ]] && ssh "${SSH_OPTS[@]}" "bench@$ip" true 2>/dev/null; then
      echo "$ip"; return 0
    fi
    sleep 1
  done
  return 1
}
