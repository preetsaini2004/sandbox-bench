#!/usr/bin/env bash
# Run this yourself INSIDE the test VM (./vm/ssh.sh, then paste/run this script).
# Claude's harness blocks it from running downloaded binaries itself. Adapted
# from the official guide: https://github.com/firecracker-microvm/firecracker/
# blob/main/docs/getting-started.md -- pinned to v1.17.0 (latest stable as of
# 2026-11-05) instead of dynamically resolving "latest", per this repo's own
# rule to pin every tool version (see versions.md).
#
# Needs nested KVM (already confirmed on in this VM: /dev/kvm present).
set -euo pipefail
FC_VERSION="v1.17.0"
ARCH="$(uname -m)"
DEST="$HOME/firecracker"
mkdir -p "$DEST" && cd "$DEST"

echo ">> firecracker binary ($FC_VERSION)"
curl -fL "https://github.com/firecracker-microvm/firecracker/releases/download/${FC_VERSION}/firecracker-${FC_VERSION}-${ARCH}.tgz" | tar -xz
mv "release-${FC_VERSION}-$(uname -m)/firecracker-${FC_VERSION}-${ARCH}" ./firecracker
mv "release-${FC_VERSION}-$(uname -m)/jailer-${FC_VERSION}-${ARCH}" ./jailer
chmod +x firecracker jailer

echo ">> kernel + Ubuntu rootfs (Firecracker's CI S3 bucket, per the official guide)"
S3="https://s3.amazonaws.com/spec.ccfc.min"
CI_ARTIFACTS_PREFIX=$(curl -fsSL "$S3?list-type=2&prefix=firecracker-ci/&delimiter=/" \
    | grep -oP "(?<=<Prefix>)firecracker-ci/[0-9]{8}-[^/]+/(?=</Prefix>)" | sort | tail -1)
latest_kernel_key=$(curl -fsSL "$S3?list-type=2&prefix=${CI_ARTIFACTS_PREFIX}${ARCH}/vmlinux-" \
    | grep -oP "(?<=<Key>)(${CI_ARTIFACTS_PREFIX}${ARCH}/vmlinux-[0-9]+\.[0-9]+\.[0-9]{1,3})(?=</Key>)" | sort -V | tail -1)
wget -q "$S3/${latest_kernel_key}"

latest_ubuntu_key=$(curl -fsSL "$S3?list-type=2&prefix=${CI_ARTIFACTS_PREFIX}${ARCH}/ubuntu-" \
    | grep -oP "(?<=<Key>)(${CI_ARTIFACTS_PREFIX}${ARCH}/ubuntu-[0-9]+\.[0-9]+\.squashfs)(?=</Key>)" | sort -V | tail -1)
ubuntu_version=$(basename "$latest_ubuntu_key" .squashfs | grep -oE '[0-9]+\.[0-9]+')
wget -q -O "ubuntu-$ubuntu_version.squashfs.upstream" "$S3/$latest_ubuntu_key"

unsquashfs -q "ubuntu-$ubuntu_version.squashfs.upstream"
ssh-keygen -q -f id_rsa -N ""
cp id_rsa.pub squashfs-root/root/.ssh/authorized_keys
mv id_rsa "./ubuntu-$ubuntu_version.id_rsa"
sudo chown -R root:root squashfs-root
truncate -s 1G "ubuntu-$ubuntu_version.ext4"
sudo mkfs.ext4 -q -d squashfs-root -F "ubuntu-$ubuntu_version.ext4"
sudo chown "$USER" "ubuntu-$ubuntu_version.ext4"

echo
echo "done. In $DEST:"
ls -la firecracker jailer vmlinux-* *.ext4 *.id_rsa
echo
echo "Next: targets/firecracker.py (once Claude writes it) will drive this via"
echo "the API socket, same as the official guide's 'Starting Firecracker' section."
