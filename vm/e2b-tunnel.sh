#!/usr/bin/env bash
# Run this YOURSELF, on the LAPTOP (not inside the VM) -- Claude's harness blocks
# it from opening an inbound tunnel itself, deliberately (opening a path from
# the public internet into this machine is the kind of thing that should stay
# in your hands). Only needed while actually running an E2B network-exfil test;
# kill it immediately after (Ctrl-C) -- it's the only target whose attacks need
# a listener reachable from the public internet, since E2B's sandboxes run on
# E2B's own cloud, not inside our private VM.
#
# Architecture: the listener (harness/listener.py) must bind 0.0.0.0 for this
# run (not the Docker bridge gateway it normally uses for Docker/gVisor), so
# it's reachable both from containers AND from the laptop at the VM's libvirt
# address. cloudflared runs HERE on the laptop (already installed) and points
# straight at that VM address -- it is NOT reachable from the Docker bridge
# gateway IP (172.17.0.1), which only exists inside the VM's own network
# namespace.
#
# Usage:
#   1. Start the listener inside the VM bound to 0.0.0.0 (Claude will tell you
#      the exact run-id/command when it's ready to run an E2B test).
#   2. Run this script here on the laptop. It prints a https://*.trycloudflare.com
#      URL -- give that to Claude.
#   3. When the run is done: Ctrl-C here to close the tunnel.
#
# cloudflared's "quick tunnel" needs no account, no domain, no config -- it's
# an outbound-only connection to Cloudflare's edge, so this works regardless
# of any router/NAT situation on this network.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"
source config.sh
VM_IP="$(vm_ip)"
PORT="${1:-18080}"
[ -n "$VM_IP" ] || { echo "error: VM has no IP (is it running? ./vm/ssh.sh to check)" >&2; exit 1; }
echo "Tunneling https://<random>.trycloudflare.com -> $VM_IP:$PORT (the VM's listener)"
cloudflared tunnel --url "http://$VM_IP:$PORT"
