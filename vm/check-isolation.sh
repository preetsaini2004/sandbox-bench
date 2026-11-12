#!/usr/bin/env bash
# Preflight: prove the test VM cannot reach the host or the host's network. Run before
# any attack run, and after joining a different network. Exits non-zero on any leak.
#   internet must work; host services, the host's own LAN IP and the gateway must not.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/config.sh"

gw="$(ip -4 route show default | awk '{print $3; exit}')"
hostip="$(ip -4 route get 1.1.1.1 | awk '{for(i=1;i<=NF;i++) if($i=="src") print $(i+1)}')"
bridge_ip="$(virsh net-dumpxml default | sed -n "s/.*<ip address='\([^']*\)'.*/\1/p")"

fail=0
check() {  # check <description> <expect: ok|blocked> <command run inside the VM>
  local desc="$1" expect="$2" cmd="$3" got
  if "$VM_DIR/ssh.sh" "$cmd" >/dev/null 2>&1; then got=ok; else got=blocked; fi
  if [[ "$got" == "$expect" ]]; then echo "PASS  $desc ($got)"; else echo "FAIL  $desc: expected $expect, got $got"; fail=1; fi
}

check "internet reachable"                ok      "curl -s -o /dev/null -m 6 https://example.com"
# "reached" = TCP connect succeeded OR was actively refused (the packet got there).
# A timeout means a firewall dropped it. Ping is not used: UFW's before.rules accept
# forwarded ICMP echo ahead of user rules, so ping reaches the LAN by design (ICMP only).
reached() { printf "python3 -c 'import socket,sys
s=socket.socket(); s.settimeout(3)
try: s.connect((\"%s\",%s))
except socket.timeout: sys.exit(1)
except OSError: pass
'" "$1" "$2"; }
for p in 22 53 80 443; do
  check "gateway $gw tcp/$p dropped"      blocked "$(reached "$gw" "$p")"
done
check "host LAN ip $hostip ssh closed"    blocked "timeout 3 bash -c '</dev/tcp/$hostip/22'"
# Not checked: ping to the host's own IP. UFW's default before.rules accept ICMP echo
# on every interface; it exposes no service and cannot be changed by forward rules.
check "bridge ip $bridge_ip ssh closed"   blocked "timeout 3 bash -c '</dev/tcp/$bridge_ip/22'"
check "private 10.0.0.1 tcp/80 dropped"   blocked "$(reached 10.0.0.1 80)"
check "private 192.168.1.1 tcp/80 dropped" blocked "$(reached 192.168.1.1 80)"

((fail == 0)) && echo "isolation OK" || { echo "ISOLATION BROKEN: do not run attacks. Re-run: sudo ./vm/host-firewall.sh" >&2; exit 1; }
