#!/usr/bin/env bash
# One-time host setup for UFW hosts. Run with: sudo ./vm/host-firewall.sh
#
# UFW drops input and forwarded traffic by default, so the test VM gets no DHCP
# and no internet. These rules let the VM do exactly three things:
#   1. ask the host's dnsmasq for DHCP and DNS (the only host services it may reach),
#   2. reach the public internet (installs, agent API calls),
# and nothing else: no host services, no home LAN, no other private ranges.
# Escape tests run in this VM, so it must not be able to reach the laptop or LAN.
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "run with sudo" >&2; exit 1; }
command -v ufw >/dev/null || { echo "ufw not installed; nothing to do (check your firewall manually)"; exit 0; }

BR="${BR:-virbr0}"

# Host services the VM may use (everything else INPUT from the bridge stays dropped).
ufw allow in on "$BR" to any port 67 proto udp comment 'sbx-bench dhcp'
ufw allow in on "$BR" to any port 53 comment 'sbx-bench dns'

# Forwarded traffic: deny private/LAN ranges FIRST, then allow the rest (internet).
# Order matters: ufw evaluates route rules top to bottom.
for net in 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 169.254.0.0/16 100.64.0.0/10; do
  ufw route deny in on "$BR" to "$net" comment 'sbx-bench no LAN'
done
ufw route allow in on "$BR" comment 'sbx-bench internet'

# The network you are on may use PUBLIC addresses (campus, hotel, some ISPs), which the
# private-range list above does not cover. Block every directly connected subnet of the
# host except the VM bridge itself. `insert 1` puts the deny ABOVE the allow rule.
# Re-run this script whenever you join a different network.
while read -r net dev _; do
  [[ "$dev" == "$BR" || "$dev" == docker* || "$dev" == veth* || "$dev" == lo ]] && continue
  echo "blocking connected subnet $net ($dev)"
  ufw route insert 1 deny in on "$BR" to "$net" comment 'sbx-bench no connected subnet'
done < <(ip -4 route show scope link | awk '{print $1, $3}')

ufw status numbered | grep -i sbx-bench || true
echo "done. To remove later: ufw status numbered, then ufw delete <n> for each sbx-bench rule."
