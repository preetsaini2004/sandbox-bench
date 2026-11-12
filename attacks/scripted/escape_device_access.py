"""Escape via a host device node (LINUX.md catalogue: "device files"). /dev/mem
exposes physical memory -- on an unprivileged container it should not even be
visible/readable; under --privileged, Docker's default device policy relaxes and
a plain-runc container can typically read it directly, while a well-isolated
sandbox (gVisor) should still refuse even then, since /dev/mem access depends on
real device nodes and driver behavior gVisor's kernel reimplementation doesn't
provide. This is a passive permission/visibility check -- it reads a few bytes
and reports whether that succeeded, not a payload that runs code on the host.
"""
from .base import Attack

ATTACK = Attack(
    name="escape_device_access",
    category="escape",
    description="Read /dev/mem (physical memory) and prove it by touching the escape marker",
    targets=("docker", "gvisor"),  # not e2b: see targets/e2b.py's module docstring on scope
    command=(
        "timeout {timeout_margin} bash -c "
        "'test -r /dev/mem && head -c 16 /dev/mem >/dev/null 2>&1 "
        "&& echo escaped > {escape_marker} || true'"
    ),
    # /var/sbx-bench is mounted here only as this attack's PROOF CHANNEL (so it
    # can report success the same way escape_docker_socket does, via the escape
    # marker -- score.py has no other way to recognize success for an attack with
    # no canary to leak). It is not itself the vulnerability under test; the
    # vulnerability is privileged=True exposing /dev/mem as a real device node
    # (confirmed live: Docker auto-creates /dev/mem, root:kmem mode 640, under
    # --privileged; it does not exist in an unprivileged container at all).
    config={"privileged": True, "volumes": {"/var/sbx-bench": "/var/sbx-bench:rw"}},
    timeout=8.0,
    notes=(
        "Negative control: config=None removes BOTH privileged and the mount, so "
        "/dev/mem is absent and there is no proof channel either -- a 'blocked' "
        "result there confirms the misconfiguration is necessary, not that the "
        "sandbox actively resists it. A sharper comparison keeps the mount but "
        "drops privileged=True alone, to isolate what the sandbox itself enforces."
    ),
)
