"""Shared contract for sandbox target adapters (LINUX.md section 3).

A target represents ONE sandbox technology (Docker, gVisor, ...), running inside
the test VM under the unprivileged `agent` account. One instance = one long-lived
sandboxed container; attack scripts run inside it via run(), possibly several
times across one start()/stop() lifecycle.

Safety: this file duplicates harness/vm_guard.py's check on purpose, instead of
importing across the harness/targets package boundary, so every target adapter
is a self-contained script. Never run outside the test VM -- see LINUX.md,
"the one rule that matters". Every concrete Target refuses in __init__ unless
SBX_BENCH_CONFIRM_VM=1 is set and the hostname matches (default "sbx-test").
"""
from __future__ import annotations

import os
import socket
from abc import ABC, abstractmethod
from dataclasses import dataclass


def require_vm(reason: str) -> None:
    if os.environ.get("SBX_BENCH_CONFIRM_VM") != "1":
        raise SystemExit(
            f"refusing to {reason}: SBX_BENCH_CONFIRM_VM=1 is not set.\n"
            "Run only inside the test VM (see LINUX.md 'the one rule that matters')."
        )
    expected = os.environ.get("SBX_BENCH_VM_HOSTNAME", "sbx-test")
    actual = socket.gethostname()
    if actual != expected:
        raise SystemExit(
            f"refusing to {reason}: hostname is {actual!r}, expected {expected!r}. "
            "This looks like it is not the test VM."
        )


@dataclass
class RunResult:
    exit_code: int
    stdout: str
    stderr: str
    duration_s: float
    timed_out: bool = False


class Target(ABC):
    """One sandbox technology. Concrete subclasses: targets/docker.py's DockerTarget,
    targets/gvisor.py's GvisorTarget. Both must behave identically from the outside
    -- same constructor, same method signatures, same RunResult shape -- so
    harness/run.py (not yet written) can swap one for the other without caring
    which it's driving.
    """

    name: str  # e.g. "docker", "gvisor"

    def __init__(self) -> None:
        require_vm(f"start {self.__class__.__name__}")

    @abstractmethod
    def start(self, config: dict | None = None) -> None:
        """Launch a fresh sandbox instance. `config` carries THIS ATTACK's required
        (mis)configuration, e.g.:
            {"privileged": True}
            {"volumes": {"/var/run/docker.sock": "/var/run/docker.sock"}}
            {"pid_mode": "host", "cap_add": ["SYS_PTRACE"]}
            {"network_mode": "none"}
            {"image": "docker:27-cli"}  # override the default pinned base image,
                                         # e.g. when an attack needs a tool (the
                                         # Docker CLI, to speak to a mounted socket)
                                         # that the default minimal image lacks
        An empty/None config means the sandbox's default, intentionally-safe
        configuration -- this is the negative control and must NOT be exploitable
        by the same attacks the misconfigured variants are vulnerable to.
        Must raise RuntimeError (not silently continue) if the instance fails to
        come up healthy -- a run that can't prove it started is 'broken', never
        'blocked' (see harness/score.py).
        """

    @abstractmethod
    def run(self, command: str, timeout: float = 30) -> RunResult:
        """Run `command` (a shell command string, executed via `sh -c`) inside the
        already-started sandbox. Must enforce `timeout` itself (kill and return
        timed_out=True rather than hanging run.py forever -- the target could be
        unresponsive after a successful escape or crash attack, and that is itself
        a valid, expected outcome to capture, not a harness bug).
        """

    @abstractmethod
    def stop(self) -> None:
        """Tear down the instance started by start(). Must not raise if it's
        already gone (e.g. an escape or crash attack killed it, or it was never
        started) -- that is an expected outcome, not an error. Log and return."""

    @abstractmethod
    def reset(self) -> None:
        """Force-cleanup for resources THIS target itself might have left behind
        (e.g. `docker rm -f` any container/volume tagged for this target's runs),
        independent of whether stop() ran cleanly. Idempotent: safe to call with
        nothing to clean up. This is NOT the VM-level snapshot revert -- see
        vm/reset.sh, which is the authoritative "back to a known-clean state" and
        is called by harness/run.py between attack classes, not by this method.
        """
