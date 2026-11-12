"""E2B adapter. Different from every other target in this repo: E2B sandboxes
run on E2B's own cloud infrastructure, not inside our VM.

Scope is deliberately narrower than Docker/gVisor/Firecracker: only network
attacks (attacks/scripted/network_*) are appropriate here. An "escape" attack
against E2B would mean trying to break into E2B's own production
infrastructure -- that is not ours to test, even for measurement, and would
be unauthorized access against a third party, not a benign benchmark. Do not
point escape_docker_socket/escape_device_access-style attacks at this target.

Requires E2B_API_KEY in the environment (see .env -- gitignored, never
committed). `config`, when given, is passed straight through as additional
keyword arguments to Sandbox.create() (e.g. {"allow_internet_access": False}
as a negative control proving the attack/measurement actually works when
E2B's own network policy truly blocks egress) -- there is no hand-enumerated
set of knobs here the way there is for Docker/gVisor, since this isn't a
misconfiguration we constructed, it's E2B's own real default posture under
test.

Network attacks against this target need the attacker listener reachable
from the public internet (E2B's sandboxes cannot reach our VM-only private
listener) -- see vm/e2b-tunnel.sh, which you run yourself; Claude's harness
is blocked from opening that tunnel itself (see the session's own notes).
"""
from __future__ import annotations

import os
import time

from e2b import Sandbox, SandboxQuery
from e2b.sandbox.commands.command_handle import CommandExitException

if __package__:
    from .base import RunResult, Target
else:  # also support importing from the targets directory directly
    from base import RunResult, Target

_METADATA_TAG = {"sbx-bench": "true"}


class E2BTarget(Target):
    name = "e2b"

    def __init__(self) -> None:
        super().__init__()  # the VM guard: this orchestrates from inside the VM,
                             # even though the sandbox itself runs on E2B's cloud
        if not os.environ.get("E2B_API_KEY"):
            raise RuntimeError("E2B_API_KEY is not set (see .env)")
        self._sandbox: Sandbox | None = None

    def start(self, config: dict | None = None) -> None:
        if self._sandbox is not None:
            raise RuntimeError("target already has a sandbox; call stop() before start()")
        kwargs = dict(config) if config else {}
        kwargs.setdefault("timeout", 180)
        try:
            self._sandbox = Sandbox.create(metadata=_METADATA_TAG, **kwargs)
        except Exception as exc:
            raise RuntimeError(f"failed to create E2B sandbox: {exc}") from exc

    def run(self, command: str, timeout: float = 30) -> RunResult:
        if self._sandbox is None:
            raise RuntimeError("E2B target has not been started")
        started = time.monotonic()
        try:
            result = self._sandbox.commands.run(command, timeout=timeout)
            return RunResult(
                exit_code=result.exit_code,
                stdout=result.stdout or "",
                stderr=result.stderr or "",
                duration_s=time.monotonic() - started,
            )
        except CommandExitException as exc:
            # Non-zero exit raises in this SDK; it's still a completed run, not
            # a harness error, so treat it as a normal (non-zero) RunResult.
            return RunResult(
                exit_code=exc.exit_code,
                stdout=exc.stdout or "",
                stderr=exc.stderr or "",
                duration_s=time.monotonic() - started,
            )
        except TimeoutError:
            return RunResult(
                exit_code=-9, stdout="", stderr="command timed out",
                duration_s=time.monotonic() - started, timed_out=True,
            )

    def stop(self) -> None:
        if self._sandbox is None:
            return
        try:
            self._sandbox.kill()
        except Exception:
            pass  # already gone is an expected outcome, not an error
        self._sandbox = None

    def reset(self) -> None:
        """Kill only sandboxes tagged with our metadata -- never anything else
        on this E2B account. Filtered server-side (SandboxQuery), so this is
        safe to call even on an account with other, unrelated sandboxes
        running. Covers the case where a crash skipped stop()."""
        self.stop()
        try:
            paginator = Sandbox.list(query=SandboxQuery(metadata=_METADATA_TAG))
            while True:
                for info in paginator.next_items():
                    try:
                        Sandbox.kill(info.sandbox_id)
                    except Exception:
                        pass
                if not paginator.has_next:
                    break
        except Exception:
            pass
