"""OpenShell adapter. OpenShell is a policy-governed sandbox runtime: a local
mTLS gateway (127.0.0.1:17670) drives a `sandbox create/exec/delete` lifecycle
that maps directly onto this file's Target contract.

Verified live on sbx-test (0.1.7) before writing this: `sandbox create` gives
each sandbox its own rootfs (an nvcr.io/nvidia/base/ubuntu:24.04 container) --
host files are NOT visible (planted canary files under ~/.aws, ~/secrets etc.
give "No such file or directory", not "Permission denied" -- they are simply
absent, unlike nono which wraps the real host filesystem). `openshell policy
get --full` shows OpenShell's own default policy is deny-by-default on BOTH
axes: filesystem (`read_only`/`read_write` allow-lists, nothing else reachable)
and network (plain TCP/UDP connect from inside a sandbox returns `Permission
denied` straight from bash's /dev/tcp, with no explicit `--block-net` needed --
the opposite default from nono). No docker socket or privileged devices are
exposed inside a default sandbox either. Given this, only the network-exfil
attacks apply here for now; there is nothing a Docker-socket- or
device-access-style escape attack could target without first knowing what a
permissive `--policy` YAML looks like, which has not been explored yet -- see
PROGRESS.md.

Attempted one quick positive control on the network block, to check it's a
real configurable policy and not some unrelated failure: `openshell policy
update <name> --add-endpoint 'HOST:PORT:full' --wait` applied and loaded
cleanly (confirmed via `policy get`), but a raw `/dev/tcp` connect from inside
the sandbox was still denied afterward. The CLI's endpoint/allow-rule system
is clearly L7-aware (host:port:access:protocol, METHOD/path glob rules,
per-binary scoping -- see `policy update --help`), so it most likely governs
an egress proxy layer rather than the raw socket syscall path, which would
mean a *proxy-aware* client might get through where a raw /dev/tcp socket
cannot -- not confirmed either way given the time spent here. Documented
honestly rather than claimed: this adapter's "blocked" results are a real,
reproducible permission denial (not a wiring bug -- the control action proves
the sandbox genuinely runs commands), but the exact mechanism/escape hatch for
network policy is not yet fully mapped.

config is a generic passthrough of extra `sandbox create` CLI flags (a list of
strings), the same approach as targets/nono.py and for the same reason:
OpenShell's own flag surface (particularly `--policy <path>`) already names
exactly what it restricts, so there is no separate hand-enumerated knob set.

`sandbox exec --timeout <seconds>` is enforced by the gateway itself (verified:
a 2s timeout against `sleep 10` returns in ~2.1s with exit code 124, partial
stdout intact) -- no Docker-style exec-completion marker trick is needed here.

The gateway occasionally returns a transient "connect error: transport error"
on an otherwise-healthy sandbox (seen a few times live, unrelated to load);
callers that need to tell a real failure from a blip should retry once before
treating `run()` raising as a 'broken' verdict.
"""
from __future__ import annotations

import json
import subprocess
import time
import uuid

if __package__:
    from .base import RunResult, Target
else:  # also support importing from the targets directory directly
    from base import RunResult, Target

_OPENSHELL_BIN = "openshell"
# OpenShell sandbox names are capped at 19 characters (verified live: a 30-char
# name is rejected with "name exceeds maximum length (30 > 19)", not documented
# in --help). 7 + 12 hex chars stays comfortably under that.
_SESSION_PREFIX = "sbx-os-"
_CLI_TIMEOUT = 30.0
_START_TIMEOUT = 120.0


class OpenShellTarget(Target):
    name = "openshell"

    def __init__(self) -> None:
        super().__init__()
        self._sandbox_name: str | None = None

    def start(self, config: dict | None = None) -> None:
        if self._sandbox_name is not None:
            raise RuntimeError("target already has a sandbox; call stop() before start()")
        if config is not None:
            flags = config.get("flags", []) if isinstance(config, dict) else config
            if not isinstance(flags, list) or any(not isinstance(f, str) for f in flags):
                raise ValueError("openshell config must be {'flags': [str, ...]} or a list of str")
        else:
            flags = []
        name = _SESSION_PREFIX + uuid.uuid4().hex[:12]
        self._sandbox_name = name
        try:
            result = subprocess.run(
                [_OPENSHELL_BIN, "sandbox", "create", "--name", name, "--detach", "--no-tty",
                 "-o", "json", *flags, "--", "sleep", "infinity"],
                capture_output=True, text=True, timeout=_START_TIMEOUT,
            )
            if result.returncode != 0:
                raise RuntimeError(f"sandbox create failed: {result.stderr.strip() or result.stdout.strip()}")
            # "Provisioning sandbox (structured output on stdout)..." precedes the
            # JSON object on its own banner line; take everything from the first '{'.
            payload = result.stdout[result.stdout.index("{"):]
            state = json.loads(payload)
            if state.get("phase") != "Ready":
                raise RuntimeError(f"sandbox {name} did not reach Ready: phase={state.get('phase')!r}")
        except Exception as exc:
            self.stop()
            raise RuntimeError(f"failed to start OpenShell sandbox {name}: {exc}") from exc

    def run(self, command: str, timeout: float = 30) -> RunResult:
        if self._sandbox_name is None:
            raise RuntimeError("OpenShell target has not been started")
        args = [
            _OPENSHELL_BIN, "sandbox", "exec", self._sandbox_name, "--no-tty",
            "--timeout", str(int(timeout)), "--", "sh", "-c", command,
        ]
        started = time.monotonic()
        try:
            result = subprocess.run(
                args, capture_output=True, text=True,
                timeout=timeout + 15, encoding="utf-8", errors="replace",
            )
            duration = time.monotonic() - started
            # The gateway's own --timeout enforces the deadline server-side and
            # returns exit 124 (verified live), so no local kill/marker is needed;
            # the generous local subprocess timeout above is only a backstop for a
            # stuck gateway connection, not the attack's real timeout enforcement.
            return RunResult(
                exit_code=result.returncode, stdout=result.stdout, stderr=result.stderr,
                duration_s=duration, timed_out=(result.returncode == 124),
            )
        except subprocess.TimeoutExpired as exc:
            return RunResult(
                exit_code=-9, stdout=exc.stdout or "", stderr=exc.stderr or "",
                duration_s=time.monotonic() - started, timed_out=True,
            )
        except OSError as exc:
            raise RuntimeError(f"could not execute openshell: {exc}") from exc

    def stop(self) -> None:
        if self._sandbox_name is None:
            return
        try:
            subprocess.run(
                [_OPENSHELL_BIN, "sandbox", "delete", self._sandbox_name],
                capture_output=True, timeout=_CLI_TIMEOUT,
            )
        except Exception:
            pass
        self._sandbox_name = None

    def reset(self) -> None:
        """Defensive cleanup: delete any sandbox left behind under our naming
        prefix (e.g. a crashed run that never reached stop()). Safe to call with
        nothing to clean up."""
        self.stop()
        try:
            listing = subprocess.run(
                [_OPENSHELL_BIN, "sandbox", "list", "--names"],
                capture_output=True, text=True, timeout=_CLI_TIMEOUT,
            )
            for name in listing.stdout.splitlines():
                name = name.strip()
                if name.startswith(_SESSION_PREFIX):
                    subprocess.run(
                        [_OPENSHELL_BIN, "sandbox", "delete", name],
                        capture_output=True, timeout=_CLI_TIMEOUT,
                    )
        except Exception:
            pass
