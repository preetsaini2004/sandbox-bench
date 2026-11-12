"""nono adapter. Architecturally different from Docker/gVisor/E2B: nono does not
virtualize a filesystem or create a persistent container -- `nono run` wraps
and restricts ONE already-running OS process tree via Landlock (+ seccomp),
directly on this VM's real filesystem and real network. There is no separate
rootfs, so there is no pinned base image, and no container to "escape" from in
the Docker-socket/device-access sense -- skip escape-category attacks here.

This also means the planted canary FILES (harness/canaries.py: ~/.aws/credentials,
~/.ssh/id_ed25519, ~/secrets/.env, ~/secrets/github.txt) are directly reachable
on the real filesystem, unlike Docker/gVisor where they had to be worked around
via /proc/<pid>/environ tricks -- see attacks/scripted/read_canary_files.py.

Because `nono run` is one-shot (launch, wait, exit), start()/stop() don't map
to "create/destroy a container" the way they do for Docker/gVisor. start()
just records this run's config; every run() call is an independent `nono run`
invocation sharing that config -- which matches how nono is actually used in
practice (wrap one process at a time), rather than forcing a container-shaped
lifecycle onto a tool that doesn't have one.

config is a generic passthrough of extra `nono run` CLI flags (a list of
strings), e.g. ["--block-net"] or ["--allow", "/some/path"] -- there is no
hand-enumerated knob set the way Docker/gVisor have, since nono's own flag
surface already names exactly what it restricts.
"""
from __future__ import annotations

import subprocess
import time
import uuid
from pathlib import Path

if __package__:
    from .base import RunResult, Target
else:  # also support importing from the targets directory directly
    from base import RunResult, Target

# Absolute path, NOT a bare "nono" looked up on PATH. vm/setup-nono.sh installs
# to ~/.local/bin and adds it to PATH via ~/.bashrc, but found live (while
# wiring up targets/firecracker.py and re-running this adapter): ~/.bashrc's
# very first lines return immediately for a non-interactive shell, which is
# exactly what `ssh host "command"` runs -- harness/run.py's own invocation
# style. So ~/.local/bin was never actually reliably on PATH here; depending
# on it was a latent bug, not something that happened to work by accident
# every time before. openshell.py doesn't need this fix: that binary installs
# to /usr/bin, already on the default non-interactive PATH.
_NONO_BIN = str(Path.home() / ".local" / "bin" / "nono")
_SESSION_PREFIX = "sbx-nono-"


class NonoTarget(Target):
    name = "nono"

    def __init__(self) -> None:
        super().__init__()
        self._extra_flags: list[str] = []
        self._started = False

    def start(self, config: dict | None = None) -> None:
        if self._started:
            raise RuntimeError("target already started; call stop() before start()")
        if config is not None:
            flags = config.get("flags", []) if isinstance(config, dict) else config
            if not isinstance(flags, list) or any(not isinstance(f, str) for f in flags):
                raise ValueError("nono config must be {'flags': [str, ...]} or a list of str")
            self._extra_flags = list(flags)
        else:
            self._extra_flags = []
        # Nothing to actually launch yet -- nono has no "create an empty
        # sandbox" concept; confirm the binary itself is at least present and
        # runnable so a broken install fails loudly as 'broken', not silently.
        probe = subprocess.run([_NONO_BIN, "--version"], capture_output=True, text=True, timeout=10)
        if probe.returncode != 0:
            raise RuntimeError(f"nono --version failed: {probe.stderr.strip()}")
        self._started = True

    def run(self, command: str, timeout: float = 30) -> RunResult:
        if not self._started:
            raise RuntimeError("nono target has not been started")
        session_name = _SESSION_PREFIX + uuid.uuid4().hex[:16]
        args = [
            _NONO_BIN, "--silent", "run",
            "--no-rollback", "--no-audit", "--name", session_name,
            # --allow-cwd: nono requires this just to start a process at all in
            # non-interactive mode, regardless of what the process then does --
            # not itself part of what any attack is testing, so it's a baseline
            # default rather than something attacks opt into via config.
            "--allow-cwd",
            *self._extra_flags, "--", "sh", "-c", command,
        ]
        started = time.monotonic()
        try:
            result = subprocess.run(
                args, capture_output=True, text=True,
                timeout=timeout, encoding="utf-8", errors="replace",
            )
            return RunResult(
                exit_code=result.returncode, stdout=result.stdout, stderr=result.stderr,
                duration_s=time.monotonic() - started,
            )
        except subprocess.TimeoutExpired as exc:
            # Found live: despite text=True above, subprocess.run()'s partial
            # output on a timeout can come back as bytes on exc.stdout/stderr
            # rather than the decoded str the non-timeout path returns --
            # callers (run_injection.py) assumed str and crashed trying to
            # concatenate stdout+stderr ("can't concat str to bytes"),
            # silently masking a real timeout as an unrelated-looking
            # exception. Decode defensively so RunResult's contract (str,
            # always) holds on both paths.
            def _decode(v):
                return v.decode("utf-8", errors="replace") if isinstance(v, bytes) else (v or "")
            return RunResult(
                exit_code=-9, stdout=_decode(exc.stdout), stderr=_decode(exc.stderr),
                duration_s=time.monotonic() - started, timed_out=True,
            )
        except OSError as exc:
            raise RuntimeError(f"could not execute nono: {exc}") from exc

    def stop(self) -> None:
        # Nothing persistent to tear down -- each run() already exited.
        self._started = False

    def reset(self) -> None:
        """Defensive cleanup: stop any session left behind under our naming
        prefix, in case a previous run() was killed before it could exit
        cleanly. Safe to call with nothing to clean up."""
        self.stop()
        try:
            listing = subprocess.run(
                [_NONO_BIN, "--silent", "ps"], capture_output=True, text=True, timeout=10,
            )
            for line in listing.stdout.splitlines():
                name = line.split()[0] if line.strip() else ""
                if name.startswith(_SESSION_PREFIX):
                    subprocess.run(
                        [_NONO_BIN, "--silent", "stop", name],
                        capture_output=True, timeout=10,
                    )
        except Exception:
            pass
