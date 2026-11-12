"""gVisor adapter; all Docker operations are gated by Target's VM guard."""

from __future__ import annotations

import json
import logging
import math
import subprocess
import time
import uuid

if __package__:
    from .base import RunResult, Target
else:  # Also support importing from the targets directory directly.
    from base import RunResult, Target


_LOG = logging.getLogger(__name__)


class GvisorTarget(Target):
    """One long-lived runsc container, driven exclusively through the Docker CLI."""

    _PREFIX = "sbx-gvisor-"
    # Explicit release tag, never "latest". Coreutils supplies the exec watchdog.
    _IMAGE = "ubuntu:24.04"
    _CLI_TIMEOUT = 10.0
    _START_TIMEOUT = 180.0
    _EXEC_GRACE = 1.0

    def __init__(self) -> None:
        self.name = "gvisor"
        super().__init__()
        self._container_name: str | None = None

    @staticmethod
    def _docker(args: list[str], timeout: float) -> subprocess.CompletedProcess:
        try:
            result = subprocess.run(
                ["docker", *args], capture_output=True, text=True,
                encoding="utf-8", errors="replace", timeout=timeout,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise RuntimeError(f"docker {args[0]} failed: {exc}") from exc
        if result.returncode:
            detail = result.stderr.strip() or result.stdout.strip()
            raise RuntimeError(f"docker {args[0]} failed ({result.returncode}): {detail}")
        return result

    @staticmethod
    def _config_args(config: dict) -> list[str]:
        args: list[str] = []
        if not isinstance(config.get("privileged", False), bool):
            raise ValueError("privileged must be a bool")
        if config.get("privileged", False):
            args.append("--privileged")

        volumes = config.get("volumes", {})
        if not isinstance(volumes, dict):
            raise ValueError("volumes must map host paths to container paths")
        for host, destination in volumes.items():
            # Accept /destination[:ro|rw], or Docker's {bind: ..., mode: ...} form.
            mode = "ro"
            if isinstance(destination, dict):
                mode = destination.get("mode", "ro")
                destination = destination.get("bind")
            elif isinstance(destination, str) and ":" in destination:
                destination, mode = destination.rsplit(":", 1)
            if (not isinstance(host, str) or not host.startswith("/")
                    or ":" in host or not isinstance(destination, str)
                    or not destination.startswith("/") or ":" in destination
                    or mode not in ("ro", "rw")):
                raise ValueError("volumes require absolute paths and a ro or rw mode")
            args.extend(["--volume", f"{host}:{destination}:{mode}"])

        caps = config.get("cap_add", [])
        if not isinstance(caps, list) or any(not isinstance(cap, str) or not cap for cap in caps):
            raise ValueError("cap_add must be a list of nonempty strings")
        for cap in caps:
            args.extend(["--cap-add", cap])
        for key, flag in (("pid_mode", "--pid"), ("network_mode", "--network")):
            if key in config:
                if not isinstance(config[key], str) or not config[key]:
                    raise ValueError(f"{key} must be a nonempty string")
                args.extend([flag, config[key]])
        if "image" in config and (not isinstance(config["image"], str) or not config["image"]):
            raise ValueError("image must be a nonempty string")
        unknown = config.keys() - {"privileged", "volumes", "cap_add", "pid_mode", "network_mode", "image"}
        if unknown:
            raise ValueError(f"unsupported configuration keys: {sorted(unknown)}")
        return args

    def start(self, config: dict | None = None) -> None:
        """Launch and probe a fresh container with this attack's configuration."""
        if self._container_name is not None:
            raise RuntimeError("target already has a container; call stop() before start()")
        if config is not None and not isinstance(config, dict):
            raise ValueError("config must be a dict or None")
        config = config if config is not None else {}
        args = self._config_args(config)
        image = config.get("image", self._IMAGE)
        name = self._PREFIX + uuid.uuid4().hex[:16]
        # Record before launch so even a failed/partially completed run is removable.
        self._container_name = name
        try:
            self._docker(
                ["run", "-d", "--runtime=runsc", "--name", name, *args,
                 image, "sleep", "infinity"],
                self._START_TIMEOUT,
            )
            state = json.loads(self._docker(
                ["inspect", "--format", "{{json .State}}", name], self._CLI_TIMEOUT,
            ).stdout)
            if not state.get("Running") or state.get("Health", {}).get("Status", "healthy") != "healthy":
                raise RuntimeError(f"container {name} is not healthy: {state}")
            self._docker(
                ["exec", name, "sh", "-c", "command -v timeout >/dev/null && :"],
                self._CLI_TIMEOUT,
            )
        except Exception as exc:
            self.stop()
            raise RuntimeError(f"failed to start gVisor container {name}: {exc}") from exc

    def run(self, command: str, timeout: float = 30) -> RunResult:
        """Execute via sh -c; kill the exec's process group when time expires.

        A host deadline also handles a stuck Docker daemon/runtime. In that case
        the container is force-removed if possible and must be started again.
        """
        if self._container_name is None:
            raise RuntimeError("gVisor target has not been started")
        if not isinstance(command, str):
            raise TypeError("command must be a string")
        if not math.isfinite(timeout) or timeout <= 0:
            raise ValueError("timeout must be positive and finite")

        marker = "sbx-exec-" + uuid.uuid4().hex
        # This wrapper survives normal shell exits, including exit 124/137. Its
        # trailer distinguishes those exits from the watchdog killing the group.
        wrapper = ('sh -c "$1"; status=$?; '
                   'printf "\\n%s:%s\\n" "$2" "$status" >&2; exit "$status"')
        args = [
            "docker", "exec", self._container_name, "sh", "-c",
            'exec timeout -s KILL "$1" sh -c "$2" sbx-exec "$3" "$4"',
            "sbx-exec", f"{timeout}s", wrapper, command, marker,
        ]
        started = time.monotonic()
        try:
            process = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        except OSError as exc:
            raise RuntimeError(f"could not execute docker: {exc}") from exc
        timed_out = False
        try:
            stdout, stderr = process.communicate(timeout=timeout + self._EXEC_GRACE)
        except subprocess.TimeoutExpired:
            timed_out = True
            # Killing the CLI alone does NOT kill an exec inside the container.
            process.kill()
            try:
                stdout, stderr = process.communicate(timeout=self._EXEC_GRACE)
            except subprocess.TimeoutExpired as exc:
                stdout, stderr = exc.output or b"", exc.stderr or b""
                if process.stdout is not None:
                    process.stdout.close()
                if process.stderr is not None:
                    process.stderr.close()
            self.stop()

        trailer = f"\n{marker}:".encode()
        position = stderr.rfind(trailer)
        completed = False
        if position >= 0:
            status = stderr[position + len(trailer):].strip()
            if status.isdigit() and int(status) <= 255:
                stderr = stderr[:position]
                completed = True
        duration = time.monotonic() - started
        if not completed and process.returncode in (124, 137) and duration >= timeout:
            timed_out = True
        exit_code = process.returncode if process.returncode is not None else -9
        return RunResult(
            exit_code=exit_code,
            stdout=stdout.decode("utf-8", errors="replace"),
            stderr=stderr.decode("utf-8", errors="replace"),
            duration_s=duration,
            timed_out=timed_out,
        )

    def _remove(self, name: str) -> bool:
        try:
            result = subprocess.run(
                ["docker", "rm", "-f", name], capture_output=True, text=True,
                encoding="utf-8", errors="replace", timeout=self._CLI_TIMEOUT,
            )
            if result.returncode:
                if "no such container" in result.stderr.lower():
                    _LOG.info("gVisor container %s is already gone", name)
                else:
                    _LOG.warning("could not remove %s: %s", name, result.stderr.strip())
                    return False
            return True
        except (OSError, subprocess.TimeoutExpired) as exc:
            _LOG.warning("could not remove %s: %s", name, exc)
            return False

    def stop(self) -> None:
        """Remove this instance; tolerate a missing container or unavailable Docker."""
        if self._container_name is None:
            _LOG.debug("no gVisor container to stop")
            return
        if self._remove(self._container_name):
            self._container_name = None

    def reset(self) -> None:
        """Remove only containers with our stable prefix, including prior runs."""
        # The local name remains useful if listing fails (e.g. daemon trouble).
        self.stop()
        try:
            names = self._docker(
                ["ps", "-a", "--filter", f"name=^/{self._PREFIX}",
                 "--format", "{{.Names}}"], self._CLI_TIMEOUT,
            ).stdout.splitlines()
            for name in names:
                # Check again locally; Docker's name filter is a regex/substring filter.
                if name.startswith(self._PREFIX) and self._remove(name):
                    if name == self._container_name:
                        self._container_name = None
        except Exception as exc:
            _LOG.warning("could not reset gVisor containers: %s", exc)
