"""Firecracker adapter. Firecracker is a bare microVM hypervisor, not a sandbox
with any built-in security policy of its own: it has no filesystem allow-list,
no network allow-list, nothing like nono's Landlock grants or OpenShell's
policy engine. Every bit of isolation here comes from running a genuinely
separate kernel + rootfs (hardware virtualization via /dev/kvm), not from any
configuration this adapter chooses. Consequently there is no applicable
escape-style attack in the catalogue for it (no shared docker socket, no
shared /proc, no shared devices -- there is nothing of the host's to escape
INTO), and the two network attacks here measure something different from
every other adapter: whether a stock, unconfigured guest OS calls out over a
network link this harness itself wired up, not a security control Firecracker
provides. See PROGRESS.md for why that's still included, carefully labeled.

Driven exactly per the official getting-started guide
(https://github.com/firecracker-microvm/firecracker/blob/main/docs/getting-started.md):
a Unix API socket, configured via PUT requests (shelled out to `curl
--unix-socket`, matching the guide's own examples rather than adding an HTTP
client dependency), then `PUT /actions {"action_type": "InstanceStart"}`.
Guest access is over SSH to a static IP, using the keypair vm/setup-firecracker.sh
already baked into the rootfs image's authorized_keys.

Needs `bench` in the `kvm` group (added live: `sudo usermod -aG kvm bench`,
confirmed via a fresh `ssh` session afterward -- group membership needs a new
login, not just re-reading /etc/group, which a brand-new SSH connection always
does). Without this, the api socket ends up root-owned (since /dev/kvm access
requires it) and an unprivileged curl can't even connect to it -- confirmed
live before making this change, error was a plain curl exit 7, not a Firecracker
API error. Running the firecracker PROCESS itself as `bench` (now that it can
open /dev/kvm directly) is simpler and safer than wrapping it in sudo, which
would also complicate signal delivery on stop().

Tap device + addressing is fixed (tap-fcbench, host 172.16.0.1/24, guest
172.16.0.2) rather than unique per instance: start()/stop() are always used
sequentially by this harness (never two Firecracker instances at once).

The tap device itself is set up ONCE via the module-level ensure_tap(), not
inside start()/stop() -- found live, the hard way: harness/run.py spawns the
attacker listener (bound to this adapter's host tap IP) BEFORE calling
target.start(), so if tap creation lived in start(), the listener's bind()
would fail with "Cannot assign requested address" on the very first run,
since the IP it's binding to wouldn't exist on any interface yet. Every other
adapter's bind address (the Docker bridge gateway, 0.0.0.0) already exists
independently of any target's lifecycle, which is why this ordering problem
is specific to Firecracker. harness/run.py's main() calls ensure_tap() once,
up front, exactly like it already calls bridge_gateway() once up front for
docker/gvisor -- see run.py for the call site.

Network reachability was verified live end-to-end before trusting it: a real
HTTP exfil attempt from inside the guest to 172.16.0.1 (this adapter's own
listener bind address, set via harness/run.py's LISTENER_BIND_OVERRIDE) showed
up correctly in the attacker listener's log, over the host<->guest tap link,
with NO additional iptables/forwarding rule needed -- direct tap adjacency is
plain INPUT-chain traffic on this VM (policy ACCEPT), unrelated to the
DOCKER-USER/DOCKER-FORWARD chains that govern the (separate, unrelated)
docker0 bridge other adapters' listener traffic crosses. This was a deliberate
design choice, not an accident: binding the listener on the tap's own host IP
means the network attacks test the GUEST's own default egress behavior, not
this VM's unrelated firewall topology for a different bridge network.
"""
from __future__ import annotations

import os
import shlex
import shutil
import signal
import subprocess
import time
import uuid
from pathlib import Path

if __package__:
    from .base import RunResult, Target
else:  # also support importing from the targets directory directly
    from base import RunResult, Target

_FC_DIR = Path.home() / "firecracker"
_KERNEL = _FC_DIR / "vmlinux-6.18.56"
_ROOTFS_TEMPLATE = _FC_DIR / "ubuntu-24.04.ext4"
_FIRECRACKER_BIN = _FC_DIR / "firecracker"
_SSH_KEY = _FC_DIR / "ubuntu-24.04.id_rsa"

_TAP_NAME = "tap-fcbench"
_HOST_IP = "172.16.0.1"
_GUEST_IP = "172.16.0.2"
_GUEST_MAC = "AA:FC:00:00:00:01"
_RUN_DIR = Path("/tmp")
_SOCK_PREFIX = "sbx-fc-"


def tap_teardown() -> None:
    subprocess.run(
        ["sudo", "-n", "ip", "link", "delete", _TAP_NAME],
        capture_output=True, timeout=10,
    )


def ensure_tap() -> None:
    """Idempotently create+configure the tap device if it doesn't already
    exist. Must run BEFORE anything binds a listener to _HOST_IP -- harness/run.py
    calls this once, up front, for the same reason it calls bridge_gateway()
    once up front for docker/gvisor: the tap device is persistent host network
    infrastructure for this benchmark's lifetime, not a per-attack resource
    tied to any one FirecrackerTarget instance's start()/stop() cycle (unlike
    every other target, where the thing the listener binds to -- the Docker
    bridge gateway, 0.0.0.0, -- already exists independently of start())."""
    probe = subprocess.run(["ip", "link", "show", _TAP_NAME], capture_output=True, timeout=10)
    if probe.returncode == 0:
        return
    for args in (
        ["sudo", "-n", "ip", "tuntap", "add", _TAP_NAME, "mode", "tap"],
        ["sudo", "-n", "ip", "addr", "add", f"{_HOST_IP}/24", "dev", _TAP_NAME],
        ["sudo", "-n", "ip", "link", "set", _TAP_NAME, "up"],
    ):
        result = subprocess.run(args, capture_output=True, text=True, timeout=10)
        if result.returncode != 0:
            raise RuntimeError(f"{' '.join(args)} failed: {result.stderr.strip()}")


_BOOT_READY_TIMEOUT = 30.0
_CURL_TIMEOUT = 10.0
_SSH_OPTS = [
    "-i", str(_SSH_KEY), "-o", "StrictHostKeyChecking=no",
    "-o", "UserKnownHostsFile=/dev/null", "-o", "LogLevel=ERROR",
    "-o", "ConnectTimeout=2",
]


class FirecrackerTarget(Target):
    name = "firecracker"

    def __init__(self) -> None:
        super().__init__()
        self._proc: subprocess.Popen | None = None
        self._sock_path: Path | None = None
        self._rootfs_copy: Path | None = None
        self._log_file = None

    @staticmethod
    def _api_put(sock: Path, path: str, body: str) -> None:
        result = subprocess.run(
            ["curl", "-s", "--unix-socket", str(sock), "-X", "PUT",
             f"http://localhost{path}", "-H", "Content-Type: application/json",
             "-d", body, "-o", "/dev/null", "-w", "%{http_code}"],
            capture_output=True, text=True, timeout=_CURL_TIMEOUT,
        )
        code = result.stdout.strip()
        if result.returncode != 0 or code != "204":
            raise RuntimeError(f"PUT {path} failed (curl rc={result.returncode}, http={code}): {result.stderr.strip()}")

    def start(self, config: dict | None = None) -> None:
        if self._proc is not None:
            raise RuntimeError("target already has a running microVM; call stop() before start()")
        config = config or {}
        if not isinstance(config, dict):
            raise ValueError("config must be a dict or None")
        vcpu_count = config.get("vcpu_count", 1)
        mem_size_mib = config.get("mem_size_mib", 256)
        read_only_rootfs = config.get("read_only_rootfs", False)
        if not isinstance(vcpu_count, int) or vcpu_count < 1:
            raise ValueError("vcpu_count must be a positive int")
        if not isinstance(mem_size_mib, int) or mem_size_mib < 128:
            raise ValueError("mem_size_mib must be an int >= 128")
        if not isinstance(read_only_rootfs, bool):
            raise ValueError("read_only_rootfs must be a bool")
        unknown = config.keys() - {"vcpu_count", "mem_size_mib", "read_only_rootfs"}
        if unknown:
            raise ValueError(f"unsupported configuration keys: {sorted(unknown)}")

        run_id = uuid.uuid4().hex[:12]
        sock = _RUN_DIR / f"{_SOCK_PREFIX}{run_id}.sock"
        rootfs_copy = _RUN_DIR / f"{_SOCK_PREFIX}{run_id}.ext4"
        log_path = _RUN_DIR / f"{_SOCK_PREFIX}{run_id}.log"
        self._sock_path = sock
        self._rootfs_copy = rootfs_copy
        try:
            if subprocess.run(["ip", "link", "show", _TAP_NAME], capture_output=True, timeout=10).returncode != 0:
                raise RuntimeError(
                    f"tap device {_TAP_NAME!r} does not exist -- call "
                    "targets.firecracker.ensure_tap() once before starting any "
                    "FirecrackerTarget (harness/run.py's main() does this already)"
                )
            shutil.copyfile(_ROOTFS_TEMPLATE, rootfs_copy)

            self._log_file = open(log_path, "wb")
            self._proc = subprocess.Popen(
                [str(_FIRECRACKER_BIN), "--api-sock", str(sock)],
                stdout=self._log_file, stderr=self._log_file, stdin=subprocess.DEVNULL,
            )
            deadline = time.monotonic() + 10
            while not sock.exists():
                if self._proc.poll() is not None or time.monotonic() > deadline:
                    raise RuntimeError(f"firecracker did not create its API socket (log: {log_path})")
                time.sleep(0.1)

            self._api_put(sock, "/machine-config",
                          f'{{"vcpu_count":{vcpu_count},"mem_size_mib":{mem_size_mib}}}')
            boot_args = (f"console=ttyS0 reboot=k panic=1 pci=off "
                         f"ip={_GUEST_IP}::{_HOST_IP}:255.255.255.0::eth0:off")
            self._api_put(sock, "/boot-source",
                          f'{{"kernel_image_path":"{_KERNEL}","boot_args":"{boot_args}"}}')
            self._api_put(sock, "/drives/rootfs",
                          f'{{"drive_id":"rootfs","path_on_host":"{rootfs_copy}",'
                          f'"is_root_device":true,"is_read_only":{"true" if read_only_rootfs else "false"}}}')
            self._api_put(sock, "/network-interfaces/eth0",
                          f'{{"iface_id":"eth0","guest_mac":"{_GUEST_MAC}","host_dev_name":"{_TAP_NAME}"}}')
            self._api_put(sock, "/actions", '{"action_type":"InstanceStart"}')

            deadline = time.monotonic() + _BOOT_READY_TIMEOUT
            last_err = ""
            while time.monotonic() < deadline:
                probe = subprocess.run(
                    ["ssh", *_SSH_OPTS, f"root@{_GUEST_IP}", "true"],
                    capture_output=True, text=True, timeout=5,
                )
                if probe.returncode == 0:
                    break
                last_err = probe.stderr.strip()
                time.sleep(0.5)
            else:
                raise RuntimeError(f"guest never became SSH-reachable within {_BOOT_READY_TIMEOUT}s: {last_err}")
        except Exception as exc:
            self.stop()
            raise RuntimeError(f"failed to start Firecracker microVM: {exc}") from exc

    def run(self, command: str, timeout: float = 30) -> RunResult:
        if self._proc is None:
            raise RuntimeError("Firecracker target has not been started")
        # ssh concatenates its trailing args with spaces and sends the result
        # as one string for the remote shell to parse, so `command` must be
        # POSIX-shell-quoted here (shlex.quote), not Python-repr'd.
        remote_cmd = f"timeout {timeout}s sh -c {shlex.quote(command)}"
        args = ["ssh", *_SSH_OPTS, f"root@{_GUEST_IP}", remote_cmd]
        started = time.monotonic()
        try:
            result = subprocess.run(
                args, capture_output=True, text=True,
                timeout=timeout + 10, encoding="utf-8", errors="replace",
            )
            return RunResult(
                exit_code=result.returncode, stdout=result.stdout, stderr=result.stderr,
                duration_s=time.monotonic() - started, timed_out=(result.returncode == 124),
            )
        except subprocess.TimeoutExpired as exc:
            return RunResult(
                exit_code=-9, stdout=exc.stdout or "", stderr=exc.stderr or "",
                duration_s=time.monotonic() - started, timed_out=True,
            )
        except OSError as exc:
            raise RuntimeError(f"could not execute ssh: {exc}") from exc

    def stop(self) -> None:
        if self._proc is not None:
            try:
                self._proc.send_signal(signal.SIGTERM)
                self._proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._proc.kill()
                self._proc.wait(timeout=5)
            except Exception:
                pass
            self._proc = None
        if self._log_file is not None:
            self._log_file.close()
            self._log_file = None
        # The tap device itself is NOT torn down here -- see ensure_tap()'s
        # docstring: it's persistent host infrastructure for this benchmark's
        # lifetime, shared across every FirecrackerTarget instance, not a
        # per-run resource. Use targets.firecracker.tap_teardown() directly if
        # you want it gone entirely (e.g. at the very end of a session).
        for path in (self._sock_path, self._rootfs_copy):
            if path is not None:
                path.unlink(missing_ok=True)
        self._sock_path = None
        self._rootfs_copy = None

    def reset(self) -> None:
        """Defensive cleanup: kill any stray firecracker process from a prior
        run that never reached stop(), and remove leftover socket/rootfs-copy
        files under our naming prefix. Does NOT touch the tap device -- see
        stop()'s comment; it's shared, persistent infrastructure, not
        per-instance. Safe to call with nothing to clean up."""
        self.stop()
        try:
            listing = subprocess.run(
                ["pgrep", "-af", str(_FIRECRACKER_BIN)],
                capture_output=True, text=True, timeout=_CURL_TIMEOUT,
            )
            for line in listing.stdout.splitlines():
                parts = line.split(None, 1)
                if len(parts) == 2 and _SOCK_PREFIX in parts[1]:
                    try:
                        os.kill(int(parts[0]), signal.SIGKILL)
                    except ProcessLookupError:
                        pass
        except Exception:
            pass
        for leftover in _RUN_DIR.glob(f"{_SOCK_PREFIX}*"):
            leftover.unlink(missing_ok=True)
