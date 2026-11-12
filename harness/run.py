"""targets x attacks -> results/summary.json (README.md's repo layout).

Must run on the test VM: every piece this touches is VM-guarded (canaries.plant,
Target.__init__, escape_marker.prepare all refuse outside sbx-test).

Usage (from ~/sandbox-bench, after `export SBX_BENCH_CONFIRM_VM=1`):
    python3 -m harness.run --targets docker,gvisor --attacks all
    python3 -m harness.run --targets docker --attacks escape_docker_socket --with-negative-controls
"""
from __future__ import annotations

import argparse
import importlib
import json
import os
import pkgutil
import signal
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))


def _load_dotenv() -> None:
    """Minimal, dependency-free .env loader (REPO_ROOT/.env, gitignored -- see
    CLAUDE.md's 'each machine keeps its own .env' rule). Only sets a variable
    if it isn't already in the environment, so an explicit export still wins."""
    env_path = REPO_ROOT / ".env"
    if not env_path.is_file():
        return
    for line in env_path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))

from harness import canaries, escape_marker, score  # noqa: E402
from targets.docker import DockerTarget  # noqa: E402
from targets.gvisor import GvisorTarget  # noqa: E402
import attacks.scripted as scripted_pkg  # noqa: E402

TARGET_CLASSES = {"docker": DockerTarget, "gvisor": GvisorTarget}
try:  # optional: only needed for the e2b target, and only it needs E2B_API_KEY
    from targets.e2b import E2BTarget
    TARGET_CLASSES["e2b"] = E2BTarget
except ImportError:
    pass
try:  # optional: only needed if nono is installed (vm/setup-nono.sh)
    from targets.nono import NonoTarget
    TARGET_CLASSES["nono"] = NonoTarget
except ImportError:
    pass
try:  # optional: only needed if OpenShell is installed (vm/setup-openshell.sh)
    from targets.openshell import OpenShellTarget
    TARGET_CLASSES["openshell"] = OpenShellTarget
except ImportError:
    pass
try:  # optional: only needed if Firecracker is installed (vm/setup-firecracker.sh)
    from targets.firecracker import FirecrackerTarget
    TARGET_CLASSES["firecracker"] = FirecrackerTarget
except ImportError:
    pass

# Docker/gVisor containers reach the listener via the Docker bridge gateway,
# which only exists inside this VM's own network namespace. E2B sandboxes run
# on E2B's own cloud and need the listener reachable from the public internet
# instead (see vm/e2b-tunnel.sh, run by hand -- not something this harness
# opens itself). Firecracker guests are on their own point-to-point tap link
# (targets/firecracker.py), reachable only at the host side of that link.
LISTENER_BIND_OVERRIDE = {"e2b": "0.0.0.0", "firecracker": "172.16.0.1"}

RESULTS_DIR = REPO_ROOT / "results"
RAW_DIR = RESULTS_DIR / "raw"
SUMMARY_PATH = RESULTS_DIR / "summary.json"

CONTROL_COMMAND = "echo -n sbx-control-ok"
CONTROL_EXPECT = "sbx-control-ok"
HTTP_PORT = 18080
DNS_PORT = 15300


def load_attacks() -> dict:
    """Every attacks/scripted/<name>.py exposing an ATTACK, discovered by import
    (no attack has to be registered anywhere else)."""
    out = {}
    for mod_info in pkgutil.iter_modules(scripted_pkg.__path__):
        if mod_info.name == "base":
            continue
        mod = importlib.import_module(f"attacks.scripted.{mod_info.name}")
        attack = getattr(mod, "ATTACK", None)
        if attack is not None:
            out[attack.name] = attack
    return out


def bridge_gateway() -> str:
    out = subprocess.run(
        ["docker", "network", "inspect", "bridge", "--format", "{{(index .IPAM.Config 0).Gateway}}"],
        capture_output=True, text=True, check=True, timeout=10,
    )
    ip = out.stdout.strip()
    if not ip:
        raise RuntimeError("could not determine the Docker bridge gateway IP")
    return ip


def append_result(entry: dict) -> None:
    """Rewrite summary.json after every run (not just at the end), so a crash
    partway through a long sweep doesn't lose already-completed results."""
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    existing = []
    if SUMMARY_PATH.exists():
        existing = json.loads(SUMMARY_PATH.read_text())
    existing.append(entry)
    fd, tmp_name = tempfile.mkstemp(dir=RESULTS_DIR, suffix=".tmp")
    with os.fdopen(fd, "w") as f:
        json.dump(existing, f, indent=2)
    os.replace(tmp_name, SUMMARY_PATH)


def run_one(target_name: str, target_cls, attack, listener_ip: str, use_config: bool,
            public_host: str | None = None) -> dict:
    run_id = f"{target_name}-{attack.name}-{'cfg' if use_config else 'ctrl'}-{uuid.uuid4().hex[:8]}"
    print(f">> {run_id}", file=sys.stderr)

    manifest = canaries.plant(run_id)
    os.environ[manifest["env_var"]] = manifest["env_value"]
    marker = escape_marker.prepare(run_id)
    RAW_DIR.mkdir(parents=True, exist_ok=True)
    listener_log = RAW_DIR / f"listener-{run_id}.jsonl"

    bind_ip = LISTENER_BIND_OVERRIDE.get(target_name, listener_ip)
    # What the ATTACK is told to connect to differs from what the listener
    # BINDS to only for e2b: it binds locally (0.0.0.0) but the sandbox reaches
    # it through the public tunnel hostname (see vm/e2b-tunnel.sh) instead of
    # the literal bind address. Every other target (including firecracker,
    # whose bind_ip is its own tap link's host IP, not the Docker bridge
    # gateway) is told to connect to wherever the listener actually bound.
    attack_host = public_host if public_host else bind_ip

    listener_proc = subprocess.Popen([
        sys.executable, str(REPO_ROOT / "harness" / "listener.py"),
        "--run-id", run_id, "--bind", bind_ip,
        "--http-port", str(HTTP_PORT), "--dns-port", str(DNS_PORT),
        "--out-dir", str(RAW_DIR),
    ])
    time.sleep(0.5)  # let it bind before anything might try to reach it

    target = target_cls()
    control_ok = None
    agent_output = ""
    error = None
    try:
        try:
            config = attack.config if use_config else None
            target.start(config)
        except Exception as exc:  # a target that can't even start is 'broken', not a crash
            control_ok = False
            error = f"start() raised: {exc}"
        else:
            try:
                control = target.run(CONTROL_COMMAND, timeout=10)
                control_ok = control.exit_code == 0 and CONTROL_EXPECT in control.stdout
            except Exception as exc:  # control itself failing is a 'broken' run, not a crash
                control_ok = False
                error = f"control action raised: {exc}"

            if control_ok:
                secret = next(iter(manifest["canaries"].values()))["variants"]["raw"]
                margin = max(1, int(attack.timeout) - 2)
                command = attack.command.format(
                    listener_ip=attack_host, listener_http_port=HTTP_PORT,
                    listener_dns_port=DNS_PORT, secret=secret, escape_marker=str(marker),
                    timeout_margin=margin,
                )
                try:
                    result = target.run(command, timeout=attack.timeout)
                    agent_output = result.stdout + result.stderr
                except Exception as exc:
                    error = f"attack command raised: {exc}"
    finally:
        # Everything below must run even if the code above raised something
        # unanticipated -- a half-torn-down target must never leave the
        # listener subprocess running (it would hold this process's stdio
        # open, hanging whatever invoked harness.run) or leak canaries/markers
        # into the next run.
        try:
            target.stop()
        except Exception as exc:
            print(f"warning: stop() raised: {exc}", file=sys.stderr)
        try:
            target.reset()
        except Exception as exc:
            print(f"warning: reset() raised: {exc}", file=sys.stderr)

        listener_proc.send_signal(signal.SIGTERM)
        try:
            listener_proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            listener_proc.kill()
            listener_proc.wait(timeout=5)

        canaries.cleanup(manifest)
        del os.environ[manifest["env_var"]]

    # Must come after the finally block (listener/target are already torn
    # down) but BEFORE the marker is unlinked below -- score() needs to see
    # whether escape_marker still exists to score an 'escaped' verdict.
    verdict = score.score(score.RunInputs(
        run_id=run_id,
        manifest=manifest,
        listener_log=listener_log,
        escape_marker=marker,
        agent_output=agent_output,
        control_ok=control_ok,
    ))
    if error:
        verdict["error"] = error

    if marker.exists():
        marker.unlink()

    entry = {
        "target": target_name,
        "attack": attack.name,
        "category": attack.category,
        "variant": "configured" if use_config else "negative_control",
        **verdict,
    }
    append_result(entry)
    print(f"   -> {verdict['verdict']}: {verdict['reason']}", file=sys.stderr)
    return entry


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--targets", default="docker,gvisor", help="comma-separated, or 'all'")
    ap.add_argument("--attacks", default="all", help="comma-separated attack names, or 'all'")
    ap.add_argument("--with-negative-controls", action="store_true",
                     help="for attacks with a config, also run with config=None")
    ap.add_argument("--public-host", default=None,
                     help="public hostname (no scheme/port) for the e2b target's listener, "
                          "e.g. the *.trycloudflare.com host printed by vm/e2b-tunnel.sh")
    args = ap.parse_args()

    _load_dotenv()
    if os.environ.get("SBX_BENCH_CONFIRM_VM") != "1":
        sys.exit("SBX_BENCH_CONFIRM_VM=1 is not set; see harness/vm_guard.py")

    all_attacks = load_attacks()
    target_names = list(TARGET_CLASSES) if args.targets == "all" else args.targets.split(",")
    attack_names = list(all_attacks) if args.attacks == "all" else args.attacks.split(",")
    for n in target_names:
        if n not in TARGET_CLASSES:
            sys.exit(f"unknown target {n!r}; choose from {sorted(TARGET_CLASSES)}")
    for n in attack_names:
        if n not in all_attacks:
            sys.exit(f"unknown attack {n!r}; choose from {sorted(all_attacks)}")

    if "e2b" in target_names and not args.public_host:
        sys.exit("--public-host is required when targeting e2b (run vm/e2b-tunnel.sh "
                  "yourself first, on the laptop, and pass its *.trycloudflare.com host)")

    listener_ip = bridge_gateway()
    print(f"listener will bind {listener_ip} (Docker bridge gateway) for docker/gvisor", file=sys.stderr)

    if "firecracker" in target_names:
        # Must happen before any listener is spawned -- see
        # targets/firecracker.py's ensure_tap() docstring for why.
        from targets.firecracker import ensure_tap
        ensure_tap()
        print("tap-fcbench ready for firecracker", file=sys.stderr)

    for target_name in target_names:
        for attack_name in attack_names:
            attack = all_attacks[attack_name]
            if target_name not in attack.targets:
                print(f"skipping {attack_name} for {target_name} (not applicable)", file=sys.stderr)
                continue
            run_one(target_name, TARGET_CLASSES[target_name], attack, listener_ip,
                    use_config=True, public_host=args.public_host)
            if args.with_negative_controls and attack.config:
                run_one(target_name, TARGET_CLASSES[target_name], attack, listener_ip,
                        use_config=False, public_host=args.public_host)

    print(f"\nresults: {SUMMARY_PATH}", file=sys.stderr)


if __name__ == "__main__":
    main()
