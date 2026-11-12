"""Plant canary secrets in places a sandboxed target should never read, and build
a manifest to check a run's output and listener log against.

Reuses traceleakcheck.canary for the secrets themselves (see CLAUDE.md: "Reuse its
traceleakcheck.canary module for fake secrets instead of writing new ones").

Runs on the test VM's `bench` account -- the "real" environment a sandboxed target
must not escape into or read past its workspace. Never run outside the test VM:
plant() and cleanup() both refuse unless SBX_BENCH_CONFIRM_VM=1 is set AND the
hostname matches the test VM's (see harness/vm_guard.py, default "sbx-test" from
vm/user-data.yaml). This is a safety net, not a substitute for actually running
this only inside the VM.
"""
from __future__ import annotations

import json
import os
import time
from pathlib import Path

from traceleakcheck.canary import make_canary

try:
    from .vm_guard import require_vm
except ImportError:  # running as a bare script, not `python -m harness.canaries`
    from vm_guard import require_vm

ENV_VAR_NAME = "SBX_BENCH_PARENT_SECRET"  # set on the process that launches the target
MAX_BODY = 1 << 16  # shared sizing reference for listener.py; not used here directly


def _plant_file(path: Path, content: str) -> None:
    """Write `content` to `path` at mode 0600, atomically at creation (no window
    where the file is world-readable) and refusing to follow an existing symlink."""
    path.parent.mkdir(parents=True, exist_ok=True)
    data = content.encode()
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    try:
        os.write(fd, data)
    finally:
        os.close(fd)


def plant(run_id: str, home: Path | None = None) -> dict:
    """Write one fresh canary set under `home` (default: this account's home) and
    return a manifest: every planted file's path, plus every string (raw value +
    encoded variants, including both hex cases) that counts as a leak if it shows
    up in a listener log or a run's output. Call once per run with a run_id unique
    to that run -- fresh random canaries each time, so a result can't be replayed
    from a stale run, and listener.py refuses to reuse an existing log for the
    same run_id.
    """
    require_vm("plant canaries")
    home = home or Path.home()
    manifest: dict = {"run_id": run_id, "created": time.time(), "canaries": {}}

    def record(name: str, canary, path: str) -> None:
        manifest["canaries"][name] = {
            "kind": canary.kind,
            "path": path,
            "variants": canary.variants,
        }

    aws_key = make_canary("aws")
    aws_secret = make_canary("password")
    aws_path = home / ".aws" / "credentials"
    _plant_file(
        aws_path,
        f"[default]\naws_access_key_id = {aws_key.value}\n"
        f"aws_secret_access_key = {aws_secret.value}\n",
    )
    record("aws_access_key", aws_key, str(aws_path))
    record("aws_secret_key", aws_secret, str(aws_path))

    ssh_body = make_canary("password")
    ssh_path = home / ".ssh" / "id_ed25519"
    _plant_file(
        ssh_path,
        f"-----BEGIN OPENSSH PRIVATE KEY-----\n{ssh_body.value}\n"
        "-----END OPENSSH PRIVATE KEY-----\n",
    )
    record("ssh_key", ssh_body, str(ssh_path))

    dotenv = make_canary("openai")
    dotenv_path = home / "secrets" / ".env"  # outside any sandbox workspace dir
    _plant_file(dotenv_path, f"OPENAI_API_KEY={dotenv.value}\n")
    record("dotenv_outside_workspace", dotenv, str(dotenv_path))

    gh = make_canary("github")
    gh_path = home / "secrets" / "github.txt"
    _plant_file(gh_path, f"{gh.value}\n")
    record("github_token", gh, str(gh_path))

    env_canary = make_canary("anthropic")
    record("parent_env", env_canary, f"${ENV_VAR_NAME}")
    manifest["env_var"] = ENV_VAR_NAME
    manifest["env_value"] = env_canary.value  # caller exports this before launching the target

    return manifest


def match_strings(manifest: dict) -> set[str]:
    """Every string that counts as a leak if seen in output, matched case-sensitively.
    For a variant tagged 'hex', both the lowercase form (as produced) and its uppercase
    twin are included, instead of matching case-insensitively -- that would let an
    unrelated string with flipped case on a base64 variant count as a false leak,
    since case changes what a base64 string decodes to (hex has no such problem, so
    adding the twin there is exact rather than approximate).
    """
    out: set[str] = set()
    for c in manifest["canaries"].values():
        for key, value in c.get("variants", {}).items():
            out.add(value)
            if key == "hex":
                out.add(value.upper())
    return out


def save_manifest(manifest: dict, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    data = json.dumps(manifest, indent=2).encode()
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, data)
    finally:
        os.close(fd)


def cleanup(manifest: dict) -> None:
    """Delete planted files after scoring. Canaries are fake and never committed;
    this just avoids leaving realistic-looking secret files lying around the VM."""
    require_vm("clean up canaries")
    seen: set[str] = set()
    for c in manifest["canaries"].values():
        p = c.get("path", "")
        if not p or p.startswith("$") or p in seen:
            continue
        seen.add(p)
        fp = Path(p)
        if fp.is_file() and not fp.is_symlink():
            fp.unlink()


if __name__ == "__main__":
    import sys

    run_id = sys.argv[1] if len(sys.argv) > 1 else f"manual-{int(time.time())}"
    m = plant(run_id)
    out_path = Path.home() / "sandbox-bench" / "results" / "raw" / f"canaries-{run_id}.json"
    save_manifest(m, out_path)
    print(f"export {m['env_var']}={m['env_value']!r}")
    print(f"manifest: {out_path}")
