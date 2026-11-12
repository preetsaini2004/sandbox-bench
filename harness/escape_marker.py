"""Escape marker lifecycle (LINUX.md section 4, step 3): a path outside any
sandbox that only a real escape could reach. Guarded the same way as
canaries.py -- VM only. The directory itself is created once by cloud-init
(vm/user-data.yaml), owned by `bench`; this module only manages per-run paths.
"""
from __future__ import annotations

from pathlib import Path

try:
    from .vm_guard import require_vm
except ImportError:  # running as a bare script, not `python -m harness.escape_marker`
    from vm_guard import require_vm

MARKER_DIR = Path("/var/sbx-bench")


def marker_path(run_id: str) -> Path:
    return MARKER_DIR / f"escaped-{run_id}"


def prepare(run_id: str) -> Path:
    """Return a clean marker path for this run: the directory must already exist
    (cloud-init's job), and any stale marker left by a previous run with the same
    id is removed first, so a leftover file can't be mistaken for a fresh escape."""
    require_vm("prepare escape marker")
    if not MARKER_DIR.is_dir():
        raise RuntimeError(f"{MARKER_DIR} does not exist; check vm/user-data.yaml's runcmd")
    p = marker_path(run_id)
    if p.exists():
        p.unlink()
    return p
