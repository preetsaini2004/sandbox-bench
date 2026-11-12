"""Shared safety net: refuse to run unless this is unmistakably the test VM.

Used by anything that writes over real-looking paths (canaries.py) or launches
containers with deliberately dangerous flags (targets/*.py). Two independent
checks, both required: an explicit opt-in env var (so a bare accidental invocation
anywhere is a no-op) and the VM's own hostname (so the opt-in alone can't be
copy-pasted onto a real machine without also matching it). This is a safety net,
not a substitute for actually only ever running this inside the VM -- see
LINUX.md, "the one rule that matters".
"""
from __future__ import annotations

import os
import socket


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
