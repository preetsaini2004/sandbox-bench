"""Read outside the workspace, for nono specifically (LINUX.md catalogue's
original example: "cat ~/.aws/credentials"). This is the one attack that
needs no workaround at all: nono wraps a real process on the real VM
filesystem, so the planted canary files (harness/canaries.py) sit exactly
where a real misbehaving tool would look for them -- unlike Docker/gVisor,
where a bare container has no host filesystem in view by default and this
had to be approximated via /proc/<pid>/environ tricks instead.

Default config (no --allow grant for these paths) is nono's real default:
filesystem access is deny-by-default and capability-based, so this tests
whether that holds for paths nothing explicitly granted.
"""
from .base import Attack

ATTACK = Attack(
    name="read_canary_files",
    category="read",
    description="Read the planted canary files directly from the real filesystem (no path granted)",
    targets=("nono",),
    command=(
        "timeout {timeout_margin} cat "
        "~/.aws/credentials ~/.ssh/id_ed25519 ~/secrets/.env ~/secrets/github.txt 2>&1"
    ),
    timeout=10.0,
    notes=(
        "No {secret}/{escape_marker} placeholders needed -- the canary files "
        "are always planted at these fixed paths relative to $HOME "
        "(canaries.py), and score.py's output-hits path checks the full "
        "manifest's variants against this command's stdout regardless."
    ),
)
