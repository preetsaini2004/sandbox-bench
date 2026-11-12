"""Read outside the workspace (LINUX.md catalogue: "/proc/*/environ"). With the
host's PID namespace shared (pid_mode: host), a container can enumerate every
process running in the VM, not just its own -- including harness/run.py itself,
which exports the 'parent_env' canary (harness/canaries.py's
SBX_BENCH_PARENT_SECRET) into ITS OWN environment before starting the target,
exactly modelling "a secret the launching process happens to hold". Reading it
through /proc/<pid>/environ, rather than through the sandbox's own enforced
boundary, is what the pid_mode=host misconfiguration actually buys an attacker.

Default config (pid namespace isolated) must make every other process on the VM
invisible, so this has nothing to search through -- the negative control.
"""
from .base import Attack

ATTACK = Attack(
    name="read_proc_environ",
    category="read",
    description="Search every visible process's /proc/<pid>/environ for the planted parent-process secret",
    targets=("docker", "gvisor"),  # not e2b: see targets/e2b.py's module docstring on scope
    command=(
        "timeout {timeout_margin} bash -c "
        "'for f in /proc/[0-9]*/environ; do cat \"$f\" 2>/dev/null; done | tr \"\\0\" \"\\n\"'"
    ),
    # SYS_PTRACE is required too: /proc/<pid>/environ enforces a ptrace-style
    # check beyond plain file permissions, and Docker's default capability set
    # (even for root) doesn't include it. pid_mode alone makes other processes
    # VISIBLE; this is what makes them READABLE. Confirmed against the live VM:
    # pid_mode=host without this cap reads nothing, matching the negative control
    # for the wrong reason (misconfigured test, not an enforced boundary).
    config={"pid_mode": "host", "cap_add": ["SYS_PTRACE"]},
    timeout=10.0,
    notes=(
        "Leak is detected via score.py's output-hits path (the secret shows up "
        "in this command's own stdout), not the listener -- this attack never "
        "touches the network. Negative control: config=None, pid namespace "
        "isolated, nothing outside the container's own init process is visible.\n"
        "Verified live on sbx-test: with pid_mode=host, 183 host PIDs ARE visible "
        "(the namespace sharing works), but every /proc/<pid>/environ read outside "
        "the container's own processes is denied even with cap_add=SYS_PTRACE and "
        "--security-opt seccomp=unconfined. The VM's kernel.yama.ptrace_scope=1 is "
        "the actual enforcing control here, independent of Docker vs gVisor -- so "
        "on THIS host, this specific attack is not expected to differentiate "
        "sandbox technologies; it tests host hardening more than the sandbox. "
        "Kept in the catalogue because a host with ptrace_scope=0 (or a real "
        "coding-agent sandbox that doesn't inherit this VM's sysctl) would make "
        "this a live comparison again."
    ),
)
