#!/usr/bin/env bash
# Run this yourself INSIDE the test VM (./vm/ssh.sh, then paste/run this script).
# Claude's harness blocks it from running third-party installer scripts itself,
# even ones it has reviewed -- see https://github.com/nolabs-ai/nono for the
# source of install.sh (reviewed: downloads a GitHub release binary, verifies
# its SHA-256 against the release's published checksum file, installs it).
set -euo pipefail
curl -fsSL https://nono.sh/install.sh | sh
export PATH="$HOME/.local/bin:$PATH"
echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc
nono --version
