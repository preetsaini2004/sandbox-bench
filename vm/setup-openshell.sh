#!/usr/bin/env bash
# Run this yourself INSIDE the test VM (./vm/ssh.sh, then paste/run this script).
# Claude's harness blocks it from running third-party installer scripts itself,
# even ones it has reviewed -- see https://github.com/NVIDIA/OpenShell for the
# source of install.sh (reviewed: downloads from github.com/NVIDIA/OpenShell
# releases only, verifies the redirect target before downloading, no other
# external endpoints contacted).
#
# Needs: Docker (already installed in this VM) as the sandbox backend.
set -euo pipefail
curl -fsSL https://raw.githubusercontent.com/NVIDIA/OpenShell/main/install.sh | sh
openshell --version
