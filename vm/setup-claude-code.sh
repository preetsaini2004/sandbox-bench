#!/usr/bin/env bash
# Run this yourself INSIDE the test VM (./vm/ssh.sh, then paste/run this script).
# Claude's harness blocks it from running downloaded third-party installers itself.
#
# Installs Node.js 22.x (NodeSource's official setup script -- both Node and
# Claude Code need 22+) and the Claude Code CLI itself, so the AGENT being
# tested runs from inside this VM, against the sandboxed targets.
#
# This does NOT authenticate anything -- see vm/CLAUDE_CODE_AUTH.md for that
# step, which needs a browser and happens on your laptop, not here.
set -euo pipefail

echo ">> Node.js 22.x (NodeSource)"
curl -fsSL https://deb.nodesource.com/setup_22.x | sudo -E bash -
sudo apt-get install -y nodejs
node --version
npm --version

echo ">> Claude Code CLI"
curl -fsSL https://claude.ai/install.sh | bash
# The installer adds itself to a shell rc file; this script runs non-interactively,
# so pick up the same PATH addition cleanly for the rest of THIS script.
export PATH="$HOME/.local/bin:$PATH"
claude --version

echo
echo "done. Next: vm/CLAUDE_CODE_AUTH.md (get a subscription token on your"
echo "laptop, put it in this VM's .env as CLAUDE_CODE_OAUTH_TOKEN)."
