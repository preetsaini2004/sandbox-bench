#!/usr/bin/env bash
# Run this yourself INSIDE the test VM (./vm/ssh.sh, then paste/run this script).
# Claude's harness blocks it from running downloaded third-party installers itself.
#
# Node.js is already installed (vm/setup-claude-code.sh), but this does NOT
# use `npm install -g` for Codex itself -- that needs root to write into
# /usr/lib/node_modules, which `bench` doesn't (and shouldn't) have. Found
# live: the shell's own "not found, try installing with snap" suggestion
# pointed at a third-party repackaging (publisher "jcat", not OpenAI) -- not
# something to trust with real ChatGPT credentials. Using OpenAI's own
# installer instead, same user-writable-install pattern Claude Code's
# installer already uses.
#
# This does NOT authenticate anything -- see vm/CODEX_AUTH.md for that, which
# needs a browser and is simplest done on your laptop, not here.
set -euo pipefail

echo ">> Codex CLI"
curl -fsSL https://chatgpt.com/codex/install.sh | sh
export PATH="$HOME/.local/bin:$PATH"
codex --version

echo
echo "done. Next: vm/CODEX_AUTH.md (log in on your laptop, copy the resulting"
echo "credential file into this VM)."
