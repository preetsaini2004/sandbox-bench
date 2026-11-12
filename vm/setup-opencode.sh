#!/usr/bin/env bash
# Run this yourself INSIDE the test VM (./vm/ssh.sh, then paste/run this script).
# Claude's harness blocks it from running downloaded third-party installers itself.
#
# OpenCode is the THIRD Week-3 agent, alongside Claude Code and Codex CLI, but
# it plays a different role: it's an open-source coding agent with no
# particular vendor behind it, paired with a free, user-chosen open-weight
# model (not Anthropic's or OpenAI's own) via FreeLLMAPI -- a local router
# running on the laptop, not in this VM. The point is to see whether a model
# with no agentic-injection-specific safety tuning falls for the same
# prompt-injection attacks Claude Code and Codex both resisted.
#
# This installs the CLI only. It does NOT configure which model it talks to --
# that's per-run via opencode.json, written by the harness itself (see
# attacks/injection -- no manual step needed here).
set -euo pipefail

echo ">> OpenCode CLI"
curl -fsSL https://opencode.ai/install | bash
export PATH="$HOME/.opencode/bin:$PATH"
opencode --version

echo
echo "done. The harness writes opencode.json and the FreeLLMAPI key per run --"
echo "no further manual setup needed."
