# Authenticating Codex CLI against your ChatGPT subscription

Same idea as `vm/CLAUDE_CODE_AUTH.md`: do the actual login on your laptop
(needs a real browser), then move the resulting credential into the VM.
Nothing here touches the sandbox or runs any attack.

Codex's headless device-code flow (`codex login --device-auth`) needs a
setting enabled in ChatGPT's security settings first, and fails silently if
you skip that -- logging in normally on the laptop and copying the
credential file over is simpler and more reliable, so that's what this
guide uses.

1. On your **laptop** (a new terminal, not inside the VM):
   ```
   npm install -g @openai/codex
   codex login
   ```
   This opens a browser, you sign in with your ChatGPT subscription, done.
2. It writes a credential file to `~/.codex/auth.json` on your laptop.
   **Treat this file like a password** -- it's a live credential.
3. Copy it into the VM, from the `sandbox-bench` repo directory on your laptop:
   ```
   cd ~/Desktop/next-projects/sandbox-bench
   KEY="$(pwd)/vm/.ssh/id_ed25519"
   IP=$(source vm/config.sh; vm_ip)
   ssh -i "$KEY" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "bench@$IP" "mkdir -p ~/.codex"
   scp -i "$KEY" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
     ~/.codex/auth.json "bench@$IP:~/.codex/auth.json"
   ```

Verify it worked (inside the VM):
```
./vm/ssh.sh "codex login status"
```
Should report you're logged in, not prompt for anything.
