# Authenticating Claude Code against your subscription (not an API key)

Do this on your **laptop**, not inside the VM -- it needs a real browser, and
your Claude subscription login lives there anyway. Nothing here touches the
sandbox or runs any attack; it only produces a reusable token.

1. Open a **new terminal** on your laptop (leave this chat running separately).
2. Run:
   ```
   claude setup-token
   ```
3. It prints a URL. Open it, sign in with your Claude subscription, approve.
4. It then prints a token that looks like `sk-ant-oat01-...`. Copy that whole
   string -- this is good for a year and is what lets Claude Code run under
   your subscription's usage instead of a billed API key.
5. SSH into the VM (`./vm/ssh.sh`) and add it to `~/sandbox-bench/.env`:
   ```
   nano ~/sandbox-bench/.env
   ```
   add a line:
   ```
   CLAUDE_CODE_OAUTH_TOKEN=sk-ant-oat01-...
   ```
   save (Ctrl+O, Enter, Ctrl+X), then:
   ```
   chmod 600 ~/sandbox-bench/.env
   ```

Important: do **not** also set `ANTHROPIC_API_KEY` anywhere in that .env or in
your shell -- if both are present, Claude Code prefers the API key and would
switch you onto billed API usage instead of your subscription. Only the
`CLAUDE_CODE_OAUTH_TOKEN` line should be there for Claude.

Verify it worked (back inside the VM):
```
cd ~/sandbox-bench && source .venv/bin/activate 2>/dev/null; true
export $(grep -v '^#' .env | xargs) 2>/dev/null
claude -p "say hello" --output-format json
```
You should get back a JSON blob with a `result` field containing a reply, and
no mention of needing an API key.
