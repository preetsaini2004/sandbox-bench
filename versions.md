# versions.md

Every number in `results/summary.json` must be reproducible from these versions. Fill in before the first result.

## Host (laptop, read-only role: runs libvirt, git, editor)
| Item | Value |
|---|---|
| Date checked | 2026-11-05 |
| OS / kernel | CachyOS (Arch-based), 7.3.1-1-cachyos |
| CPU | AMD Ryzen 5 8645HS, 12 threads |
| RAM | 14 GiB |
| Disk free | 307 GB on /home |
| /dev/kvm | present |
| Nested virtualization (kvm_amd) | on (`1`) |
| libvirt / QEMU | 12.9.0 / 12.9.0 |
| virt-install | 5.1.0 |

## Test VM `sbx-test`
| Item | Value |
|---|---|
| Image | Ubuntu 24.04 (noble) cloud image, sha256 stored beside the image as `noble-server-cloudimg-amd64.img.sha256` |
| vCPU / RAM / disk | 4 / 6144 MB / 40 GB (qcow2 overlay) |
| Boot | BIOS (internal snapshots need non-pflash firmware) |
| Users | `bench` (admin, harness), `agent` (unprivileged, runs targets); `bench` added to the `kvm` group 2026-11-05 (`sudo usermod -aG kvm bench`), needed so Firecracker can open `/dev/kvm` without running as root |
| Snapshots | `clean` (2026-11-06, default for `vm/reset.sh`): all 6 targets installed, verified clean. `base` (2026-11-05): an earlier checkpoint, predates nono/OpenShell/Firecracker -- kept but not the reset default. **Found live:** `vm/reset.sh` has always defaulted to a snapshot named `clean`, but only `base` ever actually existed -- `./vm/reset.sh` had never once succeeded before this was caught (by the user, running it directly) and fixed. Confirmed working after the fix: reverts in 15.2s, all 6 targets still present, a real attack run immediately after scored correctly. |

## Self-hosted model server (Week 3 uncensored agent)
A CPU-only Linux server running `llama.cpp` `llama-server` with `huihui-ai/Huihui-Qwen3-Coder-30B-A3B-Instruct-abliterated` (Q6_K), `-c 32768 -np 1`, measured ~15 tok/s. Reached from the test VM only through an SSH tunnel; its address and access details are deliberately not recorded in this repo.

## Targets (pin when installed)
| Target | Version | Installed on |
|---|---|---|
| Docker | 29.9.3 (docker-ce, official apt repo) | 2026-11-05, in `sbx-test` |
| gVisor (runsc) | release-20261102.0 (gvisor.dev apt repo), registered via `runsc install` | 2026-11-05, in `sbx-test` |
| Firecracker | v1.17.0 (binary + jailer + kernel 6.18.56 + Ubuntu 24.04 rootfs), adapter (targets/firecracker.py) tested live | 2026-11-05, in `sbx-test` |
| Claude Code | 2.1.319. Week 3 (prompt injection) subject, not a sandbox target -- runs the agent whose behavior is being tested, inside the other targets. Installed via `vm/setup-claude-code.sh`; authenticated via subscription token (`claude setup-token`, `CLAUDE_CODE_OAUTH_TOKEN` in `.env`), confirmed NOT a billed API key via `claude doctor` ("inference-only"). Driven inside `nono` via its own ready-made profile (`nono pull nolabs-ai/claude`, `nono run --profile nolabs-ai/claude --allow-cwd -- claude ...`). | 2026-11-06, in `sbx-test` |
| Codex CLI | codex-cli 0.167.0. Same role as Claude Code (Week 3 subject). Installed via OpenAI's official installer (`chatgpt.com/codex/install.sh`) -- `npm install -g @openai/codex` failed live (EACCES, needs root), and the shell's own "try `sudo snap install codex`" suggestion turned out to be an unofficial third-party repackaging (publisher `jcat`, not OpenAI) -- removed, not trusted with real credentials. Authenticated via `codex login` on the laptop (real browser) + `~/.codex/auth.json` copied to the VM over the project's own SSH key, confirmed via `codex login status`. No `OPENAI_API_KEY` anywhere on the VM, confirmed. Driven inside `nono` via its own ready-made profile (`nono pull nolabs-ai/codex`). Auto-loads `AGENTS.md` as trusted project instructions, confirmed live, same as Claude Code's `CLAUDE.md`. | 2026-11-06, in `sbx-test` |
| opencode | 1.19.5. Third Week-3 agent -- open-source, no vendor behind it, paired with a free open-weight model (`mistral-large-3`, via the `xkiro` platform) rather than a vendor's own model. Installed via the official installer (`opencode.ai/install`). Model served by **FreeLLMAPI** (`~/.local/share/freellmapi`), which stays on the LAPTOP (`http://127.0.0.1:31415`, the desktop app's own server, using the real already-configured provider keys) -- never copied into the VM. VM reaches it at `http://192.168.122.1:31415` via a `socat` relay on the laptop (`TCP-LISTEN:31415,bind=192.168.122.1 -> 127.0.0.1:31415`) plus a `ufw` rule scoping access to the libvirt network only (`sudo ufw allow from 192.168.122.0/24 to any port 31415 proto tcp`). Driven inside `nono` via its own ready-made profile (`nono pull nolabs-ai/opencode`), whose network policy is deliberately left `block: false` (no domain allowlist), so a successful exfil attempt reflects the model's own choice rather than a network policy incidentally blocking it. Provider/model config lives in a one-time global `~/.config/opencode/opencode.json` on the VM, not written per-run. Auto-loads `AGENTS.md`, confirmed live. Picking a working model took real trial and error -- see PROGRESS.md for the dead keys, rate limits, and a tool-call parsing bug hit along the way, plus two real bugs found and fixed in FreeLLMAPI itself (a client-side login validation bug blocking the desktop app's own seeded account). | 2026-11-06, in `sbx-test` |
| opencode-uncensored | Fourth Week-3 agent: the same `opencode` 1.19.5 CLI and `nolabs-ai/opencode` nono profile, with its model provider pointed at the self-hosted server above (an OpenAI-compatible endpoint, no API key). | 2026-11-12, agent in `sbx-test` |
| nono | 0.81.0, installed and adapter (targets/nono.py) tested live | 2026-11-05, in `sbx-test` |
| OpenShell | 0.1.7, installed and adapter (targets/openshell.py) tested live | 2026-11-05, in `sbx-test` |
| E2B SDK | 2.63.0 (pip, unpinned so far) | 2026-11-05, in `sbx-test`'s venv |

Firecracker/nono/OpenShell need the user to run vm/setup-*.sh themselves: Claude's
harness blocks it from executing downloaded third-party installers/binaries
directly, even reviewed ones (deliberate guardrail, not a bug). E2B similarly
needs the user to run vm/e2b-tunnel.sh themselves (opening an inbound path to
the internet is blocked the same way). Both scripts were reviewed for safety
before being written here -- see the session notes for what was checked.
| traceleakcheck | 0.2.2 (pinned in `harness/requirements.txt`), in a venv at `~/sandbox-bench/.venv` | 2026-11-05, in `sbx-test` |
