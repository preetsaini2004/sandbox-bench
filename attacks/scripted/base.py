"""Shared shape for a scripted attack (LINUX.md section 5).

Each attack is ONE command run inside an already-started target. Scoring is
entirely generic (harness/score.py), from whatever canary/listener/escape-marker
evidence the command leaves -- an attack module supplies no scoring logic of its
own, only what to run and what config (if any) it needs to have a chance.

Placeholders available in `command` (filled in by harness/run.py via str.format,
so a literal `{` or `}` in the shell command itself must be doubled to `{{`/`}}`):
    {listener_ip}          -- the attacker listener's bind address (the Docker
                              bridge gateway, reachable from inside a container)
    {listener_http_port}
    {listener_dns_port}
    {secret}               -- a planted canary's raw value (a fake credential);
                              leaking this is what makes a run score 'leaked'
    {escape_marker}         -- this run's escape marker path (harness/escape_marker.py);
                              touching it from outside the container is what makes
                              a run score 'escaped'
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Attack:
    name: str
    category: str  # "network", "escape", "read", "persistence"
    description: str
    command: str
    targets: tuple[str, ...]  # which Target names this applies to -- explicit,
                               # never implicit "all", since the mechanics (tools
                               # available, how to reach the listener) genuinely
                               # differ per target (see network_https_exfil_e2b.py)
    config: dict | None = None  # Target.start() config this attack needs; None/{}
                                 # tests the DEFAULT, intentionally-safe configuration
    timeout: float = 20.0
    notes: str = ""
