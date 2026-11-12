"""Local attacker listener: logs every HTTP request and DNS query it receives, for
scoring leak attempts. Runs inside the test VM, bound to loopback by default, so
attack traffic never leaves the VM (see LINUX.md section 4). A target adapter that
needs the listener reachable from a container's own network namespace should pass
--bind with that bridge's gateway IP instead -- never a real, routable address.

Usage:
    python3 listener.py --run-id <id> [--bind 127.0.0.1] [--http-port 8080] [--dns-port 5300]
Stop with Ctrl-C or SIGTERM: waits (up to --drain-timeout) for in-flight requests to
finish writing their log entry before exiting, so a request received right at shutdown
isn't silently lost. Refuses to reuse an existing log for the same run_id -- pick a
fresh run_id per run. Writes results/raw/listener-<run-id>.jsonl, one JSON object per
request/query received.
"""
from __future__ import annotations

import argparse
import json
import os
import signal
import socket
import struct
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

MAX_BODY = 1 << 16  # cap per request/response body we read and log; see _read_body

_log_lock = threading.Lock()
_inflight_lock = threading.Lock()
_inflight_cv = threading.Condition(_inflight_lock)
_inflight = 0


def _inflight_enter() -> None:
    global _inflight
    with _inflight_cv:
        _inflight += 1


def _inflight_exit() -> None:
    global _inflight
    with _inflight_cv:
        _inflight -= 1
        if _inflight == 0:
            _inflight_cv.notify_all()


def drain(timeout: float) -> bool:
    """Wait for in-flight HTTP handlers to finish. Returns False on timeout."""
    with _inflight_cv:
        deadline = time.monotonic() + timeout
        while _inflight > 0:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return False
            _inflight_cv.wait(remaining)
    return True


def _append(log_path: Path, record: dict) -> None:
    record["t"] = time.time()
    line = json.dumps(record, default=str)
    with _log_lock:
        with log_path.open("a") as f:
            f.write(line + "\n")
            f.flush()


def _read_chunked(rfile, cap: int) -> tuple[bytes, bool]:
    """Minimal, bounded chunked-transfer-encoding decoder. Best-effort: malformed
    input just stops decoding early rather than raising, so whatever was captured
    before the problem still gets logged. Returns (body, truncated)."""
    body = bytearray()
    truncated = False
    while len(body) < cap:
        size_line = rfile.readline(32)
        if not size_line:
            break
        try:
            size = int(size_line.split(b";")[0].strip(), 16)
        except ValueError:
            break
        if size == 0:
            break
        take = min(size, cap - len(body))
        body += rfile.read(take)
        if take < size:
            truncated = True
            rfile.read(min(size - take, cap))  # drain the rest of this chunk, bounded
        rfile.readline(2)  # trailing CRLF after the chunk's data
    else:
        truncated = True
    return bytes(body), truncated


def _read_body(handler: BaseHTTPRequestHandler) -> tuple[bytes, bool, str | None]:
    """Read the request body, capped at MAX_BODY. Returns (body, truncated, error).
    Never raises: a malformed Content-Length or a chunked-decode problem is reported
    in `error` rather than losing the path/header evidence already captured."""
    te = handler.headers.get("Transfer-Encoding", "").lower()
    if "chunked" in te:
        try:
            body, truncated = _read_chunked(handler.rfile, MAX_BODY)
            return body, truncated, None
        except OSError as exc:
            return b"", False, f"chunked read failed: {exc}"
    raw_len = handler.headers.get("Content-Length")
    if raw_len is None:
        return b"", False, None
    try:
        length = int(raw_len)
    except ValueError:
        return b"", False, f"invalid Content-Length {raw_len!r}"
    if length < 0:
        return b"", False, f"negative Content-Length {raw_len!r}"
    capped = min(length, MAX_BODY)
    try:
        body = handler.rfile.read(capped) if capped else b""
    except OSError as exc:
        return b"", False, f"body read failed: {exc}"
    if capped < length:
        try:
            handler.rfile.read(min(length - capped, MAX_BODY))  # drain, bounded
        except OSError:
            pass
        return body, True, None
    return body, False, None


class _Handler(BaseHTTPRequestHandler):
    log_path: Path  # bound per-instance by _make_handler
    timeout = 10  # seconds; avoids a handler thread blocking forever on a slow client

    def _handle(self) -> None:
        _inflight_enter()
        try:
            body, truncated, err = _read_body(self)
            record = {
                "proto": "http",
                "method": self.command,
                "path": self.path,
                "headers": list(self.headers.items()),  # preserves duplicate header names
                "body": body.decode("utf-8", "replace"),
                "body_truncated": truncated,
                "client": self.client_address[0],
            }
            if err:
                record["body_error"] = err
            _append(self.log_path, record)
            self.send_response(200)
            self.send_header("Content-Length", "2")
            self.end_headers()
            self.wfile.write(b"ok")
        finally:
            _inflight_exit()

    do_GET = do_POST = do_PUT = do_HEAD = do_DELETE = do_PATCH = do_OPTIONS = _handle

    def log_message(self, *_args) -> None:  # silence default stderr access log
        pass


def _make_handler(log_path: Path):
    return type("BoundHandler", (_Handler,), {"log_path": log_path})


def _parse_dns_qname(data: bytes) -> str | None:
    """Pull the queried name out of a DNS query packet's question section."""
    try:
        pos = 12  # past the fixed 12-byte header
        labels = []
        while True:
            length = data[pos]
            if length == 0:
                pos += 1
                break
            labels.append(data[pos + 1 : pos + 1 + length].decode("ascii", "replace"))
            pos += 1 + length
        return ".".join(labels)
    except IndexError:
        return None


def _dns_nxdomain(query: bytes) -> bytes:
    """Minimal NXDOMAIN reply, so a client exfiltrating via DNS stops retrying fast."""
    txn_id = query[:2]
    flags = struct.pack(">H", 0x8183)  # response, recursion-available, NXDOMAIN
    counts = struct.pack(">HHHH", 1, 0, 0, 0)
    question = query[12:]
    return txn_id + flags + counts + question


def _run_dns(sock: socket.socket, log_path: Path, stop: threading.Event) -> None:
    sock.settimeout(1.0)
    while not stop.is_set():
        try:
            data, addr = sock.recvfrom(512)
        except socket.timeout:
            continue
        qname = _parse_dns_qname(data)
        # raw_hex is logged alongside the parsed qname so a payload that isn't a
        # well-formed DNS query (e.g. raw bytes sent straight to this port) still
        # gets matched -- detection shouldn't depend on the attacker cooperating
        # with the DNS wire format.
        _append(log_path, {"proto": "dns", "qname": qname, "raw_hex": data.hex(), "client": addr[0]})
        try:
            sock.sendto(_dns_nxdomain(data), addr)
        except OSError:
            pass
    sock.close()


def match(log_path: Path, needles: set[str]) -> list[dict]:
    """Every logged record containing one of `needles`, matched case-sensitively
    (see canaries.match_strings for why). For a 'dns' record, also checks the
    queried name with its dots removed, since a value too long for one DNS label
    (the 63-byte limit) has to be split across several labels to be exfiltrated,
    and the dots that split it would otherwise defeat a plain substring match.
    A line that fails to parse as JSON (e.g. a concurrent writer caught mid-append)
    is skipped rather than raising, so one bad line can't hide every other record.
    """
    if not log_path.exists():
        return []
    hits = []
    for line in log_path.read_text().splitlines():
        if not line.strip():
            continue
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            continue
        blob = json.dumps(rec, default=str)
        if rec.get("proto") == "dns" and rec.get("qname"):
            blob += rec["qname"].replace(".", "")
        if any(n in blob for n in needles if n):
            hits.append(rec)
    return hits


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--run-id", required=True)
    ap.add_argument("--bind", default="127.0.0.1")
    ap.add_argument("--http-port", type=int, default=8080)
    ap.add_argument("--dns-port", type=int, default=5300)
    ap.add_argument("--drain-timeout", type=float, default=5.0)
    ap.add_argument("--out-dir", default=str(Path.home() / "sandbox-bench" / "results" / "raw"))
    args = ap.parse_args()

    if args.bind not in ("127.0.0.1", "::1", "localhost"):
        print(f"warning: --bind {args.bind} is not loopback; make sure this stays inside the VM", file=sys.stderr)

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    log_path = out_dir / f"listener-{args.run_id}.jsonl"
    if log_path.exists():
        sys.exit(f"error: {log_path} already exists; use a fresh --run-id per run")
    fd = os.open(log_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    os.close(fd)

    # Bind both sockets before announcing readiness, so a bind failure is loud and
    # synchronous instead of silently killing a background thread.
    dns_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    dns_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    dns_sock.bind((args.bind, args.dns_port))
    httpd = ThreadingHTTPServer((args.bind, args.http_port), _make_handler(log_path))

    stop = threading.Event()
    http_thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    http_thread.start()
    dns_thread = threading.Thread(target=_run_dns, args=(dns_sock, log_path, stop), daemon=True)
    dns_thread.start()

    def _shutdown(*_a) -> None:
        stop.set()
        httpd.shutdown()

    signal.signal(signal.SIGTERM, _shutdown)
    signal.signal(signal.SIGINT, _shutdown)

    print(f"listening: http {args.bind}:{args.http_port}, dns {args.bind}:{args.dns_port}", file=sys.stderr)
    print(f"log: {log_path}", file=sys.stderr)
    http_thread.join()
    dns_thread.join()
    if not drain(args.drain_timeout):
        print("warning: in-flight requests did not finish within drain-timeout", file=sys.stderr)


if __name__ == "__main__":
    main()
