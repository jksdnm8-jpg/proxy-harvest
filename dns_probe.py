#!/usr/bin/env python3
r"""Verify that mihomo resolves names through the configured DNS server.

This is a local-only integration probe:

1. start a mock UDP DNS server that answers `dns-probe.test` with 127.0.0.1;
2. start a local HTTP server that returns a fixed body;
3. start mihomo with an explicit `dns.nameserver` pointing at the mock;
4. send a request through mihomo's mixed port to `dns-probe.test`;
5. require the mock DNS server to have received the query.

It needs a real mihomo binary and a local curl, but no Internet or proxy node.
Run it manually:

    python dns_probe.py --mihomo C:\path\to\mihomo.exe
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

try:
    import yaml
except ImportError:
    sys.exit("dns_probe requires pyyaml")

PROBE_NAME = "dns-probe.test"


def _dns_reply(data: bytes, ip: str = "127.0.0.1") -> bytes:
    if len(data) < 12:
        return b""
    tid = data[:2]
    q_end = 12
    while q_end < len(data) and data[q_end] != 0:
        q_end += 1 + data[q_end]
    q_end += 1 + 4
    if q_end > len(data):
        return b""
    question = data[12:q_end]
    qtype = struct.unpack("!H", data[q_end - 4:q_end - 2])[0]
    answer = b""
    ancount = 0
    if qtype == 1:
        packed = socket.inet_aton(ip)
        answer = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + packed
        ancount = 1
    flags = 0x8180
    header = tid + struct.pack("!HHHHH", flags, 1, ancount, 0, 0)
    return header + question + answer


class DNSMock:
    def __init__(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.port = self.sock.getsockname()[1]
        self.queries: list[str] = []
        self._stop = threading.Event()
        self.thread = threading.Thread(target=self._run, daemon=True)

    def _run(self):
        self.sock.settimeout(0.5)
        while not self._stop.is_set():
            try:
                data, addr = self.sock.recvfrom(4096)
            except socket.timeout:
                continue
            except OSError:
                break
            name = ""
            try:
                q_end = 12
                labels = []
                while data[q_end] != 0:
                    n = data[q_end]
                    labels.append(data[q_end + 1:q_end + 1 + n].decode("ascii"))
                    q_end += 1 + n
                name = ".".join(labels)
            except Exception:
                pass
            self.queries.append(name)
            reply = _dns_reply(data)
            if reply:
                try:
                    self.sock.sendto(reply, addr)
                except OSError:
                    pass

    def start(self):
        self.thread.start()
        return self

    def close(self):
        self._stop.set()
        try:
            self.sock.close()
        except OSError:
            pass


class BodyHandler(BaseHTTPRequestHandler):
    def log_message(self, *_args):
        return

    def do_GET(self):
        body = b"ok"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def wait_port(port: int, timeout: float = 10.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.3):
                return True
        except OSError:
            time.sleep(0.15)
    return False


def run_probe(mihomo: str, timeout: float = 10.0) -> dict:
    dns = DNSMock().start()
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), BodyHandler)
    http_port = httpd.server_address[1]
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    tmp = tempfile.mkdtemp(prefix="ph-dns-probe-")
    mixed = None
    api = None
    proc = None
    result = {"ok": False, "dns_queries": dns.queries, "http_port": http_port}
    try:
        # pick free ports
        for _ in range(2):
            s = socket.socket()
            s.bind(("127.0.0.1", 0))
            if mixed is None:
                mixed = s.getsockname()[1]
            else:
                api = s.getsockname()[1]
            s.close()
        cfg = {
            "mixed-port": mixed,
            "external-controller": f"127.0.0.1:{api}",
            "allow-lan": False,
            "mode": "rule",
            "log-level": "warning",
            "proxies": [],
            "proxy-groups": [],
            "rules": ["MATCH,DIRECT"],
            "dns": {
                "enable": True,
                "enhanced-mode": "normal",
                "nameserver": [f"127.0.0.1:{dns.port}"],
            },
        }
        with open(os.path.join(tmp, "config.yaml"), "w", encoding="utf-8") as f:
            yaml.safe_dump(cfg, f, allow_unicode=True, sort_keys=False)
        flags = getattr(subprocess, "CREATE_NO_WINDOW", 0) if os.name == "nt" else 0
        proc = subprocess.Popen([mihomo, "-d", tmp], creationflags=flags)
        if not wait_port(mixed, timeout):
            result["error"] = "mihomo mixed port did not start"
            return result
        curl = shutil.which("curl") or ("curl.exe" if os.name == "nt" else "curl")
        url = f"http://{PROBE_NAME}:{http_port}/"
        out = os.path.join(tmp, "body.bin")
        r = subprocess.run(
            [curl, "-q", "-s", "-o", out, "-w", "%{http_code}",
             "--max-time", str(timeout), "-x", f"http://127.0.0.1:{mixed}", "--", url],
            capture_output=True, text=True, timeout=timeout + 5)
        result["http_code"] = r.stdout.strip()
        result["dns_queries"] = dns.queries
        result["ok"] = r.stdout.strip() == "200" and any(
            q.rstrip(".").lower() == PROBE_NAME for q in dns.queries)
        if not result["ok"]:
            result["error"] = "DNS query did not reach the configured mock or HTTP failed"
        return result
    finally:
        if proc:
            proc.terminate()
            try:
                proc.wait(timeout=3)
            except Exception:
                proc.kill()
        httpd.shutdown()
        dns.close()
        shutil.rmtree(tmp, ignore_errors=True)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--mihomo", default=os.environ.get("PH_MIHOMO", "mihomo"))
    ap.add_argument("--timeout", type=float, default=10.0)
    ap.add_argument("--json", dest="json_out", default=None)
    args = ap.parse_args()
    result = run_probe(args.mihomo, args.timeout)
    text = json.dumps(result, ensure_ascii=False, indent=2)
    print(text)
    if args.json_out:
        with open(args.json_out, "w", encoding="utf-8") as f:
            f.write(text + "\n")
    return 0 if result.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
