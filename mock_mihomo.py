#!/usr/bin/env python3
"""A tiny mihomo stand-in for tests and CI.

It intentionally implements only what proxy-harvest uses:

* `-t -f FILE -d DIR` validates a small subset of the Clash/mihomo schema.
* `-d DIR` starts an HTTP API stub plus per-port "proxy" servers that return
  `200 ok`, so TempMihomo / curl integration tests do not need a real kernel
  or Internet access.

It is not a proxy and must never be used as one.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

try:
    import yaml
except ImportError:
    sys.exit("mock_mihomo requires pyyaml")


REQUIRED = {
    "vless": ("uuid",),
    "vmess": ("uuid",),
    "trojan": ("password",),
    "ss": ("cipher", "password"),
    "ssr": ("cipher", "password", "protocol", "obfs"),
    "hysteria2": ("password",),
    "tuic": ("uuid", "password"),
    "anytls": ("password",),
}


def load_config(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        cfg = yaml.safe_load(f) or {}
    if not isinstance(cfg, dict):
        raise ValueError("配置根节点不是字典")
    return cfg


def validate(cfg: dict) -> list[str]:
    errors: list[str] = []
    proxies = cfg.get("proxies") or []
    if not isinstance(proxies, list):
        return ["proxies 不是列表"]
    reserved = {"DIRECT", "REJECT", "REJECT-DROP", "PASS", "COMPATIBLE",
                "GLOBAL", "AUTO", "PROXY"}
    names = set()
    for i, p in enumerate(proxies):
        if not isinstance(p, dict):
            errors.append(f"proxies[{i}] 不是字典")
            continue
        name = str(p.get("name") or "")
        typ = str(p.get("type") or "")
        if not name:
            errors.append(f"proxies[{i}] 缺 name")
        elif name.upper() in reserved:
            errors.append(f"节点名 {name!r} 与内核保留名冲突")
        elif name in names:
            errors.append(f"重复 name: {name}")
        names.add(name)
        if typ not in REQUIRED:
            errors.append(f"{name or i}: 未知 type {typ!r}")
            continue
        try:
            port = int(p.get("port"))
            if not 1 <= port <= 65535:
                raise ValueError
        except (TypeError, ValueError):
            errors.append(f"{name or i}: 端口无效")
        if not str(p.get("server") or "").strip():
            errors.append(f"{name or i}: 缺 server")
        for key in REQUIRED[typ]:
            if not str(p.get(key) or "").strip():
                errors.append(f"{name or i}: 缺 {key}")

    for i, listener in enumerate(cfg.get("listeners") or []):
        if not isinstance(listener, dict):
            errors.append(f"listeners[{i}] 不是字典")
            continue
        try:
            port = int(listener.get("port"))
            if not 1 <= port <= 65535:
                raise ValueError
        except (TypeError, ValueError):
            errors.append(f"listeners[{i}] 端口无效")
        if listener.get("type") not in ("mixed", "http", "socks"):
            errors.append(f"listeners[{i}] type 无效")
    if "dns" in cfg and not isinstance(cfg.get("dns"), dict):
        errors.append("dns 不是字典")
    return errors


class Server(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True
    kind = "proxy"
    api_names: list[str] = []


def make_proxy_handler(kind: str, names: list[str]):
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *_args):
            return

        def _send(self, code: int, body: bytes, ctype="application/json"):
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _json(self, obj):
            self._send(200, json.dumps(obj).encode("utf-8"))

        def do_GET(self):
            path = urllib.parse.urlsplit(self.path).path
            if kind == "api":
                if path == "/proxies":
                    self._json({"proxies": {"PROXY": {"all": names + ["AUTO"]}}})
                    return
                if path.startswith("/group/AUTO/delay"):
                    self._json({n: 100 for n in names})
                    return
                if path.startswith("/proxies/") and path.endswith("/delay"):
                    self._json({"delay": 100})
                    return
                if path == "/version":
                    self._json({"version": "mock", "meta": True})
                    return
                self._json({})
                return
            # Proxy listener: curl sends an absolute-form GET; a fixed 200 is
            # enough for the health/deep-check code paths.
            self._send(200, b"ok", "text/plain")

        def do_PUT(self):
            if kind == "api":
                self._send(204, b"")
            else:
                self._send(200, b"ok", "text/plain")

    return Handler


def start_servers(cfg: dict) -> list[ThreadingHTTPServer]:
    mixed_port = int(cfg.get("mixed-port") or cfg.get("port") or 0)
    controller = str(cfg.get("external-controller") or "127.0.0.1:9090")
    try:
        api_port = int(controller.rsplit(":", 1)[1])
    except Exception:
        api_port = 9090
    names = [str(p.get("name")) for p in cfg.get("proxies") or []
             if isinstance(p, dict) and p.get("name")]
    listener_ports = []
    for listener in cfg.get("listeners") or []:
        if isinstance(listener, dict):
            try:
                listener_ports.append(int(listener.get("port")))
            except (TypeError, ValueError):
                pass

    servers: list[ThreadingHTTPServer] = []

    def serve(kind: str, port: int):
        srv = Server(("127.0.0.1", port), make_proxy_handler(kind, names))
        srv.kind = kind
        servers.append(srv)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        print(f"mock {kind} ready on {port}", flush=True)

    if mixed_port:
        serve("proxy", mixed_port)
    for port in listener_ports:
        serve("proxy", port)
    serve("api", api_port)
    return servers


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("-t", action="store_true", help="test config only")
    ap.add_argument("-f", default=None, help="config path")
    ap.add_argument("-d", default=None, help="config dir")
    ap.add_argument("--version", action="store_true")
    args = ap.parse_args()
    if args.version:
        print("mock-mihomo 1.0")
        return 0
    path = args.f
    if not path and args.d:
        path = os.path.join(args.d, "config.yaml")
    if not path:
        print("mock_mihomo: need -f or -d", file=sys.stderr)
        return 2
    try:
        cfg = load_config(path)
    except Exception as e:
        print(f"mock_mihomo: {e}", file=sys.stderr)
        return 1
    errors = validate(cfg)
    if args.t:
        label = os.path.basename(path)
        if errors:
            for e in errors:
                print(f"mock_mihomo: {e}", file=sys.stderr)
            print(f"configuration file {label} test failed")
            return 1
        print(f"configuration file {label} test is successful")
        return 0
    if errors:
        for e in errors:
            print(f"mock_mihomo: {e}", file=sys.stderr)
        return 1
    start_servers(cfg)
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        return 0
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
