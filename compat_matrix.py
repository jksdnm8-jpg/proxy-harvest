#!/usr/bin/env python3
"""Kernel compatibility matrix for proxy-harvest.

Runs a fixed set of generated configs through `mihomo -t` (or the mock kernel)
and prints a Markdown / JSON table. Use it:

    python compat_matrix.py --mihomo mihomo.exe
    python compat_matrix.py --mihomo mock_mihomo.py --json-out matrix.json

CI intentionally uses mock_mihomo.py so it does not download a kernel; release
checks should run the same script against the real versions you care about.
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
from typing import Any, Callable, Dict, List

import configgen

Proxy = Dict[str, Any]

CASES: Dict[str, Callable[[], Dict[str, Any]]] = {
    "ss": lambda: configgen.build_config(
        [{"name": "ss", "type": "ss", "server": "127.0.0.1", "port": 1,
          "cipher": "aes-128-gcm", "password": "p"}], 2300, 9300),
    "vmess": lambda: configgen.build_config(
        [{"name": "vmess", "type": "vmess", "server": "127.0.0.1", "port": 1,
          "uuid": "00000000-0000-0000-0000-000000000000", "alterId": 0,
          "cipher": "auto"}], 2301, 9301),
    "vless": lambda: configgen.build_config(
        [{"name": "vless", "type": "vless", "server": "127.0.0.1", "port": 1,
          "uuid": "00000000-0000-0000-0000-000000000000", "network": "tcp",
          "tls": True, "servername": "example.com"}], 2302, 9302),
    "trojan": lambda: configgen.build_config(
        [{"name": "trojan", "type": "trojan", "server": "127.0.0.1", "port": 1,
          "password": "p", "sni": "example.com"}], 2303, 9303),
    "hysteria2": lambda: configgen.build_config(
        [{"name": "hy2", "type": "hysteria2", "server": "127.0.0.1", "port": 1,
          "password": "p", "sni": "example.com"}], 2304, 9304),
    "tuic": lambda: configgen.build_config(
        [{"name": "tuic", "type": "tuic", "server": "127.0.0.1", "port": 1,
          "uuid": "00000000-0000-0000-0000-000000000000", "password": "p"}],
        2305, 9305),
    "anytls": lambda: configgen.build_config(
        [{"name": "anytls", "type": "anytls", "server": "127.0.0.1", "port": 1,
          "password": "p", "sni": "example.com"}], 2306, 9306),
    "dns-fake-ip": lambda: configgen.build_config(
        [{"name": "ss", "type": "ss", "server": "127.0.0.1", "port": 1,
          "cipher": "aes-128-gcm", "password": "p"}], 2307, 9307,
        dns=configgen.default_dns_config()),
    "groups": lambda: configgen.build_config(
        [{"name": "ss", "type": "ss", "server": "127.0.0.1", "port": 1,
          "cipher": "aes-128-gcm", "password": "p"}], 2308, 9308,
        with_groups=True, proto_groups={"ss": ["ss"]}),
    "listeners": lambda: dict(
        configgen.build_config(
            [{"name": "ss", "type": "ss", "server": "127.0.0.1", "port": 1,
              "cipher": "aes-128-gcm", "password": "p"}], 2309, 9309),
        listeners=[{"name": "extra", "type": "mixed", "port": 7891}]),
}


def _version(binary: str) -> str:
    cmd = ([sys.executable, binary, "--version"] if binary.endswith(".py")
           else [binary, "-v"])
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        return (r.stdout or r.stderr).strip().splitlines()[0][:80]
    except Exception as e:
        return f"version error: {e}"


def run_case(binary: str, name: str, factory: Callable[[], Dict[str, Any]],
             timeout: float = 20.0) -> Dict[str, Any]:
    tmp = tempfile.mkdtemp(prefix="ph-compat-")
    try:
        cfg = factory()
        path = os.path.join(tmp, "config.yaml")
        with open(path, "w", encoding="utf-8", newline="\n") as f:
            import yaml
            yaml.safe_dump(cfg, f, allow_unicode=True, sort_keys=False)
        cmd = ([sys.executable, binary] if binary.endswith(".py") else [binary]) + \
              ["-t", "-f", path, "-d", tmp]
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            out = (r.stdout + r.stderr).strip().replace("\n", " ")[:300]
            return {"case": name, "ok": r.returncode == 0, "code": r.returncode,
                    "detail": out}
        except subprocess.TimeoutExpired:
            return {"case": name, "ok": False, "code": "timeout",
                    "detail": f"timeout after {timeout}s"}
    except Exception as e:
        return {"case": name, "ok": False, "code": "error", "detail": str(e)}
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def run_matrix(binaries: List[str], cases: Dict[str, Callable[[], Dict[str, Any]]] = None,
               timeout: float = 20.0) -> Dict[str, Any]:
    result: Dict[str, Any] = {"binaries": [], "cases": list((cases or CASES).keys())}
    for b in binaries:
        result["binaries"].append({
            "path": b, "version": _version(b),
            "results": [run_case(b, n, f, timeout)
                        for n, f in (cases or CASES).items()],
        })
    return result


def to_markdown(result: Dict[str, Any]) -> str:
    bins = result["binaries"]
    lines = ["# mihomo compatibility matrix", ""]
    lines.append("| case | " + " | ".join(b["version"] for b in bins) + " |")
    lines.append("|---|" + "|".join(["---"] * len(bins)) + "|")
    for i, case in enumerate(result["cases"]):
        cells = []
        for b in bins:
            r = b["results"][i]
            cells.append("PASS" if r["ok"] else f"FAIL ({r['code']})")
        lines.append(f"| {case} | " + " | ".join(cells) + " |")
    lines.append("")
    for b in bins:
        for r in b["results"]:
            if not r["ok"]:
                lines.append(f"- `{b['path']}` / `{r['case']}`: {r['detail']}")
    return "\n".join(lines) + "\n"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--mihomo", action="append", default=None,
                    help="kernel binary; repeat for multiple versions")
    ap.add_argument("--timeout", type=float, default=20.0)
    ap.add_argument("--json-out", default=None)
    ap.add_argument("--md-out", default=None)
    ap.add_argument("--only", default=None, help="comma-separated case names")
    args = ap.parse_args()
    bins = args.mihomo or [os.environ.get("PH_MIHOMO", "mihomo")]
    cases = CASES
    if args.only:
        wanted = [x.strip() for x in args.only.split(",") if x.strip()]
        cases = {k: v for k, v in CASES.items() if k in wanted}
    result = run_matrix(bins, cases, args.timeout)
    text = to_markdown(result)
    print(text)
    if args.json_out:
        with open(args.json_out, "w", encoding="utf-8") as f:
            json.dump(result, f, ensure_ascii=False, indent=2)
            f.write("\n")
    if args.md_out:
        with open(args.md_out, "w", encoding="utf-8") as f:
            f.write(text)
    return 0 if all(r["ok"] for b in result["binaries"] for r in b["results"]) else 1


if __name__ == "__main__":
    raise SystemExit(main())
