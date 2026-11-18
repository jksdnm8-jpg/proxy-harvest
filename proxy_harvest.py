#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""免费代理一键抓取 / 测速 / 筛选 / 记录 / 落地（完善版）。

设计原则
--------
1. **隔离**：抓取和测速在独立的临时 mihomo 实例（随机端口）里进行，
   完全不碰正在使用的生产 mihomo（2080/9090）。测完即销毁。
2. **默认只读**：默认只抓取、测速、记录结果，不写生产配置。
   要落地必须显式加 `--apply`，且落地前自动备份。
3. **快速**：用 mihomo 的 group delay API 一次性并发测全部节点（几秒），
   可选 `--keep N` 对前 N 个再做 curl GET 深度验证。
4. **可回滚**：每次 apply 存档旧配置，`--rollback` 一键还原。
5. **历史继承**：把完整节点定义写进 history，坏节点池时可用
   `--inherit` 把历史常青节点拉回候选池。
6. **机器可读**：`--json FILE` 导出结构化结果，便于其它 AI/脚本调用。

典型用法
--------
  python proxy_harvest.py                      # 抓+测+记录，不落地（安全）
  python proxy_harvest.py --apply              # 上面 + 把好节点写回生产配置
  python proxy_harvest.py --apply --rules split
  python proxy_harvest.py --keep 15            # 额外 curl 验证前 15 个
  python proxy_harvest.py --sources-only       # 只抓，写临时配置
  python proxy_harvest.py --inherit            # 拉回历史常青节点一起测
  python proxy_harvest.py --status             # 看当前生产配置状态
  python proxy_harvest.py --history-stats      # 分析节点寿命
  python proxy_harvest.py --rollback           # 从最近备份还原生产配置

退出码
------
  0  成功（找到了可用节点）
  1  没有任何节点通过测试
  2  参数/环境错误
  130 用户中断
"""

__version__ = "0.0.1"

import argparse
import base64
import codecs
import csv
import datetime
import hashlib
import json
import os
import re
import secrets
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.parse
import urllib.request
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    import yaml
except ImportError:
    sys.exit("缺少 pyyaml：pip install pyyaml  （或用 python -m pip install pyyaml）")

# ---------------- 常量 / 可配置路径 ----------------
# 优先级：环境变量 > 脚本同目录的 config.json > 默认（脚本所在目录）
# 这样同一份代码可以放在任意机器上，不需要改源码。
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))


def _load_settings():
    settings = {}
    cfg_path = os.path.join(SCRIPT_DIR, "config.json")
    if os.path.isfile(cfg_path):
        try:
            with open(cfg_path, "r", encoding="utf-8") as f:
                settings = json.load(f)
        except Exception:
            pass
    # 环境变量覆盖（前缀 PH_ = Proxy Harvest）
    for key in ("base_dir", "mihomo_exe", "mixed_port", "api_port", "secret"):
        env = os.environ.get("PH_" + key.upper())
        if env:
            settings[key] = env
    return settings


_SETTINGS = _load_settings()
BASE = os.path.abspath(_SETTINGS.get("base_dir") or SCRIPT_DIR)
MIHOMO_EXE = os.path.abspath(_SETTINGS.get("mihomo_exe") or
                             os.path.join(BASE, "mihomo", "mihomo.exe"))
PROD_CONF_DIR = os.path.join(BASE, "config")
PROD_CONFIG = os.path.join(PROD_CONF_DIR, "config.yaml")
BACKUP_DIR = os.path.join(BASE, "backups")
HISTORY_DIR = os.path.join(BASE, "history")
TMP_DIR = os.path.join(BASE, ".harvest-tmp")
LOG_FILE = os.path.join(BASE, "harvest.log")
CURL = _SETTINGS.get("curl", "curl.exe")
# 生产 API secret 在运行时用 resolve_prod_secret() 解算（见下），
# 不在导入期固定，这样 --secret 和"沿用现有配置"都能生效。
PROD_PORT = int(_SETTINGS.get("mixed_port", 2080))
PROD_API = int(_SETTINGS.get("api_port", 9090))


# v0.01 及更早版本的默认 secret，必须视为弱口令
LEGACY_DEFAULT_SECRETS = {"box", "", "secret", "clash", "123456"}
MIN_SECRET_LEN = 8


def is_weak_secret(s):
    """判断 secret 是否属于弱值：空、旧默认值、或长度不足。"""
    s = (s or "").strip()
    if not s:
        return True
    if s.lower() in LEGACY_DEFAULT_SECRETS:
        return True
    return len(s) < MIN_SECRET_LEN


def read_secret_from_config(path=None):
    """从现有生产 config.yaml 里读出 secret（用于沿用旧值，避免客户端失联）。"""
    p = path or PROD_CONFIG
    try:
        with open(p, "r", encoding="utf-8") as f:
            cfg = yaml.safe_load(f) or {}
        v = cfg.get("secret")
        return str(v) if v else ""
    except Exception:
        return ""


def resolve_prod_secret(cli_secret=None):
    """secret 解算优先级：
         1. 命令行 --secret
         2. config.json / PH_SECRET
         3. 现有 config.yaml 里的值（沿用，客户端不失联）
         4. 新生成
    任一来源是弱值（box / 空 / 太短）都会被拒绝并重新生成。

    返回 (secret, 来源说明, 是否为新生成)
    """
    for value, origin in ((cli_secret, "命令行 --secret"),
                          (_SETTINGS.get("secret"), "config.json / PH_SECRET"),
                          (read_secret_from_config(), "现有 config.yaml")):
        if not value:
            continue
        if is_weak_secret(value):
            log(f"  ⚠ {origin} 的 secret 过弱（{value!r}），已忽略并重新生成",
                also_file=False)
            continue
        return str(value), origin, False
    return secrets.token_hex(16), "新生成", True

# ---------------- 订阅源（可配置） ----------------
# 原始 GitHub raw 地址；抓取时先套 proxy_prefix，失败再直连兜底。
RAW_SOURCES = [
    "https://raw.githubusercontent.com/Mahdi0024/ProxyCollector/master/sub/proxies.txt",
    "https://raw.githubusercontent.com/mahdibland/V2RayAggregator/master/sub/sub_merge.txt",
    "https://raw.githubusercontent.com/ermaozi/get_subscribe/main/subscribe/v2ray.txt",
    "https://raw.githubusercontent.com/ripaojiedian/freenode/main/sub",
    "https://raw.githubusercontent.com/peasoft/NoMoreWalls/master/list.txt",
    "https://raw.githubusercontent.com/mfuu/v2ray/master/v2ray",
]

# 国内加速前缀（config.json 的 proxy_prefix 可换；设为空字符串则全部直连）
PROXY_PREFIX = _SETTINGS.get("proxy_prefix", "https://gh-proxy.com/")

# 允许 config.json 直接覆盖整个源列表
SOURCES = _SETTINGS.get("sources") or [PROXY_PREFIX + s for s in RAW_SOURCES]
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/157.0.0.0 Safari/537.36"
DEFAULT_DELAY_URL = "https://github.com/"   # 用 github 做 delay，能返回延迟即真实连通
DEFAULT_TEST_URL = "https://github.com/"


# ---------------- 工具 ----------------
def acquire_lock():
    """P2-14：简单运行锁，防止 cron 两次运行重叠。

    用 O_EXCL 创建锁文件；已存在且进程还活着就返回 None。
    """
    lock = os.path.join(BASE, ".harvest.lock")
    os.makedirs(BASE, exist_ok=True)
    try:
        fd = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
        os.write(fd, str(os.getpid()).encode())
        os.close(fd)
        return lock
    except FileExistsError:
        try:
            pid = int(open(lock, encoding="utf-8").read().strip() or 0)
        except Exception:
            pid = 0
        alive = False
        if pid:
            try:
                os.kill(pid, 0)      # 只探活，不发信号
                alive = True
            except OSError:
                alive = False
        if alive:
            log(f"另一个实例正在运行（PID {pid}），本次退出")
            return None
        # 陈旧锁，直接接管
        log(f"发现陈旧锁（PID {pid} 已不在），已接管")
        try:
            os.remove(lock)
        except OSError:
            pass
        return acquire_lock()
    except Exception as e:
        log(f"建锁失败，继续运行：{e}")
        return ""


def release_lock(lock):
    if lock:
        try:
            os.remove(lock)
        except OSError:
            pass


def log(msg, also_file=True):
    line = f"[{datetime.datetime.now():%H:%M:%S}] {msg}"
    print(line, flush=True)
    if also_file:
        try:
            os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
            # P2-14：简单轮转，超过 2 MB 就滚到 .1，避免日志无限增长
            if os.path.isfile(LOG_FILE) and os.path.getsize(LOG_FILE) > 2 * 1024 * 1024:
                bak = LOG_FILE + ".1"
                try:
                    if os.path.exists(bak):
                        os.remove(bak)
                    os.replace(LOG_FILE, bak)
                except OSError:
                    pass
            with codecs.open(LOG_FILE, "a", "utf-8") as f:
                f.write(line + "\n")
        except Exception:
            pass


def fail(msg, code=1):
    log("错误：" + msg)
    sys.exit(code)


def free_port(start):
    for p in range(start, start + 200):
        s = socket.socket()
        try:
            s.bind(("127.0.0.1", p))
            return p
        except OSError:
            continue
        finally:
            s.close()
    return None


def port_up(p):
    try:
        s = socket.create_connection(("127.0.0.1", p), timeout=0.4)
        s.close()
        return True
    except Exception:
        return False


def system_proxy_on():
    try:
        import winreg
        k = winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                           r"Software\Microsoft\Windows\CurrentVersion\Internet Settings")
        v, _ = winreg.QueryValueEx(k, "ProxyEnable")
        winreg.CloseKey(k)
        return int(v) == 1
    except Exception:
        return False


# ---------------- 抓取与解析 ----------------
def _open(url, timeout=60):
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open(req, timeout=timeout) as r:
        return r.read().decode("utf-8", "ignore")


def fetch(url):
    """抓订阅。若 URL 带加速前缀，失败时自动回退到去掉前缀的直连地址。"""
    try:
        return _open(url)
    except Exception:
        # 直连兜底：把已知前缀剥掉再试一次
        if PROXY_PREFIX and url.startswith(PROXY_PREFIX):
            direct = url[len(PROXY_PREFIX):]
            log(f"    前缀失败，直连重试 {direct[-32:]}")
            return _open(direct)
        raise


def decode_body(text):
    s = text.strip()
    b = "".join(s.split())
    if "://" in b[:2000]:
        return s
    b = b.replace("-", "+").replace("_", "/")
    b += "=" * (-len(b) % 4)
    try:
        return base64.b64decode(b).decode("utf-8", "ignore")
    except Exception:
        return s


def qs(u):
    return {k: v[0] for k, v in urllib.parse.parse_qs(urllib.parse.urlparse(u).query).items()}


def hostport(netloc):
    hp = netloc.rpartition("@")[2]
    if hp.startswith("["):
        h, _, p = hp[1:].partition("]:")
        return h, int(p or 0)
    h, _, p = hp.rpartition(":")
    return h, int(p or 0)


def _alpn_list(p):
    if not p.get("alpn"):
        return None
    items = [x for x in re.split(r"[,;]", p["alpn"]) if x]
    return items or None


def apply_transport(d, p, fallback_host):
    """填充传输层字段（vless / trojan 共用）。

    p 是 parse_qs 解出来的 dict，值已解码，不要再 unquote。
    支持：tcp / ws / httpupgrade / grpc / h2 / http / xhttp
    """
    net = p.get("type", "tcp") or "tcp"
    host = p.get("host") or p.get("sni") or fallback_host
    path = p.get("path") or "/"

    d["network"] = net
    if net == "ws":
        d["ws-opts"] = {"path": path, "headers": {"Host": host}}
    elif net == "httpupgrade":
        d["network"] = "ws"
        d["ws-opts"] = {"path": path, "headers": {"Host": host},
                        "v2ray-http-upgrade": True}
    elif net == "grpc":
        d["grpc-opts"] = {"grpc-service-name": p.get("serviceName", "")}
    elif net in ("h2", "http"):
        d["network"] = "h2"
        d["h2-opts"] = {"host": [x for x in host.split(",") if x], "path": path}
    elif net == "xhttp":
        d["xhttp-opts"] = {"path": path, "host": host,
                          "mode": p.get("mode", "auto")}

    alpn = _alpn_list(p)
    if alpn:
        d["alpn"] = alpn
    return d


def p_vless(u):
    p = qs(u)
    # mihomo 不认 vless 加密（encryption 非 none），这类节点注定测不通，直接跳过
    if p.get("encryption", "none") not in ("", "none"):
        return None
    h, port = hostport(urllib.parse.urlparse(u).netloc)
    name = urllib.parse.unquote(urllib.parse.urlparse(u).fragment) or h
    d = {"name": name[:36], "type": "vless", "server": h, "port": port,
         "uuid": urllib.parse.urlparse(u).username, "udp": True,
         "client-fingerprint": p.get("fp", "chrome")}
    sec = p.get("security", "")
    sni = p.get("sni") or p.get("host") or ""
    if sec in ("tls", "reality"):
        d["tls"] = True
        if sni:
            d["servername"] = sni
        if p.get("flow"):
            d["flow"] = p["flow"]
        if sec == "reality":
            d["reality-opts"] = {"public-key": p.get("pbk", ""), "short-id": p.get("sid", "")}
        if p.get("allowInsecure") == "1":
            d["skip-cert-verify"] = True
    else:
        d["tls"] = False
    apply_transport(d, p, h)
    return d


def p_vmess(u):
    body = u[8:] + "=" * (-len(u[8:]) % 4)
    try:
        j = json.loads(base64.urlsafe_b64decode(body).decode("utf-8", "ignore"))
    except Exception:
        j = json.loads(base64.b64decode(body).decode("utf-8", "ignore"))
    d = {"name": (j.get("ps") or j.get("add", ""))[:36], "type": "vmess", "server": j["add"],
         "port": int(j["port"]), "uuid": j["id"], "alterId": int(j.get("aid", 0)),
         "cipher": "auto", "udp": True}
    # P1-10：tls 字段只有值为 "tls" 时才算开启；
    # 写成 "none" / "" / "false" 都不应被当成 True。
    if str(j.get("tls") or "").lower() == "tls":
        d["tls"] = True
        d["servername"] = j.get("sni") or j.get("host") or ""
    # 复用公共传输层：vmess 的 net/path/host 语义与 vless/trojan 一致
    p = {
        "type": j.get("net") or "tcp",
        "host": j.get("host") or "",
        "sni": j.get("sni") or "",
        "path": j.get("path") or "/",
        "serviceName": j.get("path") or "",   # vmess 的 grpc service 常放在 path
        "alpn": j.get("alpn") or "",
    }
    apply_transport(d, p, j["add"])
    return d


def p_trojan(u):
    p = qs(u)
    h, port = hostport(urllib.parse.urlparse(u).netloc)
    name = urllib.parse.unquote(urllib.parse.urlparse(u).fragment) or h
    d = {"name": name[:36], "type": "trojan", "server": h, "port": port,
         "password": urllib.parse.urlparse(u).username, "udp": True}
    if p.get("sni"):
        d["sni"] = p["sni"]
    # 只在节点明确声明 allowInsecure=1 时才跳过证书校验
    if p.get("allowInsecure") == "1":
        d["skip-cert-verify"] = True
    apply_transport(d, p, h)
    return d


def parse_ss_plugin(raw):
    """解析 SIP002 的 plugin 串。

    形如：obfs-local;obfs=tls;obfs-host=x.com
          v2ray-plugin;mode=websocket;host=h;path=/p;tls;mux
    返回 (mihomo 插件名, 选项 dict)；不认识的插件返回 (None, None)。
    """
    if not raw:
        return None, None
    parts = raw.split(";")
    name = parts[0].strip()
    kv, flags = {}, set()
    for s in parts[1:]:
        s = s.strip()
        if not s:
            continue
        k, sep, v = s.partition("=")
        if sep:
            kv[k] = v
        else:
            flags.add(s)

    if name in ("obfs-local", "simple-obfs"):
        return "obfs", {"mode": kv.get("obfs", "http"),
                        "host": kv.get("obfs-host", "")}
    if name == "v2ray-plugin":
        o = {"mode": kv.get("mode", "websocket"),
             "host": kv.get("host", ""),
             "path": kv.get("path", "/")}
        if "tls" in flags:
            o["tls"] = True
        if "mux" in flags:
            o["mux"] = True
        return "v2ray-plugin", o
    return None, None


def p_ss(u):
    body, _, name = u[5:].partition("#")
    name = urllib.parse.unquote(name)
    # 先拆出 SIP002 的 ?plugin=... 查询串，否则 host:port 会带上它导致 int() 失败
    body, _, query = body.partition("?")
    body = body.rstrip("/")
    plugin_raw = urllib.parse.parse_qs(query).get("plugin", [""])[0]

    if "@" in body:
        ui, hp = body.split("@", 1)
        try:
            ui = base64.urlsafe_b64decode(ui + "=" * (-len(ui) % 4)).decode()
        except Exception:
            pass
        m, _, pw = ui.partition(":")
        h, _, pt = hp.partition(":")
    else:
        raw = base64.urlsafe_b64decode(body + "=" * (-len(body) % 4)).decode()
        cred, _, hp = raw.rpartition("@")
        m, _, pw = cred.partition(":")
        h, _, pt = hp.partition(":")

    d = {"name": (name or h)[:36], "type": "ss", "server": h,
         "port": int(pt or 8388), "cipher": m, "password": pw, "udp": True}

    if plugin_raw:
        pl, opts = parse_ss_plugin(plugin_raw)
        if not pl:
            # 不支持的插件：直接丢弃，别当裸 ss 去测（那样必然测不通还浪费名额）
            return None
        d["plugin"] = pl
        d["plugin-opts"] = opts
    return d


def p_hy2(u):
    p = qs(u)
    h, port = hostport(urllib.parse.urlparse(u).netloc)
    name = urllib.parse.unquote(urllib.parse.urlparse(u).fragment) or h
    d = {"name": name[:36], "type": "hysteria2", "server": h, "port": port,
         "password": urllib.parse.urlparse(u).username or ""}
    if p.get("sni"):
        d["sni"] = p["sni"]
    # 混淆（salamander 等）
    if p.get("obfs"):
        d["obfs"] = p["obfs"]
        d["obfs-password"] = p.get("obfs-password", "")
    # 端口跳跃，如 mport=20000-30000
    if p.get("mport"):
        d["ports"] = p["mport"]
    if p.get("insecure") == "1":
        d["skip-cert-verify"] = True
    alpn = _alpn_list(p)
    if alpn:
        d["alpn"] = alpn
    return d


def p_tuic(u):
    """tuic://uuid:pass@host:port?sni=...&congestion_control=bbr"""
    p = qs(u)
    h, port = hostport(urllib.parse.urlparse(u).netloc)
    name = urllib.parse.unquote(urllib.parse.urlparse(u).fragment) or h
    d = {"name": name[:36], "type": "tuic", "server": h, "port": port,
         "uuid": urllib.parse.urlparse(u).username,
         "password": urllib.parse.urlparse(u).password or "",
         "udp": True, "skip-cert-verify": True}
    if p.get("sni"):
        d["sni"] = p["sni"]
    if p.get("congestion_control"):
        d["congestion-controller"] = p["congestion_control"]
    if p.get("alpn"):
        d["alpn"] = [x for x in re.split(r"[,;]", p["alpn"]) if x]
    return d


def p_anytls(u):
    """anytls://password@host:port?sni=...  （新兴协议，免费池开始出现）"""
    p = qs(u)
    h, port = hostport(urllib.parse.urlparse(u).netloc)
    name = urllib.parse.unquote(urllib.parse.urlparse(u).fragment) or h
    d = {"name": name[:36], "type": "anytls", "server": h, "port": port,
         "password": urllib.parse.urlparse(u).username or "", "udp": True,
         "client-fingerprint": p.get("fp", "chrome"), "skip-cert-verify": True}
    if p.get("sni"):
        d["sni"] = p["sni"]
    if p.get("alpn"):
        d["alpn"] = [x for x in re.split(r"[,;]", p["alpn"]) if x]
    return d


def p_ssr(u):
    """ssr://base64(host:port:protocol:method:obfs:pass/?remarks=...)"""
    body = u[6:]
    body += "=" * (-len(body) % 4)
    try:
        raw = base64.urlsafe_b64decode(body).decode("utf-8", "ignore")
    except Exception:
        return None
    main, _, query = raw.partition("/?")
    parts = main.split(":")
    if len(parts) < 6:
        return None
    h, pt, proto, method, obfs, pwd = parts[:6]
    q = {k: v[0] for k, v in urllib.parse.parse_qs(query).items()}

    def _b64get(key):
        raw = q.get(key, "")
        if not raw:
            return ""
        try:
            return base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4)).decode("utf-8", "ignore")
        except Exception:
            return ""

    remarks = _b64get("remarks") or h
    d = {"name": (remarks or h)[:36], "type": "ssr", "server": h, "port": int(pt),
         "cipher": method, "password": pwd, "protocol": proto, "obfs": obfs, "udp": True}
    # P1-10：ssr 的 obfs-param / protocol-param 也常带，缺了认证类节点连不上
    op = _b64get("obfsparam")
    if op:
        d["obfs-param"] = op
    pp = _b64get("protoparam")
    if pp:
        d["protocol-param"] = pp
    return d


PARSERS = {"vless": p_vless, "vmess": p_vmess, "trojan": p_trojan,
           "ss": p_ss, "hysteria2": p_hy2, "hy2": p_hy2,
           "tuic": p_tuic, "anytls": p_anytls, "ssr": p_ssr}

# URI 前缀 -> mihomo type，校验时用
URI_TO_TYPE = {"vless": "vless", "vmess": "vmess", "trojan": "trojan",
               "ss": "ss", "hysteria2": "hysteria2", "hy2": "hysteria2",
               "tuic": "tuic", "anytls": "anytls", "ssr": "ssr"}
VALID_TYPES = set(URI_TO_TYPE.values())

# 协议分组：测试时可按组选择，每组独立排名
PROTO_GROUPS = {
    "ss":     {"ss", "ssr"},
    "vmess":  {"vmess"},
    "vless":  {"vless"},
    "trojan": {"trojan"},
    "hysteria": {"hysteria2"},
    "new":    {"tuic", "anytls"},       # 新兴协议
    "all":    VALID_TYPES,              # 全测
}


def proto_group(proxy_type):
    """返回节点属于哪个组（若多组归属，取第一个非 all）。"""
    for g, types in PROTO_GROUPS.items():
        if g == "all":
            continue
        if proxy_type in types:
            return g
    return "other"


def _count_protocol_lines(text):
    """统计一段订阅文本里有多少行是已知协议的 URI。用于内容校验。"""
    n = 0
    for line in (text or "").splitlines():
        m = re.match(r"^([a-z0-9]+)://", line.strip())
        if m and m.group(1) in PARSERS:
            n += 1
    return n


def harvest(limit, extra_sources=None):
    """多源抓取。

    P1-8：给每个源设配额，避免第一个源把 limit 占满、后面的源永远抓不到。
    P1-9：内容里一个已知协议行都没有（HTML/空/报错页）时视为该源失败。
    """
    srcs = list(SOURCES) + (extra_sources or [])
    if not srcs:
        return []
    # 每源先分基础配额，用完再按需补余量
    quota = max(1, limit // len(srcs))
    out, seen = [], set()
    per_source = {}

    def drain(text, src, cap):
        added = 0
        for line in text.splitlines():
            if len(out) >= limit or added >= cap:
                break
            line = line.strip()
            m = re.match(r"^([a-z0-9]+)://", line)
            if not m or m.group(1) not in PARSERS:
                continue
            try:
                d = PARSERS[m.group(1)](line)
            except Exception:
                continue
            if not d or not d.get("server") or not d.get("port"):
                continue
            key = (d["type"], d["server"], d["port"])
            if key in seen:
                continue
            seen.add(key)
            d["_source"] = src       # 供源健康度统计；落地前会剥离
            d["_group"] = proto_group(d["type"])
            out.append(d)
            added += 1
        return added

    # 第一轮：每源最多 quota 个
    texts = []
    for src in srcs:
        try:
            text = decode_body(fetch(src))
        except Exception as e:
            log(f"  源失败 {src[-38:]:40} {type(e).__name__}")
            per_source[src] = 0
            continue
        if _count_protocol_lines(text) == 0:
            # P1-9：拿到内容但没有一行合法节点，多半是 HTML 错误页
            log(f"  源无效 {src[-38:]:40} 内容无合法节点")
            per_source[src] = 0
            continue
        texts.append((src, text))
        n = drain(text, src, quota)
        per_source[src] = n
        log(f"  {src[-38:]:42} +{n:3}  (配额 {quota})")

    # 第二轮：还没满额就用各源余量补
    if len(out) < limit:
        for src, text in texts:
            if len(out) >= limit:
                break
            n = drain(text, src, limit)
            if n:
                per_source[src] = per_source.get(src, 0) + n
                log(f"  {src[-38:]:42} +{n:3}  (补余量)")

    alive = sum(1 for v in per_source.values() if v)
    log(f"  抓取汇总：{alive}/{len(srcs)} 个源有效，共 {len(out)} 节点")
    return out


def node_id(p):
    """稳定的节点身份：type|server|port 的 sha1 前 10 位。

    P0-3：免费节点重名极常见，而 dedupe 加的 #2 后缀取决于本轮顺序，
    同一个节点这轮可能叫 A#2、下轮叫 A，用名字做身份会把历史串到别的节点。
    """
    key = "{}|{}|{}".format(
        (p.get("type") or "").lower(),
        (p.get("server") or "").lower(),
        p.get("port") or 0,
    )
    return hashlib.sha1(key.encode("utf-8")).hexdigest()[:10]


def ensure_ids(proxies):
    """给每个节点补齐 _id（已有则保留）。"""
    for p in proxies:
        if not p.get("_id"):
            p["_id"] = node_id(p)
    return proxies


def dedupe_names(proxies):
    """统一处理重名，保证名字唯一。

    P2-5：不能只按计数加后缀——输入 A, A, A#2 会得到 A, A#2, A#2（又撞）。
    改为循环自增，直到名字不在已用集合里。
    P0-3：同时补齐稳定 _id。
    """
    ensure_ids(proxies)
    used = set()
    for d in proxies:
        base = d.get("name") or f'{d.get("server")}:{d.get("port")}'
        name = base
        n = 1
        while name in used:
            n += 1
            name = f"{base}#{n}"
        used.add(name)
        d["name"] = name
    return proxies


def validate_proxies(proxies):
    """返回 (good, bad)。bad 是 [(name, 缺失字段或问题)]。
    调用方直接用 good，不要再用 in/not in 对 dict 做成员判断。"""
    good, bad = [], []
    for p in proxies:
        miss = [k for k in ("name", "type", "server", "port") if not p.get(k)]
        if miss:
            bad.append((p.get("name") or "?", miss))
            continue
        if p.get("type") not in VALID_TYPES:
            bad.append((p["name"], ["type"]))
            continue
        try:
            int(p["port"])
        except (TypeError, ValueError):
            bad.append((p["name"], ["port"]))
            continue
        good.append(p)
    return good, bad


# ---------------- 配置 ----------------
def clean_proxy(p):
    """剥掉我们自己的元数据字段，只留 mihomo 认识的配置。"""
    return {k: v for k, v in p.items() if not k.startswith("_")}


def make_config(proxies, port, api_port, rules=None, with_groups=False, secret=None,
                insecure=False):
    """with_groups=True 时为每个协议组建一个 select 组，方便组级别测速。
    secret: 显式传入；默认用生产 secret。临时实例应传随机值。
    insecure: True 时才保留 skip-cert-verify，默认剥离（更安全）。"""
    proxies = [clean_proxy(p) for p in proxies]
    if not insecure:
        proxies = [{k: v for k, v in p.items() if k != "skip-cert-verify"} for p in proxies]
    names = [p["name"] for p in proxies]
    groups = [
        {"name": "AUTO", "type": "url-test", "url": "http://cp.cloudflare.com",
         "interval": 300, "tolerance": 100, "proxies": names},
        {"name": "PROXY", "type": "select", "proxies": ["AUTO"] + names},
    ]
    if with_groups:
        for g, types in PROTO_GROUPS.items():
            if g == "all":
                continue
            gn = [p["name"] for p in proxies if p["type"] in types]
            if gn:
                groups.append({"name": f"G_{g}", "type": "select", "proxies": ["AUTO"] + gn})
    return {
        "mixed-port": port,
        "external-controller": f"127.0.0.1:{api_port}",
        "secret": secret if secret is not None else "",
        "allow-lan": False, "mode": "rule", "log-level": "warning",
        "proxies": proxies,
        "proxy-groups": groups,
        "rules": rules or ["MATCH,PROXY"],
    }


def write_yaml(path, cfg):
    """原子写入：先写同目录 .tmp，再 os.replace 覆盖。
    避免写到一半崩溃留下损坏的配置。"""
    d = os.path.dirname(path) or "."
    os.makedirs(d, exist_ok=True)
    tmp = f"{path}.{os.getpid()}.tmp"
    try:
        with open(tmp, "w", encoding="utf-8", newline="\n") as f:
            yaml.safe_dump(cfg, f, allow_unicode=True, sort_keys=False)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            try:
                os.remove(tmp)
            except OSError:
                pass


def split_rules():
    return ["GEOIP,private,DIRECT,no-resolve",
            "GEOSITE,private,DIRECT",
            "GEOSITE,cn,DIRECT", "GEOIP,CN,DIRECT",
            "DOMAIN-SUFFIX,cn,DIRECT", "MATCH,PROXY"]


# ---------------- 临时 mihomo 实例 ----------------
class TempMihomo:
    """独立的测速实例：每次运行用 tempfile.mkdtemp 建新目录，
    随机 API secret，跑完销毁。不会和另一次运行抢端口/目录。"""

    def __init__(self, parent_dir, port, api_port, proxies, rules=None, insecure=False):
        os.makedirs(parent_dir, exist_ok=True)
        self.dir = tempfile.mkdtemp(prefix="run-", dir=parent_dir)
        self.port, self.api_port = port, api_port
        self.secret = secrets.token_hex(16)
        self.proc = None
        self.proxies = proxies
        self.rules = rules
        self.insecure = insecure
        self.config = os.path.join(self.dir, "config.yaml")
        write_yaml(self.config,
                   make_config(proxies, port, api_port, rules,
                               secret=self.secret, insecure=insecure))

    def __enter__(self):
        try:
            flags = getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000)
            self.proc = subprocess.Popen([MIHOMO_EXE, "-d", self.dir], creationflags=flags)
            for i in range(120):                 # 最多 30 秒
                time.sleep(0.25)
                if self.proc.poll() is not None:
                    raise RuntimeError(
                        f"临时 mihomo 提前退出，退出码 {self.proc.returncode}（配置 {self.config}）")
                if port_up(self.port) and port_up(self.api_port):
                    log(f"  临时测速实例就绪：端口 {self.port} / API {self.api_port}（{(i+1)*0.25:.1f}s）")
                    return self
            raise RuntimeError(f"临时 mihomo 启动超时（30s，配置 {self.config}）")
        except BaseException:
            # P2-6：__enter__ 抛异常时 __exit__ 不会被调用，这里自己清理，
            # 否则 run-xxxx 临时目录和进程都会残留。
            self._stop()
            shutil.rmtree(self.dir, ignore_errors=True)
            raise

    def __exit__(self, *a):
        self._stop()
        time.sleep(0.5)
        shutil.rmtree(self.dir, ignore_errors=True)

    def _restart_plain(self):
        """用不带 listeners 的原配置重启实例。成功返回 True。"""
        self._stop()
        try:
            write_yaml(self.config,
                       make_config(self.proxies, self.port, self.api_port, self.rules,
                                   secret=self.secret, insecure=self.insecure))
        except Exception as e:
            log(f"  重写基础配置失败：{e}")
            return False
        flags = getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000)
        try:
            self.proc = subprocess.Popen([MIHOMO_EXE, "-d", self.dir], creationflags=flags)
        except Exception as e:
            log(f"  启动基础实例失败：{e}")
            return False
        for _ in range(120):
            time.sleep(0.25)
            if self.proc.poll() is not None:
                return False
            if port_up(self.port) and port_up(self.api_port):
                log("  基础实例已恢复")
                return True
        return False

    def api(self, path, method="GET", data=None, timeout=10):
        url = f"http://127.0.0.1:{self.api_port}{path}"
        headers = {"Authorization": f"Bearer {self.secret}"}
        body = None
        if data is not None:
            body = json.dumps(data, ensure_ascii=False).encode("utf-8")
            headers["Content-Type"] = "application/json"
        req = urllib.request.Request(url, data=body, headers=headers, method=method)
        # P1-6：显式禁用代理。默认 urlopen 会读系统代理/环境变量，
        # 生产代理开着而 127.* 没豁免时，访问本地 API 会被转发出去。
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        with opener.open(req, timeout=timeout) as r:
            raw = r.read().decode("utf-8", "ignore")
        return json.loads(raw) if raw else {}

    def pin(self, name):
        self.api("/proxies/PROXY", "PUT", {"name": name})

    def delay_all(self, delay_url, timeout_ms):
        q = urllib.parse.quote(delay_url, safe="")
        # 组 API 内部并发，timeout 是所有节点共享的等待上限
        try:
            d = self.api(f"/group/AUTO/delay?url={q}&timeout={timeout_ms}",
                         timeout=max(30, timeout_ms // 1000 + 15))
            if isinstance(d, dict):
                return {k: int(v) for k, v in d.items()
                        if isinstance(v, (int, float)) and 0 < v < timeout_ms}
        except Exception as e:
            log(f"  组批量测速失败：{type(e).__name__}，退回逐节点并发")
        names = [n for n in self.api("/proxies").get("proxies", {})
                 .get("PROXY", {}).get("all", []) if n not in ("AUTO", "PROXY")]
        out = {}

        def one(n):
            try:
                r = self.api(f"/proxies/{urllib.parse.quote(n, safe='')}/delay?url={q}&timeout={timeout_ms}",
                             timeout=max(10, timeout_ms // 1000 + 3))
                v = r.get("delay")
                return n, int(v) if v else None
            except Exception:
                return n, None

        with ThreadPoolExecutor(max_workers=16) as ex:
            for f in as_completed([ex.submit(one, n) for n in names]):
                n, v = f.result()
                if v:
                    out[n] = v
        return out

    def curl_check(self, name, url, timeout):
        """单节点串行验证（保留作为兜底）。"""
        try:
            self.pin(name)
        except Exception:
            return None, 99.0
        return self._curl_via(f"http://127.0.0.1:{self.port}", url, timeout)

    @staticmethod
    def _curl_via(proxy_url, url, timeout):
        """通过指定本地代理做一次 curl，返回 (http_code|None, 耗时秒)。"""
        try:
            r = subprocess.run(
                [CURL, "-s", "-o", "NUL", "-w", "%{http_code} %{time_total}",
                 "--max-time", str(timeout), "-x", proxy_url, url],
                capture_output=True, text=True, timeout=timeout + 5)
            parts = r.stdout.strip().split()
            if parts and parts[0] == "200":
                return 200, float(parts[1]) if len(parts) > 1 else 99.0
            return int(parts[0]) if parts and parts[0].isdigit() else 0, 99.0
        except Exception:
            return None, 99.0

    def curl_check_many(self, names, url, timeout, workers=12, base_port=24000):
        """P2-11：并发深度验证。

        做法：为每个候选节点在配置里加一个 mixed listener（独立本地端口，
        直接绑定到该节点），重启临时实例后，用线程池同时 curl 各自的端口。
        相比串行 `pin()` + 单端口，N 个节点的耗时从 O(N) 降到约 O(1)。
        """
        if not names:
            return {}
        # 分配端口：从 base_port 起，跳过已占用的
        ports, p = {}, base_port
        for n in names:
            while True:
                s = socket.socket()
                try:
                    s.bind(("127.0.0.1", p))
                    ports[n] = p
                    p += 1
                    break
                except OSError:
                    p += 1
                    if p > base_port + 500:
                        raise RuntimeError("找不到足够的空闲端口做并发验证")
                finally:
                    s.close()

        # 重建配置：在原配置基础上加 listeners
        cfg = make_config(self.proxies, self.port, self.api_port, self.rules,
                          secret=self.secret, insecure=self.insecure)
        cfg["listeners"] = [
            {"name": f"dl-{i}", "type": "mixed", "port": ports[n],
             "listen": "127.0.0.1", "proxy": n}
            for i, n in enumerate(names)
        ]
        write_yaml(self.config, cfg)

        # 重启实例以加载 listeners
        self._stop()
        flags = getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000)
        self.proc = subprocess.Popen([MIHOMO_EXE, "-d", self.dir], creationflags=flags)
        ok_start = False
        for _ in range(120):
            time.sleep(0.25)
            if self.proc.poll() is not None:
                break
            if all(port_up(pt) for pt in ports.values()):
                ok_start = True
                break

        if not ok_start:
            # P1-4：进程已退，绝不能直接调 curl_check（它要调 API，进程死了必然全失败）。
            # 先用不带 listeners 的原配置把实例恢复起来，再串行验证。
            log("  并发验证实例启动失败，尝试恢复基础实例后串行验证")
            if not self._restart_plain():
                log("  基础实例也无法启动，本次深度验证全部记为失败")
                return {n: (None, 99.0) for n in names}
            return {n: self.curl_check(n, url, timeout) for n in names}

        log(f"  并发验证实例就绪：{len(ports)} 个独立端口（{min(ports.values())}-{max(ports.values())}）")

        results = {}

        def one(n):
            return n, self._curl_via(f"http://127.0.0.1:{ports[n]}", url, timeout)

        with ThreadPoolExecutor(max_workers=max(1, min(workers, len(names)))) as ex:
            for f in as_completed([ex.submit(one, n) for n in names]):
                n, (code, sec) = f.result()
                results[n] = (code, sec)
        return results

    def _stop(self):
        if self.proc:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=5)
            except Exception:
                self.proc.kill()
            self.proc = None


# ---------------- 历史 ----------------
def read_history(days=None, include_samples=False, samples_only=False):
    """读历史记录。

    samples_only=True  只读 samples-*.jsonl（死节点判定用）
    include_samples=True  读 proxy-* + samples-*
    默认               只读 proxy-*
    """
    rows = []
    if not os.path.isdir(HISTORY_DIR):
        return rows
    cutoff = None
    if days:
        cutoff = datetime.datetime.now() - datetime.timedelta(days=days)
    if samples_only:
        prefixes = ("samples-",)
    elif include_samples:
        prefixes = ("proxy-", "samples-")
    else:
        prefixes = ("proxy-",)
    for fn in sorted(os.listdir(HISTORY_DIR)):
        if not fn.endswith(".jsonl") or not fn.startswith(prefixes):
            continue
        with codecs.open(os.path.join(HISTORY_DIR, fn), "r", "utf-8") as f:
            for line in f:
                try:
                    r = json.loads(line)
                except Exception:
                    continue
                if cutoff:
                    try:
                        ts = datetime.datetime.fromisoformat(r["ts"])
                        if ts < cutoff:
                            continue
                    except Exception:
                        pass
                rows.append(r)
    return rows


def source_health():
    """源健康度：统计每个订阅源的历史成功率，给 --apply 的降权做参考。"""
    stat = defaultdict(lambda: [0, 0])
    rows = read_history(30)
    for r in rows:
        p = r.get("proxy") or {}
        src = p.get("_source", "")
        if not src:
            continue
        stat[src][0] += 1
        if r.get("ok"):
            stat[src][1] += 1
    return {s: {"seen": v[0], "ok": v[1],
                "rate": round(v[1] / v[0], 2) if v[0] else 0}
            for s, v in stat.items()}


def report_sources(health):
    if not health:
        return
    log("源健康度（近 30 天）：")
    for s, h in sorted(health.items(), key=lambda x: -x[1]["rate"]):
        log(f"  {s[-42:]:44} {h['ok']:3}/{h['seen']:<3} {h['rate']*100:5.0f}%")


def history_good(days=7, min_seen=2, top=40):
    """从历史里挑成功率高的节点（含完整定义），用于 --inherit。"""
    rows = read_history(days)
    stat = defaultdict(lambda: {"seen": 0, "ok": 0, "proxy": None, "last": ""})
    for r in rows:
        n = r.get("name")
        if not n:
            continue
        s = stat[n]
        s["seen"] += 1
        if r.get("ok"):
            s["ok"] += 1
        if r.get("proxy"):
            s["proxy"] = r["proxy"]
        s["last"] = max(s["last"], r.get("ts", ""))
    good = [(n, s) for n, s in stat.items()
            if s["seen"] >= min_seen and s["proxy"] and s["ok"] / s["seen"] >= 0.5]
    good.sort(key=lambda x: (-x[1]["ok"] / x[1]["seen"], -x[1]["seen"]))
    return [s["proxy"] for _, s in good[:top]], len(stat)


# ---------------- 四层存储 ----------------
def save_snapshot(proxies, group, source_stats=None):
    """A 层：全量快照。每次抓取的所有节点都落盘，不只测过的。
    按天一个 JSONL，一行 = 当时完整的节点列表。"""
    os.makedirs(HISTORY_DIR, exist_ok=True)
    ts = datetime.datetime.now().isoformat(timespec="seconds")
    path = os.path.join(HISTORY_DIR, f"snapshot-{datetime.datetime.now():%Y%m%d}.jsonl")
    rec = {
        "ts": ts, "group": group, "count": len(proxies),
        "source_stats": source_stats or {},
        "nodes": [clean_proxy(p) | {"_source": p.get("_source", ""),
                                     "_group": p.get("_group", "")}
                  for p in proxies],
    }
    with codecs.open(path, "a", "utf-8") as f:
        f.write(json.dumps(rec, ensure_ascii=False) + "\n")
    return path


def save_samples(delays, rows, group, all_names=None, min_pass_rate=0.10,
                 id_map=None):
    """B 层：多次采样。每个节点的每次延迟/HTTP 耗时都单独成行。

    传 all_names 时，延迟测试**没有响应**的节点也写一条 ok=False 记录，
    这样死节点清理才有失败数据可依据。

    P0-2 保护：如果本轮延迟通过率低于 min_pass_rate（默认 10%），
    说明是本地网络整体故障而非节点真的死了，此时**不写**无响应失败记录，
    否则一次断网就会把整池节点记成失败，下一轮 cron 就批量清掉了。

    P0-3：id_map 是 {name: _id}，写进每条记录的 "id" 字段，
    让历史按稳定身份关联，而不是靠可能变化的名字。
    """
    os.makedirs(HISTORY_DIR, exist_ok=True)
    ts = datetime.datetime.now().isoformat(timespec="seconds")
    path = os.path.join(HISTORY_DIR, f"samples-{datetime.datetime.now():%Y%m}.jsonl")
    by_name = {r["name"]: r for r in rows}
    recorded = set()
    id_map = id_map or {}

    def _id(n):
        return id_map.get(n) or ""

    total = len(all_names or []) or len(delays)
    rate = (len(delays) / total) if total else 1.0
    write_absent = bool(all_names) and rate >= min_pass_rate
    if all_names and not write_absent:
        log(f"  延迟通过率仅 {rate*100:.1f}%（<{min_pass_rate*100:.0f}%），"
            f"疑似本地网络故障，跳过记录无响应节点")

    with codecs.open(path, "a", "utf-8") as f:
        for name, ms in delays.items():
            r = by_name.get(name, {})
            f.write(json.dumps({
                "ts": ts, "group": group, "name": name, "id": _id(name),
                "delay_ms": ms,
                "http_sec": r.get("http_sec") if r.get("ok") else None,
                "ok": bool(r.get("ok")) if r else None,
                "score": r.get("score"),
            }, ensure_ascii=False) + "\n")
            recorded.add(name)
        if write_absent:
            for name in all_names:
                if name in recorded:
                    continue
                f.write(json.dumps({
                    "ts": ts, "group": group, "name": name, "id": _id(name),
                    "delay_ms": None, "http_sec": None, "ok": False, "score": 0.0,
                }, ensure_ascii=False) + "\n")
    return path


def build_daily_aggregate():
    """C 层：按天聚合表。每天每节点：出现次数 / 成功率 / 平均分 / 平均延迟。

    P0-4：只读 samples-*.jsonl，与死节点判定口径一致。
    之前同时合并 proxy-*，深验过的节点每轮被算两次（seen 翻倍、成功率失真）。
    """
    if not os.path.isdir(HISTORY_DIR):
        return None
    daily = defaultdict(lambda: {"seen": 0, "ok": 0, "score": [], "delay": [],
                                 "first": "", "last": ""})
    for f in os.listdir(HISTORY_DIR):
        if not f.startswith("samples-") or not f.endswith(".jsonl"):
            continue
        with codecs.open(os.path.join(HISTORY_DIR, f), "r", "utf-8") as fh:
            for line in fh:
                try:
                    r = json.loads(line)
                except Exception:
                    continue
                day = r.get("ts", "")[:10]
                if not day:
                    continue
                d = daily[(day, r.get("name", "?"))]
                d["seen"] += 1
                if r.get("ok"):
                    d["ok"] += 1
                if r.get("score") is not None:
                    d["score"].append(float(r["score"]))
                if r.get("delay_ms") is not None:
                    d["delay"].append(float(r["delay_ms"]))
                d["first"] = min(d["first"] or r["ts"], r["ts"])
                d["last"] = max(d["last"], r["ts"])

    path = os.path.join(HISTORY_DIR, "latest_daily.csv")
    with open(path, "w", encoding="utf-8-sig", newline="") as f:
        w = csv.writer(f)
        w.writerow(["日期", "节点", "采样次数", "成功次数", "成功率%", "平均分", "平均延迟ms", "首次", "末次"])
        for (day, name), d in sorted(daily.items(), key=lambda x: (x[0][0], -x[1]["seen"])):
            avg_s = round(sum(d["score"]) / len(d["score"]), 1) if d["score"] else ""
            avg_d = round(sum(d["delay"]) / len(d["delay"])) if d["delay"] else ""
            w.writerow([day, name, d["seen"], d["ok"],
                        round(d["ok"] / d["seen"] * 100) if d["seen"] else 0,
                        avg_s, avg_d, d["first"], d["last"]])
    return path


def export_group_configs(passed, by_name, rules, out_dir=None):
    """D 层：分组订阅输出。每个协议组单独写一份 Clash 配置，
    方便客户端直接切换 SS 组 / Trojan 组。

    P1-3：订阅文件里 **secret 留空**，这些文件常被分享出去，
    不能带生产 API 凭据。
    """
    out_dir = out_dir or os.path.join(HISTORY_DIR, "subscriptions")
    os.makedirs(out_dir, exist_ok=True)
    grouped = defaultdict(list)
    for n in passed:
        p = by_name.get(n)
        if not p:
            continue
        g = p.get("_group") or proto_group(p["type"])
        grouped[g].append(p)

    written = []
    for g, ps in grouped.items():
        if not ps:
            continue
        path = os.path.join(out_dir, f"{g}.yaml")
        write_yaml(path, make_config(ps, 2081, 9091, rules, secret=""))
        written.append((g, path, len(ps)))

    # 一份全量
    if passed:
        allp = [by_name[n] for n in passed if n in by_name]
        path = os.path.join(out_dir, "all.yaml")
        write_yaml(path, make_config(allp, 2081, 9091, rules, secret=""))
        written.append(("all", path, len(allp)))
    return written


def node_longevity(days=30, top=30):
    """节点寿命分析：从全量快照统计每个节点出现了几天、连续存活情况。"""
    stat = defaultdict(lambda: {"days": set(), "first": "", "last": "", "proxy": None})
    if not os.path.isdir(HISTORY_DIR):
        log("历史为空")
        return
    cutoff = (datetime.datetime.now() - datetime.timedelta(days=days)).date().isoformat()
    for f in os.listdir(HISTORY_DIR):
        if not f.startswith("snapshot-") or not f.endswith(".jsonl"):
            continue
        with codecs.open(os.path.join(HISTORY_DIR, f), "r", "utf-8") as fh:
            for line in fh:
                try:
                    r = json.loads(line)
                except Exception:
                    continue
                day = r.get("ts", "")[:10]
                if day < cutoff:
                    continue
                for p in r.get("nodes", []):
                    key = (p.get("server"), p.get("port"))
                    if not all(key):
                        continue
                    n = p.get("name", f"{key[0]}:{key[1]}")
                    s = stat[n]
                    s["days"].add(day)
                    s["first"] = min(s["first"] or r["ts"], r["ts"])
                    s["last"] = max(s["last"], r["ts"])
                    s["proxy"] = p
    if not stat:
        log("没有全量快照数据（跑过几次完整抓取后才有）")
        return
    ranked = sorted(stat.items(), key=lambda x: (-len(x[1]["days"]), x[0]))
    log(f"节点寿命统计（近 {days} 天，来自全量快照）：")
    print(f"{'节点':38} {'出现天数':>6}  首次 / 末次")
    for n, s in ranked[:top]:
        print(f"{n:38} {len(s['days']):6}  {s['first'][:10]} / {s['last'][:10]}")


def dead_node_names(window=7, min_fail=2, only_recent=True, protect=None):
    """找出"最近 N 次测试全部失败"的节点。

    P0-1 修正：**只读 samples-*.jsonl**。
    之前同时读 proxy- 和 samples-，同一轮深验失败会在两边各留一条 ok=False，
    一次运行就凑够 min_fail=2 判死。samples 每轮必写（未深验记 ok=None 被跳过），
    所以只读 samples 就能拿到真实的多轮序列。

    window: 看最近几天
    min_fail: 最近几次全部失败才算死
    protect: 本次通过的节点，排除
    """
    protect = protect or set()
    cutoff = (datetime.datetime.now() - datetime.timedelta(days=window)).date().isoformat()
    # P0-3：优先按稳定 _id 归并；旧记录没有 id 时回落到名字
    hist = defaultdict(list)
    names_by_key = {}
    for r in read_history(window, include_samples=True, samples_only=True):
        name = r.get("name")
        if not name:
            continue
        ok = r.get("ok")
        if ok is None:          # 未深验的采样，无判定信息
            continue
        ts = r.get("ts", "")
        if only_recent and ts[:10] < cutoff:
            continue
        key = r.get("id") or name
        hist[key].append((ts, bool(ok)))
        names_by_key[key] = name

    dead = {}
    need = max(1, int(min_fail))
    for key, recs in hist.items():
        if key in protect or names_by_key.get(key) in protect:
            continue
        recs.sort(key=lambda x: x[0])
        recent = recs[-need:] if len(recs) >= need else recs
        if len(recent) < need:
            continue
        fails = sum(1 for _, ok in recent if not ok)
        if fails == need:
            dead[names_by_key.get(key, key)] = {
                "fail": fails, "ok": 0, "last": recent[-1][0], "checked": len(recent),
                "id": key,
            }
    return dead


def clean_dead_nodes(window=7, min_fail=2, apply=False, target="both", protect=None, backup=True):
    """自动清理不可用节点。
    target: prod=只清理生产配置 / subs=只清理分组订阅 / both=都清
    apply=False 时只报告不动手（默认只读）。
    protect: 本次通过的节点，排除（cron 落地后不误删）。"""
    dead = dead_node_names(window, min_fail, protect=protect)
    if not dead:
        log(f"近 {window} 天没有连续失败 ≥{min_fail} 次的节点")
        return 0

    log(f"近 {window} 天连续失败 ≥{min_fail} 次的节点：{len(dead)} 个")
    for n, s in sorted(dead.items(), key=lambda x: -x[1]["fail"])[:15]:
        log(f"  {n:38} 失败 {s['fail']} / 成功 {s['ok']}  末次 {s['last'][:16]}")

    if not apply:
        log("只报告模式（加 --apply-clean 才真正移除）")
        return len(dead)

    # P0-2 保护：单次最多移除配置中 30% 的节点。
    # 超过就说明更可能是本地网络/上游整体故障，而不是这么多节点同时死掉。
    max_ratio = 0.30
    if target in ("prod", "both") and os.path.isfile(PROD_CONFIG):
        with open(PROD_CONFIG, "r", encoding="utf-8") as f:
            cur = yaml.safe_load(f) or {}
        cur_names = {p.get("name") for p in cur.get("proxies", [])}
        hit = len([n for n in dead if n in cur_names])
        total = len(cur_names) or 1
        if hit / total > max_ratio:
            log(f"  ⚠ 待清理 {hit}/{total} 个节点（{hit/total*100:.0f}%）"
                f"超过 {max_ratio*100:.0f}% 上限，疑似整体故障，**跳过清理**")
            log("    确认无误可调小 --dead-window/--dead-fails 后重试")
            return 0

    removed_total = 0

    def strip_cfg(path):
        nonlocal removed_total
        if not os.path.isfile(path):
            return
        with open(path, "r", encoding="utf-8") as f:
            cfg = yaml.safe_load(f)
        # P0-3：既按名字匹配，也按稳定 node_id 匹配（名字可能每轮不同）
        dead_names = set(dead)
        dead_ids = {info.get("id") for info in dead.values() if info.get("id")}

        def is_dead(p):
            return p.get("name") in dead_names or node_id(p) in dead_ids

        before = len(cfg.get("proxies", []))
        cfg["proxies"] = [p for p in cfg.get("proxies", []) if not is_dead(p)]
        after = len(cfg["proxies"])
        if before == after:
            return
        # 同步各组 proxies 列表
        good = {p["name"] for p in cfg["proxies"]}
        for g in cfg.get("proxy-groups", []):
            g["proxies"] = [n for n in g.get("proxies", [])
                            if n == "AUTO" or n in good or n.startswith("G_")]
        with open(path, "w", encoding="utf-8") as f:
            yaml.safe_dump(cfg, f, allow_unicode=True, sort_keys=False)
        log(f"  {os.path.basename(path)}: {before} → {after}（移除 {before-after}）")
        removed_total += before - after

    if target in ("prod", "both"):
        if backup:
            backup_prod()
        else:
            log("  跳过备份（本轮 apply 已备份过）")
        strip_cfg(PROD_CONFIG)

    if target in ("subs", "both"):
        sd = os.path.join(HISTORY_DIR, "subscriptions")
        if os.path.isdir(sd):
            for fn in os.listdir(sd):
                if fn.endswith(".yaml"):
                    strip_cfg(os.path.join(sd, fn))

    log(f"共移除 {removed_total} 个死节点")
    if removed_total and port_up(PROD_PORT):
        log("  生产 mihomo 正在运行，需重启才生效")
    return removed_total


def _month_last_day(yyyymm):
    """'202611' -> '2026-11-30'（该月最后一天）。"""
    y, mo = int(yyyymm[:4]), int(yyyymm[4:6])
    if mo == 12:
        nxt = datetime.date(y + 1, 1, 1)
    else:
        nxt = datetime.date(y, mo + 1, 1)
    return (nxt - datetime.timedelta(days=1)).isoformat()


def prune_history(days=90, archive=True, apply=False):
    """清理过期历史数据。默认只报告；apply=True 才执行。

    文件级 vs 行级的判定（P0-4 修正）：
      - snapshot-YYYYMMDD.jsonl：该日 < 截止日 → 整文件归档
      - 按月命名的 proxy-YYYYMM.jsonl 等：**只有该月最后一天 < 截止日**
        才整文件归档；否则走行级清理，避免把当月还没过期的数据整份删掉。
      - 其它 jsonl：一律行级清理
    """
    cutoff = (datetime.datetime.now() - datetime.timedelta(days=days)).date().isoformat()
    if not os.path.isdir(HISTORY_DIR):
        return
    old_files, old_lines = [], defaultdict(list)
    for fn in os.listdir(HISTORY_DIR):
        path = os.path.join(HISTORY_DIR, fn)
        if not os.path.isfile(path) or not fn.endswith(".jsonl"):
            continue
        # 日粒度文件名：snapshot-YYYYMMDD.jsonl
        m = re.search(r"(\d{8})\.jsonl$", fn)
        if m:
            d = f"{m.group(1)[:4]}-{m.group(1)[4:6]}-{m.group(1)[6:]}"
            if d < cutoff:
                old_files.append(fn)
            # 该日未过期：整文件都是有效期内数据，无需行级清理
            continue
        # 月粒度文件名：proxy-YYYYMM.jsonl / samples-YYYYMM.jsonl
        m = re.search(r"(\d{6})\.jsonl$", fn)
        if m:
            if _month_last_day(m.group(1)) < cutoff:
                old_files.append(fn)
                continue
            # 月份跨越截止日 → 走行级清理（下面统一处理）
        # 行级清理
        with codecs.open(path, "r", "utf-8") as f:
            for line in f:
                try:
                    ts = json.loads(line).get("ts", "")[:10]
                except Exception:
                    continue
                if ts and ts < cutoff:
                    old_lines[fn].append(line)

    log(f"历史清理（>{days} 天）：整文件 {len(old_files)} 个，行级 {sum(len(v) for v in old_lines.values())} 条")
    if not apply:
        log("只报告模式（加 --apply-prune 才真正清理）")
        return
    import gzip
    for fn in old_files:
        path = os.path.join(HISTORY_DIR, fn)
        if archive:
            with open(path, "rb") as src, gzip.open(path + ".gz", "wb") as dst:
                shutil.copyfileobj(src, dst)
        os.remove(path)
        log(f"  归档并删除 {fn}")
    for fn, lines in old_lines.items():
        path = os.path.join(HISTORY_DIR, fn)
        with codecs.open(path, "r", "utf-8") as f:
            kept = [l for l in f if l not in lines]
        if archive and lines:
            with gzip.open(path + ".old.gz", "wt", encoding="utf-8") as g:
                g.writelines(lines)
        with codecs.open(path, "w", "utf-8") as f:
            f.writelines(kept)
        log(f"  {fn}: 移除 {len(lines)} 条旧记录")


def save_history(rows, by_name):
    os.makedirs(HISTORY_DIR, exist_ok=True)
    ts = datetime.datetime.now().isoformat(timespec="seconds")
    jsonl = os.path.join(HISTORY_DIR, f"proxy-{datetime.datetime.now():%Y%m}.jsonl")
    with codecs.open(jsonl, "a", "utf-8") as f:
        for r in rows:
            rec = dict(r, ts=ts)
            p = by_name.get(r["name"])
            if p:
                rec["proxy"] = p       # 存完整定义，供 --inherit 复活
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
    csvp = os.path.join(HISTORY_DIR, "latest.csv")
    with open(csvp, "w", encoding="utf-8-sig", newline="") as f:
        w = csv.writer(f)
        w.writerow(["时间", "节点", "国家", "类型", "服务器", "端口", "延迟ms",
                    "HTTP", "耗时s", "评分", "等级", "可用"])
        for r in rows:
            w.writerow([ts, r["name"], country_of(r["name"]), r["type"], r["server"],
                        r["port"], r.get("delay_ms", ""), r.get("http_code", ""),
                        r.get("http_sec", ""), r.get("score", ""), r.get("grade", ""),
                        "是" if r.get("ok") else "否"])
    return jsonl, csvp


def country_of(name):
    m = re.match(r"\s*([^\s\w])", name or "")
    if m and ord(m.group(1)) > 0x1F000:  # emoji 国旗区
        return m.group(1)
    m = re.search(r"\b(JP|US|IT|HK|KR|SG|GB|DE|FR|NL|RU|CA|AU|TW)\b", name or "", re.I)
    return m.group(1).upper() if m else ""


def quality_score(delay_ms, http_sec):
    """0-100 综合评分，纯两维度：

      延迟 60%（<300ms 满分，>3000ms 归零）
      实速 40%（<2s 满分，>12s 归零；未深验时给中性分）

    早期版本还有个"抖动 10%"的分支，但调用处从未传入多次采样，
    那段是死代码，已在 P2-7 移除。需要稳定性请用 samples-*.jsonl 单独分析。
    """
    def band(v, full, zero):
        if v is None:
            return 0.6
        return max(0.0, min(1.0, (zero - v) / (zero - full)))

    delay_s = band(delay_ms, 300, 3000)
    speed_s = band(http_sec, 2.0, 12.0)
    score = 100 * (0.60 * delay_s + 0.40 * speed_s)
    return round(score, 1)


def grade(score):
    if score >= 80:
        return "优质"
    if score >= 60:
        return "可用"
    if score >= 40:
        return "一般"
    return "较差"


def history_stats():
    rows = read_history()
    if not rows:
        log("历史为空")
        return
    stat = defaultdict(lambda: [0, 0, "", ""])
    for r in rows:
        n = r.get("name", "?")
        stat[n][0] += 1
        if r.get("ok"):
            stat[n][1] += 1
        t = r.get("ts", "")
        stat[n][2] = min(stat[n][2] or t, t)
        stat[n][3] = max(stat[n][3], t)
    log(f"历史共 {len(rows)} 条记录，{len(stat)} 个节点")
    print(f"{'节点':38} {'出现':>4} {'成功':>4} {'成功率':>7}  首次 / 末次")
    for n, (seen, ok, first, last) in sorted(stat.items(), key=lambda x: -x[1][0])[:30]:
        print(f"{n:38} {seen:4} {ok:4} {ok/seen*100:6.0f}%  {first[:10]} / {last[:10]}")


# ---------------- 生产配置管理 ----------------
def read_prod():
    if not os.path.isfile(PROD_CONFIG):
        return None
    with open(PROD_CONFIG, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def backup_prod():
    cfg = read_prod()
    if cfg is None:
        return None
    os.makedirs(BACKUP_DIR, exist_ok=True)
    ts = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    dst = os.path.join(BACKUP_DIR, f"config-{ts}.yaml")
    shutil.copy2(PROD_CONFIG, dst)
    # 只保留最近 10 份
    bks = sorted(f for f in os.listdir(BACKUP_DIR) if f.endswith(".yaml"))
    for old in bks[:-10]:
        try:
            os.remove(os.path.join(BACKUP_DIR, old))
        except Exception:
            pass
    log(f"  生产配置已备份：{dst}")
    return dst


def rollback():
    if not os.path.isdir(BACKUP_DIR):
        fail("没有备份目录")
    bks = sorted(f for f in os.listdir(BACKUP_DIR) if f.endswith(".yaml"))
    if not bks:
        fail("没有可回滚的备份")
    src = os.path.join(BACKUP_DIR, bks[-1])
    shutil.copy2(src, PROD_CONFIG)
    log(f"已从 {src} 还原生产配置")
    log("  如生产 mihomo 正在运行，需重启它才生效")


def validate_config_file(cfg, conf_dir):
    """P1-7：用 `mihomo -t` 校验配置能否加载。

    写临时文件 → 校验 → 通过才返回 True。
    避免一个坏节点让生产 mihomo 重启后直接起不来。
    """
    os.makedirs(conf_dir, exist_ok=True)
    tmp = os.path.join(conf_dir, f".validate-{os.getpid()}.yaml")
    try:
        with open(tmp, "w", encoding="utf-8", newline="\n") as f:
            yaml.safe_dump(cfg, f, allow_unicode=True, sort_keys=False)
        r = subprocess.run(
            [MIHOMO_EXE, "-t", "-f", tmp, "-d", conf_dir],
            capture_output=True, text=True, timeout=60)
        ok = r.returncode == 0
        if not ok:
            msg = (r.stdout or "") + (r.stderr or "")
            for line in msg.splitlines():
                if "error" in line.lower() or "failed" in line.lower():
                    log(f"  配置校验失败：{line.strip()[:160]}")
                    break
            else:
                log("  配置校验失败（无详细错误输出）")
        return ok
    except Exception as e:
        log(f"  配置校验异常：{type(e).__name__}: {e}")
        return False
    finally:
        if os.path.exists(tmp):
            try:
                os.remove(tmp)
            except OSError:
                pass


def apply_prod(proxies, rules, insecure=False, secret=None):
    if system_proxy_on():
        log("  ⚠ 系统代理当前为开启状态；重启生产 mihomo 会造成短暂断网")
    sec, origin, generated = resolve_prod_secret(secret)
    cfg = make_config(proxies, PROD_PORT, PROD_API, rules, secret=sec, insecure=insecure)

    # P1-7：先校验再落地，坏节点不该把生产配置写成起不来的样子
    log("  校验生产配置…")
    if not validate_config_file(cfg, PROD_CONF_DIR):
        if len(proxies) > 1:
            log("  整体校验失败，逐个剔除后重试")
            good = []
            for p in proxies:
                trial = good + [p]
                if validate_config_file(
                        make_config(trial, PROD_PORT, PROD_API, rules,
                                    secret=sec, insecure=insecure), PROD_CONF_DIR):
                    good.append(p)
                else:
                    log(f"    剔除无效节点：{p.get('name')}")
            if not good:
                fail("所有节点都无法通过配置校验，未写入生产配置")
            proxies = good
            cfg = make_config(proxies, PROD_PORT, PROD_API, rules,
                              secret=sec, insecure=insecure)
            log(f"  剔除后保留 {len(proxies)} 个节点")
        else:
            fail("配置校验失败，未写入生产配置")

    backup_prod()
    write_yaml(PROD_CONFIG, cfg)
    log(f"  生产配置已写入（{len(proxies)} 节点，规则 {rules}）")
    log(f"  API secret 来源：{origin}")
    if generated:
        # 只在终端显示，不写进 harvest.log —— 日志常被贴出来排错
        log(f"  ★ 新 secret（请立即保存，面板/客户端需要它）：{sec}", also_file=False)
    if not insecure:
        log("  已剥离 skip-cert-verify（需要时加 --insecure）")
    if port_up(PROD_PORT):
        log("  生产 mihomo 正在运行；请自行重启它使新配置生效")
        log(f"    结束进程 mihomo.exe 后执行：\"{MIHOMO_EXE}\" -d \"{PROD_CONF_DIR}\"")


def show_status():
    cfg = read_prod()
    if cfg is None:
        log("生产配置不存在")
        return
    log(f"生产配置：{PROD_CONFIG}")
    log(f"  节点数    {len(cfg.get('proxies', []))}")
    log(f"  端口      {cfg.get('mixed-port')} / API {cfg.get('external-controller')}")
    log(f"  规则      {cfg.get('rules')}")
    log(f"  生产 mihomo {'运行中' if port_up(PROD_PORT) else '未运行'}")
    log(f"  系统代理  {'开启' if system_proxy_on() else '关闭'}")
    bks = os.listdir(BACKUP_DIR) if os.path.isdir(BACKUP_DIR) else []
    log(f"  备份数    {len(bks)}")


# ---------------- 主流程 ----------------
def main():
    ap = argparse.ArgumentParser(description="免费代理一键抓取/测速/筛选/记录/落地（完善版）")
    ap.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    ap.add_argument("--limit", type=int, default=200, help="最多抓取节点数（意大利段靠后，建议 ≥180）")
    ap.add_argument("--max-nodes", type=int, default=30,
                    help="落地到生产配置的节点数上限（默认 30；0=不限）")
    ap.add_argument("--group", default="all",
                    choices=list(PROTO_GROUPS.keys()),
                    help="只测某个协议组；all=全测（默认）。组：" + ", ".join(PROTO_GROUPS.keys()))
    ap.add_argument("--list-groups", action="store_true", help="列出协议分组后退出")
    ap.add_argument("--per-group", type=int, default=0,
                    help=">0 时每个组各自挑前 N 个深验并独立排名")
    ap.add_argument("--keep", type=int, default=0, help="深度验证的节点数；0=不深验（默认）")
    ap.add_argument("--timeout", type=int, default=10, help="深度验证单次超时秒数")
    ap.add_argument("--delay-timeout", type=int, default=5000, help="延迟测试超时毫秒")
    ap.add_argument("--test-url", default=DEFAULT_TEST_URL, help="深度验证网址")
    ap.add_argument("--delay-url", default=DEFAULT_DELAY_URL, help="延迟测试网址（能返回延迟即连通）")
    ap.add_argument("--min-pass", type=int, default=1, help="至少要通过几个才算成功")
    ap.add_argument("--good-enough", type=int, default=0, help="深验够了几个就提前停；0=全测")
    ap.add_argument("--serial-verify", action="store_true",
                    help="深度验证用串行模式（默认并发，每节点独立端口）")
    ap.add_argument("--insecure", action="store_true",
                    help="保留 skip-cert-verify（默认剥离，更安全）")
    ap.add_argument("--secret", default=None,
                    help="生产 API secret；不传则读 config.json，再没有就随机生成")
    ap.add_argument("--rules", default=None, choices=["match", "split"],
                    help="落地规则；默认 match，cron 模式默认 split（国内直连）")
    ap.add_argument("--apply", action="store_true", help="把通过的节点写回生产配置（自动备份）")
    ap.add_argument("--sources-only", action="store_true", help="只抓取，不测速")
    ap.add_argument("--inherit", action="store_true", help="把历史常青节点拉回候选池")
    ap.add_argument("--inherit-days", type=int, default=7, help="继承历史的时间窗口（天）")
    ap.add_argument("--json", dest="json_out", help="把结果写成 JSON 文件（机器可读）")
    ap.add_argument("--status", action="store_true", help="只显示当前生产配置状态")
    ap.add_argument("--history-stats", action="store_true", help="只统计历史节点寿命（测试记录）")
    ap.add_argument("--longevity", action="store_true", help="节点寿命统计（来自全量快照，看连续存活天数）")
    ap.add_argument("--no-snapshot", action="store_true", help="不落全量快照层")
    ap.add_argument("--no-subscriptions", action="store_true", help="不导出分组订阅配置")
    ap.add_argument("--cron", action="store_true",
                    help="一键全流程：抓取→测速→落地→清死节点→归档历史（等价于 --apply + 自动清理；"
                         "仍可用 --dry-run 阻止落地）")
    ap.add_argument("--dry-run", action="store_true",
                    help="配合 --cron：跑全流程但不落地不清理，只生成报告")
    ap.add_argument("--clean-dead", action="store_true", help="检查并清理连续失败的节点（默认只报告）")
    ap.add_argument("--apply-clean", action="store_true", help="配合 --clean-dead：真正移除死节点")
    ap.add_argument("--dead-window", type=int, default=7, help="死节点判定的时间窗口（天）")
    ap.add_argument("--dead-fails", type=int, default=2, help="连续失败几次算死")
    ap.add_argument("--clean-target", default="both", choices=["prod", "subs", "both"],
                    help="清理目标：生产配置/分组订阅/两者")
    ap.add_argument("--prune", action="store_true", help="检查过期历史记录（默认只报告）")
    ap.add_argument("--apply-prune", action="store_true", help="配合 --prune：真正清理并归档")
    ap.add_argument("--prune-days", type=int, default=90, help="历史保留天数")
    ap.add_argument("--no-archive", action="store_true", help="清理历史时不归档，直接删除")
    ap.add_argument("--rollback", action="store_true", help="从最近备份还原生产配置")
    args = ap.parse_args()

    # P0-3：cron 默认带深度验证，否则"延迟无响应"的节点从未留下失败记录，
    # 死节点清理就永远无事可做。显式传 --keep 时尊重用户值。
    if args.cron and args.keep == 0 and not args.dry_run:
        args.keep = 15
        log("cron 模式：深度验证默认 15 个（可用 --keep 覆盖）")

    if args.list_groups:
        log("协议分组：")
        for g, types in PROTO_GROUPS.items():
            log(f"  {g:10} → {', '.join(sorted(types))}")
        return
    if args.status:
        show_status()
        return
    if args.history_stats:
        history_stats()
        return
    if args.longevity:
        node_longevity()
        return
    if args.clean_dead:
        clean_dead_nodes(window=args.dead_window, min_fail=args.dead_fails,
                         apply=args.apply_clean, target=args.clean_target)
        return
    if args.prune:
        prune_history(days=args.prune_days, archive=not args.no_archive,
                      apply=args.apply_prune)
        return
    if args.rollback:
        rollback()
        return
    if not args.sources_only and not os.path.isfile(MIHOMO_EXE):
        fail(f"找不到 mihomo：{MIHOMO_EXE}", 2)
    if args.limit < 1:
        fail("--limit 必须 ≥1", 2)

    # P2-14：只读命令不加锁；会抓取/落地的才加
    _lock = None
    if not args.sources_only:
        _lock = acquire_lock()
        if _lock is None:
            fail("已有另一个实例在运行", 3)

    try:
        _run_main(args)
    finally:
        release_lock(_lock)


def _run_main(args):
    result = {"ts": datetime.datetime.now().isoformat(timespec="seconds"),
              "args": {k: v for k, v in vars(args).items() if k != "json_out"}}

    log(f"开始抓取（上限 {args.limit}）")
    proxies = harvest(args.limit)
    if not proxies:
        fail("一个节点都没抓到")
    log(f"抓取完成：{len(proxies)} 个节点")

    if args.inherit:
        old, total = history_good(days=args.inherit_days)
        have = {(p["server"], p["port"]) for p in proxies}
        added = [p for p in old if (p.get("server"), p.get("port")) not in have]
        proxies += added
        log(f"历史继承：从 {total} 个历史节点中拉回 {len(added)} 个常青节点")

    # 校验：返回 (good, bad)，直接用 good（P0-1 修正）
    proxies, bad = validate_proxies(proxies)
    if bad:
        log(f"  跳过 {len(bad)} 个无效节点：" + ", ".join(f"{n}({','.join(f)})" for n, f in bad[:5]))

    # 统一重名处理：在 inherit 合并 + 校验之后执行一次（P0-2 修正）
    dedupe_names(proxies)

    # 按协议组过滤
    if args.group != "all":
        types = PROTO_GROUPS[args.group]
        before = len(proxies)
        proxies = [p for p in proxies if p["type"] in types]
        log(f"协议组过滤 [{args.group}]：{before} → {len(proxies)} 个节点")
        if not proxies:
            fail(f"协议组 {args.group} 没有节点（支持：{', '.join(types)}）")
    result["total"] = len(proxies)
    result["group"] = args.group

    # A 层：全量快照（抓到就落盘，不依赖测速是否成功）
    # sources-only 模式不落：那种模式只抓几个节点做调试，会污染全量快照
    if not args.no_snapshot and not args.sources_only:
        src_stat = defaultdict(lambda: [0, 0])
        for p in proxies:
            s = p.get("_source", "")
            if s:
                src_stat[s][0] += 1
        snapshot_path = save_snapshot(
            proxies, args.group,
            {s: {"count": v[0]} for s, v in src_stat.items()})
        log(f"A层 全量快照：{snapshot_path}（{len(proxies)} 节点）")
        result["snapshot"] = snapshot_path

    if args.sources_only:
        write_yaml(os.path.join(TMP_DIR, "config.yaml"),
                   make_config(proxies, 2180, 9180, split_rules() if args.rules == "split" else None))
        log(f"只抓取模式：全量配置已写 {os.path.join(TMP_DIR, 'config.yaml')}（{len(proxies)} 节点）")
        return

    mix_port = free_port(2180)
    api_port = free_port(9180)
    if not mix_port or not api_port:
        fail("找不到空闲的临时端口", 2)

    # 落地规则：cron **强制** split（国内直连），其它模式默认 match。
    # P1-6：不再让 cron 有机会把整机流量塞进代理。
    if args.cron:
        prod_rules = split_rules()
    else:
        prod_rules = split_rules() if args.rules == "split" else ["MATCH,PROXY"]
    # 测速临时实例永远用 MATCH,PROXY —— 临时目录没有 GeoSite.dat，
    # 用 GEOSITE 规则会触发 mihomo 联网下载 geo 库，国内直连 GitHub 会超时。
    test_rules = ["MATCH,PROXY"]
    by_name = {p["name"]: p for p in proxies}
    passed, rows = [], []

    try:
        with TempMihomo(TMP_DIR, mix_port, api_port, proxies, test_rules,
                        insecure=args.insecure) as t:
            log(f"开始并发延迟测速（{len(proxies)} 节点 ← {args.delay_url}）")
            t0 = time.time()
            delays = t.delay_all(args.delay_url, args.delay_timeout)
            log(f"  测速完成：{len(delays)} 个有响应，耗时 {time.time()-t0:.1f}s")
            if not delays:
                fail("没有任何节点通过延迟测试")
            result["delay_passed"] = len(delays)

            ranked = sorted(delays.items(), key=lambda x: x[1])
            log(f"  最快：{ranked[0][0]} = {ranked[0][1]}ms")

            # 深度验证（可选）+ 质量评分
            score_of = {}

            # 决定深验候选：--per-group 时每组各挑前 N 个；否则全局前 N 个
            if args.per_group > 0:
                cand = []
                for g in PROTO_GROUPS:
                    if g == "all":
                        continue
                    gnames = [n for n, _ in ranked
                              if (by_name.get(n, {}).get("_group") or proto_group(by_name.get(n, {}).get("type", ""))) == g]
                    if gnames:
                        cand += gnames[:args.per_group]
                        log(f"  组 {g:10} 贡献 {len(gnames[:args.per_group])} 个候选（该组有响应 {len(gnames)}）")
                log(f"分组深验：共 {len(cand)} 个候选（每组前 {args.per_group}）")
            elif args.keep > 0:
                cand = [n for n, _ in ranked[:args.keep]]
            else:
                cand = []

            if cand:
                # P2-11：并发深验（每节点独立 listener 端口）
                if not args.serial_verify and len(cand) > 1:
                    log(f"开始并发深度验证（{len(cand)} 个 ← {args.test_url}）")
                    t0 = time.time()
                    checks = t.curl_check_many(cand, args.test_url, args.timeout)
                    log(f"  并发验证完成，耗时 {time.time()-t0:.1f}s")
                else:
                    log(f"开始深度验证（串行，{len(cand)} 个 ← {args.test_url}）")
                    checks = {n: t.curl_check(n, args.test_url, args.timeout) for n in cand}

                for i, name in enumerate(cand, 1):
                    code, sec = checks.get(name, (None, 99.0))
                    ok = code == 200
                    p = by_name.get(name, {})
                    sc = quality_score(delays[name], sec) if ok else 0.0
                    score_of[name] = sc
                    rows.append({"name": name, "type": p.get("type", ""),
                                 "server": p.get("server", ""), "port": p.get("port", 0),
                                 "delay_ms": delays[name], "http_code": code or 0,
                                 "http_sec": round(sec, 2) if ok else None, "ok": ok,
                                 "score": sc, "grade": grade(sc) if ok else "失败"})
                    log(f"  {i:2}/{len(cand)} {'✅' if ok else '❌'} {name:34} "
                        f"{delays[name]:>5}ms / " + (f"{sec:.2f}s" if ok else "超时") + f" / {sc:5.1f}分")
                    if ok:
                        passed.append(name)
                    if args.good_enough and args.per_group == 0 and len(passed) >= args.good_enough:
                        log(f"  已达到 good-enough={args.good_enough}，提前结束深验")
                        break
            else:
                # 未深验：延迟通过即视为可用，评分只用延迟维度（实速给中性分）
                for name, ms in ranked:
                    sc = quality_score(ms, None)
                    score_of[name] = sc
                    rows.append({"name": name, "type": by_name.get(name, {}).get("type", ""),
                                 "server": by_name.get(name, {}).get("server", ""),
                                 "port": by_name.get(name, {}).get("port", 0),
                                 "delay_ms": ms, "http_code": None, "http_sec": None,
                                 "ok": True, "score": sc, "grade": grade(sc)})
                passed = [n for n, _ in ranked]

            if len(passed) < args.min_pass:
                fail(f"通过节点仅 {len(passed)} 个，少于 --min-pass={args.min_pass}")

            # 按质量分排序（深验时综合延迟+实速；未深验时等价于按延迟）
            passed.sort(key=lambda n: -score_of.get(n, 0))
            result["passed"] = len(passed)
            result["best"] = [{"name": n, "delay_ms": delays.get(n),
                               "score": score_of.get(n),
                               "grade": grade(score_of.get(n, 0)),
                               "proxy": by_name.get(n)} for n in passed[:10]]

            # 每组独立排名
            group_rank = {}
            for g in PROTO_GROUPS:
                if g == "all":
                    continue
                gn = [n for n in passed
                      if (by_name.get(n, {}).get("_group") or
                          proto_group(by_name.get(n, {}).get("type", ""))) == g]
                if gn:
                    group_rank[g] = [{"name": n, "score": score_of.get(n),
                                      "delay_ms": delays.get(n),
                                      "proxy": by_name.get(n)} for n in gn]
            result["by_group"] = group_rank
            if len(group_rank) > 1:
                log("=== 各协议组最佳 ===")
                for g, items in group_rank.items():
                    b = items[0]
                    log(f"  {g:10} {b['name']:34} {b['score']:5.1f}分  "
                        f"{b['delay_ms']:>6}ms（该组通过 {len(items)} 个）")
    except KeyboardInterrupt:
        log("用户中断，临时实例已清理")
        sys.exit(130)

    log(f"通过：{len(passed)} 个")
    log("=== 质量最高的 5 个（评分=延迟60% + 实速40%）===")
    for n in passed[:5]:
        p = by_name.get(n, {})
        log(f"  {n:36} {score_of.get(n,0):5.1f}分[{grade(score_of.get(n,0))}] "
            f"{delays.get(n):>6}ms  {p.get('server')}:{p.get('port')}")

    do_apply = not args.dry_run and (args.apply or args.cron)
    if do_apply:
        selected = [by_name[n] for n in passed if n in by_name]
        # P2-12：落地节点数上限，避免把几十个节点全塞进生产配置
        if args.max_nodes and len(selected) > args.max_nodes:
            dropped = len(selected) - args.max_nodes
            selected = selected[:args.max_nodes]
            log(f"  按 --max-nodes={args.max_nodes} 截断，丢弃 {dropped} 个（按质量分排序）")
        apply_prod(selected, prod_rules, insecure=args.insecure, secret=args.secret)
        result["applied"] = True
    else:
        log("未落地生产配置（加 --apply 或 --cron 才会写入）")
        result["applied"] = False

    report_sources(source_health())

    jsonl, csvp = save_history(rows, by_name)
    log(f"测试记录：{jsonl}")
    log(f"最新 CSV ：{csvp}")
    result["history_jsonl"] = jsonl
    result["history_csv"] = csvp

    # B 层：多次采样
    sample_path = save_samples(delays, rows, args.group,
                               all_names=[p["name"] for p in proxies])
    log(f"B层 采样序列：{sample_path}（{len(delays)} 条）")
    result["samples"] = sample_path

    # C 层：按天聚合表
    daily_path = build_daily_aggregate()
    if daily_path:
        log(f"C层 每日聚合：{daily_path}")
        result["daily_csv"] = daily_path

    # D 层：分组订阅输出
    if not args.no_subscriptions and passed:
        written = export_group_configs(passed, by_name, prod_rules)
        for g, path, n in written:
            log(f"D层 订阅 [{g}]：{path}（{n} 节点）")
        result["subscriptions"] = {g: path for g, path, _ in written}

    # cron 收尾：清死节点 + 归档历史（dry-run 时跳过）
    if args.cron and not args.dry_run:
        log("=== cron 收尾：清理死节点 ===")
        n_dead = clean_dead_nodes(window=args.dead_window, min_fail=args.dead_fails,
                                  apply=True, target="both", protect=set(passed),
                                  backup=not do_apply)
        result["cleaned_dead"] = n_dead
        log("=== cron 收尾：归档过期历史 ===")
        prune_history(days=args.prune_days, archive=not args.no_archive, apply=True)
        result["pruned"] = True
    elif args.cron:
        log("cron --dry-run：跳过落地与清理")

    if args.json_out:
        with codecs.open(args.json_out, "w", "utf-8") as f:
            json.dump(result, f, ensure_ascii=False, indent=2)
        log(f"JSON 结果：{args.json_out}")

    if args.cron:
        log("=== cron 全流程结束 ===")


if __name__ == "__main__":
    try:
        main()
    except SystemExit:
        raise
    except Exception as e:
        log(f"异常：{type(e).__name__}: {e}")
        sys.exit(1)
