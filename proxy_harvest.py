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

__version__ = "0.0.3"

import argparse
import base64
import codecs
import configgen
import csv
import datetime
import hashlib
import json
import math
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
                data = json.load(f)
            # config.json 根节点必须是对象；[]、null、数字都视为坏配置，
            # 不能让后续 _SETTINGS.get 在导入期抛 AttributeError。
            if isinstance(data, dict):
                settings = data
        except Exception:
            pass
    # 环境变量覆盖（前缀 PH_ = Proxy Harvest）
    for key in ("base_dir", "mihomo_exe", "mixed_port", "api_port", "secret",
                "proxy_prefix", "curl"):
        env = os.environ.get("PH_" + key.upper())
        if env:
            settings[key] = env
    return settings


def _int_setting(value, default):
    """config.json 里的端口可能被手写坏；解析失败时退回默认值。"""
    try:
        v = int(str(value).strip())
    except (TypeError, ValueError):
        return default
    return v if 0 < v <= 65535 else default


_SETTINGS = _load_settings()


def _default_base_dir(script_dir=None):
    """未配置 PH_BASE_DIR / config.json 时的数据目录。

    以脚本方式运行时用脚本目录；被 pip 装进 site-packages 时如果还把
    history/backups/source-state 写在包目录里，普通用户通常没有写权限，
    升级/卸载也会连数据一起丢，所以退到用户目录。
    """
    path = os.path.abspath(script_dir or SCRIPT_DIR)
    low = path.lower().replace("\\", "/")
    if "site-packages" in low or "dist-packages" in low:
        return os.path.join(os.path.expanduser("~"), ".proxy-harvest")
    return path


BASE = os.path.abspath(
    _SETTINGS.get("base_dir")
    if isinstance(_SETTINGS.get("base_dir"), str) and _SETTINGS.get("base_dir").strip()
    else _default_base_dir())
_MIHOMO_SETTING = _SETTINGS.get("mihomo_exe")
MIHOMO_EXE = os.path.abspath(
    _MIHOMO_SETTING if isinstance(_MIHOMO_SETTING, str) and _MIHOMO_SETTING.strip()
    else os.path.join(BASE, "mihomo", "mihomo.exe" if os.name == "nt" else "mihomo"))
MIHOMO_MOCK = os.environ.get("PH_MIHOMO_MOCK", "")
PROD_CONF_DIR = os.path.join(BASE, "config")
PROD_CONFIG = os.path.join(PROD_CONF_DIR, "config.yaml")
BACKUP_DIR = os.path.join(BASE, "backups")
HISTORY_DIR = os.path.join(BASE, "history")
TMP_DIR = os.path.join(BASE, ".harvest-tmp")
LOG_FILE = os.path.join(BASE, "harvest.log")
SOURCE_STATE_FILE = os.path.join(BASE, "source-state.json")
CURL = _SETTINGS.get("curl")
if not isinstance(CURL, str) or not CURL.strip():
    CURL = "curl.exe" if os.name == "nt" else "curl"
CURL = CURL.strip()
NULL_DEVICE = "NUL" if os.name == "nt" else "/dev/null"
_MIHOMO_FLAGS = getattr(subprocess, "CREATE_NO_WINDOW", 0) if os.name == "nt" else 0
DEFAULT_EXIT_INFO_URL = "https://ipapi.co/json/"
DEFAULT_MAX_BODY_BYTES = 4096
# 生产 API secret 在运行时用 resolve_prod_secret() 解算（见下），
# 不在导入期固定，这样 --secret 和"沿用现有配置"都能生效。
PROD_PORT = _int_setting(_SETTINGS.get("mixed_port", 2080), 2080)
PROD_API = _int_setting(_SETTINGS.get("api_port", 9090), 9090)


# v0.01 及更早版本的默认 secret，必须视为弱口令
LEGACY_DEFAULT_SECRETS = {"box", "", "secret", "clash", "123456"}
MIN_SECRET_LEN = 8


def is_weak_secret(s):
    """判断 secret 是否属于弱值：空、旧默认值、或长度不足。"""
    if not isinstance(s, str):
        return True
    s = s.strip()
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
            log(f"  ⚠ {origin} 的 secret 过弱（长度 {len(str(value))}），已忽略并重新生成",
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
_PROXY_PREFIX_CFG = _SETTINGS.get("proxy_prefix", "https://gh-proxy.com/")
PROXY_PREFIX = _PROXY_PREFIX_CFG if isinstance(_PROXY_PREFIX_CFG, str) else "https://gh-proxy.com/"

# 允许 config.json 直接覆盖整个源列表；非字符串项直接忽略，避免 fetch 收到 null
_SOURCES_CFG = _SETTINGS.get("sources")
if isinstance(_SOURCES_CFG, list):
    _SOURCES_CFG = [s for s in _SOURCES_CFG if isinstance(s, str) and s.strip()]
SOURCES = (_SOURCES_CFG if isinstance(_SOURCES_CFG, list) and _SOURCES_CFG
           else [PROXY_PREFIX + s for s in RAW_SOURCES])
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/157.0.0.0 Safari/537.36"
DEFAULT_DELAY_URL = "https://github.com/"   # 用 github 做 delay，能返回延迟即真实连通
DEFAULT_TEST_URL = "https://github.com/"


# ---------------- 工具 ----------------
def mihomo_command(args):
    """返回内核命令。测试可设 PH_MIHOMO_MOCK 指向假内核脚本。"""
    if MIHOMO_MOCK:
        return [sys.executable, MIHOMO_MOCK] + list(args)
    return [MIHOMO_EXE] + list(args)


def popen_mihomo(args):
    return subprocess.Popen(mihomo_command(args), creationflags=_MIHOMO_FLAGS)


def _pid_alive(pid):
    """判断 PID 是否存活。

    绝不能用 os.kill(pid, 0)：Python 文档明确，Windows 上除 Ctrl 事件外的
    任何信号值都会走 TerminateProcess —— 探活会变成真的杀进程。
    """
    if not pid or pid <= 0:
        return False
    if os.name != "nt":
        try:
            os.kill(pid, 0)
            return True
        except PermissionError:
            # 进程存在但属于别的用户；不能当成死亡去抢锁
            return True
        except OSError:
            return False
    try:
        import ctypes
        from ctypes import wintypes
        PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
        STILL_ACTIVE = 259
        k32 = ctypes.WinDLL("kernel32", use_last_error=True)
        k32.OpenProcess.restype = wintypes.HANDLE
        k32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        k32.GetExitCodeProcess.argtypes = [wintypes.HANDLE,
                                           ctypes.POINTER(wintypes.DWORD)]
        k32.CloseHandle.argtypes = [wintypes.HANDLE]
        h = k32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
        if not h:
            return False
        try:
            code = wintypes.DWORD()
            if not k32.GetExitCodeProcess(h, ctypes.byref(code)):
                return False
            return code.value == STILL_ACTIVE
        finally:
            k32.CloseHandle(h)
    except Exception:
        # 探测失败时保守处理：当成还活着，避免误删别人的锁
        return True


def _lock_file(f):
    """对已打开的文件拿排它锁；成功返回 True，被占用返回 False。"""
    try:
        if os.name == "nt":
            import msvcrt
            f.seek(0)
            msvcrt.locking(f.fileno(), msvcrt.LK_NBLCK, 1)
        else:
            import fcntl
            fcntl.flock(f.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        return True
    except OSError:
        return False


def acquire_lock(retries=1):
    """运行锁，防止 cron 两次运行重叠。

    用操作系统文件锁（Windows msvcrt / Unix flock）而不是“读 PID→删→重建”。
    旧实现里两个进程可能同时判断对方是陈旧锁，然后互删刚建好的锁；
    OS 锁由内核持有，进程崩溃/退出时自动释放，不存在这个窗口。
    锁文件保留最后一次 PID，仅用于诊断；真正的占用状态由 OS 锁决定。
    """
    lock = os.path.join(BASE, ".harvest.lock")
    os.makedirs(BASE, exist_ok=True)
    try:
        f = open(lock, "a+b")
    except OSError as e:
        log(f"打开锁文件失败，拒绝在无锁状态下运行：{e}")
        return None
    if not _lock_file(f):
        f.close()
        return None
    try:
        f.seek(0)
        f.truncate()
        f.write(str(os.getpid()).encode("ascii", "ignore"))
        f.flush()
    except OSError:
        pass
    return f


def release_lock(lock):
    if not lock or not hasattr(lock, "fileno"):
        return
    try:
        if os.name == "nt":
            import msvcrt
            lock.seek(0)
            msvcrt.locking(lock.fileno(), msvcrt.LK_UNLCK, 1)
        else:
            import fcntl
            fcntl.flock(lock.fileno(), fcntl.LOCK_UN)
    except OSError:
        pass
    try:
        lock.close()
    except OSError:
        pass


def log(msg, also_file=True):
    line = f"[{datetime.datetime.now():%H:%M:%S}] {msg}"
    try:
        print(line, flush=True)
    except UnicodeEncodeError:
        # 旧 Windows 控制台/重定向编码可能装不下 emoji/旗帜；退化为 ASCII
        # 转义，不能因为一条日志把整轮任务打断。
        print(line.encode("ascii", "backslashreplace").decode("ascii"), flush=True)
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
# 单个订阅源最大读取 32MB。免费订阅正常只有几百 KB；没有上限时，
# 一个异常/恶意源可以把进程内存吃光。
MAX_FETCH_BYTES = 32 * 1024 * 1024


def _open(url, timeout=60):
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open(req, timeout=timeout) as r:
        data = r.read(MAX_FETCH_BYTES + 1)
    if len(data) > MAX_FETCH_BYTES:
        raise ValueError(f"响应超过 {MAX_FETCH_BYTES // (1024 * 1024)}MB 上限")
    return data.decode("utf-8", "ignore")


def fetch(url):
    """抓订阅。若 URL 带加速前缀，失败时自动回退到去掉前缀的直连地址。"""
    try:
        return _open(url)
    except Exception:
        # 直连兜底：把已知前缀剥掉再试一次
        if PROXY_PREFIX and url.startswith(PROXY_PREFIX):
            direct = url[len(PROXY_PREFIX):]
            # 不能打印 URL 尾部：订阅 URL 常带 ?token=...，日志会被贴出去排错。
            log(f"    前缀失败，直连重试 {source_label(direct)}")
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


def _urlparse(u):
    """安全版 urlparse。

    畸形 IPv6 方括号（如 ``]bad[``）在不同 CPython 版本上行为不一致：
    3.9/3.13 会抛 ValueError，3.10 某些补丁版却照常解析并返回 query。
    为保持跨版本一致，这里先主动校验 netloc 里的方括号是否成对且顺序正确，
    再调用 urlparse；任何一步异常或畸形都统一返回 None。
    """
    try:
        # 取 netloc：scheme:// 之后、第一个 / ? # 之前。
        rest = u.split("://", 1)[-1]
        netloc = re.split(r"[/?#]", rest, 1)[0]
        # IPv6 主机必须是一对匹配且顺序正确的方括号；其它情况一律视为畸形。
        if "[" in netloc or "]" in netloc:
            if netloc.count("[") != 1 or netloc.count("]") != 1:
                return None
            if netloc.index("[") > netloc.index("]"):
                return None
        return urllib.parse.urlparse(u)
    except (ValueError, TypeError):
        return None


def qs(u):
    parsed = _urlparse(u)
    if parsed is None:
        return {}
    return {k: v[0] for k, v in urllib.parse.parse_qs(parsed.query).items()}


MAX_PORT = 65535
# 名称里的控制字符、换行、零宽与双向覆盖符：既会伪造日志行，也可能让终端显示错乱
_NAME_BAD_RE = re.compile(r"[\x00-\x1f\x7f\u0080-\u009f\u200b-\u200f\u202a-\u202e\u2066-\u2069]")


def _as_port(value):
    """端口转整数，非法或越界一律返回 0（调用方据此丢弃节点）。"""
    try:
        p = int(str(value).strip())
    except (TypeError, ValueError):
        return 0
    return p if 0 < p <= MAX_PORT else 0


def _flag(value):
    """解析 allowInsecure / insecure 这类开关，兼容 1 / true / yes。"""
    return str(value or "").strip().lower() in ("1", "true", "yes", "on")


def _cred(value):
    """URL 里的用户名/密码可能带百分号编码，统一解码。"""
    return urllib.parse.unquote(value or "").strip()


def _query_cred(value):
    """parse_qs 已经解过一次码，查询串凭据只 strip，不能再 unquote。"""
    return str(value or "").strip()


def _clean_name_text(value):
    s = _NAME_BAD_RE.sub(" ", str(value or ""))
    return re.sub(r"\s+", " ", s).strip()


# Clash/mihomo 的保留名：这些是策略组/内置出口，不能同时当节点名。
RESERVED_PROXY_NAMES = frozenset(
    {"DIRECT", "REJECT", "REJECT-DROP", "PASS", "COMPATIBLE",
     "GLOBAL", "AUTO", "PROXY"})


def sanitize_name(name, fallback=""):
    """清理节点名：去控制字符、折叠空白、限制长度。

    节点名来自订阅 fragment，属于不可信输入；不清理会被写进日志、
    CSV 和 Clash 配置，换行可以伪造日志行，零宽/双向符会污染终端显示。
    另外要避开内核保留名（DIRECT/REJECT/AUTO/PROXY 等），否则配置里
    会出现“节点 DIRECT”和内置 DIRECT 重名，内核拒绝加载或规则语义错乱。
    """
    s = _clean_name_text(name)
    if not s or s.upper() in RESERVED_PROXY_NAMES:
        s = _clean_name_text(fallback)
    if not s or s.upper() in RESERVED_PROXY_NAMES:
        s = "node"
    return s[:36]


def hostport(netloc):
    """拆分 host:port，容忍 IPv6 方括号与非法端口。

    非法端口返回 0，由解析器丢弃节点，而不是抛 ValueError 让整轮抓取中断。
    """
    hp = (netloc or "").rpartition("@")[2]
    if hp.startswith("["):
        h, sep, p = hp[1:].partition("]:")
        return h, _as_port(p) if sep else 0
    h, sep, p = hp.rpartition(":")
    if not sep:
        return hp, 0
    return h, _as_port(p)


def _alpn_list(p):
    value = p.get("alpn")
    if not value:
        return None
    if isinstance(value, (list, tuple)):
        items = [str(x).strip() for x in value if str(x).strip()]
    else:
        items = [x.strip() for x in re.split(r"[,;]", str(value)) if x.strip()]
    return items or None


# mihomo 能识别的 network 取值；其余（kcp/quic/wechat-video 等）免费池里
# 常出现但 mihomo 不支持，原样写进配置会让整个内核加载失败。
SUPPORTED_NETWORKS = {"tcp", "ws", "httpupgrade", "grpc", "h2", "http", "xhttp"}


def apply_transport(d, p, fallback_host):
    """填充传输层字段（vless / trojan / vmess 共用）。

    p 是 parse_qs 解出来的 dict，值已解码，不要再 unquote。
    支持：tcp / ws / httpupgrade / grpc / h2 / http / xhttp
    不支持的传输类型返回 None，调用方应丢弃该节点。
    """
    net = str(p.get("type", "tcp") or "tcp").strip().lower()
    if net not in SUPPORTED_NETWORKS:
        return None
    host = str(p.get("host") or p.get("sni") or fallback_host or "")
    path = str(p.get("path") or "/")

    d["network"] = net
    if net == "ws":
        d["ws-opts"] = {"path": path, "headers": {"Host": host}}
    elif net == "httpupgrade":
        d["network"] = "ws"
        d["ws-opts"] = {"path": path, "headers": {"Host": host},
                        "v2ray-http-upgrade": True}
    elif net == "grpc":
        d["grpc-opts"] = {"grpc-service-name": str(p.get("serviceName", "") or "")}
    elif net in ("h2", "http"):
        d["network"] = "h2"
        d["h2-opts"] = {"host": [x for x in host.split(",") if x], "path": path}
    elif net == "xhttp":
        d["xhttp-opts"] = {"path": path, "host": host,
                          "mode": str(p.get("mode", "auto") or "auto")}

    alpn = _alpn_list(p)
    if alpn:
        d["alpn"] = alpn
    return d


def p_vless(u):
    p = qs(u)
    parsed = _urlparse(u)
    if parsed is None:
        return None
    h, port = hostport(parsed.netloc)
    uuid = _cred(parsed.username)
    # 没有 host / 合法端口 / uuid 的节点写进 mihomo 配置必然导致整份配置加载失败
    if not h or not port or not uuid:
        return None
    # mihomo 不认 vless 加密（encryption 非 none），这类节点注定测不通，直接跳过
    if str(p.get("encryption", "none") or "none").strip().lower() not in ("", "none"):
        return None
    if str(p.get("security", "") or "").strip().lower() == "reality" and not p.get("pbk"):
        # reality 缺公钥会让内核拒绝加载；提前丢弃，别拖垮整个配置
        return None
    name = sanitize_name(urllib.parse.unquote(parsed.fragment), h)
    d = {"name": name, "type": "vless", "server": h, "port": port,
         "uuid": uuid, "udp": True,
         "client-fingerprint": p.get("fp", "chrome")}
    sec = str(p.get("security", "") or "").strip().lower()
    sni = p.get("sni") or p.get("host") or ""
    if sec in ("tls", "reality"):
        d["tls"] = True
        if sni:
            d["servername"] = sni
        if p.get("flow"):
            d["flow"] = p["flow"]
        if sec == "reality":
            d["reality-opts"] = {"public-key": p.get("pbk", ""), "short-id": p.get("sid", "")}
        if _flag(p.get("allowInsecure")):
            d["skip-cert-verify"] = True
    else:
        d["tls"] = False
    if apply_transport(d, p, h) is None:
        return None      # 不支持的传输类型，丢弃
    return d


def p_vmess(u):
    if not u.startswith("vmess://"):
        return None
    payload, _, fragment = u[8:].partition("#")
    body = payload + "=" * (-len(payload) % 4)
    j = None
    for decode in (base64.urlsafe_b64decode, base64.b64decode):
        try:
            obj = json.loads(decode(body).decode("utf-8", "ignore"))
            if isinstance(obj, dict):
                j = obj
                break
        except Exception:
            continue
    if not j:
        return None      # 不是合法 base64 JSON 对象，丢弃而不是抛异常
    server = str(j.get("add") or "").strip()
    port = _as_port(j.get("port"))
    uuid = str(j.get("id") or "").strip()
    if not server or not port or not uuid:
        return None      # 缺 host/端口/uuid 的节点会让整份配置加载失败
    try:
        aid = max(0, int(str(j.get("aid") or 0).strip() or 0))
    except (TypeError, ValueError):
        aid = 0
    name_hint = j.get("ps") or urllib.parse.unquote(fragment) or server
    d = {"name": sanitize_name(name_hint, server), "type": "vmess",
         "server": server, "port": port, "uuid": uuid, "alterId": aid,
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
    if apply_transport(d, p, server) is None:
        return None
    return d


def p_trojan(u):
    p = qs(u)
    parsed = _urlparse(u)
    if parsed is None:
        return None
    h, port = hostport(parsed.netloc)
    # trojan 标准是 trojan://password@host；兼容 user:pass@host（取 password）
    password = _cred(parsed.password) or _cred(parsed.username)
    if not h or not port or not password:
        return None
    name = sanitize_name(urllib.parse.unquote(parsed.fragment), h)
    d = {"name": name, "type": "trojan", "server": h, "port": port,
         "password": password, "udp": True}
    sni = p.get("sni") or p.get("peer")
    if sni:
        d["sni"] = sni
    # 只在节点明确声明 allowInsecure=1 时才跳过证书校验
    if _flag(p.get("allowInsecure") or p.get("insecure")):
        d["skip-cert-verify"] = True
    if apply_transport(d, p, h) is None:
        return None
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
    if not u.startswith("ss://"):
        return None
    try:
        body, _, name = u[5:].partition("#")
        name = urllib.parse.unquote(name)
        # 先拆出 SIP002 的 ?plugin=... 查询串，否则 host:port 会带上它导致 int() 失败
        body, _, query = body.partition("?")
        body = body.rstrip("/")
        plugin_raw = urllib.parse.parse_qs(query).get("plugin", [""])[0]

        if "@" in body:
            ui, hp = body.split("@", 1)
            decoded_ui = False
            # 明文 SIP002 userinfo 一定含 ":"；只有不含冒号的 base64
            # userinfo 才尝试解码，避免把带冒号的明文错误地当成 base64。
            if ":" not in ui:
                try:
                    candidate = base64.urlsafe_b64decode(
                        ui + "=" * (-len(ui) % 4)).decode()
                    if ":" in candidate:
                        ui = candidate
                        decoded_ui = True
                except Exception:
                    pass
            if not decoded_ui:
                # SIP002 明文 userinfo：method:password 里的密码可能带 %40 等编码
                ui = urllib.parse.unquote(ui)
            m, _, pw = ui.partition(":")
            if not decoded_ui:
                pw = urllib.parse.unquote(pw)
        else:
            raw = base64.urlsafe_b64decode(body + "=" * (-len(body) % 4)).decode()
            cred, _, hp = raw.rpartition("@")
            m, _, pw = cred.partition(":")
        # hostport 同时处理 IPv6 方括号与非法端口，非法端口返回 0 → 丢弃
        h, port = hostport(hp)
        h = h.strip("[]")
        m = m.strip()
        if not h or not port or not m:
            return None
        d = {"name": sanitize_name(name, f"{h}:{port}"), "type": "ss", "server": h,
             "port": port, "cipher": m, "password": pw, "udp": True}

        if plugin_raw:
            pl, opts = parse_ss_plugin(plugin_raw)
            if not pl:
                # 不支持的插件：直接丢弃，别当裸 ss 去测（那样必然测不通还浪费名额）
                return None
            d["plugin"] = pl
            d["plugin-opts"] = opts
        return d
    except Exception:
        # 畸形 SIP002（坏 base64 / 缺字段）一律丢弃，不让解析异常打断抓取
        return None


def p_hy2(u):
    p = qs(u)
    parsed = _urlparse(u)
    if parsed is None:
        return None
    h, port = hostport(parsed.netloc)
    # user:pass 形式取 password；查询串里的 password/auth 优先于单个 username，
    # 兼容 hysteria2://user@host?password=...
    password = (_cred(parsed.password) or _query_cred(p.get("password"))
                or _query_cred(p.get("auth")) or _cred(parsed.username))
    if not h or not port or not password:
        return None
    name = sanitize_name(urllib.parse.unquote(parsed.fragment), h)
    d = {"name": name, "type": "hysteria2", "server": h, "port": port,
         "password": password}
    sni = p.get("sni") or p.get("peer")
    if sni:
        d["sni"] = sni
    # 混淆（salamander 等）
    if p.get("obfs"):
        d["obfs"] = p["obfs"]
        d["obfs-password"] = p.get("obfs-password", "")
    # 端口跳跃，如 mport=20000-30000；格式不对会让内核加载失败，直接忽略
    mport = (p.get("mport") or "").strip()
    if mport and re.fullmatch(r"\d+(?:-\d+)?(?:,\d+(?:-\d+)?)*", mport):
        d["ports"] = mport
    if _flag(p.get("insecure") or p.get("allowInsecure")):
        d["skip-cert-verify"] = True
    alpn = _alpn_list(p)
    if alpn:
        d["alpn"] = alpn
    return d


def p_tuic(u):
    """tuic://uuid:pass@host:port?sni=...&congestion_control=bbr

    也兼容 tuic://host:port?uuid=...&password=... 这种把凭据全放查询串的写法。
    """
    p = qs(u)
    parsed = _urlparse(u)
    if parsed is None:
        return None
    h, port = hostport(parsed.netloc)
    uuid = _cred(parsed.username) or (p.get("uuid") or "").strip()
    password = _cred(parsed.password) or (p.get("password") or "").strip()
    if not h or not port or not uuid or not password:
        return None
    name = sanitize_name(urllib.parse.unquote(parsed.fragment), h)
    d = {"name": name, "type": "tuic", "server": h, "port": port,
         "uuid": uuid, "password": password, "udp": True}
    # 与 trojan/vless 保持一致：只有显式声明才跳过证书校验
    if _flag(p.get("allowInsecure") or p.get("insecure")):
        d["skip-cert-verify"] = True
    sni = p.get("sni") or p.get("peer")
    if sni:
        d["sni"] = sni
    cc = p.get("congestion_control") or p.get("congestion-controller")
    if cc:
        d["congestion-controller"] = cc
    if p.get("alpn"):
        d["alpn"] = [x for x in re.split(r"[,;]", p["alpn"]) if x]
    return d


def p_anytls(u):
    """anytls://password@host:port?sni=...  （新兴协议，免费池开始出现）"""
    p = qs(u)
    parsed = _urlparse(u)
    if parsed is None:
        return None
    h, port = hostport(parsed.netloc)
    # password@host 优先；兼容 user@host?password=...，查询串密码优先于 username
    password = (_cred(parsed.password) or _query_cred(p.get("password"))
                or _cred(parsed.username))
    if not h or not port or not password:
        return None
    name = sanitize_name(urllib.parse.unquote(parsed.fragment), h)
    d = {"name": name, "type": "anytls", "server": h, "port": port,
         "password": password, "udp": True,
         "client-fingerprint": p.get("fp", "chrome")}
    sni = p.get("sni") or p.get("peer")
    if sni:
        d["sni"] = sni
    if p.get("alpn"):
        d["alpn"] = [x for x in re.split(r"[,;]", p["alpn"]) if x]
    if _flag(p.get("allowInsecure") or p.get("insecure")):
        d["skip-cert-verify"] = True
    return d


# mihomo 支持的 SSR 协议/混淆白名单；未知取值写进配置会让内核直接拒绝加载
SSR_PROTOCOLS = {"origin", "auth_sha1_v4", "auth_aes128_md5", "auth_aes128_sha1",
                 "auth_chain_a", "auth_chain_b", "auth_chain_c", "auth_chain_d",
                 "auth_chain_e", "auth_chain_f"}
SSR_OBFS = {"plaintext", "http_simple", "http_post", "random_head",
            "tls1.2_ticket_auth", "tls1.2_ticket_fastauth"}


def p_ssr(u):
    """ssr://base64(host:port:protocol:method:obfs:pass/?remarks=...)"""
    if not u.startswith("ssr://"):
        return None
    body = u[6:]
    body += "=" * (-len(body) % 4)
    try:
        raw = base64.urlsafe_b64decode(body).decode("utf-8", "ignore")
    except Exception:
        return None
    main, _, query = raw.partition("/?")
    if main.startswith("["):
        # SSR 的 IPv6 主机常用 [::1]:port:...；不能按冒号直接 split。
        end = main.find("]")
        if end < 0:
            return None
        h = main[1:end].strip()
        fields = main[end + 1:].lstrip(":").split(":", 4)
        if len(fields) < 5:
            return None
        pt, proto, method, obfs, pwd = fields
    else:
        fields = main.split(":", 5)
        if len(fields) < 6:
            return None
        h, pt, proto, method, obfs, pwd = fields
    h = h.strip()
    port = _as_port(pt)
    if not h or not port or not method or not pwd:
        return None
    if proto not in SSR_PROTOCOLS or obfs not in SSR_OBFS:
        return None      # 未知协议/混淆，mihomo 无法加载
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
    d = {"name": sanitize_name(remarks, h), "type": "ssr", "server": h, "port": port,
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


# 订阅里有时会把多个 URI 压在一行（空格/制表符分隔），按行切会漏掉后面的节点。
_URI_RE = re.compile(r"([a-z0-9]+)://\S+", re.I)


def _count_protocol_lines(text):
    """统计一段订阅文本里有多少个已知协议的 URI。用于内容校验。"""
    return sum(1 for m in _URI_RE.finditer(text or "")
               if m.group(1).lower() in PARSERS)


def source_meta(text):
    """订阅内容的指纹：哈希、节点数、协议构成。"""
    protos = defaultdict(int)
    for m in _URI_RE.finditer(text or ""):
        proto = m.group(1).lower()
        if proto in PARSERS:
            protos[proto] += 1
    return {
        "sha256": hashlib.sha256((text or "").encode("utf-8")).hexdigest(),
        "count": sum(protos.values()),
        "protocols": dict(sorted(protos.items())),
    }


def _safe_int(value, default=0):
    try:
        return int(value)
    except (TypeError, ValueError, OverflowError):
        return default


def source_id(url):
    """来源 URL 的稳定、不可逆标识。

    订阅 URL 常带 ?token=...，不能原样写进快照、历史、状态文件或 --json。
    这里统一只落 16 位 SHA-256 前缀；同一 URL 仍能跨轮关联。
    """
    if not isinstance(url, str) or not url:
        return ""
    return hashlib.sha256(url.encode("utf-8")).hexdigest()[:16]


def source_key(value):
    """把旧的原始 URL key 归一成 source_id；已经是 16 位 ID 的原样保留。"""
    if not isinstance(value, str) or not value:
        return ""
    if re.fullmatch(r"[0-9a-f]{16}", value):
        return value
    return source_id(value)


def source_label(value):
    """日志里只显示来源 ID，避免把带 token 的 URL 尾部打出来。"""
    sid = source_key(value)
    return f"source#{sid}" if sid else "source#?"


def safe_url_label(value):
    """日志里的探测 URL：只保留 scheme + host[:port]，丢掉 path/query/fragment。

    自定义 --test-url / --health-url 也可能带签名 token；日志常被贴到公开区，
    不能原样打印。
    """
    try:
        p = urllib.parse.urlsplit(str(value or ""))
        host = p.hostname or "?"
        if p.port:
            host += f":{p.port}"
        return f"{p.scheme or '?'}://{host}/…"
    except Exception:
        return "url#?"


def normalize_source_map(sources):
    """状态文件里的 sources 字典：key 归一为 source_id，value 必须是字典。

    只保留已知元数据字段，避免旧状态/外部输入把 source URL 等字段带进新文件。
    """
    out = {}
    if not isinstance(sources, dict):
        return out
    allowed = {"sha256", "count", "protocols", "endpoints", "mutated", "reason"}
    for key, value in sources.items():
        sid = source_key(key)
        if sid and isinstance(value, dict):
            out[sid] = {k: v for k, v in value.items() if k in allowed}
    return out


def public_proxy(p):
    """可落盘/可交给 --json 的节点定义：去掉订阅 URL，只保留来源 ID。"""
    q = clean_proxy(p) if isinstance(p, dict) else {}
    q.pop("source", None)
    q.pop("source_url", None)
    q.pop("source_id", None)
    sid = source_key(p.get("_source_id") or p.get("_source") or
                     p.get("source") or p.get("source_id") or "") if isinstance(p, dict) else ""
    if sid:
        q["_source_id"] = sid
    return q


def harvest(limit, extra_sources=None):
    """多源抓取。

    P1-8：给每个源设配额，避免第一个源把 limit 占满、后面的源永远抓不到。
    P1-9：内容里一个已知协议行都没有（HTML/空/报错页）时视为该源失败。
    P1-14：按 URI 正则切分而不是按行切，兼容多个节点挤在同一行。
    """
    extra_sources = extra_sources if isinstance(extra_sources, (list, tuple, set)) else []
    srcs = list(SOURCES) + [s for s in extra_sources
                            if isinstance(s, str) and s.strip()]
    if not srcs:
        return []
    # 每源先分基础配额，用完再按需补余量
    quota = max(1, limit // len(srcs))
    out, seen = [], set()
    per_source = {}

    def drain(text, src, cap, meta=None):
        added = 0
        for m in _URI_RE.finditer(text):
            if len(out) >= limit or added >= cap:
                break
            proto = m.group(1).lower()
            if proto not in PARSERS:
                continue
            line = m.group(0)
            try:
                d = PARSERS[proto](line)
            except Exception:
                continue
            if not d or not d.get("server") or not d.get("port"):
                continue
            key = (str(d["type"]).lower(), str(d["server"]).strip().lower(),
                   _as_port(d["port"]))
            if key in seen:
                continue
            seen.add(key)
            d["_source"] = src       # 供源健康度统计；落地/落盘前会剥离
            d["_source_id"] = source_id(src)
            d["_group"] = proto_group(d["type"])
            if meta:
                d["_source_hash"] = meta.get("sha256", "")
                d["_source_count"] = meta.get("count", 0)
                d["_source_protocols"] = meta.get("protocols", {})
            out.append(d)
            added += 1
        return added

    # 第一轮：每源最多 quota 个
    texts = []
    for src in srcs:
        try:
            text = decode_body(fetch(src))
        except Exception as e:
            log(f"  源失败 {source_label(src):24} {type(e).__name__}")
            per_source[src] = 0
            continue
        if _count_protocol_lines(text) == 0:
            # P1-9：拿到内容但没有一行合法节点，多半是 HTML 错误页
            log(f"  源无效 {source_label(src):24} 内容无合法节点")
            per_source[src] = 0
            continue
        meta = source_meta(text)
        texts.append((src, text, meta))
        n = drain(text, src, quota, meta)
        per_source[src] = n
        log(f"  {source_label(src):26} +{n:3}  (配额 {quota})")

    # 第二轮：还没满额就用各源余量补
    if len(out) < limit:
        for src, text, meta in texts:
            if len(out) >= limit:
                break
            n = drain(text, src, limit, meta)
            if n:
                per_source[src] = per_source.get(src, 0) + n
                log(f"  {source_label(src):26} +{n:3}  (补余量)")

    alive = sum(1 for v in per_source.values() if v)
    log(f"  抓取汇总：{alive}/{len(srcs)} 个源有效，共 {len(out)} 节点")
    return out


def node_id(p):
    """稳定的节点身份：type|server|port 的 sha1 前 10 位。

    P0-3：免费节点重名极常见，而 dedupe 加的 #2 后缀取决于本轮顺序，
    同一个节点这轮可能叫 A#2、下轮叫 A，用名字做身份会把历史串到别的节点。
    """
    key = "{}|{}|{}".format(
        str(p.get("type") or "").lower(),
        str(p.get("server") or "").lower(),
        _as_port(p.get("port")) or 0,
    )
    return hashlib.sha1(key.encode("utf-8")).hexdigest()[:10]


def ensure_ids(proxies):
    """给每个节点补齐 _id（已有则保留）。"""
    for p in proxies:
        if isinstance(p, dict):
            if not isinstance(p.get("_id"), str) or not p["_id"]:
                p["_id"] = node_id(p)
    return proxies


def dedupe_names(proxies):
    """统一处理重名，保证名字唯一。

    P2-5：不能只按计数加后缀——输入 A, A, A#2 会得到 A, A#2, A#2（又撞）。
    改为循环自增，直到名字不在已用集合里。
    P0-3：同时补齐稳定 _id。
    P1-11：名称来自不可信订阅，统一清洗控制字符后再去重。
    """
    ensure_ids(proxies)
    # 保留名不是普通节点名；从 used 起步，万一 sanitize_name 被绕过也不会撞上
    used = set(RESERVED_PROXY_NAMES)
    for d in proxies:
        if not isinstance(d, dict):
            continue
        base = sanitize_name(d.get("name"), f'{d.get("server")}:{d.get("port")}')
        name = base
        n = 1
        while name in used:
            n += 1
            name = f"{base}#{n}"
        used.add(name)
        d["name"] = name
    return proxies


def dedupe_endpoints(proxies):
    """按 (type, server, port) 去重，保留先出现的节点。

    --inherit 拉回的历史节点可能与本轮抓取、甚至彼此之间端点重复；
    重复端点会让测速名额和落地名额被同一台服务器占两次。
    """
    seen, out = set(), []
    for p in proxies:
        if not isinstance(p, dict):
            continue
        key = (str(p.get("type") or "").strip().lower(),
               str(p.get("server") or "").strip().lower(),
               _as_port(p.get("port")))
        if key in seen:
            continue
        seen.add(key)
        out.append(p)
    return out


# 各协议必须带的凭据字段：缺了内核会拒绝加载整份配置，必须在落地前剔除
REQUIRED_FIELDS = {
    "vless": ("uuid",),
    "vmess": ("uuid",),
    "trojan": ("password",),
    "ss": ("cipher", "password"),
    "ssr": ("cipher", "password", "protocol", "obfs"),
    "hysteria2": ("password",),
    "tuic": ("uuid", "password"),
    "anytls": ("password",),
}

# 这些名字是 mihomo 的内置出站或本程序生成的组名；节点重名会让
# proxy-groups 引用产生歧义，配置可能直接加载失败，落地前就剔除。
RESERVED_NODE_NAMES = {"DIRECT", "REJECT", "REJECT-DROP", "PASS", "COMPATIBLE",
                       "GLOBAL", "AUTO", "PROXY"}


def validate_proxies(proxies):
    """返回 (good, bad)。bad 是 [(name, 缺失字段或问题)]。
    调用方直接用 good，不要再用 in/not in 对 dict 做成员判断。

    P1-12：除必填字段外，还校验端口范围、服务器字符与协议凭据。
    以前只检查"字段非空"，uuid/password 缺失、端口 -1/70000、cipher 为空的
    节点也能通过，写进配置后 mihomo 直接拒绝加载，整轮运行报废。
    """
    good, bad = [], []
    for p in proxies:
        if not isinstance(p, dict):
            bad.append(("?", ["非字典节点"]))
            continue
        miss = [k for k in ("name", "type", "server", "port") if not p.get(k)]
        if miss:
            bad.append((sanitize_name(p.get("name")) or "?", miss))
            continue
        if not isinstance(p.get("type"), str) or p.get("type") not in VALID_TYPES:
            bad.append((sanitize_name(p.get("name")), ["type"]))
            continue
        port = _as_port(p.get("port"))
        if not port:
            bad.append((sanitize_name(p.get("name")), ["port"]))
            continue
        server = str(p.get("server") or "").strip()
        if not server or any(ch.isspace() for ch in server) or "/" in server:
            bad.append((sanitize_name(p.get("name")), ["server"]))
            continue
        missing_cred = [k for k in REQUIRED_FIELDS.get(p["type"], ())
                        if not str(p.get(k) or "").strip()]
        if missing_cred:
            bad.append((sanitize_name(p.get("name")), missing_cred))
            continue
        p["port"] = port
        p["server"] = server
        p["name"] = sanitize_name(p.get("name"), f"{server}:{port}")
        if p["name"] in RESERVED_NODE_NAMES:
            bad.append((p["name"], ["reserved-name"]))
            continue
        good.append(p)
    return good, bad


# ---------------- 配置 ----------------
def clean_proxy(p):
    """剥掉我们自己的元数据字段，只留 mihomo 认识的配置。"""
    return {k: v for k, v in p.items()
            if not k.startswith("_") and k not in ("source", "source_id", "source_url")}


def default_dns_config(servers=None):
    """显式 DNS 配置；默认让 mihomo 本地解析，不把查询交给代理节点。

    fake-ip 适合日常使用，但会改变域名解析结果；需要真实 DNS 结果或做抓包
    验证时，可把 servers 指向本地 mock DNS（如 127.0.0.1:5353）。
    """
    return configgen.default_dns_config(servers)


def make_config(proxies, port, api_port, rules=None, with_groups=False, secret=None,
                insecure=False, dns=None):
    """with_groups=True 时为每个协议组建一个 select 组，方便组级别测速。
    secret: 显式传入；默认用生产 secret。临时实例应传随机值。
    insecure: True 时才保留 skip-cert-verify，默认剥离（更安全）。"""
    return configgen.build_config(
        proxies, port, api_port, rules, with_groups=with_groups, secret=secret,
        insecure=insecure, dns=dns, proto_groups=PROTO_GROUPS)


def make_sources_only_config(proxies, rules=None, insecure=False, dns=None):
    """--sources-only 写出的临时配置；单独抽出来便于测试 insecure 传播。"""
    return configgen.build_sources_config(proxies, rules, insecure=insecure, dns=dns)


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


def copy_file_atomic(src, dst):
    """复制到同目录临时文件后 os.replace，避免回滚留下半截生产配置。"""
    d = os.path.dirname(dst) or "."
    os.makedirs(d, exist_ok=True)
    tmp = f"{dst}.{os.getpid()}.tmp"
    try:
        shutil.copy2(src, tmp)
        os.replace(tmp, dst)
    finally:
        if os.path.exists(tmp):
            try:
                os.remove(tmp)
            except OSError:
                pass


def write_csv_atomic(path, header, rows):
    """CSV 原子写入：避免进程中断时把 latest.csv / latest_daily.csv 写截断。"""
    d = os.path.dirname(path) or "."
    os.makedirs(d, exist_ok=True)
    tmp = f"{path}.{os.getpid()}.tmp"
    try:
        with open(tmp, "w", encoding="utf-8-sig", newline="") as f:
            w = csv.writer(f)
            w.writerow(header)
            for r in rows:
                w.writerow(r)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            try:
                os.remove(tmp)
            except OSError:
                pass
    return path


def split_rules(geo=True):
    """split 规则。geo=False 时退化为不依赖 geoip/geosite 的版本。

    生产目录缺 geoip.dat / geosite.dat 时，mihomo 首次启动会尝试联网下载，
    国内通常超时并导致整份配置起不来；此时只保留 .cn 直连，保证能启动。
    """
    rules = ["DOMAIN-SUFFIX,cn,DIRECT", "MATCH,PROXY"]
    if geo:
        rules = ["GEOIP,private,DIRECT,no-resolve",
                 "GEOSITE,private,DIRECT",
                 "GEOSITE,cn,DIRECT", "GEOIP,CN,DIRECT"] + rules
    return rules


# ---------------- 临时 mihomo 实例 ----------------
class TempMihomo:
    """独立的测速实例：每次运行用 tempfile.mkdtemp 建新目录，
    随机 API secret，跑完销毁。不会和另一次运行抢端口/目录。"""

    def __init__(self, parent_dir, port, api_port, proxies, rules=None, insecure=False,
                 dns=None, geo_dir=None):
        # 端口越界时 mihomo 永远不可能监听成功，提前失败，别白等 30 秒超时。
        try:
            port, api_port = int(port), int(api_port)
        except (TypeError, ValueError, OverflowError):
            raise ValueError("临时实例端口必须是整数")
        if not (1 <= port <= MAX_PORT and 1 <= api_port <= MAX_PORT):
            raise ValueError(f"临时实例端口越界：{port}/{api_port}（应在 1-{MAX_PORT}）")
        os.makedirs(parent_dir, exist_ok=True)
        self.dir = tempfile.mkdtemp(prefix="run-", dir=parent_dir)
        self.port, self.api_port = port, api_port
        self.secret = secrets.token_hex(16)
        self.proc = None
        self.proxies = proxies
        self.rules = rules
        self.insecure = insecure
        self.dns = dns
        self.config = os.path.join(self.dir, "config.yaml")
        try:
            # split 规则依赖 GEOIP/GEOSITE；临时实例的 -d 是自己的 run 目录，
            # 不会自动看到生产配置目录里的 geo 文件。健康检查/真实规则验证
            # 必须把这些数据复制进来，否则临时内核会尝试联网下载并超时。
            if geo_dir and os.path.isdir(geo_dir):
                for fn in os.listdir(geo_dir):
                    low = fn.lower()
                    src = os.path.join(geo_dir, fn)
                    if (low.startswith("geoip") or low.startswith("geosite")
                            or low == "country.mmdb") and os.path.isfile(src):
                        shutil.copy2(src, os.path.join(self.dir, fn))
            write_yaml(self.config,
                       make_config(proxies, port, api_port, rules,
                                   secret=self.secret, insecure=insecure, dns=dns))
        except BaseException:
            # 写配置/复制 geo 失败时别留下一个空 run-xxxx 目录
            shutil.rmtree(self.dir, ignore_errors=True)
            raise

    def __enter__(self):
        try:
            self.proc = popen_mihomo(["-d", self.dir])
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
                                   secret=self.secret, insecure=self.insecure,
                                   dns=self.dns))
        except Exception as e:
            log(f"  重写基础配置失败：{e}")
            return False
        try:
            self.proc = popen_mihomo(["-d", self.dir])
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
        try:
            names = [n for n in self.api("/proxies").get("proxies", {})
                     .get("PROXY", {}).get("all", []) if n not in ("AUTO", "PROXY")]
        except Exception as e:
            # 组 API 和 /proxies 都不可用时返回空，让调用方走 "没有响应" 分支；
            # 不能把异常抛到 _run_main 之外，否则本轮历史/采样都来不及落盘。
            log(f"  /proxies 回退也失败：{type(e).__name__}，本轮按无响应处理")
            return {}
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

    def curl_check(self, name, url, timeout, capture_body=False, max_bytes=DEFAULT_MAX_BODY_BYTES):
        """单节点串行验证（保留作为兜底）。"""
        try:
            self.pin(name)
        except Exception:
            return (None, 99.0, None) if capture_body else (None, 99.0)
        return self._curl_via(f"http://127.0.0.1:{self.port}", url, timeout,
                              capture_body=capture_body, max_bytes=max_bytes)

    @staticmethod
    def _curl_via(proxy_url, url, timeout, capture_body=False,
                  max_bytes=DEFAULT_MAX_BODY_BYTES):
        """通过指定本地代理做一次 curl。

        默认返回 (http_code|None, 耗时秒)。capture_body=True 时返回
        (http_code, 耗时, body bytes|None)；body 超过 max_bytes 或读取失败时
        为 None，让内容校验按失败处理，不把截断内容当成完整响应。

        安全细节：
        - `-q` 忽略用户的 .curlrc，避免本机配置改变测试语义；
        - `--proto =http,https` 禁止 file:// 等协议；
        - URL 前放 `--`，防止以 `-` 开头的字符串被 curl 当成参数。
        """
        body_path = None
        try:
            if capture_body:
                fd, body_path = tempfile.mkstemp(prefix="ph-body-")
                os.close(fd)
                out_arg = body_path
            else:
                out_arg = NULL_DEVICE
            r = subprocess.run(
                [CURL, "-q", "-s", "-o", out_arg, "-w", "%{http_code} %{time_total}",
                 "--proto", "=http,https",
                 "--max-time", str(timeout), "-x", proxy_url, "--", url],
                capture_output=True, text=True, timeout=timeout + 5)
            parts = r.stdout.strip().split()
            code = int(parts[0]) if parts and parts[0].isdigit() else 0
            sec = float(parts[1]) if len(parts) > 1 else 99.0
            body = None
            if capture_body and body_path:
                try:
                    with open(body_path, "rb") as f:
                        data = f.read(max_bytes + 1)
                    body = data if len(data) <= max_bytes else None
                except OSError:
                    body = None
            if code == 200:
                return (code, sec, body) if capture_body else (code, sec)
            return (code, 99.0, body) if capture_body else (code, 99.0)
        except Exception:
            return (None, 99.0, None) if capture_body else (None, 99.0)
        finally:
            if body_path:
                try:
                    os.remove(body_path)
                except OSError:
                    pass

    def curl_check_many(self, names, url, timeout, workers=12, base_port=24000,
                        capture_body=False, max_bytes=DEFAULT_MAX_BODY_BYTES):
        """P2-11：并发深度验证。

        做法：为每个候选节点在配置里加一个 mixed listener（独立本地端口，
        直接绑定到该节点），重启临时实例后，用线程池同时 curl 各自的端口。
        相比串行 `pin()` + 单端口，N 个节点的耗时从 O(N) 降到约 O(1)。
        capture_body=True 时每项返回 (code, sec, body)，否则 (code, sec)。
        """
        if not names:
            return {}
        fail = (None, 99.0, None) if capture_body else (None, 99.0)
        try:
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
                              secret=self.secret, insecure=self.insecure,
                              dns=self.dns)
            cfg["listeners"] = [
                {"name": f"dl-{i}", "type": "mixed", "port": ports[n],
                 "listen": "127.0.0.1", "proxy": n}
                for i, n in enumerate(names)
            ]
            write_yaml(self.config, cfg)
        except Exception as e:
            # 准备阶段失败时实例还在跑旧配置，直接串行验证即可
            log(f"  并发验证准备失败（{type(e).__name__}），退回串行验证")
            return {n: self.curl_check(n, url, timeout, capture_body=capture_body,
                                       max_bytes=max_bytes) for n in names}

        # 重启实例以加载 listeners
        self._stop()
        try:
            self.proc = popen_mihomo(["-d", self.dir])
        except Exception as e:
            log(f"  并发验证实例启动异常（{type(e).__name__}），恢复基础实例")
            if not self._restart_plain():
                return {n: fail for n in names}
            return {n: self.curl_check(n, url, timeout, capture_body=capture_body,
                                       max_bytes=max_bytes) for n in names}
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
                return {n: fail for n in names}
            return {n: self.curl_check(n, url, timeout, capture_body=capture_body,
                                       max_bytes=max_bytes) for n in names}

        log(f"  并发验证实例就绪：{len(ports)} 个独立端口（{min(ports.values())}-{max(ports.values())}）")

        results = {}

        def one(n):
            return n, self._curl_via(f"http://127.0.0.1:{ports[n]}", url, timeout,
                                     capture_body=capture_body, max_bytes=max_bytes)

        with ThreadPoolExecutor(max_workers=max(1, min(workers, len(names)))) as ex:
            for f in as_completed([ex.submit(one, n) for n in names]):
                n, result = f.result()
                results[n] = result
        return results


    def _stop(self):
        if self.proc:
            try:
                self.proc.terminate()
            except Exception:
                pass
            try:
                self.proc.wait(timeout=5)
            except Exception:
                try:
                    self.proc.kill()
                except Exception:
                    pass
            self.proc = None


def probe_nodes(temp, names, url, timeout, serial=False, capture_body=False,
                max_bytes=DEFAULT_MAX_BODY_BYTES):
    """对一组节点做一次 HTTP 探测，统一串行/并发返回形状。"""
    if not names:
        return {}
    if serial or len(names) == 1:
        return {n: temp.curl_check(n, url, timeout, capture_body=capture_body,
                                  max_bytes=max_bytes) for n in names}
    return temp.curl_check_many(names, url, timeout, capture_body=capture_body,
                                max_bytes=max_bytes)


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
        try:
            days = max(0, min(36500, int(days)))
        except (TypeError, ValueError, OverflowError):
            days = 0
        if days:
            cutoff = datetime.datetime.now() - datetime.timedelta(days=days)
    if samples_only:
        prefixes = ("samples-",)
    elif include_samples:
        prefixes = ("proxy-", "samples-")
    else:
        prefixes = ("proxy-",)
    try:
        files = os.listdir(HISTORY_DIR)
    except OSError as e:
        log(f"  历史目录不可读：{type(e).__name__}")
        return rows
    for fn in sorted(files):
        if not fn.endswith(".jsonl") or not fn.startswith(prefixes):
            continue
        try:
            with codecs.open(os.path.join(HISTORY_DIR, fn), "r", "utf-8") as f:
                for line in f:
                    try:
                        r = json.loads(line)
                    except Exception:
                        continue
                    if not isinstance(r, dict):
                        continue
                    if cutoff:
                        ts = _parse_iso_ts(r.get("ts"))
                        # 时间缺失/损坏时不猜测“它在窗口内”，窗口统计直接跳过。
                        if ts is None or ts < cutoff:
                            continue
                    rows.append(r)
        except (OSError, UnicodeError) as e:
            log(f"  跳过历史文件 {fn}：{type(e).__name__}")
    return rows


def source_health():
    """源健康度：统计每个订阅源的历史成功率、篡改率和突变标记。"""
    stat = defaultdict(lambda: [0, 0, 0])
    rows = read_history(30)
    for r in rows:
        if not isinstance(r, dict):
            continue
        p = r.get("proxy") if isinstance(r.get("proxy"), dict) else {}
        src = source_key(r.get("source_id") or p.get("_source_id") or
                         r.get("source") or p.get("_source") or "")
        if not src:
            continue
        stat[src][0] += 1
        if r.get("ok"):
            stat[src][1] += 1
        if r.get("content_tampered"):
            stat[src][2] += 1
    mutations = load_source_state().get("sources", {})
    out = {}
    for s, v in stat.items():
        seen, ok, tampered = v
        rate = ok / seen if seen else 0
        bad_rate = tampered / seen if seen else 0
        state = mutations.get(s)
        mutated = bool(state.get("mutated")) if isinstance(state, dict) else False
        reputation = max(0, round(100 * rate - 35 * bad_rate - (20 if mutated else 0), 1))
        out[s] = {"seen": seen, "ok": ok, "rate": round(rate, 2),
                  "tampered": tampered, "tampered_rate": round(bad_rate, 2),
                  "mutated": mutated, "reputation": reputation}
    return out


def report_sources(health):
    if not health:
        return
    log("源健康度（近 30 天）：")
    for s, h in sorted(health.items(), key=lambda x: -x[1]["reputation"]):
        log(f"  {source_label(s):24} {h['ok']:3}/{h['seen']:<3} {h['rate']*100:5.0f}% "
            f"篡改 {h['tampered']:<3} 信誉 {h['reputation']:5.1f}" +
            (" [突变]" if h["mutated"] else ""))


def load_source_state():
    try:
        with open(SOURCE_STATE_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception:
        return {"sources": {}}
    if not isinstance(data, dict):
        return {"sources": {}}
    sources = normalize_source_map(data.get("sources"))
    return dict(data, sources=sources)


def save_source_state(sources):
    normalized = normalize_source_map(sources)
    payload = {"updated_ts": datetime.datetime.now().isoformat(timespec="seconds"),
               "sources": normalized}
    tmp = f"{SOURCE_STATE_FILE}.{os.getpid()}.tmp"
    try:
        os.makedirs(os.path.dirname(SOURCE_STATE_FILE), exist_ok=True)
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(payload, f, ensure_ascii=False, indent=2)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, SOURCE_STATE_FILE)
        return True
    except Exception as e:
        # 不再静默：写失败会让突变基线停在旧值，至少留下可排查的痕迹
        log(f"  ⚠ 源状态写入失败：{type(e).__name__}")
        if os.path.exists(tmp):
            try:
                os.remove(tmp)
            except OSError:
                pass
        return False


def _source_current_meta(proxies):
    cur = {}
    endpoints = defaultdict(set)
    for p in proxies:
        if not isinstance(p, dict) or p.get("_inherited"):
            # 历史继承节点携带的是旧快照元数据，不能拿来和本轮源状态比较
            continue
        src = source_key(p.get("_source_id") or p.get("_source", ""))
        if not src:
            continue
        m = cur.setdefault(src, {"sha256": p.get("_source_hash", ""),
                                 "count": _safe_int(p.get("_source_count")),
                                 "protocols": p.get("_source_protocols") or {}})
        # 同一源可能混入历史继承节点；有当前抓取元数据时优先采用它
        if p.get("_source_hash"):
            m["sha256"] = p.get("_source_hash")
            m["count"] = _safe_int(p.get("_source_count"), m["count"])
            m["protocols"] = p.get("_source_protocols") or m["protocols"]
        endpoints[src].add(node_id(p))
    for src in cur:
        cur[src]["endpoints"] = sorted(endpoints.get(src, set()))
    return cur


def _share_change(prev, cur):
    """协议构成变化超过 25 个百分点且两边都有足够样本时返回说明。"""
    if not prev or not cur:
        return ""
    if not isinstance(prev, dict) or not isinstance(cur, dict):
        return ""
    pt, ct = sum(_safe_int(v) for v in prev.values()), sum(_safe_int(v) for v in cur.values())
    if pt < 10 or ct < 10:
        return ""
    for proto in set(prev) | set(cur):
        a = _safe_int(prev.get(proto)) / pt
        b = _safe_int(cur.get(proto)) / ct
        if abs(a - b) > 0.25:
            return f"协议 {proto} 占比 {a*100:.0f}%→{b*100:.0f}%"
    return ""


def _same_source_content(prev, meta):
    """判断本轮源内容是否与基线一致；用于保留上轮突变标记。"""
    prev_hash = prev.get("sha256") or ""
    cur_hash = meta.get("sha256") or ""
    if prev_hash and cur_hash:
        return prev_hash == cur_hash
    return (_safe_int(prev.get("count")) == _safe_int(meta.get("count"))
            and (prev.get("protocols") or {}) == (meta.get("protocols") or {}))


def detect_source_mutations(proxies, commit=True):
    """对比上次源状态，发现节点数暴增或协议构成骤变。

    返回 {source: reason}；命中的源会在节点上打 `_source_suspect`。
    首次运行没有基线，不会误报。commit=False 用于 --dry-run：只检测、不更新
    基线。本轮没有出现的源会保留旧基线，避免一次抓取失败把源状态清空。
    同一份被污染的内容会沿用上轮 mutated 标记，直到内容真正变化。
    """
    state = load_source_state().get("sources", {})
    cur = _source_current_meta(proxies)
    mutated = {}
    next_state = dict(state)
    for src, meta in cur.items():
        prev = state.get(src) or {}
        if not isinstance(prev, dict):
            prev = {}
        reason = ""
        prev_count = _safe_int(prev.get("count"))
        count = _safe_int(meta.get("count"))
        if prev_count and count >= max(20, prev_count * 2) and count > prev_count:
            reason = f"节点数 {prev_count}→{count}"
        if not reason:
            reason = _share_change(prev.get("protocols") or {}, meta.get("protocols") or {})
        if not reason:
            prev_eps = prev.get("endpoints")
            cur_eps = meta.get("endpoints")
            if (isinstance(prev_eps, list) and isinstance(cur_eps, list)
                    and all(isinstance(x, str) for x in prev_eps)
                    and all(isinstance(x, str) for x in cur_eps)
                    and prev_count == count and count >= 10):
                overlap = len(set(prev_eps) & set(cur_eps))
                smaller = min(len(set(prev_eps)), len(set(cur_eps)))
                # 同数量、同协议构成，但端点集合大半被换掉：不是正常轮换，
                # 更像整份订阅被替换。只有样本足够大时才判定，降低误报。
                if smaller and overlap < smaller * 0.5:
                    reason = f"端点集合大幅替换（重合 {overlap}/{smaller}）"
        if not reason and prev.get("mutated") and _same_source_content(prev, meta):
            reason = prev.get("reason") or "沿用上轮突变标记"
        if reason:
            mutated[src] = reason
        next_state[src] = dict(meta, mutated=bool(reason), reason=reason)
    if commit:
        save_source_state(next_state)
    for p in proxies:
        if not isinstance(p, dict) or p.get("_inherited"):
            continue
        sid = source_key(p.get("_source_id") or p.get("_source", ""))
        if sid in mutated:
            p["_source_suspect"] = mutated[sid]
    return mutated


def history_good(days=7, min_seen=2, top=40):
    """从历史里挑成功率高的节点（含完整定义），用于 --inherit。

    按稳定 _id 归并；旧记录没有 id 时回落到名字。
    """
    rows = read_history(days)
    stat = defaultdict(lambda: {"seen": 0, "ok": 0, "proxy": None, "last": ""})
    for r in rows:
        n = r.get("name")
        if not n or not isinstance(n, str):
            continue
        key = r.get("id") if isinstance(r.get("id"), str) and r.get("id") else n
        s = stat[key]
        s["seen"] += 1
        if r.get("ok"):
            s["ok"] += 1
        p = r.get("proxy")
        if isinstance(p, dict):
            s["proxy"] = p
        ts = r.get("ts")
        if isinstance(ts, str):
            s["last"] = max(s["last"], ts)
    good = [(k, s) for k, s in stat.items()
            if s["seen"] >= min_seen and s["proxy"] and s["ok"] / s["seen"] >= 0.5]
    good.sort(key=lambda x: (-x[1]["ok"] / x[1]["seen"], -x[1]["seen"]))
    # 历史里同一端点可能以不同名字/协议重复出现，拉回前先按端点去重
    return dedupe_endpoints([s["proxy"] for _, s in good[:top]]), len(stat)


# ---------------- 四层存储 ----------------
def save_snapshot(proxies, group, source_stats=None):
    """A 层：全量快照。每次抓取的所有节点都落盘，不只测过的。
    按天一个 JSONL，一行 = 当时完整的节点列表。"""
    os.makedirs(HISTORY_DIR, exist_ok=True)
    ts = datetime.datetime.now().isoformat(timespec="seconds")
    path = os.path.join(HISTORY_DIR, f"snapshot-{datetime.datetime.now():%Y%m%d}.jsonl")
    proxies = proxies if isinstance(proxies, list) else []
    rec = {
        "ts": ts, "group": group, "count": len(proxies),
        "source_stats": normalize_source_map(source_stats or {}),
        "nodes": [public_proxy(p) | {"_group": p.get("_group", "")}
                  for p in proxies if isinstance(p, dict)],
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
    rows = rows if isinstance(rows, list) else []
    delays = delays if isinstance(delays, dict) else {}
    all_names = list(all_names) if isinstance(all_names, (list, tuple, set)) else []
    by_name = {r.get("name"): r for r in rows
               if isinstance(r, dict) and isinstance(r.get("name"), str)}
    recorded = set()
    id_map = id_map if isinstance(id_map, dict) else {}

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
                "source_id": source_key(
                    r.get("source_id") or r.get("_source_id") or
                    r.get("_source") or r.get("source") or ""),
                "delay_ms": ms,
                "http_sec": r.get("http_sec") if r.get("ok") else None,
                "ok": bool(r.get("ok")) if r else None,
                "score": r.get("score"),
                "body_ok": r.get("body_ok"),
                "content_tampered": bool(r.get("content_tampered")),
                "exit_ip": r.get("exit_ip", ""),
                "exit_country": r.get("exit_country", ""),
                "country_match": r.get("country_match"),
                "exit_changed": bool(r.get("exit_changed")),
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
    try:
        files = os.listdir(HISTORY_DIR)
    except OSError as e:
        log(f"  历史目录不可读：{type(e).__name__}")
        return None
    for f in files:
        if not f.startswith("samples-") or not f.endswith(".jsonl"):
            continue
        try:
            with codecs.open(os.path.join(HISTORY_DIR, f), "r", "utf-8") as fh:
                lines = fh.readlines()
        except (OSError, UnicodeError) as e:
            log(f"  跳过采样文件 {f}：{type(e).__name__}")
            continue
        for line in lines:
            try:
                r = json.loads(line)
            except Exception:
                continue
            if not isinstance(r, dict):
                continue
            ts = r.get("ts")
            name = r.get("name")
            if not isinstance(ts, str) or not ts or not isinstance(name, str) or not name:
                continue
            day = ts[:10]
            if not day:
                continue
            d = daily[(day, name)]
            d["seen"] += 1
            if r.get("ok"):
                d["ok"] += 1
            try:
                if r.get("score") is not None:
                    d["score"].append(float(r["score"]))
                if r.get("delay_ms") is not None:
                    d["delay"].append(float(r["delay_ms"]))
            except (TypeError, ValueError):
                pass
            d["first"] = min(d["first"] or ts, ts)
            d["last"] = max(d["last"], ts)

    path = os.path.join(HISTORY_DIR, "latest_daily.csv")
    out_rows = []
    for (day, name), d in sorted(daily.items(), key=lambda x: (x[0][0], -x[1]["seen"])):
        avg_s = round(sum(d["score"]) / len(d["score"]), 1) if d["score"] else ""
        avg_d = round(sum(d["delay"]) / len(d["delay"])) if d["delay"] else ""
        out_rows.append([day, name, d["seen"], d["ok"],
                         round(d["ok"] / d["seen"] * 100) if d["seen"] else 0,
                         avg_s, avg_d, d["first"], d["last"]])
    write_csv_atomic(path,
                     ["日期", "节点", "采样次数", "成功次数", "成功率%", "平均分",
                      "平均延迟ms", "首次", "末次"],
                     out_rows)
    return path


def export_group_configs(passed, by_name, rules, out_dir=None, insecure=False,
                        dns=None):
    """D 层：分组订阅输出。每个协议组单独写一份 Clash 配置，
    方便客户端直接切换 SS 组 / Trojan 组。

    P1-3：订阅文件里 **secret 留空**，这些文件常被分享出去，
    不能带生产 API 凭据。
    insecure：必须与落地配置保持一致；用 --insecure 测通的节点，
    导出时也要保留 skip-cert-verify，否则自签节点在客户端会失效。
    """
    out_dir = out_dir or os.path.join(HISTORY_DIR, "subscriptions")
    os.makedirs(out_dir, exist_ok=True)
    passed = passed if isinstance(passed, (list, tuple)) else []
    by_name = by_name if isinstance(by_name, dict) else {}
    grouped = defaultdict(list)
    clean_passed = []
    for n in passed:
        if not isinstance(n, str):
            continue
        clean_passed.append(n)
        p = by_name.get(n)
        if not isinstance(p, dict):
            continue
        g = p.get("_group") or proto_group(p.get("type", ""))
        # _group 是内部字段，但不能让历史/外部输入把路径带出 out_dir；
        # 只接受已知协议组名，未知类型统一归到 other。
        if not isinstance(g, str):
            g = proto_group(p.get("type", ""))
        if g not in PROTO_GROUPS and g != "other":
            g = "other"
        grouped[g].append(p)

    written = []
    for g, ps in grouped.items():
        if not ps:
            continue
        path = os.path.join(out_dir, f"{g}.yaml")
        write_yaml(path, make_config(ps, 2081, 9091, rules, secret="",
                                     insecure=insecure, dns=dns))
        written.append((g, path, len(ps)))

    # 一份全量
    if clean_passed:
        allp = [by_name[n] for n in clean_passed if n in by_name]
        if allp:
            path = os.path.join(out_dir, "all.yaml")
            write_yaml(path, make_config(allp, 2081, 9091, rules, secret="",
                                         insecure=insecure, dns=dns))
            written.append(("all", path, len(allp)))

    # 本轮零通过的协议组要清掉旧 {g}.yaml，否则订阅目录会一直留着
    # 上一轮的文件，客户端仍能拉到已经失效的节点。只动已知组名，
    # 不碰用户在 out_dir 里放的其他文件。
    current = {g for g, _p, _n in written}
    for fn in os.listdir(out_dir):
        if not fn.endswith(".yaml"):
            continue
        g = fn[:-5]
        # proto_group() 对未知类型返回 "other"，所以它也是本程序生成的文件；
        # 零通过时同样要清掉，否则客户端会一直拉到过期订阅。
        if (g in PROTO_GROUPS or g == "other") and g not in current:
            try:
                os.remove(os.path.join(out_dir, fn))
                log(f"D层 清理零通过组旧订阅：{os.path.join(out_dir, fn)}")
            except OSError as e:
                log(f"D层 清理旧订阅失败 {fn}：{e}")
    return written


def node_longevity(days=30, top=30):
    """节点寿命分析：从全量快照统计每个节点出现了几天、连续存活情况。"""
    stat = defaultdict(lambda: {"days": set(), "first": "", "last": "", "proxy": None})
    if not os.path.isdir(HISTORY_DIR):
        log("历史为空")
        return
    try:
        days = max(0, min(36500, int(days)))
    except (TypeError, ValueError, OverflowError):
        days = 30
    cutoff = (datetime.datetime.now() - datetime.timedelta(days=days)).date().isoformat()
    try:
        files = os.listdir(HISTORY_DIR)
    except OSError as e:
        log(f"历史目录不可读：{type(e).__name__}")
        return
    for f in files:
        if not f.startswith("snapshot-") or not f.endswith(".jsonl"):
            continue
        try:
            with codecs.open(os.path.join(HISTORY_DIR, f), "r", "utf-8") as fh:
                lines = fh.readlines()
        except (OSError, UnicodeError) as e:
            log(f"  跳过快照 {f}：{type(e).__name__}")
            continue
        for line in lines:
            try:
                r = json.loads(line)
            except Exception:
                continue
            if not isinstance(r, dict):
                continue
            ts = r.get("ts")
            if not isinstance(ts, str) or not ts:
                continue
            day = ts[:10]
            if day < cutoff:
                continue
            nodes = r.get("nodes")
            if not isinstance(nodes, list):
                continue
            for p in nodes:
                if not isinstance(p, dict):
                    continue
                key = (p.get("server"), p.get("port"))
                if not all(key):
                    continue
                # 用稳定 _id 归并；快照里的节点没有 _id 时现算一个
                nid = p.get("_id") if isinstance(p.get("_id"), str) and p.get("_id") else node_id(p)
                s = stat[nid]
                s["days"].add(day)
                s["first"] = min(s["first"] or ts, ts)
                s["last"] = max(s["last"], ts)
                s["proxy"] = p
                s["name"] = p.get("name") or f"{key[0]}:{key[1]}"
    if not stat:
        log("没有全量快照数据（跑过几次完整抓取后才有）")
        return
    ranked = sorted(stat.items(), key=lambda x: (-len(x[1]["days"]), x[0]))
    log(f"节点寿命统计（近 {days} 天，来自全量快照）：")
    print(f"{'节点':38} {'出现天数':>6}  首次 / 末次")
    for nid, s in ranked[:top]:
        print(f"{sanitize_name(s.get('name') or nid):38} {len(s['days']):6}  "
              f"{s['first'][:10]} / {s['last'][:10]}")


def _parse_iso_ts(value):
    """解析历史里的 ISO 时间；坏值返回 None，调用方跳过而不是猜。"""
    try:
        dt = datetime.datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None
    if dt.tzinfo is not None:
        dt = dt.astimezone().replace(tzinfo=None)
    return dt


def _failure_span_hours(records):
    """末尾连续失败段的首尾时间差（小时），不是窗口长度。"""
    if len(records) < 2:
        return 0.0
    first = _parse_iso_ts(records[0][0])
    last = _parse_iso_ts(records[-1][0])
    if first is None or last is None:
        return None
    return (last - first).total_seconds() / 3600.0


def dead_node_names(window=7, min_fail=2, only_recent=True, protect=None,
                    min_span_hours=12):
    """找出末尾连续失败段足够长、且跨度足够的节点。

    P0-1 修正：**只读 samples-*.jsonl**。
    之前同时读 proxy- 和 samples-，同一轮深验失败会在两边各留一条 ok=False，
    一次运行就凑够 min_fail=2 判死。samples 每轮必写（未深验记 ok=None 被跳过），
    所以只读 samples 就能拿到真实的多轮序列。

    window: 看最近几天
    min_fail: 末尾连续失败至少几次才算死
    min_span_hours: 末尾连续失败段的首尾时间差至少要多久；防止 cron 高频运行时
                    两次短时抖动就被判死
    protect: 本次通过的节点，排除
    """
    protect = protect or set()
    try:
        window = max(1, min(36500, int(window)))
    except (TypeError, ValueError, OverflowError):
        window = 7
    cutoff = (datetime.datetime.now() - datetime.timedelta(days=window)).date().isoformat()
    # P0-3：优先按稳定 _id 归并；旧记录没有 id 时回落到名字
    hist = defaultdict(list)
    names_by_key = {}
    ids_by_key = {}
    for r in read_history(window, include_samples=True, samples_only=True):
        name = r.get("name")
        if not isinstance(name, str) or not name:
            continue
        ok = r.get("ok")
        if ok is None:          # 未深验的采样，无判定信息
            continue
        if isinstance(ok, str):
            ok = ok.strip().lower() in ("1", "true", "yes")
        elif not isinstance(ok, (bool, int)):
            continue
        else:
            ok = bool(ok)
        ts = r.get("ts")
        if not isinstance(ts, str) or not ts:
            continue
        if only_recent and ts[:10] < cutoff:
            continue
        key = r.get("id") if isinstance(r.get("id"), str) and r.get("id") else name
        hist[key].append((ts, bool(ok)))
        names_by_key[key] = name
        rid = r.get("id") if isinstance(r.get("id"), str) and r.get("id") else ""
        if rid and not ids_by_key.get(key):
            ids_by_key[key] = rid

    dead = {}
    try:
        need = max(1, int(min_fail))
    except (TypeError, ValueError, OverflowError):
        need = 2
    try:
        min_span = max(0.0, float(min_span_hours))
    except (TypeError, ValueError):
        min_span = 0.0
    for key, recs in hist.items():
        if key in protect or names_by_key.get(key) in protect:
            continue
        recs.sort(key=lambda x: x[0])
        # 从最新记录向前数到第一次成功为止；末尾连续失败段才是判死依据。
        # 不能只取最后 need 条：cron 每小时跑一次时，最后两条只差 1 小时，
        # 会把连续失败 72 小时的节点永远判活。
        streak = []
        for ts, ok in reversed(recs):
            if ok:
                break
            streak.append((ts, ok))
        streak.reverse()
        if len(streak) < need:
            continue
        span = _failure_span_hours(streak)
        if span is None or span < min_span:
            continue
        dead_key = ids_by_key.get(key) or names_by_key.get(key, key)
        dead[dead_key] = {
            "fail": len(streak), "ok": 0, "last": streak[-1][0], "checked": len(streak),
            "span_hours": round(span, 2), "id": ids_by_key.get(key, ""),
            "name": names_by_key.get(key, key),
        }
    return dead


def clean_dead_nodes(window=7, min_fail=2, apply=False, target="both", protect=None,
                     backup=True, min_span_hours=12):
    """自动清理不可用节点。
    target: prod=只清理生产配置 / subs=只清理分组订阅 / both=都清
    apply=False 时只报告不动手（默认只读）。
    protect: 本次通过的节点，排除（cron 落地后不误删）。
    min_span_hours: 末尾连续失败段首尾至少相隔多久才判死，默认 12 小时。"""
    dead = dead_node_names(window, min_fail, protect=protect,
                           min_span_hours=min_span_hours)
    if not dead:
        log(f"近 {window} 天没有末尾连续失败 ≥{min_fail} 次"
            f"且跨度 ≥{min_span_hours:g} 小时的节点")
        return 0

    log(f"近 {window} 天末尾连续失败 ≥{min_fail} 次的节点：{len(dead)} 个")
    for n, s in sorted(dead.items(), key=lambda x: -x[1]["fail"])[:15]:
        log(f"  {sanitize_name(s.get('name') or n):38} 失败 {s['fail']} / 成功 {s['ok']}  末次 {s['last'][:16]}")

    if not apply:
        log("只报告模式（加 --apply-clean 才真正移除）")
        return len(dead)

    # P0-2 保护：单个配置文件里一次最多移除 30% 的节点。
    # 小配置至少允许删 1 个，否则 3 个节点死 1 个（33%）永远清不掉；
    # 但 "至少 1 个" 只是上限，不是目标，且保留下面 "不能删光" 的保护。
    max_ratio = 0.30
    removed_total = 0

    def strip_cfg(path):
        nonlocal removed_total
        if not os.path.isfile(path):
            return
        try:
            with open(path, "r", encoding="utf-8") as f:
                cfg = yaml.safe_load(f)
        except Exception as e:
            log(f"  跳过 {os.path.basename(path)}：无法解析（{type(e).__name__}）")
            return
        if not isinstance(cfg, dict):
            log(f"  跳过 {os.path.basename(path)}：内容不是配置字典")
            return
        plist = cfg.get("proxies") or []
        if not isinstance(plist, list):
            log(f"  跳过 {os.path.basename(path)}：proxies 字段格式异常")
            return
        # 先验证原配置形状，避免下面遍历 proxy-groups 时把字符串等
        # 畸形字段当成列表处理，反而把配置改坏。
        if not validate_config_structure(cfg):
            log(f"  跳过 {os.path.basename(path)}：原配置结构校验失败")
            return

        # P0-3：优先按稳定 node_id 匹配；只有旧历史没有 id 时才回落到名字。
        # 名字可被新节点复用，绝不能把“旧 US 死了”误判成“新 US 也死了”。
        dead_names = {n for n, info in dead.items() if not info.get("id")}
        dead_ids = {info.get("id") for info in dead.values() if info.get("id")}

        def is_dead(p):
            if not isinstance(p, dict):
                return False
            return node_id(p) in dead_ids or p.get("name") in dead_names

        removed = [p for p in plist if is_dead(p)]
        before, after = len(plist), len(plist) - len(removed)
        if not removed:
            return
        max_remove = max(1, int(before * max_ratio))
        if len(removed) > max_remove:
            log(f"  ⚠ {os.path.basename(path)}：待清理 {len(removed)}/{before} "
                f"（{len(removed)/before*100:.0f}%）超过本次上限 {max_remove}，"
                f"疑似整体故障，**跳过清理**")
            return
        if after <= 0:
            # 全部节点都判死时宁可不写，避免生成一个没有节点、内核起不来的配置
            log(f"  ⚠ {os.path.basename(path)}：将移除全部节点，跳过写入")
            return

        removed_names = {p.get("name") for p in removed if p.get("name")}
        cfg["proxies"] = [p for p in plist if not is_dead(p)]
        # 同步各组引用：只剔除被删掉的节点名，AUTO/DIRECT/其它组名原样保留
        groups = []
        for g in cfg.get("proxy-groups") or []:
            if not isinstance(g, dict):
                continue
            g["proxies"] = [n for n in (g.get("proxies") or [])
                            if n not in removed_names]
            if g.get("proxies"):
                groups.append(g)
        if groups:
            cfg["proxy-groups"] = groups
        else:
            cfg.pop("proxy-groups", None)

        # 写前做结构校验；有内核时再用实际规则做 `mihomo -t` 校验。
        # 没有内核也不能直接写：至少拦住组/规则引用断裂这种低级错误。
        if not validate_config_structure(cfg):
            log(f"  ⚠ {os.path.basename(path)}：清理后配置结构校验失败，保持原样")
            return
        # 旧订阅/旧生产配置可能带有我们早期写入的来源字段；清理时顺手剥掉，
        # 避免 `--clean-dead` 把来源 URL 原样再写回去。
        cfg["proxies"] = [clean_proxy(p) for p in cfg.get("proxies") or []
                          if isinstance(p, dict)]
        if not validate_config_structure(cfg):
            log(f"  ⚠ {os.path.basename(path)}：清理后配置结构校验失败，保持原样")
            return
        if MIHOMO_MOCK or os.path.isfile(MIHOMO_EXE):
            # 校验配置时统一用生产配置目录做 -d：订阅目录通常没有
            # geoip.dat/geosite.dat，使用实际 split 规则校验会误判失败。
            if not validate_config_file(cfg, PROD_CONF_DIR,
                                        rules_override=cfg.get("rules"),
                                        quiet=True):
                log(f"  ⚠ {os.path.basename(path)}：清理后配置校验失败，保持原样")
                return
        write_yaml(path, cfg)
        log(f"  {os.path.basename(path)}: {before} → {after}（移除 {before-after}）")
        removed_total += before - after

    if target in ("prod", "both"):
        if backup:
            backup_prod()
        else:
            log("  跳过备份（本轮 apply 已备份过）")
        strip_cfg(PROD_CONFIG)

    if target in ("subs", "both"):
        backup_subscriptions()
        sd = os.path.join(HISTORY_DIR, "subscriptions")
        if os.path.isdir(sd):
            try:
                files = os.listdir(sd)
            except OSError as e:
                log(f"  订阅目录不可读：{type(e).__name__}")
                files = []
            for fn in files:
                if fn.endswith(".yaml"):
                    strip_cfg(os.path.join(sd, fn))

    log(f"共移除 {removed_total} 个死节点")
    if removed_total and port_up(prod_port()):
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
    try:
        days = int(days)
    except (TypeError, ValueError, OverflowError):
        log("  ⚠ 历史保留天数非法，已取消清理")
        return
    if days < 0:
        # 负数会让 cutoff 落到未来，把全部历史当成过期数据删光。
        log("  ⚠ 历史保留天数不能为负，已取消清理")
        return
    if days > 36500:
        log("  ⚠ 历史保留天数过大，已取消清理")
        return
    cutoff = (datetime.datetime.now() - datetime.timedelta(days=days)).date().isoformat()
    if not os.path.isdir(HISTORY_DIR):
        return
    old_files, old_line_idx = [], defaultdict(list)
    try:
        files = os.listdir(HISTORY_DIR)
    except OSError as e:
        log(f"  历史目录不可读：{type(e).__name__}")
        return
    for fn in files:
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
            try:
                month_last = _month_last_day(m.group(1))
            except Exception:
                # 文件名里的月份非法（如 proxy-000000.jsonl），按普通文件走行级清理
                month_last = ""
            if month_last and month_last < cutoff:
                old_files.append(fn)
                continue
            # 月份跨越截止日 → 走行级清理（下面统一处理）
        # 行级清理：记录行号，不用"按内容过滤"——内容相同的旧行会误删两次
        try:
            with codecs.open(path, "r", "utf-8") as f:
                for idx, line in enumerate(f):
                    try:
                        r = json.loads(line)
                        if not isinstance(r, dict):
                            continue
                        ts = _parse_iso_ts(r.get("ts"))
                    except Exception:
                        continue
                    # 坏时间戳不猜“一定过期”，避免把无法解析的行直接删掉。
                    if ts is not None and ts.date().isoformat() < cutoff:
                        old_line_idx[fn].append(idx)
        except (OSError, UnicodeError) as e:
            log(f"  跳过历史文件 {fn}：{type(e).__name__}")

    total_lines = sum(len(v) for v in old_line_idx.values())
    log(f"历史清理（>{days} 天）：整文件 {len(old_files)} 个，行级 {total_lines} 条")
    if not apply:
        log("只报告模式（加 --apply-prune 才真正清理）")
        return
    import gzip
    stamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S-%f")

    for fn in old_files:
        path = os.path.join(HISTORY_DIR, fn)
        if archive:
            try:
                with open(path, "rb") as src, \
                        gzip.open(f"{path}.{stamp}.gz", "wb") as dst:
                    shutil.copyfileobj(src, dst)
            except OSError as e:
                # 归档失败时保留原文件，别为了"清理"把数据直接弄丢
                log(f"  {fn} 归档失败，保留原文件：{type(e).__name__}")
                continue
        try:
            os.remove(path)
        except OSError as e:
            log(f"  {fn} 删除失败：{type(e).__name__}")
            continue
        log(f"  归档并删除 {fn}")

    for fn, idxs in old_line_idx.items():
        path = os.path.join(HISTORY_DIR, fn)
        try:
            with codecs.open(path, "r", "utf-8") as f:
                lines = f.readlines()
        except OSError as e:
            log(f"  {fn} 读取失败：{type(e).__name__}")
            continue
        idx_set = set(idxs)
        removed = [line for i, line in enumerate(lines) if i in idx_set]
        kept = [line for i, line in enumerate(lines) if i not in idx_set]
        if not removed:
            continue
        if archive:
            try:
                with gzip.open(f"{path}.{stamp}.old.gz", "wt", encoding="utf-8") as g:
                    g.writelines(removed)
            except OSError as e:
                log(f"  {fn} 行级归档失败，保留原文件：{type(e).__name__}")
                continue
        if not kept:
            try:
                os.remove(path)
            except OSError as e:
                log(f"  {fn} 删除空文件失败：{type(e).__name__}")
            log(f"  {fn}: 移除 {len(removed)} 条旧记录（文件已清空）")
            continue
        tmp = f"{path}.{os.getpid()}.tmp"
        try:
            with codecs.open(tmp, "w", "utf-8") as f:
                f.writelines(kept)
            os.replace(tmp, path)
        except OSError as e:
            log(f"  {fn} 重写失败：{type(e).__name__}")
            if os.path.exists(tmp):
                try:
                    os.remove(tmp)
                except OSError:
                    pass
            continue
        log(f"  {fn}: 移除 {len(removed)} 条旧记录")


def save_history(rows, by_name):
    os.makedirs(HISTORY_DIR, exist_ok=True)
    ts = datetime.datetime.now().isoformat(timespec="seconds")
    jsonl = os.path.join(HISTORY_DIR, f"proxy-{datetime.datetime.now():%Y%m}.jsonl")
    rows = rows if isinstance(rows, list) else []
    by_name = by_name if isinstance(by_name, dict) else {}
    with codecs.open(jsonl, "a", "utf-8") as f:
        for r in rows:
            if not isinstance(r, dict):
                continue
            name = r.get("name")
            if not isinstance(name, str) or not name:
                continue
            rec = {k: v for k, v in r.items() if not str(k).startswith("_")}
            rec["ts"] = ts
            rec.pop("proxy", None)
            p = by_name.get(name)
            if isinstance(p, dict):
                rec["proxy"] = public_proxy(p)  # 存完整定义，供 --inherit 复活；不落 URL
                rec["id"] = p.get("_id", "")   # 稳定身份，供 longevity/inherit 归并
            sid = source_key(rec.get("source_id") or rec.get("source", ""))
            if sid:
                rec["source_id"] = sid
            rec.pop("source", None)
            rec.pop("source_url", None)
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
    csvp = os.path.join(HISTORY_DIR, "latest.csv")
    out_rows = []
    for r in rows:
        if not isinstance(r, dict):
            continue
        name = r.get("name")
        if not isinstance(name, str) or not name:
            continue
        p = by_name.get(name) or {}
        if not isinstance(p, dict):
            p = {}
        out_rows.append([ts, name, p.get("_id", ""), country_of(name),
                         r.get("type", ""), r.get("server", ""),
                         r.get("port", ""), r.get("delay_ms", ""), r.get("http_code", ""),
                         r.get("http_sec", ""), r.get("score", ""), r.get("grade", ""),
                         "是" if r.get("ok") else "否"])
    write_csv_atomic(csvp,
                     ["时间", "节点", "ID", "国家", "类型", "服务器", "端口", "延迟ms",
                      "HTTP", "耗时s", "评分", "等级", "可用"],
                     out_rows)
    return jsonl, csvp


def country_of(name):
    """从节点名里提取国家/地区代码。

    免费订阅常用 🇺🇸 或 US 标注；未知时返回空字符串。返回两位代码而不是
    原始 emoji，便于和出口 IP 的 country_code 做比较。
    """
    text = str(name or "")
    flags = re.findall(r"[\U0001F1E6-\U0001F1FF]{2}", text)
    if flags:
        return "".join(chr(ord(ch) - 0x1F1E6 + ord("A")) for ch in flags[0])
    # 括号里的代码常小写，仍按不区分大小写处理
    m = re.search(r"[\[\(（【]\s*(JP|US|IT|HK|KR|SG|GB|DE|FR|NL|RU|CA|AU|TW)\s*[\]\)）】]",
                  text, re.I)
    if m:
        return m.group(1).upper()
    # 裸代码必须大写：否则 "Free for us" 会被当成 US、"it works" 会被当成 IT
    m = re.search(r"\b(JP|US|IT|HK|KR|SG|GB|DE|FR|NL|RU|CA|AU|TW)\b", text)
    return m.group(1).upper() if m else ""


def normalize_country(value):
    """把出口信息里的 country / country_code 归一为两位代码。"""
    s = str(value or "").strip()
    if not s:
        return ""
    if len(s) == 2 and s.isalpha():
        return s.upper()
    names = {
        "united states": "US", "hong kong": "HK", "united kingdom": "GB",
        "south korea": "KR", "korea": "KR", "singapore": "SG",
        "japan": "JP", "germany": "DE", "france": "FR",
        "netherlands": "NL", "russia": "RU", "canada": "CA",
        "australia": "AU", "taiwan": "TW", "italy": "IT",
    }
    return names.get(s.lower(), s.upper())


def parse_exit_info(body):
    """解析常见免费 IP 信息接口的 JSON；失败返回空字典。"""
    if not body:
        return {}
    try:
        text = body.decode("utf-8", "ignore") if isinstance(body, (bytes, bytearray)) else str(body)
        data = json.loads(text)
    except Exception:
        return {}
    if not isinstance(data, dict):
        return {}
    ip = data.get("ip") or data.get("query") or data.get("IPv4") or ""
    country = normalize_country(data.get("country_code") or data.get("countryCode") or
                                data.get("country"))
    asn = data.get("asn") or data.get("asn_number") or ""
    org = data.get("org") or data.get("asn_org") or data.get("isp") or ""
    return {
        "ip": str(ip),
        "country": country,
        "asn": str(asn),
        "org": str(org),
        "city": str(data.get("city") or ""),
        "region": str(data.get("region") or ""),
    }


def previous_exit_ips(days=30):
    """最近历史里每个稳定节点最后一次记录的出口 IP。"""
    latest = {}
    for r in read_history(days):
        ip = r.get("exit_ip")
        if not ip:
            continue
        key = r.get("id") if isinstance(r.get("id"), str) and r.get("id") else r.get("name")
        if not isinstance(key, str) or not key:
            continue
        ts = r.get("ts")
        if not isinstance(ts, str):
            continue
        if key not in latest or ts > latest[key][0]:
            latest[key] = (ts, str(ip))
    return {k: v[1] for k, v in latest.items()}


def sha256_bytes(body):
    return hashlib.sha256(body or b"").hexdigest()


def dns_from_args(mode="off", servers=None):
    """把 CLI 的 dns 选项转成配置段；off 返回 None。"""
    if mode == "off":
        return None
    names = [s.strip() for s in str(servers or "").split(",") if s.strip()]
    return default_dns_config(names or None)


def content_expectation(url, sha256_value=None, text=None):
    """构造内容校验规格。url 为空返回 None；否则必须提供哈希或文本。"""
    if not url:
        return None
    if text is not None and text != "":
        digest = sha256_bytes(text.encode("utf-8"))
    elif sha256_value:
        digest = str(sha256_value).strip().lower()
    else:
        raise ValueError("内容校验需要 --verify-content-sha256 或 --verify-content-text")
    if not re.fullmatch(r"[0-9a-f]{64}", digest):
        raise ValueError("--verify-content-sha256 必须是 64 位十六进制")
    return {"url": url, "sha256": digest}


def content_matches(body, expected_sha256):
    """固定内容比对；body 为空或哈希不匹配都返回 False。"""
    if body is None or not expected_sha256:
        return False
    if isinstance(body, str):
        body = body.encode("utf-8")
    return secrets.compare_digest(sha256_bytes(body), expected_sha256.lower())


def quality_score(delay_ms, http_sec, trust=1.0):
    """0-100 综合评分。

      延迟 60%（<300ms 满分，>3000ms 归零）
      实速 40%（<2s 满分，>12s 归零；未深验时给中性分）
      trust 是可信度系数（0-1），来自出口 IP 变化/声称地区不符等信号；
      1.0 表示未知或完全可信，不改变原有评分。

    稳定性请用 samples-*.jsonl 单独分析；本函数只做单轮质量分。
    """
    def band(v, full, zero):
        if v is None:
            return 0.6
        return max(0.0, min(1.0, (zero - v) / (zero - full)))

    try:
        trust = max(0.0, min(1.0, float(trust)))
    except (TypeError, ValueError):
        trust = 1.0
    delay_s = band(delay_ms, 300, 3000)
    speed_s = band(http_sec, 2.0, 12.0)
    score = 100 * (0.60 * delay_s + 0.40 * speed_s)
    return round(score * trust, 1)


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
        n = r.get("name")
        if not isinstance(n, str) or not n:
            n = "?"
        stat[n][0] += 1
        if r.get("ok"):
            stat[n][1] += 1
        t = r.get("ts")
        if not isinstance(t, str):
            t = ""
        stat[n][2] = min(stat[n][2] or t, t)
        stat[n][3] = max(stat[n][3], t)
    log(f"历史共 {len(rows)} 条记录，{len(stat)} 个节点")
    print(f"{'节点':38} {'出现':>4} {'成功':>4} {'成功率':>7}  首次 / 末次")
    for n, (seen, ok, first, last) in sorted(stat.items(), key=lambda x: -x[1][0])[:30]:
        print(f"{sanitize_name(n):38} {seen:4} {ok:4} {ok/seen*100:6.0f}%  {first[:10]} / {last[:10]}")


# ---------------- 生产配置管理 ----------------
def read_prod():
    if not os.path.isfile(PROD_CONFIG):
        return None
    try:
        with open(PROD_CONFIG, "r", encoding="utf-8") as f:
            cfg = yaml.safe_load(f)
    except Exception as e:
        # 只记录异常类型：PyYAML 的错误文本可能回显带 secret 的配置行。
        log(f"  生产配置解析失败：{type(e).__name__}")
        return None
    return cfg if isinstance(cfg, dict) else None


def backup_prod():
    """备份生产配置。即使配置本身解析失败也照原样复制，保证可回滚。"""
    if not os.path.isfile(PROD_CONFIG):
        return None
    os.makedirs(BACKUP_DIR, exist_ok=True)
    ts = datetime.datetime.now().strftime("%Y%m%d-%H%M%S-%f")
    dst = os.path.join(BACKUP_DIR, f"config-{ts}.yaml")
    copy_file_atomic(PROD_CONFIG, dst)
    # 只保留最近 10 份 config-*.yaml（pre-rollback-* 不参与轮转）
    bks = sorted(f for f in os.listdir(BACKUP_DIR)
                 if f.startswith("config-") and f.endswith(".yaml"))
    for old in bks[:-10]:
        try:
            os.remove(os.path.join(BACKUP_DIR, old))
        except Exception:
            pass
    log(f"  生产配置已备份：{dst}")
    return dst


def backup_subscriptions():
    """D 层清理前把 subscriptions/*.yaml 整体备份，避免批量删坏无法恢复。"""
    sd = os.path.join(HISTORY_DIR, "subscriptions")
    if not os.path.isdir(sd):
        return None
    try:
        files = [f for f in os.listdir(sd) if f.endswith(".yaml")]
    except OSError as e:
        log(f"  订阅目录不可读，跳过备份：{type(e).__name__}")
        return None
    if not files:
        return None
    ts = datetime.datetime.now().strftime("%Y%m%d-%H%M%S-%f")
    dst_dir = os.path.join(BACKUP_DIR, f"subscriptions-{ts}")
    os.makedirs(dst_dir, exist_ok=True)
    for fn in files:
        copy_file_atomic(os.path.join(sd, fn), os.path.join(dst_dir, fn))
    log(f"  D层订阅已备份：{dst_dir}（{len(files)} 个文件）")
    return dst_dir


def _unique_path(path):
    if not os.path.exists(path):
        return path
    base, ext = os.path.splitext(path)
    for i in range(1, 1000):
        cand = f"{base}-{i}{ext}"
        if not os.path.exists(cand):
            return cand
    return f"{base}-{int(time.time())}{ext}"


def rollback():
    if not os.path.isdir(BACKUP_DIR):
        fail("没有备份目录")
    bks = sorted(f for f in os.listdir(BACKUP_DIR)
                 if f.startswith("config-") and f.endswith(".yaml"))
    if not bks:
        fail("没有可回滚的备份")
    src = os.path.join(BACKUP_DIR, bks[-1])
    # 先把"当前配置"留一份，回滚本身也可撤销
    if os.path.isfile(PROD_CONFIG):
        ts = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
        dst = _unique_path(os.path.join(BACKUP_DIR, f"pre-rollback-{ts}.yaml"))
        try:
            copy_file_atomic(PROD_CONFIG, dst)
            log(f"  当前配置已另存：{dst}")
        except OSError as e:
            log(f"  ⚠ 当前配置另存失败（继续回滚）：{type(e).__name__}")
    try:
        copy_file_atomic(src, PROD_CONFIG)
    except OSError as e:
        fail(f"回滚复制失败：{type(e).__name__}: {e}")
    log(f"已从 {src} 还原生产配置")
    log("  如生产 mihomo 正在运行，需重启它才生效")


def geofiles_present(conf_dir):
    """检查 geoip.dat / geosite.dat 是否齐备。

    split 规则用到 GEOSITE/GEOIP；缺文件时 mihomo 会尝试联网下载，
    国内通常超时 —— 所以校验阶段必须避开这类规则。
    """
    try:
        names = {n.lower() for n in os.listdir(conf_dir)}
    except OSError:
        return False
    has_geoip = any(n.startswith("geoip") and n.endswith(".dat") for n in names)
    has_geosite = any(n.startswith("geosite") and n.endswith(".dat") for n in names)
    # mihomo 也支持 country.mmdb 作为 GEOIP 数据源；文件名大小写在
    # Windows 上不敏感、Linux 上敏感，统一转小写判断。
    has_geoip = has_geoip or "country.mmdb" in names
    return has_geoip and has_geosite


def validate_config_structure(cfg):
    """不依赖内核的轻量结构校验，作为无 mihomo 环境下的最后一道兜底。

    只检查 YAML 形状、节点名唯一性、组/规则引用是否存在；真实内核校验
    仍由 validate_config_file 负责（有内核时才执行）。
    """
    if not isinstance(cfg, dict):
        return False
    proxies = cfg.get("proxies")
    if not isinstance(proxies, list):
        return False
    names = []
    for p in proxies:
        name = p.get("name") if isinstance(p, dict) else None
        if not isinstance(name, str) or not name.strip():
            return False
        if not isinstance(p.get("type"), str) or not p["type"].strip():
            return False
        if name.upper() in RESERVED_NODE_NAMES:
            return False
        names.append(name)
    if len(names) != len(set(names)):
        return False
    groups = cfg.get("proxy-groups") or []
    if not isinstance(groups, list):
        return False
    group_names = set()
    group_reserved = {"DIRECT", "REJECT", "REJECT-DROP", "PASS",
                      "COMPATIBLE", "GLOBAL"}
    for g in groups:
        name = g.get("name") if isinstance(g, dict) else None
        if not isinstance(name, str) or not name.strip():
            return False
        if name.upper() in group_reserved:
            return False
        if not isinstance(g.get("type"), str) or not g["type"].strip():
            return False
        if name in group_names:
            return False
        group_names.add(name)
    if group_names & set(names):
        return False
    known = set(names) | group_names | {"DIRECT", "REJECT", "REJECT-DROP", "PASS"}
    for g in groups:
        refs = g.get("proxies") or []
        if not isinstance(refs, list):
            return False
        for r in refs:
            if not isinstance(r, str) or r not in known:
                return False
    rules = cfg.get("rules")
    if not isinstance(rules, list) or not all(isinstance(r, str) for r in rules):
        return False
    if rules:
        if not isinstance(rules[-1], str) or not rules[-1].startswith("MATCH,"):
            return False
        target = rules[-1].rsplit(",", 1)[-1].strip()
        if target not in known:
            return False
    return True


def validate_config_file(cfg, conf_dir, rules_override=None, quiet=False):
    """用 `mihomo -t` 校验配置能否加载。

    rules_override：校验时替换 rules。默认用 ["MATCH,PROXY"]，
    这样校验只关心节点本身是否合法，不依赖 geo 数据文件。
    quiet：批量/二分探测时关闭逐次失败日志，避免刷屏。
    """
    os.makedirs(conf_dir, exist_ok=True)
    tmp = os.path.join(conf_dir, f".validate-{os.getpid()}.yaml")
    try:
        probe = dict(cfg)
        probe["rules"] = rules_override or ["MATCH,PROXY"]
        # 校验文件会留在配置目录（异常退出时可能没删掉），不要把真实 API
        # secret 写进去；`mihomo -t` 校验加载能力，不依赖 secret 的值。
        probe["secret"] = "probe"
        if isinstance(probe.get("proxies"), list):
            probe["proxies"] = [clean_proxy(p) if isinstance(p, dict) else p
                                 for p in probe["proxies"]]
        with open(tmp, "w", encoding="utf-8", newline="\n") as f:
            yaml.safe_dump(probe, f, allow_unicode=True, sort_keys=False)
        r = subprocess.run(
            mihomo_command(["-t", "-f", tmp, "-d", conf_dir]),
            capture_output=True, text=True, timeout=60)
        ok = r.returncode == 0
        if not ok and not quiet:
            msg = (r.stdout or "") + (r.stderr or "")
            for line in msg.splitlines():
                low = line.lower()
                if "error" in low or "failed" in low:
                    log(f"  配置校验失败：{line.strip()[:160]}")
                    break
            else:
                log("  配置校验失败（无详细错误输出）")
        return ok
    except Exception as e:
        if not quiet:
            log(f"  配置校验异常：{type(e).__name__}: {e}")
        return False
    finally:
        if os.path.exists(tmp):
            try:
                os.remove(tmp)
            except OSError:
                pass


def drop_invalid_proxies(proxies, port, api_port, rules, insecure=False,
                          validate=None, dns=None):
    """预检整份测速配置，整体加载失败时二分定位并剔除坏节点。

    免费池里常有缺 uuid、cipher 为空、reality 缺公钥之类的节点，只要有一个，
    mihomo 启动时就会拒绝加载**整份**配置，本轮直接报废。以前只能靠人工排查；
    现在先 `mihomo -t` 预检，失败时二分（k 个坏节点约 k*log(n) 次校验），
    把坏节点单独摘掉，剩下的照常测速。

    validate: 可注入的校验函数（测试用），默认调用 validate_config_file。
    返回 (good, dropped)。
    """
    if not proxies:
        return [], []
    if validate is None:
        def validate(cfg_obj):
            return validate_config_file(cfg_obj, TMP_DIR,
                                        rules_override=["MATCH,PROXY"], quiet=True)

    def ok(lst):
        return validate(make_config(lst, port, api_port, rules,
                                    secret="probe", insecure=insecure, dns=dns))

    if ok(proxies):
        return list(proxies), []

    dropped = []

    def keep(lst):
        if not lst:
            return []
        if ok(lst):
            return list(lst)
        if len(lst) == 1:
            dropped.append(lst[0])
            return []
        mid = len(lst) // 2
        return keep(lst[:mid]) + keep(lst[mid:])

    return keep(list(proxies)), dropped


def restore_backup(backup_path):
    """把生产配置恢复到指定备份；没有备份时移除刚写入的新配置。"""
    if backup_path:
        if not os.path.isfile(backup_path):
            log(f"  ⚠ 备份文件已不存在，拒绝删除当前生产配置：{backup_path}")
            return False
        try:
            copy_file_atomic(backup_path, PROD_CONFIG)
        except OSError as e:
            log(f"  ⚠ 回滚复制失败：{type(e).__name__}")
            return False
        log(f"  已回滚生产配置：{backup_path}")
        return True
    try:
        if os.path.isfile(PROD_CONFIG):
            os.remove(PROD_CONFIG)
        log("  没有旧备份，已移除刚写入的生产配置")
        return True
    except OSError as e:
        log(f"  ⚠ 回滚失败：{type(e).__name__}")
        return False


def verify_selected_outbound(proxies, rules, insecure=False, url=None,
                             timeout=10, max_nodes=3, dns=None):
    """用新配置起一个临时实例，真实出网验证。

    这不是生产端口本身，而是与生产配置同源的临时实例：能验证节点、规则和
    出网链路，又不用先杀掉用户正在运行的 mihomo。生产端口是否重载由
    运维步骤负责，报告里会明确这个边界。
    """
    if not proxies:
        return False, "没有可验证节点"
    mix_port = free_port(2181)
    api_port = free_port(9181)
    if not mix_port or not api_port:
        return False, "找不到空闲验证端口"
    try:
        with TempMihomo(TMP_DIR, mix_port, api_port, proxies, rules,
                        insecure=insecure, dns=dns,
                        geo_dir=PROD_CONF_DIR) as t:
            for p in proxies[:max(1, max_nodes)]:
                code, _sec = t.curl_check(p["name"], url or DEFAULT_TEST_URL,
                                          timeout)
                if code == 200:
                    return True, p.get("name", "")
        return False, "前几个节点均未通过出网探测"
    except Exception as e:
        return False, f"{type(e).__name__}: {e}"


def apply_prod(proxies, rules, insecure=False, secret=None, health_check=False,
               health_url=None, health_timeout=10, dns=None):
    if system_proxy_on():
        log("  ⚠ 系统代理当前为开启状态；重启生产 mihomo 会造成短暂断网")
    sec, origin, generated = resolve_prod_secret(secret)
    existing = read_prod() or {}
    port, api_port = prod_port(existing), prod_api(existing)
    cfg = make_config(proxies, port, api_port, rules, secret=sec, insecure=insecure,
                      dns=dns)

    # P1-7：先校验再落地，坏节点不该把生产配置写成起不来的样子
    # 校验使用 cfg_obj 里的实际规则；缺 geo 时调用方已降级为无 geo 规则。
    log("  校验生产配置…")
    geo_ok = geofiles_present(PROD_CONF_DIR)
    if not geo_ok and rules != ["MATCH,PROXY"]:
        log("  ⚠ 生产目录缺少 geoip.dat / geosite.dat；当前使用无 geo 的降级 split 规则")
        log("     如需完整分流，请从 MetaCubeX/meta-rules-dat 下载后放到配置目录")

    def _val(cfg_obj):
        # 校验**实际要落地的规则**，不能再用 MATCH,PROXY 顶包：
        # 否则 GEOSITE/GEOIP 规则写错也能通过校验，生产配置起不来。
        return validate_config_file(cfg_obj, PROD_CONF_DIR,
                                    cfg_obj.get("rules"))

    # 二分剔除坏节点，避免 30 节点 × 逐次 `mihomo -t` 的线性开销
    good, dropped = drop_invalid_proxies(
        proxies, port, api_port, rules, insecure=insecure, validate=_val,
        dns=dns)
    for p in dropped[:10]:
        log(f"    剔除无效节点：{p.get('name')}")
    if len(dropped) > 10:
        log(f"    …另有 {len(dropped) - 10} 个无效节点")
    if not good:
        fail("所有节点都无法通过配置校验，未写入生产配置")
    if dropped:
        log(f"  剔除后保留 {len(good)} 个节点")
    proxies = good
    cfg = make_config(proxies, port, api_port, rules,
                      secret=sec, insecure=insecure, dns=dns)

    backup = backup_prod()
    write_yaml(PROD_CONFIG, cfg)
    log(f"  生产配置已写入（{len(proxies)} 节点，规则 {rules}）")
    log(f"  API secret 来源：{origin}")
    if generated:
        # 只在终端显示，不写进 harvest.log —— 日志常被贴出来排错
        log(f"  ★ 新 secret（请立即保存，面板/客户端需要它）：{sec}", also_file=False)
    if not insecure:
        log("  已剥离 skip-cert-verify（需要时加 --insecure）")
    if health_check:
        log("  落地后健康检查：用同源临时实例做真实出网探测…")
        ok, detail = verify_selected_outbound(
            proxies, rules, insecure=insecure, url=health_url,
            timeout=health_timeout, dns=dns)
        if not ok:
            log(f"  ❌ 健康检查失败（{detail}），开始回滚")
            restore_backup(backup)
            return False
        log(f"  健康检查通过：{detail}")
    if port_up(prod_port(cfg)):
        log("  生产 mihomo 正在运行；请自行重启它使新配置生效")
        log(f"    结束进程 mihomo.exe 后执行：\"{MIHOMO_EXE}\" -d \"{PROD_CONF_DIR}\"")
    return True


def prod_port(cfg=None):
    """生产实际使用的 mixed-port；读不到配置时才退回 PROD_PORT。"""
    if cfg is None:
        cfg = read_prod() or {}
    value = cfg.get("mixed-port") if isinstance(cfg, dict) else None
    try:
        port = int(value)
    except (TypeError, ValueError, OverflowError):
        return PROD_PORT
    return port if 0 < port <= 65535 else PROD_PORT


def prod_api(cfg=None):
    """生产实际使用的 API 端口；优先沿用现有 external-controller。"""
    if cfg is None:
        cfg = read_prod() or {}
    controller = cfg.get("external-controller") if isinstance(cfg, dict) else None
    if isinstance(controller, str) and ":" in controller:
        port = _as_port(controller.rpartition(":")[2])
        if port:
            return port
    return PROD_API


def show_status():
    cfg = read_prod()
    if cfg is None:
        log("生产配置不存在")
        return
    port = prod_port(cfg)
    proxies = cfg.get("proxies")
    proxy_count = len(proxies) if isinstance(proxies, list) else 0
    log(f"生产配置：{PROD_CONFIG}")
    log(f"  节点数    {proxy_count}")
    log(f"  端口      {cfg.get('mixed-port')} / API {cfg.get('external-controller')}")
    log(f"  规则      {cfg.get('rules')}")
    log(f"  生产 mihomo {'运行中' if port_up(port) else '未运行'}")
    log(f"  系统代理  {'开启' if system_proxy_on() else '关闭'}")
    try:
        bks = os.listdir(BACKUP_DIR) if os.path.isdir(BACKUP_DIR) else []
    except OSError:
        bks = []
    log(f"  备份数    {len(bks)}")


# ---------------- 主流程 ----------------
def _validate_cli_args(args):
    """校验只读分支也会用到的数字参数，避免负值/零值静默改变语义。"""
    checks = [
        ("--limit", args.limit, 1),
        ("--keep", args.keep, 0),
        ("--per-group", args.per_group, 0),
        ("--max-nodes", args.max_nodes, 0),
        ("--timeout", args.timeout, 1),
        ("--delay-timeout", args.delay_timeout, 100),
        ("--verify-content-max-bytes", args.verify_content_max_bytes, 1),
        ("--prune-days", args.prune_days, 0),
        ("--dead-window", args.dead_window, 1),
        ("--dead-fails", args.dead_fails, 1),
        ("--inherit-days", args.inherit_days, 1),
        ("--min-pass", args.min_pass, 0),
        ("--good-enough", args.good_enough, 0),
    ]
    for name, value, minimum in checks:
        if value < minimum:
            fail(f"{name} 必须 ≥{minimum}", 2)
    for name, value in (("--prune-days", args.prune_days),
                        ("--dead-window", args.dead_window),
                        ("--inherit-days", args.inherit_days)):
        if value > 36500:
            fail(f"{name} 不能超过 36500（避免日期计算溢出）", 2)
    if not math.isfinite(args.dead_min_span) or args.dead_min_span < 0:
        fail("--dead-min-span 必须是有限非负数", 2)


def main():
    ap = argparse.ArgumentParser(description="免费代理一键抓取/测速/筛选/记录/落地（完善版）")
    ap.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    ap.add_argument("--limit", type=int, default=200, help="最多抓取节点数（默认 200）")
    ap.add_argument("--max-nodes", type=int, default=30,
                    help="落地到生产配置的节点数上限（默认 30；0=不限）")
    ap.add_argument("--group", default="all",
                    choices=list(PROTO_GROUPS.keys()),
                    help="只测某个协议组；all=全测（默认）。组：" + ", ".join(PROTO_GROUPS.keys()))
    ap.add_argument("--list-groups", action="store_true", help="列出协议分组后退出")
    ap.add_argument("--per-group", type=int, default=0,
                    help=">0 时每个组各自挑前 N 个深验并独立排名")
    ap.add_argument("--keep", type=int, default=None,
                    help="深度验证的节点数；0=不深验（默认；cron 模式默认 15）")
    ap.add_argument("--timeout", type=int, default=10, help="深度验证单次超时秒数")
    ap.add_argument("--delay-timeout", type=int, default=5000, help="延迟测试超时毫秒")
    ap.add_argument("--test-url", default=DEFAULT_TEST_URL, help="深度验证网址")
    ap.add_argument("--delay-url", default=DEFAULT_DELAY_URL, help="延迟测试网址（能返回延迟即连通）")
    ap.add_argument("--verify-content-url", default=None,
                    help="内容完整性探测地址；默认关闭，配合 sha256/text 使用")
    ap.add_argument("--verify-content-sha256", default=None,
                    help="期望响应体的 SHA256（64 位十六进制）")
    ap.add_argument("--verify-content-text", default=None,
                    help="期望响应体的固定文本；与 sha256 二选一")
    ap.add_argument("--verify-content-max-bytes", type=int, default=DEFAULT_MAX_BODY_BYTES,
                    help="内容探测最多读取字节数（默认 4096）")
    ap.add_argument("--verify-https-url", default=None,
                    help="额外做一次 HTTPS 内容探测，使用同一个期望哈希；默认关闭")
    ap.add_argument("--exit-info", action="store_true",
                    help="深验时记录出口 IP/ASN/地理信息；默认关闭")
    ap.add_argument("--exit-info-url", default=DEFAULT_EXIT_INFO_URL,
                    help="出口信息接口，需返回含 ip/country_code/asn 的 JSON")
    ap.add_argument("--no-health-check", action="store_true",
                    help="落地后不做真实出网健康检查（默认会做，失败自动回滚）")
    ap.add_argument("--health-url", default="https://www.cloudflare.com/cdn-cgi/trace",
                    help="落地后健康检查使用的出网地址")
    ap.add_argument("--dns-mode", default="off", choices=["off", "explicit"],
                    help="DNS 配置：off=沿用现状；explicit=写显式 dns 段（默认本地解析）")
    ap.add_argument("--dns-servers", default=None,
                    help="显式 DNS 的 nameserver 列表，逗号分隔；默认 Cloudflare/Google DoH")
    ap.add_argument("--min-pass", type=int, default=1, help="至少要通过几个才算成功")
    ap.add_argument("--good-enough", type=int, default=0,
                    help="评分到够 N 个就提前停止后续评分；0=全评"
                         "（并发网络探测仍会先完成）")
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
    ap.add_argument("--dead-min-span", type=float, default=12.0,
                    help="末尾连续失败段首尾至少相隔多少小时才算死（默认 12，必须有限非负）")
    ap.add_argument("--clean-target", default="both", choices=["prod", "subs", "both"],
                    help="清理目标：生产配置/分组订阅/两者")
    ap.add_argument("--prune", action="store_true", help="检查过期历史记录（默认只报告）")
    ap.add_argument("--apply-prune", action="store_true", help="配合 --prune：真正清理并归档")
    ap.add_argument("--prune-days", type=int, default=90, help="历史保留天数")
    ap.add_argument("--no-archive", action="store_true", help="清理历史时不归档，直接删除")
    ap.add_argument("--rollback", action="store_true", help="从最近备份还原生产配置")
    args = ap.parse_args()

    # P0-3：cron 默认带深度验证；用 None 区分“没写 --keep”和“显式 --keep 0”，
    # 这样 --cron --keep 0 能真正关闭深验。
    if args.keep is None:
        args.keep = 15 if args.cron else 0
        if args.cron:
            log("cron 模式：深度验证默认 15 个（可用 --keep 0 关闭，或 --keep N 覆盖）")

    # 只读分支（--list-groups/--status 等）也会经过这里，先拦住非法数字
    _validate_cli_args(args)

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
    if args.apply_clean and not args.clean_dead:
        fail("--apply-clean 需要配合 --clean-dead 使用", 2)
    if args.apply_prune and not args.prune:
        fail("--apply-prune 需要配合 --prune 使用", 2)

    # dry-run 是全局只读开关：清理/修剪/回滚这些“分支提前 return”的写操作
    # 也必须止步于此，不能绕开 _run_main 里的 dry-run 保护。
    dry_run = bool(args.dry_run)
    if args.clean_dead:
        do_clean = bool(args.apply_clean and not dry_run)
        _lock = None
        if do_clean:
            _lock = acquire_lock()
            if _lock is None:
                fail("已有另一个实例在运行", 3)
        try:
            clean_dead_nodes(window=args.dead_window, min_fail=args.dead_fails,
                             apply=do_clean,
                             target=args.clean_target,
                             min_span_hours=args.dead_min_span)
        finally:
            if _lock is not None:
                release_lock(_lock)
        if dry_run:
            log("dry-run：清理只报告，不修改生产配置/订阅")
        return
    if args.prune:
        do_prune = bool(args.apply_prune and not dry_run)
        _lock = None
        if do_prune:
            _lock = acquire_lock()
            if _lock is None:
                fail("已有另一个实例在运行", 3)
        try:
            prune_history(days=args.prune_days, archive=not args.no_archive,
                          apply=do_prune)
        finally:
            if _lock is not None:
                release_lock(_lock)
        if dry_run:
            log("dry-run：历史清理只报告，不删除/归档")
        return
    if args.rollback:
        if dry_run:
            log("dry-run：跳过回滚，不写生产配置")
            return
        _lock = acquire_lock()
        if _lock is None:
            fail("已有另一个实例在运行", 3)
        try:
            rollback()
        finally:
            release_lock(_lock)
        return

    # 写路径统一加锁：抓取/落地、sources-only，以及 --apply-clean/--apply-prune/
    # --rollback。旧实现里这三类写操作在加锁前就 return，两个清理进程可能
    # 同时改生产配置。
    _lock = acquire_lock()
    if _lock is None:
        fail("已有另一个实例在运行", 3)

    try:
        if not args.sources_only and not MIHOMO_MOCK and not os.path.isfile(MIHOMO_EXE):
            fail(f"找不到 mihomo：{MIHOMO_EXE}", 2)
        if (args.verify_content_url or args.verify_https_url):
            if bool(args.verify_content_sha256) == bool(args.verify_content_text):
                fail("内容校验需要且只能提供 --verify-content-sha256 或 --verify-content-text 之一", 2)
            try:
                content_expectation(args.verify_content_url or args.verify_https_url,
                                    args.verify_content_sha256, args.verify_content_text)
            except ValueError as e:
                fail(str(e), 2)
        if (args.verify_content_url or args.verify_https_url or args.exit_info) and \
                args.keep <= 0 and args.per_group <= 0:
            fail("内容/出口探测只在深度验证时执行：请加 --keep N 或 --per-group N", 2)
        if args.sources_only and (args.apply or args.cron):
            fail("--sources-only 不能与 --apply / --cron 同时使用", 2)

        _run_main(args)
    finally:
        release_lock(_lock)


def _run_main(args):
    # secret/带 token 的探测 URL 绝不能进 --json 输出（那是给其它脚本/AI 消费的）；
    # 这些 URL 可能来自私有探针，没必要把查询参数一起暴露。
    _HIDDEN_ARGS = {"json_out", "secret", "verify_content_text",
                    "test_url", "delay_url", "verify_content_url",
                    "verify_https_url", "exit_info_url", "health_url"}
    result = {"ts": datetime.datetime.now().isoformat(timespec="seconds"),
              "args": {k: v for k, v in vars(args).items() if k not in _HIDDEN_ARGS}}
    dns = dns_from_args(args.dns_mode, args.dns_servers)

    log(f"开始抓取（上限 {args.limit}）")
    proxies = harvest(args.limit)
    if not proxies:
        fail("一个节点都没抓到")
    log(f"抓取完成：{len(proxies)} 个节点")

    if args.inherit:
        old, total = history_good(days=args.inherit_days)
        have = {(str(p.get("server") or "").lower(), _as_port(p.get("port")))
                for p in proxies if isinstance(p, dict)}
        added = [p for p in old
                 if isinstance(p, dict)
                 and (str(p.get("server") or "").lower(), _as_port(p.get("port"))) not in have]
        for p in added:
            p["_inherited"] = True
        proxies += added
        log(f"历史继承：从 {total} 个历史节点中拉回 {len(added)} 个常青节点")

    # 校验：返回 (good, bad)，直接用 good（P0-1 修正）
    proxies, bad = validate_proxies(proxies)
    if bad:
        log(f"  跳过 {len(bad)} 个无效节点：" + ", ".join(f"{n}({','.join(f)})" for n, f in bad[:5]))

    # 统一重名处理：在 inherit 合并 + 校验之后执行一次（P0-2 修正）
    # 端点先去重，避免同一台服务器以不同名字重复占用测速名额
    before_ep = len(proxies)
    proxies = dedupe_endpoints(proxies)
    if len(proxies) != before_ep:
        log(f"  端点去重：{before_ep} → {len(proxies)}")
    dedupe_names(proxies)

    # 源信誉/突变检测：首次运行建立基线；命中源仍参与测速，但不允许落地
    source_mutations = {}
    if not args.sources_only:
        source_mutations = detect_source_mutations(proxies, commit=not args.dry_run)
        if source_mutations:
            result["source_mutations"] = source_mutations
            for sid, reason in source_mutations.items():
                log(f"  ⚠ 源突变，拒绝落地：{source_label(sid)}（{reason}）")
        else:
            result["source_mutations"] = {}

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
    # dry-run 只做读/探测与 JSON 审阅报告，不写快照、历史、采样、订阅
    if not args.no_snapshot and not args.sources_only and not args.dry_run:
        src_stat = {}
        for p in proxies:
            s = p.get("_source_id") or source_key(p.get("_source", ""))
            if s:
                src_stat[s] = {
                    "count": _safe_int(p.get("_source_count")),
                    "sha256": p.get("_source_hash", ""),
                    "protocols": p.get("_source_protocols") or {},
                }
        snapshot_path = save_snapshot(
            proxies, args.group, src_stat)
        log(f"A层 全量快照：{snapshot_path}（{len(proxies)} 节点）")
        result["snapshot"] = snapshot_path

    if args.sources_only:
        if args.dry_run:
            log("dry-run：跳过 sources-only 临时配置写盘")
            result["sources_only"] = False
        else:
            write_yaml(os.path.join(TMP_DIR, "config.yaml"),
                       make_sources_only_config(
                           proxies,
                           split_rules() if args.rules == "split" else None,
                           insecure=args.insecure, dns=dns))
            log(f"只抓取模式：全量配置已写 {os.path.join(TMP_DIR, 'config.yaml')}（{len(proxies)} 节点）")
            result["sources_only"] = True
        _write_json_result(args, result)
        return

    mix_port = free_port(2180)
    api_port = free_port(9180)
    if not mix_port or not api_port:
        fail("找不到空闲的临时端口", 2)

    # P1-13：启动测速实例前先 `mihomo -t` 预检。免费池里一个缺 uuid / 空 cipher /
    # reality 缺公钥的节点就能让整份配置加载失败，整轮直接报废。
    log("  预检节点配置（mihomo -t）…")
    valid, dropped = drop_invalid_proxies(proxies, mix_port, api_port,
                                          ["MATCH,PROXY"], insecure=args.insecure,
                                          dns=dns)
    if dropped:
        shown = ", ".join(sanitize_name(p.get("name"), "?") for p in dropped[:8])
        more = f" …另有 {len(dropped) - 8} 个" if len(dropped) > 8 else ""
        log(f"  预检剔除 {len(dropped)} 个配置非法节点：{shown}{more}")
    if not valid:
        fail("所有节点都无法通过配置预检", 2)
    proxies = valid
    result["valid"] = len(proxies)

    # 落地规则：cron **强制** split（国内直连），其它模式默认 match。
    # P1-6：不再让 cron 有机会把整机流量塞进代理。
    if args.cron:
        prod_rules = split_rules()
    else:
        prod_rules = split_rules() if args.rules == "split" else ["MATCH,PROXY"]
    # 缺 geo 数据时降级为不依赖 geo 的 split 规则，避免写出一个启动即失败的配置
    if prod_rules != ["MATCH,PROXY"] and not geofiles_present(PROD_CONF_DIR):
        log("  ⚠ 缺少 geoip.dat / geosite.dat，split 规则降级为无 geo 版本（仅 .cn 直连）")
        log("     如需完整分流，请从 MetaCubeX/meta-rules-dat 下载后放到配置目录")
        prod_rules = split_rules(geo=False)
    # 测速临时实例永远用 MATCH,PROXY —— 临时目录没有 GeoSite.dat，
    # 用 GEOSITE 规则会触发 mihomo 联网下载 geo 库，国内直连 GitHub 会超时。
    test_rules = ["MATCH,PROXY"]
    by_name = {p["name"]: p for p in proxies}
    passed, rows = [], []
    content_specs = []
    try:
        if args.verify_content_url:
            content_specs.append(("content", content_expectation(
                args.verify_content_url, args.verify_content_sha256,
                args.verify_content_text)))
        if args.verify_https_url:
            content_specs.append(("https", content_expectation(
                args.verify_https_url, args.verify_content_sha256,
                args.verify_content_text)))
    except ValueError as e:
        fail(str(e), 2)
    prev_exit = previous_exit_ips() if args.exit_info else {}

    try:
        with TempMihomo(TMP_DIR, mix_port, api_port, proxies, test_rules,
                        insecure=args.insecure, dns=dns) as t:
            log(f"开始并发延迟测速（{len(proxies)} 节点 ← {safe_url_label(args.delay_url)}）")
            t0 = time.time()
            delays = t.delay_all(args.delay_url, args.delay_timeout)
            log(f"  测速完成：{len(delays)} 个有响应，耗时 {time.time()-t0:.1f}s")
            if not delays:
                fail("没有任何节点通过延迟测试")
            result["delay_passed"] = len(delays)
            # 每轮记录通过率，便于观察免费池正常水位、校准阈值
            _rate = len(delays) / len(proxies) if proxies else 0.0
            result["pass_rate"] = round(_rate, 4)
            log(f"  延迟通过率：{len(delays)}/{len(proxies)} = {_rate*100:.1f}%")

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
                    log(f"开始并发深度验证（{len(cand)} 个 ← {safe_url_label(args.test_url)}）")
                    t0 = time.time()
                    checks = t.curl_check_many(cand, args.test_url, args.timeout)
                    log(f"  并发验证完成，耗时 {time.time()-t0:.1f}s")
                else:
                    log(f"开始深度验证（串行，{len(cand)} 个 ← {safe_url_label(args.test_url)}）")
                    checks = {n: t.curl_check(n, args.test_url, args.timeout) for n in cand}

                content_checks = {}
                for kind, spec in content_specs:
                    cnames = [n for n in cand if checks.get(n, (None, 99.0))[0] == 200]
                    if not cnames:
                        continue
                    log(f"内容完整性探测 [{kind}]：{len(cnames)} 个 ← {safe_url_label(spec['url'])}")
                    results = probe_nodes(t, cnames, spec["url"], args.timeout,
                                          serial=args.serial_verify, capture_body=True,
                                          max_bytes=args.verify_content_max_bytes)
                    for n, probe_result in results.items():
                        code2, _sec2, body = probe_result
                        # 超时 / 超过 max-bytes / 读 body 失败都不是“内容不符”；
                        # 把这类记成 tampered 会让来源信誉被 35 分地误伤。
                        if code2 != 200:
                            status = "http_error"
                        elif body is None:
                            status = "inconclusive"
                        elif content_matches(body, spec["sha256"]):
                            status = "ok"
                        else:
                            status = "mismatch"
                        content_checks.setdefault(n, {})[kind] = {
                            "ok": status == "ok",
                            "status": status,
                            "http_code": code2 or 0,
                            "sha256": sha256_bytes(body) if body is not None else None,
                        }

                exit_checks = {}
                if args.exit_info:
                    enames = [n for n in cand if checks.get(n, (None, 99.0))[0] == 200]
                    if enames:
                        log(f"出口信息探测：{len(enames)} 个 ← {safe_url_label(args.exit_info_url)}")
                        results = probe_nodes(t, enames, args.exit_info_url, args.timeout,
                                              serial=args.serial_verify, capture_body=True,
                                              max_bytes=args.verify_content_max_bytes)
                        for n, probe_result in results.items():
                            code2, _sec2, body = probe_result
                            exit_checks[n] = parse_exit_info(body) if code2 == 200 else {}

                content_tampered_count = 0
                content_inconclusive_count = 0
                exit_checked_count = 0
                exit_mismatch_count = 0

                for i, name in enumerate(cand, 1):
                    code, sec = checks.get(name, (None, 99.0))
                    p = by_name.get(name, {})
                    c = content_checks.get(name, {})
                    content_ok = True
                    content_mismatch = False
                    content_inconclusive = False
                    body_ok = None
                    body_sha = None
                    https_ok = None
                    for kind, _spec in content_specs:
                        item = c.get(kind) or {}
                        status = item.get("status") or "inconclusive"
                        if status == "mismatch":
                            content_mismatch = True
                            content_ok = False
                        elif status != "ok":
                            content_inconclusive = True
                            content_ok = False
                        if kind == "content":
                            body_ok = status == "ok"
                            body_sha = item.get("sha256")
                        elif kind == "https":
                            https_ok = status == "ok"
                    content_tampered = bool(content_specs and code == 200 and content_mismatch)
                    content_inconclusive = bool(content_specs and content_inconclusive)

                    exit_info = exit_checks.get(name, {})
                    claimed = country_of(p.get("name", ""))
                    exit_country = normalize_country(exit_info.get("country"))
                    country_match = (exit_country == claimed) if (exit_country and claimed) else None
                    prev_id = p.get("_id") or name
                    exit_changed = bool(prev_exit.get(prev_id) and exit_info.get("ip") and
                                        prev_exit.get(prev_id) != exit_info["ip"])
                    trust = 1.0
                    if exit_changed:
                        trust *= 0.85
                    if country_match is False:
                        trust *= 0.75

                    ok = code == 200 and content_ok
                    sc = quality_score(delays[name], sec, trust=trust) if ok else 0.0
                    score_of[name] = sc
                    if content_tampered:
                        content_tampered_count += 1
                    if content_inconclusive:
                        content_inconclusive_count += 1
                    if exit_info.get("ip"):
                        exit_checked_count += 1
                    if country_match is False:
                        exit_mismatch_count += 1
                    rows.append({"name": name, "type": p.get("type", ""),
                                 "server": p.get("server", ""), "port": p.get("port", 0),
                                 "source": source_key(p.get("_source_id") or p.get("_source", "")),
                                 "id": p.get("_id", ""),
                                 "delay_ms": delays[name], "http_code": code or 0,
                                 "http_sec": round(sec, 2) if code == 200 else None, "ok": ok,
                                 "score": sc, "grade": grade(sc) if ok else "失败",
                                 "body_ok": body_ok, "body_sha256": body_sha,
                                 "https_ok": https_ok, "content_tampered": content_tampered,
                                 "content_inconclusive": content_inconclusive,
                                 "exit_ip": exit_info.get("ip", ""),
                                 "exit_country": exit_info.get("country", ""),
                                 "exit_asn": exit_info.get("asn", ""),
                                 "exit_org": exit_info.get("org", ""),
                                 "country_match": country_match,
                                 "exit_changed": exit_changed,
                                 "trust": round(trust, 2)})
                    extra = ""
                    if content_tampered:
                        extra += " [内容被篡改]"
                    elif content_inconclusive:
                        extra += " [内容探测未决]"
                    if country_match is False:
                        extra += f" [出口 {exit_country}≠声称 {claimed}]"
                    if exit_changed:
                        extra += " [出口 IP 变化]"
                    log(f"  {i:2}/{len(cand)} {'✅' if ok else '❌'} {name:34} "
                        f"{delays[name]:>5}ms / " + (f"{sec:.2f}s" if code == 200 else "超时") +
                        f" / {sc:5.1f}分{extra}")
                    if ok:
                        passed.append(name)
                    if args.good_enough and args.per_group == 0 and len(passed) >= args.good_enough:
                        log(f"  已达到 good-enough={args.good_enough}，提前结束深验")
                        break

                result["content_checked"] = len([n for n in cand
                                                 if content_checks.get(n)])
                result["content_tampered"] = content_tampered_count
                result["content_inconclusive"] = content_inconclusive_count
                if args.exit_info:
                    result["exit_checked"] = exit_checked_count
                    result["exit_mismatch"] = exit_mismatch_count
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
                               "proxy": public_proxy(by_name.get(n, {}))} for n in passed[:10]]

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
                                      "proxy": public_proxy(by_name.get(n, {}))} for n in gn]
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

    # 先把本轮数据落盘，再做落地。
    # 落地可能因配置校验/secret 等原因 fail() 退出，数据不该跟着丢。
    # dry-run 只保留 JSON 审阅报告，不写历史/采样/每日聚合/订阅。
    if not args.dry_run:
        jsonl, csvp = save_history(rows, by_name)
        log(f"测试记录：{jsonl}")
        log(f"最新 CSV ：{csvp}")
        result["history_jsonl"] = jsonl
        result["history_csv"] = csvp

        _id_map = {p["name"]: p.get("_id", "") for p in proxies}
        sample_path = save_samples(delays, rows, args.group,
                                   all_names=[p["name"] for p in proxies],
                                   id_map=_id_map)
        log(f"B层 采样序列：{sample_path}（{len(delays)} 条）")
        result["samples"] = sample_path
    else:
        log("dry-run：跳过历史/采样/每日聚合/订阅写盘（JSON 报告仍会写出）")

    do_apply = not args.dry_run and (args.apply or args.cron)
    if do_apply:
        selected = [by_name[n] for n in passed if n in by_name and
                    source_key(by_name[n].get("_source_id") or
                               by_name[n].get("_source", "")) not in source_mutations]
        if not selected and passed:
            fail("通过节点全部来自突变源，已拒绝落地")
        # P2-12：落地节点数上限，避免把几十个节点全塞进生产配置
        if args.max_nodes and len(selected) > args.max_nodes:
            dropped = len(selected) - args.max_nodes
            selected = selected[:args.max_nodes]
            log(f"  按 --max-nodes={args.max_nodes} 截断，丢弃 {dropped} 个（按质量分排序）")
        apply_ok = apply_prod(selected, prod_rules, insecure=args.insecure, secret=args.secret,
                              health_check=not args.no_health_check,
                              health_url=args.health_url, health_timeout=args.timeout,
                              dns=dns)
        if not apply_ok:
            fail("落地后健康检查失败，已回滚到落地前备份")
        result["applied"] = True
        result["health_check"] = not args.no_health_check
    else:
        log("未落地生产配置（加 --apply 或 --cron 才会写入）")
        result["applied"] = False

    report_sources(source_health())

    # C 层：按天聚合表
    daily_path = None
    if not args.dry_run:
        daily_path = build_daily_aggregate()
    if daily_path:
        log(f"C层 每日聚合：{daily_path}")
        result["daily_csv"] = daily_path

    # D 层：分组订阅输出；突变源不进入可分享配置
    export_names = [n for n in passed
                    if source_key(by_name.get(n, {}).get("_source_id") or
                                  by_name.get(n, {}).get("_source", ""))
                    not in source_mutations]
    if not args.no_subscriptions and not args.dry_run and export_names:
        written = export_group_configs(export_names, by_name, prod_rules,
                                       insecure=args.insecure, dns=dns)
        for g, path, n in written:
            log(f"D层 订阅 [{g}]：{path}（{n} 节点）")
        result["subscriptions"] = {g: path for g, path, _ in written}
    elif args.dry_run:
        log("dry-run：跳过 D 层订阅写盘")
    elif not args.no_subscriptions and passed and not export_names:
        # 通过节点全部来自突变源时不能清空旧订阅；保留上一轮可用的文件，
        # 等源内容恢复正常后再重新导出。
        log("D层：通过节点全部来自突变源，跳过订阅导出与旧文件清理")

    # cron 收尾：清死节点 + 归档历史（dry-run 时跳过）
    if args.cron and not args.dry_run:
        log("=== cron 收尾：清理死节点 ===")
        # 名字 + 稳定 id 双重保护：本轮通过的节点在历史里可能已经改过名
        protect = set(passed) | {by_name[n].get("_id")
                                 for n in passed
                                 if by_name.get(n, {}).get("_id")}
        n_dead = clean_dead_nodes(window=args.dead_window, min_fail=args.dead_fails,
                                  apply=True, target="both", protect=protect,
                                  backup=not do_apply,
                                  min_span_hours=args.dead_min_span)
        result["cleaned_dead"] = n_dead
        log("=== cron 收尾：归档过期历史 ===")
        prune_history(days=args.prune_days, archive=not args.no_archive, apply=True)
        result["pruned"] = True
    elif args.cron:
        log("cron --dry-run：跳过落地与清理")

    _write_json_result(args, result)

    if args.cron:
        log("=== cron 全流程结束 ===")


def _write_json_result(args, result):
    """写 --json 结果。自动建父目录，原子写入，避免半截 JSON。"""
    if not getattr(args, "json_out", None):
        return None
    path = os.path.abspath(args.json_out)
    parent = os.path.dirname(path)
    if parent:
        os.makedirs(parent, exist_ok=True)
    tmp = f"{path}.{os.getpid()}.tmp"
    try:
        with codecs.open(tmp, "w", "utf-8") as f:
            json.dump(result, f, ensure_ascii=False, indent=2)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            try:
                os.remove(tmp)
            except OSError:
                pass
    log(f"JSON 结果：{path}")
    return path


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        log("用户中断")
        sys.exit(130)
    except SystemExit:
        raise
    except Exception as e:
        log(f"异常：{type(e).__name__}: {e}")
        sys.exit(1)
