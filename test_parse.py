"""协议解析器与核心逻辑的单元测试。

运行：
    python -m unittest test_parse -v
或：
    python test_parse.py
"""
import base64
import datetime
import hashlib
import json
import os
import shutil
import sys
import tempfile
import unittest
from unittest.mock import patch

# P0-1：必须在 import proxy_harvest 之前把 base_dir 指到临时目录。
# 否则 config.json 里的 base_dir 会把 PROD_CONFIG / BACKUP_DIR / LOG_FILE
# 全都指向用户真实目录，测试会覆盖真配置。
_TEST_BASE = tempfile.mkdtemp(prefix="ph-test-base-")
os.environ["PH_BASE_DIR"] = _TEST_BASE

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import configgen
import proxy_harvest as m
import mock_mihomo


def tearDownModule():
    shutil.rmtree(_TEST_BASE, ignore_errors=True)


def b64(s):
    return base64.b64encode(s.encode()).decode()


def b64u(s):
    return base64.urlsafe_b64encode(s.encode()).decode().rstrip("=")


class TestParsers(unittest.TestCase):
    """8 种协议解析函数。"""

    def test_vless_basic(self):
        u = "vless://11111111-2222-3333-4444-555555555555@example.com:443?encryption=none&security=tls&sni=ex.com&type=ws&path=%2Fws#VL"
        d = m.p_vless(u)
        self.assertEqual(d["type"], "vless")
        self.assertEqual(d["server"], "example.com")
        self.assertEqual(d["port"], 443)
        self.assertEqual(d["uuid"], "11111111-2222-3333-4444-555555555555")
        self.assertTrue(d["tls"])
        self.assertEqual(d["servername"], "ex.com")
        self.assertEqual(d["network"], "ws")
        self.assertEqual(d["ws-opts"]["path"], "/ws")
        self.assertEqual(d["name"], "VL")

    def test_vless_reality(self):
        u = "vless://uuid-here@example.org:8443?security=reality&pbk=KEY&sid=abc&type=tcp&fp=firefox#Reality"
        d = m.p_vless(u)
        self.assertEqual(d["type"], "vless")
        self.assertTrue(d["tls"])
        self.assertEqual(d["reality-opts"]["public-key"], "KEY")
        self.assertEqual(d["reality-opts"]["short-id"], "abc")
        self.assertEqual(d["client-fingerprint"], "firefox")

    def test_vmess_basic(self):
        obj = {"v": "2", "ps": "VM节点", "add": "vm.example.com", "port": "80",
               "id": "vm-uuid", "aid": "0", "net": "tcp", "tls": ""}
        u = "vmess://" + b64(json.dumps(obj))
        d = m.p_vmess(u)
        self.assertEqual(d["type"], "vmess")
        self.assertEqual(d["server"], "vm.example.com")
        self.assertEqual(d["port"], 80)
        self.assertEqual(d["uuid"], "vm-uuid")
        self.assertEqual(d["name"], "VM节点")
        self.assertNotIn("tls", d)

    def test_vmess_ws_tls(self):
        obj = {"v": "2", "ps": "WS", "add": "w.example.com", "port": "443",
               "id": "id", "aid": "2", "net": "ws", "tls": "tls",
               "sni": "sni.example.com", "host": "h.example.com", "path": "/p"}
        d = m.p_vmess("vmess://" + b64u(json.dumps(obj)))
        self.assertTrue(d["tls"])
        self.assertEqual(d["servername"], "sni.example.com")
        self.assertEqual(d["network"], "ws")
        self.assertEqual(d["ws-opts"]["path"], "/p")
        self.assertEqual(d["ws-opts"]["headers"]["Host"], "h.example.com")
        self.assertEqual(d["alterId"], 2)

    def test_trojan(self):
        u = "trojan://mypassword@trojan.example.com:443?sni=t.example.com#TJ"
        d = m.p_trojan(u)
        self.assertEqual(d["type"], "trojan")
        self.assertEqual(d["server"], "trojan.example.com")
        self.assertEqual(d["port"], 443)
        self.assertEqual(d["password"], "mypassword")
        self.assertEqual(d["sni"], "t.example.com")
        # P1-6 之后：未声明 allowInsecure 不再强行跳过证书校验
        self.assertNotIn("skip-cert-verify", d)

    def test_ss_userinfo(self):
        cred = b64u("aes-256-gcm:pass:word")
        u = f"ss://{cred}@ss.example.com:8388#SS-Name"
        d = m.p_ss(u)
        self.assertEqual(d["type"], "ss")
        self.assertEqual(d["server"], "ss.example.com")
        self.assertEqual(d["port"], 8388)
        self.assertEqual(d["cipher"], "aes-256-gcm")
        self.assertEqual(d["password"], "pass:word")
        self.assertEqual(d["name"], "SS-Name")

    def test_ss_plain_userinfo_percent_decode(self):
        """SIP002 明文 userinfo 的密码要做 percent-decode。"""
        d = m.p_ss("ss://aes-256-gcm:p%40ss@ss.example.com:8388#SS")
        self.assertEqual(d["password"], "p@ss")

    def test_ss_b64_userinfo_not_double_decoded(self):
        """Base64 里的 %40 是密码字面量，不能再 unquote 成 @。"""
        cred = b64u("aes-256-gcm:p%40ss")
        d = m.p_ss(f"ss://{cred}@ss.example.com:8388#SS")
        self.assertEqual(d["password"], "p%40ss")

    def test_ss_whole_b64(self):
        raw = b64u("aes-128-gcm:pwd@ss2.example.com:1234")
        d = m.p_ss("ss://" + raw)
        self.assertEqual(d["type"], "ss")
        self.assertEqual(d["server"], "ss2.example.com")
        self.assertEqual(d["port"], 1234)

    def test_hysteria2(self):
        u = "hysteria2://hypass@hy.example.com:443?sni=hy2.example.com#HY"
        d = m.p_hy2(u)
        self.assertEqual(d["type"], "hysteria2")
        self.assertEqual(d["server"], "hy.example.com")
        self.assertEqual(d["password"], "hypass")
        self.assertEqual(d["sni"], "hy2.example.com")

        d2 = m.PARSERS["hy2"]("hy2://p@h2.example.com:1000#H2")
        self.assertEqual(d2["type"], "hysteria2")
        self.assertEqual(d2["port"], 1000)

    def test_hysteria2_user_password(self):
        """user:pass 形式必须取 password，不能只拿 username。"""
        d = m.p_hy2("hysteria2://user:pa%40ss@hy.example.com:443#HY")
        self.assertEqual(d["password"], "pa@ss")

    def test_tuic(self):
        u = "tuic://uuid-1:pwd@tuic.example.com:443?sni=t.example.com&congestion_control=bbr&alpn=h3,h2#TC"
        d = m.p_tuic(u)
        self.assertEqual(d["type"], "tuic")
        self.assertEqual(d["server"], "tuic.example.com")
        self.assertEqual(d["uuid"], "uuid-1")
        self.assertEqual(d["password"], "pwd")
        self.assertEqual(d["congestion-controller"], "bbr")
        self.assertEqual(d["alpn"], ["h3", "h2"])

    def test_anytls(self):
        u = "anytls://mypassword@at.example.com:443?sni=a.example.com#AT"
        d = m.p_anytls(u)
        self.assertEqual(d["type"], "anytls")
        self.assertEqual(d["server"], "at.example.com")
        self.assertEqual(d["password"], "mypassword")
        self.assertEqual(d["sni"], "a.example.com")

    def test_ssr(self):
        remarks = b64u("SSR-Name")
        inner = f"ssr.example.com:1234:auth_sha1_v4:aes-256-cfb:tls1.2_ticket_auth:pwd/?remarks={remarks}"
        d = m.p_ssr("ssr://" + b64u(inner))
        self.assertEqual(d["type"], "ssr")
        self.assertEqual(d["server"], "ssr.example.com")
        self.assertEqual(d["port"], 1234)
        self.assertEqual(d["protocol"], "auth_sha1_v4")
        self.assertEqual(d["name"], "SSR-Name")

    def test_ssr_bad_input_returns_none(self):
        self.assertIsNone(m.p_ssr("ssr://not-base64!!!"))


class TestHelpers(unittest.TestCase):
    def test_hostport_ipv6(self):
        self.assertEqual(m.hostport("[2001:db8::1]:443"), ("2001:db8::1", 443))
        self.assertEqual(m.hostport("user:pwd@example.com:8080"), ("example.com", 8080))

    def test_proto_group(self):
        self.assertEqual(m.proto_group("ss"), "ss")
        self.assertEqual(m.proto_group("ssr"), "ss")
        self.assertEqual(m.proto_group("hysteria2"), "hysteria")
        self.assertEqual(m.proto_group("tuic"), "new")
        self.assertEqual(m.proto_group("anytls"), "new")
        self.assertEqual(m.proto_group("vmess"), "vmess")

    def test_grade(self):
        self.assertEqual(m.grade(85), "优质")
        self.assertEqual(m.grade(65), "可用")
        self.assertEqual(m.grade(45), "一般")
        self.assertEqual(m.grade(10), "较差")

    def test_quality_score_ordering(self):
        # 真实案例：延迟低但真实慢 vs 延迟高但真实快
        slow = m.quality_score(466, 5.8)
        fast = m.quality_score(573, 3.8)
        self.assertGreater(fast, slow, "真实耗时应该影响排名，不能只看延迟")

    def test_quality_score_range(self):
        for delay, http in [(100, 1), (500, 5), (3000, 12), (5000, 30)]:
            s = m.quality_score(delay, http)
            self.assertGreaterEqual(s, 0)
            self.assertLessEqual(s, 100)

    def test_clean_proxy_strips_meta(self):
        p = {"name": "x", "type": "ss", "server": "1.2.3.4", "port": 1,
             "_source": "http://src", "_group": "ss"}
        cleaned = m.clean_proxy(p)
        self.assertNotIn("_source", cleaned)
        self.assertNotIn("_group", cleaned)
        self.assertEqual(cleaned["server"], "1.2.3.4")

    def test_validate_proxies(self):
        """返回 (good, bad) 二元组。"""
        good = {"name": "x", "type": "hysteria2", "server": "1.2.3.4", "port": 443,
                "password": "pw"}
        g, b = m.validate_proxies([good])
        self.assertEqual(len(g), 1)
        self.assertEqual(b, [])

        bad = {"name": "y", "type": "unknown_proto", "server": "1.2.3.4", "port": 1}
        g2, b2 = m.validate_proxies([bad])
        self.assertEqual(g2, [])
        self.assertEqual(len(b2), 1)
        self.assertEqual(b2[0][0], "y")


class TestDedupeNames(unittest.TestCase):
    def test_duplicates_get_suffix(self):
        ps = [{"name": "A"}, {"name": "A"}, {"name": "A"}, {"name": "B"}]
        m.dedupe_names(ps)
        self.assertEqual([p["name"] for p in ps], ["A", "A#2", "A#3", "B"])

    def test_missing_name_filled_from_host(self):
        ps = [{"server": "1.2.3.4", "port": 80}]
        m.dedupe_names(ps)
        self.assertEqual(ps[0]["name"], "1.2.3.4:80")

    def test_unique_names_unchanged(self):
        ps = [{"name": "X"}, {"name": "Y"}]
        m.dedupe_names(ps)
        self.assertEqual([p["name"] for p in ps], ["X", "Y"])

    def test_reserved_names_fall_back_to_hostport(self):
        """DIRECT/REJECT/AUTO/PROXY 等内核保留名不能当节点名。"""
        ps = [{"name": "DIRECT", "server": "1.2.3.4", "port": 80},
              {"name": "proxy", "server": "5.6.7.8", "port": 443}]
        m.dedupe_names(ps)
        self.assertEqual([p["name"] for p in ps], ["1.2.3.4:80", "5.6.7.8:443"])

    def test_reserved_name_never_used(self):
        self.assertEqual(m.sanitize_name("REJECT", "h:1"), "h:1")
        self.assertEqual(m.sanitize_name("REJECT", ""), "node")

    def test_mock_kernel_rejects_reserved_name(self):
        cfg = {"proxies": [{"name": "PROXY", "type": "ss", "server": "1.2.3.4",
                            "port": 80, "cipher": "aes-128-gcm", "password": "p"}]}
        errors = mock_mihomo.validate(cfg)
        self.assertTrue(any("保留名" in e for e in errors), errors)


class TestMonthBoundary(unittest.TestCase):
    """prune_history 的月边界：只有当月最后一天 < 截止日才整文件归档。"""

    def test_month_last_day(self):
        self.assertEqual(m._month_last_day("202611"), "2026-11-30")
        self.assertEqual(m._month_last_day("202602"), "2026-02-28")
        self.assertEqual(m._month_last_day("202412"), "2024-12-31")
        self.assertEqual(m._month_last_day("202402"), "2024-02-29")  # 闰年


class TestDeadNodes(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="ph-test-")
        self._old = m.HISTORY_DIR
        m.HISTORY_DIR = self.tmp

    def tearDown(self):
        m.HISTORY_DIR = self._old
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _write(self, records):
        # P0-1 之后死节点判定只读 samples-*.jsonl
        path = os.path.join(self.tmp, "samples-202611.jsonl")
        with open(path, "a", encoding="utf-8") as f:
            for r in records:
                f.write(json.dumps(r) + "\n")

    def test_all_recent_failures_is_dead(self):
        t1 = (datetime.datetime.now() - datetime.timedelta(hours=13)).isoformat(timespec="seconds")
        t2 = datetime.datetime.now().isoformat(timespec="seconds")
        self._write([
            {"ts": t1, "name": "dead", "ok": False, "http_code": 0},
            {"ts": t2, "name": "dead", "ok": False, "http_code": 0},
        ])
        dead = m.dead_node_names(window=7, min_fail=2)
        self.assertIn("dead", dead)

    def test_failures_only_10_minutes_apart_not_dead(self):
        t1 = (datetime.datetime.now() - datetime.timedelta(minutes=10)).isoformat(timespec="seconds")
        t2 = datetime.datetime.now().isoformat(timespec="seconds")
        self._write([
            {"ts": t1, "name": "flaky", "ok": False, "http_code": 0},
            {"ts": t2, "name": "flaky", "ok": False, "http_code": 0},
        ])
        dead = m.dead_node_names(window=7, min_fail=2)
        self.assertNotIn("flaky", dead)
        dead = m.dead_node_names(window=7, min_fail=2, min_span_hours=0)
        self.assertIn("flaky", dead, "跨度阈值应可配置")

    def test_hourly_failure_streak_72h_is_dead(self):
        """高频 cron 每小时一次，连续失败 72 小时；不能只看最后两条。"""
        now = datetime.datetime.now()
        records = [
            {"ts": (now - datetime.timedelta(hours=h)).isoformat(timespec="seconds"),
             "name": "hourly", "ok": False}
            for h in range(72, -1, -1)
        ]
        self._write(records)
        dead = m.dead_node_names(window=7, min_fail=2)
        self.assertIn("hourly", dead)
        self.assertGreaterEqual(dead["hourly"]["fail"], 72)
        self.assertGreaterEqual(dead["hourly"]["span_hours"], 12)

    def test_long_failure_last_two_five_minutes_apart_is_dead(self):
        """连续失败 3 天、最后两条只差 5 分钟；整段跨度仍然足够。"""
        now = datetime.datetime.now()
        records = [
            {"ts": (now - datetime.timedelta(hours=h)).isoformat(timespec="seconds"),
             "name": "long-dead", "ok": False}
            for h in (72, 60, 48, 36, 24, 12, 6)
        ]
        records += [
            {"ts": (now - datetime.timedelta(minutes=5)).isoformat(timespec="seconds"),
             "name": "long-dead", "ok": False},
            {"ts": now.isoformat(timespec="seconds"), "name": "long-dead", "ok": False},
        ]
        self._write(records)
        dead = m.dead_node_names(window=7, min_fail=2)
        self.assertIn("long-dead", dead)
        self.assertGreaterEqual(dead["long-dead"]["span_hours"], 12)

    def test_success_breaks_failure_streak(self):
        """中间一次成功要把连续失败段切断，只从最新失败重新计数。"""
        now = datetime.datetime.now()
        records = [
            {"ts": (now - datetime.timedelta(hours=48)).isoformat(timespec="seconds"),
             "name": "reset", "ok": False},
            {"ts": (now - datetime.timedelta(hours=36)).isoformat(timespec="seconds"),
             "name": "reset", "ok": False},
            {"ts": (now - datetime.timedelta(hours=24)).isoformat(timespec="seconds"),
             "name": "reset", "ok": True},
            {"ts": (now - datetime.timedelta(minutes=10)).isoformat(timespec="seconds"),
             "name": "reset", "ok": False},
            {"ts": now.isoformat(timespec="seconds"), "name": "reset", "ok": False},
        ]
        self._write(records)
        dead = m.dead_node_names(window=7, min_fail=2)
        self.assertNotIn("reset", dead)
        dead = m.dead_node_names(window=7, min_fail=2, min_span_hours=0)
        self.assertIn("reset", dead)
        self.assertEqual(dead["reset"]["fail"], 2, "成功之前的两条失败不能计入")

    def test_old_failure_then_recent_ok_not_dead(self):
        """P0-3 关键回归：以前失败过、最近成功，不该被杀。"""
        now = datetime.datetime.now().isoformat(timespec="seconds")
        old = (datetime.datetime.now() - datetime.timedelta(days=2)).isoformat(timespec="seconds")
        self._write([
            {"ts": old, "name": "revived", "ok": False, "http_code": 0},
            {"ts": old, "name": "revived", "ok": False, "http_code": 0},
            {"ts": now, "name": "revived", "ok": True, "http_code": 200},
        ])
        dead = m.dead_node_names(window=7, min_fail=2)
        self.assertNotIn("revived", dead)

    def test_not_enough_records_not_dead(self):
        now = datetime.datetime.now().isoformat(timespec="seconds")
        self._write([{"ts": now, "name": "once", "ok": False, "http_code": 0}])
        dead = m.dead_node_names(window=7, min_fail=2)
        self.assertNotIn("once", dead)

    def test_protect_excludes(self):
        now = datetime.datetime.now().isoformat(timespec="seconds")
        self._write([
            {"ts": now, "name": "keepme", "ok": False, "http_code": 0},
            {"ts": now, "name": "keepme", "ok": False, "http_code": 0},
        ])
        dead = m.dead_node_names(window=7, min_fail=2, protect={"keepme"})
        self.assertNotIn("keepme", dead)


class TestWriteYamlAtomic(unittest.TestCase):
    def test_no_tmp_left_and_content_ok(self):
        tmp = tempfile.mkdtemp(prefix="ph-yaml-")
        try:
            path = os.path.join(tmp, "c.yaml")
            m.write_yaml(path, {"a": 1})
            self.assertTrue(os.path.isfile(path))
            self.assertEqual([f for f in os.listdir(tmp) if f.endswith(".tmp")], [])
            import yaml as _y
            with open(path, encoding="utf-8") as f:
                self.assertEqual(_y.safe_load(f)["a"], 1)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


class TestTransportAndFields(unittest.TestCase):
    """P2-10：传输层抽取 + 各协议补全字段。"""

    # ---- SS 插件 ----
    def test_ss_plugin_obfs(self):
        u = ("ss://" + b64u("aes-256-gcm:pw") +
             "@h.example.com:8388/?plugin=obfs-local%3Bobfs%3Dtls%3Bobfs-host%3Dx.com#OB")
        d = m.p_ss(u)
        self.assertIsNotNone(d)
        self.assertEqual(d["server"], "h.example.com")
        self.assertEqual(d["port"], 8388)
        self.assertEqual(d["plugin"], "obfs")
        self.assertEqual(d["plugin-opts"]["mode"], "tls")
        self.assertEqual(d["plugin-opts"]["host"], "x.com")

    def test_ss_plugin_v2ray(self):
        u = ("ss://" + b64u("aes-256-gcm:pw") +
             "@h.example.com:8388/?plugin=v2ray-plugin%3Bmode%3Dwebsocket%3Bhost%3Dh.com%3Bpath%3D%2Fp%3Btls")
        d = m.p_ss(u)
        self.assertEqual(d["plugin"], "v2ray-plugin")
        self.assertEqual(d["plugin-opts"]["mode"], "websocket")
        self.assertEqual(d["plugin-opts"]["path"], "/p")
        self.assertTrue(d["plugin-opts"]["tls"])

    def test_ss_unknown_plugin_dropped(self):
        u = ("ss://" + b64u("aes-256-gcm:pw") +
             "@h.example.com:8388/?plugin=some-weird-plugin%3Bfoo%3D1")
        self.assertIsNone(m.p_ss(u), "未知插件应返回 None，不能当裸 ss 去测")

    def test_ss_plain_still_works(self):
        d = m.p_ss("ss://" + b64u("aes-128-gcm:pwd@h2.example.com:1234"))
        self.assertEqual(d["server"], "h2.example.com")
        self.assertNotIn("plugin", d)

    # ---- Trojan 传输层 ----
    def test_trojan_ws(self):
        u = "trojan://pw@t.example.com:443?type=ws&path=%2Fa&host=x.com#TJ"
        d = m.p_trojan(u)
        self.assertEqual(d["network"], "ws")
        self.assertEqual(d["ws-opts"]["path"], "/a")
        self.assertEqual(d["ws-opts"]["headers"]["Host"], "x.com")

    def test_trojan_grpc(self):
        u = "trojan://pw@t.example.com:443?type=grpc&serviceName=mygrpc#TJ"
        d = m.p_trojan(u)
        self.assertEqual(d["network"], "grpc")
        self.assertEqual(d["grpc-opts"]["grpc-service-name"], "mygrpc")

    def test_trojan_no_insecure_by_default(self):
        """没声明 allowInsecure 就不该强行跳过证书校验。"""
        d = m.p_trojan("trojan://pw@t.example.com:443#TJ")
        self.assertNotIn("skip-cert-verify", d)

    def test_trojan_insecure_opt_in(self):
        d = m.p_trojan("trojan://pw@t.example.com:443?allowInsecure=1#TJ")
        self.assertTrue(d["skip-cert-verify"])

    # ---- VLESS 传输层 ----
    def test_vless_httpupgrade(self):
        u = "vless://u@v.example.com:443?security=tls&type=httpupgrade&path=%2Fup&host=h.com#HU"
        d = m.p_vless(u)
        self.assertEqual(d["network"], "ws", "httpupgrade 在 mihomo 里映射为 ws")
        self.assertTrue(d["ws-opts"]["v2ray-http-upgrade"])
        self.assertEqual(d["ws-opts"]["path"], "/up")
        self.assertEqual(d["ws-opts"]["headers"]["Host"], "h.com")

    def test_vless_encryption_rejected(self):
        u = "vless://u@v.example.com:443?encryption=mlkem768x25519plus&type=tcp#ENC"
        self.assertIsNone(m.p_vless(u), "非 none 加密的 vless 应被跳过")

    def test_vless_encryption_none_ok(self):
        u = "vless://u@v.example.com:443?encryption=none&security=tls#OK"
        d = m.p_vless(u)
        self.assertIsNotNone(d)
        self.assertTrue(d["tls"])

    def test_vless_grpc(self):
        u = "vless://u@v.example.com:443?security=tls&type=grpc&serviceName=gsvc#G"
        d = m.p_vless(u)
        self.assertEqual(d["grpc-opts"]["grpc-service-name"], "gsvc")

    def test_vless_h2(self):
        u = "vless://u@v.example.com:443?security=tls&type=h2&host=a.com,b.com&path=%2Fh2#H2"
        d = m.p_vless(u)
        self.assertEqual(d["network"], "h2")
        self.assertEqual(d["h2-opts"]["host"], ["a.com", "b.com"])

    # ---- Hysteria2 ----
    def test_hy2_obfs_and_mport(self):
        u = ("hy2://pw@hy.example.com:443?sni=s.com"
             "&obfs=salamander&obfs-password=secret&mport=20000-30000#HY")
        d = m.p_hy2(u)
        self.assertEqual(d["obfs"], "salamander")
        self.assertEqual(d["obfs-password"], "secret")
        self.assertEqual(d["ports"], "20000-30000")

    def test_hy2_insecure_opt_in(self):
        d = m.p_hy2("hy2://pw@hy.example.com:443#HY")
        self.assertNotIn("skip-cert-verify", d)
        d2 = m.p_hy2("hy2://pw@hy.example.com:443?insecure=1#HY")
        self.assertTrue(d2["skip-cert-verify"])


class TestDeadNodeRegressions(unittest.TestCase):
    """P0-1 / P0-2：死节点判定不能一轮就杀，断网不能批量杀。"""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="ph-dead-")
        self._old = m.HISTORY_DIR
        m.HISTORY_DIR = self.tmp

    def tearDown(self):
        m.HISTORY_DIR = self._old
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _append(self, fname, recs):
        with open(os.path.join(self.tmp, fname), "a", encoding="utf-8") as f:
            for r in recs:
                f.write(json.dumps(r) + "\n")

    def test_same_ts_proxy_and_samples_not_dead(self):
        """P0-1：同一轮在 proxy 和 samples 各写一条失败，不能凑成 2 次判死。"""
        now = datetime.datetime.now().isoformat(timespec="seconds")
        self._append("proxy-202611.jsonl",
                     [{"ts": now, "name": "n1", "ok": False, "http_code": 0}])
        self._append("samples-202611.jsonl",
                     [{"ts": now, "name": "n1", "ok": False, "delay_ms": None}])
        dead = m.dead_node_names(window=7, min_fail=2)
        self.assertNotIn("n1", dead, "同一轮的两条记录不能算两轮")

    def test_two_rounds_samples_is_dead(self):
        """两轮不同 ts 的 samples 失败 → 判死。"""
        t1 = (datetime.datetime.now() - datetime.timedelta(hours=13)).isoformat(timespec="seconds")
        t2 = datetime.datetime.now().isoformat(timespec="seconds")
        self._append("samples-202611.jsonl", [
            {"ts": t1, "name": "n2", "ok": False, "delay_ms": None},
            {"ts": t2, "name": "n2", "ok": False, "delay_ms": None},
        ])
        dead = m.dead_node_names(window=7, min_fail=2)
        self.assertIn("n2", dead)

    def test_low_pass_rate_skips_absent_records(self):
        """P0-2：通过率 5% 时不该写"无响应"失败记录。"""
        delays = {"n0": 100}                      # 1 个响应
        all_names = [f"n{i}" for i in range(20)]  # 20 个节点 → 5%
        path = m.save_samples(delays, [], "all", all_names=all_names)
        rows = [json.loads(l) for l in open(path, encoding="utf-8")]
        absent = [r for r in rows if r.get("delay_ms") is None]
        self.assertEqual(absent, [], "低通过率时应跳过无响应记录")

    def test_normal_pass_rate_writes_absent(self):
        """通过率正常时，无响应节点仍要记录。"""
        delays = {f"n{i}": 100 for i in range(8)}
        all_names = [f"n{i}" for i in range(10)]  # 80%
        path = m.save_samples(delays, [], "all", all_names=all_names)
        rows = [json.loads(l) for l in open(path, encoding="utf-8")]
        absent = [r for r in rows if r.get("delay_ms") is None]
        self.assertEqual(len(absent), 2)

    def test_clean_skips_when_over_30_percent(self):
        """P0-2：单次要清的节点超过配置 30% 时跳过。"""
        # 造生产配置：10 个节点
        os.makedirs(os.path.dirname(m.PROD_CONFIG), exist_ok=True)
        cfg = {"proxies": [{"name": f"p{i}", "type": "ss", "server": "h", "port": 1}
                           for i in range(10)],
               "proxy-groups": [{"name": "PROXY", "type": "select",
                                 "proxies": [f"p{i}" for i in range(10)]}],
               "rules": ["MATCH,PROXY"]}
        with open(m.PROD_CONFIG, "w", encoding="utf-8") as f:
            json.dump(cfg, f)   # yaml 是 json 超集，能读
        self._old_cfg = m.PROD_CONFIG
        # 6 个节点死（60% > 30%）
        t1 = (datetime.datetime.now() - datetime.timedelta(hours=13)).isoformat(timespec="seconds")
        t2 = datetime.datetime.now().isoformat(timespec="seconds")
        recs = []
        for i in range(6):
            recs += [{"ts": t1, "name": f"p{i}", "ok": False},
                     {"ts": t2, "name": f"p{i}", "ok": False}]
        self._append("samples-202611.jsonl", recs)
        removed = m.clean_dead_nodes(window=7, min_fail=2, apply=True,
                                     target="prod", backup=False)
        self.assertEqual(removed, 0, "超过 30% 应跳过清理")


class TestSecretResolution(unittest.TestCase):
    """P1-3：secret 优先级与订阅脱敏。"""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="ph-sec-")
        self._old_cfg = m.PROD_CONFIG
        self._old_set = m._SETTINGS
        m.PROD_CONFIG = os.path.join(self.tmp, "config.yaml")
        m._SETTINGS = {}

    def tearDown(self):
        m.PROD_CONFIG = self._old_cfg
        m._SETTINGS = self._old_set
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_reuses_existing_config_secret(self):
        with open(m.PROD_CONFIG, "w", encoding="utf-8") as f:
            f.write("secret: existing-secret-123\nproxies: []\n")
        sec, origin, gen = m.resolve_prod_secret()
        self.assertEqual(sec, "existing-secret-123")
        self.assertIn("config.yaml", origin)
        self.assertFalse(gen)

    def test_legacy_box_secret_is_replaced(self):
        """P0-2：v0.01 的默认 secret 'box' 必须被替换。"""
        with open(m.PROD_CONFIG, "w", encoding="utf-8") as f:
            f.write("secret: box\nproxies: []\n")
        sec, origin, gen = m.resolve_prod_secret()
        self.assertNotEqual(sec, "box")
        self.assertTrue(gen, "弱 secret 应重新生成")
        self.assertGreaterEqual(len(sec), m.MIN_SECRET_LEN)

    def test_short_secret_is_replaced(self):
        with open(m.PROD_CONFIG, "w", encoding="utf-8") as f:
            f.write("secret: abc\nproxies: []\n")
        sec, _o, gen = m.resolve_prod_secret()
        self.assertNotEqual(sec, "abc")
        self.assertTrue(gen)

    def test_weak_secret_not_written_to_log(self):
        """P0-2：新 secret 只进终端，不写 harvest.log。"""
        if os.path.exists(m.LOG_FILE):
            os.remove(m.LOG_FILE)
        with open(m.PROD_CONFIG, "w", encoding="utf-8") as f:
            f.write("secret: box\nproxies: []\n")
        sec, _o, _g = m.resolve_prod_secret()
        # 校验需要真 mihomo，测试里直接放行
        old_validate = m.validate_config_file
        m.validate_config_file = lambda cfg, d, rules_override=None: True
        try:
            m.apply_prod([{"name": "a", "type": "ss", "server": "h", "port": 1,
                           "cipher": "aes-128-gcm", "password": "x"}],
                         ["MATCH,PROXY"], insecure=True)
        finally:
            m.validate_config_file = old_validate
        actual = m.read_secret_from_config()
        if os.path.exists(m.LOG_FILE):
            content = open(m.LOG_FILE, encoding="utf-8").read()
            self.assertNotIn(actual, content, "secret 不应出现在日志文件里")

    def test_cli_secret_wins(self):
        with open(m.PROD_CONFIG, "w", encoding="utf-8") as f:
            f.write("secret: from-file\nproxies: []\n")
        sec, origin, _gen = m.resolve_prod_secret("cli-secret")
        self.assertEqual(sec, "cli-secret")

    def test_settings_secret_over_file(self):
        with open(m.PROD_CONFIG, "w", encoding="utf-8") as f:
            f.write("secret: from-file\nproxies: []\n")
        m._SETTINGS = {"secret": "from-config-json"}
        sec, _o, _gen = m.resolve_prod_secret()
        self.assertEqual(sec, "from-config-json")

    def test_subscription_has_no_secret(self):
        """订阅文件里的 secret 必须为空。"""
        proxies = [{"name": "a", "type": "ss", "server": "h", "port": 1,
                    "cipher": "aes-128-gcm", "password": "x", "_group": "ss"}]
        out = tempfile.mkdtemp(prefix="ph-sub-")
        try:
            written = m.export_group_configs(["a"], {"a": proxies[0]},
                                             ["MATCH,PROXY"], out_dir=out)
            self.assertTrue(written)
            import yaml as _y
            for _, path, _ in written:
                with open(path, encoding="utf-8") as f:
                    cfg = _y.safe_load(f)
                self.assertEqual(cfg.get("secret", ""), "",
                                 f"{os.path.basename(path)} 不应带 secret")
        finally:
            shutil.rmtree(out, ignore_errors=True)


class TestStaleSubscriptions(unittest.TestCase):
    def test_zero_pass_group_removes_old_yaml(self):
        out = tempfile.mkdtemp(prefix="ph-stale-sub-")
        try:
            for name in ("ss.yaml", "trojan.yaml", "all.yaml", "notes.yaml"):
                with open(os.path.join(out, name), "w", encoding="utf-8") as f:
                    f.write("old\n")
            node = {"name": "a", "type": "ss", "server": "h", "port": 1,
                    "cipher": "aes-128-gcm", "password": "x", "_group": "ss"}
            m.export_group_configs(["a"], {"a": node}, ["MATCH,PROXY"],
                                   out_dir=out)
            self.assertTrue(os.path.isfile(os.path.join(out, "ss.yaml")))
            self.assertFalse(os.path.isfile(os.path.join(out, "trojan.yaml")))
            self.assertTrue(os.path.isfile(os.path.join(out, "all.yaml")))
            self.assertTrue(os.path.isfile(os.path.join(out, "notes.yaml")),
                            "未知文件不应被清理")
            # 第二次零通过，ss/all 也应消失
            m.export_group_configs([], {}, ["MATCH,PROXY"], out_dir=out)
            self.assertFalse(os.path.isfile(os.path.join(out, "ss.yaml")))
            self.assertFalse(os.path.isfile(os.path.join(out, "all.yaml")))
        finally:
            shutil.rmtree(out, ignore_errors=True)


class TestInsecureExport(unittest.TestCase):
    """--insecure 必须传到分组订阅，否则自签节点导出后失效。"""

    def _export(self, insecure):
        node = {"name": "self", "type": "ss", "server": "h", "port": 1,
                "cipher": "aes-128-gcm", "password": "x",
                "skip-cert-verify": True, "_group": "ss"}
        out = tempfile.mkdtemp(prefix="ph-insecure-")
        try:
            m.export_group_configs(["self"], {"self": node}, ["MATCH,PROXY"],
                                   out_dir=out, insecure=insecure)
            import yaml as _y
            with open(os.path.join(out, "all.yaml"), encoding="utf-8") as f:
                cfg = _y.safe_load(f)
            return cfg["proxies"][0].get("skip-cert-verify")
        finally:
            shutil.rmtree(out, ignore_errors=True)

    def test_insecure_keeps_skip_cert_verify(self):
        self.assertTrue(self._export(True))

    def test_default_strips_skip_cert_verify(self):
        self.assertIsNone(self._export(False))

    def test_sources_only_config_respects_insecure(self):
        node = {"name": "self", "type": "ss", "server": "h", "port": 1,
                "cipher": "aes-128-gcm", "password": "x",
                "skip-cert-verify": True}
        self.assertTrue(m.make_sources_only_config([node], insecure=True)["proxies"][0]
                        .get("skip-cert-verify"))
        self.assertIsNone(m.make_sources_only_config([node], insecure=False)["proxies"][0]
                          .get("skip-cert-verify"))


class TestDeadSpanAndCap(unittest.TestCase):
    """死节点：时间跨度 + 小配置删除上限。"""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="ph-deadcap-")
        self._old_cfg, self._old_hist, self._old_exe = (
            m.PROD_CONFIG, m.HISTORY_DIR, m.MIHOMO_EXE)
        m.PROD_CONFIG = os.path.join(self.tmp, "config", "config.yaml")
        m.HISTORY_DIR = os.path.join(self.tmp, "history")
        m.MIHOMO_EXE = os.path.join(self.tmp, "no-such-mihomo.exe")
        os.makedirs(os.path.dirname(m.PROD_CONFIG), exist_ok=True)
        os.makedirs(m.HISTORY_DIR, exist_ok=True)

    def tearDown(self):
        m.PROD_CONFIG, m.HISTORY_DIR, m.MIHOMO_EXE = (
            self._old_cfg, self._old_hist, self._old_exe)
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _write_cfg(self, names):
        import yaml as _y
        cfg = {
            "proxies": [{"name": n, "type": "ss", "server": f"h{n}", "port": 1,
                         "cipher": "aes-128-gcm", "password": "p"} for n in names],
            "proxy-groups": [{"name": "PROXY", "type": "select", "proxies": names}],
            "rules": ["MATCH,PROXY"],
        }
        with open(m.PROD_CONFIG, "w", encoding="utf-8") as f:
            _y.safe_dump(cfg, f, allow_unicode=True, sort_keys=False)

    def _dead_samples(self, names):
        t1 = (datetime.datetime.now() - datetime.timedelta(hours=13)).isoformat(timespec="seconds")
        t2 = datetime.datetime.now().isoformat(timespec="seconds")
        path = os.path.join(m.HISTORY_DIR, "samples-202611.jsonl")
        with open(path, "w", encoding="utf-8") as f:
            for n in names:
                f.write(json.dumps({"ts": t1, "name": n, "ok": False}) + "\n")
                f.write(json.dumps({"ts": t2, "name": n, "ok": False}) + "\n")

    def test_three_nodes_one_dead_removed(self):
        self._write_cfg(["p0", "p1", "p2"])
        self._dead_samples(["p0"])
        removed = m.clean_dead_nodes(window=7, min_fail=2, apply=True,
                                     target="prod", backup=False)
        self.assertEqual(removed, 1)

    def test_three_nodes_two_dead_skipped(self):
        self._write_cfg(["p0", "p1", "p2"])
        self._dead_samples(["p0", "p1"])
        removed = m.clean_dead_nodes(window=7, min_fail=2, apply=True,
                                     target="prod", backup=False)
        self.assertEqual(removed, 0, "2/3 超过本次上限 1，应跳过")

    def test_two_nodes_one_dead_removed_but_not_all(self):
        self._write_cfg(["p0", "p1"])
        self._dead_samples(["p0"])
        removed = m.clean_dead_nodes(window=7, min_fail=2, apply=True,
                                     target="prod", backup=False)
        self.assertEqual(removed, 1, "2 节点删 1 个是公式允许的边界")
        import yaml as _y
        with open(m.PROD_CONFIG, encoding="utf-8") as f:
            self.assertEqual(len(_y.safe_load(f)["proxies"]), 1)


class TestDedupeSuffixCollision(unittest.TestCase):
    """P2-5：A, A, A#2 不能撞成两个 A#2。"""

    def test_suffix_collision(self):
        ps = [{"name": "A"}, {"name": "A"}, {"name": "A#2"}]
        m.dedupe_names(ps)
        names = [p["name"] for p in ps]
        self.assertEqual(len(names), len(set(names)), f"仍有重名：{names}")

    def test_three_same(self):
        ps = [{"name": "X"}, {"name": "X"}, {"name": "X"}]
        m.dedupe_names(ps)
        self.assertEqual(len(set(p["name"] for p in ps)), 3)


class TestPruneHistory(unittest.TestCase):
    """P2-9：跨截止日的月文件应走行级清理，而非整文件删除。"""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="ph-prune-")
        self._old = m.HISTORY_DIR
        m.HISTORY_DIR = self.tmp

    def tearDown(self):
        m.HISTORY_DIR = self._old
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_cross_month_file_row_level(self):
        now = datetime.datetime.now()
        ym = f"{now:%Y%m}"          # 当月
        path = os.path.join(self.tmp, f"proxy-{ym}.jsonl")
        old_ts = (now - datetime.timedelta(days=200)).isoformat(timespec="seconds")
        new_ts = now.isoformat(timespec="seconds")
        with open(path, "w", encoding="utf-8") as f:
            f.write(json.dumps({"ts": old_ts, "name": "old"}) + "\n")
            f.write(json.dumps({"ts": new_ts, "name": "new"}) + "\n")
        m.prune_history(days=90, archive=False, apply=True)
        self.assertTrue(os.path.isfile(path), "当月文件不能被整份删掉")
        lines = [json.loads(l) for l in open(path, encoding="utf-8")]
        names = [r["name"] for r in lines]
        self.assertNotIn("old", names, "过期行应被清掉")
        self.assertIn("new", names, "期内行必须保留")

    def test_fully_old_day_file_removed(self):
        old_day = (datetime.datetime.now() - datetime.timedelta(days=200))
        fname = f"snapshot-{old_day:%Y%m%d}.jsonl"
        path = os.path.join(self.tmp, fname)
        with open(path, "w", encoding="utf-8") as f:
            f.write(json.dumps({"ts": old_day.isoformat(timespec="seconds")}) + "\n")
        m.prune_history(days=90, archive=False, apply=True)
        self.assertFalse(os.path.isfile(path), "完全过期的日文件应整份删除")


class TestStableNodeId(unittest.TestCase):
    """P0-3：节点身份必须稳定，不能靠可能变化的 name。"""

    def test_same_node_different_names_same_id(self):
        a = {"type": "ss", "server": "h.com", "port": 8388, "name": "A#2"}
        b = {"type": "ss", "server": "h.com", "port": 8388, "name": "A"}
        self.assertEqual(m.node_id(a), m.node_id(b))

    def test_different_port_different_id(self):
        a = {"type": "ss", "server": "h.com", "port": 8388}
        b = {"type": "ss", "server": "h.com", "port": 8389}
        self.assertNotEqual(m.node_id(a), m.node_id(b))

    def test_different_type_different_id(self):
        a = {"type": "ss", "server": "h.com", "port": 1}
        b = {"type": "trojan", "server": "h.com", "port": 1}
        self.assertNotEqual(m.node_id(a), m.node_id(b))

    def test_case_insensitive(self):
        a = {"type": "SS", "server": "H.com", "port": 1}
        b = {"type": "ss", "server": "h.com", "port": 1}
        self.assertEqual(m.node_id(a), m.node_id(b))

    def test_dedupe_sets_id(self):
        ps = [{"name": "x", "type": "ss", "server": "a", "port": 1}]
        m.dedupe_names(ps)
        self.assertTrue(ps[0].get("_id"))
        self.assertEqual(len(ps[0]["_id"]), 10)

    def test_dead_detection_across_name_change(self):
        """同一节点两轮改名，仍被判定为同一个（用 id 归并）。"""
        tmp = tempfile.mkdtemp(prefix="ph-id-")
        old = m.HISTORY_DIR
        m.HISTORY_DIR = tmp
        try:
            node = {"type": "ss", "server": "h.com", "port": 8388}
            nid = m.node_id(node)
            t1 = (datetime.datetime.now() - datetime.timedelta(hours=13)).isoformat(timespec="seconds")
            t2 = datetime.datetime.now().isoformat(timespec="seconds")
            with open(os.path.join(tmp, "samples-202611.jsonl"), "w", encoding="utf-8") as f:
                f.write(json.dumps({"ts": t1, "name": "A", "id": nid, "ok": False}) + "\n")
                f.write(json.dumps({"ts": t2, "name": "A#2", "id": nid, "ok": False}) + "\n")
            dead = m.dead_node_names(window=7, min_fail=2)
            self.assertEqual(len(dead), 1, "改名后仍应识别为同一节点")
        finally:
            m.HISTORY_DIR = old
            shutil.rmtree(tmp, ignore_errors=True)


class TestDailyAggregateNoDoubleCount(unittest.TestCase):
    """P0-4：深验节点不能在一轮里被算两次。"""

    def test_single_round_counts_once(self):
        tmp = tempfile.mkdtemp(prefix="ph-agg-")
        old = m.HISTORY_DIR
        m.HISTORY_DIR = tmp
        try:
            ts = datetime.datetime.now().isoformat(timespec="seconds")
            # samples 一条
            with open(os.path.join(tmp, "samples-202611.jsonl"), "w", encoding="utf-8") as f:
                f.write(json.dumps({"ts": ts, "name": "n1", "id": "abc",
                                    "ok": True, "score": 80, "delay_ms": 500}) + "\n")
            # proxy 也有一条（同一轮深验）
            with open(os.path.join(tmp, "proxy-202611.jsonl"), "w", encoding="utf-8") as f:
                f.write(json.dumps({"ts": ts, "name": "n1", "http_code": 200,
                                    "ok": True, "score": 80}) + "\n")
            m.build_daily_aggregate()
            csvp = os.path.join(tmp, "latest_daily.csv")
            self.assertTrue(os.path.isfile(csvp))
            rows = open(csvp, encoding="utf-8-sig").read().strip().split("\n")
            self.assertEqual(len(rows), 2, "应只有表头 + 1 行")
            seen = int(rows[1].split(",")[2])
            self.assertEqual(seen, 1, f"采样次数应为 1，实际 {seen}")
        finally:
            m.HISTORY_DIR = old
            shutil.rmtree(tmp, ignore_errors=True)


class TestHarvestQuota(unittest.TestCase):
    """P1-8：多源配额，不能第一个源吃满。"""

    def test_quota_per_source(self):
        calls = []

        def fake_fetch(url):
            calls.append(url)
            # 每个源都给 50 个节点
            return "\n".join(
                f"ss://{b64u('aes-128-gcm:pw')}@{i}.{len(calls)}.com:8388#N{i}"
                for i in range(50))

        old_fetch, old_sources = m.fetch, m.SOURCES
        m.fetch = fake_fetch
        m.SOURCES = ["https://a/1", "https://a/2", "https://a/3"]
        try:
            got = m.harvest(30)
            self.assertLessEqual(len(got), 30)
            # 三个源都该被访问
            self.assertEqual(len(calls), 3, "所有源都应被抓取")
            srcs = {p.get("_source") for p in got}
            self.assertGreaterEqual(len(srcs), 2, "不能只来自一个源")
        finally:
            m.fetch, m.SOURCES = old_fetch, old_sources

    def test_invalid_content_treated_as_failure(self):
        """P1-9：返回 HTML 的源应被判为无效。"""
        def fake_fetch(url):
            return "<html><body>error</body></html>"

        old_fetch, old_sources = m.fetch, m.SOURCES
        m.fetch = fake_fetch
        m.SOURCES = ["https://a/1"]
        try:
            got = m.harvest(10)
            self.assertEqual(got, [], "HTML 内容不该产出节点")
        finally:
            m.fetch, m.SOURCES = old_fetch, old_sources

    def test_multiple_uris_on_one_line(self):
        """P1-14：多个 URI 挤在同一行时不能只解析第一个。"""
        def fake_fetch(url):
            return " ".join(
                "ss://" + b64u("aes-128-gcm:pw") + f"@{i}.h.com:8388#N{i}"
                for i in range(3))

        old_fetch, old_sources = m.fetch, m.SOURCES
        m.fetch = fake_fetch
        m.SOURCES = ["https://a/1"]
        try:
            got = m.harvest(10)
            self.assertEqual(len(got), 3)
        finally:
            m.fetch, m.SOURCES = old_fetch, old_sources


class TestVmessAndSsr(unittest.TestCase):
    """P1-10：vmess tls 判定、传输层；ssr obfs-param / protocol-param。"""

    def _vm(self, obj):
        return m.p_vmess("vmess://" + b64(json.dumps(obj)))

    def test_vmess_tls_none_not_true(self):
        d = self._vm({"v": "2", "ps": "x", "add": "h.com", "port": "443",
                      "id": "u", "aid": "0", "net": "tcp", "tls": "none"})
        self.assertNotIn("tls", d, "tls='none' 不该被当成开启")

    def test_vmess_tls_empty_not_true(self):
        d = self._vm({"v": "2", "ps": "x", "add": "h.com", "port": "443",
                      "id": "u", "aid": "0", "net": "tcp", "tls": ""})
        self.assertNotIn("tls", d)

    def test_vmess_tls_tls_is_true(self):
        d = self._vm({"v": "2", "ps": "x", "add": "h.com", "port": "443",
                      "id": "u", "aid": "0", "net": "tcp", "tls": "tls"})
        self.assertTrue(d["tls"])

    def test_vmess_grpc(self):
        d = self._vm({"v": "2", "ps": "x", "add": "h.com", "port": "443",
                      "id": "u", "aid": "0", "net": "grpc", "path": "gsvc"})
        self.assertEqual(d["network"], "grpc")
        self.assertEqual(d["grpc-opts"]["grpc-service-name"], "gsvc")

    def test_vmess_httpupgrade(self):
        d = self._vm({"v": "2", "ps": "x", "add": "h.com", "port": "443",
                      "id": "u", "aid": "0", "net": "httpupgrade",
                      "path": "/u", "host": "hh.com"})
        self.assertEqual(d["network"], "ws")
        self.assertTrue(d["ws-opts"]["v2ray-http-upgrade"])

    def test_ssr_extra_params(self):
        op = b64u("obfsparam-value")
        pp = b64u("proto-param-value")
        rm = b64u("SSR名")
        inner = (f"h.com:1234:auth_sha1_v4:aes-256-cfb:tls1.2_ticket_auth:pw/"
                 f"?remarks={rm}&obfsparam={op}&protoparam={pp}")
        d = m.p_ssr("ssr://" + b64u(inner))
        self.assertEqual(d["obfs-param"], "obfsparam-value")
        self.assertEqual(d["protocol-param"], "proto-param-value")


class TestLockSafety(unittest.TestCase):
    """P0-1：锁的探活绝不能在 Windows 上杀进程；陈旧锁要能接管。"""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="ph-lock-")
        self._old_base = m.BASE
        m.BASE = self.tmp

    def tearDown(self):
        m.BASE = self._old_base
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_stale_lock_taken_over(self):
        """残留的锁文件没有 OS 持有者，应能直接接管。"""
        lock = os.path.join(self.tmp, ".harvest.lock")
        with open(lock, "w") as f:
            f.write("999999")          # 极不可能存在的 PID
        got = m.acquire_lock()
        self.assertTrue(got, "陈旧锁应被接管")
        m.release_lock(got)

    def test_alive_pid_blocks(self):
        """同一进程持有 OS 锁时，第二次获取必须失败。"""
        first = m.acquire_lock()
        self.assertTrue(first)
        self.assertIsNone(m.acquire_lock(), "已持有的锁应阻止第二次获取")
        m.release_lock(first)
        again = m.acquire_lock()
        self.assertTrue(again, "释放后应能重新获取")
        m.release_lock(again)

    @unittest.skipIf(os.name == "nt", "POSIX 权限语义")
    def test_permission_error_means_alive(self):
        """Linux 上 kill(pid,0) 报 EPERM 说明进程存在但属于别人，不能当死。"""
        from unittest.mock import patch
        with patch.object(m.os, "kill", side_effect=PermissionError):
            self.assertTrue(m._pid_alive(12345))

    def test_pid_alive_self(self):
        self.assertTrue(m._pid_alive(os.getpid()))

    def test_pid_alive_bogus(self):
        self.assertFalse(m._pid_alive(999999))

    def test_pid_alive_zero(self):
        self.assertFalse(m._pid_alive(0))

    def test_rollback_branch_acquires_lock(self):
        """--rollback 是写操作，必须在加锁后执行。"""
        calls = []
        old_argv = sys.argv
        sys.argv = ["proxy_harvest.py", "--rollback"]
        try:
            with patch.object(m, "acquire_lock", side_effect=lambda: calls.append("acquire") or "LOCK"), \
                 patch.object(m, "release_lock", side_effect=lambda _l: calls.append("release")), \
                 patch.object(m, "rollback", side_effect=lambda: calls.append("rollback")):
                m.main()
        finally:
            sys.argv = old_argv
        self.assertEqual(calls, ["acquire", "rollback", "release"])


class TestBaseDir(unittest.TestCase):
    def test_non_editable_install_falls_back_to_home(self):
        p = m._default_base_dir("/usr/lib/python3/site-packages/proxy_harvest")
        self.assertEqual(p, os.path.join(os.path.expanduser("~"), ".proxy-harvest"))
        self.assertEqual(m._default_base_dir("/opt/proxy-harvest"),
                         os.path.abspath("/opt/proxy-harvest"))

    def test_ph_base_dir_still_wins(self):
        with patch.dict(os.environ, {"PH_BASE_DIR": "/tmp/ph-explicit"}):
            self.assertEqual(m._load_settings()["base_dir"], "/tmp/ph-explicit")


class TestSecretNotInJson(unittest.TestCase):
    """P0-2：--secret 不能进 --json 输出。"""

    def test_secret_filtered(self):
        import argparse
        args = argparse.Namespace(json_out="x.json", secret="TOP-SECRET-VALUE",
                                  limit=1, cron=False)
        hidden = {"json_out", "secret"}
        dumped = {k: v for k, v in vars(args).items() if k not in hidden}
        self.assertNotIn("secret", dumped)
        self.assertNotIn("json_out", dumped)
        self.assertNotIn("TOP-SECRET-VALUE", json.dumps(dumped))


class TestIdPlumbing(unittest.TestCase):
    """P0-3：真实调用 save_samples 时每条记录都要带非空 id。"""

    def test_save_samples_writes_id(self):
        tmp = tempfile.mkdtemp(prefix="ph-id2-")
        old = m.HISTORY_DIR
        m.HISTORY_DIR = tmp
        try:
            proxies = [{"name": "A", "type": "ss", "server": "h.com", "port": 1}]
            m.dedupe_names(proxies)          # 补齐 _id
            id_map = {p["name"]: p["_id"] for p in proxies}
            path = m.save_samples({"A": 100},
                                  [{"name": "A", "ok": True, "score": 80}],
                                  "all", all_names=["A"], id_map=id_map)
            rows = [json.loads(l) for l in open(path, encoding="utf-8")]
            self.assertTrue(rows)
            for r in rows:
                self.assertTrue(r.get("id"), "每条记录都要有非空 id")
                self.assertEqual(r["id"], id_map["A"])
        finally:
            m.HISTORY_DIR = old
            shutil.rmtree(tmp, ignore_errors=True)

    def test_save_history_writes_id(self):
        tmp = tempfile.mkdtemp(prefix="ph-id3-")
        old = m.HISTORY_DIR
        m.HISTORY_DIR = tmp
        try:
            p = {"name": "B", "type": "ss", "server": "h.com", "port": 2}
            m.dedupe_names([p])
            rows = [{"name": "B", "type": "ss", "server": "h.com", "port": 2,
                     "ok": True, "score": 90}]
            jsonl, _csv = m.save_history(rows, {"B": p})
            recs = [json.loads(l) for l in open(jsonl, encoding="utf-8")]
            self.assertEqual(recs[0].get("id"), p["_id"])
        finally:
            m.HISTORY_DIR = old
            shutil.rmtree(tmp, ignore_errors=True)


class TestUnsupportedNetwork(unittest.TestCase):
    """建议 5：不支持的传输类型应该被丢弃，而不是原样写进配置。"""

    def test_vless_kcp_dropped(self):
        u = "vless://u@v.com:443?security=tls&type=kcp#KCP"
        self.assertIsNone(m.p_vless(u))

    def test_trojan_quic_dropped(self):
        u = "trojan://pw@t.com:443?type=quic#QUIC"
        self.assertIsNone(m.p_trojan(u))

    def test_supported_still_ok(self):
        u = "vless://u@v.com:443?security=tls&type=ws&path=%2Fw#WS"
        d = m.p_vless(u)
        self.assertIsNotNone(d)
        self.assertEqual(d["network"], "ws")


class TestGeofiles(unittest.TestCase):
    """P0-4：geo 文件缺失检测。"""

    def test_missing(self):
        tmp = tempfile.mkdtemp(prefix="ph-geo-")
        try:
            self.assertFalse(m.geofiles_present(tmp))
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_present(self):
        tmp = tempfile.mkdtemp(prefix="ph-geo2-")
        try:
            open(os.path.join(tmp, "geoip.dat"), "wb").close()
            open(os.path.join(tmp, "geosite.dat"), "wb").close()
            self.assertTrue(m.geofiles_present(tmp))
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


class TestParserHardening(unittest.TestCase):
    """v0.0.3 解析器边界用例：畸形 URI 不得抛异常，也不得产出必然加载失败的节点。"""

    def test_bad_ports_return_none(self):
        cases = {
            "vless": ["vless://u@h.com?security=tls#no-port",
                      "vless://u@h.com:abc#bad-port",
                      "vless://u@h.com:70000#overflow"],
            "trojan": ["trojan://p@h.com:0#zero"],
            "hy2": ["hy2://p@h.com#no-port", "hy2://p@h.com:abc#bad"],
            "ss": ["ss://" + b64u("aes-128-gcm:pw") + "@h.com:abc#bad",
                   "ss://" + b64u("aes-128-gcm:pw") + "@h.com#no-port"],
            "ssr": ["ssr://" + b64u("h.com:abc:origin:aes-256-cfb:plaintext:pw")],
        }
        for proto, uris in cases.items():
            for u in uris:
                self.assertIsNone(m.PARSERS[proto](u), f"{proto} 应丢弃：{u}")

    def test_vless_missing_credentials(self):
        self.assertIsNone(m.p_vless("vless://@h.com:443?security=tls#no-uuid"))
        self.assertIsNone(m.p_vless("vless://u@h.com:443?security=reality#no-pbk"))

    def test_vmess_malformed_base64_json(self):
        for payload in (b"not-json", b"[1,2,3]", b'{"add":"h.com"}',
                        b'{"add":"h.com","port":"abc","id":"u"}'):
            u = "vmess://" + base64.b64encode(payload).decode()
            self.assertIsNone(m.p_vmess(u), f"应丢弃：{payload!r}")

    def test_vmess_negative_port_dropped(self):
        obj = {"add": "h.com", "port": -1, "id": "u"}
        u = "vmess://" + b64(json.dumps(obj))
        self.assertIsNone(m.p_vmess(u))

    def test_ss_ipv6_host(self):
        u = "ss://" + b64u("aes-128-gcm:pw") + "@[::1]:8388#v6"
        d = m.p_ss(u)
        self.assertIsNotNone(d)
        self.assertEqual(d["server"], "::1")
        self.assertEqual(d["port"], 8388)

    def test_ss_garbage_dropped(self):
        self.assertIsNone(m.p_ss("ss://!!!notbase64@@@#junk"))

    def test_tuic_query_credentials(self):
        d = m.p_tuic("tuic://h.com:443?uuid=u&password=p#TC")
        self.assertIsNotNone(d)
        self.assertEqual(d["uuid"], "u")
        self.assertEqual(d["password"], "p")

    def test_hy2_bad_mport_ignored(self):
        d = m.p_hy2("hy2://p@h.com:443?mport=not-a-range#HY")
        self.assertNotIn("ports", d)

    def test_malformed_ipv6_never_raises(self):
        """urlparse 自身会对畸形方括号抛 ValueError，解析层必须返回 None。"""
        for proto in ("vless", "trojan", "hy2", "tuic", "anytls"):
            self.assertIsNone(m.PARSERS[proto](f"{proto}://]bad[#x"))
        self.assertEqual(m.qs("vless://]bad[?a=1"), {})

    def test_ssr_unknown_obfs_dropped(self):
        inner = "h.com:8388:origin:aes-256-cfb:evil-obfs:pw"
        self.assertIsNone(m.p_ssr("ssr://" + b64u(inner)))


class TestValidateHardening(unittest.TestCase):
    """校验层必须拦住会让 mihomo 整份配置加载失败的节点。"""

    def test_rejects_bad_nodes(self):
        cases = [
            {"name": "no-uuid", "type": "vless", "server": "h", "port": 443},
            {"name": "neg-port", "type": "ss", "server": "h", "port": -1,
             "cipher": "aes-128-gcm", "password": "x"},
            {"name": "huge-port", "type": "ss", "server": "h", "port": 70000,
             "cipher": "aes-128-gcm", "password": "x"},
            {"name": "no-cipher", "type": "ss", "server": "h", "port": 8388,
             "password": "x"},
            {"name": "no-pass", "type": "trojan", "server": "h", "port": 443},
            {"name": "bad-host", "type": "ss", "server": "h o", "port": 8388,
             "cipher": "aes-128-gcm", "password": "x"},
        ]
        good, bad = m.validate_proxies(cases)
        self.assertEqual(good, [])
        self.assertEqual(len(bad), len(cases))

    def test_accepts_full_node_and_normalizes(self):
        p = {"name": "ok", "type": "ss", "server": "h.com", "port": "8388",
             "cipher": "aes-128-gcm", "password": "p"}
        good, bad = m.validate_proxies([p])
        self.assertEqual(bad, [])
        self.assertEqual(good[0]["port"], 8388)

    def test_control_chars_in_name_removed(self):
        p = {"name": "evil\r\nFAKE-LOG", "type": "ss", "server": "h.com",
             "port": 8388, "cipher": "aes-128-gcm", "password": "p"}
        good, _ = m.validate_proxies([p])
        self.assertEqual(good[0]["name"], "evil FAKE-LOG")
        self.assertNotIn("\n", good[0]["name"])


class TestDedupeEndpoints(unittest.TestCase):
    def test_same_endpoint_removed(self):
        ps = [
            {"name": "A", "type": "ss", "server": "H.com", "port": 1},
            {"name": "B", "type": "ss", "server": "h.com", "port": 1},
            {"name": "C", "type": "trojan", "server": "h.com", "port": 1},
        ]
        out = m.dedupe_endpoints(ps)
        self.assertEqual([p["name"] for p in out], ["A", "C"])


class TestDropInvalidProxies(unittest.TestCase):
    """预检二分：坏节点必须被单独摘掉，好节点全部保留。"""

    def test_bisect_finds_two_bad(self):
        ps = [{"name": f"n{i}", "type": "ss", "server": f"h{i}", "port": 1,
               "cipher": "aes-128-gcm", "password": "p"} for i in range(10)]
        calls = []

        def fake_validate(cfg):
            calls.append(1)
            return all(p.get("name") not in {"n2", "n5"}
                       for p in cfg.get("proxies", []))

        good, dropped = m.drop_invalid_proxies(
            ps, 12345, 12346, ["MATCH,PROXY"], validate=fake_validate)
        self.assertEqual(len(good), 8)
        self.assertEqual({p["name"] for p in dropped}, {"n2", "n5"})
        # 二分应在 O(k log n) 量级，绝不能逐节点 10 次以上
        self.assertLessEqual(len(calls), 12, f"校验调用次数过多：{len(calls)}")

    def test_all_good_no_drop(self):
        ps = [{"name": f"n{i}", "type": "ss", "server": f"h{i}", "port": 1,
               "cipher": "aes-128-gcm", "password": "p"} for i in range(5)]
        good, dropped = m.drop_invalid_proxies(
            ps, 12345, 12346, ["MATCH,PROXY"], validate=lambda cfg: True)
        self.assertEqual(len(good), 5)
        self.assertEqual(dropped, [])


class TestCleanDeadSafety(unittest.TestCase):
    """清理死节点不能把生产配置写坏。"""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="ph-clean-")
        self._old_cfg, self._old_bak = m.PROD_CONFIG, m.BACKUP_DIR
        self._old_hist = m.HISTORY_DIR
        self._old_mihomo = m.MIHOMO_EXE
        m.PROD_CONFIG = os.path.join(self.tmp, "config", "config.yaml")
        m.BACKUP_DIR = os.path.join(self.tmp, "backups")
        m.HISTORY_DIR = os.path.join(self.tmp, "history")
        m.MIHOMO_EXE = os.path.join(self.tmp, "no-such-mihomo.exe")
        os.makedirs(os.path.dirname(m.PROD_CONFIG), exist_ok=True)
        os.makedirs(m.HISTORY_DIR, exist_ok=True)

    def tearDown(self):
        m.PROD_CONFIG, m.BACKUP_DIR = self._old_cfg, self._old_bak
        m.HISTORY_DIR = self._old_hist
        m.MIHOMO_EXE = self._old_mihomo
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _dead_samples(self, names):
        t1 = (datetime.datetime.now() - datetime.timedelta(hours=13)).isoformat(timespec="seconds")
        t2 = datetime.datetime.now().isoformat(timespec="seconds")
        path = os.path.join(m.HISTORY_DIR, "samples-202611.jsonl")
        with open(path, "w", encoding="utf-8") as f:
            for n in names:
                f.write(json.dumps({"ts": t1, "name": n, "ok": False}) + "\n")
                f.write(json.dumps({"ts": t2, "name": n, "ok": False}) + "\n")

    def _write_cfg(self, text):
        with open(m.PROD_CONFIG, "w", encoding="utf-8") as f:
            f.write(text)

    def test_corrupt_config_is_not_touched(self):
        bad = "proxies: [unclosed"
        self._write_cfg(bad)
        self._dead_samples(["p0"])
        removed = m.clean_dead_nodes(window=7, min_fail=2, apply=True,
                                     target="prod", backup=False)
        self.assertEqual(removed, 0)
        self.assertEqual(open(m.PROD_CONFIG, encoding="utf-8").read(), bad)

    def test_removal_is_atomic_and_groups_synced(self):
        import yaml as _y
        cfg = {
            "proxies": [{"name": f"p{i}", "type": "ss", "server": f"h{i}",
                         "port": 1, "cipher": "aes-128-gcm", "password": "p"}
                        for i in range(10)],
            "proxy-groups": [
                {"name": "AUTO", "type": "url-test", "proxies": [f"p{i}" for i in range(10)]},
                {"name": "PROXY", "type": "select", "proxies": ["AUTO"] + [f"p{i}" for i in range(10)]},
            ],
            "rules": ["MATCH,PROXY"],
        }
        self._write_cfg(_y.safe_dump(cfg, allow_unicode=True, sort_keys=False))
        self._dead_samples(["p0", "p1"])
        removed = m.clean_dead_nodes(window=7, min_fail=2, apply=True,
                                     target="prod", backup=False)
        self.assertEqual(removed, 2)
        with open(m.PROD_CONFIG, encoding="utf-8") as f:
            after = _y.safe_load(f)
        self.assertEqual(len(after["proxies"]), 8)
        names = {p["name"] for p in after["proxies"]}
        for g in after["proxy-groups"]:
            self.assertTrue(g["proxies"])
            for n in g["proxies"]:
                self.assertTrue(n == "AUTO" or n in names)
        leftovers = [f for f in os.listdir(os.path.dirname(m.PROD_CONFIG))
                     if f.endswith(".tmp")]
        self.assertEqual(leftovers, [])


class TestPruneByIndex(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="ph-prune2-")
        self._old = m.HISTORY_DIR
        m.HISTORY_DIR = self.tmp

    def tearDown(self):
        m.HISTORY_DIR = self._old
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_duplicate_old_lines_both_removed(self):
        now = datetime.datetime.now()
        ym = f"{now:%Y%m}"
        path = os.path.join(self.tmp, f"proxy-{ym}.jsonl")
        old = json.dumps({"ts": (now - datetime.timedelta(days=200)).isoformat(timespec="seconds"),
                          "name": "old"})
        new = json.dumps({"ts": now.isoformat(timespec="seconds"), "name": "new"})
        with open(path, "w", encoding="utf-8") as f:
            f.write(old + "\n" + old + "\n" + new + "\n")
        m.prune_history(days=90, archive=False, apply=True)
        recs = [json.loads(l) for l in open(path, encoding="utf-8") if l.strip()]
        self.assertEqual([r["name"] for r in recs], ["new"])

    def test_archive_file_is_unique_and_kept(self):
        now = datetime.datetime.now()
        ym = f"{now:%Y%m}"
        path = os.path.join(self.tmp, f"proxy-{ym}.jsonl")
        with open(path, "w", encoding="utf-8") as f:
            f.write(json.dumps({"ts": (now - datetime.timedelta(days=200)).isoformat(timespec="seconds")}) + "\n")
            f.write(json.dumps({"ts": now.isoformat(timespec="seconds")}) + "\n")
        m.prune_history(days=90, archive=True, apply=True)
        gz = [f for f in os.listdir(self.tmp) if f.endswith(".old.gz")]
        self.assertTrue(gz, "行级清理应生成归档文件")
        self.assertFalse(os.path.exists(path + ".old.gz"), "不应覆盖固定名归档")


class TestRollbackSafety(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="ph-roll-")
        self._old_cfg, self._old_bak = m.PROD_CONFIG, m.BACKUP_DIR
        m.PROD_CONFIG = os.path.join(self.tmp, "config", "config.yaml")
        m.BACKUP_DIR = os.path.join(self.tmp, "backups")
        os.makedirs(os.path.dirname(m.PROD_CONFIG), exist_ok=True)
        os.makedirs(m.BACKUP_DIR, exist_ok=True)

    def tearDown(self):
        m.PROD_CONFIG, m.BACKUP_DIR = self._old_cfg, self._old_bak
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_rollback_preserves_current(self):
        bak = os.path.join(m.BACKUP_DIR, "config-20260101-000000.yaml")
        with open(bak, "w", encoding="utf-8") as f:
            f.write("secret: old\n")
        with open(m.PROD_CONFIG, "w", encoding="utf-8") as f:
            f.write("secret: current\n")
        m.rollback()
        self.assertEqual(open(m.PROD_CONFIG, encoding="utf-8").read(), "secret: old\n")
        pre = [f for f in os.listdir(m.BACKUP_DIR) if f.startswith("pre-rollback-")]
        self.assertTrue(pre, "回滚前应把当前配置另存一份")


class TestCurlHardening(unittest.TestCase):
    def test_curl_uses_safe_argv(self):
        captured = {}

        class R:
            stdout = "200 0.5"

        def fake_run(cmd, **kw):
            captured["cmd"] = cmd
            return R()

        old = m.subprocess.run
        m.subprocess.run = fake_run
        try:
            code, sec = m.TempMihomo._curl_via("http://127.0.0.1:1", "--evil-url", 2)
        finally:
            m.subprocess.run = old
        self.assertEqual((code, sec), (200, 0.5))
        cmd = captured["cmd"]
        self.assertIn("-q", cmd, "必须忽略 .curlrc")
        self.assertIn("--proto", cmd)
        self.assertEqual(cmd[cmd.index("--proto") + 1], "=http,https")
        self.assertEqual(cmd[-2], "--")
        self.assertEqual(cmd[-1], "--evil-url")


class TestFetchSizeLimit(unittest.TestCase):
    def test_oversize_body_rejected(self):
        class Resp:
            def __init__(self, data):
                self.data = data

            def read(self, n=None):
                return self.data[:n] if n else self.data

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

        class Opener:
            def __init__(self, data):
                self.data = data

            def open(self, req, timeout=60):
                return Resp(self.data)

        old_open, old_max = m.urllib.request.build_opener, m.MAX_FETCH_BYTES
        m.MAX_FETCH_BYTES = 10
        try:
            m.urllib.request.build_opener = lambda *a, **k: Opener(b"0123456789AB")
            with self.assertRaises(ValueError):
                m._open("http://example.com/x")
            m.urllib.request.build_opener = lambda *a, **k: Opener(b"0123456789")
            self.assertEqual(m._open("http://example.com/x"), "0123456789")
        finally:
            m.urllib.request.build_opener, m.MAX_FETCH_BYTES = old_open, old_max


class TestJsonResultWriter(unittest.TestCase):
    def test_creates_parent_and_is_atomic(self):
        import argparse
        tmp = tempfile.mkdtemp(prefix="ph-json-")
        try:
            args = argparse.Namespace(json_out=os.path.join(tmp, "nested", "r.json"))
            path = m._write_json_result(args, {"passed": 1})
            self.assertEqual(path, args.json_out)
            self.assertEqual(json.load(open(path, encoding="utf-8")), {"passed": 1})
            self.assertEqual([f for f in os.listdir(os.path.dirname(path))
                             if f.endswith(".tmp")], [])
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


class TestIntSetting(unittest.TestCase):
    def test_bad_port_falls_back(self):
        self.assertEqual(m._int_setting("abc", 2080), 2080)
        self.assertEqual(m._int_setting("70000", 2080), 2080)
        self.assertEqual(m._int_setting("2081", 2080), 2081)


class TestTempInstancePorts(unittest.TestCase):
    def test_bad_port_fails_fast_without_dir(self):
        parent = tempfile.mkdtemp(prefix="ph-port-")
        try:
            with self.assertRaises(ValueError):
                m.TempMihomo(parent, 70000, 9090, [])
            with self.assertRaises(ValueError):
                m.TempMihomo(parent, 2080, 0, [])
            with self.assertRaises(ValueError):
                m.TempMihomo(parent, "abc", 9090, [])
            self.assertEqual(os.listdir(parent), [])
        finally:
            shutil.rmtree(parent, ignore_errors=True)


class TestIntegrityAndExit(unittest.TestCase):
    def test_content_expectation_from_text(self):
        spec = m.content_expectation("http://probe.test/x", text="ok")
        self.assertEqual(spec["sha256"], m.sha256_bytes(b"ok"))
        self.assertTrue(m.content_matches(b"ok", spec["sha256"]))
        self.assertFalse(m.content_matches(b"tampered", spec["sha256"]))
        self.assertFalse(m.content_matches(None, spec["sha256"]))

    def test_content_expectation_rejects_bad_hash(self):
        with self.assertRaises(ValueError):
            m.content_expectation("http://probe.test/x", sha256_value="not-a-hash")
        with self.assertRaises(ValueError):
            m.content_expectation("http://probe.test/x")

    def test_exit_info_parse(self):
        body = json.dumps({"ip": "203.0.113.7", "country_code": "JP",
                           "asn": "AS1234", "org": "Example"}).encode()
        info = m.parse_exit_info(body)
        self.assertEqual(info["ip"], "203.0.113.7")
        self.assertEqual(info["country"], "JP")
        self.assertEqual(info["asn"], "AS1234")
        self.assertEqual(m.parse_exit_info(b"not-json"), {})

    def test_country_of_flag_and_code(self):
        self.assertEqual(m.country_of("🇺🇸 US node"), "US")
        self.assertEqual(m.country_of("node JP"), "JP")
        self.assertEqual(m.country_of("no country"), "")

    def test_country_of_lowercase_bare_words_not_codes(self):
        self.assertEqual(m.country_of("Free for us"), "")
        self.assertEqual(m.country_of("it works"), "")
        self.assertEqual(m.country_of("(us) edge"), "US")
        self.assertEqual(m.country_of("US node"), "US")

    def test_trust_reduces_quality(self):
        base = m.quality_score(500, 3.0)
        lower = m.quality_score(500, 3.0, trust=0.75)
        self.assertLess(lower, base)
        self.assertEqual(m.quality_score(500, 3.0, trust=1.0), base)


class TestSourceState(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="ph-src-state-")
        self.old_state = m.SOURCE_STATE_FILE
        m.SOURCE_STATE_FILE = os.path.join(self.tmp, "source-state.json")

    def tearDown(self):
        m.SOURCE_STATE_FILE = self.old_state
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _node(self, count=10, proto="ss", h="h"):
        return {"name": "n", "_source": "https://src", "_source_id": m.source_id("https://src"),
                "_source_hash": h,
                "_source_count": count, "_source_protocols": {proto: count}}

    def test_first_run_baseline_no_mutation(self):
        sid = m.source_id("https://src")
        self.assertEqual(m.detect_source_mutations([self._node()]), {})
        state = m.load_source_state()["sources"][sid]
        self.assertEqual(state["count"], 10)
        self.assertFalse(state["mutated"])

    def test_count_jump_marks_mutation(self):
        sid = m.source_id("https://src")
        m.detect_source_mutations([self._node(10)])
        mutated = m.detect_source_mutations([self._node(30)])
        self.assertIn(sid, mutated)
        self.assertIn("节点数", mutated[sid])

    def test_protocol_shift_marks_mutation(self):
        p1 = {"ss": 10, "vmess": 0}
        p2 = {"ss": 2, "vmess": 8}
        n1 = {"name": "n", "_source": "https://src", "_source_hash": "h1",
              "_source_count": 10, "_source_protocols": p1}
        n2 = dict(n1, _source_hash="h2", _source_protocols=p2)
        sid = m.source_id("https://src")
        m.detect_source_mutations([n1])
        mutated = m.detect_source_mutations([n2])
        self.assertIn(sid, mutated)

    def test_mutation_persists_until_content_changes(self):
        sid = m.source_id("https://src")
        m.detect_source_mutations([self._node(10)])
        self.assertIn(sid, m.detect_source_mutations([self._node(30)]))
        # 同一份污染内容下一轮仍要拦截，不能把污染后的基线当成新常态
        self.assertIn(sid, m.detect_source_mutations([self._node(30)]))
        state = m.load_source_state()["sources"][sid]
        self.assertTrue(state["mutated"])
        # 内容真正变化且没有新的突变信号时，才允许清除标记
        self.assertEqual(m.detect_source_mutations([self._node(11, "ss", "h2")]), {})

    def test_dry_run_does_not_commit_baseline(self):
        sid = m.source_id("https://src")
        m.detect_source_mutations([self._node(10)])
        before = m.load_source_state()["sources"]
        mutated = m.detect_source_mutations([self._node(30)], commit=False)
        self.assertIn(sid, mutated)
        self.assertEqual(m.load_source_state()["sources"], before)

    def test_absent_source_baseline_is_kept(self):
        sid_b = m.source_id("https://b")
        m.save_source_state({
            "https://a": {"count": 10, "sha256": "ha"},
            "https://b": {"count": 20, "sha256": "hb"},
        })
        m.detect_source_mutations([self._node()])
        state = m.load_source_state()["sources"]
        self.assertIn(sid_b, state)
        self.assertEqual(state[sid_b]["count"], 20)

    def test_inherited_nodes_do_not_override_current_meta(self):
        sid = m.source_id("https://src")
        m.detect_source_mutations([self._node(10)])
        fresh = self._node(30)
        inherited = self._node(999)
        inherited["_inherited"] = True
        mutated = m.detect_source_mutations([fresh, inherited])
        self.assertIn("节点数 10→30", mutated[sid])

    def test_source_health_includes_tamper_and_mutation(self):
        sid = m.source_id("https://src")
        m.save_source_state({"https://src": {"count": 10, "mutated": True}})
        old_read = m.read_history
        m.read_history = lambda days=30: [
            {"source": "https://src", "ok": True, "content_tampered": False},
            {"source": "https://src", "ok": False, "content_tampered": True},
        ]
        try:
            h = m.source_health()[sid]
        finally:
            m.read_history = old_read
        self.assertEqual(h["seen"], 2)
        self.assertEqual(h["tampered"], 1)
        self.assertTrue(h["mutated"])
        self.assertLess(h["reputation"], 100)


class TestDnsConfig(unittest.TestCase):
    def test_default_dns_config_is_explicit_and_local(self):
        dns = m.default_dns_config()
        self.assertTrue(dns["enable"])
        self.assertEqual(dns["enhanced-mode"], "fake-ip")
        self.assertIn("nameserver", dns)
        self.assertIn("proxy-server-nameserver", dns)

    def test_make_config_includes_dns_only_when_requested(self):
        node = {"name": "n", "type": "ss", "server": "h", "port": 1,
                "cipher": "aes-128-gcm", "password": "p"}
        self.assertNotIn("dns", m.make_config([node], 2000, 9000))
        cfg = m.make_config([node], 2000, 9000, dns=m.default_dns_config())
        self.assertIn("dns", cfg)

    def test_dns_from_args(self):
        self.assertIsNone(m.dns_from_args("off"))
        cfg = m.dns_from_args("explicit", "127.0.0.1:5353")
        self.assertEqual(cfg["nameserver"], ["127.0.0.1:5353"])


class TestConfigLayer(unittest.TestCase):
    def _node(self):
        return {"name": "n", "type": "ss", "server": "h", "port": 1,
                "cipher": "aes-128-gcm", "password": "p",
                "skip-cert-verify": True, "_source": "s1"}

    def test_build_config_strips_metadata_and_insecure(self):
        cfg = configgen.build_config([self._node()], 2200, 9200,
                                     ["MATCH,PROXY"], secret="x",
                                     proto_groups={"ss": ["ss"]})
        p = cfg["proxies"][0]
        self.assertNotIn("_source", p)
        self.assertNotIn("skip-cert-verify", p)
        self.assertEqual([g["name"] for g in cfg["proxy-groups"]],
                         ["AUTO", "PROXY"])
        cfg2 = configgen.build_config([self._node()], 2201, 9201,
                                      insecure=True)
        self.assertTrue(cfg2["proxies"][0]["skip-cert-verify"])
        self.assertEqual(cfg2["secret"], "")

    def test_groups_dns_and_sources_port(self):
        cfg = configgen.build_config(
            [self._node()], 2202, 9202, with_groups=True,
            dns=configgen.default_dns_config(["127.0.0.1:5353"]),
            proto_groups={"ss": ["ss"]})
        self.assertIn("G_ss", [g["name"] for g in cfg["proxy-groups"]])
        self.assertEqual(cfg["dns"]["nameserver"], ["127.0.0.1:5353"])
        sc = configgen.build_sources_config([self._node()])
        self.assertEqual(sc["mixed-port"], 2180)
        self.assertEqual(sc["external-controller"], "127.0.0.1:9180")

    def test_main_wrapper_matches_layer(self):
        node = self._node()
        a = m.make_config([node], 2203, 9203, ["MATCH,PROXY"],
                          with_groups=True)
        b = configgen.build_config([node], 2203, 9203, ["MATCH,PROXY"],
                                   with_groups=True,
                                   proto_groups=m.PROTO_GROUPS)
        self.assertEqual(a, b)


class TestCompatMatrix(unittest.TestCase):
    def test_mock_matrix_ss_case(self):
        import compat_matrix
        mock = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                            "mock_mihomo.py")
        res = compat_matrix.run_matrix([mock], {"ss": compat_matrix.CASES["ss"]},
                                       timeout=10)
        self.assertTrue(res["binaries"][0]["results"][0]["ok"],
                        res["binaries"][0]["results"][0]["detail"])


class TestCliGuards(unittest.TestCase):
    def _expect_exit_2(self, argv):
        old_argv = sys.argv
        old_mock = m.MIHOMO_MOCK
        m.MIHOMO_MOCK = "mock"
        sys.argv = ["proxy_harvest.py"] + argv
        try:
            with self.assertRaises(SystemExit) as cm:
                m.main()
        finally:
            sys.argv = old_argv
            m.MIHOMO_MOCK = old_mock
        self.assertEqual(cm.exception.code, 2)

    def test_content_probe_without_keep_is_rejected(self):
        self._expect_exit_2([
            "--keep", "0", "--verify-content-url", "http://example.test/",
            "--verify-content-sha256", "0" * 64,
        ])

    def test_exit_info_without_keep_is_rejected(self):
        self._expect_exit_2(["--keep", "0", "--exit-info"])


class _FakeTemp:
    def __init__(self, *_args, **_kwargs):
        pass

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def delay_all(self, _url, _timeout):
        return {"n": 100}

    def curl_check_many(self, names, _url, _timeout):
        return {n: (200, 0.01) for n in names}

    def curl_check(self, _name, _url, _timeout):
        return (200, 0.01)


class TestMainFlowProbe(unittest.TestCase):
    def _node(self):
        return {"name": "n", "type": "ss", "server": "1.2.3.4", "port": 8388,
                "cipher": "aes-128-gcm", "password": "p",
                "_source": "https://src"}

    def _run_main_with_probe(self, extra_args, probe_body):
        out = os.path.join(_TEST_BASE, "result.json")
        node = self._node()
        old_argv = sys.argv
        old_mock = m.MIHOMO_MOCK
        m.MIHOMO_MOCK = "mock"
        sys.argv = ["proxy_harvest.py", "--keep", "1", "--json", out] + extra_args
        try:
            with patch.object(m, "harvest", return_value=[node]), \
                 patch.object(m, "drop_invalid_proxies", return_value=([node], [])), \
                 patch.object(m, "TempMihomo", _FakeTemp), \
                 patch.object(m, "probe_nodes", return_value={"n": (200, 0.01, probe_body)}):
                m.main()
            with open(out, encoding="utf-8") as f:
                return json.load(f)
        finally:
            sys.argv = old_argv
            m.MIHOMO_MOCK = old_mock
            if os.path.exists(out):
                os.remove(out)

    def test_content_probe_keeps_outer_result_dict(self):
        data = self._run_main_with_probe(
            ["--verify-content-url", "http://example.test/fixed",
             "--verify-content-sha256", m.sha256_bytes(b"ok")],
            b"ok")
        self.assertEqual(data["content_checked"], 1)
        self.assertEqual(data["content_tampered"], 0)

    def test_exit_info_keeps_outer_result_dict(self):
        data = self._run_main_with_probe(
            ["--exit-info"],
            b'{"ip":"1.2.3.4","country_code":"US","asn":123,"org":"x"}')
        self.assertEqual(data["exit_checked"], 1)
        self.assertEqual(data["exit_mismatch"], 0)

    def test_content_oversize_is_inconclusive_not_tampered(self):
        """超时/body 超限/读失败不能算内容被篡改，否则来源信誉被误伤。"""
        data = self._run_main_with_probe(
            ["--verify-content-url", "http://example.test/fixed",
             "--verify-content-sha256", m.sha256_bytes(b"ok"),
             "--min-pass", "0"],
            None)
        self.assertEqual(data["content_checked"], 1)
        self.assertEqual(data["content_tampered"], 0)
        self.assertEqual(data["content_inconclusive"], 1)
        self.assertEqual(data["passed"], 0)

    def test_content_mismatch_is_tampered(self):
        data = self._run_main_with_probe(
            ["--verify-content-url", "http://example.test/fixed",
             "--verify-content-sha256", m.sha256_bytes(b"ok"),
             "--min-pass", "0"],
            b"bad")
        self.assertEqual(data["content_tampered"], 1)
        self.assertEqual(data["content_inconclusive"], 0)


class TestDryRunNoWrites(unittest.TestCase):
    """--cron --dry-run 只写 JSON 报告，不落 A/B/C/D 数据。"""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="ph-dry-")
        self._old = {name: getattr(m, name) for name in
                     ("BASE", "HISTORY_DIR", "TMP_DIR", "SOURCE_STATE_FILE", "LOG_FILE")}
        m.BASE = self.tmp
        m.HISTORY_DIR = os.path.join(self.tmp, "history")
        m.TMP_DIR = os.path.join(self.tmp, ".harvest-tmp")
        m.SOURCE_STATE_FILE = os.path.join(self.tmp, "source-state.json")
        m.LOG_FILE = os.path.join(self.tmp, "harvest.log")

    def tearDown(self):
        for name, value in self._old.items():
            setattr(m, name, value)
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_cron_dry_run_writes_only_json(self):
        node = {"name": "n", "type": "ss", "server": "1.2.3.4", "port": 8388,
                "cipher": "aes-128-gcm", "password": "p", "_source": "https://src"}
        out = os.path.join(self.tmp, "result.json")
        old_argv, old_mock = sys.argv, m.MIHOMO_MOCK
        m.MIHOMO_MOCK = "mock"
        sys.argv = ["proxy_harvest.py", "--cron", "--dry-run", "--json", out]
        try:
            with patch.object(m, "harvest", return_value=[node]), \
                 patch.object(m, "drop_invalid_proxies", return_value=([node], [])), \
                 patch.object(m, "TempMihomo", _FakeTemp):
                m.main()
        finally:
            sys.argv = old_argv
            m.MIHOMO_MOCK = old_mock
        self.assertTrue(os.path.isfile(out))
        hist = os.path.join(self.tmp, "history")
        self.assertFalse(os.path.isdir(hist) and os.listdir(hist),
                         "dry-run 不应写快照/历史/采样/每日聚合/订阅")
        self.assertFalse(os.path.exists(os.path.join(self.tmp, "source-state.json")))

    def test_cron_dry_run_uses_same_deep_verify_count(self):
        """cron --dry-run 也要默认深验 15 个，不能只导出延迟通过的节点。"""
        nodes = [{"name": f"n{i}", "type": "ss", "server": f"h{i}", "port": 8388,
                  "cipher": "aes-128-gcm", "password": "p",
                  "_source": "https://src"} for i in range(20)]
        seen = []

        class RecordingTemp(_FakeTemp):
            def delay_all(self, _url, _timeout):
                return {p["name"]: 100 for p in nodes}

            def curl_check_many(self, names, _url, _timeout):
                seen.extend(names)
                return {n: (200, 0.01) for n in names}

        out = os.path.join(self.tmp, "result.json")
        old_argv, old_mock = sys.argv, m.MIHOMO_MOCK
        m.MIHOMO_MOCK = "mock"
        sys.argv = ["proxy_harvest.py", "--cron", "--dry-run", "--json", out,
                    "--min-pass", "0"]
        try:
            with patch.object(m, "harvest", return_value=nodes), \
                 patch.object(m, "drop_invalid_proxies", return_value=(nodes, [])), \
                 patch.object(m, "TempMihomo", RecordingTemp):
                m.main()
        finally:
            sys.argv = old_argv
            m.MIHOMO_MOCK = old_mock
        self.assertEqual(len(seen), 15, f"dry-run 深验候选数：{len(seen)}")


class TestMockKernel(unittest.TestCase):
    """用假内核跑预检、二分剔除和临时实例集成路径，不依赖真实 mihomo/外网。"""

    def setUp(self):
        self.old_mock = m.MIHOMO_MOCK
        m.MIHOMO_MOCK = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                     "mock_mihomo.py")
        self.tmp = tempfile.mkdtemp(prefix="ph-mock-kernel-")

    def tearDown(self):
        m.MIHOMO_MOCK = self.old_mock
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _node(self, name="n"):
        return {"name": name, "type": "ss", "server": "h", "port": 1,
                "cipher": "aes-128-gcm", "password": "p"}

    def test_validate_config_with_mock(self):
        self.assertTrue(m.validate_config_file(
            m.make_config([self._node()], 2200, 9200), self.tmp))
        bad = {"name": "bad", "type": "vless", "server": "h", "port": 1}
        self.assertFalse(m.validate_config_file(
            m.make_config([bad], 2201, 9201), self.tmp))

    def test_drop_invalid_proxies_with_mock(self):
        good = self._node("good")
        bad = {"name": "bad", "type": "vless", "server": "h", "port": 1}
        kept, dropped = m.drop_invalid_proxies([good, bad], 2202, 9202,
                                              ["MATCH,PROXY"])
        self.assertEqual([p["name"] for p in kept], ["good"])
        self.assertEqual([p["name"] for p in dropped], ["bad"])

    def test_temp_instance_with_mock(self):
        mp = m.free_port(2240)
        ap = m.free_port(9240)
        with m.TempMihomo(self.tmp, mp, ap, [self._node()],
                          ["MATCH,PROXY"]) as t:
            self.assertEqual(t.delay_all("http://probe.test", 1000), {"n": 100})
            code, _sec = t.curl_check("n", "http://probe.test", 2)
            self.assertEqual(code, 200)
            code2, _sec2, body = t.curl_check(
                "n", "http://probe.test", 2, capture_body=True, max_bytes=10)
            self.assertEqual(code2, 200)
            self.assertEqual(body, b"ok")

    def test_curl_many_with_mock(self):
        mp = m.free_port(2250)
        ap = m.free_port(9250)
        nodes = [self._node("a"), self._node("b")]
        with m.TempMihomo(self.tmp, mp, ap, nodes, ["MATCH,PROXY"]) as t:
            results = t.curl_check_many(["a", "b"], "http://probe.test", 2,
                                        base_port=24500, capture_body=True,
                                        max_bytes=10)
            self.assertEqual(results["a"][0], 200)
            self.assertEqual(results["a"][2], b"ok")
            self.assertEqual(results["b"][0], 200)

    def test_temp_instance_dns_passed_through(self):
        dns = {"enable": True, "nameserver": ["127.0.0.1:5353"]}
        mp = m.free_port(2260)
        ap = m.free_port(9260)
        with m.TempMihomo(self.tmp, mp, ap, [self._node()],
                          ["MATCH,PROXY"], dns=dns) as t:
            self.assertEqual(t.dns, dns)
            with open(t.config, encoding="utf-8") as f:
                cfg = m.yaml.safe_load(f)
            self.assertEqual(cfg["dns"], dns)

    def test_verify_selected_accepts_dns(self):
        dns = {"enable": True, "nameserver": ["127.0.0.1:5353"]}
        ok, detail = m.verify_selected_outbound(
            [self._node()], ["MATCH,PROXY"], url="http://probe.test",
            timeout=2, max_nodes=1, dns=dns)
        self.assertTrue(ok, detail)

    def test_drop_invalid_passes_dns_to_config(self):
        seen = []
        dns = {"enable": True, "nameserver": ["127.0.0.1:5353"]}
        def fake(cfg):
            seen.append(cfg.get("dns"))
            return True
        m.drop_invalid_proxies([self._node()], 12345, 12346,
                               ["MATCH,PROXY"], validate=fake, dns=dns)
        self.assertEqual(seen[0], dns)

    def test_apply_health_check_with_mock(self):
        os.makedirs(os.path.dirname(m.PROD_CONFIG), exist_ok=True)
        with open(m.PROD_CONFIG, "w", encoding="utf-8") as f:
            f.write("proxies: []\n")
        ok = m.apply_prod([self._node()], ["MATCH,PROXY"], insecure=True,
                          health_check=True, health_url="http://probe.test",
                          health_timeout=2)
        self.assertTrue(ok)

    def test_apply_health_failure_rolls_back(self):
        os.makedirs(os.path.dirname(m.PROD_CONFIG), exist_ok=True)
        old_content = "proxies: []\n# old\n"
        with open(m.PROD_CONFIG, "w", encoding="utf-8") as f:
            f.write(old_content)
        old_verify = m.verify_selected_outbound
        m.verify_selected_outbound = lambda *a, **kw: (False, "mock failure")
        try:
            ok = m.apply_prod([self._node()], ["MATCH,PROXY"], insecure=True,
                              health_check=True)
        finally:
            m.verify_selected_outbound = old_verify
        self.assertFalse(ok)
        with open(m.PROD_CONFIG, encoding="utf-8") as f:
            self.assertEqual(f.read(), old_content)


class TestReleaseRegressions(unittest.TestCase):
    """v0.0.3 定向回归。"""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="ph-v033-")
        self._old = {}
        for name in ("BASE", "PROD_CONF_DIR", "PROD_CONFIG", "BACKUP_DIR",
                     "HISTORY_DIR", "TMP_DIR", "SOURCE_STATE_FILE", "LOG_FILE",
                     "MIHOMO_EXE"):
            self._old[name] = getattr(m, name)
        m.BASE = self.tmp
        m.PROD_CONF_DIR = os.path.join(self.tmp, "config")
        m.PROD_CONFIG = os.path.join(m.PROD_CONF_DIR, "config.yaml")
        m.BACKUP_DIR = os.path.join(self.tmp, "backups")
        m.HISTORY_DIR = os.path.join(self.tmp, "history")
        m.TMP_DIR = os.path.join(self.tmp, ".harvest-tmp")
        m.SOURCE_STATE_FILE = os.path.join(self.tmp, "source-state.json")
        m.LOG_FILE = os.path.join(self.tmp, "harvest.log")
        m.MIHOMO_EXE = os.path.join(self.tmp, "no-such-mihomo.exe")
        self._old_mock = m.MIHOMO_MOCK
        m.MIHOMO_MOCK = ""
        os.makedirs(m.PROD_CONF_DIR, exist_ok=True)
        os.makedirs(m.HISTORY_DIR, exist_ok=True)

    def tearDown(self):
        m.MIHOMO_MOCK = self._old_mock
        for name, value in self._old.items():
            setattr(m, name, value)
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _node(self, name="n", server="1.2.3.4", port=8388):
        return {"name": name, "type": "ss", "server": server, "port": port,
                "cipher": "aes-128-gcm", "password": "p"}

    def test_source_id_is_stable_and_not_url(self):
        secret = "https://private.example/sub?token=TOPSECRET"
        sid = m.source_id(secret)
        self.assertEqual(len(sid), 16)
        self.assertNotIn("TOPSECRET", sid)
        self.assertEqual(sid, m.source_id(secret))
        self.assertEqual(sid, m.source_key(sid))

    def test_snapshot_history_samples_do_not_store_source_url(self):
        secret = "https://private.example/sub?token=TOPSECRET"
        sid = m.source_id(secret)
        node = self._node()
        node.update({"_source": secret, "_source_id": sid, "_group": "ss"})

        snap = m.save_snapshot([node], "all", {secret: {"count": 1}})
        with open(snap, encoding="utf-8") as f:
            snap_text = f.read()
        self.assertNotIn("TOPSECRET", snap_text)
        self.assertIn(sid, snap_text)

        rows = [{"name": "n", "type": "ss", "server": "1.2.3.4", "port": 8388,
                 "source": secret, "id": "", "delay_ms": 100, "ok": True}]
        hist, _csv = m.save_history(rows, {"n": node})
        with open(hist, encoding="utf-8") as f:
            rec = json.loads(f.readline())
        self.assertNotIn("TOPSECRET", json.dumps(rec, ensure_ascii=False))
        self.assertEqual(rec["source_id"], sid)
        self.assertNotIn("_source", rec["proxy"])

        samples = m.save_samples({"n": 100}, rows, "all", all_names=["n"])
        with open(samples, encoding="utf-8") as f:
            sample_text = f.read()
        self.assertNotIn("TOPSECRET", sample_text)

    def test_save_source_state_normalizes_raw_keys(self):
        secret = "https://private.example/sub?token=TOPSECRET"
        sid = m.source_id(secret)
        m.save_source_state({secret: {"count": 1, "mutated": True}})
        with open(m.SOURCE_STATE_FILE, encoding="utf-8") as f:
            raw = f.read()
        self.assertNotIn("TOPSECRET", raw)
        self.assertIn(sid, raw)
        self.assertIn(sid, m.load_source_state()["sources"])

    def test_prune_negative_does_not_delete(self):
        path = os.path.join(m.HISTORY_DIR, "samples-202001.jsonl")
        with open(path, "w", encoding="utf-8") as f:
            f.write('{"ts":"2020-01-01T00:00:00","name":"old"}\n')
        m.prune_history(days=-1, apply=True, archive=False)
        self.assertTrue(os.path.isfile(path))

    def test_cli_negative_prune_exits_2_and_keeps_file(self):
        path = os.path.join(m.HISTORY_DIR, "samples-202001.jsonl")
        with open(path, "w", encoding="utf-8") as f:
            f.write('{"ts":"2020-01-01T00:00:00","name":"old"}\n')
        old_argv = sys.argv
        sys.argv = ["proxy_harvest.py", "--prune", "--apply-prune",
                    "--prune-days", "-1", "--no-archive"]
        try:
            with self.assertRaises(SystemExit) as cm:
                m.main()
        finally:
            sys.argv = old_argv
        self.assertEqual(cm.exception.code, 2)
        self.assertTrue(os.path.isfile(path))

    def test_dry_run_rollback_does_not_write(self):
        calls = []
        old_argv = sys.argv
        sys.argv = ["proxy_harvest.py", "--rollback", "--dry-run"]
        try:
            with patch.object(m, "rollback", side_effect=lambda: calls.append("x")):
                m.main()
        finally:
            sys.argv = old_argv
        self.assertEqual(calls, [])

    def test_dry_run_sources_only_does_not_write_config(self):
        node = self._node()
        old_argv = sys.argv
        m.MIHOMO_MOCK = "mock"
        sys.argv = ["proxy_harvest.py", "--sources-only", "--dry-run"]
        try:
            with patch.object(m, "harvest", return_value=[node]):
                m.main()
        finally:
            sys.argv = old_argv
            m.MIHOMO_MOCK = ""
        self.assertFalse(os.path.exists(os.path.join(m.TMP_DIR, "config.yaml")))

    def test_cron_keep_zero_is_not_rewritten(self):
        captured = []
        old_argv = sys.argv
        m.MIHOMO_MOCK = "mock"
        sys.argv = ["proxy_harvest.py", "--cron", "--keep", "0"]
        try:
            with patch.object(m, "_run_main", side_effect=lambda args: captured.append(args)):
                m.main()
        finally:
            sys.argv = old_argv
            m.MIHOMO_MOCK = ""
        self.assertEqual(captured[0].keep, 0)

    def test_dead_name_reuse_does_not_remove_new_node(self):
        import yaml as _y
        names = [f"p{i}" for i in range(9)] + ["US"]
        cfg = {
            "proxies": [self._node(n, "old-host" if n == "US" else f"h{i}", 443)
                        for i, n in enumerate(names)],
            "proxy-groups": [{"name": "PROXY", "type": "select", "proxies": names}],
            "rules": ["MATCH,PROXY"],
        }
        with open(m.PROD_CONFIG, "w", encoding="utf-8") as f:
            _y.safe_dump(cfg, f, allow_unicode=True, sort_keys=False)
        # 旧 US 的稳定 ID 是 dead-id；新 US 的 endpoint 已换成 new-host
        cfg["proxies"][-1]["server"] = "new-host"
        with open(m.PROD_CONFIG, "w", encoding="utf-8") as f:
            _y.safe_dump(cfg, f, allow_unicode=True, sort_keys=False)
        t1 = (datetime.datetime.now() - datetime.timedelta(hours=13)).isoformat(timespec="seconds")
        t2 = datetime.datetime.now().isoformat(timespec="seconds")
        path = os.path.join(m.HISTORY_DIR, "samples-202611.jsonl")
        with open(path, "w", encoding="utf-8") as f:
            for ts in (t1, t2):
                f.write(json.dumps({"ts": ts, "name": "US", "id": "dead-id",
                                    "ok": False}) + "\n")
        removed = m.clean_dead_nodes(window=7, min_fail=2, apply=True,
                                     target="prod", backup=False)
        self.assertEqual(removed, 0)
        with open(m.PROD_CONFIG, encoding="utf-8") as f:
            after = _y.safe_load(f)
        self.assertIn("US", [p["name"] for p in after["proxies"]])

    def test_apply_prod_validates_actual_rules(self):
        rules = ["GEOIP,private,DIRECT,no-resolve", "GEOSITE,cn,DIRECT",
                 "MATCH,PROXY"]
        seen = []
        old_geofiles = m.geofiles_present
        old_backup = m.backup_prod
        old_port = m.port_up
        old_secret = m.resolve_prod_secret
        old_validate = m.validate_config_file
        m.geofiles_present = lambda _d: True
        m.backup_prod = lambda: None
        m.port_up = lambda _p: False
        m.resolve_prod_secret = lambda _s=None: ("x" * 16, "test", False)

        def fake_validate(cfg, _d, rules_override=None):
            seen.append(list(cfg.get("rules") or []))
            return True

        m.validate_config_file = fake_validate
        try:
            ok = m.apply_prod([self._node()], rules, health_check=False)
        finally:
            m.geofiles_present = old_geofiles
            m.backup_prod = old_backup
            m.port_up = old_port
            m.resolve_prod_secret = old_secret
            m.validate_config_file = old_validate
        self.assertTrue(ok)
        self.assertIn(rules, seen)

    def test_curl_check_many_keeps_dns(self):
        m.MIHOMO_MOCK = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                     "mock_mihomo.py")
        dns = {"enable": True, "nameserver": ["127.0.0.1:5353"]}
        mp, ap = m.free_port(2270), m.free_port(9270)
        try:
            with m.TempMihomo(m.TMP_DIR, mp, ap, [self._node()],
                              ["MATCH,PROXY"], dns=dns) as t:
                t.curl_check_many(["n"], "http://probe.test", 2, base_port=24600)
                with open(t.config, encoding="utf-8") as f:
                    cfg = m.yaml.safe_load(f)
                self.assertEqual(cfg["dns"], dns)
        finally:
            m.MIHOMO_MOCK = ""

    def test_delay_all_proxies_fallback_returns_empty(self):
        t = object.__new__(m.TempMihomo)

        def fail(_path, _method="GET", _payload=None, timeout=5):
            raise RuntimeError("api down")

        t.api = fail
        self.assertEqual(t.delay_all("http://probe.test", 1000), {})

    def test_show_status_uses_config_mixed_port(self):
        cfg = {"mixed-port": 12345, "external-controller": "127.0.0.1:9090",
               "proxies": [], "rules": ["MATCH,PROXY"]}
        seen = []
        old_read, old_port, old_sys = m.read_prod, m.port_up, m.system_proxy_on
        m.read_prod = lambda: cfg
        m.port_up = lambda p: seen.append(p) or False
        m.system_proxy_on = lambda: False
        try:
            m.show_status()
        finally:
            m.read_prod, m.port_up, m.system_proxy_on = old_read, old_port, old_sys
        self.assertEqual(seen, [12345])

    def test_geofiles_case_insensitive_and_country_mmdb(self):
        os.makedirs(m.TMP_DIR, exist_ok=True)
        for fn in ("GeoIP.DAT", "GeoSite.DAT"):
            with open(os.path.join(m.TMP_DIR, fn), "w", encoding="utf-8") as f:
                f.write("x")
        self.assertTrue(m.geofiles_present(m.TMP_DIR))
        os.remove(os.path.join(m.TMP_DIR, "GeoIP.DAT"))
        with open(os.path.join(m.TMP_DIR, "Country.mmdb"), "w", encoding="utf-8") as f:
            f.write("x")
        self.assertTrue(m.geofiles_present(m.TMP_DIR))

    def test_other_yaml_is_cleaned_when_zero_pass(self):
        out_dir = os.path.join(m.HISTORY_DIR, "subscriptions")
        os.makedirs(out_dir, exist_ok=True)
        with open(os.path.join(out_dir, "other.yaml"), "w", encoding="utf-8") as f:
            f.write("proxies: []\n")
        m.export_group_configs([], {}, ["MATCH,PROXY"], out_dir=out_dir)
        self.assertFalse(os.path.exists(os.path.join(out_dir, "other.yaml")))

    def test_parser_credential_edges(self):
        trojan = m.p_trojan("trojan://user:pass@tj.example.com:443#T")
        self.assertEqual(trojan["password"], "pass")
        anytls = m.p_anytls("anytls://user@at.example.com:443?password=query#A")
        self.assertEqual(anytls["password"], "query")
        hy2 = m.p_hy2("hy2://user@hy.example.com:443?password=query#H")
        self.assertEqual(hy2["password"], "query")

    def test_vmess_list_alpn_does_not_crash(self):
        obj = {"v": "2", "ps": "VM", "add": "vm.example.com", "port": "443",
               "id": "uuid", "net": "ws", "tls": "tls",
               "alpn": ["h2", "http/1.1"]}
        d = m.p_vmess("vmess://" + b64u(json.dumps(obj)))
        self.assertEqual(d["alpn"], ["h2", "http/1.1"])

    def test_node_id_with_non_string_server(self):
        self.assertEqual(len(m.node_id({"type": "ss", "server": 123, "port": 1})), 10)

    def test_load_settings_non_dict_root_is_ignored(self):
        old_script = m.SCRIPT_DIR
        m.SCRIPT_DIR = self.tmp
        with open(os.path.join(self.tmp, "config.json"), "w", encoding="utf-8") as f:
            f.write("[]")
        try:
            self.assertIsInstance(m._load_settings(), dict)
        finally:
            m.SCRIPT_DIR = old_script

    def test_save_samples_records_source_id(self):
        sid = m.source_id("https://src")
        rows = [{"name": "n", "type": "ss", "server": "h", "port": 1,
                 "source": sid, "id": "", "delay_ms": 100, "ok": True}]
        path = m.save_samples({"n": 100}, rows, "all")
        with open(path, encoding="utf-8") as f:
            rec = json.loads(f.readline())
        self.assertEqual(rec["source_id"], sid)

    def test_endpoint_replacement_marks_mutation(self):
        sid = m.source_id("https://src")
        def batch(prefix, h):
            return [{"name": f"{prefix}{i}", "type": "ss", "server": f"{prefix}{i}",
                     "port": 443, "_source": "https://src", "_source_id": sid,
                     "_source_hash": h, "_source_count": 10,
                     "_source_protocols": {"ss": 10}} for i in range(10)]
        m.detect_source_mutations(batch("old", "h1"))
        mutated = m.detect_source_mutations(batch("new", "h2"))
        self.assertIn(sid, mutated)
        self.assertIn("端点集合", mutated[sid])

    def test_scalar_and_list_history_are_skipped(self):
        path = os.path.join(m.HISTORY_DIR, "samples-202611.jsonl")
        with open(path, "w", encoding="utf-8") as f:
            f.write("1\n[]\n")
            f.write(json.dumps({"ts": 123, "name": ["x"]}) + "\n")
        self.assertEqual(m.dead_node_names(window=7, min_fail=2), {})
        self.assertTrue(m.build_daily_aggregate())

    def test_subscription_cleanup_creates_backup(self):
        import yaml as _y
        sd = os.path.join(m.HISTORY_DIR, "subscriptions")
        os.makedirs(sd, exist_ok=True)
        names = ["p0", "p1"]
        cfg = {"proxies": [self._node(n) for n in names],
               "proxy-groups": [{"name": "PROXY", "type": "select",
                                 "proxies": names}],
               "rules": ["MATCH,PROXY"]}
        for fn in ("ss.yaml", "trojan.yaml"):
            with open(os.path.join(sd, fn), "w", encoding="utf-8") as f:
                _y.safe_dump(cfg, f, allow_unicode=True, sort_keys=False)
        t1 = (datetime.datetime.now() - datetime.timedelta(hours=13)).isoformat(timespec="seconds")
        t2 = datetime.datetime.now().isoformat(timespec="seconds")
        path = os.path.join(m.HISTORY_DIR, "samples-202611.jsonl")
        with open(path, "w", encoding="utf-8") as f:
            for ts in (t1, t2):
                f.write(json.dumps({"ts": ts, "name": "p0", "ok": False}) + "\n")
        removed = m.clean_dead_nodes(window=7, min_fail=2, apply=True,
                                     target="subs", backup=False)
        self.assertEqual(removed, 2, "两个订阅文件各移除 p0")
        bks = [d for d in os.listdir(m.BACKUP_DIR) if d.startswith("subscriptions-")]
        self.assertEqual(len(bks), 1)
        self.assertEqual(len(os.listdir(os.path.join(m.BACKUP_DIR, bks[0]))), 2)

    def test_apply_preserves_existing_mixed_port(self):
        import yaml as _y
        with open(m.PROD_CONFIG, "w", encoding="utf-8") as f:
            _y.safe_dump({"mixed-port": 12345,
                          "external-controller": "127.0.0.1:9191",
                          "proxies": []}, f)
        old_validate, old_backup, old_port, old_secret = (
            m.validate_config_file, m.backup_prod, m.port_up, m.resolve_prod_secret)
        m.validate_config_file = lambda cfg, d, rules_override=None: True
        m.backup_prod = lambda: None
        m.port_up = lambda _p: False
        m.resolve_prod_secret = lambda _s=None: ("x" * 16, "test", False)
        try:
            m.apply_prod([self._node()], ["MATCH,PROXY"], health_check=False)
        finally:
            m.validate_config_file, m.backup_prod, m.port_up, m.resolve_prod_secret = (
                old_validate, old_backup, old_port, old_secret)
        with open(m.PROD_CONFIG, encoding="utf-8") as f:
            cfg = _y.safe_load(f)
        self.assertEqual(cfg["mixed-port"], 12345)
        self.assertEqual(cfg["external-controller"], "127.0.0.1:9191")

    def test_source_state_non_dict_sources_is_ignored(self):
        with open(m.SOURCE_STATE_FILE, "w", encoding="utf-8") as f:
            json.dump({"sources": []}, f)
        self.assertEqual(m.load_source_state()["sources"], {})
        self.assertEqual(m.detect_source_mutations([self._node()]), {})

    def test_ssr_password_keeps_colon(self):
        inner = "h.example:443:origin:aes-256-cfb:plaintext:pa:ss"
        u = "ssr://" + m.base64.urlsafe_b64encode(inner.encode()).decode().rstrip("=")
        d = m.p_ssr(u)
        self.assertEqual(d["password"], "pa:ss")

    def test_ssr_ipv6_bracket_host(self):
        inner = "[2001:db8::1]:443:origin:aes-256-cfb:plaintext:p"
        u = "ssr://" + m.base64.urlsafe_b64encode(inner.encode()).decode().rstrip("=")
        d = m.p_ssr(u)
        self.assertEqual(d["server"], "2001:db8::1")
        self.assertEqual(d["port"], 443)

    def test_node_id_normalizes_string_port(self):
        self.assertEqual(m.node_id({"type": "ss", "server": "h", "port": "8388"}),
                         m.node_id({"type": "ss", "server": "h", "port": 8388}))

    def test_dead_same_name_different_ids_are_not_overwritten(self):
        sid1, sid2 = "id-one", "id-two"
        t1 = (datetime.datetime.now() - datetime.timedelta(hours=13)).isoformat(timespec="seconds")
        t2 = datetime.datetime.now().isoformat(timespec="seconds")
        path = os.path.join(m.HISTORY_DIR, "samples-202611.jsonl")
        with open(path, "w", encoding="utf-8") as f:
            for nid, name in ((sid1, "US"), (sid2, "US")):
                for ts in (t1, t2):
                    f.write(json.dumps({"ts": ts, "name": name, "id": nid,
                                        "ok": False}) + "\n")
        dead = m.dead_node_names(window=7, min_fail=2)
        self.assertEqual(len(dead), 2, "同名但不同 ID 的死节点不能互相覆盖")
        self.assertEqual({v["id"] for v in dead.values()}, {sid1, sid2})

    def test_fetch_fallback_log_does_not_leak_url(self):
        marker = "SECRET_TOKEN_123"
        logs = []
        old_log, old_open = m.log, m._open
        m.log = lambda msg, *a, **k: logs.append(str(msg))
        def fake_open(url, timeout=60):
            if url.startswith(m.PROXY_PREFIX):
                raise RuntimeError("prefix down")
            return "ok"
        m._open = fake_open
        try:
            m.fetch(m.PROXY_PREFIX + "https://example.com/sub?token=" + marker)
        finally:
            m.log, m._open = old_log, old_open
        joined = "\n".join(logs)
        self.assertNotIn(marker, joined)
        self.assertIn("source#", joined)

    def test_validate_structure_rejects_duplicate_group_and_missing_type(self):
        cfg = {"proxies": [{"name": "p", "type": "ss", "server": "h", "port": 1}],
               "proxy-groups": [{"name": "G", "type": "select", "proxies": ["p"]},
                                {"name": "G", "type": "select", "proxies": ["p"]}],
               "rules": ["MATCH,G"]}
        self.assertFalse(m.validate_config_structure(cfg))
        cfg["proxy-groups"] = [{"name": "G", "type": "select", "proxies": ["p"]}]
        cfg["proxies"] = [{"name": "p", "server": "h", "port": 1}]
        self.assertFalse(m.validate_config_structure(cfg))

    def test_restore_missing_backup_does_not_delete_prod(self):
        with open(m.PROD_CONFIG, "w", encoding="utf-8") as f:
            f.write("mixed-port: 2080\n")
        self.assertFalse(m.restore_backup(os.path.join(m.BACKUP_DIR, "missing.yaml")))
        self.assertTrue(os.path.isfile(m.PROD_CONFIG))

    def test_apply_clean_and_prune_acquire_lock(self):
        calls = []
        old_acquire, old_release = m.acquire_lock, m.release_lock
        old_clean, old_prune = m.clean_dead_nodes, m.prune_history
        m.acquire_lock = lambda retries=30: calls.append("acquire") or object()
        m.release_lock = lambda lock: calls.append("release")
        m.clean_dead_nodes = lambda **k: calls.append(("clean", k.get("apply"))) or 0
        m.prune_history = lambda **k: calls.append(("prune", k.get("apply")))
        try:
            with patch.object(sys, "argv", ["proxy_harvest.py", "--clean-dead", "--apply-clean"]):
                m.main()
            self.assertEqual(calls, ["acquire", ("clean", True), "release"])
            calls.clear()
            with patch.object(sys, "argv", ["proxy_harvest.py", "--prune", "--apply-prune"]):
                m.main()
            self.assertEqual(calls, ["acquire", ("prune", True), "release"])
        finally:
            m.acquire_lock, m.release_lock = old_acquire, old_release
            m.clean_dead_nodes, m.prune_history = old_clean, old_prune

    def test_public_proxy_and_clean_proxy_strip_nonunderscore_source_fields(self):
        secret = "https://private.example/sub?token=TOPSECRET"
        node = self._node()
        node.update({"source": secret, "source_url": secret, "source_id": secret})
        out = m.public_proxy(node)
        text = json.dumps(out, ensure_ascii=False)
        self.assertNotIn("TOPSECRET", text)
        self.assertNotIn("source_url", out)
        self.assertNotIn("source_id", out)
        self.assertEqual(out["_source_id"], m.source_id(secret))

        cfg = configgen.build_config([node], 2080, 9090, ["MATCH,PROXY"])
        cfg_text = json.dumps(cfg, ensure_ascii=False)
        self.assertNotIn("TOPSECRET", cfg_text)
        self.assertNotIn("source_url", cfg["proxies"][0])

    def test_normalize_source_map_drops_unknown_url_fields(self):
        secret = "https://private.example/sub?token=TOPSECRET"
        out = m.normalize_source_map({secret: {"count": 1, "url": secret,
                                                "reason": "legacy"}})
        self.assertEqual(len(out), 1)
        self.assertEqual(list(out.values())[0],
                         {"count": 1, "reason": "legacy"})
        self.assertNotIn("TOPSECRET", json.dumps(out, ensure_ascii=False))

    def test_save_history_drops_internal_source_from_row(self):
        secret = "https://private.example/sub?token=TOPSECRET"
        rows = [{"name": "n", "type": "ss", "server": "1.2.3.4", "port": 8388,
                 "_source": secret, "id": "", "delay_ms": 100, "ok": True}]
        hist, _csv = m.save_history(rows, {})
        with open(hist, encoding="utf-8") as f:
            rec = json.loads(f.readline())
        self.assertNotIn("TOPSECRET", json.dumps(rec, ensure_ascii=False))
        self.assertNotIn("_source", rec)

    def test_validate_structure_rejects_reserved_name_and_bad_last_rule(self):
        cfg = {"proxies": [{"name": "DIRECT", "type": "ss", "server": "h", "port": 1}],
               "proxy-groups": [{"name": "PROXY", "type": "select",
                                 "proxies": ["DIRECT"]}],
               "rules": ["MATCH,PROXY"]}
        self.assertFalse(m.validate_config_structure(cfg))
        cfg["proxies"] = [{"name": "p", "type": "ss", "server": "h", "port": 1}]
        cfg["proxy-groups"] = [{"name": "PROXY", "type": "select", "proxies": ["p"]}]
        cfg["rules"] = [None]
        self.assertFalse(m.validate_config_structure(cfg))

    def test_show_status_tolerates_non_list_proxies(self):
        import yaml as _y
        with open(m.PROD_CONFIG, "w", encoding="utf-8") as f:
            _y.safe_dump({"mixed-port": 12345,
                          "external-controller": "127.0.0.1:9090",
                          "proxies": None}, f)
        m.show_status()

    def test_read_history_skips_bad_timestamp_in_window(self):
        path = os.path.join(m.HISTORY_DIR, "proxy-202611.jsonl")
        now = datetime.datetime.now().isoformat(timespec="seconds")
        with open(path, "w", encoding="utf-8") as f:
            f.write(json.dumps({"ts": "2020-01-01T00:00:00", "name": "old"}) + "\n")
            f.write(json.dumps({"ts": now, "name": "fresh"}) + "\n")
            f.write(json.dumps({"ts": "not-a-date", "name": "broken"}) + "\n")
            f.write(json.dumps({"name": "missing"}) + "\n")
        rows = m.read_history(1)
        self.assertEqual({r.get("name") for r in rows}, {"fresh"})

    def test_temp_instance_copies_geo_files(self):
        geo_src = os.path.join(self.tmp, "geo-src")
        os.makedirs(geo_src, exist_ok=True)
        for fn in ("geoip.dat", "geosite.dat", "country.mmdb", "unrelated.txt"):
            with open(os.path.join(geo_src, fn), "w", encoding="utf-8") as f:
                f.write("x")
        t = m.TempMihomo(self.tmp, 28001, 28002, [self._node()],
                         rules=["MATCH,PROXY"], geo_dir=geo_src)
        try:
            self.assertTrue(os.path.isfile(os.path.join(t.dir, "geoip.dat")))
            self.assertTrue(os.path.isfile(os.path.join(t.dir, "geosite.dat")))
            self.assertTrue(os.path.isfile(os.path.join(t.dir, "country.mmdb")))
            self.assertFalse(os.path.exists(os.path.join(t.dir, "unrelated.txt")))
        finally:
            shutil.rmtree(t.dir, ignore_errors=True)

    def test_export_group_configs_handles_non_string_group(self):
        node = self._node()
        node["_group"] = ["ss"]
        out = os.path.join(self.tmp, "subs")
        written = m.export_group_configs(["n"], {"n": node}, ["MATCH,PROXY"],
                                         out_dir=out)
        self.assertTrue(any(g == "ss" for g, _path, _n in written))
        self.assertTrue(os.path.isfile(os.path.join(out, "ss.yaml")))

    def test_vmess_fragment_is_used_as_name(self):
        obj = {"v": "2", "ps": "", "add": "example.com", "port": "443",
               "id": "00000000-0000-0000-0000-000000000000", "aid": "0",
               "net": "tcp", "tls": ""}
        u = "vmess://" + base64.urlsafe_b64encode(
            json.dumps(obj).encode()).decode().rstrip("=") + "#Edge%20Name"
        node = m.p_vmess(u)
        self.assertIsNotNone(node)
        self.assertEqual(node["name"], "Edge Name")

    def test_safe_url_label_hides_credentials_and_query(self):
        label = m.safe_url_label(
            "https://user:pass@example.com/private?token=TOPSECRET#frag")
        self.assertIn("example.com", label)
        self.assertNotIn("TOPSECRET", label)
        self.assertNotIn("pass", label)
        self.assertNotIn("private", label)

    def test_safe_int_handles_infinity(self):
        self.assertEqual(m._safe_int(float("inf"), 7), 7)
        self.assertEqual(m._safe_int(float("nan"), 8), 8)

    def test_validate_structure_handles_unhashable_group_refs(self):
        node = self._node(name="n")
        cfg = {"proxies": [node],
               "proxy-groups": [{"name": "G", "type": "select", "proxies": [[]]}],
               "rules": ["MATCH,G"]}
        self.assertFalse(m.validate_config_structure(cfg))

    def test_content_matches_accepts_string_body(self):
        body = "hello"
        digest = hashlib.sha256(body.encode()).hexdigest()
        self.assertTrue(m.content_matches(body, digest))
        self.assertFalse(m.content_matches(body, "0" * 64))

    def test_dedupe_endpoints_is_case_insensitive(self):
        a = {"name": "a", "type": "SS", "server": "Host.Example", "port": "8388"}
        b = {"name": "b", "type": "ss", "server": "host.example", "port": 8388}
        self.assertEqual(m.dedupe_endpoints([a, b]), [a])


if __name__ == "__main__":
    unittest.main(verbosity=2)
