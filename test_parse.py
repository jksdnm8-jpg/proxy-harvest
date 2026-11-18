"""协议解析器与核心逻辑的单元测试。

运行：
    python -m unittest test_parse -v
或：
    python test_parse.py
"""
import base64
import datetime
import json
import os
import shutil
import sys
import tempfile
import unittest

# P0-1：必须在 import proxy_harvest 之前把 base_dir 指到临时目录。
# 否则 config.json 里的 base_dir 会把 PROD_CONFIG / BACKUP_DIR / LOG_FILE
# 全都指向用户真实目录，测试会覆盖真配置。
_TEST_BASE = tempfile.mkdtemp(prefix="ph-test-base-")
os.environ["PH_BASE_DIR"] = _TEST_BASE

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import proxy_harvest as m


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
        good = {"name": "x", "type": "hysteria2", "server": "1.2.3.4", "port": 443}
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
        t1 = (datetime.datetime.now() - datetime.timedelta(hours=2)).isoformat(timespec="seconds")
        t2 = datetime.datetime.now().isoformat(timespec="seconds")
        self._write([
            {"ts": t1, "name": "dead", "ok": False, "http_code": 0},
            {"ts": t2, "name": "dead", "ok": False, "http_code": 0},
        ])
        dead = m.dead_node_names(window=7, min_fail=2)
        self.assertIn("dead", dead)

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
        t1 = (datetime.datetime.now() - datetime.timedelta(hours=2)).isoformat(timespec="seconds")
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
        t1 = (datetime.datetime.now() - datetime.timedelta(hours=2)).isoformat(timespec="seconds")
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
        m.validate_config_file = lambda cfg, d: True
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
            t1 = (datetime.datetime.now() - datetime.timedelta(hours=2)).isoformat(timespec="seconds")
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


if __name__ == "__main__":
    unittest.main(verbosity=2)
