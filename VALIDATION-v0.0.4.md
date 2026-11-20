# Proxy Harvest v0.0.4 真实 split / geo 复核记录

- 日期：2026-11-20（Asia/Shanghai）
- 结论：Windows 本机真实 mihomo 能加载完整 split 规则（GEOSITE / GEOIP）；临时实例、临时落地、死节点清理和分组订阅导出均通过真实内核复核。
- 隔离验证：`apply_prod` / `clean_dead_nodes` 都在 `tempfile.mkdtemp()` 生成的隔离 BASE 中执行；项目 `config/` 只补充了 geo 数据，`mihomo/` 只放了内核二进制，没有写入生产 `config.yaml`。

## 内核

| 项 | 值 |
|---|---|
| 路径 | `<repo>\mihomo\mihomo.exe` |
| 版本 | `Mihomo Meta v1.19.34 windows amd64 with go1.26.11` |
| 字节 | 61,192,704 |
| SHA256 | `5A0231811A80B27477EBDEE15684B41946D01AFBD2114534E9A4B256125CA147` |

## geo 数据

来源：`MetaCubeX/meta-rules-dat` 的 `latest` release；下载通道为 `https://gh-proxy.com/` 加速前缀（原始 URL 均为 `https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/...`）。已安装到项目 `config/`。

| 文件 | 字节 | SHA256 |
|---|---:|---|
| `geoip.dat` | 16,503,149 | `D4EC4C5E5D5A38C1399964EA9FD8C94288426A3B31B483904B67819FC07F4466` |
| `geosite.dat` | 4,359,441 | `05383CF8D1086234116D0CFF2AF6DC595370B6A8C1197814168DC8A527A781D1` |
| `country.mmdb` | 7,630,477 | `9840946762FA8C2673738BBBBAB22BB720BDE931F6DEA327EB58E689BABC37DC` |

## 验证命令与结果

```text
python -c "import proxy_harvest as m; print(m.geofiles_present(m.PROD_CONF_DIR))"
→ True

python -c "... make_config(..., m.split_rules()); validate_config_file(..., rules_override=m.split_rules())"
→ split_structure: True
→ split_real_t: True
```

完整 split 规则：

```text
GEOIP,private,DIRECT,no-resolve
GEOSITE,private,DIRECT
GEOSITE,cn,DIRECT
GEOIP,CN,DIRECT
DOMAIN-SUFFIX,cn,DIRECT
MATCH,PROXY
```

真实内核复核（隔离 BASE）：

```text
geofiles_present: True
split_structure: True
split_real_t: True
TempMihomo with geo_dir=PROD_CONF_DIR: 启动成功（0.2s），/version=v1.19.34，/proxies 可读
apply_prod(..., rules=split_rules(), health_check=False): 写入临时 BASE 成功，prod real -t=True
clean_dead_nodes(..., apply=True, target=prod): 移除 1 个死节点，剩余配置 real -t=True
D 层 export_group_configs 的 ss.yaml / all.yaml: real -t=True
verify_selected_outbound(..., max_nodes=1): 按预期返回 False（节点为不可出网的本地占位节点；未崩溃、临时实例已清理）
```

## 仍未覆盖

- 真实外网出口/真实代理节点：本机没有可用上游节点，`verify_selected_outbound` 只验证了失败路径和资源清理，不代表真实出网成功。
- 真实 DoH 查询：当前只验证真实内核加载 DNS 配置，没有做真实 DoH 请求命中测试。
- 真实生产重启/重载：未执行；健康检查仍使用同源临时实例。

## 复现方式

```powershell
cd <repo>
python -m unittest test_parse
python compat_matrix.py --mihomo .\mihomo\mihomo.exe
python -c "import proxy_harvest as m; print(m.geofiles_present(m.PROD_CONF_DIR))"
```

如果要验证真实出网，需要先把真实的、可用的上游节点放进候选池；不要把本记录中的 `127.0.0.1` 占位节点当作可用代理。
