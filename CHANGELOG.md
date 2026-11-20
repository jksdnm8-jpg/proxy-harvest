# Changelog

## v0.0.4

2026-11-20

维护发版。相对 v0.0.3 无功能与代码逻辑变更，只调整 CI、依赖声明和分发物。

### 主要变化

- 项目版本号升级到 `0.0.4`（`pyproject.toml`、`proxy_harvest.py`、README 与验证记录）。
- CI 测试矩阵改为 `3.10` / `3.13` / `3.14`。`ubuntu-latest` 已指向 Ubuntu 26.04，
  而 `actions/python-versions` 不再为 26.04 提供 Python 3.9 构建，`setup-python` 会直接失败；
  3.9 已 EOL，CI 最低版本提到 3.10。代码本身仍声明 `requires-python = ">=3.9"`，只是不再纳入 CI。
- CI 里的 `actions/checkout`、`actions/setup-python`、`actions/upload-artifact` 升级到 v7（Node 24），
  消除 `Node.js 20 is deprecated` 告警。
- README 依赖一节写明 mihomo 需要 **>= v1.19.12**：更早版本的 `rule-providers` 在 `type: file`
  分支不校验路径，配合 `PUT /configs` 与 `/logs` 的回显可读取任意文件
  （CVE-2025-56499，CVSS 6.5，上游修复 PR #2177）。本项目自身不生成 `rule-providers`，
  `external-controller` 也只绑 `127.0.0.1`，不受该漏洞影响；写进依赖只是避免被降级到受影响版本。
- 分发物 `proxy-harvest-v0.0.4.patch` 与 `proxy-harvest-v0.0.4.zip` 按新版本号重新生成。

## v0.0.3

2026-11-20

版本维护发版。相对 v0.0.2 无功能变更，统一版本号与分发物命名到 v0.0.3；另修复一处跨平台解析兼容问题。

### 主要变化

- 项目版本号升级到 `0.0.3`（`pyproject.toml`、`proxy_harvest.py`、README 与验证记录）。
- 修复畸形方括号 URL 的解析在不同 Python 版本行为不一致的问题：`_urlparse` 现在主动校验 netloc 的方括号配对，不再依赖 `urlparse` 是否抛 `ValueError`。此前 3.10 某些补丁版会把 `vless://]bad[?a=1` 当成合法解析，导致 CI 上 3.9/3.10 的回归用例失败。
- 分发物 `proxy-harvest-v0.0.3.patch` 与 `proxy-harvest-v0.0.3.zip` 按新版本号重新生成。

## v0.0.2

2026-11-20

第二个公开版本。相对 v0.0.1，主要补充跨平台支持、配置生成与落地保护，以及更多解析和回归测试。

### 主要变化

- Windows / Linux / macOS 的路径与进程处理；默认内核名随平台变化。
- 新增 `configgen.py`，配置生成和校验可以单独测试；新增 `mock_mihomo.py` 供本地测试和 CI 使用。
- 抓取与历史记录只保留来源 ID，不把带 token 的订阅 URL 写入快照、历史、日志或 `--json`。
- 配置落地增加预检、备份、临时实例健康检查和失败回滚；`--dry-run` 下不写盘。
- 测速仍使用临时 mihomo 实例和独立本地端口；保留 8 种协议、分组和串行/并发验证。
- 解析器补充畸形 URI、IPv6、凭据编码和必填字段等边界处理。
- 兼容矩阵的 mock 输出只显示配置文件名，不写入临时绝对路径。
- 单元测试 220 项；Windows 和 Ubuntu 上通过，Windows 跳过 1 个 POSIX 权限用例。CI 在 Windows 和 Ubuntu 上运行完整回归。
- 兼容矩阵 mock 内核 10/10；Windows 真实 mihomo v1.19.34 10/10；完整 split / GEOSITE / GEOIP 规则已用真实内核加载验证。

### 边界

- 真实 DoH 查询、真实外网出口、生产 mihomo 重启/重载未实测。
- macOS 未纳入 CI，也未做真实环境验证。

## v0.0.1

2026-11-20

首个公开版本。Windows 下的代理订阅抓取、测速、筛选、记录与配置落地工具。
