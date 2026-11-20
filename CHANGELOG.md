# Changelog

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
