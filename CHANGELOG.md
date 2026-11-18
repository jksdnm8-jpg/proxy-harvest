# Changelog

## v0.0.1

首个正式发布。免费代理节点一键抓取、测速、筛选、记录与落地工具。

### 功能

- 8 种协议：SS / SSR / VMess / VLESS / Trojan / Hysteria2 / TUIC / AnyTLS
- 完整传输层：ws / grpc / httpupgrade / h2 / http / xhttp / alpn
- SS 插件（obfs、v2ray-plugin）、hy2 混淆与端口跳跃
- 多源订阅抓取，按源配额分配，内容无效自动直连兜底
- mihomo 隔离实例并发测速 + 独立端口并发深验，不干扰在用的代理
- 质量评分：延迟 60% + 真实 HTTP 耗时 40%
- 协议分组，可单组测试或每组独立排名
- 四层数据沉淀：全量快照 / 采样序列 / 每日聚合 / 分组订阅
- 节点稳定 `_id`，重名后缀变化不串号
- 自动维护：死节点清理、过期历史归档、配置备份与回滚
- 生产配置落地前 `mihomo -t` 校验，失败逐个剔除坏节点

### 安全设计

- 默认只读，落地必须显式 `--apply` 或 `--cron`
- 默认剥离 `skip-cert-verify`（自签节点会测速失败，可用 `--insecure` 打开）
- `--cron` 强制 split 规则，国内流量直连
- 生产 secret 拒绝弱值（`box` / 空 / 短于 8 位），新 secret 只进终端不写日志
- 订阅导出文件 secret 恒为空
- 日志轮转、运行锁、备份只处理 `.yaml`

### 主要参数

| 参数 | 作用 |
|---|---|
| `--cron` | 一键全流程：抓取 → 测速 → 落地 → 清理 → 归档 |
| `--keep N` | 深度验证前 N 个节点 |
| `--group G` / `--per-group N` | 只测某组 / 每组独立排名 |
| `--insecure` | 保留 `skip-cert-verify` |
| `--max-nodes N` | 落地节点上限（默认 30） |
| `--secret S` / `PH_SECRET` | 指定生产 API secret |
| `--rollback` | 回滚到最近备份 |

详见 README。
