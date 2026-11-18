# Proxy Harvest

`v0.0.1` · 免费代理节点一键抓取、测速、筛选、记录与落地工具。

> **平台：仅支持 Windows。** 脚本依赖 `curl.exe`、`winreg`、`CREATE_NO_WINDOW`、`taskkill` 等 Windows 特性，Linux/macOS 未适配。

多源抓取 → 隔离测速 → 质量评分 → 四层数据沉淀 → 分组订阅 → 自动清理，一条命令跑完全流程。

## 特性

- **8 种协议**：SS / SSR / VMess / VLESS / Trojan / Hysteria2 / TUIC / AnyTLS
- **完整传输层**：ws / grpc / httpupgrade / h2 / xhttp；SS 插件（obfs、v2ray-plugin）；hy2 混淆与端口跳跃
- **协议分组**：可只测某一组，或每组各自独立排名
- **隔离测速**：测速跑在独立的临时 mihomo 实例里，不干扰正在使用的代理
- **并发验证**：每个候选节点绑独立本地端口，线程池并发验证（默认）；`--serial-verify` 可切回串行
- **质量评分**：延迟 60% + 真实 HTTP 耗时 40%，不是只看延迟
- **四层存储**：全量快照 / 采样序列 / 每日聚合 / 分组订阅
- **自动维护**：清理连续失败的节点、归档过期历史、一键回滚
- **机器可读**：`--json` 导出结构化结果，方便其它脚本或 AI 消费

## 依赖

- **Windows 10/11**（见上方平台说明）
- Python 3.9+（推荐 3.10+）
- `pyyaml>=6.0,<7.0`
- [mihomo](https://github.com/MetaCubeX/mihomo)（Meta 内核，用于测速与本地代理）
- `curl.exe`（Windows 10/11 自带）
- 国内环境需要 `gh-proxy.com` 可访问（脚本默认经它抓 GitHub 订阅）

```bash
pip install -r requirements.txt
```

## 快速开始

```bash
# 只抓取 + 测速 + 记录，不改动任何现有配置（安全）
python proxy_harvest.py

# 试运行全流程：跑完所有步骤但不落地不清理
python proxy_harvest.py --cron --dry-run

# 一键全流程：抓取 → 测速 → 落地 → 清死节点 → 归档
python proxy_harvest.py --cron
```

## 测试

```bash
python -m unittest test_parse -v
# 或
python test_parse.py
```

单元测试覆盖 8 种协议解析器（VLESS / VMess / Trojan / SS / Hysteria2 / TUIC / AnyTLS / SSR）、
host:port 解析、协议分组、质量评分、配置清洗与校验、重名去重、死节点判定、月边界归类、原子写入、传输层字段、SS 插件、hy2 混淆。改逻辑后先跑测试。

## 配置

脚本不硬编码路径。优先级：**环境变量 > `config.json` > 脚本所在目录**。

`config.json` 示例（可选，不建则用默认值）：

```json
{
  "base_dir": "D:/proxy-harvest-data",
  "mihomo_exe": "D:/tools/mihomo/mihomo.exe",
  "mixed_port": 2080,
  "api_port": 9090,
  "secret": "PH_SECRET_PLACEHOLDER",
  "curl": "curl.exe",
  "proxy_prefix": "https://gh-proxy.com/",
  "sources": []
}
```

| 字段 | 说明 |
|---|---|
| `secret` | 生产 mihomo API 的 secret。**不要填 `box` 之类的弱值**，短于 8 位会被拒绝 |
| `proxy_prefix` | 订阅加速前缀；设为空串则全部直连 |
| `sources` | 覆盖整个订阅源列表；留空用内置源 |

也可直接用环境变量覆盖，例如 `PH_BASE_DIR=/data/proxy`、`PH_SECRET=...`。

### secret 优先级

```
--secret  >  config.json 或 PH_SECRET  >  现有 config.yaml 里的值  >  新生成
```

弱值（`box`、空、短于 8 位）会被忽略并重新生成。新生成的 secret **只打印到终端**，
不写入 `harvest.log`；订阅导出文件里的 secret 恒为空。

> 建议用 `PH_SECRET` 环境变量而不是 `--secret` 命令行 —— 后者会留在 shell 历史和进程列表里。

默认目录结构（相对 `base_dir`）：

```
config/          生产代理配置（config.yaml）
backups/         配置备份（--rollback 用）
history/         四层存储数据
.harvest-tmp/    测速用临时实例（每次运行独立子目录）
harvest.log      运行日志（超过 2 MB 自动轮转为 .1）
.harvest.lock    运行锁，防 cron 重叠
```

> **生产目录需要 `geoip.dat` 和 `geosite.dat`。** split 规则用到 `GEOSITE`/`GEOIP`，
> 缺这两个文件时 mihomo 首次启动会尝试联网下载，国内直连 GitHub 通常超时导致启动失败。
> 可从 [MetaCubeX/meta-rules-dat](https://github.com/MetaCubeX/meta-rules-dat/releases) 下载后
> 放进与 `config.yaml` 同级的目录。

## 常用命令

```bash
# 协议分组
python proxy_harvest.py --list-groups
python proxy_harvest.py --group hysteria --keep 5      # 只测 Hysteria2
python proxy_harvest.py --per-group 2                   # 每组前 2 个独立排名

# 数据沉淀
python proxy_harvest.py --longevity                     # 节点连续存活天数
python proxy_harvest.py --history-stats                 # 测试记录统计

# 清理与回滚
python proxy_harvest.py --clean-dead                    # 报告死节点（只读）
python proxy_harvest.py --clean-dead --apply-clean      # 真正移除
python proxy_harvest.py --prune --apply-prune           # 归档 >90 天的历史
python proxy_harvest.py --rollback                      # 回滚到最近备份

# 给其它程序用
python proxy_harvest.py --json result.json

# 深验默认并发；要串行（慢但更省端口）加 --serial-verify
python proxy_harvest.py --keep 15
python proxy_harvest.py --keep 15 --serial-verify
```

完整参数见 `python proxy_harvest.py --help`。

> **深度验证的参数是 `--keep N`**（对延迟最快的 N 个节点做真实 HTTP 验证），
> 不是 `--deep-verify`。脚本没有 `--deep-verify` 这个参数，照旧文档敲会报错。

### 值得注意的参数

| 参数 | 作用 |
|---|---|
| `--keep N` | 深度验证前 N 个节点（`--cron` 默认 15） |
| `--serial-verify` | 深验改回串行（默认并发，每节点独立端口） |
| `--insecure` | 保留 `skip-cert-verify`（默认剥离，会更安全但可用节点变少） |
| `--secret S` | 指定生产 API secret；推荐改用 `PH_SECRET` 环境变量 |
| `--max-nodes N` | 落地到生产配置的节点上限（默认 30，`0` 不限） |
| `--group G` | 只测某个协议组（`--list-groups` 查看） |
| `--per-group N` | 每组各挑前 N 个深验并独立排名 |

## 数据流

| 层 | 文件 | 内容 |
|---|---|---|
| A 全量快照 | `history/snapshot-YYYYMMDD.jsonl` | 每次抓取的全部节点（含来源/协议组） |
| B 采样序列 | `history/samples-YYYYMM.jsonl` | 每节点每次延迟/耗时/评分 |
| C 每日聚合 | `history/latest_daily.csv` | 每日成功率/平均分/平均延迟 |
| D 分组订阅 | `history/subscriptions/*.yaml` | 每组单独的 Clash 配置 |

测试记录写入 `history/proxy-YYYYMM.jsonl`，含完整节点定义，供 `--inherit` 复活常青节点。

## 安全设计

- **默认只读**：不加 `--apply` / `--cron` 绝不改生产配置
- **落地前备份**：每次 apply 自动备份，`--rollback` 可回退
- **隔离测速**：临时实例用随机端口，跑完销毁，不影响在用的代理
- **清理保护**：cron 清死节点时排除本轮通过的节点，不误删刚落地的
- **cron 默认 split 规则**：国内流量直连，不会把本机所有程序都塞进代理

## 数据源

默认订阅源（都经 `gh-proxy.com` 直连）：

- `Mahdi0024/ProxyCollector`（带测活，每 24h 更新）
- `mahdibland/V2RayAggregator`
- `ermaozi/get_subscribe`
- `ripaojiedian/freenode`
- `peasoft/NoMoreWalls`
- `mfuu/v2ray`

可在源码 `SOURCES` 列表里增删。

## 许可

见 LICENSE。

## 免责声明

本项目仅供个人学习与研究使用。抓取公开订阅、测速筛选属于对公开信息的整理；
使用代理节点请遵守所在地法律法规与目标网站的服务条款。作者不对使用后果负责。
