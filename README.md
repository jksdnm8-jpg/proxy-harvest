# Proxy Harvest

`v0.0.3` · 代理订阅抓取、测速与 mihomo 配置落地工具。

从订阅源抓取节点，用临时 mihomo 实例测速并记录结果；需要时生成分组订阅，或写入 mihomo 配置。
默认只读，只有显式 `--apply` / `--cron` 才会改动配置。

> 平台：Windows / Linux / macOS。Windows 和 Ubuntu 上跑过 220 项测试；macOS 目前只做路径与进程处理的兼容，
> 未做真实环境验证。运行需要 Python 3.9+、curl 和 mihomo。
> 没有可用上游节点时，健康检查只能覆盖失败和回滚路径。

## 功能

- 多来源订阅抓取，按来源配额分配
- 8 种协议：SS / SSR / VMess / VLESS / Trojan / Hysteria2 / TUIC / AnyTLS
- 常用传输层：ws / grpc / httpupgrade / h2 / xhttp；SS 插件（obfs、v2ray-plugin）；hy2 混淆与端口跳跃
- 隔离测速：测速跑在临时 mihomo 实例中，使用随机本地端口，结束后清理
- 预检：测速前和落地前调用 `mihomo -t`，加载失败时逐个剔除坏节点
- 配置落地：备份、预检、写入、临时实例健康检查，失败回滚
- 历史记录：全量快照、采样、每日聚合和分组订阅
- 来源隐私：快照、历史、采样和 `--json` 只记录来源 ID，不保存完整订阅 URL
- 机器可读：`--json` 输出；附带 mock 内核和兼容矩阵脚本，便于本地复现

## 依赖

- Python 3.9+（推荐 3.10+）
- `pyyaml>=6.0,<7.0`
- [mihomo](https://github.com/MetaCubeX/mihomo)（Meta 内核，用于预检、测速与本地代理）
- split 规则还需要 `geoip.dat` / `geosite.dat`（可选 `country.mmdb`）；来自 [MetaCubeX/meta-rules-dat](https://github.com/MetaCubeX/meta-rules-dat)，放到 `config/` 或与 `-d` 配置目录同级
- `curl`（Windows 10/11 自带 `curl.exe`；Linux/macOS 通常已安装）
- 国内环境需要 `gh-proxy.com` 可访问（脚本默认经它抓 GitHub 订阅）

```bash
pip install -r requirements.txt
# 或
pip install -e .
```

## 快速开始

```bash
# 只抓取 + 测速 + 记录，不改动任何现有配置（安全）
python proxy_harvest.py

# 试运行全流程：跑完所有步骤但不落地不清理
python proxy_harvest.py --cron --dry-run

# 一键全流程：抓取 → 测速 → 落地 → 健康检查 → 清死节点 → 归档
python proxy_harvest.py --cron
```

## 质量检查

### 内容完整性探测（默认关闭）

思路来自 [Free Proxies Unmasked](https://arxiv.org/html/2403.02445v1)：自建一个返回固定内容的蜜罐站点，
让每个节点去取同一份内容，再比对响应体 SHA256。返回 200 但内容被替换的节点会被标记
`content_tampered=true`、`ok=false`，不进入落地与导出。

```bash
# 期望 64 位十六进制 SHA256；也可用 --verify-content-text 固定文本
python proxy_harvest.py --keep 10 \
  --verify-content-url https://your-honeypot.example/fixed.bin \
  --verify-content-sha256 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef

# 额外再做一次 HTTPS 探测（同一个期望哈希，默认关闭）
python proxy_harvest.py --keep 10 \
  --verify-content-url https://your-honeypot.example/fixed.bin \
  --verify-content-sha256 <64hex> \
  --verify-https-url https://your-honeypot.example/fixed.bin
```

边界：这只证明“这次请求的响应体与期望一致”，不证明整条链路没有被选择性篡改；
HTTPS 探测也需要你自己的可信站点，不能拿第三方页面当基准。默认关闭，因为蜜罐地址必须由你提供。
内容/出口探测只在深验阶段执行：只给探测参数、不给 `--keep` 或 `--per-group` 会直接以退出码 2 拒绝，
不会静默跳过、把未经探测的节点当成通过。

内容探测结果分三态：`ok`、`mismatch`、`inconclusive`。只有 HTTP 200 且拿到 body、但内容与期望不符
才记 `content_tampered=true`；请求超时、body 超过 `--verify-content-max-bytes`、读 body 失败记
`content_inconclusive=true`，节点不会通过，但来源信誉不会被当成篡改扣分。日志里未决会显示
`[内容探测未决]`，JSON 顶层有 `content_inconclusive` 计数。

### 出口 IP / ASN / 地理位置

```bash
python proxy_harvest.py --keep 10 --exit-info
```

深验时额外请求 `https://ipapi.co/json/`（可用 `--exit-info-url` 换），记录：

- `exit_ip` / `exit_country` / `exit_asn` / `exit_org`
- `country_match`：节点名里的国家代码（如 `US`、`JP`）与出口国家是否一致
- `exit_changed`：与最近 30 天历史出口 IP 是否变化

评分中，出口 IP 变化乘 `0.85`，声称地区不符乘 `0.75`；默认不开启时 trust 恒为 `1.0`，原评分不变。
注意这会向出口信息接口发起一次请求，属于主动探测，默认关闭。

### 来源信誉与突变检测（自动）

每次抓取会记录订阅源的 SHA256、节点数、协议构成和端点集合到 `source-state.json`；
状态 key 是来源 URL 的 16 位 SHA-256 前缀（`source_id`），不保存带 token 的原始 URL。
`report_sources()` 按近 30 天历史计算每个源的有效率、被篡改率和信誉分：

```
信誉分 = 100 × 有效率 − 35 × 篡改率 − 20（若源被标记突变）
```

突变判定：

- 节点数 ≥ `max(20, 上次节点数 × 2)`；或
- 某协议占比变化超过 25 个百分点（两边样本均 ≥ 10）；或
- 节点数相同、协议构成相同且样本 ≥ 10，但端点集合重合 < 50%（整份订阅被替换）

首次运行只建立基线，不误报。命中突变的源仍参与测速，但其节点不会落地到生产配置，也不会进入 D 层导出。
信誉分目前用于报告和突变门禁，**尚未**作为排序或准入硬门槛；这是 v0.2 的已知边界。

## 配置落地与回滚

```bash
# 默认落地后会做真实出网健康检查；失败自动回滚到落地前备份
python proxy_harvest.py --apply

# 换健康检查地址
python proxy_harvest.py --apply --health-url https://www.cloudflare.com/cdn-cgi/trace

# 明确跳过健康检查（不推荐）
python proxy_harvest.py --apply --no-health-check
```

健康检查使用**同源临时 mihomo 实例**，取前 3 个待落地节点做出网请求；失败则调用
`restore_backup()` 恢复落地前配置并返回失败。边界：它验证的是“这套配置能出网”，
**不会重启或重载生产 mihomo 进程**；生产进程仍需你自行重启/重载后生效。这一点在报告里也会写明。

## 显式 DNS

```bash
# 写显式 dns 段；默认 fake-ip + Cloudflare/Google DoH
python proxy_harvest.py --apply --dns-mode explicit

# 指定 nameserver（逗号分隔）
python proxy_harvest.py --apply --dns-mode explicit \
  --dns-servers 127.0.0.1:5353,https://1.1.1.1/dns-query
```

默认段：

```yaml
dns:
  enable: true
  ipv6: false
  enhanced-mode: fake-ip
  fake-ip-range: 198.18.0.1/16
  nameserver:
    - https://1.1.1.1/dns-query
    - https://8.8.8.8/dns-query
  proxy-server-nameserver:
    - https://1.1.1.1/dns-query
    - https://8.8.8.8/dns-query
```

不要加 `nameserver-policy: geosite:cn`：真实 mihomo v1.19.34 在缺少 GeoSite 数据时会尝试联网下载并导致
`mihomo -t` 失败。当前已验证“移除该 policy 后 `-t` 通过”。

### DNS 实测

`dns_probe.py` 用本地 UDP DNS mock + 本地 HTTP 服务 + 真实 mihomo 验证查询是否真的命中配置的
`nameserver`：

```bash
python dns_probe.py --mihomo /path/to/mihomo
# {"ok": true, "dns_queries": ["dns-probe.test", "dns-probe.test"], "http_code": "200"}
```

它不需要外网或代理节点，适合在改动 DNS 默认值后做回归。

## 测试与兼容矩阵

```bash
python -m unittest test_parse -v
# 或
python test_parse.py
```

单元测试 220 项；Windows 和 Ubuntu 上通过，Windows 跳过 1 个 POSIX 权限用例。覆盖 8 种协议解析器、host:port 与 IPv6、畸形输入容错、必填字段校验、
协议分组、质量评分、配置清洗/重名去重/端点去重、死节点末尾连续失败段、`--insecure` 传播、
原子写入、传输层字段、SS 插件、hy2 混淆、`mihomo -t` 预检二分剔除、清理/归档/回滚安全、
curl 参数加固、抓取体积上限、内容完整性（含未决三态）、出口信息解析与 trust 降权、DNS 配置、
来源状态/突变检测、来源 URL 隐私、探测 URL 日志脱敏、mock 内核预检与临时实例、落地健康检查与回滚、配置生成层、OS 文件锁、
dry-run 写盘边界、保留名与零通过组订阅清理、临时实例 geo 数据复制、来源字段剥离与坏时间戳过滤。

```bash
# 假内核 + 真实内核一起跑矩阵
python compat_matrix.py \
  --mihomo mock_mihomo.py \
  --mihomo /path/to/mihomo

# 只跑部分用例，输出 JSON
python compat_matrix.py --mihomo mock_mihomo.py --only ss,vless --json-out compat.json
```

矩阵用例：`ss` / `vmess` / `vless` / `trojan` / `hysteria2` / `tuic` / `anytls` /
`dns-fake-ip` / `groups` / `listeners`。CI 使用 mock 内核生成 `compat.json`；真实内核矩阵可在本机用
`compat_matrix.py` 生成，不随仓库提交。本机验证记录见
[VALIDATION-v0.0.3.md](VALIDATION-v0.0.3.md)。

## 配置

脚本不硬编码路径。优先级：**环境变量 > `config.json` > 默认目录**。默认目录通常是脚本所在目录；
如果脚本被非 editable `pip install` 装进 `site-packages` / `dist-packages`，默认退到 `~/.proxy-harvest`，
避免历史/备份/日志写进包目录或升级时丢失。

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
| `mihomo_exe` | 内核路径；默认 `base_dir/mihomo/mihomo.exe`（Windows）或 `base_dir/mihomo/mihomo` |
| `curl` | curl 路径；默认 `curl.exe`（Windows）或 `curl` |
| `secret` | 生产 mihomo API 的 secret。不要填 `box` 之类的弱值，短于 8 位会被拒绝 |
| `proxy_prefix` | 订阅加速前缀；设为空串则全部直连 |
| `sources` | 覆盖整个订阅源列表；留空用内置源 |

也可直接用环境变量覆盖，例如 `PH_BASE_DIR=/data/proxy`、`PH_SECRET=...`、`PH_MIHOMO_EXE=...`、
`PH_CURL=...`。测试专用 `PH_MIHOMO_MOCK` 可让 `mihomo_command()` 指向 `mock_mihomo.py`。

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
source-state.json 订阅源基线/突变状态
harvest.log      运行日志（超过 2 MB 自动轮转为 .1）
.harvest.lock    运行锁（OS 文件锁），防 cron 重叠
```

`--clean-dead --apply-clean`、`--prune --apply-prune`、`--rollback` 与抓取/落地一样先拿锁；
`--clean-dead` / `--prune` 的只读报告不加锁。`--cron --dry-run` 只写 `--json` 报告，不写快照、
历史、采样、每日聚合和订阅。

> **生产目录建议放 `geoip.dat` 和 `geosite.dat`。** split 规则优先使用 `GEOSITE`/`GEOIP`；
> 缺这两个文件时脚本会自动降级为 `DOMAIN-SUFFIX,cn,DIRECT` + `MATCH,PROXY`，保证配置仍能启动，
> 但国内直连分流会粗一些。

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
python proxy_harvest.py --clean-dead --apply-clean --dead-min-span 12
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
> 不是 `--deep-verify`。脚本没有 `--deep-verify` 这个参数。

### 值得注意的参数

| 参数 | 作用 |
|---|---|
| `--keep N` | 深度验证前 N 个节点；默认非 cron=0、cron=15；显式 `--keep 0` 可真正关闭深验 |
| `--dry-run` | 全局只读：不落快照/历史/采样/订阅，不清理、不修剪、不回滚、不写临时配置 |
| `--serial-verify` | 深验改回串行（默认并发，每节点独立端口） |
| `--insecure` | 保留 `skip-cert-verify`（默认剥离，会更安全但可用节点变少） |
| `--secret S` | 指定生产 API secret；推荐改用 `PH_SECRET` 环境变量 |
| `--max-nodes N` | 落地到生产配置的节点上限（默认 30，`0` 不限） |
| `--dead-min-span H` | 末尾连续失败段首尾的最短时间跨度，默认 12 小时；必须有限非负 |
| `--verify-content-url` | 内容完整性探测地址；默认关闭，需同时给 sha256 或 text |
| `--verify-content-sha256` | 期望响应体 SHA256，必须 64 位十六进制 |
| `--verify-content-text` | 期望响应体固定文本；与 sha256 二选一 |
| `--verify-https-url` | 额外 HTTPS 探测地址；复用同一期望哈希 |
| `--exit-info` | 深验时记录出口 IP/ASN/地理信息；默认关闭 |
| `--no-health-check` | 落地后跳过健康检查（默认开启，失败自动回滚） |
| `--dns-mode explicit` | 写显式 `dns` 段；默认 `off` 沿用现状 |
| `--dns-servers` | 显式 DNS 的 nameserver，逗号分隔 |

## 数据流

| 层 | 文件 | 内容 |
|---|---|---|
| A 全量快照 | `history/snapshot-YYYYMMDD.jsonl` | 每次抓取的全部节点（含来源 ID/协议组/源哈希；不落订阅 URL） |
| B 采样序列 | `history/samples-YYYYMM.jsonl` | 每节点每次延迟/耗时/评分；含内容/出口字段 |
| C 每日聚合 | `history/latest_daily.csv` | 每日成功率/平均分/平均延迟 |
| D 分组订阅 | `history/subscriptions/*.yaml` | 每组单独的 Clash 配置 |

测试记录写入 `history/proxy-YYYYMM.jsonl`，含完整节点定义，供 `--inherit` 复活常青节点。
`source-state.json` 保存每个源的节点数、协议构成、内容哈希和突变标记，用于下一轮对比。

> **D 层导出包含第三方节点的凭据，仅限本机使用。** 不要把 `history/subscriptions/` 或生产
> `config.yaml` 公开分发；如需分享，只分享节点数量/延迟等元数据。当前未实现“默认不导出”或
> “导出时去凭据”，这是有意的兼容性取舍，使用前请自行控制。

## 安全设计

- **默认只读**：不加 `--apply` / `--cron` 绝不改生产配置；`--dry-run` 连清理/修剪/回滚/临时配置也跳过
- **落地前预检**：测速配置先过 `mihomo -t`，坏节点二分剔除；生产配置落地前同样校验实际规则
- **落地前备份**：每次 apply 自动备份，`--rollback` 可回退，回滚前还会另存当前配置；备份/回滚/订阅备份均为临时文件 + `os.replace()`
- **落地后健康检查**：同源临时实例验证出网，失败自动 `restore_backup()`
- **隔离测速**：临时实例用随机端口，跑完销毁，不影响在用的代理
- **清理保护**：cron 清死节点时排除本轮通过的节点，不误删刚落地的；按稳定 `node_id` 匹配，避免同名新节点被旧历史误删
- **cron 默认 split 规则**：国内流量直连，不会把本机所有程序都塞进代理
- **突变源门禁**：被判定突变的源不落地、不导出
- **来源 URL 隐私**：快照/历史/采样/状态/`--json` 只保存来源 ID，日志不打印订阅 URL 尾部

## 安全边界与适用场景

**这个工具不是隐私工具，也不是“匿名上网”工具。** 它抓的是公开免费节点，节点运营者不可信：

- 节点运营者可以看到你的源 IP、目标域名 / TLS SNI、访问时间和流量特征；明文 HTTP 的内容、DNS 查询也可能被看到。HTTPS 内容本身有端到端加密，但目标是哪个站点仍然暴露。
- **DNS 默认仍是“沿用现状”**。`--dns-mode explicit` 只是显式写出一段配置；默认 fake-ip + DoH 的实际行为已用 `dns_probe.py` 在真实 mihomo 上验证“查询命中本地 mock”，但不等于所有场景都不泄漏。需要严格 DNS 策略时，请自己指定可信 `nameserver` 并复测。
- 内容完整性探测默认关闭，且只覆盖你指定的固定内容 URL；它不能证明整条链路没有被选择性篡改，也不能替代端到端加密。
- 来源信誉分目前是报告和突变门禁，不是排序/准入硬门槛；首次运行没有基线，不会拦截。
- 落地健康检查使用同源临时实例，**不会重启/重载生产 mihomo**；生产进程需要你自行重启后新配置才生效。
- `--cron` 的 split 规则只保证 `.cn` 后缀直连；其它域名（包括登录、支付、工作账号相关站点）仍然可能走免费节点。
- 默认订阅经 `gh-proxy.com` 等第三方前缀，失败时会回退直连；内容哈希只用于检测“源内容是否变化/被篡改”，不是签名校验，不能证明发布者身份。
- 测速用的 `curl` 默认校验证书，未加 `-k`；`--insecure` 只控制节点自身的 `skip-cert-verify`，不代表测试链路“不安全”。

**建议**：不要用免费节点登录重要账号、支付、处理工作敏感数据或传输隐私文件。需要敏感流量时直连，或使用你信任的代理；把免费池限制在 GitHub、下载站等低敏感场景。

## 数据源

默认订阅源（都经 `gh-proxy.com` 直连）：

- `Mahdi0024/ProxyCollector`（带测活，每 24h 更新）
- `mahdibland/V2RayAggregator`
- `ermaozi/get_subscribe`
- `ripaojiedian/freenode`
- `peasoft/NoMoreWalls`
- `mfuu/v2ray`

可用 `config.json` 的 `sources` 字段整体覆盖，或用 `proxy_prefix` 换加速前缀；不配置则用内置源。

## 工程结构

```
proxy_harvest.py   抓取/解析/测速/评分/存储/落地主流程
configgen.py       配置生成层：端口、组、规则、DNS、凭据剥离
mock_mihomo.py     假内核：-t 校验 + HTTP API/代理 stub，供测试/CI
compat_matrix.py   内核兼容矩阵：固定用例 × 多个内核
dns_probe.py       DNS 实测：本地 DNS/HTTP mock + 真实 mihomo
test_parse.py      单元/集成测试（220 项）
```

## 许可

见 LICENSE。

## 免责声明

本项目仅供个人学习与研究使用。抓取公开订阅、测速筛选属于对公开信息的整理；
使用代理节点请遵守所在地法律法规与目标网站的服务条款。作者不对使用后果负责。
