# Cloudflare IP 发现、检测与 BPB 导出（首版 0.1.0）

本工具使用 FOFA 发现候选 IP，再从运行工具的本机网络检测。原有 `bun run start`
订阅采集流程保留；新命令只使用 Node.js 标准库，无需安装依赖。要求 Node.js 20.12+
（推荐 Node.js 24）；不需要 Bun。

## 运行

在本机创建 `.env.local`，内容如下。该文件已被 Git 忽略，请不要将实际密钥写进命令示例、截图或提交。

```dotenv
FOFA_KEY=你的密钥
```

完整流程（请将 URL 和预期文本替换为自己的 Worker 健康检查地址及其响应）：

```powershell
node --env-file=.env.local ip.mjs run --country JP --test-url https://your-worker.example/health --expect healthy
```

使用 `--country HK`、`--region Tokyo`、`--city Tokyo` 进行筛选；同一字段精确匹配，忽略大小写。
国家参数是两位代码。服务器查询与本地结果复核都应用这些过滤条件。**这些是 FOFA 的资产标签，
不是实测出口地区。** Cloudflare Anycast 的接入位置取决于实际路由。

可分别执行：

```powershell
# 每个池仅查一页、每页 20 条；使用 --kind clean 或 --kind proxy 只查其中一类
node --env-file=.env.local ip.mjs discover --country JP --size 20 --pages 1 --out out/ip

# 每个地址测 3 次，并发上限 5；保留正确 Host/SNI 并校验证书
node ip.mjs probe --input out/ip/discovery.json --test-url https://your-worker.example/health --expect healthy --attempts 3 --concurrency 5 --timeout 5000 --out out/ip

# 合格结果导出；默认成功率 100%、HTTP 延迟 <=1500ms、测试距今 <=24 小时
node ip.mjs export --input out/ip/report.json --top 10 --max-latency 1500 --out out/ip
```

FOFA 密钥仅发送到 `https://fofa.info/api/v1/search/all`，不接受自定义 API 域名，禁止重定向。
异常不回显请求 URL、API 错误正文或密钥。FOFA 可能按账户等级限制字段、查询量及额度，
API 拒绝会返回错误并停止，不进行无界重试。默认每个池最多查询 20 行；可调至每页 100 行、
5 页。发现任务失败时不会使用不完整结果覆盖现有导出。

## 分类依据

| 分类 | 判定依据 | 含义 |
| --- | --- | --- |
| Clean 候选 | 公网地址位于 Cloudflare 当前公布的 IPv4/IPv6 CIDR 内 | 官方网络入口候选，仍须实际测速 |
| Proxy 候选 | 不位于官方 CIDR；ASN 不在 Cloudflare 排除表；服务指纹包含 Cloudflare | 可能的中转入口，未证明 BPB 转发可用 |
| 未分类 | ASN 是 Cloudflare，但地址不在公开 CIDR；或证据不够 | 不自动导出 |

默认 ASN 表仅为 `13335,209242`，可用 `--cf-asns` 替换。不要把文章中的 Google、
其他云厂商 ASN 作为 Cloudflare 官方 ASN。发现时会下载并保存官方 CIDR 快照；下载失败则停止。
可用 `--cf-ranges snapshot.json` 指定离线快照，结构为
`{"cidrs":["104.16.0.0/13","2606:4700::/32"],"fetchedAt":"..."}`；使用者需确认其来源和时效。
公开 CIDR 清单并不覆盖 Cloudflare 所有产品或合作网络，因此首版会保守地遗漏部分可用入口。

候选以 IP:端口去重；首版仅支持 443。循环地址、私网、文档网段、组播及 IPv4 映射 IPv6 等
非公网目标会被拒绝。发现 JSON 中保存查询条件、来源、时间、分类依据与剔除原因计数。
两池合并发现时，以官方 CIDR 分类为准；即使 FOFA 的 ASN 标签导致官方入口出现在 Proxy
查询结果中，也会保留为 Clean 候选。弃用的 IPv6 站点本地地址 `fec0::/10` 同样禁止检测。

## 检测指标及边界

- `tcpMs`：建立 TCP 的时间。
- `tlsMs`：TCP 建立后完成 TLS 握手的时间。
- `httpMs`：从请求开始到 HTTP 响应头的时间，包含 TCP/TLS。
- `successRate`：HTTP 2xx 且包含指定 `--expect` 文本的成功比例。
- `jitterMs`：成功请求 HTTP 时间的总体标准差；延迟汇总使用中位数。
- `transferMbps`：仅指定 `--download` 时计算，表示有界响应体传输速率。

测速直连候选 IP，使用 `--test-url` 的域名作为 SNI 和 Host，严格验证证书；不跟随跳转，
不把 403、证书错误和验证页面自动视作成功。建议始终提供 `--expect`，避免将普通 200
错误页当作可用结果。每次请求有绝对超时与响应体上限（默认 64 KiB，最大 8 MiB），不会无限下载。

下载测试可把 `--test-url` 设为同一 Worker 上足够大的静态文件，配合
`--download --max-bytes 1048576`。小健康检查页面测得的速率仅代表这个小响应，不能代表持续带宽。
可通过导出参数 `--min-mbps` 设置下限；未测吞吐量的候选不能通过正数下限。

本机对 Proxy 候选进行的只是指定目标 HTTPS 检测。**没有测 Worker→Proxy 的 TCP 延迟，
也没有验证 BPB 隧道转发、实际出口地区、IP 信誉或特定服务访问资格。**
报告固定保留 `bpbForwardingVerified:false`、`exitCountry:null`，不将这些结果宣称为验证过的 BPB 节点。
从其他机器或其他网络运行得到的延迟不能替代使用者实际网络的测试。

## BPB 配置导出

以 BPB v5 的设置字段为目标，不部署 Worker、不调用面板写入 API、不更改在线服务。

| 输出 | 用途 |
| --- | --- |
| `discovery.json` | FOFA 查询、分类和网段快照 |
| `report.json` | 检测参数、每次原始指标和汇总 |
| `clean-ips.txt` | 通过门槛的入口，供 Clean IP/Domains 字段使用 |
| `proxy-candidates.txt` | 通过指定目标 HTTPS 检测的待验证 Proxy 候选，含端口 |
| `bpb-settings.patch.json` | 部分设置补丁，默认只包含非空 `cleanIPs` |
| `bpb-settings.patch.dat` | 面板可导入的 Base64 部分设置，导入后与当前设置合并，需人工复核并应用 |
| `export-metadata.json` | 数量、验证边界、风险标签 |
| `bpb-settings.json` | 仅提供 `--bpb-template` 时生成：保留原配置其他字段的合并结果 |
| `bpb-settings.dat` | 仅提供模板时生成，符合 BPB v5 面板原生导入格式的合并备份 |

BPB v5 导出文件使用 `btoa(JSON.stringify(settings))` 编码，文件后缀为 `.dat`；面板以
`JSON.parse(atob(text))` 解码，再与当前设置合并。JSON 文件用于检查，不直接交给面板导入。
可以粘贴文本字段，或将 `bpb-settings.patch.dat` 通过面板的 Import File 导入，复核后再应用。
也可以提供自己的 BPB `.dat` 备份生成保留其他字段的合并备份：

```powershell
node ip.mjs export --input out/ip/report.json --bpb-template bpb-backup.local.dat --out out/ip
```

模板也接受解码后的平铺 JSON 设置对象（包含 `cleanIPs`，不是 HTTP API 响应包装）。
工具同时生成 `bpb-settings.json` 供检查，以及 `bpb-settings.dat` 供原生面板导入。
模板中的非 ASCII 内容会转为 JSON Unicode 转义，确保与面板的 `atob` 解码保持一致。

Proxy 候选默认不进入设置补丁。需要人工在自己的 Worker 链路继续验证时，可显式生成候选配置：

```powershell
node ip.mjs export --input out/ip/report.json --include-proxy-candidates --out out/ip
```

这会在补丁中加入 `proxyIpMode:"proxyip"` 和 `proxyIPs:["IP:443",...]`，
并保持未验证标签。只存在 Proxy 候选而未使用该参数时，导出以非零状态退出。
IPv6 使用方括号；排名先看成功率，再看 HTTP 延迟。无合格结果、过期或不符合地区过滤时，
不会用空补丁覆盖已有可用设置。未产生新完整配置时，先前生成的文件仍是旧结果，应核对元数据时间。

导出结构核对依据（2026-11-01，BPB 主分支 `9b2e33e`）：

- [Clean IP 与 Proxy IP 官方说明](https://github.com/bia-pain-bache/BPB-Worker-Panel/blob/9b2e33e8470b9c5de03a30592e99c640e7b1ae71/docs/en/docs/configuration/vless-trojan.md)
- [BPB 设置字段](https://github.com/bia-pain-bache/BPB-Worker-Panel/blob/9b2e33e8470b9c5de03a30592e99c640e7b1ae71/src/settings/settings.ts)
- [Proxy IP 主设置](https://github.com/bia-pain-bache/BPB-Worker-Panel/blob/9b2e33e8470b9c5de03a30592e99c640e7b1ae71/src/settings/main.ts)
- [备份编码](https://github.com/bia-pain-bache/BPB-Worker-Panel/blob/9b2e33e8470b9c5de03a30592e99c640e7b1ae71/src/handlers/subscription.ts)及[面板导入解码](https://github.com/bia-pain-bache/BPB-Worker-Panel/blob/9b2e33e8470b9c5de03a30592e99c640e7b1ae71/src/assets/panel/script.js)
- [Cloudflare 官方 IPv4](https://www.cloudflare.com/ips-v4)、[IPv6](https://www.cloudflare.com/ips-v6)
- [FOFA API](https://fofa.info/api)、[官方 Go SDK 字段清单](https://github.com/FofaInfo/GoFOFA/blob/main/fields.go)
- [Cloudflare Anycast](https://developers.cloudflare.com/fundamentals/concepts/cloudflare-ip-addresses/)

## 验证与更新公告

0.1.0（2026-11-01）：新增 FOFA 两池发现、网段分类、地区筛选、有界 TCP/TLS/HTTP 与响应体
测速、成功率及波动排名、BPB v5 部分补丁与备份合并导出。此版本作为独立 CLI 提供，
不包含 Web 管理界面、定时调度、代理池轮换、ZoomEye/Censys 接入或在线部署。

离线验证：`node --test tests/ip/core.test.mjs tests/ip/probe.test.mjs tests/ip/cli.test.mjs`。
CI 在 Windows/Linux、Node.js 20/24 执行，无需密钥、不扫描网络。

真实小样本验证已分别调用日本地区两池和不限地区 Clean 池，验证 FOFA、官方网段下载、
HTTPS 检测与实际导出。日本样本中的非官方网段结果未被误导出为 Clean IP。
实测官方入口的 HTTP 延迟超过默认 1500ms，使用 `--max-latency 5000` 后成功导出。
未完成真实 BPB 面板导入、Worker 侧转发或 v2rayN 端到端验收。
