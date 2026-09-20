# Domain Scanner (Rust Web Edition)

[![Rust](https://img.shields.io/badge/rust-1.88%2B-orange.svg)](https://www.rust-lang.org)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](./LICENSE)
[![Docker](https://img.shields.io/badge/docker-ready-blue.svg)](./Dockerfile)

一个基于 Rust、Axum 和 SQLite 的异步域名注册记录扫描工具。项目提供 Web 控制台、任务队列、实时 SSE 状态流、DNSHE/DoH/RDAP/WHOIS 多源检查、字典组合扫描、公开结果发布和公开域名前缀搜索。

> **重要：**“未发现注册记录”只表示权威 DNSHE/RDAP/WHOIS 响应明确未找到记录，不等于注册商确认该域名当前可购买。溢价、保留、注册局策略、实时库存和渠道限制仍须向注册商查询。

## 核心功能

- Web 控制台：创建扫描任务，查看进度，暂停、恢复、取消任务，发布完成结果。
- 实时更新：任务列表、单任务状态、扫描日志和未发现注册记录的候选域名通过 SSE 推送。
- 扫描来源：支持生成式扫描、手动域名列表、内联字典、持久化字典和多字典组合。
- 多源检查：内置 LocalReserved、DNSHE、DoH、RDAP 和 WHOIS 检查器。
- 任务恢复：候选域名与生成游标在同一事务中保存，恢复时补齐未完成候选并从游标继续生成，支持乱序完成。
- 限流处理：DNSHE 在全部任务和支持后缀间共享固定的 30 次/分钟限制；其他网络检查器按服务端点控制请求间隔。冷却请求进入有界延期队列，到期重试与新候选交替执行，等待配额不消耗失败重试次数。
- 候选去重：对最终拼接出的域名进行规范化和持久化去重，避免字典组合碰撞产生重复网络请求。
- 公开发布：完成后的扫描可以发布为静态页面，并写入公开搜索索引。

## 合规使用

本工具仅用于个人域名资产管理、学术研究和合法的域名注册记录分析。大量查询可能触发 DNSHE、DoH、RDAP 或 WHOIS 服务商的限制，请控制任务规模并遵守相关服务条款。不要使用本工具进行商标侵权、恶意抢注或绕过第三方服务限制。

## 快速开始

### Docker

```bash
docker pull ghcr.io/veegn/domain-scanner:latest
docker run -d -p 3000:3000 \
  -e DNSHE_API_KEY=your-api-key \
  -e DNSHE_API_SECRET=your-api-secret \
  -v ./data:/app/data -v ./logs:/app/logs \
  ghcr.io/veegn/domain-scanner
```

### 本地运行

需要 Rust 1.88+。

```bash
git clone https://github.com/veegn/domain-scanner.git
cd domain-scanner
export DNSHE_API_KEY="your-api-key"
export DNSHE_API_SECRET="your-api-secret"
cargo run --release -- --port 3000
```

访问：

```text
http://localhost:3000
```

公开发布入口：

```text
http://localhost:3000/published.html
```

## 配置

首次启动会自动生成 `config.json`：

```json
{
  "doh_servers": [],
  "whois_servers": {},
  "rdap_servers": {},
  "rdap_bootstrap_url": "https://data.iana.org/rdap/dns.json",
  "scheduler": {
    "max_parallel_tlds": 3,
    "workers_per_scan": 10,
    "max_global_checks": 20
  },
  "logging": {
    "console_enabled": true,
    "file_enabled": true,
    "directory": "logs",
    "file_prefix": "domain-scanner",
    "max_files": 14
  }
}
```

配置说明：

- `doh_servers`：自定义 DoH 服务列表；为空时使用内置默认值。
- `whois_servers`：补充或覆盖 WHOIS server 映射，格式为 `TLD -> host` 或 `TLD -> host:port`。
- `rdap_servers`：补充或覆盖 RDAP endpoint。
- `rdap_bootstrap_url`：RDAP bootstrap 数据源，默认使用 IANA `dns.json`。
- `scheduler`：同时运行的 TLD 分组数、每任务 worker 数、全局网络请求并发上限。服务端点仍保留请求间隔和 `Retry-After` 退避；增加 worker 不会跳过这些限制。
- `logging`：控制台日志、文件日志目录、文件名前缀和保留数量。

### DNSHE 三级域名

`l.cd`、`us.ci`、`bot.cd`、`de5.net`、`ccwu.cc`、`ddns.ge` 和 `bbroot.com` 使用 DNSHE 官方 JSON WHOIS API。凭据只从 `DNSHE_API_KEY` 和 `DNSHE_API_SECRET` 环境变量读取，不会保存到配置数据库或通过设置接口返回。

这些后缀只接受“一个前缀标签 + 后缀”的三级域名。DNSHE 查询间隔至少为 2001 毫秒，即所有任务、worker 和七个后缀合计不超过 30 次/分钟。限流时间保存在 `data/scans.db`，通过原子更新协调使用同一数据库的进程，应用重启不会清空尚未到期的请求间隔。DNSHE 返回错误或限流时不会回退到父级 RDAP/WHOIS，以免产生错误的“未发现注册记录”结果。

同一组 DNSHE 凭据不要同时用于未共享该数据库的其他部署或外部程序；这些请求不在本项目的限流统计范围内。

## 数据目录

```text
data/scans.db                      SQLite 数据库
data/seed.sql                      默认 TLD 和 WHOIS server 种子
data/dictionaries/                 上传的字典文件
data/cache/rdap/                   RDAP bootstrap 本地缓存
data/cache/whois/rate_limits.json  WHOIS 限流缓存
data/published/<slug>/             已发布的静态结果页
logs/                              文件日志
```

## 扫描规则

生成式扫描支持三种模式：

- `d`：数字，字符集 `0-9`
- `D`：字母，字符集 `a-z`
- `a`：字母数字，字符集 `a-z0-9`

其他输入方式：

- `regex`：在生成阶段过滤候选前缀。
- `priority_words`：优先扫描指定前缀。
- `domains`：直接提交完整域名列表。
- `dictionary_words` / `dictionary_id`：按字典词加前缀、后缀和 TLD 生成候选。
- `dictionary_ids`：多字典笛卡尔组合，支持 `{0}`、`{1}` 形式模板。

系统会校验任务规模、正则长度、域名格式、字典词格式和模板格式，避免提交不可控任务。

正则枚举在阻塞任务中执行，按 500 个匹配候选或 50 毫秒分批交付，稀疏匹配无需等待全部枚举结束。候选表用于记录唯一域名和未完成工作；生成游标与候选批次一起提交，结果与候选完成标记一起提交。已有任务首次恢复会建立该记录；后续恢复可直接定位。字典内容改变时会重新枚举，并通过候选表过滤已生成的域名。

任务日志中的 `task.summary` 包含本次运行的 `elapsed_ms`、`conclusive_results`、`conclusive_per_minute`、`provider_deferrals` 和 `failed_attempts`。需要分析各检查阶段时，可启用 `domain_scanner::checker::registry=debug` 日志过滤器，查看 `stage_metrics` 中的耗时、延期和错误类型。正常 NXDOMAIN 只表示 DNS 名称不存在，仍须继续权威注册记录检查。

## 任务状态

任务状态包括：

```text
pending
running
pausing
paused
cancelling
cancelled
finished
failed
```

只有 `finished` 且存在“未发现注册记录”候选域名的扫描可以发布；发布结果不构成可购买保证。

## API 概览

任务接口：

```text
GET    /api/scans
GET    /api/scans/stream
POST   /api/scan
GET    /api/scan/:id
DELETE /api/scan/:id
POST   /api/scan/:id/pause
POST   /api/scan/:id/resume
GET    /api/scan/:id/stream
GET    /api/scan/:id/results?offset=0&limit=500
GET    /api/scan/:id/logs
POST   /api/scan/:id/reorder
```

发布接口：

```text
POST   /api/scan/:id/publish
GET    /api/published
GET    /api/published/:id
PUT    /api/published/:id
DELETE /api/published/:id
```

公开接口：

```text
GET    /api/public/published
GET    /api/public/search?q=<prefix>
```

字典接口：

```text
POST   /api/dictionary?name=<name>
GET    /api/dictionaries
GET    /api/dictionary/:id
PUT    /api/dictionary/:id
DELETE /api/dictionary/:id
GET    /api/dictionary/:id/words?offset=0&limit=100
```

## 开发验证

```bash
cargo fmt
cargo check
cargo test
```

如果 Windows 上已有 `target/debug/domain-scanner.exe` 正在运行，测试或构建可能因为文件锁失败。先停止运行中的服务后再执行完整测试。

## 许可

MIT License。详见 [LICENSE](./LICENSE)。
