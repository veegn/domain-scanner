# Domain Scanner (Rust Web Edition)

[![Rust](https://img.shields.io/badge/rust-1.85%2B-orange.svg)](https://www.rust-lang.org)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](./LICENSE)
[![Docker](https://img.shields.io/badge/docker-ready-blue.svg)](./Dockerfile)

一个基于 Rust、Axum 和 SQLite 的异步域名可用性扫描工具。项目提供 Web 控制台、任务队列、实时 SSE 状态流、DoH/RDAP/WHOIS 多源检查、字典组合扫描、公开结果发布和公开域名前缀搜索。

## 核心功能

- Web 控制台：创建扫描任务，查看进度，暂停、恢复、取消任务，发布完成结果。
- 实时更新：任务列表、单任务状态、扫描日志和可用域名通过 SSE 推送。
- 扫描来源：支持生成式扫描、手动域名列表、内联字典、持久化字典和多字典组合。
- 多源检查：内置 LocalReserved、DoH、RDAP 和 WHOIS 检查器。
- 任务恢复：服务启动时恢复未完成任务，并修复计数器。
- 限流处理：WHOIS 检测到限流或超时后会退避、降低并发并记录可重试异常。
- 公开发布：完成后的扫描可以发布为静态页面，并写入公开搜索索引。

## 合规使用

本工具仅用于个人域名资产管理、学术研究和合法的域名可用性分析。大量查询可能触发 DoH、RDAP 或 WHOIS 服务商的限制，请控制任务规模并遵守相关服务条款。不要使用本工具进行商标侵权、恶意抢注或绕过第三方服务限制。

## 快速开始

### Docker

```bash
docker pull ghcr.io/veegn/domain-scanner:latest
docker run -d -p 3000:3000 -v ./data:/app/data -v ./logs:/app/logs ghcr.io/veegn/domain-scanner
```

### 本地运行

需要 Rust 1.85+。

```bash
git clone https://github.com/veegn/domain-scanner.git
cd domain-scanner
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
- `logging`：控制台日志、文件日志目录、文件名前缀和保留数量。

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

只有 `finished` 且存在可用域名的扫描可以发布。

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
