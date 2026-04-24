# Domain Scanner (Rust Web Edition)

[![Rust](https://img.shields.io/badge/rust-1.85%2B-orange.svg)](https://www.rust-lang.org)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](./LICENSE)
[![Docker](https://img.shields.io/badge/docker-ready-blue.svg)](./Dockerfile)

一个基于 Rust、Axum、SQLite 实现的异步域名可用性扫描系统。项目提供 Web 控制台、任务队列、实时扫描状态流、RDAP/WHOIS/DoH 多源检查、公开结果发布和域名检索能力。

## 核心特性

- **Web 控制台**：通过浏览器创建扫描任务、查看最近任务、暂停/恢复/取消任务、导出结果和发布结果页。
- **事件驱动实时更新**：任务列表、扫描进度、域名状态滑动窗口和可用域名结果通过 `SSE` 推送，支持事件编号和断线续传。
- **异步任务队列**：后台队列按优先级执行扫描任务，并在服务重启后恢复未完成任务。
- **多源检查引擎**：
  - `LocalReserved`：本地保留域名检查。
  - `DoH`：DNS-over-HTTPS 快速探测。
  - `RDAP`：支持 IANA bootstrap，并带本地缓存。
  - `WHOIS`：支持 DB seed + `config.json` 覆盖的 server 映射、到期时间解析和限流嗅探。
- **自适应限流**：WHOIS 触发限流后会暂停当前任务、优先降低 worker 并发；并发降到 1 后再降低扫描速度。嗅探到的 WHOIS server 限流值会缓存到本地，供下次启动加载。
- **异常重扫策略**：扫描中遇到 timeout、rate limit 等可重试异常时先记录异常域名，主扫描完成后统一调度异常重扫，并限制重扫轮次。
- **公开发布与检索**：完成的扫描结果可以发布为公开静态页面，并写入检索索引，支持跨发布结果的公开域名搜索。
- **结构化日志**：接入 `tracing`，支持控制台输出、每日文件日志和自动清理。

## 合规使用

本工具仅用于学术研究、个人域名资产管理和合法的域名可用性分析。大量查询可能触发 DoH、RDAP 或 WHOIS 服务商的限制，请控制任务规模并遵守服务条款。

系统内置了熔断、限流、暂停和异常重扫机制，但这些机制不能替代合规使用。严禁利用本工具进行商标侵权、恶意抢注或绕过第三方服务限制的行为。

## 快速开始

### Docker

```bash
docker pull ghcr.io/veegn/domain-scanner:latest
docker run -d -p 3000:3000 -v ./data:/app/data -v ./logs:/app/logs ghcr.io/veegn/domain-scanner
```

### 本地运行

需要 Rust Edition 2024 / Rust 1.85+。

```bash
git clone https://github.com/veegn/domain-scanner.git
cd domain-scanner
cargo run --release -- --port 3000
```

访问：

```text
http://localhost:3000
```

公开发布页入口：

```text
http://localhost:3000/published.html
```

## 配置

首次启动时系统会自动生成 `config.json`。

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

配置项说明：

- `doh_servers`：自定义 DoH 服务列表；为空时使用内置默认。
- `whois_servers`：覆盖或补充 WHOIS server 映射，格式为 `TLD -> host` 或 `TLD -> host:port`。
- `rdap_servers`：覆盖或补充 RDAP endpoint。
- `rdap_bootstrap_url`：RDAP bootstrap 数据源，默认使用 IANA `dns.json`。
- `logging`：控制日志输出位置、文件名前缀和保留数量。

WHOIS 默认映射来自数据库初始化 seed，`config.json` 中的 `whois_servers` 会覆盖默认值。

## 数据与缓存目录

常用运行时文件：

```text
scans.db                         # SQLite 数据库
logs/                            # 每日滚动日志
data/seed.sql                    # TLD 和 WHOIS server 初始化数据
data/cache/rdap/                 # RDAP bootstrap 本地缓存
data/cache/whois/rate_limits.json # WHOIS server 限流嗅探缓存
web/published/<slug>/            # 已发布的静态结果页
```

## 扫描规则

生成式扫描支持三种模式：

- `d`：数字，字符集 `0-9`
- `D`：字母，字符集 `a-z`
- `a`：字母数字，字符集 `a-z0-9`

其他能力：

- `regex`：在生成阶段过滤候选前缀。
- `priority_words`：优先扫描指定词。
- `domains`：直接提交域名列表进行扫描。

系统会校验任务规模、正则长度、域名格式和批量域名数量，避免提交不可控的大任务。

## 任务生命周期

任务状态包括：

- `pending`
- `running`
- `paused`
- `cancelling`
- `cancelled`
- `finished`
- `failed`

支持操作：

- 创建任务
- 暂停任务
- 恢复任务
- 删除或取消任务
- 调整 pending 任务优先级
- 使用已发现可用域名重新扫描
- 发布已完成扫描结果

暂停和 WHOIS 限流冷却不会阻塞删除操作。

## 实时更新

前端主要通过 `SSE` 接收实时事件：

- `/api/scans/stream`：最近任务列表更新。
- `/api/scan/:id/stream`：单个任务的状态、域名状态滑动窗口和结果增量。

单任务流带事件编号，浏览器断线重连时会通过 `Last-Event-ID` 补发缺失的日志和结果批次。

## 公开发布

扫描完成后，可以将结果发布为公开静态页面。发布过程会：

- 生成唯一 `slug`
- 写入 `web/published/<slug>/index.html`
- 写入 `meta.json`
- 写入 `data.json`
- 写入 `published_scans`
- 写入 `published_domains`

公开页面只展示可公开的结果数据，不包含内部 trace、限流细节、worker 状态或调试日志。

公开入口：

```text
/published.html
/published/<slug>/
```

公开检索接口基于 `published_domains` 表，不扫描静态 JSON 文件。

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
GET    /api/scan/:id/results
GET    /api/scan/:id/logs
POST   /api/scan/:id/reorder
```

发布管理接口：

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
GET    /api/public/search?q=<domain>
```

## 项目结构

```text
src/
├── checker/          # LocalReserved, DoH, RDAP, WHOIS 检查器
├── publish/          # 静态结果发布、slug、meta/data/index 生成
├── web/              # API、DB、队列、状态模型
├── config.rs         # config.json 加载与默认配置
├── generator.rs      # 域名候选生成
├── lib.rs            # 公共模型导出
├── logging.rs        # tracing 初始化、文件日志和清理
└── worker.rs         # 扫描 worker 与任务节流

web/
├── index.html        # 管理控制台
├── published.html    # 公开发布列表和域名检索页
└── published/        # 发布生成的静态结果目录
```

## 开发验证

常用检查：

```bash
cargo fmt
cargo check
cargo test --lib
cargo test --test integration -- --nocapture
```

如果本地正在运行 `target/debug/domain-scanner.exe`，Windows 可能会因为文件锁导致完整测试无法重新构建。先停止运行中的服务后再执行完整测试。

## 许可证与作者

- 作者: Veegn (veegn.me@gmail.com)
- 许可证: [MIT License](./LICENSE)
