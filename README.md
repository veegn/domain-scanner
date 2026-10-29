# Domain Scanner (Rust Web & MCP Edition)

[![Rust](https://img.shields.io/badge/rust-1.88%2B-orange.svg)](https://www.rust-lang.org)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](./LICENSE)
[![Docker](https://img.shields.io/badge/docker-ready-blue.svg)](./Dockerfile)
[![MCP](https://img.shields.io/badge/MCP-2025--03--26-purple.svg)](./docs/mcp.md)

**Domain Scanner** 是一个基于 **Rust (Edition 2024)**、**Axum** 和 **SQLite** 构建的高性能异步域名注册记录扫描与分析平台。项目深度融合了 Web 管理控制台、自适应任务调度引擎、实时 SSE 状态流、多源级联检查流水线（Local / DNSHE / DoH / RDAP / WHOIS）、词库笛卡尔积生成、公开发布系统，以及原生的 **Model Context Protocol (MCP)** 大模型上下文协议支持。

> **重要声明：**“未发现注册记录（`registration_record_absent = true`）”仅代表权威 DNSHE、RDAP 或 WHOIS 响应明确未找到该域名的注册数据，**不等于注册商确认该域名当前可按普通价格购买**。注册局保留词、溢价定价、实时库存配额及渠道限制仍须向对应注册商查询。详见 [合规使用与免责声明](./docs/disclaimer.md)。

---

## 目录

- [核心功能特性](#核心功能特性)
- [快速开始](#快速开始)
  - [Docker 部署](#docker-部署)
  - [本地编译运行](#本地编译运行)
- [AI & Model Context Protocol (MCP) 接入](#ai--model-context-protocol-mcp-接入)
- [配置说明](#配置说明)
- [专题文档索引 (Docs)](#专题文档索引-docs)
- [合规使用规范](#合规使用规范)

---

## 核心功能特性

- **Web 管理控制台**：提供现代化管理界面，支持创建扫描、查看实时进度、暂停/恢复/取消任务、词库字典管理与公开结果发布。
- **MCP 开放协议集成**：原生内嵌 11 个 MCP Tools，AI Agent（Claude Desktop、Cursor、Antigravity 等）可直接发起后台长任务扫描并监控进度。
- **全链路多源检查**：
  - `LocalReserved` (Priority 0)：本地预留词规则检查（无网络消耗，最优先短路）。
  - `Dnshe` (Priority 5)：专有子域名权威 API 校验（共享 30 次/分钟限流）。
  - `DoH` (Priority 10)：基于 AliDNS、DNSPod、Google、Cloudflare、dns.sb 等公共 DoH 进行快速 NS 预筛。
  - `Rdap` (Priority 20)：基于 IANA Bootstrap 动态路由的标准 RDAP 协议解析。
  - `Whois` (Priority 30)：基于 TCP 43 端口直连 200+ 顶级域注册局服务器并自动嗅探状态词。
- **智能调度与熔断保护**：
  - 检查器均内置 `CircuitBreaker`，连续失败自动熔断并在冷却后探测自愈。
  - `WorkerThrottle` 自适应降频机制，遇到注册局限流自动暂停并阶梯式降速。
  - 瞬态失败进入有界延期重试队列，不浪费失败重试配额。
- **灵活的候选词生成策略**：
  - 纯数字、纯字母及字母数字组合模式。
  - 内存恒定的惰性流式生成器（`CandidateFeeder`），轻松应对百万级组合。
  - 支持持久化字典上传、多字典笛卡尔积组合及自定义拼接模板（如 `{0}-{1}`）。
  - 支持前缀、后缀及复杂的正则表达式实时过滤。
- **崩溃自愈与原子恢复**：
  - 启动阶段自动修复过渡态任务（`pausing`/`cancelling`），依据已持久化数据原子重算进度。
  - 中断的任务自动从断点游标处无缝继续执行，杜绝重复网络请求。
- **实时更新与公开发布**：
  - 基于 Server-Sent Events (SSE) 推送任务状态、操作日志和发现的域名结果，支持 `Last-Event-ID` 断线断点续传。
  - 一键发布静态 HTML 报告，并建立支持前缀与模糊匹配的公开域名索引库。

---

## 快速开始

### Docker 部署

```bash
docker pull ghcr.io/veegn/domain-scanner:latest
docker run -d -p 3000:3000 \
  -e DNSHE_API_KEY=your-api-key \
  -e DNSHE_API_SECRET=your-api-secret \
  -v ./data:/app/data -v ./logs:/app/logs \
  ghcr.io/veegn/domain-scanner
```

### 本地编译运行

需要 **Rust 1.88+**：

```bash
# 1. 克隆代码仓库
git clone https://github.com/veegn/domain-scanner.git
cd domain-scanner

# 2. 配置环境变量 (可选)
export DNSHE_API_KEY="your-api-key"
export DNSHE_API_SECRET="your-api-secret"

# 3. 运行 Web 服务模式 (默认端口 3000)
cargo run --release -- --port 3000
```

服务就绪后：
- **Web 控制台**：`http://localhost:3000`
- **公开发布库**：`http://localhost:3000/published.html`
- **MCP 服务端点**：`http://localhost:3000/mcp`
- **MCP 自发现清单**：`http://localhost:3000/api/mcp/info`

---

## AI & Model Context Protocol (MCP) 接入

Domain Scanner 支持双传输模式连接大模型客户端：

### 1. HTTP 模式（推荐，与 Web 服务同进程）
启动 Web 服务后，直接在 Claude Desktop 或 Cursor 中配置：
```json
{
  "mcpServers": {
    "domain-scanner": {
      "url": "http://localhost:3000/mcp"
    }
  }
}
```

### 2. Stdio 模式（作为独立子进程）
```json
{
  "mcpServers": {
    "domain-scanner": {
      "command": "cargo",
      "args": ["run", "--release", "--", "mcp"]
    }
  }
}
```

### 支持的核心 MCP 工具：
- `create_scan`: 提交后台长任务扫描（组合、字典、正则、列表）。
- `get_scan_status`: 轮询扫描进度、生命周期状态与发现计数。
- `get_scan_results`: 分页提取扫描产出的可用域名清单。
- `check_domain` / `batch_check_domains`: 同步即时权威检测（毫秒级响应，无需入库）。
- `pause_scan` / `resume_scan` / `delete_scan`: 任务生命周期控制。
- `list_scans` / `list_tlds` / `list_dictionaries`: 系统元数据与资产概览。

详细协议说明与客户端集成步骤，请参阅 [MCP 接入指南](./docs/mcp.md)。

---

## 配置说明

首次启动时，系统会自动在数据库中生成默认配置并输出初始模板 `config.json`：

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

- **配置项说明**：
  - `doh_servers`：自定义 DoH 节点；为空时采用内置节点轮询。
  - `whois_servers`：自定义各 TLD 对应的 WHOIS 服务器，优先级高于数据库内置映射。
  - `rdap_bootstrap_url`：IANA RDAP 根路径；留空时禁用引导发现。
  - `scheduler.max_parallel_tlds`：同时支持不同 TLD 独立处理的并发度。
  - `scheduler.workers_per_scan`：单个扫描任务消费域名的并发 Worker 数量（默认 10）。
  - `scheduler.max_global_checks`：跨所有任务允许的最大网络 I/O 并发数。

---

## 专题文档索引 (Docs)

所有深入架构与定制化指南均已归档至 [`docs/`](./docs) 目录：

| 文档 | 主要内容 |
| :--- | :--- |
| 📘 **[系统架构设计与内部机制](./docs/architecture.md)** | 10 步启动依赖链、流水线优先级、CandidateFeeder 惰性生成器、Worker 调度模型、崩溃恢复与状态机设计。 |
| 🤖 **[MCP 接入与开发指南](./docs/mcp.md)** | Model Context Protocol 双通道架构、11 个 MCP Tools 详细输入输出定义、客户端配置范式与安全隔离。 |
| 📡 **[REST API 与 SSE 流式事件规范](./docs/api.md)** | 完整的 RESTful 接口清单、请求参数、返回 JSON Schema、游标分页拉取及 SSE 实时事件定义。 |
| 🔌 **[检查器扩展与定制开发指南](./docs/extending.md)** | 如何实现 `DomainChecker` trait、定义优先级、接入 `CircuitBreaker` 及注册到核心流水线。 |
| ⚖️ **[合规使用与免责声明](./docs/disclaimer.md)** | 负责任使用倡议、反网络抢注（Anti-Cybersquatting）、第三方服务协议遵从及责任限制声明。 |

---

## 合规使用规范

本工具仅用于个人域名资产管理、学术研究与授权技术分析。使用期间必须严格遵守相关第三方服务商（如 DoH 供应商、ICANN、各大顶级域注册局）的使用条款与频率上限。

严禁利用本工具进行分布式拒绝服务攻击（DoS）、恶意扫库、域名抢注侵权或其他破坏互联网公共设施的行为。

---

## 许可证 (License)

本项目基于 [MIT License](./LICENSE) 开源。
