# Domain Scanner (Rust Web Edition)

[![Rust](https://img.shields.io/badge/rust-1.85%2B-orange.svg)](https://www.rust-lang.org)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](./LICENSE)
[![Docker](https://img.shields.io/badge/docker-ready-blue.svg)](./Dockerfile)

一个基于 Rust 实现的高性能、异步队列域名可用性扫描器。现在已从 CLI 工具全面升级为具备 Web 控制面板和 SQLite 持久化能力的生产级扫描系统。

## 🚀 核心特性

- **现代 Web 界面**：基于 Axum 的 RESTful API 和模块化前端 Dashboard，支持实时日志流和任务状态追踪。
- **智能任务队列**：内置单线程异步任务队列，确保同一时间只有一个扫描任务执行，防止网络拥塞和 IP 封禁。
- **鲁棒性设计**：支持断点续传。服务重启后，未完成的任务会自动从数据库加载并从精确位置恢复。
- **多维度检查引擎**：
  - **DoH (DNS over HTTPS)**：支持 Google/Cloudflare/AliDNS 多源负载均衡。
  - **RDAP (Registration Data Access Protocol)**：支持 IANA 官方引导的权威数据查询。
  - **WHOIS 到期解析**：自动提取到期时间（Expiration Date）并解析域名状态。
  - **本地保留规则**：内置 RFC 2606 规定的保留域名过滤。
- **分层检查策略**：采用 `Local -> Fast (DoH) -> Standard (RDAP) -> Fallback (WHOIS)` 的分层架构，兼顾性能与准确性。
- **结构化日志**：接入 `tracing` 日志系统，支持控制台彩色输出、每日滚动文件存储及自动清理（默认保留 14 天）。

## ⚖️ 法律声明与合规使用

本工具仅用于**学术研究**及**个人域名资产管理**。在使用过程中，请务必遵守以下原则：

1. **尊重服务条款**：大量并发查询可能违反 DoH 或 WHOIS 服务商的 TOS，请根据实际情况调整 `config.json` 中的频率限制。
2. **禁止恶意抢注**：严禁利用本工具进行针对品牌商标的恶意抢注行为。
3. **熔断保护**：系统内置了熔断器（Circuit Breaker），当监测到限流（HTTP 429）或网络故障时会自动降级。

## 🛠️ 快速开始

### 方案 A：使用 Docker (推荐)

项目已配置 GitHub Actions 自动构建，您可以使用极简的 Docker 镜像部署：

```bash
docker pull ghcr.io/veegn/domain-scanner:latest
docker run -d -p 3000:3000 -v ./data:/app/data -v ./logs:/app/logs ghcr.io/veegn/domain-scanner
```

### 方案 B：本地编译运行

确保安装了 Rust (Edition 2024 / 1.85+):

```bash
# 1. 克隆并进入目录
git clone https://github.com/veegn/domain-scanner.git
cd domain-scanner

# 2. 编译并启动
cargo run --release -- --port 3000
```
访问 `http://localhost:3000` 即可开始扫描。

## ⚙️ 核心配置 (`config.json`)

系统在首次启动时会自动生成 `config.json`。您可以根据需要调整：

- `logging`: 配置日志保持时间、存储目录及是否启用文件记录。
- `doh_servers`: 自定义 DoH 服务器列表。
- `whois_servers`: 手动覆盖特定 TLD 的 WHOIS 服务器映射。
- `rdap_bootstrap_url`: 指向 IANA 的 RDAP 引导配置文件。

## 📝 扫描规则说明

- **模式生成**：支持 `d` (数字)、`D` (大写字母)、`a` (小写字母+数字) 灵活组合。
- **正则表达式**：在生成阶段进行过滤。例如 `^a.*123$` 仅扫描以 a 开头 123 结尾的域名。
- **字典上传**：支持纯文本格式，每行一个前缀。

## 📂 项目结构

```text
src/
├── logging.rs       # 结构化日志系统初始化
├── config.rs        # 配置加载与序列化逻辑
├── checker/         # 插件式检查引擎 (DNS, RDAP, WHOIS)
├── web/             # Web 核心模块 (API, DB, Queue)
├── generator.rs     # 高性能域名生成核心
└── worker.rs        # 异步扫描 Worker 逻辑
web/
└── index.html       # 模块化前端应用 (State-Action 架构)
```

## 📜 许可证与作者

- **作者**: Veegn (veegn.me@gmail.com)
- **许可证**: [MIT License](./LICENSE)

---
*Made with ❤️ using Rust and Axum.*
