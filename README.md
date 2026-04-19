# Domain Scanner (Rust Web Edition)

一个基于 Rust 实现的高性能、异步队列域名可用性扫描器。现在已从 CLI 工具全面升级为具备 Web 控制面板和 SQLite 持久化能力的生产级扫描系统。

## 🚀 核心特性

- **现代 Web 界面**：基于 Axum 的 RESTful API 和简洁的单页 Dashboard，支持任务实时监控。
- **智能任务队列**：内置异步任务队列，确保同一时间只有一个扫描任务在执行，支持 multi-task 排队。
- **断点续传**：服务重启或崩溃后，未完成的任务会自动重新入列，并从上次扫描的精确位置恢复。
- **灵活的匹配规则**：
  - **长度 + 模式**：支持数字 (d)、字母 (D) 及混合 (a) 模式生成。
  - **正则表达式**：支持在生成阶段进行高性能正则过滤。
  - **优先字典**：支持上传自定义 `.txt` 字典文件进行深度优先扫描。
- **深度检查引擎**：
  - **WHOIS 到期解析**：自动提取域名的到期时间（Expiration Date）。
  - **DoH (DNS over HTTPS)**：极速并发检查。
  - **智能重扫**：支持对已发现的可用域名进行一键增量重扫。
- **数据持久化**：采用 3NF 范式设计的 SQLite 数据库，确保海量扫描结果的读写性能。
- **SEO 友好**：内置优化过的 Meta 标签，支持添加推广链接。

## ⚖️ 法律声明与合规使用

本工具仅用于**学术研究**及**个人域名资产管理**。在使用过程中，请务必遵守以下原则：

1. **尊重服务条款**：大量并发查询可能违反 DoH 或 WHOIS 服务商的 TOS，请根据实际情况调整扫描频率。
2. **禁止恶意抢注**：严禁利用本工具进行针对品牌商标的恶意抢注行为。
3. **熔断保护**：系统内置了熔断器（Circuit Breaker），当检测到服务商限流（HTTP 429）时会自动暂停后续请求。

更多详细条款请参阅 [DISCLAIMER.md](./DISCLAIMER.md)。

## 🛠️ 快速开始

### 1. 编译
确保你已安装 Rust (Edition 2024)。
```bash
cd domain-scanner
cargo build --release
```

### 2. 运行
```bash
# 启动 Web 服务 (默认端口 3000)
cargo run --release -- --port 3000
```
访问 `http://localhost:3000` 即可进入控制面板。

## 📝 字典文件格式示例

上传 **Priority Dictionary** 时，请使用简单的纯文本格式，每行一个单词/组合：
```text
888888
123456
112233
abcabc
```

## 📂 项目结构

```text
src/
├── main.rs          # 服务入口，负责 DB 初始化及任务恢复
├── checker/         # 底层检查引擎 (DNS, WHOIS, 本地规则)
├── web/             # Web 核心模块
│   ├── api.rs       # HTTP 路由与控制器
│   ├── queue.rs     # 任务队列调度与执行引擎
│   ├── db.rs        # 数据库 Schema 与迁移逻辑
│   └── models.rs    # 数据模型
├── generator.rs     # 域名生成与正则过滤引擎
└── worker.rs        # 并发执行 Worker
web/
└── index.html       # 前端控制面板 (Dashboard)
```

## ⚙️ 核心配置

你可以通过修改根目录下的 `config.json` 来调整检查器行为（如 DoH 服务器、RDAP 端点等）。

## 🤝 贡献与扩展

如果你想添加新的域名检查协议（如特定注册商的 API），请参考 [EXTENDING.md](./EXTENDING.md)。

## 📜 许可证

本项目采用 [MIT License](./LICENSE) 开源。
