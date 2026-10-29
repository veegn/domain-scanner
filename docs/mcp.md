# Model Context Protocol (MCP) 接入指南

Domain Scanner 原生支持 Anthropic 发起的 **Model Context Protocol (MCP)** 开放协议。通过 MCP，AI 助手（如 Claude Desktop、Cursor、Antigravity、Cline 等）可以直接调用 Domain Scanner 的全套长任务扫描与多源实时判定能力，充当智能域名顾问与资产管理助手。

---

## 目录

1. [架构与传输方式](#一-架构与传输方式)
2. [MCP 工具完整清单 (11 个 Tools)](#二-mcp-工具完整清单)
3. [客户端配置接入](#三-客户端配置接入)
4. [AI 自动发现机制](#四-ai-自动发现机制)
5. [开发与协议安全细节](#五-开发与协议安全细节)

---

## 一、 架构与传输方式

Domain Scanner 提供了**双传输通道（Dual Transport）**，支持不同部署与使用场景：

```
                    ┌──────────────────────────────────────────────┐
                    │               Claude Desktop / Cursor        │
                    └──────────────────────┬───────────────────────┘
                                           │ stdio (JSON-RPC)
                                           ▼
┌──────────────────────────────────────────────────────────────────┐
│  domain-scanner CLI: `cargo run --release -- mcp`                │
│  (子进程模式: 控制台日志重定向至 stderr，保证 stdout 协议纯净)   │
└──────────────────────────────────────────────────────────────────┘

                                    或

                    ┌──────────────────────────────────────────────┐
                    │               Remote Agent / Web AI          │
                    └──────────────────────┬───────────────────────┘
                                           │ HTTP POST/SSE (/mcp)
                                           ▼
┌──────────────────────────────────────────────────────────────────┐
│  domain-scanner Server: `cargo run --release -- --port 3000`     │
│  (常驻服务: Axum Router 挂载 StreamableHttpService)              │
│  - /api/* (现存 Web API)                                         │
│  - /mcp   (MCP 统一服务入口)                                     │
│  - 后台扫描 Worker (共享 Task Queue 与 SQLite)                   │
└──────────────────────────────────────────────────────────────────┘
```

### 1. HTTP 模式（推荐，与 Web 服务共享）
- **端点**：`http://localhost:3000/mcp`
- **特点**：随现有 Web 控制台一同启动，共享后台扫描 Worker、SQLite 数据库及限流监控，支持长任务在后台持续推进。

### 2. Stdio 模式（本地进程直接管道通信）
- **命令**：`domain-scanner mcp` 或 `cargo run --release -- mcp`
- **特点**：作为 Claude Desktop、Cursor 等桌面客户端的本地子进程启动，通过标准输入输出传输 JSON-RPC 消息。

---

## 二、 MCP 工具完整清单

Domain Scanner 向模型提供了 11 个原子工具，涵盖长任务扫描调度、进度监控、结果提取以及即时单/多域名权威检测。

### 1. `create_scan`
提交并排期一个后台长运行扫描任务。支持纯规则生成、自定义域名列表、单字典及多字典笛卡尔积组合。

- **输入参数**：
  - `suffix` (String, 必填): 目标后缀/TLD，如 `".xyz"`, `".com"`, `".ai"`。
  - `length` (Option<usize>): 域名字符长度（纯数字/字母组合模式下有效，默认 3）。
  - `pattern` (Option<String>): 字符集类型：`"d"`（纯数字 0-9）、`"D"`（纯字母 a-z，默认）、`"a"`（字母数字混合）。
  - `regex` (Option<String>): 候选词过滤正则表达式，如 `"^[a-z]{3}$"`。
  - `domains` (Option<Vec<String>>): 直接指定的显式域名列表（用于批量专项扫描）。
  - `prefix` (Option<String>): 附加前缀。
  - `postfix` (Option<String>): 附加后缀。
  - `dictionary_words` (Option<Vec<String>>): 内联字典词条列表。
  - `dictionary_id` (Option<String>): 已上传字典的 UUID。
  - `dictionary_ids` (Option<Vec<String>>): 多个字典 UUID（用于笛卡尔积组合，生成量上限为 200 万）。
  - `separator` (Option<String>): 字典组合时的分隔符（如 `"-"`）。
  - `format_template` (Option<String>): 组合模板（如 `"{0}{1}"`）。
- **返回结构**：
  ```json
  {
    "scan_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
    "status": "pending",
    "message": "Scan task 3fa85f64-... successfully queued and worker notified.",
    "suffix": ".xyz",
    "pattern": "D"
  }
  ```

### 2. `get_scan_status`
查询指定扫描任务的实时执行状态与进度指标。

- **输入参数**：
  - `scan_id` (String, 必填): 扫描任务 UUID。
- **返回结构**：
  ```json
  {
    "scan_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
    "status": "running",
    "total": 17576,
    "processed": 1240,
    "found": 88,
    "progress_percent": 7.05,
    "is_completed": false
  }
  ```
  *(注：`status` 可能为 `pending`、`running`、`finished`、`paused`、`cancelled`、`failed`)*

### 3. `get_scan_results`
分页获取扫描任务中发现的域名。默认只获取未发现注册记录（可用）的域名。

- **输入参数**：
  - `scan_id` (String, 必填): 扫描任务 UUID。
  - `limit` (Option<i64>): 返回记录上限（默认 100，最大 1000）。
  - `offset` (Option<i64>): 分页偏移量（默认 0）。
  - `absent_only` (Option<bool>): 仅筛选未发现注册记录的域名（默认 `true`）。
- **返回结构**：
  ```json
  {
    "scan_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
    "total_returned": 2,
    "results": [
      {
        "domain": "abc.xyz",
        "registration_record_absent": true,
        "purchasable": null,
        "expiration_date": null,
        "signatures": "RDAP, WHOIS"
      }
    ]
  }
  ```

### 4. `list_scans`
列出系统内的所有扫描任务概况。

- **输入参数**：
  - `limit` (Option<i64>): 返回数量（默认 20，最大 100）。
  - `offset` (Option<i64>): 分页偏移量（默认 0）。
- **返回结构**：包含任务 ID、后缀、状态、总数、已扫数、发现数、创建时间列表。

### 5. `pause_scan`
暂停正在运行或排队中的任务。

- **输入参数**：`scan_id` (String, 必填)。
- **返回结构**：`{ "scan_id": "...", "success": true, "message": "Pause signal dispatched." }`

### 6. `resume_scan`
恢复处于暂停状态的任务，将其重新放入就绪队列。

- **输入参数**：`scan_id` (String, 必填)。
- **返回结构**：`{ "scan_id": "...", "success": true, "message": "Scan task resumed and queued." }`

### 7. `delete_scan`
删除扫描任务，并级联清除其所有的候选载荷、日志与检测结果。

- **输入参数**：`scan_id` (String, 必填)。
- **返回结构**：`{ "scan_id": "...", "success": true, "message": "Scan task deleted successfully." }`

### 8. `check_domain`
单域名权威即时检测（同步执行，毫秒级响应，无需在数据库建任务）。

- **输入参数**：
  - `domain` (String, 必填): 完整域名（如 `"mycoolstartup.com"`）。
- **返回结构**：
  ```json
  {
    "domain": "mycoolstartup.com",
    "registration_record_absent": true,
    "expiration_date": null,
    "signatures": ["DNS", "RDAP", "WHOIS"],
    "error": null,
    "rate_limited": false
  }
  ```

### 9. `batch_check_domains`
小批量域名即时并发检测（一次最多 20 个）。适合 AI 进行品牌创意发散时批量校验可用性。

- **输入参数**：
  - `domains` (Vec<String>, 必填): 候选域名列表。
- **返回结构**：包含各域名的 `CheckDomainOutput` 数组及统计总数。

### 10. `list_tlds`
查询系统支持的全部顶级后缀及 WHOIS 服务器映射。

### 11. `list_dictionaries`
查询系统内保存的词库字典列表（UUID、名称、词条总数），便于模型配置笛卡尔积组合。

---

## 三、 客户端配置接入

### 1. Claude Desktop 配置
编辑 Claude Desktop 配置文件（Windows: `%APPDATA%\Claude\claude_desktop_config.json`，macOS: `~/Library/Application Support/Claude/claude_desktop_config.json`）：

#### 选项 A：HTTP 模式（服务需在后台运行）
```json
{
  "mcpServers": {
    "domain-scanner": {
      "url": "http://localhost:3000/mcp"
    }
  }
}
```

#### 选项 B：Stdio 模式（客户端拉起独立进程）
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

### 2. Cursor / Antigravity / Cline 配置
在客户端的 MCP 插件或配置面板中添加：
- **Name**: `domain-scanner`
- **Type**: `sse` / `streamable-http`
- **URL**: `http://localhost:3000/mcp`

---

## 四、 AI 自动发现机制

为支持 Agent 自动理解与无缝集成，系统内置了标准化的自动发现能力：

1. **HTML 语义声明**：
   在 Web 首页 `<head>` 中注入了自动关联信息：
   ```html
   <link rel="alternate" type="application/json+mcp" href="/mcp" title="Domain Scanner MCP Server">
   <link rel="mcp-server" href="/mcp">
   <meta name="mcp-server-url" content="/mcp">
   <meta name="mcp-discovery-endpoint" content="/api/mcp/info">
   ```
2. **机器可读元数据清单**：
   访问 `GET /api/mcp/info` 或 `GET /.well-known/mcp`，返回包含协议版本、端点定义和工具列表的 JSON Schema。
3. **前端一键接入面板**：
   在 Web 控制台右上角点击 **「AI / MCP」** 按钮，支持实时切换 HTTP 与 Stdio 配置并一键复制到剪贴板。

---

## 五、 开发与协议安全细节

1. **控制台输出与 JSON-RPC 隔离**：
   MCP stdio 依赖进程的标准输出（`stdout`）传递 JSON-RPC 消息。为了避免日志污染协议流，在 `src/logging.rs` 中，控制台日志默认输出到 `stderr`，且在 `mcp` 子命令模式下自动关闭控制台日志。
2. **限流与熔断防护**：
   即时类接口（如 `batch_check_domains`）限制最大并发域名数为 20，并受到底层各个检查器内置的 `CircuitBreaker` 熔断机制保护，防止因模型高频调用导致注册局 IP 封禁。

