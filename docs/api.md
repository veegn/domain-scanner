# REST API 与 SSE 流式事件接口规范

Domain Scanner 提供了基于 HTTP 的 RESTful API 以及基于 Server-Sent Events (SSE) 的实时更新流。本文档详细说明所有可用端点、请求参数与返回结构。

---

## 目录

1. [通用规范](#一-通用规范)
2. [扫描任务管理 API](#二-扫描任务管理-api)
3. [SSE 实时流 API](#三-sse-实时流-api)
4. [词库字典 API](#四-词库字典-api)
5. [系统设置与限流监控 API](#五-系统设置与限流监控-api)
6. [公开发布与检索 API](#六-公开发布与检索-api)
7. [MCP 协议与元数据 API](#七-mcp-协议与元数据-api)

---

## 一、 通用规范

- **默认监听地址**：`http://0.0.0.0:3000`
- **请求格式**：`Content-Type: application/json`（文件上传接口为 `multipart/form-data`）
- **错误响应格式**：
  ```json
  {
    "error": "错误描述信息"
  }
  ```

---

## 二、 扫描任务管理 API

### 1. 获取任务列表
- **路径**：`GET /api/scans`
- **说明**：获取所有扫描任务的概要列表，按创建时间降序排列。
- **响应示例**：
  ```json
  [
    {
      "id": "7f09a1b2-...",
      "status": "running",
      "length": 3,
      "suffix": ".xyz",
      "pattern": "D",
      "regex": null,
      "total": 17576,
      "processed": 450,
      "found": 32,
      "priority": 0,
      "created_at": "2026-10-29T03:00:00Z"
    }
  ]
  ```

### 2. 创建扫描任务
- **路径**：`POST /api/scan`
- **请求体参数**：
  ```json
  {
    "length": 3,
    "suffix": ".xyz",
    "pattern": "D",
    "regex": "^[a-z]{3}$",
    "domains": null,
    "dictionary_id": null,
    "dictionary_ids": null,
    "separator": null,
    "format_template": null,
    "prefix": null,
    "postfix": null
  }
  ```
- **响应**：`202 Accepted`，返回新任务的 UUID 字符串，例如 `"7f09a1b2-..."`。

### 3. 获取单个任务状态
- **路径**：`GET /api/scan/:id`
- **响应示例**：
  ```json
  {
    "id": "7f09a1b2-...",
    "status": "running",
    "total": 17576,
    "processed": 1050,
    "found": 78,
    "deferred": 0
  }
  ```

### 4. 暂停扫描任务
- **路径**：`POST /api/scan/:id/pause`
- **响应**：`200 OK`

### 5. 恢复扫描任务
- **路径**：`POST /api/scan/:id/resume`
- **响应**：`200 OK`

### 6. 删除扫描任务
- **路径**：`DELETE /api/scan/:id`
- **说明**：删除任务并级联清除其所有的候选载荷、检测日志与发现结果。
- **响应**：`200 OK`

### 7. 获取任务扫描结果
- **路径**：`GET /api/scan/:id/results`
- **查询参数**：
  - `offset` (i64, 默认 0): 分页偏移量。
  - `limit` (i64, 默认 500, 最大 5000): 返回数量。
  - `after` (i64, 可选): 基于 `event_id`（rowid）的增量游标拉取。
  - `latest` (bool, 可选): 为 true 时按倒序返回最新结果。
- **响应示例**：
  ```json
  [
    {
      "event_id": 101,
      "domain": "abc.xyz",
      "registration_record_absent": true,
      "purchasable": null,
      "expiration_date": null,
      "signatures": "WHOIS"
    }
  ]
  ```

### 8. 获取任务日志
- **路径**：`GET /api/scan/:id/logs`
- **说明**：获取最近最多 500 条任务日志记录。

### 9. 调整任务执行顺序 / 优先级
- **路径**：`POST /api/scan/:id/reorder`
- **请求体**：`{ "priority": 10 }`

---

## 三、 SSE 实时流 API

系统利用 Server-Sent Events 实现高效的双向游标增量同步与断线重连恢复。

### 1. 全局任务列表流
- **路径**：`GET /api/scans/stream`
- **说明**：推送任务列表版本更新，事件 ID 形如 `v:{version}`。客户端重连时带上 `Last-Event-ID`。

### 2. 单任务详情流
- **路径**：`GET /api/scan/:id/stream`
- **查询参数**：
  - `log_after`: 起始日志 ID
  - `result_after`: 起始结果 ID
- **事件类型**：
  - `event: status`: 任务计数与状态。
  - `event: log`: 单条日志追加。
  - `event: result`: 新发现的空闲域名。
  - `event: completed`: 任务全部执行完成。
  - `event: deleted`: 任务被删除。

---

## 四、 词库字典 API

### 1. 上传新词库字典
- **路径**：`POST /api/dictionary`
- **请求格式**：`multipart/form-data`（字段：`name` 和 `file`）。
- **说明**：上传包含换行符分隔单词的 `.txt` 文本，单文件上限支持 200 万词条。

### 2. 查询字典列表
- **路径**：`GET /api/dictionaries`
- **响应示例**：
  ```json
  [
    {
      "id": "e4b6c31a-...",
      "name": "tech-prefixes",
      "word_count": 250,
      "created_at": "2026-10-29T02:00:00Z"
    }
  ]
  ```

### 3. 查看 / 重命名 / 删除字典
- `GET /api/dictionary/:id`: 获取字典元数据。
- `PUT /api/dictionary/:id`: 重命名字典（请求体 `{"name": "new-name"}`）。
- `DELETE /api/dictionary/:id`: 删除字典及其文件。
- `GET /api/dictionary/:id/words`: 分页查看字典包含的具体词条（参数 `offset`, `limit`）。

---

## 五、 系统设置与限流监控 API

### 1. 支持的 TLD 列表
- **路径**：`GET /api/tlds`
- **说明**：返回系统配置的所有后缀与默认 WHOIS 服务器映射。

### 2. 系统运行时设置
- **路径**：`GET /api/settings`
- **说明**：查询 DoH、RDAP、WHOIS 覆盖配置及调度器并发参数。
- **更新设置**：`PUT /api/settings`

### 3. 限流状态监控
- **路径**：`GET /api/rate_limits`
- **说明**：查询当前处于冷却中的检查器服务、剩余冷却时间（秒）以及请求间隔设置。

---

## 六、 公开发布与检索 API

### 1. 发布完成的任务
- **路径**：`POST /api/scan/:id/publish`
- **请求体**：`{ "title": "3-Letter .XYZ Scan", "description": "Weekly run" }`
- **说明**：在 `data/published/{slug}/` 生成静态 HTML 站点，并将发现的域名写入跨任务检索库。

### 2. 公开域名搜索
- **路径**：`GET /api/public/search?q=<query>&limit=50`
- **说明**：跨所有已发布扫描集合快速模糊搜索匹配的可用域名。

### 3. 公开发布集合列表
- **路径**：`GET /api/public/published`

---

## 七、 MCP 协议与元数据 API

- `POST /mcp` 与 `GET /mcp`：Model Context Protocol (Streamable HTTP / SSE) 统一服务入口。
- `GET /api/mcp/info`：返回 MCP 服务器能力描述、11 个工具列表及传输端点信息。
- `GET /.well-known/mcp`：标准开放发现端点（与 `/api/mcp/info` 等价）。

