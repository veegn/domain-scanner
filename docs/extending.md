# 检查器扩展与定制开发指南 (Extending Checkers)

本文档介绍如何为 Domain Scanner 添加新的自定义域名检查器（Checker），接入系统的优先级调度链。

---

## 目录

1. [检查器体系架构](#一-检查器体系架构)
2. [DomainChecker Trait 定义](#二-domainchecker-trait-定义)
3. [CheckResult 与权威判定规范](#三-checkresult-与权威判定规范)
4. [添加自定义检查器的具体步骤](#四-添加自定义检查器的具体步骤)
5. [熔断机制与并发安全](#五-熔断机制与并发安全)
6. [测试与验证](#六-测试与验证)

---

## 一、 检查器体系架构

Domain Scanner 的检查模块位于 `src/checker/`：

```
src/checker/
├── mod.rs                  # 模块入口与重新导出
├── traits.rs               # DomainChecker trait、优先级与 CheckResult 定义
├── registry.rs             # 检查器注册表 (CheckerRegistry)
├── circuit_breaker.rs      # 独立熔断器
├── local.rs                # Priority 0: RFC 2606 本地预留域名检查 (无网络)
├── dnshe.rs                # Priority 5: DNSHE 权威子域名 API 检查 (独占路由)
├── doh.rs                  # Priority 10: DNS-over-HTTPS NS 记录快速预筛
├── rdap.rs                 # Priority 20: 注册局 RDAP 协议检查
├── whois.rs                # Priority 30: 传统 WHOIS TCP 43 端口检查
└── [custom_checker.rs]     # 您的自定义检查器
```

---

## 二、 `DomainChecker` Trait 定义

所有检查器均需实现位于 `src/checker/traits.rs` 中的 `DomainChecker` trait：

```rust
use async_trait::async_trait;
use std::fmt::Debug;

#[async_trait]
pub trait DomainChecker: Send + Sync + Debug {
    /// 检查器唯一标识名称（用于日志和结果签名，如 "WHOIS"、"RDAP"）
    fn name(&self) -> &'static str;

    /// 检查器优先级（数值越小越优先执行）
    fn priority(&self) -> CheckerPriority;

    /// 对单个域名执行检查并返回结果
    async fn check(&self, domain: &str) -> CheckResult;

    /// 判定该检查器是否支持给定的域名或后缀
    fn supports_domain(&self, domain: &str) -> bool {
        true
    }

    /// 是否对该域名拥有独占路由（如 true，则跳过后续常规检查器）
    fn exclusive_for_domain(&self, _domain: &str) -> bool {
        false
    }
}
```

### 优先级枚举 (`CheckerPriority`)

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum CheckerPriority {
    Local = 0,       // 本地检查（无网络消耗，最优先）
    Exclusive = 5,   // 专有/独占检查（如特定服务商 API）
    Fast = 10,       // 快速网络检查（如 DoH）
    Standard = 20,   // 标准注册数据协议（如 RDAP）
    Fallback = 30,   // 后备/慢速协议（如传统 WHOIS）
}
```

---

## 三、 `CheckResult` 与权威判定规范

```rust
#[derive(Debug, Clone)]
pub struct CheckResult {
    /// 权威来源是否明确未发现注册记录
    pub registration_record_absent: bool,
    /// 命中的检测标识签名（如 ["DoH", "RDAP"]）
    pub signatures: Vec<String>,
    /// 错误信息（若发生网络超时或异常）
    pub error: Option<String>,
    /// 到期时间（若域名已注册且能提取到有效期）
    pub expiration_date: Option<String>,
    /// 是否被注册局服务端限流
    pub rate_limited: bool,
    /// 该错误是否可瞬态重试
    pub retryable: bool,
    /// 建议重试等待时间（秒）
    pub retry_after_secs: Option<u64>,
    /// 是否进入延期队列
    pub deferred: bool,
    /// 追踪链路记录
    pub trace: Vec<String>,
}
```

### 权威性黄金准则：
- **只有权威返回明确的否定应答**（如 RDAP 404、WHOIS 包含明确未找到词）时，才能将 `registration_record_absent` 置为 `true`。
- **DNS 查询未命中（NXDOMAIN）或查询超时一律保持未知**，绝对不能直接作为未注册结论。
- `registration_record_absent` 仅代表权威数据库未见记录，不代表可在任意注册商按标准价即刻购买。

---

## 四、 添加自定义检查器的具体步骤

假设我们要添加一个基于第三方可用性 API 的检查器 `CustomApiChecker`：

### 1. 新建检查器文件 `src/checker/custom_api.rs`

```rust
use async_trait::async_trait;
use reqwest::Client;
use std::time::Duration;
use super::traits::{CheckResult, CheckerPriority, DomainChecker};
use super::circuit_breaker::CircuitBreaker;

#[derive(Debug)]
pub struct CustomApiChecker {
    client: Client,
    circuit_breaker: CircuitBreaker,
}

impl CustomApiChecker {
    pub fn new() -> Self {
        Self {
            client: Client::builder()
                .timeout(Duration::from_secs(5))
                .build()
                .unwrap_or_default(),
            circuit_breaker: CircuitBreaker::new(20, Duration::from_secs(30)),
        }
    }
}

#[async_trait]
impl DomainChecker for CustomApiChecker {
    fn name(&self) -> &'static str {
        "CustomAPI"
    }

    fn priority(&self) -> CheckerPriority {
        CheckerPriority::Standard
    }

    async fn check(&self, domain: &str) -> CheckResult {
        if !self.circuit_breaker.allow_request() {
            return CheckResult::circuit_open("CustomAPI circuit open");
        }

        // 执行网络调用逻辑...
        // 成功时调用 self.circuit_breaker.record_success();
        // 失败时调用 self.circuit_breaker.record_failure();

        CheckResult::unknown()
    }
}
```

### 2. 导出模块
编辑 `src/checker/mod.rs`：
```rust
pub mod custom_api;
pub use custom_api::CustomApiChecker;
```

### 3. 注册到 `CheckerRegistry`
在 `src/checker/registry.rs` 的 `with_defaults` 中注册并排序：
```rust
registry.add_checker(Arc::new(CustomApiChecker::new()));
registry.sort_by_priority();
```

---

## 五、 熔断机制与并发安全

1. **避免单点雪崩**：网络请求必须包含超时控制，并挂载 `CircuitBreaker`。连续 20 次超时或 5xx 响应应触发熔断，避免持续阻塞 Worker 协程。
2. **限流识别**：若服务商返回 HTTP 429 或配额警告，必须将 `result.rate_limited = true` 并提供建议等待秒数 `retry_after_secs`，底层的自适应调度器会自动将其降级并推入延期队列。

---

## 六、 测试与验证

为新检查器编写单元测试：

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_custom_api_checker() {
        let checker = CustomApiChecker::new();
        let res = checker.check("example.com").await;
        // 验证返回状态
        assert!(!res.registration_record_absent);
    }
}
```
运行测试验证：
```bash
cargo test --lib checker::custom_api
```

