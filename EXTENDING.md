# 扩展域名检查器指南 (Extending Domain Checkers)

本文档介绍如何为 Domain Scanner 添加新的域名检查方式。

## 架构概述

Domain Scanner 使用基于 Trait 的可扩展架构：

```
src/
├── checker/                    # 域名检查模块
│   ├── mod.rs                  # 模块入口和导出
│   ├── traits.rs               # DomainChecker trait 定义
│   ├── registry.rs             # 检查器注册表
│   ├── doh.rs                  # DNS over HTTPS 检查器
│   ├── rdap.rs                 # RDAP 协议检查器
│   ├── local.rs                # 本地保留域名规则检查器
│   └── [your_checker.rs]       # 您的自定义检查器
├── generator/                  # 域名生成器
├── reserved/                   # 保留域名规则
├── types.rs                    # 共享类型定义
├── worker.rs                   # 工作线程
└── main.rs                     # 程序入口
```

## 核心 Trait

所有检查器必须实现 `DomainChecker` trait：

```rust
#[async_trait]
pub trait DomainChecker: Send + Sync + Debug {
    /// 返回检查器名称（用于日志和签名）
    fn name(&self) -> &'static str;

    /// 返回检查器优先级
    fn priority(&self) -> CheckerPriority;

    /// 检查域名是否可用
    async fn check(&self, domain: &str) -> CheckResult;

    /// 检查是否支持给定的 TLD
    fn supports_tld(&self, tld: &str) -> bool;

    /// 是否为权威检查器（可选，默认 false）
    fn is_authoritative(&self) -> bool { false }
}
```

### 优先级

```rust
pub enum CheckerPriority {
    Local = 0,      // 本地检查（最快，无网络）
    Fast = 10,      // 快速网络检查（如 DoH）
    Standard = 20,  // 标准检查（如 RDAP）
    Fallback = 30,  // 后备/慢速检查（如传统 WHOIS）
}
```

### 检查结果

```rust
pub struct CheckResult {
    pub available: bool,           // 域名是否可注册
    pub signatures: Vec<String>,   // 检测到的签名/标识
    pub error: Option<String>,     // 错误信息
}

// 便捷方法
CheckResult::available()                    // 域名可用
CheckResult::registered(vec!["RDAP"])       // 域名已注册
CheckResult::error("Connection failed")     // 检查失败
```

## 添加新检查器的步骤

### 1. 创建检查器文件

在 `src/checker/` 目录下创建新文件，例如 `whois.rs`：

```rust
//! 传统 WHOIS 协议检查器
//!
//! 使用 TCP 端口 43 查询 WHOIS 服务器

use async_trait::async_trait;
use tokio::net::TcpStream;
use tokio::io::{AsyncWriteExt, AsyncReadExt};
use std::time::Duration;

use super::traits::{CheckResult, CheckerPriority, DomainChecker};

/// WHOIS 检查器配置
#[derive(Debug, Clone)]
pub struct WhoisChecker {
    /// 超时时间（秒）
    pub timeout: u64,
}

impl WhoisChecker {
    pub fn new() -> Self {
        Self { timeout: 5 }
    }
    
    async fn query_whois(&self, domain: &str, server: &str) -> Result<String, String> {
        let address = format!("{}:43", server);
        
        let stream = tokio::time::timeout(
            Duration::from_secs(self.timeout),
            TcpStream::connect(&address)
        ).await
            .map_err(|_| "Connection timeout")?
            .map_err(|e| e.to_string())?;
            
        let mut stream = stream;
        stream.write_all(format!("{}\r\n", domain).as_bytes()).await
            .map_err(|e| e.to_string())?;
            
        let mut response = String::new();
        stream.read_to_string(&mut response).await
            .map_err(|e| e.to_string())?;
            
        Ok(response)
    }
}

impl Default for WhoisChecker {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl DomainChecker for WhoisChecker {
    fn name(&self) -> &'static str {
        "WHOIS"
    }

    fn priority(&self) -> CheckerPriority {
        CheckerPriority::Fallback  // 作为后备检查器
    }

    async fn check(&self, domain: &str) -> CheckResult {
        // 根据 TLD 选择 WHOIS 服务器
        let server = "whois.iana.org";  // 简化示例
        
        match self.query_whois(domain, server).await {
            Ok(response) => {
                let response_lower = response.to_lowercase();
                
                // 检查可用性指示词
                if response_lower.contains("no match") 
                    || response_lower.contains("not found")
                    || response_lower.contains("status: free") 
                {
                    return CheckResult::available();
                }
                
                // 检查已注册指示词
                if response_lower.contains("registrar:")
                    || response_lower.contains("creation date:")
                    || response_lower.contains("name server:")
                {
                    return CheckResult::registered(vec!["WHOIS".to_string()]);
                }
                
                // 无法确定，返回可用（让其他检查器确认）
                CheckResult::available()
            }
            Err(e) => CheckResult::error(format!("WHOIS query failed: {}", e)),
        }
    }

    fn supports_tld(&self, _tld: &str) -> bool {
        true  // WHOIS 理论上支持所有 TLD
    }

    fn is_authoritative(&self) -> bool {
        false  // WHOIS 响应可能不够准确
    }
}
```

### 2. 注册检查器模块

编辑 `src/checker/mod.rs`，添加模块声明：

```rust
pub mod doh;
pub mod local;
pub mod rdap;
pub mod registry;
pub mod traits;
pub mod whois;  // 添加这行

// 重新导出
pub use whois::WhoisChecker;  // 添加这行
```

### 3. 添加到注册表（可选）

如果希望默认启用新检查器，编辑 `src/checker/registry.rs`：

```rust
pub fn with_defaults(doh_url: Option<String>) -> Self {
    let mut registry = Self::new();

    registry.add_checker(Arc::new(LocalReservedChecker::new()));
    registry.add_checker(Arc::new(doh_checker));
    registry.add_checker(Arc::new(RdapChecker::new()));
    
    // 添加 WHOIS 作为后备
    registry.add_checker(Arc::new(WhoisChecker::new()));

    registry.sort_by_priority();
    registry
}
```

### 4. 手动添加检查器

也可以在 `main.rs` 中手动添加：

```rust
let mut registry = CheckerRegistry::new();
registry.add_checker(Arc::new(LocalReservedChecker::new()));
registry.add_checker(Arc::new(DohChecker::with_url(args.doh.clone())));
registry.add_checker(Arc::new(RdapChecker::new()));
registry.add_checker(Arc::new(WhoisChecker::new()));  // 手动添加
registry.sort_by_priority();
```

## 检查器执行流程

1. 检查器按优先级排序（低值 = 高优先级）
2. 依次执行每个检查器的 `check()` 方法
3. 收集所有签名
4. 如果任一检查器返回"已注册"且该检查器是权威的，停止检查
5. 如果所有检查器都返回"可用"，域名被标记为可用

## 示例：添加 Zone File 检查器

```rust
//! Zone File 检查器
//! 直接查询 DNS Zone 文件判断域名是否存在

use async_trait::async_trait;
use super::traits::{CheckResult, CheckerPriority, DomainChecker};

#[derive(Debug, Clone)]
pub struct ZoneFileChecker {
    zone_file_url: String,
}

impl ZoneFileChecker {
    pub fn new(zone_file_url: impl Into<String>) -> Self {
        Self { zone_file_url: zone_file_url.into() }
    }
}

#[async_trait]
impl DomainChecker for ZoneFileChecker {
    fn name(&self) -> &'static str { "ZoneFile" }
    
    fn priority(&self) -> CheckerPriority { CheckerPriority::Fast }
    
    async fn check(&self, domain: &str) -> CheckResult {
        // 实现 Zone 文件查询逻辑
        // ...
        CheckResult::available()
    }
    
    fn supports_tld(&self, tld: &str) -> bool {
        // 只支持特定 TLD
        tld == "com" || tld == "net"
    }
    
    fn is_authoritative(&self) -> bool {
        true  // Zone 文件是权威来源
    }
}
```

## 最佳实践

1. **错误处理**：使用 `CheckResult::error()` 返回错误，不要 panic
2. **超时设置**：所有网络请求都应设置合理的超时
3. **支持的 TLD**：准确实现 `supports_tld()`，避免对不支持的 TLD 发起无效请求
4. **权威性**：只有能提供可靠结果的检查器才应返回 `is_authoritative() = true`
5. **优先级**：选择合适的优先级，快速检查器应有更高优先级
6. **连接复用**：使用 `once_cell::sync::Lazy` 创建共享的 HTTP 客户端

## 测试

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_whois_checker() {
        let checker = WhoisChecker::new();
        
        // 测试已知已注册的域名
        let result = checker.check("google.com").await;
        assert!(!result.available);
        
        // 测试可能可用的域名（需要小心选择）
        // let result = checker.check("xyzabc123notexist.com").await;
        // assert!(result.available);
    }
}
```

## 贡献指南

1. 创建新分支：`git checkout -b feature/my-checker`
2. 实现检查器并添加测试
3. 更新本文档
4. 提交 Pull Request

如有问题，请在 GitHub Issues 中反馈。
