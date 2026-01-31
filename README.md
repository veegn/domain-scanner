# Domain Scanner (Rust)

一个用于检查域名可用性的高性能工具，使用 Rust 实现。

## 特性

- 🚀 **高性能**：异步并发设计，支持多 worker 同时检查
- 🔌 **可扩展**：基于 Trait 的插件架构，易于添加新的检查方式
- 🌐 **多协议支持**：
  - DNS over HTTPS (DoH)
  - RDAP (Registration Data Access Protocol)
  - 本地保留域名规则
- 📝 **多种输入模式**：
  - 长度 + 模式生成（字母/数字/混合）
  - 正则表达式过滤
  - 字典文件

## 安装

```bash
# 克隆仓库
git clone https://github.com/xuemian168/domain-scanner.git
cd domain-scanner/domain-scanner-rust

# 编译
cargo build --release

# 运行
./target/release/domain-scanner-rust --help
```

## 使用方法

### 基本用法

```bash
# 检查 3 位字母的 .li 域名
cargo run -- -l 3 -s .li -p D

# 检查 4 位数字的 .com 域名
cargo run -- -l 4 -s .com -p d

# 使用 20 个并发 worker
cargo run -- -l 3 -s .li -p D --workers 20

# 显示已注册的域名
cargo run -- -l 3 -s .li -p D --show-registered
```

### 命令行参数

| 参数 | 说明 | 默认值 |
|------|------|--------|
| `-l, --length` | 域名长度 | 3 |
| `-s, --suffix` | 域名后缀 | .li |
| `-p, --pattern` | 模式：d(数字), D(字母), a(混合) | D |
| `-r, --regex` | 正则表达式过滤 | - |
| `--dict` | 字典文件路径 | - |
| `--delay` | 查询间隔（毫秒） | 1000 |
| `--workers` | 并发 worker 数 | 10 |
| `--show-registered` | 显示已注册域名 | false |
| `--force` | 跳过性能警告 | false |
| `--doh` | DoH 服务器 URL | https://dns.alidns.com/resolve |

### 使用字典

```bash
# 使用自定义字典
cargo run -- --dict words.txt -s .com

# 字典 + 正则过滤
cargo run -- --dict words.txt -s .com -r "^[a-z]{4,8}$"
```

### 正则表达式过滤

```bash
# 以 "abc" 开头
cargo run -- -l 5 -s .li -p D -r "^abc"

# 两字母 + 一数字
cargo run -- -l 3 -s .li -p a -r "^[a-z]{2}[0-9]$"
```

## 项目结构

```
src/
├── checker/                    # 域名检查模块（可扩展）
│   ├── mod.rs                  # 模块入口
│   ├── traits.rs               # DomainChecker trait
│   ├── registry.rs             # 检查器注册表
│   ├── doh.rs                  # DoH 检查器
│   ├── rdap.rs                 # RDAP 检查器
│   └── local.rs                # 本地规则检查器
├── generator.rs                # 域名生成器
├── reserved.rs                 # 保留域名规则
├── types.rs                    # 共享类型
├── worker.rs                   # 工作线程
└── main.rs                     # 程序入口
```

## 扩展

本项目设计为易于扩展。要添加新的域名检查方式：

1. 实现 `DomainChecker` trait
2. 在 `src/checker/mod.rs` 中注册模块
3. 在 `CheckerRegistry` 中添加检查器

详见 [EXTENDING.md](./EXTENDING.md)

## 检查流程

```
域名 → LocalReserved → DoH → RDAP → 结果
       (本地规则)     (DNS)  (注册数据)
```

1. **LocalReserved**：检查本地保留规则（无网络）
2. **DoH**：检查 DNS 记录是否存在（快速）
3. **RDAP**：查询注册数据（权威）

## 依赖

- `tokio` - 异步运行时
- `reqwest` - HTTP 客户端
- `clap` - 命令行解析
- `serde` - 序列化
- `regex` - 正则表达式
- `colored` - 终端颜色

## 许可证

AGPL-3.0

## 作者

www.ict.run

## 链接

- [GitHub](https://github.com/xuemian168/domain-scanner)
- [原 Go 版本](../)
