//! Domain Checker Module
//!
//! This module provides a flexible, extensible architecture for domain availability checking.
//!
//! # Architecture Overview
//!
//! The checker system is built around the `DomainChecker` trait, which defines the interface
//! for all domain checking implementations. Multiple checkers can be combined using the
//! `CheckerRegistry` to provide comprehensive domain availability checking.
//!
//! # Built-in Checkers
//!
//! - **LocalReservedChecker**: Checks against local reserved domain rules (fastest, no network)
//! - **DohChecker**: DNS over HTTPS queries to check for DNS records
//!
//! # Adding a New Checker
//!
//! To add a new checker:
//!
//! 1. Create a new file (e.g., `src/checker/my_checker.rs`)
//! 2. Implement the `DomainChecker` trait
//! 3. Add `pub mod my_checker;` to this file
//! 4. Register in `CheckerRegistry::with_defaults()` or add manually
//!
//! See the [EXTENDING.md](../../../EXTENDING.md) file for detailed instructions.
//!
//! # Example
//!
//! ```rust,ignore
//! use domain_scanner::checker::{CheckerRegistry, CheckResult};
//!
//! #[tokio::main]
//! async fn main() {
//!     let registry = CheckerRegistry::with_defaults(None);
//!     let result = registry.check("example.com").await;
//!     
//!     if result.available {
//!         println!("Domain is available!");
//!     } else {
//!         println!("Domain is registered: {:?}", result.signatures);
//!     }
//! }
//! ```

pub mod circuit_breaker;
pub mod doh;
pub mod local;
pub mod rdap;
pub mod registry;
pub mod traits;
pub mod whois;

// Re-export main types for convenience
pub use doh::DohChecker;
pub use local::LocalReservedChecker;
pub use rdap::RdapChecker;
pub use registry::CheckerRegistry;
pub use traits::{CheckResult, CheckerPriority, DomainChecker};
pub use whois::WhoisChecker;
