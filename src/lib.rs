pub mod checker;
pub mod config;
pub mod generator;
pub mod reserved;
pub mod state;
pub mod tui;
pub mod worker;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainResult {
    pub domain: String,
    pub available: bool,
    pub error: Option<String>,
    pub signatures: Vec<String>,
}
