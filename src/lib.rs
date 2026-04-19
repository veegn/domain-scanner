pub mod checker;
pub mod config;
pub mod generator;
pub mod logging;

pub mod web;
pub mod worker;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainResult {
    pub domain: String,
    pub available: bool,
    pub error: Option<String>,
    pub signatures: Vec<String>,
    pub expiration_date: Option<String>,
    pub rate_limited: bool,
    pub retryable: bool,
    pub retry_after_secs: Option<u64>,
    pub trace: Vec<String>,
}

pub enum WorkerMessage {
    Scanning(String),
    Result(DomainResult),
}
