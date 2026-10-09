// async_trait emits `#[must_use]` on desugared methods whose return type
// (`Pin<Box<dyn Future>>`) is already `#[must_use]`; recent clippy flags this
// as `clippy::double_must_use` and CI denies warnings, so allow it crate-wide.
#![allow(clippy::double_must_use)]

pub mod checker;
pub mod config;
pub mod generator;
pub mod logging;
pub mod publish;

pub mod web;
pub mod worker;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainResult {
    pub domain: String,
    /// An authoritative registration-data source reported no record.
    pub registration_record_absent: bool,
    /// Whether a registrar confirmed that the domain can be purchased.
    /// None means no commercial availability provider was queried.
    pub purchasable: Option<bool>,
    pub error: Option<String>,
    pub signatures: Vec<String>,
    pub expiration_date: Option<String>,
    pub rate_limited: bool,
    pub retryable: bool,
    /// Waiting for a provider slot, without consuming a failed-query attempt.
    #[serde(default)]
    pub deferred: bool,
    /// Resume a deferred pipeline without repeating earlier network checks.
    #[serde(default)]
    pub resume_checker: Option<String>,
    pub retry_after_secs: Option<u64>,
    pub trace: Vec<String>,
}

pub enum WorkerMessage {
    Scanning(String),
    Result(DomainResult),
}
