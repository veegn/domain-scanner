//! Implementation of Model Context Protocol (MCP) Server for Domain Scanner

use rmcp::{
    handler::server::{
        router::tool::ToolRouter,
        wrapper::{Json, Parameters},
    },
    schemars, tool, tool_router,
};
use serde::{Deserialize, Serialize};
use std::borrow::Cow;
use std::sync::Arc;
use tokio::task::JoinSet;
use uuid::Uuid;

use crate::checker::CheckerRegistry;
use crate::web::dictionary;
use crate::web::models::{AppState, MAX_DICTIONARY_PRODUCT, StartScanRequest};

#[derive(Clone)]
pub struct DomainScannerMcpServer {
    state: Arc<AppState>,
    registry: Arc<CheckerRegistry>,
    #[allow(dead_code)]
    tool_router: ToolRouter<Self>,
}

fn err_invalid(msg: impl Into<Cow<'static, str>>) -> rmcp::ErrorData {
    rmcp::ErrorData::invalid_params(msg, None)
}

fn err_internal(msg: impl Into<Cow<'static, str>>) -> rmcp::ErrorData {
    rmcp::ErrorData::internal_error(msg, None)
}

// -----------------------------------------------------------------------------
// Tool: create_scan
// -----------------------------------------------------------------------------

#[derive(Deserialize, schemars::JsonSchema, Debug, Clone)]
pub struct CreateScanParams {
    /// Target domain suffix / TLD (e.g. ".xyz", ".com", ".ai")
    pub suffix: String,
    /// Length of domain name (e.g. 3, 4). Used for pattern/combinatorial scans. Default is 3.
    #[serde(default)]
    pub length: Option<usize>,
    /// Pattern type: "d" for numeric (0-9), "D" for alphabetic (a-z), "a" for alphanumeric. Default is "D".
    #[serde(default)]
    pub pattern: Option<String>,
    /// Optional regex to filter generated candidates (e.g. "^[a-z]{3}$")
    #[serde(default)]
    pub regex: Option<String>,
    /// Optional explicit list of domain names to scan directly
    #[serde(default)]
    pub domains: Option<Vec<String>>,
    /// Optional prefix to prepend to candidates
    #[serde(default)]
    pub prefix: Option<String>,
    /// Optional postfix to append to candidates
    #[serde(default)]
    pub postfix: Option<String>,
    /// Optional inline list of words for dictionary scanning
    #[serde(default)]
    pub dictionary_words: Option<Vec<String>>,
    /// Optional UUID of an existing dictionary in the system
    #[serde(default)]
    pub dictionary_id: Option<String>,
    /// Optional array of dictionary UUIDs for multi-dictionary Cartesian product
    #[serde(default)]
    pub dictionary_ids: Option<Vec<String>>,
    /// Separator string when combining multiple dictionary words (e.g. "-")
    #[serde(default)]
    pub separator: Option<String>,
    /// Format template for combinations (e.g. "{0}{1}")
    #[serde(default)]
    pub format_template: Option<String>,
}

#[derive(Serialize, schemars::JsonSchema, Debug, Clone)]
pub struct CreateScanOutput {
    pub scan_id: String,
    pub status: String,
    pub message: String,
    pub suffix: String,
    pub pattern: String,
}

// -----------------------------------------------------------------------------
// Tool: get_scan_status
// -----------------------------------------------------------------------------

#[derive(Deserialize, schemars::JsonSchema, Debug, Clone)]
pub struct GetScanStatusParams {
    /// The UUID of the scan task
    pub scan_id: String,
}

#[derive(Serialize, schemars::JsonSchema, Debug, Clone)]
pub struct ScanStatusOutput {
    pub scan_id: String,
    pub status: String,
    pub total: i64,
    pub processed: i64,
    pub found: i64,
    pub progress_percent: f64,
    pub is_completed: bool,
}

// -----------------------------------------------------------------------------
// Tool: get_scan_results
// -----------------------------------------------------------------------------

#[derive(Deserialize, schemars::JsonSchema, Debug, Clone)]
pub struct GetScanResultsParams {
    /// The UUID of the scan task
    pub scan_id: String,
    /// Maximum number of results to return (default: 100, max: 1000)
    #[serde(default)]
    pub limit: Option<i64>,
    /// Offset for pagination (default: 0)
    #[serde(default)]
    pub offset: Option<i64>,
    /// If true (default), returns only absent/available domains. If false, returns all results.
    #[serde(default)]
    pub absent_only: Option<bool>,
}

#[derive(Serialize, schemars::JsonSchema, Debug, Clone)]
pub struct ScanResultItem {
    pub domain: String,
    pub registration_record_absent: bool,
    pub purchasable: Option<bool>,
    pub expiration_date: Option<String>,
    pub signatures: String,
}

#[derive(Serialize, schemars::JsonSchema, Debug, Clone)]
pub struct ScanResultsOutput {
    pub scan_id: String,
    pub total_returned: usize,
    pub results: Vec<ScanResultItem>,
}

// -----------------------------------------------------------------------------
// Tool: list_scans
// -----------------------------------------------------------------------------

#[derive(Deserialize, schemars::JsonSchema, Debug, Clone, Default)]
pub struct ListScansParams {
    /// Maximum number of scans to return (default: 20)
    #[serde(default)]
    pub limit: Option<i64>,
    /// Offset for pagination (default: 0)
    #[serde(default)]
    pub offset: Option<i64>,
}

#[derive(Serialize, schemars::JsonSchema, Debug, Clone)]
pub struct ScanSummaryItem {
    pub id: String,
    pub status: String,
    pub suffix: String,
    pub pattern: String,
    pub length: i64,
    pub total: i64,
    pub processed: i64,
    pub found: i64,
    pub created_at: String,
}

#[derive(Serialize, schemars::JsonSchema, Debug, Clone)]
pub struct ListScansOutput {
    pub total_returned: usize,
    pub scans: Vec<ScanSummaryItem>,
}

// -----------------------------------------------------------------------------
// Tool: pause / resume / delete scan
// -----------------------------------------------------------------------------

#[derive(Deserialize, schemars::JsonSchema, Debug, Clone)]
pub struct ScanControlParams {
    /// The UUID of the scan task
    pub scan_id: String,
}

#[derive(Serialize, schemars::JsonSchema, Debug, Clone)]
pub struct ScanControlOutput {
    pub scan_id: String,
    pub success: bool,
    pub message: String,
}

// -----------------------------------------------------------------------------
// Tool: check_domain (instant)
// -----------------------------------------------------------------------------

#[derive(Deserialize, schemars::JsonSchema, Debug, Clone)]
pub struct CheckDomainParams {
    /// The full domain name to check, e.g. "example.com"
    pub domain: String,
}

#[derive(Serialize, schemars::JsonSchema, Debug, Clone)]
pub struct CheckDomainOutput {
    pub domain: String,
    pub registration_record_absent: bool,
    pub expiration_date: Option<String>,
    pub signatures: Vec<String>,
    pub error: Option<String>,
    pub rate_limited: bool,
}

// -----------------------------------------------------------------------------
// Tool: batch_check_domains (instant)
// -----------------------------------------------------------------------------

#[derive(Deserialize, schemars::JsonSchema, Debug, Clone)]
pub struct BatchCheckDomainsParams {
    /// List of domain names to check in real time (up to 20 domains)
    pub domains: Vec<String>,
}

#[derive(Serialize, schemars::JsonSchema, Debug, Clone)]
pub struct BatchCheckDomainsOutput {
    pub total: usize,
    pub results: Vec<CheckDomainOutput>,
}

// -----------------------------------------------------------------------------
// Tool: list_tlds
// -----------------------------------------------------------------------------

#[derive(Serialize, schemars::JsonSchema, Debug, Clone)]
pub struct TldItem {
    pub tld: String,
    pub whois_server: Option<String>,
}

#[derive(Serialize, schemars::JsonSchema, Debug, Clone)]
pub struct ListTldsOutput {
    pub total: usize,
    pub tlds: Vec<TldItem>,
}

// -----------------------------------------------------------------------------
// Tool: list_dictionaries
// -----------------------------------------------------------------------------

#[derive(Serialize, schemars::JsonSchema, Debug, Clone)]
pub struct DictionaryItem {
    pub id: String,
    pub name: String,
    pub word_count: i64,
    pub created_at: String,
}

#[derive(Serialize, schemars::JsonSchema, Debug, Clone)]
pub struct ListDictionariesOutput {
    pub total: usize,
    pub dictionaries: Vec<DictionaryItem>,
}

// -----------------------------------------------------------------------------
// Server Implementation
// -----------------------------------------------------------------------------

#[tool_router(server_handler)]
impl DomainScannerMcpServer {
    pub fn new(state: Arc<AppState>, registry: Arc<CheckerRegistry>) -> Self {
        Self {
            state,
            registry,
            tool_router: Self::tool_router(),
        }
    }

    /// Create and queue an asynchronous long-running domain scan.
    #[tool(
        description = "Queue an asynchronous long-running domain scan task. Supports combinatorial patterns, custom domains list, and dictionary Cartesian products. Returns the scan_id for tracking."
    )]
    async fn create_scan(
        &self,
        Parameters(params): Parameters<CreateScanParams>,
    ) -> Result<Json<CreateScanOutput>, rmcp::ErrorData> {
        let mut req = StartScanRequest {
            length: params.length.unwrap_or(3),
            suffix: params.suffix.clone(),
            pattern: params.pattern.unwrap_or_else(|| "D".to_string()),
            regex: params.regex,
            priority_words: None,
            domains: params.domains,
            dictionary_words: params.dictionary_words,
            dictionary_id: params.dictionary_id,
            dictionary_ids: params.dictionary_ids,
            separator: params.separator,
            format_template: params.format_template,
            prefix: params.prefix,
            postfix: params.postfix,
        };

        req.normalize();
        if let Err(err) = req.validate() {
            return Err(err_invalid(format!("Invalid scan configuration: {}", err)));
        }

        // Validate dictionary product cap
        if let Some(dict_ids) = &req.dictionary_ids
            && !dict_ids.is_empty()
        {
            let mut total: usize = 1;
            for dict_id in dict_ids {
                match dictionary::get_dictionary(&self.state.db, dict_id).await {
                    Ok(Some(d)) => {
                        let wc = d.word_count as usize;
                        total = total.saturating_mul(wc);
                        if total > MAX_DICTIONARY_PRODUCT {
                            break;
                        }
                    }
                    Ok(None) => {
                        return Err(err_invalid(format!("Dictionary not found: {}", dict_id)));
                    }
                    Err(e) => {
                        return Err(err_internal(format!(
                            "Failed to load dictionary {}: {}",
                            dict_id, e
                        )));
                    }
                }
            }
            if total > MAX_DICTIONARY_PRODUCT {
                return Err(err_invalid(format!(
                    "Dictionary product {} exceeds maximum of {}",
                    total, MAX_DICTIONARY_PRODUCT
                )));
            }
        }

        let scan_id = Uuid::new_v4().to_string();
        let priority_words_json =
            serde_json::to_string(&req.priority_words).unwrap_or_else(|_| "null".to_string());
        let domains_json =
            serde_json::to_string(&req.domains).unwrap_or_else(|_| "null".to_string());
        let dictionary_words_json =
            serde_json::to_string(&req.dictionary_words).unwrap_or_else(|_| "null".to_string());
        let dictionary_ids_json =
            serde_json::to_string(&req.dictionary_ids).unwrap_or_else(|_| "null".to_string());
        let scheduler_key = req.scheduler_key();

        let mut tx = self
            .state
            .db
            .begin()
            .await
            .map_err(|e| err_internal(e.to_string()))?;

        if let Err(e) = sqlx::query(
            "INSERT INTO scans (id, status, length, suffix, pattern, regex, scheduler_key) VALUES (?, 'pending', ?, ?, ?, ?, ?)",
        )
        .bind(&scan_id)
        .bind(req.length as i64)
        .bind(&req.suffix)
        .bind(&req.pattern)
        .bind(&req.regex)
        .bind(&scheduler_key)
        .execute(&mut *tx)
        .await
        {
            return Err(err_internal(e.to_string()));
        }

        if let Err(e) = sqlx::query(
            "INSERT INTO scan_payloads (scan_id, priority_words, domains, dictionary_words, prefix, postfix, dictionary_id, dictionary_ids, separator, format_template) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(&scan_id)
        .bind(priority_words_json)
        .bind(domains_json)
        .bind(dictionary_words_json)
        .bind(&req.prefix)
        .bind(&req.postfix)
        .bind(&req.dictionary_id)
        .bind(&dictionary_ids_json)
        .bind(&req.separator)
        .bind(&req.format_template)
        .execute(&mut *tx)
        .await
        {
            return Err(err_internal(e.to_string()));
        }

        if let Err(e) = tx.commit().await {
            return Err(err_internal(e.to_string()));
        }

        // Wake background scheduler
        let _ = self.state.task_tx.try_send(());
        self.state.streams.notify_scans();

        Ok(Json(CreateScanOutput {
            scan_id: scan_id.clone(),
            status: "pending".to_string(),
            message: format!(
                "Scan task {} successfully queued and worker notified.",
                scan_id
            ),
            suffix: req.suffix,
            pattern: req.pattern,
        }))
    }

    /// Get current execution status, progress, and counters of a scan task.
    #[tool(
        description = "Query progress, lifecycle status (pending, running, finished, paused, cancelled, failed), and counts of a scan task by scan_id."
    )]
    async fn get_scan_status(
        &self,
        Parameters(params): Parameters<GetScanStatusParams>,
    ) -> Result<Json<ScanStatusOutput>, rmcp::ErrorData> {
        let row: Option<(String, String, i64, i64, i64)> =
            sqlx::query_as("SELECT id, status, total, processed, found FROM scans WHERE id = ?")
                .bind(&params.scan_id)
                .fetch_optional(&self.state.db)
                .await
                .map_err(|e| err_internal(e.to_string()))?;

        match row {
            Some((id, status, total, processed, found)) => {
                let progress_percent = if total > 0 {
                    ((processed as f64 / total as f64) * 100.0).clamp(0.0, 100.0)
                } else {
                    0.0
                };
                let is_completed = matches!(
                    status.as_str(),
                    "finished" | "completed" | "cancelled" | "failed"
                );
                Ok(Json(ScanStatusOutput {
                    scan_id: id,
                    status,
                    total,
                    processed,
                    found,
                    progress_percent,
                    is_completed,
                }))
            }
            None => Err(err_invalid(format!(
                "Scan task not found: {}",
                params.scan_id
            ))),
        }
    }

    /// Retrieve found domains from a scan task.
    #[tool(
        description = "Retrieve domain results discovered by a scan task. By default filters for absent/available domains (absent_only=true)."
    )]
    async fn get_scan_results(
        &self,
        Parameters(params): Parameters<GetScanResultsParams>,
    ) -> Result<Json<ScanResultsOutput>, rmcp::ErrorData> {
        let limit = params.limit.unwrap_or(100).clamp(1, 1000);
        let offset = params.offset.unwrap_or(0).max(0);
        let absent_only = params.absent_only.unwrap_or(true);

        type ScanResultRow = (String, bool, Option<bool>, Option<String>, String);
        let rows: Vec<ScanResultRow> = if absent_only {
            sqlx::query_as(
                "SELECT domain, registration_record_absent, purchasable, expiration_date, signatures
                 FROM results
                 WHERE scan_id = ? AND registration_record_absent = 1
                 ORDER BY rowid ASC
                 LIMIT ? OFFSET ?",
            )
            .bind(&params.scan_id)
            .bind(limit)
            .bind(offset)
            .fetch_all(&self.state.db)
            .await
        } else {
            sqlx::query_as(
                "SELECT domain, registration_record_absent, purchasable, expiration_date, signatures
                 FROM results
                 WHERE scan_id = ?
                 ORDER BY rowid ASC
                 LIMIT ? OFFSET ?",
            )
            .bind(&params.scan_id)
            .bind(limit)
            .bind(offset)
            .fetch_all(&self.state.db)
            .await
        }
        .map_err(|e| err_internal(e.to_string()))?;

        let results: Vec<ScanResultItem> = rows
            .into_iter()
            .map(
                |(domain, registration_record_absent, purchasable, expiration_date, signatures)| {
                    ScanResultItem {
                        domain,
                        registration_record_absent,
                        purchasable,
                        expiration_date,
                        signatures,
                    }
                },
            )
            .collect();

        Ok(Json(ScanResultsOutput {
            scan_id: params.scan_id,
            total_returned: results.len(),
            results,
        }))
    }

    /// List recent scan tasks and summaries.
    #[tool(
        description = "List recent domain scan tasks with summary metrics (id, status, suffix, pattern, total, processed, found)."
    )]
    async fn list_scans(
        &self,
        Parameters(params): Parameters<ListScansParams>,
    ) -> Result<Json<ListScansOutput>, rmcp::ErrorData> {
        let limit = params.limit.unwrap_or(20).clamp(1, 100);
        let offset = params.offset.unwrap_or(0).max(0);

        type ScanSummaryRow = (
            String,
            String,
            String,
            String,
            i64,
            i64,
            i64,
            i64,
            Option<String>,
        );
        let rows: Vec<ScanSummaryRow> = sqlx::query_as(
            "SELECT id, status, suffix, pattern, length, total, processed, found, datetime(created_at) as created_at
             FROM scans
             ORDER BY created_at DESC
             LIMIT ? OFFSET ?",
        )
        .bind(limit)
        .bind(offset)
        .fetch_all(&self.state.db)
        .await
        .map_err(|e| err_internal(e.to_string()))?;

        let scans = rows
            .into_iter()
            .map(
                |(id, status, suffix, pattern, length, total, processed, found, created_at)| {
                    ScanSummaryItem {
                        id,
                        status,
                        suffix,
                        pattern,
                        length,
                        total,
                        processed,
                        found,
                        created_at: created_at.unwrap_or_default(),
                    }
                },
            )
            .collect::<Vec<_>>();

        Ok(Json(ListScansOutput {
            total_returned: scans.len(),
            scans,
        }))
    }

    /// Pause a running scan task.
    #[tool(description = "Pause an actively running or pending scan task.")]
    async fn pause_scan(
        &self,
        Parameters(params): Parameters<ScanControlParams>,
    ) -> Result<Json<ScanControlOutput>, rmcp::ErrorData> {
        self.state.task_control.pause(&params.scan_id);

        let res = sqlx::query(
            "UPDATE scans SET status = 'paused' WHERE id = ? AND status IN ('pending', 'running')",
        )
        .bind(&params.scan_id)
        .execute(&self.state.db)
        .await
        .map_err(|e| err_internal(e.to_string()))?;

        self.state.streams.notify_scans();

        Ok(Json(ScanControlOutput {
            scan_id: params.scan_id,
            success: res.rows_affected() > 0,
            message: "Pause signal dispatched.".to_string(),
        }))
    }

    /// Resume a paused scan task.
    #[tool(description = "Resume a paused scan task.")]
    async fn resume_scan(
        &self,
        Parameters(params): Parameters<ScanControlParams>,
    ) -> Result<Json<ScanControlOutput>, rmcp::ErrorData> {
        let res = sqlx::query(
            "UPDATE scans SET status = 'pending' WHERE id = ? AND status IN ('paused', 'pausing')",
        )
        .bind(&params.scan_id)
        .execute(&self.state.db)
        .await
        .map_err(|e| err_internal(e.to_string()))?;

        if res.rows_affected() > 0 {
            let _ = self.state.task_tx.try_send(());
            self.state.streams.notify_scans();
            Ok(Json(ScanControlOutput {
                scan_id: params.scan_id,
                success: true,
                message: "Scan task resumed and queued.".to_string(),
            }))
        } else {
            Ok(Json(ScanControlOutput {
                scan_id: params.scan_id,
                success: false,
                message: "Scan task was not in paused state or does not exist.".to_string(),
            }))
        }
    }

    /// Delete a scan task and its associated records.
    #[tool(description = "Delete a scan task, its candidate payloads, and all scan logs/results.")]
    async fn delete_scan(
        &self,
        Parameters(params): Parameters<ScanControlParams>,
    ) -> Result<Json<ScanControlOutput>, rmcp::ErrorData> {
        self.state.task_control.cancel(&params.scan_id);

        let res = sqlx::query("DELETE FROM scans WHERE id = ?")
            .bind(&params.scan_id)
            .execute(&self.state.db)
            .await
            .map_err(|e| err_internal(e.to_string()))?;

        self.state.streams.cleanup_scan(&params.scan_id).await;
        self.state.streams.notify_scans();

        Ok(Json(ScanControlOutput {
            scan_id: params.scan_id,
            success: res.rows_affected() > 0,
            message: if res.rows_affected() > 0 {
                "Scan task deleted successfully.".to_string()
            } else {
                "Scan task not found.".to_string()
            },
        }))
    }

    /// Check single domain registration status in real time.
    #[tool(
        description = "Perform an instant, real-time authoritative registration check for a single domain name (e.g. example.com) using the multi-source pipeline (DNS/RDAP/WHOIS)."
    )]
    async fn check_domain(
        &self,
        Parameters(params): Parameters<CheckDomainParams>,
    ) -> Json<CheckDomainOutput> {
        let res = self.registry.check(&params.domain).await;
        Json(CheckDomainOutput {
            domain: params.domain,
            registration_record_absent: res.registration_record_absent,
            expiration_date: res.expiration_date,
            signatures: res.signatures,
            error: res.error,
            rate_limited: res.rate_limited,
        })
    }

    /// Check multiple domains in real time (up to 20 domains).
    #[tool(
        description = "Check availability for multiple candidate domains concurrently (up to 20 domains) in real time. Ideal for evaluating AI-generated candidate lists."
    )]
    async fn batch_check_domains(
        &self,
        Parameters(params): Parameters<BatchCheckDomainsParams>,
    ) -> Json<BatchCheckDomainsOutput> {
        let domains: Vec<String> = params.domains.into_iter().take(20).collect();
        let registry = self.registry.clone();

        let mut join_set = JoinSet::new();
        for domain in domains {
            let reg = registry.clone();
            join_set.spawn(async move {
                let res = reg.check(&domain).await;
                CheckDomainOutput {
                    domain,
                    registration_record_absent: res.registration_record_absent,
                    expiration_date: res.expiration_date,
                    signatures: res.signatures,
                    error: res.error,
                    rate_limited: res.rate_limited,
                }
            });
        }

        let mut results = Vec::new();
        while let Some(res) = join_set.join_next().await {
            if let Ok(item) = res {
                results.push(item);
            }
        }

        Json(BatchCheckDomainsOutput {
            total: results.len(),
            results,
        })
    }

    /// List all supported Top-Level Domains (TLDs).
    #[tool(
        description = "List all supported TLDs and their configured WHOIS / RDAP lookup endpoints."
    )]
    async fn list_tlds(&self) -> Result<Json<ListTldsOutput>, rmcp::ErrorData> {
        let rows: Vec<(String, Option<String>)> =
            sqlx::query_as("SELECT tld, whois_server FROM tlds ORDER BY tld ASC")
                .fetch_all(&self.state.db)
                .await
                .map_err(|e| err_internal(e.to_string()))?;

        let tlds = rows
            .into_iter()
            .map(|(tld, whois_server)| TldItem { tld, whois_server })
            .collect::<Vec<_>>();

        Ok(Json(ListTldsOutput {
            total: tlds.len(),
            tlds,
        }))
    }

    /// List all wordlist dictionaries in the system.
    #[tool(
        description = "List all available wordlist dictionaries that can be used for dictionary-based domain scanning."
    )]
    async fn list_dictionaries(&self) -> Result<Json<ListDictionariesOutput>, rmcp::ErrorData> {
        let rows: Vec<(String, String, i64, Option<String>)> = sqlx::query_as(
            "SELECT id, name, word_count, datetime(created_at) as created_at FROM dictionaries ORDER BY created_at DESC",
        )
        .fetch_all(&self.state.db)
        .await
        .map_err(|e| err_internal(e.to_string()))?;

        let dictionaries = rows
            .into_iter()
            .map(|(id, name, word_count, created_at)| DictionaryItem {
                id,
                name,
                word_count,
                created_at: created_at.unwrap_or_default(),
            })
            .collect::<Vec<_>>();

        Ok(Json(ListDictionariesOutput {
            total: dictionaries.len(),
            dictionaries,
        }))
    }
}
