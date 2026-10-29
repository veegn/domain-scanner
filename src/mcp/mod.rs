//! MCP (Model Context Protocol) Integration for Domain Scanner

pub mod discovery;
pub mod server;

use axum::{Router, routing::get};
use rmcp::{
    ServiceExt,
    transport::io,
    transport::streamable_http_server::{
        StreamableHttpServerConfig, StreamableHttpService, session::local::LocalSessionManager,
    },
};
use std::sync::Arc;

pub use discovery::get_mcp_discovery_info;
pub use server::DomainScannerMcpServer;

use crate::checker::CheckerRegistry;
use crate::web::models::AppState;

/// Creates an MCP server instance.
pub fn create_mcp_server(
    state: Arc<AppState>,
    registry: Arc<CheckerRegistry>,
) -> DomainScannerMcpServer {
    DomainScannerMcpServer::new(state, registry)
}

/// Creates a Streamable HTTP Tower service for MCP.
pub fn create_mcp_http_service(
    server: DomainScannerMcpServer,
) -> StreamableHttpService<DomainScannerMcpServer, LocalSessionManager> {
    StreamableHttpService::new(
        move || Ok(server.clone()),
        LocalSessionManager::default().into(),
        StreamableHttpServerConfig::default(),
    )
}

/// Mounts the MCP endpoints onto an Axum router:
/// - `/mcp` -> Live Streamable HTTP MCP server (for Claude, Cursor, Antigravity, etc.)
/// - `/api/mcp/info` and `/.well-known/mcp` -> Discovery manifest
pub fn mount_mcp_routes(router: Router, server: DomainScannerMcpServer, port: u16) -> Router {
    let service = create_mcp_http_service(server);
    let discovery_handler = move || async move { axum::Json(get_mcp_discovery_info(port)) };

    router
        .nest_service("/mcp", service)
        .route("/api/mcp/info", get(discovery_handler))
        .route("/.well-known/mcp", get(discovery_handler))
}

/// Runs the MCP server in standard I/O (stdio) mode.
/// Ideal for desktop clients like Claude Desktop or local agents.
pub async fn run_mcp_stdio(server: DomainScannerMcpServer) -> anyhow::Result<()> {
    let service = server.serve(io::stdio());
    service.await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mcp_discovery_manifest() {
        let manifest = get_mcp_discovery_info(3000);
        assert_eq!(manifest["server"]["name"], "domain-scanner");
        assert_eq!(manifest["transports"]["http"]["endpoint"], "/mcp");
        assert_eq!(
            manifest["transports"]["http"]["url"],
            "http://localhost:3000/mcp"
        );
        assert_eq!(manifest["transports"]["stdio"]["command"], "domain-scanner");

        let tools = manifest["capabilities"]["tools"]
            .as_array()
            .expect("tools array");
        assert!(tools.iter().any(|t| t["name"] == "create_scan"));
        assert!(tools.iter().any(|t| t["name"] == "get_scan_status"));
        assert!(tools.iter().any(|t| t["name"] == "get_scan_results"));
        assert!(tools.iter().any(|t| t["name"] == "check_domain"));
        assert!(tools.iter().any(|t| t["name"] == "batch_check_domains"));
        assert!(tools.iter().any(|t| t["name"] == "list_scans"));
        assert!(tools.iter().any(|t| t["name"] == "pause_scan"));
        assert!(tools.iter().any(|t| t["name"] == "resume_scan"));
        assert!(tools.iter().any(|t| t["name"] == "delete_scan"));
        assert!(tools.iter().any(|t| t["name"] == "list_tlds"));
        assert!(tools.iter().any(|t| t["name"] == "list_dictionaries"));
    }
}
