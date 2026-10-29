use serde_json::{Value, json};

/// Generates machine-readable discovery information about the MCP server.
/// This allows AI agents or web scrapers visiting the homepage or API to automatically
/// detect the MCP capabilities and connection instructions.
pub fn get_mcp_discovery_info(port: u16) -> Value {
    json!({
        "mcp_version": "2025-03-26",
        "server": {
            "name": "domain-scanner",
            "version": env!("CARGO_PKG_VERSION"),
            "description": "High-performance domain scanner with async long-running task management, dictionary generators, and instant multi-source verification.",
        },
        "transports": {
            "http": {
                "endpoint": "/mcp",
                "url": format!("http://localhost:{}/mcp", port),
                "type": "streamable-http",
                "instructions": "Connect via HTTP POST/GET with Mcp-Session-Id header or SSE stream."
            },
            "stdio": {
                "command": "domain-scanner",
                "args": ["mcp"],
                "instructions": "Run the binary with 'mcp' subcommand to connect via standard input/output."
            }
        },
        "config_examples": {
            "claude_desktop_http": {
                "mcpServers": {
                    "domain-scanner": {
                        "url": format!("http://localhost:{}/mcp", port)
                    }
                }
            },
            "claude_desktop_stdio": {
                "mcpServers": {
                    "domain-scanner": {
                        "command": "cargo",
                        "args": ["run", "--release", "--", "mcp"]
                    }
                }
            }
        },
        "capabilities": {
            "tools": [
                {
                    "name": "create_scan",
                    "description": "Queue an asynchronous long-running domain scan with pattern, dictionary, or direct domain list."
                },
                {
                    "name": "get_scan_status",
                    "description": "Get real-time progress, counters (total, processed, found), and lifecycle status of a scan."
                },
                {
                    "name": "get_scan_results",
                    "description": "Retrieve found available/absent domains from a scan with pagination and filtering."
                },
                {
                    "name": "list_scans",
                    "description": "List existing scan tasks and their summaries."
                },
                {
                    "name": "pause_scan",
                    "description": "Pause a currently running scan task."
                },
                {
                    "name": "resume_scan",
                    "description": "Resume a paused scan task."
                },
                {
                    "name": "delete_scan",
                    "description": "Delete a scan task and its associated records."
                },
                {
                    "name": "check_domain",
                    "description": "Perform an instant, authoritative registration check on a single domain."
                },
                {
                    "name": "batch_check_domains",
                    "description": "Perform instant checks on up to 20 domains in parallel."
                },
                {
                    "name": "list_tlds",
                    "description": "List all configured TLDs and their query endpoints."
                },
                {
                    "name": "list_dictionaries",
                    "description": "List available dictionary wordlists for combinatorial domain generation."
                }
            ]
        }
    })
}
