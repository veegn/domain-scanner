use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::RwLock;

use super::circuit_breaker::CircuitBreaker;
use super::traits::{CheckResult, CheckerPriority, DomainChecker};
use async_trait::async_trait;

/// WHOIS Checker with DNS Caching to prevent UDP storms
#[derive(Debug, Clone)]
pub struct WhoisChecker {
    // Cache WHOIS server hostname -> IP
    ip_cache: Arc<RwLock<HashMap<String, IpAddr>>>,
    // Map TLD -> Whois Server Host
    server_map: Arc<HashMap<&'static str, &'static str>>,
    // Circuit breaker for WHOIS rate limits
    cb: Arc<CircuitBreaker>,
}

impl WhoisChecker {
    pub fn new() -> Self {
        let mut m = HashMap::new();
        // Common WHOIS servers
        // gTLDs
        m.insert("com", "whois.verisign-grs.com");
        m.insert("net", "whois.verisign-grs.com");
        m.insert("org", "whois.pir.org");
        m.insert("info", "whois.afilias.net");
        m.insert("biz", "whois.biz");
        m.insert("xyz", "whois.nic.xyz");
        m.insert("top", "whois.nic.top");
        m.insert("tech", "whois.nic.tech");
        m.insert("site", "whois.nic.site");
        m.insert("online", "whois.nic.online");
        m.insert("store", "whois.nic.store");
        m.insert("shop", "whois.nic.shop");
        m.insert("app", "whois.nic.google");
        m.insert("dev", "whois.nic.google");
        m.insert("cloud", "whois.nic.cloud");
        m.insert("club", "whois.nic.club");
        m.insert("fun", "whois.nic.fun");
        m.insert("icu", "whois.nic.icu");
        m.insert("vip", "whois.nic.vip");
        m.insert("work", "whois.nic.work");
        m.insert("link", "whois.uniregistry.net");
        m.insert("click", "whois.uniregistry.net");
        m.insert("help", "whois.uniregistry.net");
        m.insert("moe", "whois.nic.moe");

        // ccTLDs
        m.insert("io", "whois.nic.io");
        m.insert("ai", "whois.nic.ai");
        m.insert("cn", "whois.cnnic.cn");
        m.insert("us", "whois.nic.us");
        m.insert("ca", "whois.cira.ca");
        m.insert("uk", "whois.nic.uk");
        m.insert("de", "whois.denic.de");
        m.insert("fr", "whois.nic.fr");
        m.insert("it", "whois.nic.it");
        m.insert("nl", "whois.sidn.nl");
        m.insert("eu", "whois.eurid.eu");
        m.insert("au", "whois.auda.org.au");
        m.insert("co", "whois.nic.co");
        m.insert("me", "whois.nic.me");
        m.insert("tv", "whois.nic.tv");
        m.insert("cc", "whois.nic.cc");
        m.insert("ru", "whois.tcinet.ru");
        m.insert("ch", "whois.nic.ch");
        m.insert("se", "whois.iis.se");
        m.insert("nu", "whois.iis.nu");
        m.insert("in", "whois.registry.in");
        m.insert("br", "whois.registry.br");
        m.insert("kr", "whois.kr");
        m.insert("jp", "whois.jprs.jp");

        // Add more as needed

        Self {
            ip_cache: Arc::new(RwLock::new(HashMap::new())),
            server_map: Arc::new(m),
            cb: Arc::new(CircuitBreaker::new(5, 120)), // 5 fails -> 2 min cooldown
        }
    }

    /// Resolve IP with caching
    async fn resolve_server(&self, server_host: &str) -> Option<IpAddr> {
        // Fast path: Read lock
        {
            let cache = self.ip_cache.read().await;
            if let Some(&ip) = cache.get(server_host) {
                return Some(ip);
            }
        }

        // Slow path: Resolve DNS
        // Note: Using lookup_host is async and non-blocking
        let addr_str = format!("{}:43", server_host);

        match tokio::net::lookup_host(&addr_str).await {
            Ok(mut addrs) => {
                if let Some(addr) = addrs.next() {
                    let ip = addr.ip();
                    // Update cache
                    let mut cache = self.ip_cache.write().await;
                    cache.insert(server_host.to_string(), ip);
                    return Some(ip);
                }
            }
            Err(_e) => {
                // Log error if needed: println!("DNS Error for {}: {}", server_host, e);
            }
        }
        None
    }

    async fn query_whois(&self, domain: &str, server: &str) -> Result<String, String> {
        let ip = self
            .resolve_server(server)
            .await
            .ok_or_else(|| format!("Could not resolve WHOIS server IP for {}", server))?;

        // Connect directly to IP to avoid repetitive DNS lookups (UDP traffic)
        let stream_future = TcpStream::connect((ip, 43));

        // Short connect timeout to fail fast if blocked
        let mut stream = tokio::time::timeout(Duration::from_secs(3), stream_future)
            .await
            .map_err(|_| "Connection timeout".to_string())?
            .map_err(|e| format!("Connection failed: {}", e))?;

        let query = format!("{}\r\n", domain);
        stream
            .write_all(query.as_bytes())
            .await
            .map_err(|e| format!("Send failed: {}", e))?;

        let mut buffer = String::new();
        let read_future = stream.read_to_string(&mut buffer);

        // Longer read timeout for slow servers
        tokio::time::timeout(Duration::from_secs(10), read_future)
            .await
            .map_err(|_| "Read timeout".to_string())?
            .map_err(|e| format!("Read failed: {}", e))?;

        Ok(buffer)
    }

    /// Simple heuristic to guess if WHOIS response means "Available"
    fn is_available(&self, response: &str) -> bool {
        let lower = response.to_lowercase();
        lower.contains("no match") ||
        lower.contains("not found") ||
        lower.contains("no entries found") ||
        lower.contains("status: free") ||
        lower.contains("domain not found") || 
        // .cn specific
        lower.contains("no matching record")
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
        // Fallback checks run last
        CheckerPriority::Fallback
    }

    async fn check(&self, domain: &str) -> CheckResult {
        if !self.cb.allow_request() {
            return CheckResult::error("WHOIS Circuit Breaker Open");
        }

        let parts: Vec<&str> = domain.split('.').collect();
        let tld = if parts.len() > 1 {
            *parts.last().unwrap()
        } else {
            return CheckResult::error("Invalid domain");
        };

        let server = if let Some(s) = self.server_map.get(tld) {
            *s
        } else {
            // Unknown TLD for internal map, maybe fallback to IANA payload?
            // For now skip
            return CheckResult::available(); // Skip cleanly
        };

        match self.query_whois(domain, server).await {
            Ok(response) => {
                self.cb.record_success();
                if self.is_available(&response) {
                    CheckResult::available()
                } else {
                    CheckResult::registered(vec!["WHOIS".to_string()])
                }
            }
            Err(e) => {
                self.cb.record_failure();
                CheckResult::error(format!("WHOIS: {}", e))
            }
        }
    }

    fn supports_tld(&self, tld: &str) -> bool {
        self.server_map.contains_key(tld)
    }

    fn is_authoritative(&self) -> bool {
        // TCP Whois is usually authoritative
        true
    }
}
