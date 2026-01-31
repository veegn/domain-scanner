use once_cell::sync::Lazy;
use regex::Regex;
use std::collections::{HashMap, HashSet};

// Lazy initialization of static resources similar to init() or sync.Once in Go
static COMPILED_PATTERNS: Lazy<Vec<Regex>> = Lazy::new(|| {
    let patterns = vec![
        "^[a-z]$",      // Single letter
        "^[a-z]{2}$",   // Two letters
        "^[0-9]{2,3}$", // 2-3 digits
        "^.{1,2}$",     // Very short domains
    ];
    patterns
        .into_iter()
        .filter_map(|p| Regex::new(p).ok())
        .collect()
});

static RESERVED_WORDS: Lazy<HashSet<&'static str>> = Lazy::new(|| {
    let mut s = HashSet::new();
    let words = vec![
        "www",
        "ftp",
        "mail",
        "email",
        "smtp",
        "pop",
        "imap",
        "ns",
        "dns",
        "mx",
        "admin",
        "root",
        "test",
        "demo",
        "example",
        "localhost",
        "api",
        "app",
        "web",
        "site",
        "blog",
        "shop",
        "store",
        "com",
        "net",
        "org",
        "gov",
        "edu",
        "mil",
        "int",
        "info",
        "biz",
        "name",
        "pro",
        "museum",
        "coop",
        "aero",
        "jobs",
        "mobi",
        "travel",
        "xxx",
        "tel",
        "asia",
        "cat",
        "post",
        "geo",
        // Service names
        "google",
        "facebook",
        "twitter",
        "youtube",
        "amazon",
        "microsoft",
        "apple",
        "netflix",
        "instagram",
        "linkedin",
        "whatsapp",
        "telegram",
        "github",
        "gitlab",
        "bitbucket",
        "stackoverflow",
        "reddit",
        "wikipedia",
        "cloudflare",
        "aws",
        "azure",
        "docker",
        "kubernetes",
        "nginx",
        "apache",
        "mysql",
        "postgresql",
        "mongodb",
        "redis",
        "stripe",
        "paypal",
        "bitcoin",
        "ethereum",
        "wordpress",
        "shopify",
        "zoom",
        "slack",
        // Generic terms
        "login",
        "register",
        "signup",
        "signin",
        "logout",
        "profile",
        "account",
        "dashboard",
        "settings",
        "config",
        "preferences",
        "privacy",
        "security",
        "terms",
        "conditions",
        "policy",
        "legal",
        "help",
        "support",
        "contact",
        "about",
        "faq",
        "blog",
        "news",
        "press",
        "media",
        "careers",
        "jobs",
        "team",
        "company",
        "home",
        "index",
        "main",
        "default",
        "landing",
        "welcome",
        "hello",
        "start",
        "begin",
        "download",
        "upload",
        "search",
        "find",
        "discover",
        "explore",
        "browse",
        "navigate",
        "menu",
        "navbar",
    ];
    for w in words {
        s.insert(w);
    }
    s
});

static TECH_PREFIXES: Lazy<HashSet<&'static str>> = Lazy::new(|| {
    let mut s = HashSet::new();
    let prefixes = vec![
        "localhost",
        "dns",
        "ns",
        "mx",
        "mail",
        "smtp",
        "pop",
        "imap",
        "ftp",
        "www",
        "web",
        "server",
        "host",
        "node",
        "db",
        "cache",
        "cdn",
        "api",
        "app",
        "admin",
        "root",
        "sys",
        "net",
        "org",
        "gov",
        "edu",
        "mil",
        "int",
        "com",
        "info",
        "biz",
        "name",
        "pro",
    ];
    for p in prefixes {
        s.insert(p);
    }
    s
});

static TLD_RULES: Lazy<HashMap<&'static str, HashSet<&'static str>>> = Lazy::new(|| {
    let mut m = HashMap::new();

    let com_reserved = vec![
        "com",
        "net",
        "org",
        "edu",
        "gov",
        "mil",
        "int",
        "www",
        "ftp",
        "mail",
        "email",
        "smtp",
        "pop",
        "imap",
        "dns",
        "ns",
        "mx",
        "web",
        "site",
        "blog",
        "shop",
        "store",
        "app",
        "api",
        "admin",
        "root",
        "test",
        "demo",
        "example",
        "localhost",
        "google",
        "facebook",
        "twitter",
        "youtube",
        "amazon",
        "microsoft",
        "apple",
        "netflix",
        "instagram",
        "linkedin",
    ];

    let net_reserved = vec![
        "net",
        "com",
        "org",
        "edu",
        "gov",
        "mil",
        "int",
        "www",
        "ftp",
        "mail",
        "email",
        "smtp",
        "pop",
        "imap",
        "dns",
        "ns",
        "mx",
        "web",
        "site",
        "blog",
        "shop",
        "store",
        "app",
        "api",
        "admin",
        "root",
        "test",
        "demo",
        "example",
        "localhost",
        "network",
        "internet",
        "intranet",
        "extranet",
        "lan",
        "wan",
        "vpn",
    ];

    let org_reserved = vec![
        "org",
        "com",
        "net",
        "edu",
        "gov",
        "mil",
        "int",
        "www",
        "ftp",
        "mail",
        "email",
        "smtp",
        "pop",
        "imap",
        "dns",
        "ns",
        "mx",
        "web",
        "site",
        "blog",
        "shop",
        "store",
        "app",
        "api",
        "admin",
        "root",
        "test",
        "demo",
        "example",
        "localhost",
        "organization",
        "foundation",
        "charity",
        "nonprofit",
        "ngo",
    ];

    let li_reserved = vec![
        "li",
        "com",
        "net",
        "org",
        "edu",
        "gov",
        "mil",
        "int",
        "www",
        "ftp",
        "mail",
        "email",
        "smtp",
        "pop",
        "imap",
        "dns",
        "ns",
        "mx",
        "web",
        "site",
        "blog",
        "shop",
        "store",
        "app",
        "api",
        "admin",
        "root",
        "test",
        "demo",
        "example",
        "localhost",
        "liechtenstein",
        "principality",
        "government",
        "official",
        "royal",
    ];

    // Helper to insert
    fn add_rule(
        map: &mut HashMap<&'static str, HashSet<&'static str>>,
        tld: &'static str,
        list: Vec<&'static str>,
    ) {
        let mut s = HashSet::new();
        for item in list {
            s.insert(item);
        }
        map.insert(tld, s);
    }

    add_rule(&mut m, ".com", com_reserved);
    add_rule(&mut m, ".net", net_reserved);
    add_rule(&mut m, ".org", org_reserved);
    add_rule(&mut m, ".li", li_reserved);

    // Add others as needed if requested, but this matches the provided Go code sample logic roughly

    m
});

pub fn is_reserved_domain(domain: &str) -> bool {
    // Check pattern-based rules
    if is_reserved_by_pattern(domain) {
        return true;
    }

    // Check TLD-specific rules
    if is_reserved_by_tld(domain) {
        return true;
    }

    false
}

fn is_reserved_by_pattern(domain: &str) -> bool {
    let domain_lower = domain.to_lowercase();
    let parts: Vec<&str> = domain_lower.split('.').collect();
    if parts.len() < 2 {
        return false;
    }
    let domain_name = parts[0];

    // Check map
    if RESERVED_WORDS.contains(domain_name) {
        return true;
    }

    // Check compiled patterns
    for re in COMPILED_PATTERNS.iter() {
        if re.is_match(domain_name) {
            return true;
        }
    }

    // Check technical terms with numbers
    if check_technical_pattern(domain_name) {
        return true;
    }

    // Check IP-like patterns
    match domain_name {
        "127" | "192" | "10" | "172" | "255" => true,
        _ => false,
    }
}

fn check_technical_pattern(name: &str) -> bool {
    if TECH_PREFIXES.contains(name) {
        return true;
    }

    // Check for patterns with number suffix
    // Loop from end to find where digits begin
    let chars: Vec<char> = name.chars().collect();
    for i in (0..chars.len()).rev() {
        if !chars[i].is_ascii_digit() {
            // Found non-digit, check prefix
            if i < chars.len() - 1 {
                let prefix: String = chars[0..=i].iter().collect();
                if TECH_PREFIXES.contains(prefix.as_str()) {
                    return true;
                }
            }
            break;
        }
    }
    false
}

fn is_reserved_by_tld(domain: &str) -> bool {
    let domain_lower = domain.to_lowercase();
    let parts: Vec<&str> = domain_lower.split('.').collect();
    if parts.len() < 2 {
        return false;
    }

    let tld = format!(".{}", parts[parts.len() - 1]);
    let domain_name = parts[0];

    if let Some(reserved_map) = TLD_RULES.get(tld.as_str()) {
        return reserved_map.contains(domain_name);
    }

    false
}
