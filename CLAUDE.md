# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
# Build
cargo build                    # Debug build
cargo build --release          # Release build

# Run (default port 3000)
cargo run --release -- --port 3000

# Lint / static analysis
cargo check                    # Fast compilation check (no codegen)
cargo fmt                      # Format code
cargo fmt -- --check           # Check formatting only

# Tests
cargo test --lib               # Unit tests
cargo test --test integration -- --nocapture   # Integration tests
cargo test                     # All tests

# Docker
docker build -t domain-scanner .
docker run -d -p 3000:3000 -v ./data:/app/data -v ./logs:/app/logs domain-scanner
```

## Architecture

**Language**: Rust Edition 2024 (1.85+), Tokio async runtime, Axum web framework, SQLite via SQLx.

### Entry point (`src/main.rs`)

Startup runs a 10-step sequence: parse CLI args → load/create `config.json` → init logging → open SQLite & create schema → seed TLDs/WHOIS servers → build checker registry → spawn background task worker → recover unfinished scans → build Axum router → serve.

### Multi-source checker pipeline (`src/checker/`)

Domain availability is determined by a **priority-ordered pipeline** defined via the `DomainChecker` trait in `src/checker/traits.rs`. The `CheckerRegistry` in `src/checker/registry.rs` orchestrates checkers in order, stopping at the first authoritative "registered" result or on rate-limit:

1. **LocalReserved** (priority 0) — checks RFC 2606 reserved words, no network.
2. **DoH** (priority 10) — DNS-over-HTTPS NS record lookup using 5 providers (AliDNS, DNSPod, Google, Cloudflare, dns.sb), round-robin selected at startup.
3. **RDAP** (priority 20) — RDAP protocol via IANA bootstrap (cached locally, 24h TTL). Custom server overrides from `config.json`.
4. **WHOIS** (priority 30) — TCP port 43 queries to 200+ WHOIS servers from `data/seed.sql` + `config.json` overrides.

Each checker has a `CircuitBreaker` (`src/checker/circuit_breaker.rs`) that trips after 20 failures and recovers after 30s.

See `EXTENDING.md` for the full guide on adding new checkers.

### Background worker (`src/web/queue.rs` + `src/web/scan_runtime.rs`)

A single background task loops forever, polling the `scans` table for the next pending task (ordered by priority DESC, created_at ASC). When a task is found:

1. Mark scan as `running` in DB.
2. Prepare a **job feeder** that generates domain names (combinatorial, dictionary, or direct list) into an `async_channel` (bounded, 1000).
3. Spawn 10 concurrent workers (`src/worker.rs`) that consume from the channel, check each domain through the registry pipeline, and send results back via `mpsc`.
4. Results are batch-persisted to the `results` table (batch size 50) and counter-updated every 50 domains.
5. Retryable errors (timeout, rate-limit) are deferred and replayed after the main pass (up to 3 retry rounds).

### Adaptive throttling (`src/worker.rs`)

When a WHOIS rate limit is detected, `WorkerThrottle` first pauses all workers for 60s, then reduces concurrency by 1. When concurrency reaches 1, it slows down by increasing inter-request delay by 20%. Rate limit data is persisted to `data/cache/whois/rate_limits.json`.

### SSE streaming (`src/web/models.rs` StreamHub)

Real-time updates are pushed via Server-Sent Events:
- `/api/scans/stream` — broadcast scan list changes with event IDs like `v:{version}`.
- `/api/scan/:id/stream` — per-scan status, logs, and result batches with event IDs `l:{log_id};r:{result_id}`.
- Clients reconnect using `Last-Event-ID` for resumption.

### Publish system (`src/publish/`)

Completed scans can be published as static pages under `data/published/{slug}/` with `meta.json`, `data.json`, and a static `index.html`. DB tables `published_scans` and `published_domains` support cross-scan search at `/api/public/search?q=<domain>`.

### Frontend (`web/index.html`)

Single-page vanilla HTML + Tailwind CSS (CDN) admin dashboard. Communicates exclusively via the REST API + SSE streams. The published results browser is at `web/published.html`.

### Database (`src/web/db.rs`)

SQLite with WAL mode (`data/scans.db`). Schema is created on startup via `CREATE TABLE IF NOT EXISTS` — there are no migration files. Tables: `scans`, `scan_payloads`, `results`, `scan_logs`, `tlds`, `whois_servers`, `published_scans`, `published_domains`. The `seed.sql` file inserts ~260 TLDs and ~130 WHOIS server mappings on first run.

### Startup recovery (`src/web/recovery.rs`)

On restart, stale `cancelling`/`pausing` scans are finalized, counter columns are repaired from actual results, and interrupted `running`/`pending` scans are re-queued after their retry window has passed.

### Key types (`src/lib.rs`)

- `DomainResult` — the scan result for a single domain (available, signatures, expiration, error, retry flags, trace).
- `WorkerMessage` — the worker-to-runtime channel message enum: `Scanning(domain)` or `Result(DomainResult)`.

## Upcoming feature: dictionary matching

`dictionary_domain_scan_plan.md` describes a multi-phase plan to add dictionary-based domain generation. Phase 1 (MVP) adds txt file upload parsing to the existing `StartScanRequest`. Phase 2 adds multi-dictionary Cartesian product combinations with lazy iterators. When modifying the scan creation flow, the payload model is `scan_payloads` in the DB and `StartScanRequest` in `src/web/models.rs`.
