//! Local centralized gzip zone-data checker.
//!
//! A zone snapshot is only extracted once globally and shared among concurrent lookups.
//! The uncompressed temporary file is automatically cleaned up after 5 minutes of inactivity.

use async_trait::async_trait;
use flate2::read::GzDecoder;
use std::cmp::Ordering;
use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufRead, BufReader, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::{broadcast, Mutex};

use super::traits::{CheckResult, CheckerPriority, DomainChecker};

const ZONE_DATA_DIR: &str = "data/centralized_zone_data";
const IDLE_TIMEOUT_SECS: u64 = 300; // 5 minutes

fn now_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs()
}

struct ExtractedZone {
    path: PathBuf,
    last_accessed: Arc<AtomicU64>,
}

enum ZoneState {
    Empty,
    Extracting(broadcast::Receiver<Result<PathBuf, String>>),
    Ready(ExtractedZone),
}

struct ZoneManager {
    gzip_path: PathBuf,
    apex: Vec<u8>,
    state: Mutex<ZoneState>,
}

impl std::fmt::Debug for ZoneManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ZoneManager")
            .field("gzip_path", &self.gzip_path)
            .field("apex", &self.apex)
            .field("state", &"<Mutex>")
            .finish()
    }
}

impl Drop for ZoneManager {
    fn drop(&mut self) {
        if let ZoneState::Ready(extracted) = self.state.get_mut() {
            let _ = fs::remove_file(&extracted.path);
        }
    }
}

impl ZoneManager {
    fn new(gzip_path: PathBuf, apex: Vec<u8>) -> Self {
        Self {
            gzip_path,
            apex,
            state: Mutex::new(ZoneState::Empty),
        }
    }

    async fn get_extracted_path(self: &Arc<Self>) -> Result<PathBuf, String> {
        let mut rx = {
            let mut state = self.state.lock().await;
            
            loop {
                match &*state {
                    ZoneState::Ready(extracted) => {
                        extracted.last_accessed.store(now_secs(), AtomicOrdering::Relaxed);
                        if extracted.path.exists() {
                            return Ok(extracted.path.clone());
                        } else {
                            *state = ZoneState::Empty;
                            continue;
                        }
                    }
                    ZoneState::Extracting(rx) => {
                        break rx.resubscribe();
                    }
                    ZoneState::Empty => {
                        let (tx, rx) = broadcast::channel(1);
                        *state = ZoneState::Extracting(rx.resubscribe());

                        let manager_clone = self.clone();
                        tokio::spawn(async move {
                            let gzip_path = manager_clone.gzip_path.clone();
                            let apex = manager_clone.apex.clone();
                            
                            tracing::info!(
                                tld = std::str::from_utf8(&apex).unwrap_or("").trim_end_matches('.'),
                                "ZoneData: starting lazy extraction of zone snapshot"
                            );
                            
                            let result = tokio::task::spawn_blocking(move || {
                                decompress_gzip_to_temp(&gzip_path, &apex)
                            }).await;

                            let mut state = manager_clone.state.lock().await;
                            match result {
                                Ok(Ok(path)) => {
                                    tracing::info!(
                                        tld = std::str::from_utf8(&manager_clone.apex).unwrap_or("").trim_end_matches('.'),
                                        "ZoneData: finished lazy extraction of zone snapshot"
                                    );
                                    *state = ZoneState::Ready(ExtractedZone {
                                        path: path.clone(),
                                        last_accessed: Arc::new(AtomicU64::new(now_secs())),
                                    });
                                    let _ = tx.send(Ok(path));
                                }
                                Ok(Err(e)) => {
                                    tracing::error!("ZoneData: lazy extraction failed: {}", e);
                                    *state = ZoneState::Empty;
                                    let _ = tx.send(Err(e.to_string()));
                                }
                                Err(e) => {
                                    tracing::error!("ZoneData: lazy extraction task panicked: {}", e);
                                    *state = ZoneState::Empty;
                                    let _ = tx.send(Err(e.to_string()));
                                }
                            }
                        });

                        break rx;
                    }
                }
            }
        };

        match rx.recv().await {
            Ok(Ok(path)) => Ok(path),
            Ok(Err(e)) => Err(e),
            Err(_) => Err("Extraction task failed or cancelled".to_string()),
        }
    }

    async fn cleanup_if_idle(&self, timeout_secs: u64) {
        let mut state = self.state.lock().await;
        if let ZoneState::Ready(extracted) = &*state {
            let last = extracted.last_accessed.load(AtomicOrdering::Relaxed);
            if now_secs().saturating_sub(last) >= timeout_secs {
                let _ = fs::remove_file(&extracted.path);
                *state = ZoneState::Empty;
            }
        }
    }
}

/// Checks domains against local gzip-compressed CentralNic zone snapshots.
#[derive(Debug, Clone)]
pub struct ZoneDataChecker {
    managers: Arc<HashMap<String, Arc<ZoneManager>>>,
}

impl ZoneDataChecker {
    pub fn new() -> Self {
        Self::with_directory(ZONE_DATA_DIR)
    }

    pub fn with_directory(directory: impl AsRef<Path>) -> Self {
        let mut map = HashMap::new();
        for (suffix, path) in discover_zone_files(directory.as_ref()) {
            let apex = format!("{}.", suffix).into_bytes();
            map.insert(suffix, Arc::new(ZoneManager::new(path, apex)));
        }
        let managers_arc = Arc::new(map);
        let weak_managers = Arc::downgrade(&managers_arc);

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(60));
            loop {
                interval.tick().await;
                if let Some(managers) = weak_managers.upgrade() {
                    for manager in managers.values() {
                        manager.cleanup_if_idle(IDLE_TIMEOUT_SECS).await;
                    }
                } else {
                    break;
                }
            }
        });

        Self {
            managers: managers_arc,
        }
    }

    #[cfg(test)]
    fn with_path(path: impl Into<PathBuf>) -> Self {
        let apex = b"xyz.".to_vec();
        let manager = Arc::new(ZoneManager::new(path.into(), apex));
        Self {
            managers: Arc::new(HashMap::from([("xyz".to_string(), manager)])),
        }
    }
}

impl Default for ZoneDataChecker {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl DomainChecker for ZoneDataChecker {
    fn name(&self) -> &'static str {
        "ZoneData"
    }

    fn priority(&self) -> CheckerPriority {
        CheckerPriority::ZoneData
    }

    async fn check(&self, domain: &str) -> CheckResult {
        let domain = domain.trim().trim_end_matches('.').to_ascii_lowercase();
        let Some(suffix) = self.matching_suffix(&domain) else {
            return CheckResult::available().with_trace("ZoneData: no matching gzip zone file");
        };
        let Some(manager) = self.managers.get(&suffix) else {
            return CheckResult::available().with_trace("ZoneData: no matching gzip zone file");
        };

        let target = format!("{}.", domain).into_bytes();
        let apex = format!("{}.", suffix).into_bytes();

        let extracted_path = match manager.get_extracted_path().await {
            Ok(path) => path,
            Err(e) => return CheckResult::error(format!("ZoneData extraction failed: {}", e))
                .with_trace("ZoneData: extraction failed"),
        };

        match tokio::task::spawn_blocking(move || zone_contains(&extracted_path, &target, &apex))
            .await
        {
            Ok(Ok(true)) => CheckResult::registered(vec!["ZONE".to_string()])
                .with_trace(format!("ZoneData: registered in {} zone snapshot", suffix)),
            Ok(Ok(false)) => CheckResult::available()
                .with_trace(format!("ZoneData: absent from {} zone snapshot", suffix)),
            Ok(Err(err)) => {
                CheckResult::error(format!("ZoneData lookup failed for {}: {}", domain, err))
                    .with_trace("ZoneData: lookup failed")
            }
            Err(err) => CheckResult::error(format!("ZoneData lookup task failed: {}", err))
                .with_trace("ZoneData: lookup task failed"),
        }
    }

    fn supports_tld(&self, tld: &str) -> bool {
        self.managers.contains_key(&tld.to_ascii_lowercase())
    }

    fn is_authoritative(&self) -> bool {
        true
    }

    fn should_stop_pipeline(&self, result: &CheckResult) -> bool {
        // A matching local zone snapshot is the source of truth for this
        // suffix. Both a present and absent delegation are final results;
        // only a local read/extraction error may fall through to network
        // checkers.
        result.error.is_none()
    }
}

fn discover_zone_files(directory: &Path) -> HashMap<String, PathBuf> {
    let Ok(entries) = fs::read_dir(directory) else {
        return HashMap::new();
    };

    entries
        .filter_map(Result::ok)
        .filter_map(|entry| {
            let file_type = entry.file_type().ok()?;
            if !file_type.is_file() {
                return None;
            }
            let name = entry.file_name();
            let suffix = name
                .to_string_lossy()
                .strip_suffix(".txt.gz")?
                .to_ascii_lowercase();
            if suffix.is_empty() {
                return None;
            }
            Some((suffix, entry.path()))
        })
        .collect()
}

fn decompress_gzip_to_temp(gzip_path: &Path, apex: &[u8]) -> io::Result<PathBuf> {
    let temporary_path = unique_temp_path(gzip_path, apex)?;
    let result = (|| -> io::Result<()> {
        let source = File::open(gzip_path)?;
        let mut decoder = GzDecoder::new(source);
        let mut destination = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&temporary_path)?;
        io::copy(&mut decoder, &mut destination)?;
        destination.flush()?;
        Ok(())
    })();

    if let Err(err) = result {
        let _ = fs::remove_file(&temporary_path);
        return Err(err);
    }

    Ok(temporary_path)
}

fn unique_temp_path(_gzip_path: &Path, apex: &[u8]) -> io::Result<PathBuf> {
    let directory = std::env::temp_dir();
    let suffix = std::str::from_utf8(apex)
        .unwrap_or("zone.")
        .trim_end_matches('.');
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();

    for attempt in 0..100_u32 {
        let candidate = directory.join(format!(
            "domain-scanner-zone-{}-{}-{}-{}.tmp",
            suffix,
            std::process::id(),
            timestamp,
            attempt
        ));
        if !candidate.exists() {
            return Ok(candidate);
        }
    }

    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "could not allocate a unique temporary zone file path",
    ))
}

fn zone_contains(path: &Path, target: &[u8], apex: &[u8]) -> io::Result<bool> {
    let file = File::open(path)?;
    let file_len = file.metadata()?.len();
    let (mut low, mut high) = searchable_bounds(&file, file_len, apex)?;
    let mut reader = BufReader::new(file);

    while low < high {
        let midpoint = low + (high - low) / 2;
        let line_start = line_start_before(&mut reader, midpoint)?;
        reader.seek(SeekFrom::Start(line_start))?;
        let mut line = Vec::new();
        if reader.read_until(b'\n', &mut line)? == 0 {
            high = midpoint;
            continue;
        }
        let next_line = reader.stream_position()?;

        let Some(owner) = owner_name(&line) else {
            low = next_line;
            continue;
        };

        match target.cmp(owner) {
            Ordering::Equal => return Ok(true),
            Ordering::Less => high = line_start,
            Ordering::Greater => low = next_line,
        }
    }

    Ok(false)
}

fn line_start_before(reader: &mut BufReader<File>, offset: u64) -> io::Result<u64> {
    const MAX_RECORD_BYTES: u64 = 64 * 1024;

    let start = offset.saturating_sub(MAX_RECORD_BYTES);
    let bytes_to_read = (offset - start) as usize;
    reader.seek(SeekFrom::Start(start))?;
    let mut preceding = vec![0_u8; bytes_to_read];
    reader.read_exact(&mut preceding)?;

    match preceding.iter().rposition(|byte| *byte == b'\n') {
        Some(position) => Ok(start + position as u64 + 1),
        None if start == 0 => Ok(0),
        None => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "zone record exceeds 64 KiB",
        )),
    }
}

fn searchable_bounds(file: &File, file_len: u64, apex: &[u8]) -> io::Result<(u64, u64)> {
    let mut reader = BufReader::new(file.try_clone()?);
    let mut first_line = Vec::new();
    reader.read_until(b'\n', &mut first_line)?;
    let low = if owner_name(&first_line) == Some(apex) {
        reader.stream_position()?
    } else {
        0
    };

    let tail_len = file_len.min(64 * 1024) as usize;
    let mut tail_file = file.try_clone()?;
    tail_file.seek(SeekFrom::Start(file_len - tail_len as u64))?;
    let mut tail = Vec::with_capacity(tail_len);
    tail_file.read_to_end(&mut tail)?;
    let high = last_line_start(&tail)
        .filter(|start| owner_name(&tail[*start..]) == Some(apex))
        .map(|start| file_len - tail_len as u64 + start as u64)
        .unwrap_or(file_len);

    Ok((low, high.max(low)))
}

fn last_line_start(bytes: &[u8]) -> Option<usize> {
    let mut end = bytes.len();
    while end > 0 && matches!(bytes[end - 1], b'\n' | b'\r') {
        end -= 1;
    }
    if end == 0 {
        return None;
    }
    Some(
        bytes[..end]
            .iter()
            .rposition(|byte| *byte == b'\n')
            .map_or(0, |position| position + 1),
    )
}

fn owner_name(line: &[u8]) -> Option<&[u8]> {
    if line.first() == Some(&b';') {
        return None;
    }
    line.split(|byte| byte.is_ascii_whitespace())
        .find(|field| !field.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checker::{CheckerRegistry, DomainChecker};
    use std::sync::atomic::{AtomicBool, Ordering};

    #[derive(Debug)]
    struct NetworkSentinel {
        called: Arc<AtomicBool>,
    }

    #[async_trait]
    impl DomainChecker for NetworkSentinel {
        fn name(&self) -> &'static str {
            "NetworkSentinel"
        }

        fn priority(&self) -> CheckerPriority {
            CheckerPriority::Fast
        }

        async fn check(&self, _domain: &str) -> CheckResult {
            self.called.store(true, Ordering::Relaxed);
            CheckResult::registered(vec!["NETWORK".to_string()])
        }

        fn supports_tld(&self, _tld: &str) -> bool {
            true
        }
    }

    fn fixture_dir() -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "domain-scanner-zone-data-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir(&path).unwrap();
        path
    }

    fn fixture_contents() -> &'static [u8] {
        concat!(
            "xyz. 900 IN SOA ns0.example. hostmaster.example. 1 2 3 4 5\n",
            "alpha.xyz. 3600 IN NS ns1.example.\n",
            "alpha.xyz. 3600 IN NS ns2.example.\n",
            "middle.xyz. 3600 IN NS ns1.example.\n",
            "zulu.xyz. 3600 IN NS ns1.example.\n",
            "xyz. 900 IN SOA ns0.example. hostmaster.example. 1 2 3 4 5\n",
        )
        .as_bytes()
    }

    fn write_gzip_fixture(path: &Path) {
        use flate2::Compression;
        use flate2::write::GzEncoder;

        let output = File::create(path).unwrap();
        let mut encoder = GzEncoder::new(output, Compression::default());
        encoder.write_all(fixture_contents()).unwrap();
        encoder.finish().unwrap();
    }

    #[test]
    fn binary_search_finds_zone_owners_and_ignores_apex_records() {
        let directory = fixture_dir();
        let path = directory.join("zone.txt");
        fs::write(&path, fixture_contents()).unwrap();

        assert!(zone_contains(&path, b"alpha.xyz.", b"xyz.").unwrap());
        assert!(zone_contains(&path, b"middle.xyz.", b"xyz.").unwrap());
        assert!(zone_contains(&path, b"zulu.xyz.", b"xyz.").unwrap());
        assert!(!zone_contains(&path, b"available.xyz.", b"xyz.").unwrap());

        fs::remove_dir_all(directory).unwrap();
    }

    #[tokio::test]
    async fn checker_decompresses_gzip_and_cleans_up_on_drop() {
        let directory = fixture_dir();
        let gzip_path = directory.join("xyz.txt.gz");
        write_gzip_fixture(&gzip_path);
        let checker = ZoneDataChecker::with_path(&gzip_path);

        let result = checker.check("ALPHA.XYZ").await;
        assert!(!result.available);
        assert!(result.signatures.contains(&"ZONE".to_string()));
        assert!(checker.should_stop_pipeline(&result));

        let result = checker.check("available.xyz").await;
        assert!(result.available);
        assert!(checker.should_stop_pipeline(&result));
        
        let path = checker.managers.get("xyz").unwrap().get_extracted_path().await.unwrap();
        assert!(path.exists());
        
        drop(checker);
        
        assert!(!path.exists());
        fs::remove_dir_all(directory).unwrap();
    }

    #[tokio::test]
    async fn available_local_zone_result_skips_network_checkers() {
        let directory = fixture_dir();
        let gzip_path = directory.join("xyz.txt.gz");
        write_gzip_fixture(&gzip_path);

        let mut registry = CheckerRegistry::new();
        registry.add_checker(Arc::new(ZoneDataChecker::with_path(&gzip_path)));
        let network_called = Arc::new(AtomicBool::new(false));
        registry.add_checker(Arc::new(NetworkSentinel {
            called: network_called.clone(),
        }));
        registry.sort_by_priority();

        let result = registry.check("available.xyz").await;

        assert!(result.available);
        assert!(!network_called.load(Ordering::Relaxed));
        fs::remove_dir_all(directory).unwrap();
    }

    #[tokio::test]
    async fn discovers_only_gzip_zone_files() {
        let directory = fixture_dir();
        write_gzip_fixture(&directory.join("xyz.txt.gz"));
        fs::write(directory.join("com.txt"), b"not a supported source").unwrap();

        let checker = ZoneDataChecker::with_directory(&directory);
        assert!(checker.supports_tld("xyz"));
        assert!(!checker.supports_tld("com"));

        fs::remove_dir_all(directory).unwrap();
    }

    #[tokio::test]
    async fn idle_timeout_cleans_up_extracted_file() {
        let directory = fixture_dir();
        let gzip_path = directory.join("xyz.txt.gz");
        write_gzip_fixture(&gzip_path);
        
        let manager = Arc::new(ZoneManager::new(gzip_path, b"xyz.".to_vec()));
        let path = manager.get_extracted_path().await.unwrap();
        assert!(path.exists());
        
        // Mock the last_accessed to be long in the past
        {
            let mut state = manager.state.lock().await;
            if let ZoneState::Ready(extracted) = &mut *state {
                extracted.last_accessed.store(now_secs() - 400, AtomicOrdering::Relaxed);
            }
        }
        
        manager.cleanup_if_idle(IDLE_TIMEOUT_SECS).await;
        
        assert!(!path.exists());
        
        fs::remove_dir_all(directory).unwrap();
    }

    #[tokio::test]
    #[ignore = "requires data/centralized_zone_data/xyz.txt.gz"]
    async fn searches_the_local_xyz_snapshot() {
        let gzip_path = Path::new(ZONE_DATA_DIR).join("xyz.txt.gz");
        let manager = Arc::new(ZoneManager::new(gzip_path, b"xyz.".to_vec()));
        let path = manager.get_extracted_path().await.unwrap();
        assert!(zone_contains(&path, b"0--0--7.xyz.", b"xyz.").unwrap());
        assert!(zone_contains(&path, b"zzzzzz.xyz.", b"xyz.").unwrap());
    }
}
