//! Local centralized gzip zone-data checker.
//!
//! A zone snapshot is only used when a matching `{suffix}.txt.gz` file exists.
//! The gzip source is expanded into a unique temporary file for one lookup,
//! binary-searched, and removed regardless of the lookup outcome.

use async_trait::async_trait;
use flate2::read::GzDecoder;
use std::cmp::Ordering;
use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufRead, BufReader, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use super::traits::{CheckResult, CheckerPriority, DomainChecker};

const ZONE_DATA_DIR: &str = "data/centralized_zone_data";

/// Checks domains against local gzip-compressed CentralNic zone snapshots.
#[derive(Debug, Clone)]
pub struct ZoneDataChecker {
    zone_files: Arc<HashMap<String, PathBuf>>,
}

impl ZoneDataChecker {
    pub fn new() -> Self {
        Self::with_directory(ZONE_DATA_DIR)
    }

    pub fn with_directory(directory: impl AsRef<Path>) -> Self {
        Self {
            zone_files: Arc::new(discover_zone_files(directory.as_ref())),
        }
    }

    #[cfg(test)]
    fn with_path(path: impl Into<PathBuf>) -> Self {
        Self {
            zone_files: Arc::new(HashMap::from([("xyz".to_string(), path.into())])),
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
        let Some(gzip_path) = self.zone_files.get(&suffix).cloned() else {
            return CheckResult::available().with_trace("ZoneData: no matching gzip zone file");
        };

        let target = format!("{}.", domain).into_bytes();
        let apex = format!("{}.", suffix).into_bytes();
        match tokio::task::spawn_blocking(move || lookup_gzip_zone(&gzip_path, &target, &apex))
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
        self.zone_files.contains_key(&tld.to_ascii_lowercase())
    }

    fn is_authoritative(&self) -> bool {
        true
    }

    fn should_stop_pipeline(&self, result: &CheckResult) -> bool {
        // A matching delegation in the zone is definitive. An absent name is
        // only a snapshot result and must still be confirmed by network checks.
        !result.available && result.error.is_none()
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

fn lookup_gzip_zone(gzip_path: &Path, target: &[u8], apex: &[u8]) -> io::Result<bool> {
    let temporary_path = decompress_gzip_to_temp(gzip_path, apex)?;
    let lookup_result = zone_contains(&temporary_path, target, apex);
    let cleanup_result = fs::remove_file(&temporary_path);

    match (lookup_result, cleanup_result) {
        (Ok(found), Ok(())) => Ok(found),
        (Err(lookup_error), Ok(())) => Err(lookup_error),
        (Ok(_), Err(cleanup_error)) => Err(cleanup_error),
        (Err(lookup_error), Err(cleanup_error)) => Err(io::Error::new(
            lookup_error.kind(),
            format!(
                "{}; failed to remove temporary zone file: {}",
                lookup_error, cleanup_error
            ),
        )),
    }
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

fn unique_temp_path(gzip_path: &Path, apex: &[u8]) -> io::Result<PathBuf> {
    let directory = gzip_path.parent().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "gzip zone file has no parent directory",
        )
    })?;
    let suffix = std::str::from_utf8(apex)
        .unwrap_or("zone.")
        .trim_end_matches('.');
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();

    for attempt in 0..100_u32 {
        let candidate = directory.join(format!(
            ".{}.txt.query-{}-{}-{}.tmp",
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

/// Resolve an arbitrary byte offset to the beginning of its line without
/// assuming that the offset happens to land on a record boundary.
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

/// Return the byte interval containing sorted delegations, excluding the apex
/// SOA records that appear before and after the sorted owner-name records.
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
    async fn checker_decompresses_gzip_and_removes_temporary_file() {
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
        assert!(!checker.should_stop_pipeline(&result));

        let remaining_files = fs::read_dir(&directory).unwrap().count();
        assert_eq!(
            remaining_files, 1,
            "temporary decompression file was not removed"
        );
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn discovers_only_gzip_zone_files() {
        let directory = fixture_dir();
        write_gzip_fixture(&directory.join("xyz.txt.gz"));
        fs::write(directory.join("com.txt"), b"not a supported source").unwrap();

        let checker = ZoneDataChecker::with_directory(&directory);
        assert!(checker.supports_tld("xyz"));
        assert!(!checker.supports_tld("com"));

        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    #[ignore = "requires data/centralized_zone_data/xyz.txt.gz"]
    fn searches_the_local_xyz_snapshot() {
        let gzip_path = Path::new(ZONE_DATA_DIR).join("xyz.txt.gz");
        assert!(lookup_gzip_zone(&gzip_path, b"0--0--7.xyz.", b"xyz.").unwrap());
        assert!(lookup_gzip_zone(&gzip_path, b"zzzzzz.xyz.", b"xyz.").unwrap());
    }
}
