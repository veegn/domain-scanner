mod templates;

use anyhow::{Context, Result, anyhow, bail};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, QueryBuilder, Sqlite, SqlitePool};
use std::path::{Path, PathBuf};
use tokio::fs;
use uuid::Uuid;

use crate::web::models::{PublishScanRequest, PublishedScanSummary};

const PUBLISHED_ROOT: &str = "data/published";

#[derive(Debug, Clone, Serialize)]
pub struct PublishedPageMeta {
    pub id: String,
    pub slug: String,
    pub scan_id: String,
    pub title: String,
    pub description: Option<String>,
    pub suffix: String,
    pub pattern: String,
    pub length: i64,
    pub result_count: i64,
    pub published_at: String,
    pub scan_finished_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct PublishedPageData {
    pub meta: PublishedPageMeta,
    pub domains: Vec<PublishedDomainFileRow>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub chunks: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, FromRow)]
pub struct PublishedDomainFileRow {
    pub domain: String,
    pub registration_record_absent: bool,
    pub purchasable: Option<bool>,
    pub expiration_date: Option<String>,
    pub signatures: String,
}

#[derive(Debug, Clone, FromRow)]
struct ScanPublicationSource {
    id: String,
    status: String,
    suffix: String,
    pattern: String,
    length: i64,
    finished_at: Option<String>,
    created_at: String,
}

pub async fn create_published_scan(
    db: &SqlitePool,
    scan_id: &str,
    request: &PublishScanRequest,
) -> Result<PublishedScanSummary> {
    let title = request.title.trim();
    if title.is_empty() {
        bail!("publish title cannot be empty");
    }

    let scan = sqlx::query_as::<_, ScanPublicationSource>(
        "SELECT id, status, suffix, pattern, length, finished_at, created_at
         FROM scans
         WHERE id = ?",
    )
    .bind(scan_id)
    .fetch_optional(db)
    .await
    .context("failed to load scan for publication")?
    .ok_or_else(|| anyhow!("scan not found"))?;

    if scan.status != "finished" {
        bail!("only finished scans can be published");
    }

    let domains = sqlx::query_as::<_, PublishedDomainFileRow>(
        "SELECT domain, registration_record_absent, purchasable, expiration_date, signatures
         FROM results
         WHERE scan_id = ? AND registration_record_absent = 1
         ORDER BY domain ASC",
    )
    .bind(scan_id)
    .fetch_all(db)
    .await
    .context("failed to load scan results without registration records")?;

    let publication_id = Uuid::new_v4().to_string();
    let slug_seed = slugify(title);
    let slug_base = if slug_seed.is_empty() {
        format!("scan-{}", short_scan_id(scan_id))
    } else {
        slug_seed
    };
    let published_at = Utc::now().to_rfc3339();
    let description = request
        .description
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned);
    let scan_finished_at = scan.finished_at.unwrap_or(scan.created_at);
    let mut attempt = 1_u32;
    let meta = loop {
        let slug = slug_candidate(&slug_base, attempt);
        let static_dir_path = publication_dir(&slug);
        if static_dir_path.exists() {
            attempt += 1;
            continue;
        }
        let candidate = PublishedPageMeta {
            id: publication_id.clone(),
            slug,
            scan_id: scan.id.clone(),
            title: title.to_string(),
            description: description.clone(),
            suffix: scan.suffix.clone(),
            pattern: scan.pattern.clone(),
            length: scan.length,
            result_count: domains.len() as i64,
            published_at: published_at.clone(),
            scan_finished_at: scan_finished_at.clone(),
            updated_at: published_at.clone(),
        };
        if reserve_publication(db, &candidate).await? {
            break candidate;
        }
        attempt += 1;
    };
    let static_dir_path = publication_dir(&meta.slug);
    let staging_dir = publication_staging_dir(&publication_id);
    let data = PublishedPageData {
        meta: meta.clone(),
        domains: domains.clone(),
        chunks: Vec::new(),
    };

    let mut final_dir_owned = false;
    let publish_result = async {
        write_publication_files(&staging_dir, &meta, &data).await?;
        persist_publication_domains(db, &meta, &domains).await?;
        fs::rename(&staging_dir, &static_dir_path)
            .await
            .with_context(|| {
                format!(
                    "failed to activate publication directory '{}'",
                    static_dir_path.display()
                )
            })?;
        final_dir_owned = true;
        activate_publication(db, &publication_id, &static_dir_path).await
    }
    .await;
    if let Err(error) = publish_result {
        let _ = fs::remove_dir_all(&staging_dir).await;
        if final_dir_owned {
            let _ = fs::remove_dir_all(&static_dir_path).await;
        }
        let _ = sqlx::query("DELETE FROM published_scans WHERE id = ? AND status = 'publishing'")
            .bind(&publication_id)
            .execute(db)
            .await;
        return Err(error);
    }

    fetch_published_scan_summary(db, &publication_id)
        .await?
        .ok_or_else(|| anyhow!("published scan was inserted but could not be loaded"))
}

pub async fn delete_published_scan(db: &SqlitePool, id: &str) -> Result<bool> {
    let record = sqlx::query_scalar::<_, String>(
        "SELECT slug
         FROM published_scans
         WHERE id = ?",
    )
    .bind(id)
    .fetch_optional(db)
    .await
    .context("failed to load published scan for deletion")?;

    let Some(slug) = record else {
        return Ok(false);
    };

    let static_dir_path = publication_dir(&slug);
    let delete_dir = publication_staging_dir(&format!("delete-{id}-{}", Uuid::new_v4()));
    let claimed = sqlx::query(
        "UPDATE published_scans SET status = 'deleting' WHERE id = ? AND status = 'active'",
    )
    .bind(id)
    .execute(db)
    .await
    .context("failed to claim published scan for deletion")?;
    if claimed.rows_affected() != 1 {
        bail!("publication is currently being modified");
    }
    let moved = if static_dir_path.exists() {
        if let Err(error) = fs::rename(&static_dir_path, &delete_dir).await {
            let _ = sqlx::query(
                "UPDATE published_scans SET status = 'active' WHERE id = ? AND status = 'deleting'",
            )
            .bind(id)
            .execute(db)
            .await;
            return Err(error)
                .with_context(|| format!("failed to stage publication '{slug}' for deletion"));
        }
        true
    } else {
        false
    };

    if let Err(error) =
        sqlx::query("DELETE FROM published_scans WHERE id = ? AND status = 'deleting'")
            .bind(id)
            .execute(db)
            .await
    {
        if moved {
            let _ = fs::rename(&delete_dir, &static_dir_path).await;
        }
        let _ = sqlx::query(
            "UPDATE published_scans SET status = 'active' WHERE id = ? AND status = 'deleting'",
        )
        .bind(id)
        .execute(db)
        .await;
        return Err(error).context("failed to delete published scan");
    }
    if moved {
        fs::remove_dir_all(&delete_dir).await.with_context(|| {
            format!("deleted publication '{slug}' but failed to remove its staged directory")
        })?;
    }

    Ok(true)
}

pub async fn update_published_scan(
    db: &SqlitePool,
    id: &str,
    request: &PublishScanRequest,
) -> Result<Option<PublishedScanSummary>> {
    let title = request.title.trim();
    if title.is_empty() {
        bail!("publish title cannot be empty");
    }

    let row = sqlx::query_as::<_, (String, String, String, String, i64, String, Option<String>)>(
        "SELECT ps.scan_id, ps.slug, s.suffix, s.pattern, s.length, ps.published_at, s.finished_at
         FROM published_scans ps
         JOIN scans s ON s.id = ps.scan_id
         WHERE ps.id = ?",
    )
    .bind(id)
    .fetch_optional(db)
    .await
    .context("failed to load published scan for update")?;

    let Some((scan_id, slug, suffix, pattern, length, published_at, finished_at)) = row else {
        return Ok(None);
    };

    let description = request
        .description
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned);
    let updated_at = Utc::now().to_rfc3339();

    let domains = sqlx::query_as::<_, PublishedDomainFileRow>(
        "SELECT domain, registration_record_absent, purchasable, expiration_date, signatures
         FROM published_domains
         WHERE published_scan_id = ? AND registration_record_absent = 1
         ORDER BY domain ASC",
    )
    .bind(id)
    .fetch_all(db)
    .await
    .context("failed to load published domains for update")?;

    let meta = PublishedPageMeta {
        id: id.to_string(),
        slug: slug.clone(),
        scan_id,
        title: title.to_string(),
        description: description.clone(),
        suffix,
        pattern,
        length,
        result_count: domains.len() as i64,
        published_at: published_at.clone(),
        scan_finished_at: finished_at.unwrap_or(published_at.clone()),
        updated_at: updated_at.clone(),
    };
    let data = PublishedPageData {
        meta: meta.clone(),
        domains,
        chunks: Vec::new(),
    };

    let claimed = sqlx::query(
        "UPDATE published_scans SET status = 'updating' WHERE id = ? AND status = 'active'",
    )
    .bind(id)
    .execute(db)
    .await
    .context("failed to claim published scan for update")?;
    if claimed.rows_affected() != 1 {
        bail!("publication is already being updated");
    }

    let static_dir_path = publication_dir(&slug);
    let staging_dir = publication_staging_dir(&format!("update-{id}-{}", Uuid::new_v4()));
    let backup_dir = publication_staging_dir(&format!("backup-{id}-{}", Uuid::new_v4()));
    let update_result = async {
        write_publication_files(&staging_dir, &meta, &data).await?;
        fs::rename(&static_dir_path, &backup_dir)
            .await
            .context("failed to move current publication to backup")?;
        if let Err(err) = fs::rename(&staging_dir, &static_dir_path).await {
            let _ = fs::rename(&backup_dir, &static_dir_path).await;
            return Err(anyhow!("failed to activate updated publication: {err}"));
        }

        sqlx::query(
            "UPDATE published_scans
         SET title = ?, description = ?, result_count = ?, updated_at = ?, status = 'active'
         WHERE id = ?",
        )
        .bind(&meta.title)
        .bind(&meta.description)
        .bind(meta.result_count)
        .bind(&updated_at)
        .bind(id)
        .execute(db)
        .await
        .context("failed to update published scan metadata")?;
        Ok::<(), anyhow::Error>(())
    }
    .await;
    if let Err(error) = update_result {
        let _ = fs::remove_dir_all(&staging_dir).await;
        if backup_dir.exists() {
            if static_dir_path.exists() {
                let _ = fs::remove_dir_all(&static_dir_path).await;
            }
            let _ = fs::rename(&backup_dir, &static_dir_path).await;
        }
        let _ = sqlx::query(
            "UPDATE published_scans SET status = 'active' WHERE id = ? AND status = 'updating'",
        )
        .bind(id)
        .execute(db)
        .await;
        return Err(error);
    }
    let _ = fs::remove_dir_all(&backup_dir).await;

    fetch_published_scan_summary(db, id)
        .await
        .context("failed to reload published scan after update")
}

pub fn slugify(input: &str) -> String {
    let mut slug = String::with_capacity(input.len());
    let mut previous_dash = false;

    for ch in input.chars() {
        let normalized = ch.to_ascii_lowercase();
        if normalized.is_ascii_alphanumeric() {
            slug.push(normalized);
            previous_dash = false;
        } else if !previous_dash {
            slug.push('-');
            previous_dash = true;
        }
    }

    slug.trim_matches('-').to_string()
}

pub fn publication_dir(slug: &str) -> PathBuf {
    Path::new(PUBLISHED_ROOT).join(slug)
}

/// Reconcile publication workflows interrupted between their filesystem and
/// database commits. This runs before the HTTP server starts, so no live
/// publication can be mistaken for stale staging data.
pub async fn recover_incomplete_publications(db: &SqlitePool) -> Result<u64> {
    fs::create_dir_all(PUBLISHED_ROOT)
        .await
        .context("failed to create publication root during recovery")?;

    let rows = sqlx::query_as::<_, (String, String, String, i64)>(
        "SELECT id, slug, status, result_count
         FROM published_scans
         WHERE status != 'active'",
    )
    .fetch_all(db)
    .await
    .context("failed to load incomplete publications")?;

    let mut recovered = 0_u64;
    for (id, slug, status, result_count) in rows {
        let final_dir = publication_dir(&slug);
        match status.as_str() {
            "publishing" => {
                let persisted_count = sqlx::query_scalar::<_, i64>(
                    "SELECT COUNT(*) FROM published_domains WHERE published_scan_id = ?",
                )
                .bind(&id)
                .fetch_one(db)
                .await
                .context("failed to verify interrupted publication domains")?;
                let files_complete = final_dir.join("index.html").is_file()
                    && final_dir.join("data.json").is_file()
                    && final_dir.join("meta.json").is_file();
                if files_complete && persisted_count == result_count {
                    sqlx::query(
                        "UPDATE published_scans SET status = 'active' WHERE id = ? AND status = 'publishing'",
                    )
                    .bind(&id)
                    .execute(db)
                    .await
                    .context("failed to activate recovered publication")?;
                } else {
                    if final_dir.exists() {
                        fs::remove_dir_all(&final_dir).await.with_context(|| {
                            format!(
                                "failed to remove incomplete publication '{}'",
                                final_dir.display()
                            )
                        })?;
                    }
                    sqlx::query(
                        "DELETE FROM published_scans WHERE id = ? AND status = 'publishing'",
                    )
                    .bind(&id)
                    .execute(db)
                    .await
                    .context("failed to remove incomplete publication row")?;
                }
                recovered += 1;
            }
            "updating" => {
                let backup_prefix = format!(".staging-backup-{id}-");
                if let Some(backup_dir) = find_staging_dir(&backup_prefix).await? {
                    if final_dir.exists() {
                        fs::remove_dir_all(&final_dir).await.with_context(|| {
                            format!(
                                "failed to discard interrupted update '{}'",
                                final_dir.display()
                            )
                        })?;
                    }
                    fs::rename(&backup_dir, &final_dir).await.with_context(|| {
                        format!(
                            "failed to restore publication backup '{}'",
                            backup_dir.display()
                        )
                    })?;
                }

                if final_dir.exists() {
                    // The metadata transaction is committed only after the new
                    // directory is active. Until then, restoring the old files
                    // keeps them aligned with the old database metadata.
                    sqlx::query(
                        "UPDATE published_scans SET status = 'active' WHERE id = ? AND status = 'updating'",
                    )
                    .bind(&id)
                    .execute(db)
                    .await
                    .context("failed to recover interrupted publication update")?;
                } else {
                    sqlx::query("DELETE FROM published_scans WHERE id = ? AND status = 'updating'")
                        .bind(&id)
                        .execute(db)
                        .await
                        .context("failed to remove unrecoverable publication update")?;
                }
                recovered += 1;
            }
            "deleting" => {
                if final_dir.exists() {
                    fs::remove_dir_all(&final_dir).await.with_context(|| {
                        format!(
                            "failed to finish deleting publication '{}'",
                            final_dir.display()
                        )
                    })?;
                }
                sqlx::query("DELETE FROM published_scans WHERE id = ? AND status = 'deleting'")
                    .bind(&id)
                    .execute(db)
                    .await
                    .context("failed to finish deleting publication row")?;
                recovered += 1;
            }
            _ => {}
        }
    }

    let mut entries = fs::read_dir(PUBLISHED_ROOT)
        .await
        .context("failed to inspect publication staging directories")?;
    while let Some(entry) = entries.next_entry().await? {
        if entry.file_name().to_string_lossy().starts_with(".staging-")
            && entry.file_type().await?.is_dir()
        {
            fs::remove_dir_all(entry.path()).await.with_context(|| {
                format!(
                    "failed to remove stale staging directory '{}'",
                    entry.path().display()
                )
            })?;
        }
    }

    Ok(recovered)
}

async fn find_staging_dir(prefix: &str) -> Result<Option<PathBuf>> {
    let mut entries = fs::read_dir(PUBLISHED_ROOT)
        .await
        .context("failed to inspect publication staging directories")?;
    while let Some(entry) = entries.next_entry().await? {
        if entry.file_name().to_string_lossy().starts_with(prefix)
            && entry.file_type().await?.is_dir()
        {
            return Ok(Some(entry.path()));
        }
    }
    Ok(None)
}

fn slug_candidate(base: &str, attempt: u32) -> String {
    if attempt == 1 {
        base.to_string()
    } else {
        format!("{base}-{attempt}")
    }
}

fn publication_staging_dir(id: &str) -> PathBuf {
    Path::new(PUBLISHED_ROOT).join(format!(".staging-{id}"))
}

async fn write_publication_files(
    dir: &Path,
    meta: &PublishedPageMeta,
    data: &PublishedPageData,
) -> Result<()> {
    fs::create_dir_all(dir)
        .await
        .with_context(|| format!("failed to create publication directory '{}'", dir.display()))?;

    const DOMAIN_CHUNK_SIZE: usize = 2_000;
    let meta_json = serde_json::to_vec_pretty(meta).context("failed to serialize meta.json")?;
    let mut manifest = data.clone();
    if data.domains.len() > DOMAIN_CHUNK_SIZE {
        manifest.domains.clear();
        manifest.chunks = data
            .domains
            .chunks(DOMAIN_CHUNK_SIZE)
            .enumerate()
            .map(|(index, _)| format!("domains-{index:05}.json"))
            .collect();
        for (name, chunk) in manifest
            .chunks
            .iter()
            .zip(data.domains.chunks(DOMAIN_CHUNK_SIZE))
        {
            let bytes = serde_json::to_vec(chunk).context("failed to serialize domain chunk")?;
            fs::write(dir.join(name), bytes)
                .await
                .with_context(|| format!("failed to write publication chunk '{name}'"))?;
        }
    }
    let data_json =
        serde_json::to_vec_pretty(&manifest).context("failed to serialize data.json")?;
    let index_html = templates::render_index_html(meta);

    fs::write(dir.join("meta.json"), meta_json)
        .await
        .context("failed to write meta.json")?;
    fs::write(dir.join("data.json"), data_json)
        .await
        .context("failed to write data.json")?;
    fs::write(dir.join("index.html"), index_html)
        .await
        .context("failed to write index.html")?;

    Ok(())
}

async fn reserve_publication(db: &SqlitePool, meta: &PublishedPageMeta) -> Result<bool> {
    let static_dir = publication_dir(&meta.slug)
        .to_string_lossy()
        .replace('\\', "/");
    let result = sqlx::query(
        "INSERT INTO published_scans
            (id, scan_id, slug, title, description, status, static_dir, result_count, published_at, updated_at)
         VALUES (?, ?, ?, ?, ?, 'publishing', ?, ?, ?, ?)",
    )
    .bind(&meta.id).bind(&meta.scan_id).bind(&meta.slug).bind(&meta.title)
    .bind(&meta.description).bind(static_dir).bind(meta.result_count)
    .bind(&meta.published_at).bind(&meta.updated_at).execute(db).await;
    match result {
        Ok(_) => Ok(true),
        Err(sqlx::Error::Database(error)) if error.is_unique_violation() => Ok(false),
        Err(error) => Err(error).context("failed to reserve publication slug"),
    }
}

async fn activate_publication(db: &SqlitePool, id: &str, static_dir: &Path) -> Result<()> {
    let result = sqlx::query("UPDATE published_scans SET status = 'active', static_dir = ? WHERE id = ? AND status = 'publishing'")
        .bind(static_dir.to_string_lossy().replace('\\', "/"))
        .bind(id).execute(db).await.context("failed to activate published scan")?;
    if result.rows_affected() != 1 {
        bail!("publication reservation was lost before activation");
    }
    Ok(())
}

async fn persist_publication_domains(
    db: &SqlitePool,
    meta: &PublishedPageMeta,
    domains: &[PublishedDomainFileRow],
) -> Result<()> {
    let mut tx = db
        .begin()
        .await
        .context("failed to begin publication transaction")?;

    for batch in domains.chunks(500) {
        let mut builder: QueryBuilder<'_, Sqlite> = QueryBuilder::new(
            "INSERT INTO published_domains
                (published_scan_id, domain, available, registration_record_absent, purchasable,
                 expiration_date, signatures, published_at) ",
        );

        builder.push_values(batch, |mut row, domain| {
            row.push_bind(&meta.id)
                .push_bind(&domain.domain)
                // Never claim purchase availability through the legacy field.
                .push_bind(false)
                .push_bind(domain.registration_record_absent)
                .push_bind(domain.purchasable)
                .push_bind(&domain.expiration_date)
                .push_bind(&domain.signatures)
                .push_bind(&meta.published_at);
        });

        builder
            .build()
            .execute(&mut *tx)
            .await
            .context("failed to insert published domain batch")?;
    }

    tx.commit()
        .await
        .context("failed to commit publication transaction")?;
    Ok(())
}

async fn fetch_published_scan_summary(
    db: &SqlitePool,
    id: &str,
) -> Result<Option<PublishedScanSummary>> {
    sqlx::query_as::<_, PublishedScanSummary>(
        "SELECT id, scan_id, slug, title, description, status, result_count, published_at, updated_at
         FROM published_scans
         WHERE id = ?",
    )
    .bind(id)
    .fetch_optional(db)
    .await
    .context("failed to fetch published scan summary")
}

fn short_scan_id(scan_id: &str) -> &str {
    scan_id.get(..8).unwrap_or(scan_id)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_meta() -> PublishedPageMeta {
        PublishedPageMeta {
            id: "publication-1".to_string(),
            slug: "chunked-publication".to_string(),
            scan_id: "scan-1".to_string(),
            title: "Chunked publication".to_string(),
            description: None,
            suffix: ".test".to_string(),
            pattern: "D".to_string(),
            length: 3,
            result_count: 2_001,
            published_at: "2026-01-01T00:00:00Z".to_string(),
            scan_finished_at: "2026-01-01T00:00:00Z".to_string(),
            updated_at: "2026-01-01T00:00:00Z".to_string(),
        }
    }

    #[test]
    fn slugify_collapses_separators() {
        assert_eq!(slugify("Hello, Domain Scanner!"), "hello-domain-scanner");
        assert_eq!(slugify("  multiple___spaces  "), "multiple-spaces");
        assert_eq!(slugify("---"), "");
    }

    #[tokio::test]
    async fn large_publications_are_written_as_chunked_manifests() {
        let dir = std::env::temp_dir().join(format!(
            "domain-scanner-publication-test-{}",
            Uuid::new_v4()
        ));
        let meta = test_meta();
        let domains = (0..2_001)
            .map(|index| PublishedDomainFileRow {
                domain: format!("domain-{index}.test"),
                registration_record_absent: true,
                purchasable: None,
                expiration_date: None,
                signatures: "WHOIS".to_string(),
            })
            .collect();
        let data = PublishedPageData {
            meta: meta.clone(),
            domains,
            chunks: Vec::new(),
        };

        write_publication_files(&dir, &meta, &data).await.unwrap();
        let manifest: serde_json::Value =
            serde_json::from_slice(&fs::read(dir.join("data.json")).await.unwrap()).unwrap();
        assert_eq!(manifest["domains"].as_array().unwrap().len(), 0);
        assert_eq!(manifest["chunks"].as_array().unwrap().len(), 2);
        let first: Vec<PublishedDomainFileRow> =
            serde_json::from_slice(&fs::read(dir.join("domains-00000.json")).await.unwrap())
                .unwrap();
        let second: Vec<PublishedDomainFileRow> =
            serde_json::from_slice(&fs::read(dir.join("domains-00001.json")).await.unwrap())
                .unwrap();
        assert_eq!(first.len(), 2_000);
        assert_eq!(second.len(), 1);
        fs::remove_dir_all(&dir).await.unwrap();
    }

    #[tokio::test]
    #[ignore = "manual regeneration utility; uses the workspace database and output directories"]
    async fn test_regenerate_all() {
        let db = SqlitePool::connect("sqlite:data/scans.db").await.unwrap();
        let rows = sqlx::query_as::<_, (String, String, String, String, Option<String>, String, String, i64, String, Option<String>)> (
            "SELECT ps.id, ps.slug, ps.scan_id, ps.title, ps.description, s.suffix, s.pattern, s.length, ps.published_at, s.finished_at
             FROM published_scans ps
             JOIN scans s ON s.id = ps.scan_id"
        )
        .fetch_all(&db)
        .await
        .unwrap();

        for row in rows {
            let (
                id,
                slug,
                scan_id,
                title,
                description,
                suffix,
                pattern,
                length,
                published_at,
                finished_at,
            ) = row;
            println!("Regenerating {}", slug);

            let domains = sqlx::query_as::<_, PublishedDomainFileRow>(
                "SELECT domain, registration_record_absent, purchasable, expiration_date, signatures
                 FROM published_domains
                 WHERE published_scan_id = ? AND registration_record_absent = 1
                 ORDER BY domain ASC",
            )
            .bind(&id)
            .fetch_all(&db)
            .await
            .unwrap();

            let meta = PublishedPageMeta {
                id: id.clone(),
                slug: slug.clone(),
                scan_id,
                title,
                description,
                suffix,
                pattern,
                length,
                result_count: domains.len() as i64,
                published_at: published_at.clone(),
                scan_finished_at: finished_at.unwrap_or(published_at.clone()),
                updated_at: chrono::Utc::now().to_rfc3339(),
            };

            let data = PublishedPageData {
                meta: meta.clone(),
                domains,
                chunks: Vec::new(),
            };

            // Write to data/published (served by dev server)
            let dir = Path::new("data/published").join(&slug);
            write_publication_files(&dir, &meta, &data).await.unwrap();
            println!("Wrote to {}", dir.display());

            // Also write to web/published (fallback/backup)
            let web_dir = Path::new("web/published").join(&slug);
            write_publication_files(&web_dir, &meta, &data)
                .await
                .unwrap();
            println!("Wrote to {}", web_dir.display());
        }
    }
}
