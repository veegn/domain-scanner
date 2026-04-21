mod templates;

use anyhow::{Context, Result, anyhow, bail};
use chrono::Utc;
use serde::Serialize;
use sqlx::{FromRow, SqlitePool};
use std::path::{Path, PathBuf};
use tokio::fs;
use uuid::Uuid;

use crate::web::models::{PublishScanRequest, PublishedScanSummary};

const PUBLISHED_ROOT: &str = "web/published";

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
}

#[derive(Debug, Clone, Serialize, FromRow)]
pub struct PublishedDomainFileRow {
    pub domain: String,
    pub available: bool,
    pub expiration_date: Option<String>,
    pub signatures: String,
}

#[derive(Debug, Clone, FromRow)]
struct ScanPublicationSource {
    id: String,
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
        "SELECT id, suffix, pattern, length, finished_at, created_at
         FROM scans
         WHERE id = ?",
    )
    .bind(scan_id)
    .fetch_optional(db)
    .await
    .context("failed to load scan for publication")?
    .ok_or_else(|| anyhow!("scan not found"))?;

    let domains = sqlx::query_as::<_, PublishedDomainFileRow>(
        "SELECT domain, available, expiration_date, signatures
         FROM results
         WHERE scan_id = ? AND available = 1
         ORDER BY domain ASC",
    )
    .bind(scan_id)
    .fetch_all(db)
    .await
    .context("failed to load available scan results")?;

    let publication_id = Uuid::new_v4().to_string();
    let slug_seed = slugify(title);
    let slug_base = if slug_seed.is_empty() {
        format!("scan-{}", short_scan_id(scan_id))
    } else {
        slug_seed
    };
    let slug = allocate_unique_slug(db, &slug_base).await?;
    let static_dir_path = publication_dir(&slug);
    let static_dir = static_dir_path.to_string_lossy().replace('\\', "/");
    let published_at = Utc::now().to_rfc3339();
    let meta = PublishedPageMeta {
        id: publication_id.clone(),
        slug: slug.clone(),
        scan_id: scan.id.clone(),
        title: title.to_string(),
        description: request
            .description
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToOwned::to_owned),
        suffix: scan.suffix,
        pattern: scan.pattern,
        length: scan.length,
        result_count: domains.len() as i64,
        published_at: published_at.clone(),
        scan_finished_at: scan.finished_at.unwrap_or(scan.created_at),
        updated_at: published_at,
    };
    let data = PublishedPageData {
        meta: meta.clone(),
        domains: domains.clone(),
    };

    write_publication_files(&static_dir_path, &meta, &data).await?;

    let insert_result = persist_publication(db, &meta, &static_dir, &domains).await;
    if let Err(error) = insert_result {
        let _ = fs::remove_dir_all(&static_dir_path).await;
        return Err(error);
    }

    fetch_published_scan_summary(db, &publication_id)
        .await?
        .ok_or_else(|| anyhow!("published scan was inserted but could not be loaded"))
}

pub async fn delete_published_scan(db: &SqlitePool, id: &str) -> Result<bool> {
    let record = sqlx::query_as::<_, (String, String)>(
        "SELECT slug, static_dir
         FROM published_scans
         WHERE id = ?",
    )
    .bind(id)
    .fetch_optional(db)
    .await
    .context("failed to load published scan for deletion")?;

    let Some((slug, static_dir)) = record else {
        return Ok(false);
    };

    sqlx::query("DELETE FROM published_scans WHERE id = ?")
        .bind(id)
        .execute(db)
        .await
        .context("failed to delete published scan")?;

    let static_dir_path = PathBuf::from(static_dir);
    if static_dir_path.exists() {
        fs::remove_dir_all(&static_dir_path)
            .await
            .with_context(|| {
                format!(
                    "deleted db row for slug '{slug}' but failed to remove static directory '{}'",
                    static_dir_path.display()
                )
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

    let row = sqlx::query_as::<_, (String, String, String, String, i64, String, String)>(
        "SELECT ps.scan_id, ps.slug, s.suffix, s.pattern, s.length, ps.published_at, ps.static_dir
         FROM published_scans ps
         JOIN scans s ON s.id = ps.scan_id
         WHERE ps.id = ?",
    )
    .bind(id)
    .fetch_optional(db)
    .await
    .context("failed to load published scan for update")?;

    let Some((scan_id, slug, suffix, pattern, length, published_at, static_dir)) = row else {
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
        "SELECT domain, available, expiration_date, signatures
         FROM published_domains
         WHERE published_scan_id = ?
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
        scan_finished_at: published_at.clone(), // Default for existing ones if field missing
        updated_at: updated_at.clone(),
    };
    let data = PublishedPageData {
        meta: meta.clone(),
        domains,
    };

    write_publication_files(Path::new(&static_dir), &meta, &data).await?;

    sqlx::query(
        "UPDATE published_scans
         SET title = ?, description = ?, updated_at = ?
         WHERE id = ?",
    )
    .bind(&meta.title)
    .bind(&meta.description)
    .bind(&updated_at)
    .bind(id)
    .execute(db)
    .await
    .context("failed to update published scan metadata")?;

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

async fn allocate_unique_slug(db: &SqlitePool, base: &str) -> Result<String> {
    let mut attempt = 1_u32;
    loop {
        let candidate = if attempt == 1 {
            base.to_string()
        } else {
            format!("{base}-{attempt}")
        };

        let exists_in_db =
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM published_scans WHERE slug = ?")
                .bind(&candidate)
                .fetch_one(db)
                .await
                .with_context(|| format!("failed to check slug uniqueness for '{candidate}'"))?;

        if exists_in_db == 0 && !publication_dir(&candidate).exists() {
            return Ok(candidate);
        }

        attempt += 1;
    }
}

async fn write_publication_files(
    dir: &Path,
    meta: &PublishedPageMeta,
    data: &PublishedPageData,
) -> Result<()> {
    fs::create_dir_all(dir)
        .await
        .with_context(|| format!("failed to create publication directory '{}'", dir.display()))?;

    let meta_json = serde_json::to_vec_pretty(meta).context("failed to serialize meta.json")?;
    let data_json = serde_json::to_vec_pretty(data).context("failed to serialize data.json")?;
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

async fn persist_publication(
    db: &SqlitePool,
    meta: &PublishedPageMeta,
    static_dir: &str,
    domains: &[PublishedDomainFileRow],
) -> Result<()> {
    let mut tx = db
        .begin()
        .await
        .context("failed to begin publication transaction")?;

    sqlx::query(
        "INSERT INTO published_scans
            (id, scan_id, slug, title, description, status, static_dir, result_count, published_at, updated_at)
         VALUES (?, ?, ?, ?, ?, 'active', ?, ?, ?, ?)",
    )
    .bind(&meta.id)
    .bind(&meta.scan_id)
    .bind(&meta.slug)
    .bind(&meta.title)
    .bind(&meta.description)
    .bind(static_dir)
    .bind(meta.result_count)
    .bind(&meta.published_at)
    .bind(&meta.updated_at)
    .execute(&mut *tx)
    .await
    .context("failed to insert published scan")?;

    for domain in domains {
        sqlx::query(
            "INSERT INTO published_domains
                (published_scan_id, domain, available, expiration_date, signatures, published_at)
             VALUES (?, ?, ?, ?, ?, ?)",
        )
        .bind(&meta.id)
        .bind(&domain.domain)
        .bind(domain.available)
        .bind(&domain.expiration_date)
        .bind(&domain.signatures)
        .bind(&meta.published_at)
        .execute(&mut *tx)
        .await
        .with_context(|| format!("failed to insert published domain '{}'", domain.domain))?;
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

    #[test]
    fn slugify_collapses_separators() {
        assert_eq!(slugify("Hello, Domain Scanner!"), "hello-domain-scanner");
        assert_eq!(slugify("  multiple___spaces  "), "multiple-spaces");
        assert_eq!(slugify("---"), "");
    }
}
