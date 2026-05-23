use anyhow::{Context, Result, anyhow};
use chrono::Utc;
use serde::Serialize;
use sqlx::{FromRow, SqlitePool};
use std::path::Path;
use tokio::fs;
use uuid::Uuid;

use super::models::validate_domain_fragment;

const DICTIONARY_ROOT: &str = "data/dictionaries";
const MAX_DICTIONARY_WORDS: usize = 2_000_000;

#[derive(Debug, Clone, Serialize, FromRow)]
pub struct DictionarySummary {
    pub id: String,
    pub name: String,
    pub word_count: i64,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, serde::Deserialize, Serialize)]
pub struct RenameRequest {
    pub name: String,
}

pub async fn create_dictionary(
    db: &SqlitePool,
    name: &str,
    body: &[u8],
) -> Result<DictionarySummary> {
    let name = name.trim();
    if name.is_empty() {
        anyhow::bail!("dictionary name cannot be empty");
    }

    let text = String::from_utf8(body.to_vec()).context("dictionary file is not valid UTF-8")?;

    let words: Vec<&str> = text
        .lines()
        .map(|l| l.trim())
        .filter(|l| !l.is_empty())
        .collect();

    if words.is_empty() {
        anyhow::bail!("dictionary file is empty");
    }

    if words.len() > MAX_DICTIONARY_WORDS {
        anyhow::bail!(
            "too many dictionary words: {} (max {})",
            words.len(),
            MAX_DICTIONARY_WORDS
        );
    }

    for word in &words {
        validate_domain_fragment("dictionary word", word).map_err(anyhow::Error::msg)?;
    }

    let id = Uuid::new_v4().to_string();
    let now = Utc::now().to_rfc3339();
    let dir = Path::new(DICTIONARY_ROOT);
    let file_path = dir.join(format!("{}.txt", id));

    fs::create_dir_all(dir)
        .await
        .context("failed to create dictionaries directory")?;

    fs::write(&file_path, &text)
        .await
        .context("failed to write dictionary file")?;

    let insert_result = sqlx::query(
        "INSERT INTO dictionaries (id, name, word_count, created_at, updated_at) VALUES (?, ?, ?, ?, ?)",
    )
    .bind(&id)
    .bind(name)
    .bind(words.len() as i64)
    .bind(&now)
    .bind(&now)
    .execute(db)
    .await;

    match insert_result {
        Ok(_) => Ok(DictionarySummary {
            id,
            name: name.to_string(),
            word_count: words.len() as i64,
            created_at: now.clone(),
            updated_at: now,
        }),
        Err(e) => {
            let _ = fs::remove_file(&file_path).await;
            Err(anyhow!("failed to insert dictionary: {}", e))
        }
    }
}

pub async fn list_dictionaries(db: &SqlitePool) -> Result<Vec<DictionarySummary>, sqlx::Error> {
    sqlx::query_as::<_, DictionarySummary>(
        "SELECT id, name, word_count, created_at, updated_at FROM dictionaries ORDER BY updated_at DESC",
    )
    .fetch_all(db)
    .await
}

pub async fn get_dictionary(
    db: &SqlitePool,
    id: &str,
) -> Result<Option<DictionarySummary>, sqlx::Error> {
    sqlx::query_as::<_, DictionarySummary>(
        "SELECT id, name, word_count, created_at, updated_at FROM dictionaries WHERE id = ?",
    )
    .bind(id)
    .fetch_optional(db)
    .await
}

pub async fn get_dictionary_words(id: &str, offset: usize, limit: usize) -> Result<Vec<String>> {
    let file_path = Path::new(DICTIONARY_ROOT).join(format!("{}.txt", id));
    let text = fs::read_to_string(&file_path)
        .await
        .context("failed to read dictionary file")?;

    let words: Vec<String> = text
        .lines()
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty())
        .skip(offset)
        .take(limit)
        .collect();

    Ok(words)
}

pub async fn load_dictionary_words(id: &str) -> Result<Vec<String>> {
    let file_path = Path::new(DICTIONARY_ROOT).join(format!("{}.txt", id));
    let text = fs::read_to_string(&file_path)
        .await
        .context("failed to read dictionary file for scan")?;

    let words: Vec<String> = text
        .lines()
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty())
        .collect();

    Ok(words)
}

pub async fn load_multiple_dictionary_words(ids: &[String]) -> Result<Vec<Vec<String>>> {
    let mut all_words = Vec::with_capacity(ids.len());
    for id in ids {
        let words = load_dictionary_words(id).await?;
        if words.is_empty() {
            anyhow::bail!("Dictionary '{}' is empty", id);
        }
        all_words.push(words);
    }
    Ok(all_words)
}

pub async fn rename_dictionary(
    db: &SqlitePool,
    id: &str,
    name: &str,
) -> Result<Option<DictionarySummary>> {
    let name = name.trim();
    if name.is_empty() {
        anyhow::bail!("dictionary name cannot be empty");
    }

    let now = Utc::now().to_rfc3339();
    let result = sqlx::query("UPDATE dictionaries SET name = ?, updated_at = ? WHERE id = ?")
        .bind(name)
        .bind(&now)
        .bind(id)
        .execute(db)
        .await
        .context("failed to rename dictionary")?;

    if result.rows_affected() == 0 {
        return Ok(None);
    }

    get_dictionary(db, id)
        .await
        .map_err(|e| anyhow!("failed to fetch renamed dictionary: {}", e))
}

pub async fn delete_dictionary(db: &SqlitePool, id: &str) -> Result<bool> {
    let result = sqlx::query("DELETE FROM dictionaries WHERE id = ?")
        .bind(id)
        .execute(db)
        .await
        .context("failed to delete dictionary")?;

    if result.rows_affected() == 0 {
        return Ok(false);
    }

    let file_path = Path::new(DICTIONARY_ROOT).join(format!("{}.txt", id));
    if file_path.exists() {
        fs::remove_file(&file_path).await.with_context(|| {
            format!(
                "deleted db row but failed to remove dictionary file '{}'",
                file_path.display()
            )
        })?;
    }

    Ok(true)
}
