use super::models::{ScanStreamMessage, TaskControl, TaskSignal};
use super::scan_runtime_support::enqueue_unprocessed_batch;
use crate::generator::{self, CandidateGenerator, DictionaryCombinator};
use sqlx::{QueryBuilder, Sqlite, sqlite::SqlitePool};
use std::hash::{Hash, Hasher};
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use tokio::sync::{Semaphore, broadcast};

pub(super) fn input_fingerprint(value: &impl Hash) -> String {
    let mut hash = std::collections::hash_map::DefaultHasher::new();
    value.hash(&mut hash);
    format!("v1-{:016x}", hash.finish())
}

pub(super) async fn load_generation_cursor(
    db: &SqlitePool,
    scan_id: &str,
    fingerprint: &str,
) -> Result<usize, sqlx::Error> {
    // A changed dictionary or generator version restarts enumeration; the
    // durable unique-domain ledger still prevents repeating existing work.
    let cursor: i64 = sqlx::query_scalar(
        "INSERT INTO scan_generation (scan_id, cursor, fingerprint) VALUES (?, 0, ?)
         ON CONFLICT(scan_id) DO UPDATE SET
            cursor = CASE WHEN fingerprint = excluded.fingerprint THEN cursor ELSE 0 END,
            fingerprint = excluded.fingerprint RETURNING cursor",
    )
    .bind(scan_id)
    .bind(fingerprint)
    .fetch_one(db)
    .await?;
    Ok(cursor.max(0) as usize)
}

pub(super) enum CandidateSource {
    Domains(Vec<String>),
    Combinator(DictionaryCombinator),
    Generated(CandidateGenerator),
}

pub(super) struct CandidateFeeder {
    pub db: SqlitePool,
    pub jobs_tx: async_channel::Sender<String>,
    pub scan_id: String,
    pub feeder_done: Arc<AtomicBool>,
    pub feeder_error: Arc<Mutex<Option<String>>>,
    pub pending_domains: Arc<AtomicUsize>,
    pub task_signal: Arc<AtomicU8>,
    pub scan_stream: broadcast::Sender<ScanStreamMessage>,
    pub candidate_slots: Arc<Semaphore>,
}

impl CandidateFeeder {
    pub fn spawn(self, source: CandidateSource) {
        tokio::spawn(async move {
            if let Err(error) = self.run(source).await {
                *self
                    .feeder_error
                    .lock()
                    .expect("feeder error mutex poisoned") = Some(error.to_string());
            }
            self.feeder_done.store(true, Ordering::Release);
        });
    }

    fn running(&self) -> bool {
        TaskControl::signal(&self.task_signal) == TaskSignal::Run
    }

    async fn run(&self, source: CandidateSource) -> Result<(), sqlx::Error> {
        let mut generated = match source {
            CandidateSource::Domains(domains) => {
                let fingerprint = input_fingerprint(&domains);
                let cursor = load_generation_cursor(&self.db, &self.scan_id, &fingerprint).await?;
                let total = domains.len();
                generator::stream_candidates(
                    domains.into_iter().skip(cursor).map(Some),
                    cursor,
                    total,
                )
            }
            CandidateSource::Combinator(mut combinator) => {
                let fingerprint = input_fingerprint(&combinator);
                let cursor = load_generation_cursor(&self.db, &self.scan_id, &fingerprint).await?;
                let total = combinator.total_combinations();
                combinator.set_position(cursor);
                generator::stream_candidates(combinator.map(Some), cursor, total)
            }
            CandidateSource::Generated(generated) => generated,
        };

        // Replay committed but unfinished candidates before seeking past the
        // checkpoint. Results can complete in any order without creating gaps.
        let mut position = -1i64;
        let mut last_domain = String::new();
        while self.running() {
            let rows = sqlx::query_as::<_, (i64, String)>(
                "SELECT c.position, c.domain FROM scan_candidates c
                 WHERE c.scan_id = ? AND c.completed = 0
                   AND (c.position, c.domain) > (?, ?)
                   AND NOT EXISTS (SELECT 1 FROM results r WHERE r.scan_id = c.scan_id AND r.domain = c.domain)
                   AND NOT EXISTS (SELECT 1 FROM scan_retries r WHERE r.scan_id = c.scan_id AND r.domain = c.domain)
                 ORDER BY c.position, c.domain LIMIT 500")
                .bind(&self.scan_id).bind(position).bind(&last_domain).fetch_all(&self.db).await?;
            let Some(last) = rows.last() else {
                break;
            };
            position = last.0;
            last_domain = last.1.clone();
            let domains: Vec<String> = rows.into_iter().map(|(_, domain)| domain).collect();
            if !self.enqueue(&domains).await? {
                return Ok(());
            }
        }
        while self.running() {
            let batch = tokio::select! {
                batch = generated.batches.recv() => batch,
                _ = tokio::time::sleep(std::time::Duration::from_millis(50)) => continue,
            };
            let Some(batch) = batch else {
                break;
            };
            let domains = persist_candidate_batch(&self.db, &self.scan_id, batch).await?;
            if !self.enqueue(&domains).await? {
                break;
            }
        }
        Ok(())
    }

    async fn enqueue(&self, domains: &[String]) -> Result<bool, sqlx::Error> {
        enqueue_unprocessed_batch(
            &self.db,
            &self.scan_id,
            "candidate",
            domains,
            &self.jobs_tx,
            &self.pending_domains,
            &self.task_signal,
            &self.scan_stream,
            &self.candidate_slots,
        )
        .await
    }
}

pub(super) async fn persist_candidate_batch(
    db: &SqlitePool,
    scan_id: &str,
    batch: generator::CandidateBatch,
) -> Result<Vec<String>, sqlx::Error> {
    let mut tx = db.begin().await?;
    let mut inserted = Vec::new();
    if !batch.domains.is_empty() {
        let mut builder = QueryBuilder::<Sqlite>::new(
            "INSERT OR IGNORE INTO scan_candidates (scan_id, domain, position) ",
        );
        builder.push_values(batch.domains.iter(), |mut row, domain| {
            row.push_bind(scan_id)
                .push_bind(domain.trim().trim_end_matches('.').to_ascii_lowercase())
                .push_bind(batch.cursor as i64);
        });
        builder.push(" RETURNING domain");
        inserted = builder
            .build_query_scalar::<String>()
            .fetch_all(&mut *tx)
            .await?;
    }
    sqlx::query("UPDATE scan_generation SET cursor = ? WHERE scan_id = ?")
        .bind(batch.cursor as i64)
        .bind(scan_id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(inserted)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::generator::CandidateBatch;

    #[tokio::test]
    async fn normalized_collisions_are_deduplicated_across_unfinished_batches() {
        let db = super::super::test_support::scan_db().await;
        load_generation_cursor(&db, "scan-1", "input")
            .await
            .unwrap();
        let first = persist_candidate_batch(
            &db,
            "scan-1",
            CandidateBatch {
                cursor: 3,
                domains: vec!["ABC.test".into(), "abc.test.".into(), "other.test".into()],
            },
        )
        .await
        .unwrap();
        assert_eq!(first.len(), 2);
        let second = persist_candidate_batch(
            &db,
            "scan-1",
            CandidateBatch {
                cursor: 4,
                domains: vec!["abc.test".into()],
            },
        )
        .await
        .unwrap();
        assert!(second.is_empty());
        assert_eq!(
            load_generation_cursor(&db, "scan-1", "input")
                .await
                .unwrap(),
            4
        );
    }

    #[tokio::test]
    async fn checkpoint_failure_rolls_back_candidates_and_keeps_previous_cursor() {
        let db = super::super::test_support::scan_db().await;
        load_generation_cursor(&db, "scan-1", "input")
            .await
            .unwrap();
        sqlx::query(
            "CREATE TRIGGER fail_cursor BEFORE UPDATE ON scan_generation
            BEGIN SELECT RAISE(ABORT, 'simulated storage failure'); END",
        )
        .execute(&db)
        .await
        .unwrap();
        assert!(
            persist_candidate_batch(
                &db,
                "scan-1",
                CandidateBatch {
                    cursor: 1,
                    domains: vec!["pending.test".into()]
                }
            )
            .await
            .is_err()
        );
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM scan_candidates")
            .fetch_one(&db)
            .await
            .unwrap();
        let cursor: i64 = sqlx::query_scalar("SELECT cursor FROM scan_generation")
            .fetch_one(&db)
            .await
            .unwrap();
        assert_eq!((count, cursor), (0, 0));
    }

    #[tokio::test]
    async fn resume_replays_gaps_then_seeks_cursor_without_duplicate_dispatch() {
        let db = super::super::test_support::scan_db().await;
        let domains = vec![
            "a.test".to_string(),
            "b.test".to_string(),
            "c.test".to_string(),
        ];
        let fingerprint = input_fingerprint(&domains);
        load_generation_cursor(&db, "scan-1", &fingerprint)
            .await
            .unwrap();
        persist_candidate_batch(
            &db,
            "scan-1",
            CandidateBatch {
                cursor: 2,
                domains: domains[..2].to_vec(),
            },
        )
        .await
        .unwrap();
        sqlx::query("INSERT INTO results (scan_id, domain) VALUES ('scan-1', 'b.test')")
            .execute(&db)
            .await
            .unwrap();
        let (jobs_tx, jobs_rx) = async_channel::bounded(8);
        let (scan_stream, _) = broadcast::channel(8);
        let feeder = CandidateFeeder {
            db: db.clone(),
            jobs_tx,
            scan_id: "scan-1".into(),
            feeder_done: Arc::new(AtomicBool::new(false)),
            feeder_error: Arc::new(Mutex::new(None)),
            pending_domains: Arc::new(AtomicUsize::new(0)),
            task_signal: Arc::new(AtomicU8::new(0)),
            scan_stream,
            candidate_slots: Arc::new(Semaphore::new(8)),
        };
        feeder.run(CandidateSource::Domains(domains)).await.unwrap();
        assert_eq!(jobs_rx.len(), 2);
        assert_eq!(jobs_rx.recv().await.unwrap(), "a.test");
        assert_eq!(jobs_rx.recv().await.unwrap(), "c.test");
        assert_eq!(
            load_generation_cursor(&db, "scan-1", &fingerprint)
                .await
                .unwrap(),
            3
        );
        assert_eq!(
            load_generation_cursor(&db, "scan-1", "changed dictionary")
                .await
                .unwrap(),
            0
        );
    }
}
