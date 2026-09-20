use std::collections::{BTreeSet, HashMap};
use std::time::Instant;

/// One deadline per domain, with FIFO ordering for equal deadlines. Replacing
/// a deadline removes the old entry instead of accumulating stale heap nodes.
#[derive(Default)]
pub(super) struct RetryQueue {
    deadlines: BTreeSet<(Instant, u64, String)>,
    entries: HashMap<String, (Instant, u64)>,
    sequence: u64,
}

impl RetryQueue {
    pub(super) fn insert(&mut self, domain: String, ready_at: Instant) {
        self.remove(&domain);
        let sequence = self.sequence;
        self.sequence = self.sequence.wrapping_add(1);
        self.deadlines.insert((ready_at, sequence, domain.clone()));
        self.entries.insert(domain, (ready_at, sequence));
    }

    pub(super) fn remove(&mut self, domain: &str) {
        if let Some((ready_at, sequence)) = self.entries.remove(domain) {
            self.deadlines
                .remove(&(ready_at, sequence, domain.to_owned()));
        }
    }

    pub(super) fn next_deadline(&self) -> Option<Instant> {
        self.deadlines.first().map(|entry| entry.0)
    }

    pub(super) fn pop_due(&mut self, now: Instant) -> Option<(String, Instant)> {
        if self.next_deadline()? > now {
            return None;
        }
        let (ready_at, _, domain) = self.deadlines.pop_first()?;
        self.entries.remove(&domain);
        Some((domain, ready_at))
    }

    pub(super) fn clear(&mut self) {
        self.deadlines.clear();
        self.entries.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn deadlines_are_ordered_and_replacement_does_not_replay_stale_entries() {
        let now = Instant::now();
        let later = now + Duration::from_secs(10);
        let mut queue = RetryQueue::default();
        queue.insert("late".into(), later);
        queue.insert("first".into(), now);
        queue.insert("second".into(), now);
        queue.insert("first".into(), later);
        assert_eq!(queue.pop_due(now), Some(("second".into(), now)));
        assert_eq!(queue.pop_due(now), None);
        assert_eq!(queue.pop_due(later), Some(("late".into(), later)));
        assert_eq!(queue.pop_due(later), Some(("first".into(), later)));
        assert_eq!(queue.next_deadline(), None);
    }
}
