use regex::Regex;
use std::collections::HashSet;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::sync::Arc;
use std::sync::atomic::{AtomicI64, Ordering};
use tokio::sync::mpsc;

pub struct DomainGenerator {
    pub domains: mpsc::Receiver<String>,
    pub total_count: usize,
    pub generated: Arc<AtomicI64>,
}

fn normalized_skip_count(skip_count: i64) -> usize {
    if skip_count < 0 {
        0
    } else {
        skip_count as usize
    }
}

pub fn generate_domains(
    length: usize,
    suffix: String,
    pattern: String,
    regex_filter: String,
    dict_file: String,
    priority_words_input: Vec<String>,
    skip_count: i64,
) -> Result<DomainGenerator, String> {
    let letters = "abcdefghijklmnopqrstuvwxyz";
    let numbers = "0123456789";

    let regex = if !regex_filter.is_empty() {
        match Regex::new(&regex_filter) {
            Ok(r) => Some(r),
            Err(e) => {
                return Err(format!("Invalid regex pattern: {}", e));
            }
        }
    } else {
        None
    };

    let (tx, rx) = mpsc::channel(1000);
    // Initialize generated count with skipped count
    let generated = Arc::new(AtomicI64::new(skip_count));
    let generated_clone = generated.clone();

    let mut total_estimated = 0;
    let mut priority_set_raw = HashSet::new();
    let mut priority_lines = Vec::new();

    // 1. Process priority words
    for word in priority_words_input {
        let word = word.trim().to_string();
        if word.is_empty() {
            continue;
        }
        if let Some(ref r) = regex {
            if !r.is_match(&word) {
                continue;
            }
        }
        if priority_set_raw.insert(word.clone()) {
            priority_lines.push(word);
        }
    }

    let priority_set_len = priority_set_raw.len();
    let priority_set = Arc::new(priority_set_raw);

    if !dict_file.is_empty() {
        // Dictionary mode
        let file =
            File::open(&dict_file).map_err(|e| format!("Error reading dictionary file: {}", e))?;
        let reader = BufReader::new(file);
        let lines: Vec<String> = reader.lines().filter_map(|l| l.ok()).collect();
        total_estimated = count_filtered_dictionary_entries(&lines, regex.as_ref(), &priority_set);

        let tx = tx.clone();
        let suffix = suffix.clone();
        let priority_set_clone = priority_set.clone();
        tokio::spawn(async move {
            let skip = normalized_skip_count(skip_count);
            let mut current_idx = 0;

            // Priority Phase
            for word in priority_lines {
                if current_idx >= skip {
                    let domain = if word.contains('.') {
                        word
                    } else {
                        format!("{}{}", word, suffix)
                    };
                    if tx.send(domain).await.is_err() {
                        return;
                    }
                    generated_clone.fetch_add(1, Ordering::Relaxed);
                }
                current_idx += 1;
            }

            // Regular Phase
            for word in lines {
                let word = word.trim();
                if word.is_empty() || priority_set_clone.contains(word) {
                    continue;
                }

                if let Some(ref r) = regex {
                    if !r.is_match(word) {
                        continue;
                    }
                }

                if current_idx >= skip {
                    let domain = if word.contains('.') {
                        word.to_string()
                    } else {
                        format!("{}{}", word, suffix)
                    };
                    if tx.send(domain).await.is_err() {
                        break;
                    }
                    generated_clone.fetch_add(1, Ordering::Relaxed);
                }
                current_idx += 1;
            }
        });
    } else {
        // Traditional mode
        let charset = match pattern.as_str() {
            "d" => numbers.to_string(),
            "D" => letters.to_string(),
            "a" => format!("{}{}", letters, numbers),
            _ => {
                return Err(
                    "Invalid pattern. Use -d for numbers, -D for letters, -a for alphanumeric"
                        .to_string(),
                );
            }
        };

        let charset_len = charset.len();
        if charset_len > 0 && length > 0 {
            total_estimated = if regex.is_none() {
                exact_combination_count(&charset, length, &priority_set)
            } else {
                count_matching_combinations(&charset, length, regex.as_ref(), &priority_set)
                    + priority_set_len
            };

            let tx = tx.clone();
            let suffix = suffix.clone();
            let priority_set_clone = priority_set.clone();

            tokio::spawn(async move {
                let skip = normalized_skip_count(skip_count);
                let mut current_idx = 0;

                // Priority Phase
                for word in priority_lines {
                    if current_idx >= skip {
                        let domain = format!("{}{}", word, suffix);
                        if tx.send(domain).await.is_err() {
                            return;
                        }
                        generated_clone.fetch_add(1, Ordering::Relaxed);
                    }
                    current_idx += 1;
                }

                // Regular Phase
                generate_combinations_iterative(
                    tx,
                    charset,
                    length,
                    suffix,
                    regex,
                    generated_clone,
                    priority_set_clone,
                    skip,
                )
                .await;
            });
        }
    }

    Ok(DomainGenerator {
        domains: rx,
        total_count: total_estimated.max(priority_set_len),
        generated,
    })
}

async fn generate_combinations_iterative(
    tx: mpsc::Sender<String>,
    charset: String,
    length: usize,
    suffix: String,
    regex: Option<Regex>,
    generated: Arc<AtomicI64>,
    priority_set: Arc<HashSet<String>>,
    skip: usize,
) {
    let charset_chars: Vec<char> = charset.chars().collect();
    let charset_size = charset_chars.len();

    let total = charset_size.pow(length as u32);

    let mut actual_idx = priority_set.len();

    for counter in 0..total {
        let mut current = String::with_capacity(length);
        let mut temp = counter;

        for _ in 0..length {
            let idx = temp % charset_size;
            current.insert(0, charset_chars[idx]);
            temp /= charset_size;
        }

        if priority_set.contains(&current) {
            continue;
        }

        // Regex check
        if let Some(ref r) = regex {
            if !r.is_match(&current) {
                continue;
            }
        }

        if actual_idx >= skip {
            let domain = format!("{}{}", current, suffix);
            if tx.send(domain).await.is_err() {
                break;
            }
            generated.fetch_add(1, Ordering::Relaxed);
        }
        actual_idx += 1;
    }
}

fn count_filtered_dictionary_entries(
    lines: &[String],
    regex: Option<&Regex>,
    priority_set: &HashSet<String>,
) -> usize {
    let mut count = priority_set.len();
    for word in lines {
        let word = word.trim();
        if word.is_empty() || priority_set.contains(word) {
            continue;
        }

        if regex.is_some_and(|r| !r.is_match(word)) {
            continue;
        }

        count += 1;
    }

    count
}

fn count_matching_combinations(
    charset: &str,
    length: usize,
    regex: Option<&Regex>,
    priority_set: &HashSet<String>,
) -> usize {
    let charset_chars: Vec<char> = charset.chars().collect();
    let charset_size = charset_chars.len();
    let total = charset_size.pow(length as u32);
    let mut count = 0;

    for counter in 0..total {
        let current = build_combination(counter, &charset_chars, length);
        if priority_set.contains(&current) {
            continue;
        }

        if regex.is_some_and(|r| !r.is_match(&current)) {
            continue;
        }

        count += 1;
    }

    count
}

fn exact_combination_count(charset: &str, length: usize, priority_set: &HashSet<String>) -> usize {
    let charset_size = charset.len();
    let total = charset_size.pow(length as u32);

    let duplicate_priority_count = priority_set
        .iter()
        .filter(|word| {
            word.len() == length && word.bytes().all(|b| charset.as_bytes().contains(&b))
        })
        .count();

    total + priority_set.len().saturating_sub(duplicate_priority_count)
}

fn build_combination(mut counter: usize, charset_chars: &[char], length: usize) -> String {
    let charset_size = charset_chars.len();
    let mut current = vec![0_u8; length];
    for position in (0..length).rev() {
        let charset_idx = counter % charset_size;
        current[position] = charset_chars[charset_idx] as u8;
        counter /= charset_size;
    }
    String::from_utf8(current).expect("domain charset is always ASCII")
}

/// A lazy odometer-based iterator that yields Cartesian product combinations
/// of words from multiple dictionaries.
///
/// The `format_template` string uses `{0}`, `{1}`, ... as placeholders for
/// words from each dictionary. The `suffix` (TLD) is appended after the template.
///
/// The "least significant" dimension is the last dictionary in `word_lists`,
/// meaning that dict advances fastest.
pub struct DictionaryCombinator {
    word_lists: Vec<Vec<String>>,
    indices: Vec<usize>,
    format_template: String,
    suffix: String,
    done: bool,
}

impl DictionaryCombinator {
    pub fn new(word_lists: Vec<Vec<String>>, format_template: String, suffix: String) -> Self {
        let list_count = word_lists.len();
        let done = list_count == 0 || word_lists.iter().any(|l| l.is_empty());
        Self {
            word_lists,
            indices: vec![0; list_count],
            format_template,
            suffix,
            done,
        }
    }

    /// Build a combinator from legacy prefix/separator/postfix fields.
    /// Constructs the equivalent template string.
    pub fn from_parts(
        word_lists: Vec<Vec<String>>,
        prefix: &str,
        separator: &str,
        postfix: &str,
        suffix: String,
    ) -> Self {
        let mut template = String::from(prefix);
        for i in 0..word_lists.len() {
            if i > 0 && !separator.is_empty() {
                template.push_str(separator);
            }
            template.push_str(&format!("{{{}}}", i));
        }
        template.push_str(postfix);
        Self::new(word_lists, template, suffix)
    }

    pub fn total_combinations(&self) -> usize {
        self.word_lists
            .iter()
            .fold(1usize, |acc, wl| acc.saturating_mul(wl.len()))
    }

    pub fn current_position(&self) -> usize {
        if self.done {
            return self.total_combinations();
        }
        let mut pos = 0usize;
        let mut multiplier = 1usize;
        for i in (0..self.word_lists.len()).rev() {
            pos += self.indices[i] * multiplier;
            multiplier *= self.word_lists[i].len();
        }
        pos
    }

    pub fn set_position(&mut self, pos: usize) {
        let total = self.total_combinations();
        if pos >= total {
            self.done = true;
            return;
        }
        let mut remaining = pos;
        for i in (0..self.word_lists.len()).rev() {
            let size = self.word_lists[i].len();
            if size > 0 {
                self.indices[i] = remaining % size;
                remaining /= size;
            } else {
                self.indices[i] = 0;
            }
        }
        self.done = false;
    }

    pub fn skip_to(&mut self, pos: usize) {
        self.set_position(pos);
    }

    pub fn next(&mut self) -> Option<String> {
        if self.done {
            return None;
        }

        // Render template by replacing {N} placeholders with current dict words.
        // Request validation keeps templates ASCII, but char iteration keeps this
        // renderer correct if it is used directly in tests or future code.
        let mut domain = String::new();
        let mut chars = self.format_template.chars().peekable();
        while let Some(ch) = chars.next() {
            if ch == '{' {
                let mut idx_str = String::new();
                while let Some(&next) = chars.peek() {
                    chars.next();
                    if next == '}' {
                        break;
                    }
                    idx_str.push(next);
                }
                if let Ok(idx) = idx_str.parse::<usize>() {
                    if let Some(list) = self.word_lists.get(idx) {
                        domain.push_str(&list[self.indices[idx]]);
                        continue;
                    }
                }
                domain.push('{');
                domain.push_str(&idx_str);
                domain.push('}');
            } else {
                domain.push(ch);
            }
        }
        // Only append suffix if the rendered domain doesn't already contain a TLD.
        if !domain.contains('.') {
            domain.push_str(&self.suffix);
        }

        // Advance odometer (least significant = last dict)
        for i in (0..self.indices.len()).rev() {
            self.indices[i] += 1;
            if self.indices[i] < self.word_lists[i].len() {
                break;
            }
            self.indices[i] = 0;
            if i == 0 {
                self.done = true;
            }
        }

        Some(domain)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_generator_skip() {
        // Test pattern "a" (alphanumeric), length 1
        // Charset: a-z (0-25), 0-9 (26-35)
        // Total 36
        // Sequence: a.com, b.com, c.com ...

        // 1. Generate full list
        let gen_full = generate_domains(
            1,
            ".com".to_string(),
            "a".to_string(),
            "".to_string(),
            "".to_string(),
            vec![],
            0,
        )
        .unwrap();

        let mut full_list = Vec::new();
        let mut rx = gen_full.domains;
        while let Some(d) = rx.recv().await {
            full_list.push(d);
        }

        assert_eq!(full_list.len(), 36);
        assert_eq!(full_list[0], "a.com");
        assert_eq!(full_list[1], "b.com");
        assert_eq!(full_list[2], "c.com");

        // 2. Generate with skip = 2
        let gen_skip = generate_domains(
            1,
            ".com".to_string(),
            "a".to_string(),
            "".to_string(),
            "".to_string(),
            vec![],
            2, // Skip 'a.com', 'b.com', start at 'c.com'
        )
        .unwrap();

        let mut skip_list = Vec::new();
        let mut rx = gen_skip.domains;
        while let Some(d) = rx.recv().await {
            skip_list.push(d);
        }

        assert_eq!(skip_list.len(), 34);
        assert_eq!(skip_list[0], "c.com"); // Should be c.com
        assert_eq!(skip_list, full_list[2..].to_vec());
    }

    #[test]
    fn test_combinator_two_dicts() {
        let dicts = vec![
            vec!["red".to_string(), "blue".to_string()],
            vec!["fox".to_string(), "bird".to_string()],
        ];
        let mut c = DictionaryCombinator::new(dicts, "{0}{1}".into(), ".io".into());
        assert_eq!(c.total_combinations(), 4);
        assert_eq!(c.next(), Some("redfox.io".to_string()));
        assert_eq!(c.next(), Some("redbird.io".to_string()));
        assert_eq!(c.next(), Some("bluefox.io".to_string()));
        assert_eq!(c.next(), Some("bluebird.io".to_string()));
        assert_eq!(c.next(), None);
    }

    #[test]
    fn test_combinator_with_separator() {
        let dicts = vec![
            vec!["go".to_string()],
            vec!["app".to_string(), "tech".to_string()],
        ];
        let mut c = DictionaryCombinator::new(dicts, "{0}-{1}".into(), ".com".into());
        assert_eq!(c.next(), Some("go-app.com".to_string()));
        assert_eq!(c.next(), Some("go-tech.com".to_string()));
        assert_eq!(c.next(), None);
    }

    #[test]
    fn test_combinator_with_prefix_postfix() {
        let dicts = vec![
            vec!["app".to_string(), "web".to_string()],
            vec!["dev".to_string()],
        ];
        let mut c = DictionaryCombinator::new(dicts, "my{0}-{1}hq".into(), ".xyz".into());
        assert_eq!(c.next(), Some("myapp-devhq.xyz".to_string()));
        assert_eq!(c.next(), Some("myweb-devhq.xyz".to_string()));
        assert_eq!(c.next(), None);
    }

    #[test]
    fn test_combinator_set_position() {
        let dicts = vec![
            vec!["a".to_string(), "b".to_string(), "c".to_string()],
            vec!["x".to_string(), "y".to_string()],
        ];
        let mut c = DictionaryCombinator::new(dicts, "{0}{1}".into(), ".com".into());
        c.skip_to(2);
        assert_eq!(c.current_position(), 2);
        assert_eq!(c.next(), Some("bx.com".to_string()));
        assert_eq!(c.current_position(), 3);
        assert_eq!(c.next(), Some("by.com".to_string()));
        c.skip_to(6);
        assert_eq!(c.next(), None);
    }

    #[test]
    fn test_combinator_empty_dict() {
        let dicts = vec![vec!["a".to_string()], vec![]];
        let mut c = DictionaryCombinator::new(dicts, "{0}{1}".into(), ".com".into());
        assert_eq!(c.total_combinations(), 0);
        assert_eq!(c.next(), None);
    }

    #[test]
    fn test_combinator_single_dict() {
        let dicts = vec![vec![
            "alpha".to_string(),
            "beta".to_string(),
            "gamma".to_string(),
        ]];
        let mut c = DictionaryCombinator::new(dicts, "{0}".into(), ".net".into());
        assert_eq!(c.next(), Some("alpha.net".to_string()));
        assert_eq!(c.next(), Some("beta.net".to_string()));
        assert_eq!(c.next(), Some("gamma.net".to_string()));
        assert_eq!(c.next(), None);
    }

    #[test]
    fn test_combinator_from_parts() {
        let dicts = vec![
            vec!["app".to_string(), "web".to_string()],
            vec!["dev".to_string()],
        ];
        let mut c = DictionaryCombinator::from_parts(dicts, "go", "-", "hq", ".xyz".into());
        assert_eq!(c.next(), Some("goapp-devhq.xyz".to_string()));
        assert_eq!(c.next(), Some("goweb-devhq.xyz".to_string()));
        assert_eq!(c.next(), None);
    }

    #[test]
    fn test_combinator_template_placeholder() {
        let dicts = vec![vec!["a".to_string(), "b".to_string()]];
        let mut c = DictionaryCombinator::new(dicts, "just-text-{0}nope".into(), ".com".into());
        assert_eq!(c.next(), Some("just-text-anope.com".to_string()));
        assert_eq!(c.next(), Some("just-text-bnope.com".to_string()));
        assert_eq!(c.next(), None);
    }

    #[test]
    fn test_combinator_template_oob_kept() {
        let dicts = vec![vec!["a".to_string()]];
        let mut c = DictionaryCombinator::new(dicts, "pre-{99}-literal".into(), ".com".into());
        assert_eq!(c.next(), Some("pre-{99}-literal.com".to_string()));
        assert_eq!(c.next(), None);
    }

    #[test]
    fn test_combinator_full_domain_words() {
        // When all dictionary words already contain a TLD (dot), suffix should NOT be appended.
        let dicts = vec![vec![
            "example.com".to_string(),
            "test.org".to_string(),
            "hello.xyz".to_string(),
        ]];
        let mut c = DictionaryCombinator::new(dicts, "{0}".into(), ".net".into());
        assert_eq!(c.next(), Some("example.com".to_string()));
        assert_eq!(c.next(), Some("test.org".to_string()));
        assert_eq!(c.next(), Some("hello.xyz".to_string()));
        assert_eq!(c.next(), None);
    }

    #[test]
    fn test_combinator_mixed_words() {
        // Mixed dictionary: words with dots keep their TLD, words without get suffix.
        let dicts = vec![vec!["example.com".to_string(), "hello".to_string()]];
        let mut c = DictionaryCombinator::new(dicts, "{0}".into(), ".xyz".into());
        assert_eq!(c.next(), Some("example.com".to_string()));
        assert_eq!(c.next(), Some("hello.xyz".to_string()));
        assert_eq!(c.next(), None);
    }

    #[test]
    fn test_combinator_full_domain_empty_suffix() {
        // When all words are full domains and suffix is empty, should work fine.
        let dicts = vec![vec!["a.com".to_string(), "b.org".to_string()]];
        let mut c = DictionaryCombinator::new(dicts, "{0}".into(), String::new());
        assert_eq!(c.next(), Some("a.com".to_string()));
        assert_eq!(c.next(), Some("b.org".to_string()));
        assert_eq!(c.next(), None);
    }
}
