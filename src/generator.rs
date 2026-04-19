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
            let skip = if skip_count < 0 {
                0
            } else {
                skip_count as usize
            };
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
                    let domain = format!("{}{}", word, suffix);
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
            total_estimated =
                count_matching_combinations(&charset, length, regex.as_ref(), &priority_set)
                    + priority_set_len;

            let tx = tx.clone();
            let suffix = suffix.clone();
            let priority_set_clone = priority_set.clone();

            tokio::spawn(async move {
                let skip = if skip_count < 0 {
                    0
                } else {
                    skip_count as usize
                };
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

fn build_combination(mut counter: usize, charset_chars: &[char], length: usize) -> String {
    let charset_size = charset_chars.len();
    let mut current = String::with_capacity(length);
    for _ in 0..length {
        let idx = counter % charset_size;
        current.insert(0, charset_chars[idx]);
        counter /= charset_size;
    }
    current
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
}
