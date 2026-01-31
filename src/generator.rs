use regex::Regex;
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
    skip_count: i64,
) -> DomainGenerator {
    let letters = "abcdefghijklmnopqrstuvwxyz";
    let numbers = "0123456789";

    let regex = if !regex_filter.is_empty() {
        match Regex::new(&regex_filter) {
            Ok(r) => Some(r),
            Err(e) => {
                eprintln!("Invalid regex pattern: {}", e);
                std::process::exit(1);
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

    if !dict_file.is_empty() {
        // Dictionary mode
        let file = File::open(&dict_file).unwrap_or_else(|e| {
            eprintln!("Error reading dictionary file: {}", e);
            std::process::exit(1);
        });
        let reader = BufReader::new(file);
        let lines: Vec<String> = reader.lines().filter_map(|l| l.ok()).collect();
        total_estimated = lines.len();

        let tx = tx.clone();
        let suffix = suffix.clone();
        tokio::spawn(async move {
            // simple check to avoid skip overflow
            let skip = if skip_count < 0 {
                0
            } else {
                skip_count as usize
            };

            for word in lines.into_iter().skip(skip) {
                let word = word.trim();
                if word.is_empty() {
                    continue;
                }

                // Regex check on the word/prefix
                if let Some(ref r) = regex {
                    if !r.is_match(word) {
                        continue;
                    }
                }

                let domain = format!("{}{}", word, suffix);
                if tx.send(domain).await.is_err() {
                    break;
                }
                generated_clone.fetch_add(1, Ordering::Relaxed);
            }
        });
    } else {
        // Traditional mode
        let charset = match pattern.as_str() {
            "d" => numbers.to_string(),
            "D" => letters.to_string(),
            "a" => format!("{}{}", letters, numbers),
            _ => {
                eprintln!(
                    "Invalid pattern. Use -d for numbers, -D for letters, -a for alphanumeric"
                );
                std::process::exit(1);
            }
        };

        let charset_len = charset.len();
        if charset_len > 0 && length > 0 {
            total_estimated = charset_len.pow(length as u32);

            let tx = tx.clone();
            let suffix = suffix.clone();

            tokio::spawn(async move {
                generate_combinations_iterative(
                    tx,
                    charset,
                    length,
                    suffix,
                    regex,
                    generated_clone,
                    skip_count,
                )
                .await;
            });
        }
    }

    DomainGenerator {
        domains: rx,
        total_count: total_estimated,
        generated,
    }
}

async fn generate_combinations_iterative(
    tx: mpsc::Sender<String>,
    charset: String,
    length: usize,
    suffix: String,
    regex: Option<Regex>,
    generated: Arc<AtomicI64>,
    skip_count: i64,
) {
    let charset_chars: Vec<char> = charset.chars().collect();
    let charset_size = charset_chars.len();

    let total = charset_size.pow(length as u32);
    // Ensure we don't start beyond total
    let start_index = if skip_count < 0 {
        0
    } else {
        skip_count as usize
    };
    let start_index = std::cmp::min(start_index, total);

    for counter in start_index..total {
        let mut current = String::with_capacity(length);
        let mut temp = counter;

        // Build string from counter (base conversion)
        // Original Go logic:
        // for i := 0; i < length; i++ {
        //     current = string(charset[temp%charsetSize]) + current
        //     temp /= charsetSize
        // }
        // Wait, the Go logic prepends.

        for _ in 0..length {
            let idx = temp % charset_size;
            current.insert(0, charset_chars[idx]);
            temp /= charset_size;
        }

        // Regex check
        if let Some(ref r) = regex {
            if !r.is_match(&current) {
                continue;
            }
        }

        let domain = format!("{}{}", current, suffix);
        if tx.send(domain).await.is_err() {
            break;
        }
        generated.fetch_add(1, Ordering::Relaxed);
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
            0,
        );

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
            2, // Skip 'a.com', 'b.com', start at 'c.com'
        );

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
