use crossterm::{
    event::{Event, KeyCode},
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use ratatui::{
    Frame, Terminal,
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Gauge, Paragraph},
};
use std::io;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;

#[derive(Debug, Clone, PartialEq)]
pub enum DomainStatus {
    Scanning,
    Available,
    Registered,
}

#[derive(Clone)]
pub struct LogEntry {
    pub domain: String,
    pub status: DomainStatus,
    pub timestamp: Instant,
    pub signature: Option<String>,
}

pub struct TuiApp {
    pub total_domains: u64,
    pub scanned_count: u64,         // Processed count
    pub initial_scanned_count: u64, // processing start point
    pub found_domains: Vec<String>,
    pub fail_count: u64,
    pub logs: Vec<LogEntry>,
    pub start_time: Instant,
    pub scan_start_time: Option<Instant>,
    pub current_rate: f64,
    pub status_message: String,
    pub checker_stats: Vec<String>,
}

impl TuiApp {
    pub fn new(total: u64, start_scanned: u64) -> Self {
        Self {
            total_domains: total,
            scanned_count: start_scanned,
            initial_scanned_count: start_scanned,
            found_domains: Vec::new(),
            fail_count: 0,
            logs: Vec::new(),
            start_time: Instant::now(),
            scan_start_time: None,
            current_rate: 0.0,
            status_message: "Initializing scan...".to_string(),
            checker_stats: Vec::new(),
        }
    }

    pub fn on_tick(&mut self) {
        // Detect start of scanning
        if self.scan_start_time.is_none() && self.scanned_count > self.initial_scanned_count {
            self.scan_start_time = Some(Instant::now());
        }

        // Update rate calculation based on active scan time
        if self.scanned_count < self.total_domains {
            if let Some(start_time) = self.scan_start_time {
                let elapsed = start_time.elapsed().as_secs_f64();
                if elapsed > 1.0 {
                    // Wait a bit for stability
                    let count_diff = self
                        .scanned_count
                        .saturating_sub(self.initial_scanned_count);
                    self.current_rate = count_diff as f64 / elapsed;
                }
            }
        }

        // Check for completion
        if self.total_domains > 0 && self.scanned_count >= self.total_domains {
            // Use scan_start_time if available, otherwise fallback to start_time
            let duration = self
                .scan_start_time
                .map(|t| t.elapsed())
                .unwrap_or_else(|| self.start_time.elapsed());

            let hours = duration.as_secs() / 3600;
            let minutes = (duration.as_secs() % 3600) / 60;
            let seconds = duration.as_secs() % 60;

            let time_str = if hours > 0 {
                format!("{}h {}m {}s", hours, minutes, seconds)
            } else if minutes > 0 {
                format!("{}m {}s", minutes, seconds)
            } else {
                format!("{}s", seconds)
            };

            self.status_message = format!("Scan Finished in {}! Press 'q' to exit.", time_str);
        }
    }

    pub fn clear_logs(&mut self) {
        self.logs.clear();
    }
}

pub struct RenderState {
    pub total_domains: u64,
    pub scanned_count: u64,
    pub found_count: usize,
    pub fail_count: u64,
    pub logs: Vec<LogEntry>,
    pub current_rate: f64,
    pub status_message: String,
    pub checker_stats: Vec<String>,
}

pub fn ui(f: &mut Frame, state: &RenderState) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // Title
            Constraint::Length(3), // Progress
            Constraint::Length(3), // Stats
            Constraint::Min(0),    // Found domains
            Constraint::Length(3), // Status bar
        ])
        .split(f.area());

    // Title
    let title = Paragraph::new("Domain Scanner (Rust Edition)")
        .style(
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )
        .block(Block::default().borders(Borders::ALL));
    f.render_widget(title, chunks[0]);

    // Progress Bar
    let percent = if state.total_domains > 0 {
        (state.scanned_count as f64 / state.total_domains as f64).min(1.0)
    } else {
        0.0
    };
    let label = if state.current_rate > 0.1 && percent < 1.0 {
        let remaining = state.total_domains.saturating_sub(state.scanned_count);
        let seconds = remaining as f64 / state.current_rate;
        format!("{:.2}% (ETA: {:.0}s)", percent * 100.0, seconds)
    } else {
        format!("{:.2}%", percent * 100.0)
    };
    let gauge = Gauge::default()
        .block(Block::default().title("Progress").borders(Borders::ALL))
        .gauge_style(Style::default().fg(Color::Green))
        .ratio(percent)
        .label(label);
    f.render_widget(gauge, chunks[1]);

    // Stats
    let stats_text = vec![Line::from(vec![
        Span::raw("Scanned: "),
        Span::styled(
            format!("{}", state.scanned_count),
            Style::default().fg(Color::Yellow),
        ),
        Span::raw(format!(" / {}", state.total_domains)),
        Span::raw(" | Rate: "),
        Span::styled(
            format!("{:.1} d/s", state.current_rate),
            Style::default().fg(Color::Magenta),
        ),
        Span::raw(" | Found: "),
        Span::styled(
            format!("{}", state.found_count),
            Style::default().fg(Color::Green),
        ),
        Span::raw(" | Failed: "),
        Span::styled(
            format!("{}", state.fail_count),
            Style::default().fg(Color::Red),
        ),
    ])];
    let stats = Paragraph::new(stats_text)
        .block(Block::default().title("Statistics").borders(Borders::ALL));
    f.render_widget(stats, chunks[2]);

    // Found Domains List (Activity Log) - Multi-column Layout
    let log_area = chunks[3];
    let width = log_area.width as usize;
    let height = log_area.height as usize;

    // Default column width (e.g. "abc.com" + margin)
    // 25 chars provides space for most short domains + status.
    let col_width = 30; // Increased to fit signature
    let num_cols = (width / col_width).max(1);

    // Calculate maximum capacity of the view
    let usable_height = height.saturating_sub(2);
    let max_items = usable_height * num_cols;

    // We want to fill the view.
    // Take the last N items that fit.
    let start_idx = state.logs.len().saturating_sub(max_items);
    let visible_logs = state.logs.iter().skip(start_idx);

    // Grid Rendering
    // We flatten the log entries into rows of text
    let mut rows = Vec::new();
    let mut current_row = Vec::new();

    for entry in visible_logs {
        let style = match entry.status {
            DomainStatus::Scanning => Style::default().fg(Color::White),
            DomainStatus::Available => Style::default().fg(Color::Green),
            DomainStatus::Registered => Style::default().fg(Color::Gray), // Gray is less distracting for high volume
        };

        // Truncate or pad domain to fit column
        // -2 for gutter spacing
        let max_len = col_width.saturating_sub(2);

        // Format with signature if registered
        let display_text = if let Some(sig) = &entry.signature {
            if entry.status == DomainStatus::Registered {
                format!("{} [{}]", entry.domain, sig)
            } else {
                entry.domain.clone() // Available usually doesn't need signature prominent
            }
        } else {
            entry.domain.clone()
        };

        let final_text = if display_text.len() > max_len {
            format!("{}..", &display_text[..max_len.saturating_sub(2)])
        } else {
            format!("{:<width$}", display_text, width = max_len)
        };

        let span = Span::styled(final_text, style);
        current_row.push(span);

        if current_row.len() >= num_cols {
            // Join spans with space
            let mut line_spans = Vec::new();
            for (i, span) in current_row.iter().enumerate() {
                line_spans.push(span.clone());
                if i < current_row.len() - 1 {
                    line_spans.push(Span::raw("  ")); // Gutter 2 chars
                }
            }
            rows.push(Line::from(line_spans));
            current_row.clear();
        }
    }

    // Flush remaining items in the last row
    if !current_row.is_empty() {
        let mut line_spans = Vec::new();
        for (i, span) in current_row.iter().enumerate() {
            line_spans.push(span.clone());
            if i < current_row.len() - 1 {
                line_spans.push(Span::raw("  "));
            }
        }
        rows.push(Line::from(line_spans));
    }

    // Use Paragraph to render the grid
    let paragraph = Paragraph::new(rows).block(
        Block::default()
            .title(format!("Activity Log (Found: {})", state.found_count))
            .borders(Borders::ALL),
    );
    f.render_widget(paragraph, chunks[3]);

    // Status Bar / Checkers
    let status_str = if state.checker_stats.is_empty() {
        state.status_message.clone()
    } else {
        format!(
            "{} | {}",
            state.status_message,
            state.checker_stats.join(" | ")
        )
    };

    let status_bar = Paragraph::new(status_str)
        .style(Style::default().fg(Color::Gray))
        .block(Block::default().borders(Borders::TOP));
    f.render_widget(status_bar, chunks[4]);
}

/// Setup terminal, run the application loop, and restore terminal
pub async fn run(app: Arc<Mutex<TuiApp>>) -> io::Result<()> {
    // Setup
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    // Run loop
    // Faster tick rate for smoother ui updates
    let tick_rate = Duration::from_millis(33); // ~30 FPS

    let res = run_loop(&mut terminal, app, tick_rate).await;

    // Cleanup
    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;

    if let Err(err) = res {
        println!("{:?}", err);
    }

    Ok(())
}

async fn run_loop(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    app: Arc<Mutex<TuiApp>>,
    tick_rate: Duration,
) -> io::Result<()> {
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();

    // Spawn input thread
    // We use a dedicated thread for blocking input reads to verify it causes no potential interference with the async runtime
    std::thread::spawn(move || {
        // Poll with a small timeout to allow checking if we should exit (send failure)
        // or just rely on read blocking. Relying on read blocking is fine if we accept the thread hangs until next input on exit.
        // But better to loop.
        loop {
            // Check if we have an event ready
            if let Ok(true) = crossterm::event::poll(Duration::from_millis(200)) {
                if let Ok(event) = crossterm::event::read() {
                    if tx.send(event).is_err() {
                        return; // Receiver dropped, exit thread
                    }
                }
            } else {
                // If poll failed or timed out, just check if channel is closed by sending a 'dummy'?
                // No, we can't checks channel easily.
                // Just relying on the next send failure is standard.
                // But if no input ever comes, this thread lingers until process exit. That is acceptable for this app.
            }
        }
    });

    let mut interval = tokio::time::interval(tick_rate);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        tokio::select! {
            _ = interval.tick() => {
                let render_state = {
                    let mut state = app.lock().await;
                    // state.scanned_count is updated externally
                    state.on_tick();

                    // Log clearing logic
                    if let Ok(size) = terminal.size() {
                        let height = size.height as usize;
                        let width = size.width as usize;
                        let col_width = 25;
                        let cols = (width / col_width).max(1);
                        let rows = height.saturating_sub(12);
                        let capacity = rows * cols;
                        let max_cap = (capacity * 5).max(2000);

                        if state.logs.len() > max_cap {
                            let drain_cnt = state.logs.len() - max_cap;
                            state.logs.drain(0..drain_cnt);
                        }
                    }

                    RenderState {
                        total_domains: state.total_domains,
                        scanned_count: state.scanned_count,
                        found_count: state.found_domains.len(),
                        fail_count: state.fail_count,
                        logs: state.logs.clone(),
                        current_rate: state.current_rate,
                        status_message: state.status_message.clone(),
                        checker_stats: state.checker_stats.clone(),
                    }
                };
                terminal.draw(|f| ui(f, &render_state))?;
            }

            Some(event) = rx.recv() => {
                 if let Event::Key(key) = event {
                    if key.code == KeyCode::Char('q') || key.code == KeyCode::Esc {
                        return Ok(());
                    }
                }
            }
        }
    }
}
