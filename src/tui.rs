use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode},
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use ratatui::{
    Frame, Terminal,
    backend::{Backend, CrosstermBackend},
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Gauge, List, ListItem, Paragraph},
};
use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicI64, Ordering};
use std::time::{Duration, Instant};
use tokio::sync::Mutex;

pub struct TuiApp {
    pub total_domains: u64,
    pub scanned_count: u64,
    pub found_domains: Vec<String>,
    pub start_time: Instant,
    pub current_rate: f64, // domains per second
    pub status_message: String,
    pub checker_stats: Vec<String>,
}

impl TuiApp {
    pub fn new(total: u64, start_scanned: u64) -> Self {
        Self {
            total_domains: total,
            scanned_count: start_scanned,
            found_domains: Vec::new(),
            start_time: Instant::now(),
            current_rate: 0.0,
            status_message: "Initializing scan...".to_string(),
            checker_stats: Vec::new(),
        }
    }

    pub fn on_tick(&mut self) {
        // Update rate calculation based on elapsed time - simple moving average could be better but this is fine
        let elapsed = self.start_time.elapsed().as_secs_f64();
        if elapsed > 1.0 {
            // Wait a bit for stability
            let count_diff = if self.scanned_count > 0 {
                self.scanned_count
            } else {
                0
            };
            self.current_rate = count_diff as f64 / elapsed;
        }
    }
}

pub fn ui(f: &mut Frame, app: &TuiApp) {
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
    let percent = if app.total_domains > 0 {
        (app.scanned_count as f64 / app.total_domains as f64).min(1.0)
    } else {
        0.0
    };
    let label = format!("{:.2}%", percent * 100.0);
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
            format!("{}", app.scanned_count),
            Style::default().fg(Color::Yellow),
        ),
        Span::raw(format!(" / {}", app.total_domains)),
        Span::raw(" | Rate: "),
        Span::styled(
            format!("{:.1} d/s", app.current_rate),
            Style::default().fg(Color::Magenta),
        ),
        Span::raw(" | Found: "),
        Span::styled(
            format!("{}", app.found_domains.len()),
            Style::default().fg(Color::Green),
        ),
    ])];
    let stats = Paragraph::new(stats_text)
        .block(Block::default().title("Statistics").borders(Borders::ALL));
    f.render_widget(stats, chunks[2]);

    // Found Domains List
    let items: Vec<ListItem> = app
        .found_domains
        .iter()
        .rev() // Show newest first
        .take(20) // Limit display
        .map(|d| {
            ListItem::new(Line::from(Span::styled(
                d,
                Style::default().fg(Color::Green),
            )))
        })
        .collect();

    let list = List::new(items).block(
        Block::default()
            .title("Found Domains (Live)")
            .borders(Borders::ALL),
    );
    f.render_widget(list, chunks[3]);

    // Status Bar / Checkers
    let status_str = if app.checker_stats.is_empty() {
        app.status_message.clone()
    } else {
        format!("{} | {}", app.status_message, app.checker_stats.join(" | "))
    };

    let status_bar = Paragraph::new(status_str)
        .style(Style::default().fg(Color::Gray))
        .block(Block::default().borders(Borders::TOP));
    f.render_widget(status_bar, chunks[4]);
}

/// Setup terminal, run the application loop, and restore terminal
pub async fn run(app: Arc<Mutex<TuiApp>>, scan_generated: Arc<AtomicI64>) -> io::Result<()> {
    // Setup
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    // Run loop
    let tick_rate = Duration::from_millis(100);

    let res = run_loop(&mut terminal, app, scan_generated, tick_rate).await;

    // Cleanup
    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )?;
    terminal.show_cursor()?;

    if let Err(err) = res {
        println!("{:?}", err);
    }

    Ok(())
}

async fn run_loop(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    app: Arc<Mutex<TuiApp>>,
    scan_generated: Arc<AtomicI64>,
    tick_rate: Duration,
) -> io::Result<()> {
    let mut last_tick = Instant::now();
    loop {
        {
            let state = app.lock().await;
            terminal.draw(|f| ui(f, &state))?;
        }

        let timeout = tick_rate
            .checked_sub(last_tick.elapsed())
            .unwrap_or_else(|| Duration::from_secs(0));

        if crossterm::event::poll(timeout)? {
            if let Event::Key(key) = event::read()? {
                if key.code == KeyCode::Char('q') || key.code == KeyCode::Esc {
                    return Ok(());
                }
            }
        }

        if last_tick.elapsed() >= tick_rate {
            let mut state = app.lock().await;
            state.scanned_count = scan_generated.load(Ordering::Relaxed) as u64;
            state.on_tick();
            last_tick = Instant::now();
        }
    }
}
