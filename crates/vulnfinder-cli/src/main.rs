use anyhow::{Context, Result};
use clap::{Args, Parser, Subcommand};
use crossterm::event::{self, Event, KeyCode};
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use crossterm::{execute, terminal};
use ratatui::layout::{Constraint, Direction, Layout};
use ratatui::style::{Color, Style};
use ratatui::widgets::{Block, Borders, Gauge, List, ListItem, Paragraph};
use ratatui::Terminal;
use serde::Serialize;
use std::collections::VecDeque;
use std::io::{self, IsTerminal};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::mpsc;
use vulnfinder_core::cve_db::CveDatabase;
use vulnfinder_core::output::{build_report, render_table, ScanReport};
use vulnfinder_core::ports::load_ports;
use vulnfinder_core::scanner::{scan_targets, ScanConfig, ScanEvent, ScanStats};
use vulnfinder_core::target::parse_targets;

#[derive(Parser)]
#[command(
    name = "vulnfinder",
    version,
    about = "Authorized defensive vulnerability awareness scanner"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Scan(ScanArgs),
}

#[derive(Args, Clone)]
struct ScanArgs {
    target: String,
    #[arg(long)]
    ports: Option<String>,
    #[arg(long)]
    ports_file: Option<PathBuf>,
    #[arg(long, default_value_t = 800)]
    timeout_ms: u64,
    #[arg(long, default_value_t = 200)]
    concurrency: usize,
    #[arg(long)]
    json: bool,
    #[arg(long)]
    evidence: bool,
    #[arg(long, default_value = "./data/cve_db.json")]
    cve_db: PathBuf,
    #[arg(long)]
    no_ui: bool,
    #[arg(long)]
    i_own_or_am_authorized: bool,
}

#[derive(Default, Clone)]
struct UiState {
    stats: ScanStats,
    current_target: String,
    current_port: u16,
    logs: VecDeque<String>,
}

#[derive(Serialize)]
struct JsonOutput {
    report: ScanReport,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Scan(args) => run_scan(args).await,
    }
}

async fn run_scan(args: ScanArgs) -> Result<()> {
    if !args.i_own_or_am_authorized {
        eprintln!(
            "Refusing to scan. You must explicitly confirm authorization with --i-own-or-am-authorized"
        );
        std::process::exit(2);
    }

    let targets = parse_targets(&args.target).context("unable to parse target")?;
    let ports = load_ports(args.ports.as_deref(), args.ports_file.as_deref())
        .context("unable to load port list")?;
    let cve_db = CveDatabase::load(&args.cve_db)
        .with_context(|| format!("failed to load CVE database from {}", args.cve_db.display()))?;

    let config = ScanConfig {
        timeout_ms: args.timeout_ms,
        concurrency: args.concurrency,
    };

    let interactive = io::stdout().is_terminal() && !args.no_ui && !args.json;
    let (scan_events_tx, ui_task) = if args.json {
        (None, None)
    } else {
        let (tx, rx) = mpsc::unbounded_channel();
        let task = if interactive {
            let ui_state = Arc::new(Mutex::new(UiState::default()));
            tokio::spawn(run_tui(rx, ui_state))
        } else {
            tokio::spawn(async move {
                run_plain_progress(rx).await;
                Ok(())
            })
        };
        (Some(tx), Some(task))
    };

    let scan_results = scan_targets(targets, ports, config, scan_events_tx).await;

    if let Some(task) = ui_task {
        let _ = task.await;
    }

    let report = build_report(&scan_results, |product, version| {
        cve_db.match_service(product, version)
    });
    let cve_count: usize = report
        .hosts
        .iter()
        .flat_map(|h| h.ports.iter())
        .map(|p| p.cves.len())
        .sum();

    if args.json {
        let json = serde_json::to_string_pretty(&JsonOutput { report })?;
        println!("{json}");
    } else {
        println!("{}", render_table(&report, args.evidence));
        println!("Matched CVEs: {cve_count}");
    }

    Ok(())
}

async fn run_plain_progress(mut rx: mpsc::UnboundedReceiver<ScanEvent>) {
    while let Some(event) = rx.recv().await {
        println!(
            "progress {}/{} - {}:{} ({})",
            event.stats.scanned,
            event.stats.total_ports,
            event.current_target,
            event.current_port,
            event.message
        );
    }
}

async fn run_tui(
    mut rx: mpsc::UnboundedReceiver<ScanEvent>,
    state: Arc<Mutex<UiState>>,
) -> Result<()> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = ratatui::backend::CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    loop {
        while let Ok(event) = rx.try_recv() {
            let mut st = state.lock().expect("state lock");
            st.stats = event.stats;
            st.current_target = event.current_target;
            st.current_port = event.current_port;
            st.logs.push_front(event.message);
            while st.logs.len() > 10 {
                st.logs.pop_back();
            }
        }

        let snapshot = state.lock().expect("state lock").clone();
        terminal.draw(|f| {
            let chunks = Layout::default()
                .direction(Direction::Vertical)
                .constraints([
                    Constraint::Length(3),
                    Constraint::Length(3),
                    Constraint::Length(4),
                    Constraint::Min(8),
                ])
                .split(f.area());

            let ratio = if snapshot.stats.total_ports == 0 {
                0.0
            } else {
                snapshot.stats.scanned as f64 / snapshot.stats.total_ports as f64
            };

            let gauge = Gauge::default()
                .block(
                    Block::default()
                        .title("Scan Progress")
                        .borders(Borders::ALL),
                )
                .gauge_style(Style::default().fg(Color::Green))
                .ratio(ratio)
                .label(format!(
                    "targets {} | ports {}/{}",
                    snapshot.stats.total_targets,
                    snapshot.stats.scanned,
                    snapshot.stats.total_ports
                ));
            f.render_widget(gauge, chunks[0]);

            let current = Paragraph::new(format!(
                "Current: {}:{}",
                snapshot.current_target, snapshot.current_port
            ))
            .block(Block::default().title("Current Job").borders(Borders::ALL));
            f.render_widget(current, chunks[1]);

            let counters = Paragraph::new(format!(
                "Open ports: {} | Services: {} | CVEs: {}",
                snapshot.stats.open_ports,
                snapshot.stats.services_identified,
                snapshot.stats.cves_matched
            ))
            .block(Block::default().title("Counters").borders(Borders::ALL));
            f.render_widget(counters, chunks[2]);

            let items: Vec<ListItem> = snapshot
                .logs
                .iter()
                .map(|line| ListItem::new(line.as_str()))
                .collect();
            let list =
                List::new(items).block(Block::default().title("Activity").borders(Borders::ALL));
            f.render_widget(list, chunks[3]);
        })?;

        if rx.is_closed() {
            break;
        }

        if event::poll(Duration::from_millis(100))? {
            if let Event::Key(k) = event::read()? {
                if k.code == KeyCode::Char('q') {
                    break;
                }
            }
        }

        tokio::time::sleep(Duration::from_millis(120)).await;
    }

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    Ok(())
}
