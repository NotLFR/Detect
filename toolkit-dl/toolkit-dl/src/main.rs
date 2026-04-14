use std::{
    collections::HashSet,
    fs,
    io::{self, Read, Write},
    path::{Path, PathBuf},
    time::Duration,
};

use anyhow::{Context, Result};
use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyModifiers},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use indicatif::{ProgressBar, ProgressStyle};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Alignment, Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, BorderType, Borders, List, ListItem, ListState, Paragraph, Wrap},
    Frame, Terminal,
};
use reqwest::blocking::Client;
use zip::ZipArchive;

// ─── Tool catalogue ──────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
struct ToolCategory {
    name: &'static str,
    icon: &'static str,
    tools: Vec<Tool>,
}

#[derive(Debug, Clone)]
struct Tool {
    name: &'static str,
    description: &'static str,
    url: &'static str,
    filename: &'static str,
    /// Auto-extract if this is a .zip file after download
    auto_extract: bool,
}

fn catalogue() -> Vec<ToolCategory> {
    vec![
        // ── detect.ac tools ────────────────────────────────────────────────
        ToolCategory {
            name: "detect.ac Tools",
            icon: "🛡",
            tools: vec![
                Tool {
                    name: "USN Journal Parser",
                    description: "Analyses the USN Journal with in-depth filtering",
                    url: "https://github.com/detect-ac/USNJournal/releases/download/forensics/USN.Journal.exe",
                    filename: "USN.Journal.exe",
                    auto_extract: false,
                },
                Tool {
                    name: "Deleted BAM Keys Parser",
                    description: "Finds deleted BAM registry keys + digital signature & entropy",
                    url: "https://github.com/detect-ac/Deleted-BAM-Scanner/releases/download/forensics/Deleted.BAM.Keys.exe",
                    filename: "Deleted.BAM.Keys.exe",
                    auto_extract: false,
                },
                Tool {
                    name: "Windows Sqlite Database Parser",
                    description: "Parse Win11 DBs for paths, executables, search & notepad history",
                    url: "https://github.com/detect-ac/Windows-Sqlite-DB-Parser/releases/download/forensics/Windows.Sqlite.Database.Parser.exe",
                    filename: "Windows.Sqlite.Database.Parser.exe",
                    auto_extract: false,
                },
                Tool {
                    name: "BAM Parser",
                    description: "Parse BAM data for timestamps, USN mods & YARA-flagged files",
                    url: "https://github.com/spokwn/BAM-parser/releases/download/v1.2.9/BAMParser.exe",
                    filename: "BAMParser.exe",
                    auto_extract: false,
                },
                Tool {
                    name: "Prefetch Parser",
                    description: "Analyse Prefetch for unsigned/YARA-flagged files & execution timestamps",
                    url: "https://github.com/spokwn/prefetch-parser/releases/download/v1.5.5/PrefetchParser.exe",
                    filename: "PrefetchParser.exe",
                    auto_extract: false,
                },
                Tool {
                    name: "PcaSvc Executed",
                    description: "Track PCA Service executions, flag unsigned & YARA-matched files",
                    url: "https://github.com/spokwn/pcasvc-executed/releases/download/v0.8.6/PcaSvcExecuted.exe",
                    filename: "PcaSvcExecuted.exe",
                    auto_extract: false,
                },
                Tool {
                    name: "Process Parser",
                    description: "Analyse AppInfo & Diagtrack for YARA-flagged files in one pass",
                    url: "https://github.com/spokwn/process-parser/releases/download/v0.5.5/ProcessParser.exe",
                    filename: "ProcessParser.exe",
                    auto_extract: false,
                },
            ],
        },
        // ── Classic forensics ──────────────────────────────────────────────
        ToolCategory {
            name: "Forensics & Analysis",
            icon: "🔍",
            tools: vec![
                Tool {
                    name: "WinPrefetchView",
                    description: "View & analyse Windows Prefetch files (.pf)",
                    url: "https://www.nirsoft.net/utils/winprefetchview.zip",
                    filename: "winprefetchview.zip",
                    auto_extract: true,
                },
                Tool {
                    name: "System Informer (Process Hacker 3)",
                    description: "Advanced process, memory & network monitor",
                    url: "https://github.com/winsiderss/systeminformer/releases/download/3.0.7895/systeminformer-3.0.7895-setup.exe",
                    filename: "systeminformer-setup.exe",
                    auto_extract: false,
                },
                Tool {
                    name: "Autoruns",
                    description: "Comprehensive autostart entry viewer by Sysinternals",
                    url: "https://download.sysinternals.com/files/Autoruns.zip",
                    filename: "Autoruns.zip",
                    auto_extract: true,
                },
                Tool {
                    name: "Process Monitor",
                    description: "Real-time file/registry/process/network monitor",
                    url: "https://download.sysinternals.com/files/ProcessMonitor.zip",
                    filename: "ProcessMonitor.zip",
                    auto_extract: true,
                },
                Tool {
                    name: "Volatility3",
                    description: "Memory forensics framework (standalone Win EXE)",
                    url: "https://github.com/volatilityfoundation/volatility3/releases/latest/download/volatility3.exe",
                    filename: "volatility3.exe",
                    auto_extract: false,
                },
            ],
        },
        // ── Network ────────────────────────────────────────────────────────
        ToolCategory {
            name: "Network Tools",
            icon: "🌐",
            tools: vec![
                Tool {
                    name: "Wireshark",
                    description: "Industry-standard packet analyser",
                    url: "https://1.na.dl.wireshark.org/win64/Wireshark-latest-x64.exe",
                    filename: "Wireshark-latest-x64.exe",
                    auto_extract: false,
                },
                Tool {
                    name: "TCPView",
                    description: "Live TCP/UDP endpoint viewer by Sysinternals",
                    url: "https://download.sysinternals.com/files/TCPView.zip",
                    filename: "TCPView.zip",
                    auto_extract: true,
                },
                Tool {
                    name: "Nmap",
                    description: "Network scanner and port mapper",
                    url: "https://nmap.org/dist/nmap-7.94-setup.exe",
                    filename: "nmap-setup.exe",
                    auto_extract: false,
                },
                Tool {
                    name: "CurrPorts",
                    description: "Display currently opened TCP/IP & UDP ports",
                    url: "https://www.nirsoft.net/utils/cports.zip",
                    filename: "cports.zip",
                    auto_extract: true,
                },
            ],
        },
        // ── Disk & File ────────────────────────────────────────────────────
        ToolCategory {
            name: "Disk & File",
            icon: "💾",
            tools: vec![
                Tool {
                    name: "WinDirStat",
                    description: "Disk usage statistics & cleanup helper",
                    url: "https://github.com/windirstat/windirstat/releases/latest/download/windirstat1_1_2_setup.exe",
                    filename: "windirstat-setup.exe",
                    auto_extract: false,
                },
                Tool {
                    name: "Everything",
                    description: "Instant file search by name across all drives",
                    url: "https://www.voidtools.com/Everything-1.4.1.1026.x64-Setup.exe",
                    filename: "Everything-setup.exe",
                    auto_extract: false,
                },
                Tool {
                    name: "CrystalDiskInfo",
                    description: "HDD/SSD S.M.A.R.T. health monitoring",
                    url: "https://crystalmark.info/redirect.php?product=CrystalDiskInfoInstaller",
                    filename: "CrystalDiskInfo-setup.exe",
                    auto_extract: false,
                },
                Tool {
                    name: "FTK Imager",
                    description: "Forensic disk imaging (Lite, no install required)",
                    url: "https://ad-zip.s3.amazonaws.com/ftkimager.3.1.1.exe",
                    filename: "FTKImager.exe",
                    auto_extract: false,
                },
            ],
        },
        // ── Registry & System ──────────────────────────────────────────────
        ToolCategory {
            name: "Registry & System",
            icon: "🔧",
            tools: vec![
                Tool {
                    name: "RegRipper",
                    description: "Extract/parse Registry hive data for forensics",
                    url: "https://github.com/keydet89/RegRipper3.0/archive/refs/heads/master.zip",
                    filename: "RegRipper3.0.zip",
                    auto_extract: true,
                },
                Tool {
                    name: "Registry Explorer",
                    description: "Advanced Registry hive viewer by Eric Zimmermann",
                    url: "https://f001.backblazeb2.com/file/EricZimmermanTools/net6/RegistryExplorer.zip",
                    filename: "RegistryExplorer.zip",
                    auto_extract: true,
                },
                Tool {
                    name: "Sysinternals Suite",
                    description: "Complete Sysinternals toolset (all tools in one ZIP)",
                    url: "https://download.sysinternals.com/files/SysinternalsSuite.zip",
                    filename: "SysinternalsSuite.zip",
                    auto_extract: true,
                },
            ],
        },
        // ── Password & Credentials ─────────────────────────────────────────
        ToolCategory {
            name: "Password & Credentials",
            icon: "🔑",
            tools: vec![
                Tool {
                    name: "Mimikatz",
                    description: "Credential extraction utility (research/CTF use)",
                    url: "https://github.com/gentilkiwi/mimikatz/releases/latest/download/mimikatz_trunk.zip",
                    filename: "mimikatz.zip",
                    auto_extract: true,
                },
                Tool {
                    name: "NirSoft PasswordFox",
                    description: "Recover Firefox stored passwords",
                    url: "https://www.nirsoft.net/utils/passwordfox.zip",
                    filename: "passwordfox.zip",
                    auto_extract: true,
                },
                Tool {
                    name: "NirSoft WebBrowserPassView",
                    description: "Recover passwords from all major browsers",
                    url: "https://www.nirsoft.net/utils/webbrowserpassview.zip",
                    filename: "WebBrowserPassView.zip",
                    auto_extract: true,
                },
            ],
        },
    ]
}

// ─── App state ────────────────────────────────────────────────────────────────

#[derive(PartialEq)]
enum Screen {
    CategoryList,
    ToolList,
    Confirm,
    Downloading,
    Done,
}

struct App {
    screen: Screen,
    categories: Vec<ToolCategory>,
    cat_state: ListState,
    tool_state: ListState,
    selected_tools: HashSet<String>,
    output_dir: PathBuf,
    log: Vec<String>,
}

impl App {
    fn new() -> Self {
        let mut cat_state = ListState::default();
        cat_state.select(Some(0));
        let mut tool_state = ListState::default();
        tool_state.select(Some(0));

        let output_dir = dirs::download_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("toolkit-dl");

        App {
            screen: Screen::CategoryList,
            categories: catalogue(),
            cat_state,
            tool_state,
            selected_tools: HashSet::new(),
            output_dir,
            log: Vec::new(),
        }
    }

    fn current_cat_idx(&self) -> usize { self.cat_state.selected().unwrap_or(0) }
    fn current_tool_idx(&self) -> usize { self.tool_state.selected().unwrap_or(0) }

    fn tool_key(cat: usize, tool: usize) -> String { format!("{cat}:{tool}") }

    fn toggle_tool(&mut self) {
        let key = Self::tool_key(self.current_cat_idx(), self.current_tool_idx());
        if self.selected_tools.contains(&key) {
            self.selected_tools.remove(&key);
        } else {
            self.selected_tools.insert(key);
        }
    }

    fn select_all_in_category(&mut self) {
        let cat = self.current_cat_idx();
        let keys: Vec<String> = (0..self.categories[cat].tools.len())
            .map(|t| Self::tool_key(cat, t))
            .collect();
        let all_on = keys.iter().all(|k| self.selected_tools.contains(k));
        for k in keys {
            if all_on { self.selected_tools.remove(&k); } else { self.selected_tools.insert(k); }
        }
    }

    fn selected_tool_list(&self) -> Vec<(usize, usize)> {
        let mut out: Vec<(usize, usize)> = self
            .selected_tools
            .iter()
            .filter_map(|k| {
                let mut p = k.splitn(2, ':');
                Some((p.next()?.parse().ok()?, p.next()?.parse().ok()?))
            })
            .collect();
        out.sort();
        out
    }
}

// ─── UI ───────────────────────────────────────────────────────────────────────

fn render(f: &mut Frame, app: &App) {
    let area = f.area();
    let outer = Block::default()
        .title(Span::styled(
            " ⬇  toolkit-dl — Windows Tool Downloader ",
            Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD),
        ))
        .title_alignment(Alignment::Center)
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(Color::DarkGray));
    let inner = outer.inner(area);
    f.render_widget(outer, area);

    match app.screen {
        Screen::CategoryList => render_category(f, app, inner),
        Screen::ToolList    => render_tools(f, app, inner),
        Screen::Confirm     => render_confirm(f, app, inner),
        _                   => render_log(f, app, inner),
    }
}

fn render_category(f: &mut Frame, app: &App, area: ratatui::layout::Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(3), Constraint::Length(3)])
        .split(area);

    let items: Vec<ListItem> = app.categories.iter().enumerate().map(|(i, cat)| {
        let sel = (0..cat.tools.len()).filter(|&t| app.selected_tools.contains(&App::tool_key(i, t))).count();
        let badge = if sel > 0 { format!(" [{}✓]", sel) } else { String::new() };
        ListItem::new(Line::from(vec![
            Span::raw(format!("  {} ", cat.icon)),
            Span::styled(cat.name, Style::default().add_modifier(Modifier::BOLD)),
            Span::styled(badge, Style::default().fg(Color::Green).add_modifier(Modifier::BOLD)),
            Span::styled(format!("  ({} tools)", cat.tools.len()), Style::default().fg(Color::DarkGray)),
        ]))
    }).collect();

    let mut state = app.cat_state.clone();
    f.render_stateful_widget(
        List::new(items)
            .block(Block::default().title(" Categories ").borders(Borders::ALL).border_type(BorderType::Rounded).border_style(Style::default().fg(Color::Blue)))
            .highlight_style(Style::default().bg(Color::Blue).fg(Color::White).add_modifier(Modifier::BOLD))
            .highlight_symbol("▶ "),
        chunks[0],
        &mut state,
    );
    render_help(f, chunks[1], &[("↑↓","navigate"),("Enter","open"),("D","download"),("Q","quit")]);
}

fn render_tools(f: &mut Frame, app: &App, area: ratatui::layout::Rect) {
    let cat = &app.categories[app.current_cat_idx()];
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(3), Constraint::Length(3)])
        .split(area);

    let items: Vec<ListItem> = cat.tools.iter().enumerate().map(|(t, tool)| {
        let checked = if app.selected_tools.contains(&App::tool_key(app.current_cat_idx(), t)) {
            Span::styled("  [✓] ", Style::default().fg(Color::Green))
        } else {
            Span::styled("  [ ] ", Style::default().fg(Color::DarkGray))
        };
        let ext_tag = if tool.auto_extract {
            Span::styled(" [auto-extract]", Style::default().fg(Color::Rgb(120, 120, 220)))
        } else { Span::raw("") };

        ListItem::new(vec![
            Line::from(vec![checked, Span::styled(tool.name, Style::default().add_modifier(Modifier::BOLD)), ext_tag]),
            Line::from(Span::styled(format!("       {}", tool.description), Style::default().fg(Color::DarkGray))),
        ])
    }).collect();

    let mut state = app.tool_state.clone();
    f.render_stateful_widget(
        List::new(items)
            .block(Block::default().title(format!(" {} {} ", cat.icon, cat.name)).borders(Borders::ALL).border_type(BorderType::Rounded).border_style(Style::default().fg(Color::Magenta)))
            .highlight_style(Style::default().bg(Color::Rgb(40,20,60)).fg(Color::White).add_modifier(Modifier::BOLD))
            .highlight_symbol("▶ "),
        chunks[0],
        &mut state,
    );
    render_help(f, chunks[1], &[("↑↓","navigate"),("Space","toggle"),("A","toggle all"),("Esc","back"),("D","download")]);
}

fn render_confirm(f: &mut Frame, app: &App, area: ratatui::layout::Rect) {
    let selected = app.selected_tool_list();
    let mut lines = vec![
        Line::from(Span::styled("The following tools will be downloaded:", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD))),
        Line::from(""),
    ];
    for (c, t) in &selected {
        let tool = &app.categories[*c].tools[*t];
        let note = if tool.auto_extract { "  → will extract" } else { "" };
        lines.push(Line::from(vec![
            Span::styled("  ✓ ", Style::default().fg(Color::Green)),
            Span::styled(tool.name, Style::default().add_modifier(Modifier::BOLD)),
            Span::styled(note, Style::default().fg(Color::Rgb(120,120,220))),
        ]));
    }
    lines.push(Line::from(""));
    lines.push(Line::from(vec![
        Span::styled("  Output: ", Style::default().fg(Color::DarkGray)),
        Span::styled(app.output_dir.display().to_string(), Style::default().fg(Color::Yellow)),
    ]));
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled("  Enter = confirm   Esc = back", Style::default().fg(Color::DarkGray))));

    f.render_widget(
        Paragraph::new(lines)
            .block(Block::default().title(" Confirm Downloads ").borders(Borders::ALL).border_type(BorderType::Rounded).border_style(Style::default().fg(Color::Yellow)))
            .wrap(Wrap { trim: false }),
        area,
    );
}

fn render_log(f: &mut Frame, app: &App, area: ratatui::layout::Rect) {
    let title = if app.screen == Screen::Done { " ✓ Complete " } else { " Downloading… " };
    let border_color = if app.screen == Screen::Done { Color::Green } else { Color::Yellow };

    let lines: Vec<Line> = app.log.iter().map(|l| {
        let color = if l.contains('✓') { Color::Green }
            else if l.contains('✗') || l.contains("Error") { Color::Red }
            else if l.contains('→') || l.contains("📦") { Color::Cyan }
            else { Color::White };
        Line::from(Span::styled(l.clone(), Style::default().fg(color)))
    }).collect();

    f.render_widget(
        Paragraph::new(lines)
            .block(Block::default().title(title).borders(Borders::ALL).border_type(BorderType::Rounded).border_style(Style::default().fg(border_color)))
            .wrap(Wrap { trim: false }),
        area,
    );
}

fn render_help(f: &mut Frame, area: ratatui::layout::Rect, keys: &[(&str, &str)]) {
    let mut spans = vec![Span::raw("  ")];
    for (key, desc) in keys {
        spans.push(Span::styled(format!(" {key} "), Style::default().fg(Color::Black).bg(Color::DarkGray).add_modifier(Modifier::BOLD)));
        spans.push(Span::styled(format!(" {desc}  "), Style::default().fg(Color::DarkGray)));
    }
    f.render_widget(
        Paragraph::new(Line::from(spans))
            .block(Block::default().borders(Borders::ALL).border_type(BorderType::Rounded).border_style(Style::default().fg(Color::DarkGray))),
        area,
    );
}

// ─── Download + extract ───────────────────────────────────────────────────────

fn download_file(client: &Client, url: &str, dest: &Path) -> Result<u64> {
    let mut resp = client
        .get(url)
        .send()
        .with_context(|| format!("GET {url}"))?
        .error_for_status()
        .with_context(|| format!("HTTP error for {url}"))?;

    let mut buf = Vec::new();
    let mut tmp = [0u8; 65536];
    loop {
        match resp.read(&mut tmp) {
            Ok(0) => break,
            Ok(n) => buf.extend_from_slice(&tmp[..n]),
            Err(e) => return Err(anyhow::anyhow!("Read error: {e}")),
        }
    }
    fs::write(dest, &buf).with_context(|| format!("Writing {}", dest.display()))?;
    Ok(buf.len() as u64)
}

/// Extracts a ZIP into `<output_dir>/<zip_stem>/`, returns file count.
fn extract_zip(zip_path: &Path, output_dir: &Path) -> Result<usize> {
    let stem = zip_path.file_stem().unwrap_or_default().to_string_lossy().to_string();
    let extract_dir = output_dir.join(&stem);
    fs::create_dir_all(&extract_dir)?;

    let data = fs::read(zip_path)?;
    let mut archive = ZipArchive::new(std::io::Cursor::new(data)).context("Opening ZIP")?;
    let count = archive.len();

    for i in 0..count {
        let mut file = archive.by_index(i)?;
        let outpath = extract_dir.join(file.mangled_name());
        if file.name().ends_with('/') {
            fs::create_dir_all(&outpath)?;
        } else {
            if let Some(p) = outpath.parent() { fs::create_dir_all(p)?; }
            let mut out = fs::File::create(&outpath)?;
            io::copy(&mut file, &mut out)?;
        }
    }
    Ok(count)
}

fn run_downloads_plaintext(app: &App) -> Result<()> {
    fs::create_dir_all(&app.output_dir)?;

    let client = Client::builder()
        .timeout(Duration::from_secs(300))
        .user_agent("toolkit-dl/0.1")
        .redirect(reqwest::redirect::Policy::limited(10))
        .build()?;

    let selected = app.selected_tool_list();
    println!("\n  toolkit-dl — {} download(s)\n", selected.len());
    println!("  Output → {}\n", app.output_dir.display());

    for (i, (c, t)) in selected.iter().enumerate() {
        let tool = &app.categories[*c].tools[*t];
        let dest = app.output_dir.join(tool.filename);

        print!("  [{}/{}] {} … ", i + 1, selected.len(), tool.name);
        io::stdout().flush().ok();

        let pb = ProgressBar::new_spinner();
        pb.set_style(
            ProgressStyle::with_template("{spinner:.cyan} {bytes} @ {bytes_per_sec}")
                .unwrap()
                .tick_strings(&["⠋","⠙","⠹","⠸","⠼","⠴","⠦","⠧","⠇","⠏"]),
        );
        pb.enable_steady_tick(Duration::from_millis(80));

        match download_file(&client, tool.url, &dest) {
            Ok(bytes) => {
                pb.finish_and_clear();
                println!("✓  {:.1} MB", bytes as f64 / 1_048_576.0);

                if tool.auto_extract && dest.extension().map(|e| e.eq_ignore_ascii_case("zip")).unwrap_or(false) {
                    print!("         📦 Extracting {} … ", tool.filename);
                    io::stdout().flush().ok();
                    match extract_zip(&dest, &app.output_dir) {
                        Ok(n)  => println!("✓  {n} files"),
                        Err(e) => println!("✗  {e}"),
                    }
                }
            }
            Err(e) => {
                pb.finish_and_clear();
                println!("✗");
                eprintln!("    Error: {e}");
            }
        }
    }

    println!("\n  ✓ All done — {}", app.output_dir.display());
    println!("  Press Enter to exit.");
    let mut s = String::new();
    io::stdin().read_line(&mut s).ok();
    Ok(())
}

// ─── Main loop ────────────────────────────────────────────────────────────────

fn main() -> Result<()> {
    #[cfg(not(target_os = "windows"))]
    eprintln!("Warning: This tool downloads Windows executables.\n");

    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let mut terminal = Terminal::new(CrosstermBackend::new(stdout))?;
    let mut app = App::new();

    loop {
        terminal.draw(|f| render(f, &app))?;

        if !event::poll(Duration::from_millis(100))? { continue; }
        let Event::Key(key) = event::read()? else { continue; };

        if key.code == KeyCode::Char('c') && key.modifiers.contains(KeyModifiers::CONTROL) { break; }
        if matches!(key.code, KeyCode::Char('q') | KeyCode::Char('Q'))
            && matches!(app.screen, Screen::Done | Screen::CategoryList) { break; }

        match app.screen {
            Screen::CategoryList => match key.code {
                KeyCode::Up    => { let i = app.cat_state.selected().unwrap_or(0); app.cat_state.select(Some(i.saturating_sub(1))); }
                KeyCode::Down  => { let i = app.cat_state.selected().unwrap_or(0); app.cat_state.select(Some((i+1).min(app.categories.len()-1))); }
                KeyCode::Enter => { app.tool_state.select(Some(0)); app.screen = Screen::ToolList; }
                KeyCode::Char('d') | KeyCode::Char('D') => { if !app.selected_tools.is_empty() { app.screen = Screen::Confirm; } }
                _ => {}
            },
            Screen::ToolList => match key.code {
                KeyCode::Up    => { let i = app.tool_state.selected().unwrap_or(0); app.tool_state.select(Some(i.saturating_sub(1))); }
                KeyCode::Down  => { let i = app.tool_state.selected().unwrap_or(0); let max = app.categories[app.current_cat_idx()].tools.len()-1; app.tool_state.select(Some((i+1).min(max))); }
                KeyCode::Char(' ')             => app.toggle_tool(),
                KeyCode::Char('a') | KeyCode::Char('A') => app.select_all_in_category(),
                KeyCode::Esc | KeyCode::Char('b') | KeyCode::Char('B') => app.screen = Screen::CategoryList,
                KeyCode::Char('d') | KeyCode::Char('D') => { if !app.selected_tools.is_empty() { app.screen = Screen::Confirm; } }
                _ => {}
            },
            Screen::Confirm => match key.code {
                KeyCode::Enter => {
                    app.screen = Screen::Downloading;
                    terminal.draw(|f| render(f, &app))?;
                    disable_raw_mode()?;
                    execute!(terminal.backend_mut(), LeaveAlternateScreen, DisableMouseCapture)?;
                    terminal.show_cursor()?;
                    run_downloads_plaintext(&app)?;
                    return Ok(());
                }
                KeyCode::Esc => app.screen = Screen::ToolList,
                _ => {}
            },
            _ => {}
        }
    }

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen, DisableMouseCapture)?;
    terminal.show_cursor()?;
    Ok(())
}
