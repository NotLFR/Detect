use std::{
    collections::HashSet,
    fs,
    io::{self, Read, Write},
    path::{Path, PathBuf},
    time::{Duration, Instant},
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

// ─── Animation state ──────────────────────────────────────────────────────────

struct Anim {
    start: Instant,
    /// When Some, a tool was just toggled: (cat, tool, selected, until)
    flash: Option<(usize, usize, bool, Instant)>,
    /// Last navigation direction for cursor trail: -1 up, 1 down, 0 none
    nav_dir: i8,
    nav_at: Instant,
}

impl Anim {
    fn new() -> Self {
        Anim {
            start: Instant::now(),
            flash: None,
            nav_dir: 0,
            nav_at: Instant::now(),
        }
    }

    fn t(&self) -> f64 {
        self.start.elapsed().as_secs_f64()
    }

    /// 0.0..=1.0 smooth sine pulse, period = `period_s` seconds
    fn pulse(&self, period_s: f64) -> f64 {
        (self.t() * std::f64::consts::TAU / period_s).sin() * 0.5 + 0.5
    }

    /// Breathing border color for the active panel
    fn border_color(&self) -> Color {
        let p = self.pulse(2.5);
        let r = (0.0 + p * 80.0) as u8;
        let g = (100.0 + p * 100.0) as u8;
        let b = (200.0 + p * 55.0) as u8;
        Color::Rgb(r, g, b)
    }

    /// Animated cursor symbol — cycles through a "glow" sequence
    fn cursor_symbol(&self) -> &'static str {
        let frames = ["▶ ", "► ", "▷ ", "► "];
        let idx = ((self.t() * 4.0) as usize) % frames.len();
        frames[idx]
    }

    /// Nav trail color — briefly highlights the row we just came from
    fn nav_trail_age(&self) -> f64 {
        self.nav_at.elapsed().as_secs_f64()
    }

    fn set_flash(&mut self, cat: usize, tool: usize, selected: bool) {
        self.flash = Some((cat, tool, selected, Instant::now() + Duration::from_millis(300)));
    }

    fn flash_active(&self, cat: usize, tool: usize) -> Option<bool> {
        if let Some((fc, ft, sel, until)) = self.flash {
            if fc == cat && ft == tool && Instant::now() < until {
                return Some(sel);
            }
        }
        None
    }

    fn clear_expired_flash(&mut self) {
        if let Some((_, _, _, until)) = self.flash {
            if Instant::now() >= until {
                self.flash = None;
            }
        }
    }
}

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
    auto_extract: bool,
}

fn catalogue() -> Vec<ToolCategory> {
    vec![
        ToolCategory {
            name: "detect.ac Tools",
            icon: "🔍",
            tools: vec![
                Tool {
                    name: "USN Journal Parser",
                    description: "Analyses the USN Journal, prints everything in the Journal and allows in depth filtering of the Journal, very good for in depth analysis.",
                    url: "https://github.com/detect-ac/USNJournal/releases/download/forensics/USN.Journal.exe",
                    filename: "USN.Journal.exe",
                    auto_extract: false,
                },
                Tool {
                    name: "Deleted BAM Keys Parser",
                    description: "Analyses the registry, specifically for BAM (Background Activity Monitor) Key Deletions, and outputs found deleted, keys + if the file exists, its digital signature, and its entropy.",
                    url: "https://github.com/detect-ac/Deleted-BAM-Scanner/releases/download/forensics/Deleted.BAM.Keys.exe",
                    filename: "Deleted.BAM.Keys.exe",
                    auto_extract: false,
                },
                Tool {
                    name: "Windows Sqlite Database Parser",
                    description: "Analyze Windows database files for recent paths, executables, search history and notepad history. This only works on Windows 11 Machines.",
                    url: "https://github.com/detect-ac/Windows-Sqlite-DB-Parser/releases/download/forensics/Windows.Sqlite.Database.Parser.exe",
                    filename: "Windows.Sqlite.Database.Parser.exe",
                    auto_extract: false,
                },
                Tool {
                    name: "BAM Parser",
                    description: "Parse and analyze BAM (Background Activity Moderator) data for timestamps, usn modifications and unsigned/flagged files with yara rules.",
                    url: "https://github.com/spokwn/BAM-parser/releases/download/v1.2.9/BAMParser.exe",
                    filename: "BAMParser.exe",
                    auto_extract: false,
                },
                Tool {
                    name: "Prefetch Parser",
                    description: "Analyze Windows Prefetch files for unsigned, flagged files using yara and timestamps for execution.",
                    url: "https://github.com/spokwn/prefetch-parser/releases/download/v1.5.5/PrefetchParser.exe",
                    filename: "PrefetchParser.exe",
                    auto_extract: false,
                },
                Tool {
                    name: "PcaSvc Executed",
                    description: "Track and analyze Program Compatibility Assistant Service executions and flag unsigned files, and flagged files using yara rules.",
                    url: "https://github.com/spokwn/pcasvc-executed/releases/download/v0.8.6/PcaSvcExecuted.exe",
                    filename: "PcaSvcExecuted.exe",
                    auto_extract: false,
                },
                Tool {
                    name: "Process Parser",
                    description: "Analyze AppInfo and Diagtrack for flagged files with yara rules, all in instance.",
                    url: "https://github.com/spokwn/process-parser/releases/download/v0.5.5/ProcessParser.exe",
                    filename: "ProcessParser.exe",
                    auto_extract: false,
                },
            ],
        },
        ToolCategory {
            name: "Forensics & Analysis",
            icon: "🕵️",
            tools: vec![
                Tool {
                    name: "WinPrefetchView",
                    description: "View & analyse Windows Prefetch files (.pf)",
                    url: "https://www.nirsoft.net/utils/winprefetchview.zip",
                    filename: "winprefetchview.zip",
                    auto_extract: true,
                },
                Tool {
                    name: "System Informer",
                    description: "Advanced process, memory & network monitor",
                    url: "https://sourceforge.net/projects/systeminformer/files/systeminformer-3.2.25011-release-setup.exe/download",
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
                    name: "Hayabusa 🏍️",
                    description: "Windows Event Log forensics timeline generator",
                    url: "https://github.com/Yamato-Security/hayabusa/releases/download/v3.8.1/hayabusa-3.8.1-win-x64.zip",
                    filename: "hayabusa-3.8.1-win-x64.zip",
                    auto_extract: true,
                },
            ],
        },
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
    anim: Anim,
}

impl App {
    fn new() -> Self {
        let mut cat_state = ListState::default();
        cat_state.select(Some(0));
        let mut tool_state = ListState::default();
        tool_state.select(Some(0));

        let output_dir = dirs::download_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("elementary");

        App {
            screen: Screen::CategoryList,
            categories: catalogue(),
            cat_state,
            tool_state,
            selected_tools: HashSet::new(),
            output_dir,
            log: Vec::new(),
            anim: Anim::new(),
        }
    }

    fn current_cat_idx(&self) -> usize { self.cat_state.selected().unwrap_or(0) }
    fn current_tool_idx(&self) -> usize { self.tool_state.selected().unwrap_or(0) }
    fn tool_key(cat: usize, tool: usize) -> String { format!("{cat}:{tool}") }

    fn toggle_tool(&mut self) {
        let cat = self.current_cat_idx();
        let tool = self.current_tool_idx();
        let key = Self::tool_key(cat, tool);
        let selected = if self.selected_tools.contains(&key) {
            self.selected_tools.remove(&key);
            false
        } else {
            self.selected_tools.insert(key);
            true
        };
        self.anim.set_flash(cat, tool, selected);
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

    fn nav_up_cat(&mut self) {
        let i = self.cat_state.selected().unwrap_or(0);
        self.cat_state.select(Some(i.saturating_sub(1)));
        self.anim.nav_dir = -1;
        self.anim.nav_at = Instant::now();
    }
    fn nav_down_cat(&mut self) {
        let i = self.cat_state.selected().unwrap_or(0);
        self.cat_state.select(Some((i + 1).min(self.categories.len() - 1)));
        self.anim.nav_dir = 1;
        self.anim.nav_at = Instant::now();
    }
    fn nav_up_tool(&mut self) {
        let i = self.tool_state.selected().unwrap_or(0);
        self.tool_state.select(Some(i.saturating_sub(1)));
        self.anim.nav_dir = -1;
        self.anim.nav_at = Instant::now();
    }
    fn nav_down_tool(&mut self) {
        let i = self.tool_state.selected().unwrap_or(0);
        let max = self.categories[self.current_cat_idx()].tools.len() - 1;
        self.tool_state.select(Some((i + 1).min(max)));
        self.anim.nav_dir = 1;
        self.anim.nav_at = Instant::now();
    }
}

// ─── UI ───────────────────────────────────────────────────────────────────────

fn render(f: &mut Frame, app: &App) {
    let area = f.size();

    // Animated title — scrolling shimmer on the header text
    let t = app.anim.t();
    let shimmer_pos = ((t * 8.0) as usize) % 60;
    let title_base = r#" ⬇  Elementary — "Elementary, my dear Watson"  ⬇ "#;
    let title_chars: Vec<char> = title_base.chars().collect();
    let title_spans: Vec<Span> = title_chars.iter().enumerate().map(|(i, &c)| {
    let dist = ((i as i32 - shimmer_pos as i32).abs()) as usize;
    let style = if dist == 0 {
        Style::default().fg(Color::White).add_modifier(Modifier::BOLD)
    } else if dist <= 2 {
        Style::default().fg(Color::LightGreen).add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(Color::Green).add_modifier(Modifier::BOLD)
    };
    Span::styled(c.to_string(), style)
}).collect();

    let border_p = app.anim.pulse(4.0);
let outer_border = Color::Rgb(
    (10.0 + border_p * 10.0) as u8,  //R
    (50.0 + border_p * 150.0) as u8,  //G
    (10.0 + border_p * 20.0) as u8,   //B
);

    let outer = Block::default()
        .title(Line::from(title_spans))
        .title_alignment(Alignment::Center)
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(outer_border));

    let inner = outer.inner(area);
    f.render_widget(outer, area);

    match app.screen {
        Screen::CategoryList => render_category(f, app, inner),
        Screen::ToolList     => render_tools(f, app, inner),
        Screen::Confirm      => render_confirm(f, app, inner),
        _                    => render_log(f, app, inner),
    }
}

fn render_category(f: &mut Frame, app: &App, area: ratatui::layout::Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(3), Constraint::Length(3)])
        .split(area);

    let cursor = app.anim.cursor_symbol();
    let active_border = app.anim.border_color();
    let trail_age = app.anim.nav_trail_age();
    let cur = app.current_cat_idx();

    let items: Vec<ListItem> = app.categories.iter().enumerate().map(|(i, cat)| {
        let sel_count = (0..cat.tools.len())
            .filter(|&t| app.selected_tools.contains(&App::tool_key(i, t)))
            .count();
        let badge = if sel_count > 0 { format!(" [{}✓]", sel_count) } else { String::new() };

        // Nav trail: row just left gets a brief dim highlight
        let is_trail = trail_age < 0.18 && i != cur && (
            (app.anim.nav_dir == 1 && i + 1 == cur) ||
            (app.anim.nav_dir == -1 && i == cur + 1)
        );

        let name_style = if is_trail {
            Style::default().fg(Color::Rgb(140, 180, 220)).add_modifier(Modifier::BOLD)
        } else {
            Style::default().add_modifier(Modifier::BOLD)
        };

        ListItem::new(Line::from(vec![
            Span::raw(format!("  {} ", cat.icon)),
            Span::styled(cat.name, name_style),
            Span::styled(badge, Style::default().fg(Color::Green).add_modifier(Modifier::BOLD)),
            Span::styled(format!("  ({} tools)", cat.tools.len()), Style::default().fg(Color::DarkGray)),
        ]))
    }).collect();

    let mut state = app.cat_state.clone();
    f.render_stateful_widget(
        List::new(items)
            .block(
                Block::default()
                    .title(" Categories ")
                    .borders(Borders::ALL)
                    .border_type(BorderType::Rounded)
                    .border_style(Style::default().fg(active_border)),
            )
            .highlight_style(
    Style::default()
        .bg(Color::Rgb(144, 238, 144)) 
        .fg(Color::Black)
        .add_modifier(Modifier::BOLD),
)
            .highlight_symbol(cursor),
        chunks[0],
        &mut state,
    );

    render_help(f, chunks[1], &[("↑↓","navigate"),("Enter","open"),("D","download"),("Q","quit")]);
}

fn render_tools(f: &mut Frame, app: &App, area: ratatui::layout::Rect) {
    let cat_idx = app.current_cat_idx();
    let cat = &app.categories[cat_idx];
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(3), Constraint::Length(3)])
        .split(area);

    let cursor = app.anim.cursor_symbol();
    let active_border = app.anim.border_color();
    let trail_age = app.anim.nav_trail_age();
    let cur = app.current_tool_idx();

    let items: Vec<ListItem> = cat.tools.iter().enumerate().map(|(t, tool)| {
        let key = App::tool_key(cat_idx, t);
        let is_selected = app.selected_tools.contains(&key);

        // Flash animation on toggle
        let (checkbox_span, row_bg) = if let Some(just_selected) = app.anim.flash_active(cat_idx, t) {
            let flash_color = if just_selected {
                Color::Rgb(0, 220, 100)
            } else {
                Color::Rgb(220, 60, 60)
            };
            let cb = if just_selected { "  [✓] " } else { "  [ ] " };
            (Span::styled(cb, Style::default().fg(flash_color).add_modifier(Modifier::BOLD | Modifier::RAPID_BLINK)),
             Some(Color::Rgb(20, 30, 20)))
        } else if is_selected {
            (Span::styled("  [✓] ", Style::default().fg(Color::Green)), None)
        } else {
            (Span::styled("  [ ] ", Style::default().fg(Color::DarkGray)), None)
        };

        // Nav trail on tool rows
        let is_trail = trail_age < 0.18 && t != cur && (
            (app.anim.nav_dir == 1 && t + 1 == cur) ||
            (app.anim.nav_dir == -1 && t == cur + 1)
        );

        let name_style = if is_trail {
            Style::default().fg(Color::Rgb(140, 180, 220)).add_modifier(Modifier::BOLD)
        } else if let Some(bg) = row_bg {
            Style::default().bg(bg).add_modifier(Modifier::BOLD)
        } else {
            Style::default().add_modifier(Modifier::BOLD)
        };

        let ext_tag = if tool.auto_extract {
            Span::styled(" [auto-extract]", Style::default().fg(Color::Rgb(120, 120, 220)))
        } else {
            Span::raw("")
        };

        ListItem::new(vec![
            Line::from(vec![checkbox_span, Span::styled(tool.name, name_style), ext_tag]),
            Line::from(Span::styled(
                format!("       {}", tool.description),
                Style::default().fg(Color::DarkGray),
            )),
        ])
    }).collect();

    let mut state = app.tool_state.clone();
    f.render_stateful_widget(
        List::new(items)
            .block(
                Block::default()
                    .title(format!(" {} {} ", cat.icon, cat.name))
                    .borders(Borders::ALL)
                    .border_type(BorderType::Rounded)
                    .border_style(Style::default().fg(active_border)),
            )
            .highlight_style(
                Style::default()
                    .bg(Color::Rgb(40, 20, 80))
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD),
            )
            .highlight_symbol(cursor),
        chunks[0],
        &mut state,
    );

    render_help(f, chunks[1], &[("↑↓","Navigate"),("Space","Toggle"),("A","Toggle (a)ll"),("Esc","Back"),("D","(D)ownload")]);
}

fn render_confirm(f: &mut Frame, app: &App, area: ratatui::layout::Rect) {
    let selected = app.selected_tool_list();
    let active_border = app.anim.border_color();

    let mut lines = vec![
        Line::from(Span::styled(
            "The following tools will be downloaded:",
            Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
    ];
    for (c, t) in &selected {
        let tool = &app.categories[*c].tools[*t];
        let note = if tool.auto_extract { "  → will extract" } else { "" };
        lines.push(Line::from(vec![
            Span::styled("  ✓ ", Style::default().fg(Color::Green)),
            Span::styled(tool.name, Style::default().add_modifier(Modifier::BOLD)),
            Span::styled(note, Style::default().fg(Color::Rgb(120, 120, 220))),
        ]));
    }
    lines.push(Line::from(""));
    lines.push(Line::from(vec![
        Span::styled("  Output: ", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
        Span::styled(app.output_dir.display().to_string(), Style::default().fg(Color::Yellow)),
    ]));
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        "  Enter = confirm   Esc = back",
        Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD),
    )));

    f.render_widget(
        Paragraph::new(lines)
            .block(
                Block::default()
                    .title(" Confirm Downloads ")
                    .borders(Borders::ALL)
                    .border_type(BorderType::Rounded)
                    .border_style(Style::default().fg(active_border)),
            )
            .wrap(Wrap { trim: false }),
        area,
    );
}

fn render_log(f: &mut Frame, app: &App, area: ratatui::layout::Rect) {
    let title = if app.screen == Screen::Done { " ✓ Complete " } else { " Downloading… " };
    let border_color = if app.screen == Screen::Done {
        Color::Green
    } else {
        app.anim.border_color()
    };

    let lines: Vec<Line> = app.log.iter().map(|l| {
        let color = if l.contains('✓') { Color::Green }
            else if l.contains('✗') || l.contains("Error") { Color::Red }
            else if l.contains('→') || l.contains("📦") { Color::Cyan }
            else { Color::White };
        Line::from(Span::styled(l.clone(), Style::default().fg(color)))
    }).collect();

    f.render_widget(
        Paragraph::new(lines)
            .block(
                Block::default()
                    .title(title)
                    .borders(Borders::ALL)
                    .border_type(BorderType::Rounded)
                    .border_style(Style::default().fg(border_color)),
            )
            .wrap(Wrap { trim: false }),
        area,
    );
}

fn render_help(f: &mut Frame, area: ratatui::layout::Rect, keys: &[(&str, &str)]) {
    let mut spans = vec![Span::raw("  ")];
    for (key, desc) in keys {
        spans.push(Span::styled(
            format!(" {key} "),
            Style::default().fg(Color::Black).bg(Color::DarkGray).add_modifier(Modifier::BOLD),
        ));
        spans.push(Span::styled(
            format!(" {desc}  "),
            Style::default().fg(Color::DarkGray),
        ));
    }
    f.render_widget(
        Paragraph::new(Line::from(spans))
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .border_type(BorderType::Rounded)
                    .border_style(Style::default().fg(Color::DarkGray)),
            ),
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
        .user_agent("Elementary/0.1")
        .redirect(reqwest::redirect::Policy::limited(10))
        .build()?;

    let selected = app.selected_tool_list();
    println!("\n  Elementary — {} download(s)\n", selected.len());
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
                .tick_strings(&["[    ]", "[=   ]", "[==  ]", "[=== ]", "[====]", "[ ===]", "[  ==]", "[   =]"])
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

    
    let frame_duration = Duration::from_millis(16);

    loop {
        terminal.draw(|f| render(f, &app))?;
        app.anim.clear_expired_flash();

        
        if event::poll(frame_duration)? {
            let Event::Key(key) = event::read()? else { continue; };
            if key.kind != crossterm::event::KeyEventKind::Press { continue; }

            if key.code == KeyCode::Char('c') && key.modifiers.contains(KeyModifiers::CONTROL) { break; }
            if matches!(key.code, KeyCode::Char('q') | KeyCode::Char('Q'))
                && matches!(app.screen, Screen::Done | Screen::CategoryList) { break; }

            match app.screen {
                Screen::CategoryList => match key.code {
                    KeyCode::Up    => app.nav_up_cat(),
                    KeyCode::Down  => app.nav_down_cat(),
                    KeyCode::Enter => { app.tool_state.select(Some(0)); app.screen = Screen::ToolList; }
                    KeyCode::Char('d') | KeyCode::Char('D') => {
                        if !app.selected_tools.is_empty() { app.screen = Screen::Confirm; }
                    }
                    _ => {}
                },
                Screen::ToolList => match key.code {
                    KeyCode::Up    => app.nav_up_tool(),
                    KeyCode::Down  => app.nav_down_tool(),
                    KeyCode::Char(' ')                       => app.toggle_tool(),
                    KeyCode::Char('a') | KeyCode::Char('A') => app.select_all_in_category(),
                    KeyCode::Esc | KeyCode::Char('b') | KeyCode::Char('B') => {
                        app.screen = Screen::CategoryList;
                    }
                    KeyCode::Char('d') | KeyCode::Char('D') => {
                        if !app.selected_tools.is_empty() { app.screen = Screen::Confirm; }
                    }
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
    }

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen, DisableMouseCapture)?;
    terminal.show_cursor()?;
    Ok(())
}
