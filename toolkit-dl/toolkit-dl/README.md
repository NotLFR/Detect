#Elementary
## "Elementary, ny dear Watson" Sherlock Holmes

A terminal-based interactive downloader for Windows forensics, sysadmin, and security tools — written in Rust.

## Features

- Fully interactive TUI (keyboard-driven, no mouse needed)
- Organised into tool categories with multi-select
- Downloads directly to `~/Downloads/toolkit-dl/`
- Live progress bars during download
- No config files required — just pick and download

## Included Tools

| Category | Tools |
|---|---|
| 🔍 Forensics & Analysis | WinPrefetchView, System Informer, Autoruns, Process Monitor, Volatility3 |
| 🌐 Network | Wireshark, TCPView, Nmap, CurrPorts |
| 💾 Disk & File | WinDirStat, Everything, CrystalDiskInfo, FTK Imager |
| 🔧 Registry & System | RegRipper, Registry Explorer, Sysinternals Suite |
| 🔑 Password & Credentials | Mimikatz, PasswordFox, WebBrowserPassView |

## Keybindings

| Key | Action |
|---|---|
| `↑` / `↓` | Navigate |
| `Enter` | Open category |
| `Space` | Toggle tool selection |
| `A` | Toggle all tools in category |
| `D` | Go to download confirmation |
| `Esc` / `B` | Go back |
| `Q` | Quit |

## Build

Requirements: [Rust toolchain](https://rustup.rs/) (stable, 1.75+)

```bash
git clone https://github.com/yourhandle/toolkit-dl
cd toolkit-dl
cargo build --release
```

Binary will be at `target/release/toolkit-dl.exe` (Windows) or `target/release/toolkit-dl` (other).

## Run

```bash
cargo run --release
# or directly:
./target/release/toolkit-dl
```

## Adding Your Own Tools

Edit the `catalogue()` function in `src/main.rs`. Each tool is a simple struct:

```rust
Tool {
    name: "My Tool",
    description: "What it does",
    url: "https://example.com/mytool.zip",
    filename: "mytool.zip",
},
```

Add it to the relevant `ToolCategory`, or create a new one.

## Notes

- This tool downloads Windows executables. Running it on Linux/macOS will work but the downloaded files are Windows-only.
- Some tools (Mimikatz, credential tools) may trigger AV — add exceptions as needed for your forensics environment.
- No tool is bundled — all downloads happen at runtime from official/GitHub sources.
