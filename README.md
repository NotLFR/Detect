# "Elementary, ny dear Watson" - Sherlock Holmes

A TUI downloader for Windows Forensics & Security tools written in Rust 🦀



## Build

Requirements: [Rust toolchain](https://rustup.rs/) (stable, 1.75+)

```bash
git clone https://github.com/NotLFR/Sherlock
cd elementary
cargo build --release
```

Binary will be at `target/release/elementary.exe` 

## Run

```bash
cargo run --release
# or directly:
./target/release/elementary
```

## Adding Your Own Tools

Edit the `catalogue()` function in `src/main.rs`. Each tool is a simple struct:

```rust
Tool {
    name: "Name of Tools",
    description: "Description of tool",
    url: "https://example.com/mytool.zip",
    filename: "mytool.zip",
},
```

Add it to the relevant `ToolCategory`, or create a new one.

## Notes

- This tool is intended for Windows only. Error handling designed for all Operating Systems, but only Windows enviroment configured so far.
- Some tools (Mimikatz, credential tools) may trigger AV add exceptions as needed for your specific environment.
- No tool is bundled. All downloads happen at runtime from official sources.
