# AGENTS.md — OhUnzip Developer & Agent Guide

This document describes the architecture, conventions, invariants, and gotchas of **OhUnzip** so coding agents can work safely and effectively in this repository.

## Project Overview

- **What**: A compact, minimalist Windows-first desktop archive extractor built with **Rust (Edition 2024)** + **GPUI Kit (`gpui-kit 0.11`)**, delegating extraction to system-installed **7-Zip (`7z.exe`)**.
- **Core Capabilities**: Normal archives, disguised/missing extensions, disguised split archives (`.7z.001.mp4`, `.part1.rar删`), polyglot/steganography archives (appended ZIP/7Z/RAR inside images/videos/PDFs), smart recursive nested extraction, plaintext password book with multi-format import/export, Windows Explorer cascading context menu, single-instance IPC, real-time progress/cancellation, ZIP codepage re-extraction (GBK / Shift-JIS), and Recycle Bin cleanup.

## Build, Test & Verification Commands

- Type-check: `cargo check` (use `--offline` when offline)
- Unit tests: `cargo test`
- Debug build: `cargo build`
- Release build: `cargo build --release` (uses `opt-level = "s"`, `lto = "thin"`, `strip = true`, `windows_subsystem = "windows"`)
- **Note on Windows builds**: `build.rs` compiles `assets/icon.ico` directly into a Windows `.res` binary (`RT_ICON` + `RT_GROUP_ICON` resource ID `1`) in pure Rust and links it via `cargo:rustc-link-arg-bins=...`. No external `rc.exe` is required, and it works on both **Windows ARM64** and **x64**.
- **Note on `oh-unzip.exe` lock**: On Windows, if `target\debug\oh-unzip.exe` is currently running, `cargo build` fails with `os error 5 (Access Denied)` when overwriting the binary. Stop the running process before rebuilding.

## Module Architecture

| File | Responsibility |
| --- | --- |
| `build.rs` | Pure-Rust `.ico` → Windows `.res` compiler (`RT_GROUP_ICON` ID `1`, loaded automatically by `gpui-pre-windows`). |
| `src/main.rs` | CLI parsing (`--extract-here`, `--extract-to`, bare paths), single-instance election, initial theme & window bounds, GPUI app boot (`assets::AllAssets`). |
| `src/config.rs` | `AppConfig` JSON persistence (`%APPDATA%\OhUnzip\config.json` or portable `<exe_dir>/config.json`), `ImportDelimiter` multi-format password parser, `ExportFormat` (`TXT`/`JSON`/`CSV`), UTF-8/UTF-16 decoder. |
| `src/detector.rs` | Archive magic-byte detector (including LZ4 Frame with xxHash32 header checksum), `ByteSource` random-access trait + unified format validators (7z/RAR5/RAR4 CRC, ZIP/ZIP64 EOCD, TAR checksum, Office/EPUB guard), disguised/wrapped split filename parser, protected component blacklist, and password hint extractor (filename, archive comment, sibling `.txt`). |
| `src/lz4.rs` | Pure-Rust, zero-dependency streaming LZ4 Frame (v1.6.4) + xxHash32 decoder (supports independent/dependent blocks, concatenated/skippable frames, checksums, cancellation, and Zip Bomb max-size guard) so `.lz4` files and LZ4-wrapped split volumes work on standard 7-Zip. |
| `src/stego/` | Pluggable steganography & polyglot codec registry (`mod.rs`: `StegoCodec` / `StegoRestorer` / `ProbeCost` tiers; `apate.rs`: Apate O(1) virtual `ByteSource` + stacked multi-layer streaming single/split restoration; `polyglot.rs`: O(1) ZIP EOCD & chunked 7z/RAR polyglot scanner + streaming offset carving). Add new tools as a file here + register in `CODECS`. |
| `src/extractor.rs` | 7z extraction pipeline: `-bsp1` streaming progress & `Arc<AtomicBool>` cancellation, `-mcp=<codepage>` support, fast 3-tier encryption probe (`7z l -slt -p-`) with explicit missing-volume/fatal error classification, standalone LZ4 extraction, generic `StegoRestorer` single & split staging, mixed outer-wrapped split volume unwrapping & header validation, smart nesting heuristic, Zip Bomb size guard, and Recycle Bin cleanup. |
| `src/seven_zip.rs` | Auto-detection of `7z.exe` via Windows Registry (`HKLM/HKCU\SOFTWARE\7-Zip`), `PATH`, and common install dirs (7-Zip, Scoop, Chocolatey, NanaZip), with `CREATE_NO_WINDOW`. |
| `src/context_menu.rs` | HKCU cascading Explorer context menu (`Software\Classes\*\shell\OhUnzip` and `Directory\shell\OhUnzip`) with zero UAC required. |
| `src/single_instance.rs` | Atomic localhost TCP (`127.0.0.1:47923`) single-instance election and IPC forwarding so Explorer multi-select launches merge cleanly into one window. |
| `src/trash.rs` | Zero-dependency Win32 `SHFileOperationW` (`FO_DELETE | FOF_ALLOWUNDO`) safe Recycle Bin move. |
| `src/notify.rs` | Registers `HKCU\Software\Classes\AppUserModelId\OhUnzip` with embedded `assets/icon.png` and sends non-blocking Windows Toast notifications. |
| `src/theme.rs` | 8 curated Light/Dark theme presets (`THEME_PRESETS`) applied via `Theme::change` + `Theme::update`. |
| `src/ui/mod.rs` | `OhUnzipApp` root state, IPC debounced poller, concurrency queue (`MAX_CONCURRENT_TASKS = 3`), window height sync, always-on-top Win32 `SetWindowPos`, `Esc` back-to-main shortcut, top bar + theme `Popover` dropdown. |
| `src/ui/main_page.rs` | Fixed-height drop zone + collapsible log drawer + task cards (progress bar, cancel, codepage re-extract popover, open folder with missing-dir `AlertDialog`). |
| `src/ui/passwords_page.rs` | Plaintext password management page (live input filter, sort by hits, import/export dialogs, confirmed clear-all). |
| `src/ui/import_dialog.rs` | `ImportDialogView` modal entity: file read, clipboard paste, delimiter switcher + custom separator, live deduplicated preview. |
| `src/ui/settings_page.rs` | Settings page: 7z path, output mode, context menu switch, strategy switches, max nesting depth, portable mode indicator. |

## Critical Invariants & Gotchas (Do Not Break!)

1. **7-Zip `-p` switch**:
   - **NEVER** pass bare `"-p"` for an empty password. In 7-Zip CLI, bare `-p` triggers an interactive stdin password prompt even on unencrypted archives and breaks non-interactive runs. Always use `"-p-"` when `pw.is_empty()` (`add_password_arg` in `src/extractor.rs`).
2. **Component Protection & Smart Nesting**:
   - Do **not** treat software package/library containers (`.jar`, `.whl`, `.lib`, `.a`, `.apk`, `.vsix`, `.nupkg`, `.dll`, `.exe`, Office docs) as disguised archives (`is_protected_component_ext` in `src/detector.rs`). Note in particular that MSVC `.lib` / Unix `.a` share `!<arch>\n` magic with `.deb`, and Eclipse P2 `.jar` files lack `META-INF/MANIFEST.MF`.
   - Do **not** skip explicit `.zip`/`.zipx` files in `is_real_zip_document` (a real `.zip` may contain `AndroidManifest.xml` or `[Content_Types].xml`).
   - Do **not** recursively unpack nested `.zip`/`.7z` files buried inside large extracted software distributions (e.g., Ghidra plugins). Keep the `MAX_FILES_FOR_NESTED_SCAN` and `real_payload_files <= 2` heuristic in `scan_and_extract_nested`.
   - **Never** delete top-level user-dropped files via `clean_intermediate`, and **never** delete/trash stego/polyglot carrier media files (`detected.is_stego_carrier()`).
3. **GPUI Kit 0.11 & Rust 2024 Conventions**:
   - `gpui-kit 0.11` uses `use gpui_kit::*;` and `use gpui_kit::prelude::FluentBuilder as _;` for `.when()` / `.when_some()`.
   - Because this crate uses **Rust Edition 2024**, helper render methods returning `impl IntoElement` should include `+ use<>` (or return a concrete type like `Div`) so they don't capture `&Context<Self>` lifetimes across sibling calls in `Render::render`.
   - Always pass `assets::AllAssets` (not `assets::Assets`) in `main.rs` because we use extended Lucide icons (`KeyRound`, `Pin`, `PinOff`, `Download`, `Upload`).
   - `gpui_kit::open_window` already wraps the root view in `gpui_base::Root`, which hosts `WindowExt::open_dialog`, `open_alert_dialog`, and `Popover` layers automatically.
   - Plain `Dialog` does **not** render footer buttons from `button_props` — compose action buttons inside the dialog child entity (`ImportDialogView`) or use `AlertDialog` for confirm/warning modals.
   - When updating `Theme`, call `Theme::change(mode, None, cx)` first and then `Theme::update(cx, |t| ...)` (never mutate `Theme::global_mut` directly without going through `Theme::update`, or tokens and base projections will drift).
4. **UX Principles**:
   - Keep the UI compact, calm, and minimalist: concise 4–5 character labels in Settings, no verbose helper paragraphs, no forced page switching on Main.
   - Do **not** auto-expand the log drawer on file drop; preserve the user's last persisted `logs_expanded` state.
   - Passwords are intentionally displayed in **plaintext** (never masked with asterisks).
