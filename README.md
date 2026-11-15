# Markseal

Markseal is a local-first, offline Markdown editor for Windows. Any note can be
encrypted on its own, together with its images, with a passphrase only you know.
There is no account, no cloud and no telemetry.

Built with Tauri v2 (Rust), React 19 and Milkdown Crepe.

> **Status: 0.2.0 public preview.** Tested on Windows 11 only. The installer is
> not code-signed yet, so Windows shows a SmartScreen warning on first run. Read
> [What is not ready yet](#what-is-not-ready-yet) before you trust it with
> important notes, and keep backups.

## Features

**Writing**

- WYSIWYG Markdown editing: tables, task lists, code blocks with syntax
  highlighting, LaTeX math and Mermaid diagrams.
- Open a folder as a workspace: file tree, tabs, a clickable outline of the
  current note, live word count and full-text search across the folder.
- Command palette (`Ctrl+K`) and focus mode.
- Four themes: Obsidian Cobalt (default), Editorial Ivory, Cyber Neon and
  Nordic Slate.
- Paste an image straight from the clipboard.
- Export a note to a sanitized, standalone HTML file, or print it to PDF.

**Protection**

- **Per-note encryption.** A note is encrypted into a single `.md.enc` file
  with AES-256-GCM; the key is derived from your passphrase with Argon2id.
- **Images are encrypted too.** Pictures that belong to an encrypted note are
  stored encrypted and are only ever decrypted in memory.
- **Change passphrase.** The note and its images are re-encrypted as one unit;
  a crash halfway leaves the old note readable with the old passphrase.
- **Auto-lock.** Decrypted notes lock after 5 minutes idle (1, 5, 15, 30 or
  never), and one minute after the window is hidden or minimised.
- **Panic key.** `Ctrl+Shift+L` locks every decrypted note at once and clears
  the clipboard.
- **Screen-capture shield.** While a decrypted note is on screen the window is
  hidden from screenshots, screen sharing and Windows Recall. On by default.
- **Offline by design.** The Content Security Policy gives the app window no
  route to the network.

There is no passphrase recovery. If you forget the passphrase of a note, the
note is gone.

## Keyboard shortcuts

| Shortcut | Action |
|---|---|
| `Ctrl+K` | Command palette |
| `Ctrl+N` | New note |
| `Ctrl+S` | Save |
| `Ctrl+W` | Close tab |
| `Ctrl+L` | Encrypt the note, or change the passphrase of an encrypted note |
| `Ctrl+Shift+L` | Panic key: lock all notes and clear the clipboard |
| `Ctrl+Shift+F` | Search the workspace |
| `Ctrl+Shift+E` | Show or hide the sidebar |
| `Ctrl+E` | Export sanitized HTML |
| `Ctrl+P` | Print or save as PDF |
| `Ctrl+\` or `F11` | Focus mode |

## Install

Markseal 0.2.0 supports **Windows 11**. Windows 10 and macOS have not been
tested.

1. Download `Markseal_0.2.0_x64-setup.exe` and `SHA256SUMS` from the Releases
   page of this repository.
2. Check the download (see below).
3. Run the installer. It installs for the current user and does not need
   administrator rights. Windows will show "Windows protected your PC" because
   the preview is not signed: choose **More info → Run anyway** only after the
   checksum matches.

### Verify your download

In PowerShell, in the folder with the downloaded file:

```powershell
Get-FileHash .\Markseal_0.2.0_x64-setup.exe -Algorithm SHA256
```

The hash must be the same as the line for that file in `SHA256SUMS`. If it is
different, delete the file and do not run it.

## Security

The full threat model, the enforced boundaries and the known limitations are in
[SECURITY.md](SECURITY.md). In short:

- AES-256-GCM with a random salt and nonce per save; Argon2id key derivation
  (64 MiB memory, 3 iterations, 4 lanes). The file header is authenticated.
- File access is confined to the open workspace folder and to paths you pick
  in a native Open/Save dialog. Deleting is stricter still.
- Saves are atomic (temporary file, flush, rename).
- Exported HTML is sanitized.
- File reads, saves, pastes and search are capped at 25 MiB.

Please report vulnerabilities privately, as described in
[SECURITY.md](SECURITY.md#reporting-a-vulnerability).

### What is not ready yet

- The installer is **unsigned**. Code signing is planned.
- Tested on **Windows 11 only**, by one person. There is no automatic update.
- Locking Windows (`Win+L`) does not lock notes at once; they lock when the
  idle time runs out.
- "Overwrite & delete the original" is best-effort. It cannot guarantee
  erasure on SSDs or copy-on-write file systems. Use full-disk encryption
  (BitLocker) as well.
- The capture shield stops ordinary capture tools. It is not protection
  against malware already running under your account.
- Decrypted text lives in the app's memory while a note is open and is
  released, not wiped, when it locks.
- One low-severity advisory in the math renderer (KaTeX) has no clean fix yet;
  see SECURITY.md.

## Build from source

Requirements: [Node.js](https://nodejs.org/) 20 or later,
[Rust](https://www.rust-lang.org/) (stable) and the Microsoft C++ Build Tools.

```bash
npm install
npm run tauri dev
```

Run the security tests:

```bash
cargo test --manifest-path src-tauri/Cargo.toml
```

Build the installer (written to `src-tauri/target/release/bundle/nsis/`):

```bash
npm run tauri build
```

## How it is put together

- **Frontend:** React 19, TypeScript, Vite, Milkdown Crepe, lucide icons.
- **Backend:** Rust on Tauri v2. It owns all file access, the cryptography,
  HTML export and the window.
- The two sides talk only through Tauri `invoke` commands; every path the
  frontend sends is validated again in Rust.

Encrypted files start with the tags `MARKFORGE_ENC_V1` (notes) and
`MARKFORGE_IMG_V1` (images). They carry the project's earlier name and are part
of the file format, so they stay.

## Licence

[MIT](LICENSE). Copyright (c) 2026 D3lta Security.
