# MarkForge Security Model

MarkForge is a local-first, offline Markdown editor. This document describes its
threat model, the enforced security boundaries, known limitations, and how to
report a vulnerability.

## Threat model

- **Trusted:** the local user acting through the app's own UI and native OS
  file dialogs. A path the user explicitly picks in an Open/Save dialog is
  treated as user-consented.
- **Untrusted:** the *content* of any note, pasted image, or file opened in the
  editor. Markdown content is never granted authority over the filesystem, and
  rendered HTML is sanitized.
- **Out of scope:** multi-user / network sharing (MarkForge is single-user and
  offline) and OS-level attackers who already have the user's filesystem rights.

## Enforced boundaries

### 1. Filesystem path confinement
All filesystem commands resolve paths through `validate_secure_path`, which
unconditionally blocks:
- empty paths and embedded null bytes,
- `..` parent-directory traversal,
- paths whose parent directory cannot be canonicalized.

On top of that, access is gated two ways:
- **Workspace lock (`AUTHORIZED_WORKSPACE`):** reads, saves, encryption, image
  pastes and HTML export are confined to the currently opened workspace folder.
- **Dialog allowlist (`DIALOG_AUTHORIZED_PATHS`):** when the user explicitly
  picks a path through a native Open/Save dialog, the frontend calls
  `authorize_dialog_path`, which adds that path to a per-session allowlist so
  Save-As and Export can write outside the workspace — but *only* to
  user-chosen locations.

The allowlist is **folder-scoped**: authorizing a note also authorizes its
sibling files and its `assets/` subfolder, so note-relative images
(`<note_dir>/assets/img_*.png`) load correctly. It never widens to the whole
filesystem.

### 2. Deletion is strictly workspace-only
`delete_note_file` and `secure_shred_file` use `validate_strict_workspace_path`
and ignore the dialog allowlist entirely. A file Save-As'd outside the workspace
can never be deleted or overwritten by the app, even after it was authorized for
writing.

### 3. Encryption (zero-knowledge notes)
- Key derivation: **Argon2id** (64 MiB memory, 3 iterations, 4 lanes, 32-byte
  output).
- Encryption: **AES-256-GCM** with a random 16-byte salt and random 12-byte
  nonce per save; the file header is bound as additional authenticated data
  (AAD), so header tampering fails decryption.
- Passphrases and derived keys are held in `Zeroizing` buffers and wiped after
  use. Plaintext is never written to disk for encrypted notes.

### 4. HTML export sanitization
Exported HTML is generated with `pulldown-cmark` and then sanitized with
`ammonia`; the document title is HTML-entity-escaped. Script tags and event
handlers (e.g. `onerror=`) are stripped (covered by tests).

### 5. Content Security Policy
The production CSP is locked down: `script-src 'self'` (no `unsafe-eval`),
`connect-src 'self' ipc: http://ipc.localhost` only. Even in the unlikely event
of script injection into the webview, there is **no network egress path** to
exfiltrate file contents.

### 6. Resource limits
A 25 MiB cap (`MAX_FILE_SIZE_BYTES`) applies to file reads, saves, image pastes
and workspace search to prevent out-of-memory conditions.

## Known limitations

- **Allowlist granularity is per-folder, not per-file.** Authorizing one file in
  a directory authorizes read/write to that directory and its immediate
  subfolders (required for `assets/`). It never extends to the whole disk.
- **"Secure shred" is best-effort.** A single-pass zero overwrite cannot
  guarantee physical erasure on wear-leveled SSDs, NVMe, or copy-on-write
  filesystems (NTFS/APFS/Btrfs) due to the flash translation layer and journaling.
  This is stated in the UI.
- **Dev mode CSP.** The locked production CSP may limit Vite hot-reload during
  `npm run tauri dev`; the shipped binary is unaffected.

## Audit trail

The pre-release hardening history is in git:
- `d12505e` — initial review fixes (image-paste contract, workspace lock, CSP,
  25 MiB caps, atomic writes).
- `0ecf63b` — dialog-path validation for Save-As/Export, dynamic asset scope,
  live-theme CSS, dead-code removal.
- `82bad79` — session dialog allowlist, strict delete confinement, production
  CSP, license + documentation.

Covered by 7 Rust integration tests in `src-tauri/tests/security_tests.rs`
(encryption + tamper detection, path traversal / null byte, workspace
confinement, dialog-allowlist allow/deny, strict delete, HTML XSS stripping,
image-paste contract).

## Reporting a vulnerability

Please report security issues privately via GitHub Security Advisories on this
repository ("Security" tab → "Report a vulnerability") rather than opening a
public issue. We aim to acknowledge reports within a few days.
