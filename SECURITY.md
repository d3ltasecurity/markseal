# Markseal Security Model

Markseal is a local-first, offline Markdown editor. This document describes its
threat model, the enforced security boundaries, known limitations, and how to
report a vulnerability.

## Threat model

- **Trusted:** the local user acting through the app's own UI and native OS
  file dialogs. A path the user explicitly picks in an Open/Save dialog is
  treated as user-consented.
- **Untrusted:** the *content* of any note, pasted image, or file opened in the
  editor. Markdown content is never granted authority over the filesystem, and
  rendered HTML is sanitized.
- **Out of scope:** multi-user / network sharing (Markseal is single-user and
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

A path that is neither inside the open workspace nor covered by the dialog
allowlist is refused. This also holds when **no workspace is open**: then only
dialog-picked paths are reachable, and with an empty allowlist every file
command fails.

The allowlist is **folder-scoped**: authorizing a note also authorizes its
sibling files and its `assets/` subfolder, so note-relative images
(`<note_dir>/assets/img_*.png`) load correctly. It never widens to the whole
filesystem.

**Image display (asset protocol).** The static asset scope in
`tauri.conf.json` is empty, so the webview can load no local file at startup.
Scope is granted at runtime only: the opened workspace folder, and for a note
opened or read outside it, that note's own folder and its immediate subfolders
(not recursive; hidden folders and symlinked folders are skipped).

### 2. Deletion follows a stricter, two-branch rule
`delete_note_file` and `secure_shred_file` use `validate_strict_workspace_path`:
- **A workspace is open:** the file must be inside that workspace. The dialog
  allowlist is ignored, so a file Save-As'd outside the workspace can never be
  deleted by the app, even after it was authorized for writing.
- **No workspace is open:** the file must be covered by the dialog allowlist
  (a path the user picked in a native dialog this session, or a file in that
  note's folder or its immediate subfolders). This lets a standalone note be
  encrypted with "delete original"; any other path is refused. "No workspace"
  never means "delete anything".

The zero-overwrite before deletion is skipped for a file that has more than one
hard link (or whose link count cannot be read); such a file is only unlinked.
Otherwise a hard link planted in the workspace could get the data of a file
outside it overwritten.

### 3. Encryption (zero-knowledge notes)
- Key derivation: **Argon2id** (64 MiB memory, 3 iterations, 4 lanes, 32-byte
  output).
- Encryption: **AES-256-GCM** with a random 16-byte salt and random 12-byte
  nonce per save; the file header is bound as additional authenticated data
  (AAD), so header tampering fails decryption.
- Passphrases and derived keys are held in `Zeroizing` buffers and wiped after
  use. Plaintext is never written to disk for encrypted notes.

#### Images in encrypted notes
- An image pasted into an encrypted note is written by `save_encrypted_image` as
  a binary envelope (`MARKFORGE_IMG_V1` | salt | nonce | AES-256-GCM
  ciphertext), with its own random salt and nonce and the same Argon2id
  parameters. It is decrypted in memory by `read_encrypted_image` and shown from
  a `blob:` URL; the plaintext image never touches the disk.
- The format tags `MARKFORGE_ENC_V1` and `MARKFORGE_IMG_V1` carry the project's
  earlier name (MarkForge). They are part of the file format and of what is
  authenticated, so they stay as they are; changing them would make existing
  encrypted notes unreadable.
- The AAD of an image is its header plus its own file name. The header keeps
  images in a separate domain from notes, so a note envelope cannot be replayed
  as an image or the reverse. The file name means an encrypted image cannot be
  renamed, or swapped with another image under the same passphrase, without
  failing authentication.
- Encrypting a note (or changing its passphrase) goes through `seal_note`, which
  treats the note and its images as one unit. It only ever writes **new** files
  first: plaintext images are encrypted next to the originals, and
  already-encrypted images are re-encrypted under the new passphrase into new
  files (`pic.png.enc` → `pic_k<8 hex>.png.enc`). The links are then rewritten
  and the note is saved with one atomic rename. Nothing that existed before is
  changed until that rename succeeds, so an error or a crash at any point leaves
  the old note and all its images readable with the old passphrase. Superseded
  files are removed only afterwards.
- `seal_note` only touches regular files with an image extension that resolve
  inside the note's own folder. Links with a scheme, a drive letter, an absolute
  path, `..`, or a symlink are skipped, so crafted Markdown cannot get other
  files encrypted or deleted. Originals are removed only after the encrypted
  copy is verified on disk, and only under the strict-workspace delete rule.

#### Session protection for decrypted notes
- **Auto-lock.** After a set idle time (default 5 minutes; 1, 5, 15, 30 or
  never) every decrypted note is locked: unsaved edits are written back
  encrypted, then the plaintext and passphrase are dropped from app state. The
  idle check uses wall-clock time, so it still fires after the window was
  hidden or the machine slept.
- **Out of view.** When the window is hidden or minimised, notes lock after one
  minute (or the auto-lock time, if that is shorter). Turning auto-lock off
  turns this off too. Two signals are used: the page's own visibility state,
  and the native window state (minimised / not visible), which is read every
  5 seconds. The second one is needed because WebView2 does not report a
  minimised window as hidden. Expect the lock 60 to 65 seconds after
  minimising. A window that is only covered by other windows does not count as
  out of view.
- **Panic key (`Ctrl+Shift+L`).** Does the same immediately and also clears the
  clipboard. The window is covered before any note is saved or closed.
- A note that cannot be saved is left open rather than discarded; locking never
  loses work.
- **Screen-capture shield.** While a decrypted note or the passphrase dialog is
  on screen, the window is excluded from capture (`SetWindowDisplayAffinity`
  with `WDA_EXCLUDEFROMCAPTURE` on Windows), which covers screenshots, screen
  sharing and Windows Recall. It is on by default and can be turned off.

### 4. HTML export sanitization
Exported HTML is generated with `pulldown-cmark` and then sanitized with
`ammonia`; the document title is HTML-entity-escaped. Script tags and event
handlers (e.g. `onerror=`) are stripped (covered by tests).

### 5. Content Security Policy
The production CSP is locked down: `script-src 'self'` (no `unsafe-eval`),
`connect-src 'self' ipc: http://ipc.localhost` only. Even in the unlikely event
of script injection into the webview, there is **no network egress path** from
the page to exfiltrate file contents. This is a statement about Markseal's own
page. The WebView2 runtime underneath is a separate matter; see "Known
limitations".

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
- **The capture shield is not DRM.** It stops ordinary capture tools. Another
  process running as the same user can switch the flag off, and a camera pointed
  at the screen is unaffected. It does not protect against malware already on
  the machine.
- **Locking drops references, it does not wipe webview memory.** Decrypted text
  and the session passphrase live in JavaScript memory while a note is open;
  after a lock they are released for garbage collection, not overwritten.
- **The WebView2 runtime can contact Microsoft on its own.** Markseal's window
  is drawn by Microsoft Edge WebView2, a Windows component that Markseal does
  not ship or control. Measured on runtime 157.0.4341.46 (November 2026) with
  Chromium's own network log: with default settings the runtime fetched its
  configuration from `config.edge.skype.com`, looked for a proxy (`wpad`) and
  downloaded browser components. Markseal therefore starts the runtime with
  `--disable-background-networking --disable-component-update
  --no-proxy-server`; with these the network log showed no outside request.
  **One connection remains that Markseal cannot switch off:** the runtime's
  main process sometimes opens an HTTPS connection to Microsoft's Office /
  Outlook servers shortly after start-up. It does not pass through the page or
  through Chromium's network stack, and it is a known, open issue for every
  WebView2 application (MicrosoftEdge/WebView2Feedback issue 5760). Markseal
  hands the runtime no note text, file name or passphrase to send, but the
  content of that connection is Microsoft's, is encrypted, and was not
  inspected. At the least it shows Microsoft that a WebView2 application
  started at your IP address. If that matters to you, run Markseal on a machine
  without network access, or block outbound traffic with a firewall. The
  switches above are not an interface Microsoft supports and may stop working
  in a later runtime; re-measure after runtime updates. Security updates for
  the runtime arrive through the Edge update service, which these switches do
  not touch.
- **Locking Windows does not lock notes at once.** There is no hook into the
  Windows session lock (`Win+L`). Notes lock when the idle time runs out, or one
  minute after the window is hidden or minimised. A locked Windows session
  leaves the window neither hidden nor minimised as far as is known (not
  verified), so assume the idle time applies.
- **Decrypted images are released, not wiped.** They are shown from in-memory
  `blob:` URLs that are revoked when the note is locked or its tab is left; the
  bytes are then freed by the webview, not overwritten.
- **An encrypted image must keep its file name.** The name is part of what is
  authenticated, so renaming a `.enc` image by hand makes it unreadable until it
  is renamed back.
- **What name binding does not stop.** Someone with write access to the disk can
  still put back an older copy of the same image file, or exchange two images
  that have the same file name in different folders and the same passphrase.
  Both are outside the scope of the v1 image format.
- **The allowlist trusts the app's own interface.** The backend records a path
  as "picked in a dialog" when the interface tells it so; it cannot check that a
  dialog was really shown. The same holds for the workspace folder. These rules
  stop mistakes and crafted note content, not script that is already running
  inside the app window. The Content Security Policy (`script-src 'self'`) is
  the control against that. Opening the dialogs from the Rust side, so the
  backend sees the user's choice itself, is planned for a later release.
- **Leftover files after a crash.** If the app dies while a note is being
  encrypted or re-keyed, unreferenced `.enc` files can remain in the note's
  folder. They are ciphertext and can be deleted by hand.
- **KaTeX advisory GHSA-238p-pmpm-9mq7 (low) is present.** Math rendering uses
  KaTeX through `@milkdown/crepe`, at a version before the fix (0.18.2), and
  there is no non-breaking upgrade yet. The advisory needs a separate
  prototype-pollution bug to already exist in the page; none is known here. If
  one did, the worst documented outcome is a crafted link or an external
  resource load; the CSP blocks inline script and `javascript:` URLs and does
  not allow the page to load images or data from the network. HTML export does
  not use KaTeX. This is an accepted risk to re-check on every dependency
  update, not a proof that it cannot be exploited.
- **Image file names and sizes are visible.** Encrypted images keep a
  recognisable name (`img_<time>_<random>.png.enc`) and their size on disk; only
  the contents are protected.
- **Shared images.** If two notes reference the same image file and one is
  encrypted with "delete originals" ticked, the other note loses that image.
- **Only inline image links are converted.** Reference-style images
  (`![alt][ref]`), percent-encoded paths, and images outside the note's folder
  are left unencrypted; the app reports which ones were skipped.
- **One key derivation per image.** Opening a note decrypts its images one at a
  time (64 MiB of memory each), so a note with many images takes longer to show
  them.

## Audit trail

The pre-release hardening history is in git:
- `d7ef06f` — initial review fixes (image-paste contract, workspace lock, CSP,
  25 MiB caps, atomic writes).
- `96f9638` — dialog-path validation for Save-As/Export, dynamic asset scope,
  live-theme CSS, dead-code removal.
- `820a3d8` — session dialog allowlist, strict delete confinement, production
  CSP, license + documentation.
- `7a4f728` — images of encrypted notes are encrypted; `seal_note`.
- `3bb3160` — auto-lock, panic key, screen-capture shield.
- `fd6825b` — image bound to its file name, re-key into new files, hard-link
  check before zero-overwrite, empty static asset scope, lock when hidden.
- `8ad1aa1`, `ca8234a` — with no workspace open, delete and then every file
  command accept only a dialog-authorized path.

Covered by 13 Rust integration tests in `src-tauri/tests/security_tests.rs`
(encryption + tamper detection, path traversal / null byte, workspace
confinement, dialog-allowlist allow/deny, no file access with no workspace open
and nothing dialog-authorized, strict delete with a workspace open,
delete refused with no workspace open unless dialog-authorized, HTML XSS stripping,
image-paste contract, encrypted images never in plaintext on disk, images bound
to their file name (swap and rename fail), sealing a note's existing images with
crafted-link refusal and no overwrite through a hard link, re-key that never
touches the old files and cleans up on failure).

Not covered by automated tests: the asset-protocol scope, the screen-capture
shield, and the lock behaviour in the user interface.

## Reporting a vulnerability

Please report security issues privately via GitHub Security Advisories on this
repository ("Security" tab → "Report a vulnerability") rather than opening a
public issue. We aim to acknowledge reports within a few days.
