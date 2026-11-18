# Changelog

All notable changes to Markseal are listed here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [0.2.0] - Unreleased

First public preview. Windows 11 only; the installer is not code-signed.

### Added

- New interface: four themes (Obsidian Cobalt, Editorial Ivory, Cyber Neon,
  Nordic Slate), command palette (`Ctrl+K`), focus mode, resizable sidebar,
  clickable outline, live word count and an unsaved-changes guard.
- Images that belong to an encrypted note are encrypted too, and are decrypted
  only in memory.
- Encrypting a note, or changing its passphrase, handles the note and its
  images as one all-or-nothing step.
- Auto-lock after idle time (default 5 minutes) and about one minute after the
  window is hidden or minimised.
- Panic key `Ctrl+Shift+L`: locks every decrypted note and clears the clipboard.
- Screen-capture shield: the window is hidden from screenshots, screen sharing
  and Windows Recall while a decrypted note is on screen.
- Markseal app icon (a page with a padlock); the source drawing is
  `src-tauri/icons/markseal-icon.svg`.
- `SECURITY.md` with the threat model, enforced boundaries and known
  limitations.

### Changed

- The project was renamed from MarkForge to Markseal. The app identifier is now
  `in.d3ltasecurity.markseal`. The file-format tags `MARKFORGE_ENC_V1` and
  `MARKFORGE_IMG_V1` are unchanged, so existing encrypted notes still open.
- The dialog for changing the passphrase of an encrypted note is now titled
  "Change passphrase" instead of "Encrypt note".
- The installer is a single NSIS `.exe` that installs for the current user.

### Security

- Each encrypted image is bound to its own file name, so it cannot be renamed
  or swapped with another image without failing authentication.
- With no workspace open, every file command is refused unless the path was
  picked in a native dialog.
- A file with more than one hard link is never zero-overwritten on delete.
- The app window starts with no access to local files; access is granted at
  runtime for the opened folder only.
- The out-of-view lock now also reads the native window state. Before this,
  a minimised window did not lock, because WebView2 does not report a minimised
  window as hidden (found in the installer test).
- HTML export sanitiser `ammonia` updated 4.2.4 -> 4.2.5 (RUSTSEC-2026-0533:
  mutation XSS through embedded SVG and MathML).
- The WebView2 runtime is started with background networking, component
  updates and proxy auto-detection switched off. This removes the runtime's own
  start-up requests to Microsoft that Chromium's network log can see. One
  connection made by the runtime itself remains and cannot be switched off by
  an application; see "Known limitations" in `SECURITY.md`.

### Known issues

- See "Known limitations" in `SECURITY.md` and "What is not ready yet" in
  `README.md`.

## [0.1.0] - not released

Internal builds under the name MarkForge. Never published.
