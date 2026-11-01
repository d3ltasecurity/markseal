# MarkForge — Review & Fix List (reviewer + CISO + user + attacker)
Date: 2026-11-01 · Reviewing: src-tauri/src/lib.rs, src/CrepeEditor.tsx, src/App.tsx, tauri.conf.json, capabilities/default.json

## P0 — BROKEN / MUST FIX

### 1. Image paste is completely broken (frontend/backend contract mismatch)
`CrepeEditor.tsx` calls:
    invoke("save_pasted_image", { activeMdPath, imageBytes: number[], extension })
`lib.rs` signature is:
    save_pasted_image(workspace_root: String, base64_data: String)
Arg names AND types don't match → Tauri rejects every call → pasting an image always fails.
Also: backend hardcodes `.png` (ignores extension) and saves to `workspace_root/assets`,
but the spec + proxyDomURL resolve `assets/` relative to the NOTE's folder, not the workspace root.
FIX (pick one contract). Recommended backend to match the note-relative design:
    #[tauri::command]
    pub fn save_pasted_image(active_md_path: String, image_bytes: Vec<u8>, extension: String) -> Result<String, String> {
        let note = validate_secure_path(&active_md_path, None)?;
        let dir = note.parent().ok_or("No parent dir for note")?;
        let assets = dir.join("assets");
        std::fs::create_dir_all(&assets).map_err(|e| e.to_string())?;
        let ext = extension.chars().filter(|c| c.is_ascii_alphanumeric()).take(5).collect::<String>();
        let ext = if ext.is_empty() { "png".into() } else { ext.to_lowercase() };
        let name = format!("img_{}.{}", std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH).unwrap().as_millis(), ext);
        atomic_write_bytes(&assets.join(&name), &image_bytes)?;
        Ok(format!("assets/{}", name))
    }
(If you keep the base64 version instead, change CrepeEditor to send base64_data + workspaceRoot. Don't half-do it.)

## P1 — SECURITY (CISO / attacker)

### 2. Workspace confinement is dead code — every command passes None
`validate_secure_path(path, None)` is called everywhere, so the "authorized workspace boundary"
branch never runs. The `..` block + canonicalize stops relative traversal, but ANY absolute path
with no `..` is accepted. Impact by command:
  - secure_shred_file(abs_path)  -> can OVERWRITE + DELETE any file on disk outside the vault
  - save_markdown_file / export_to_html -> can WRITE anywhere
A malicious .md the user opens, or any path that reaches invoke, is unconstrained.
FIX: thread the real workspace root through and enforce it on all write/delete/read commands.
Keep a module-level OnceLock<PathBuf> set when a folder is opened, and pass Some(&root) to
validate_secure_path for every fs-touching command (at minimum shred, save, save_encrypted, export).

### 3. asset protocol scope is "**" (whole filesystem)
tauri.conf.json: assetProtocol.scope = ["**"] → convertFileSrc can load any file on disk.
FIX: scope it to the opened workspace, or the narrowest set you need (e.g. the assets dirs).

### 4. App-window CSP is null
tauri.conf.json: "csp": null. The editor renders user markdown + mermaid + katex with no CSP.
The exported HTML has a CSP but the live app does not.
FIX: set a restrictive csp (default-src 'self'; img-src 'self' asset: data:; style-src 'self' 'unsafe-inline';
script-src 'self') and widen only as mermaid/katex require.

### 5. "secure_shred_file" overstates its guarantee
Single-pass zero overwrite does NOT reliably erase on SSD / journaling / copy-on-write filesystems.
Calling it "secure shred" / "zero-knowledge" is misleading.
FIX: rename to delete_note_file, or document the limitation. Don't claim secure erasure in UI/README.

## P2 — ROBUSTNESS / UX

### 6. No size limits on read_markdown_file + search_workspace
Both read whole files to String with no cap; a multi-GB file = OOM/hang.
FIX: cap file size (e.g. 25 MB) before read; skip oversized files in search.

### 7. Editor rebuilds on theme change -> loses undo history + cursor
CrepeEditor useEffect deps = [docId, theme]. Switching theme destroys/recreates Crepe.
FIX: apply theme without full recreate if Crepe supports it, or accept + document it.

### 8. Not a git repo
No .git in D:\JETBRAINS PROJECTS — zero history/backup of all this work.
FIX: git init + .gitignore (node_modules, target, dist, gen) + initial commit NOW.

## WHAT'S GOOD (keep)
- Crypto is solid: Argon2id (64MB/t3/p4) + AES-256-GCM, per-save random salt(16)+nonce(12),
  header as AAD, wrong-pass + tamper both rejected (test proves it). Keys in Zeroizing.
- HTML export: pulldown-cmark + ammonia::clean + title entity-escaping; XSS test passes.
- Atomic writes (temp + fsync + rename); symlinks skipped in dir walk; null-byte + '..' blocked.
