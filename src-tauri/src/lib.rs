use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use argon2::{Algorithm, Argon2, Params, Version};
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Component, Path, PathBuf};
use std::sync::{LazyLock, RwLock};
use tauri::Manager;
use zeroize::{Zeroize, Zeroizing};

pub const ENC_HEADER: &str = "MARKFORGE_ENC_V1";
pub const MAX_FILE_SIZE_BYTES: u64 = 25 * 1024 * 1024; // 25 MiB cap to prevent OOM

static AUTHORIZED_WORKSPACE: RwLock<Option<PathBuf>> = RwLock::new(None);
static APP_HANDLE: RwLock<Option<tauri::AppHandle>> = RwLock::new(None);
static DIALOG_AUTHORIZED_PATHS: LazyLock<RwLock<HashSet<PathBuf>>> =
    LazyLock::new(|| RwLock::new(HashSet::new()));

pub fn set_app_handle(handle: tauri::AppHandle) {
    if let Ok(mut guard) = APP_HANDLE.write() {
        *guard = Some(handle);
    }
}

pub fn get_app_handle() -> Option<tauri::AppHandle> {
    APP_HANDLE.read().ok().and_then(|g| g.clone())
}

pub fn set_active_workspace_bound(ws_path: Option<PathBuf>) {
    if let Ok(mut guard) = AUTHORIZED_WORKSPACE.write() {
        *guard = ws_path;
    }
}

pub fn get_active_workspace_bound() -> Option<PathBuf> {
    AUTHORIZED_WORKSPACE.read().ok().and_then(|g| g.clone())
}

pub fn clear_dialog_authorized_paths() {
    if let Ok(mut set) = DIALOG_AUTHORIZED_PATHS.write() {
        set.clear();
    }
}

pub fn authorize_dialog_path_inner(path_str: &str) -> Result<PathBuf, String> {
    let resolved = validate_secure_path(path_str, Some(""))?;
    if let Ok(mut set) = DIALOG_AUTHORIZED_PATHS.write() {
        set.insert(resolved.clone());
    }
    Ok(resolved)
}

fn is_dialog_authorized(resolved_path: &Path) -> bool {
    if let Ok(guard) = DIALOG_AUTHORIZED_PATHS.read() {
        if guard.contains(resolved_path) {
            return true;
        }
        // For assets (e.g. <note_dir>/assets/img_<timestamp>.png) created by save_pasted_image,
        // check if parent or grandparent directory contains an authorized dialog note.
        if let Some(parent) = resolved_path.parent() {
            if guard.iter().any(|p| p.parent() == Some(parent)) {
                return true;
            }
            if let Some(grandparent) = parent.parent() {
                if guard.iter().any(|p| p.parent() == Some(grandparent)) {
                    return true;
                }
            }
        }
    }
    false
}

pub fn set_workspace_root_inner(dir_path: &str) -> Result<PathBuf, String> {
    let canon = validate_secure_path(dir_path, Some(dir_path))?;
    if !canon.is_dir() {
        return Err("Selected workspace path is not a directory.".into());
    }
    set_active_workspace_bound(Some(canon.clone()));
    Ok(canon)
}

pub fn validate_strict_workspace_path(path_str: &str) -> Result<PathBuf, String> {
    let resolved = validate_secure_path(path_str, Some(""))?;
    if let Some(canon_ws) = get_active_workspace_bound() {
        if !resolved.starts_with(&canon_ws) {
            return Err(
                "Security Error: Target path escapes the active workspace boundary.".into(),
            );
        }
    }
    Ok(resolved)
}

pub fn validate_secure_path(
    path_str: &str,
    explicit_workspace: Option<&str>,
) -> Result<PathBuf, String> {
    if path_str.is_empty() || path_str.contains('\0') {
        return Err("Security Error: Invalid path or null byte detected.".into());
    }

    let raw_path = Path::new(path_str);
    if raw_path
        .components()
        .any(|c| matches!(c, Component::ParentDir))
    {
        return Err(
            "Security Error: Relative parent directory traversal ('..') is blocked.".into(),
        );
    }

    let resolved_path = if raw_path.exists() {
        fs::canonicalize(raw_path).map_err(|e| format!("Failed to canonicalize path: {}", e))?
    } else if let Some(parent) = raw_path.parent() {
        if parent.as_os_str().is_empty() {
            return Err("Security Error: File path must include a valid parent directory.".into());
        }
        let canon_parent = fs::canonicalize(parent)
            .map_err(|e| format!("Parent directory does not exist or is inaccessible: {}", e))?;
        let file_name = raw_path
            .file_name()
            .ok_or_else(|| "Security Error: Missing target filename.".to_string())?;
        canon_parent.join(file_name)
    } else {
        return Err("Security Error: Unresolvable filesystem path.".into());
    };

    // Enforce explicit workspace parameter if provided, otherwise check session allowlist / active workspace lock
    if let Some(ws_str) = explicit_workspace {
        if !ws_str.is_empty() {
            let canon_ws = fs::canonicalize(ws_str)
                .map_err(|e| format!("Invalid workspace root directory: {}", e))?;
            if !resolved_path.starts_with(&canon_ws) {
                return Err(
                    "Security Error: Target path escapes the authorized workspace boundary.".into(),
                );
            }
        }
    } else {
        if is_dialog_authorized(&resolved_path) {
            return Ok(resolved_path);
        }
        if let Some(canon_ws) = get_active_workspace_bound() {
            if !resolved_path.starts_with(&canon_ws) {
                return Err(
                    "Security Error: Target path escapes the active workspace boundary.".into(),
                );
            }
        }
    }

    Ok(resolved_path)
}

pub fn enforce_file_size_limit(path: &Path) -> Result<u64, String> {
    let meta =
        fs::metadata(path).map_err(|e| format!("Failed to read file metadata: {}", e))?;
    let len = meta.len();
    if len > MAX_FILE_SIZE_BYTES {
        return Err(format!(
            "File exceeds the 25 MB safety limit ({} bytes).",
            len
        ));
    }
    Ok(len)
}

pub fn atomic_write_bytes(target_path: &Path, data: &[u8]) -> Result<(), String> {
    let parent = target_path
        .parent()
        .ok_or_else(|| "Missing parent directory for atomic write".to_string())?;
    let file_name = target_path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("markforge_note");

    let mut rand_suffix = [0u8; 4];
    rand::thread_rng().fill_bytes(&mut rand_suffix);
    let tmp_name = format!(
        ".{}.{}.tmp",
        file_name,
        rand_suffix
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<String>()
    );
    let tmp_path = parent.join(tmp_name);

    {
        let mut tmp_file = File::create(&tmp_path)
            .map_err(|e| format!("Failed to create atomic temp file: {}", e))?;
        tmp_file
            .write_all(data)
            .map_err(|e| format!("Failed to write to atomic temp file: {}", e))?;
        tmp_file
            .sync_all()
            .map_err(|e| format!("Failed to flush atomic temp file to disk: {}", e))?;
    }

    fs::rename(&tmp_path, target_path).map_err(|e| {
        let _ = fs::remove_file(&tmp_path);
        format!("Atomic rename failed: {}", e)
    })
}

#[derive(Serialize, Deserialize)]
pub struct SearchMatch {
    pub file_path: String,
    pub line_number: usize,
    pub snippet: String,
}

pub mod commands {
    use super::*;

    #[tauri::command]
    pub fn set_workspace_root(app: tauri::AppHandle, dir_path: String) -> Result<String, String> {
        set_app_handle(app.clone());
        let canon = set_workspace_root_inner(&dir_path)?;
        let _ = app.asset_protocol_scope().allow_directory(&canon, true);
        Ok(canon.to_string_lossy().to_string())
    }

    #[tauri::command]
    pub fn authorize_dialog_path(app: tauri::AppHandle, path: String) -> Result<String, String> {
        let canon = authorize_dialog_path_inner(&path)?;
        if let Some(parent) = canon.parent() {
            let _ = app.asset_protocol_scope().allow_directory(parent, true);
        }
        Ok(canon.to_string_lossy().to_string())
    }

    /// Best-effort single-pass zero overwrite before unlinking.
    /// Note: On wear-leveled SSDs, NVMe, or copy-on-write filesystems (NTFS/APFS/Btrfs),
    /// physical blocks may persist in flash translation layers until TRIM/garbage collection.
    #[tauri::command]
    pub fn delete_note_file(file_path: String) -> Result<(), String> {
        let path = validate_strict_workspace_path(&file_path)?;
        if !path.exists() {
            return Ok(());
        }
        let len = fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
        if len > 0 && len <= MAX_FILE_SIZE_BYTES {
            if let Ok(mut file) = OpenOptions::new().write(true).open(&path) {
                let zeros = vec![0u8; len as usize];
                let _ = file.write_all(&zeros);
                let _ = file.sync_all();
            }
        }
        fs::remove_file(&path).map_err(|e| format!("Failed to delete file: {}", e))
    }

    #[tauri::command]
    pub fn secure_shred_file(file_path: String) -> Result<(), String> {
        delete_note_file(file_path)
    }

    pub fn list_markdown_files_inner(dir_path: &str) -> Result<Vec<String>, String> {
        let root = set_workspace_root_inner(dir_path)?;
        let mut results = Vec::new();
        collect_md_files(&root, &root, &mut results)?;
        results.sort_by(|a, b| a.to_lowercase().cmp(&b.to_lowercase()));
        Ok(results)
    }

    #[tauri::command]
    pub fn list_markdown_files(app: tauri::AppHandle, dir_path: String) -> Result<Vec<String>, String> {
        set_app_handle(app.clone());
        let root = set_workspace_root_inner(&dir_path)?;
        let _ = app.asset_protocol_scope().allow_directory(&root, true);
        let mut results = Vec::new();
        collect_md_files(&root, &root, &mut results)?;
        results.sort_by(|a, b| a.to_lowercase().cmp(&b.to_lowercase()));
        Ok(results)
    }

    fn collect_md_files(
        dir: &Path,
        canon_root: &Path,
        acc: &mut Vec<String>,
    ) -> Result<(), String> {
        if let Ok(entries) = fs::read_dir(dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if let Ok(meta) = fs::symlink_metadata(&path) {
                    if meta.file_type().is_symlink() {
                        continue;
                    }
                }
                let file_name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
                if file_name.starts_with('.')
                    || file_name == "node_modules"
                    || file_name == "target"
                    || file_name == "dist"
                {
                    continue;
                }
                if path.is_dir() {
                    let _ = collect_md_files(&path, canon_root, acc);
                } else if path.is_file() {
                    let lower = file_name.to_lowercase();
                    if lower.ends_with(".md")
                        || lower.ends_with(".markdown")
                        || lower.ends_with(".md.enc")
                    {
                        if path.starts_with(canon_root) {
                            if let Some(p) = path.to_str() {
                                acc.push(p.to_string());
                            }
                        }
                    }
                }
            }
        }
        Ok(())
    }

    #[tauri::command]
    pub fn read_markdown_file(file_path: String) -> Result<String, String> {
        let path = validate_secure_path(&file_path, None)?;
        enforce_file_size_limit(&path)?;
        fs::read_to_string(&path).map_err(|e| format!("Failed to read file: {}", e))
    }

    #[tauri::command]
    pub fn save_markdown_file(file_path: String, content: String) -> Result<(), String> {
        if content.len() as u64 > MAX_FILE_SIZE_BYTES {
            return Err("Note content exceeds the 25 MB maximum size limit.".into());
        }
        let path = validate_secure_path(&file_path, None)?;
        atomic_write_bytes(&path, content.as_bytes())
    }

    #[tauri::command]
    pub fn is_encrypted_note(file_path: String) -> Result<bool, String> {
        if file_path.to_lowercase().ends_with(".enc") {
            return Ok(true);
        }
        let path = validate_secure_path(&file_path, None)?;
        if !path.exists() {
            return Ok(false);
        }
        if enforce_file_size_limit(&path).is_err() {
            return Ok(false);
        }
        if let Ok(content) = fs::read_to_string(&path) {
            return Ok(content.starts_with(ENC_HEADER));
        }
        Ok(false)
    }

    /// Saves a pasted image into `<note_parent_dir>/assets/img_<timestamp>.<ext>`
    /// Matches CrepeEditor contract: { activeMdPath, imageBytes, extension }
    #[tauri::command]
    pub fn save_pasted_image(
        active_md_path: String,
        image_bytes: Vec<u8>,
        extension: String,
    ) -> Result<String, String> {
        if image_bytes.is_empty() {
            return Err("Image payload is empty.".into());
        }
        if image_bytes.len() as u64 > MAX_FILE_SIZE_BYTES {
            return Err("Image exceeds the 25 MB size limit.".into());
        }

        let note_path = validate_secure_path(&active_md_path, None)?;
        let note_dir = note_path
            .parent()
            .ok_or_else(|| "Note path has no parent directory.".to_string())?;
        let assets_dir = note_dir.join("assets");
        fs::create_dir_all(&assets_dir)
            .map_err(|e| format!("Failed to create assets directory: {}", e))?;

        if let Some(app) = get_app_handle() {
            let _ = app.asset_protocol_scope().allow_directory(&assets_dir, true);
        }

        let clean_ext: String = extension
            .chars()
            .filter(|c| c.is_ascii_alphanumeric())
            .take(5)
            .collect();
        let ext = if clean_ext.is_empty() {
            "png".to_string()
        } else {
            clean_ext.to_lowercase()
        };

        let filename = format!(
            "img_{}.{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis(),
            ext
        );
        let target = assets_dir.join(&filename);
        atomic_write_bytes(&target, &image_bytes)?;
        Ok(format!("assets/{}", filename))
    }

    #[tauri::command]
    pub fn search_workspace(
        workspace_root: String,
        query: String,
        case_sensitive: bool,
    ) -> Result<Vec<SearchMatch>, String> {
        if query.trim().is_empty() {
            return Ok(Vec::new());
        }
        let files = list_markdown_files_inner(&workspace_root)?;
        let mut matches = Vec::new();
        let target = if case_sensitive {
            query.clone()
        } else {
            query.to_lowercase()
        };

        for file in files {
            if file.to_lowercase().ends_with(".enc") {
                continue;
            }
            let path = Path::new(&file);
            if enforce_file_size_limit(path).is_err() {
                continue; // Skip oversized files over 25 MB to prevent OOM
            }
            if let Ok(content) = fs::read_to_string(path) {
                if content.starts_with(ENC_HEADER) {
                    continue;
                }
                for (idx, line) in content.lines().enumerate() {
                    let haystack = if case_sensitive {
                        line.to_string()
                    } else {
                        line.to_lowercase()
                    };
                    if haystack.contains(&target) {
                        matches.push(SearchMatch {
                            file_path: file.clone(),
                            line_number: idx + 1,
                            snippet: line.trim().chars().take(120).collect(),
                        });
                        if matches.len() >= 200 {
                            return Ok(matches);
                        }
                    }
                }
            }
        }
        Ok(matches)
    }

    fn derive_hardened_key(
        password: &[u8],
        salt: &[u8; 16],
    ) -> Result<Zeroizing<[u8; 32]>, String> {
        let mut key = Zeroizing::new([0u8; 32]);
        let params = Params::new(65536, 3, 4, Some(32))
            .map_err(|e| format!("Failed to initialize Argon2id parameters: {}", e))?;
        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
        argon2
            .hash_password_into(password, salt, key.as_mut())
            .map_err(|e| format!("Argon2id key derivation failed: {}", e))?;
        Ok(key)
    }

    #[tauri::command]
    pub fn save_encrypted_markdown(
        file_path: String,
        content: String,
        password: String,
    ) -> Result<(), String> {
        if content.len() as u64 > MAX_FILE_SIZE_BYTES {
            return Err("Note content exceeds the 25 MB maximum size limit.".into());
        }
        let path = validate_secure_path(&file_path, None)?;
        let pass_guard = Zeroizing::new(password);
        let content_guard = Zeroizing::new(content);

        if pass_guard.trim().is_empty() {
            return Err("Passphrase cannot be empty.".into());
        }

        let mut salt = [0u8; 16];
        let mut nonce_bytes = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut salt);
        rand::thread_rng().fill_bytes(&mut nonce_bytes);

        let derived_key = derive_hardened_key(pass_guard.as_bytes(), &salt)?;
        let cipher = Aes256Gcm::new_from_slice(derived_key.as_ref()).map_err(|e| e.to_string())?;
        let nonce = Nonce::from_slice(&nonce_bytes);

        let payload = Payload {
            msg: content_guard.as_bytes(),
            aad: ENC_HEADER.as_bytes(),
        };

        let ciphertext = cipher
            .encrypt(nonce, payload)
            .map_err(|e| format!("AES-256-GCM encryption failed: {}", e))?;

        let envelope = format!(
            "{}:{}:{}:{}",
            ENC_HEADER,
            BASE64.encode(salt),
            BASE64.encode(nonce_bytes),
            BASE64.encode(ciphertext)
        );

        atomic_write_bytes(&path, envelope.as_bytes())
    }

    #[tauri::command]
    pub fn read_encrypted_markdown(
        file_path: String,
        password: String,
    ) -> Result<String, String> {
        let path = validate_secure_path(&file_path, None)?;
        enforce_file_size_limit(&path)?;
        let pass_guard = Zeroizing::new(password);

        let raw = fs::read_to_string(&path).map_err(|e| format!("Failed to read file: {}", e))?;
        let parts: Vec<&str> = raw.trim().split(':').collect();
        if parts.len() != 4 || parts[0] != ENC_HEADER {
            return Err("Invalid or tampered MarkForge encrypted file header.".into());
        }

        let salt_vec = BASE64
            .decode(parts[1])
            .map_err(|_| "Corrupted salt encoding in encrypted file.".to_string())?;
        let nonce_vec = BASE64
            .decode(parts[2])
            .map_err(|_| "Corrupted nonce encoding in encrypted file.".to_string())?;
        let ciphertext = BASE64
            .decode(parts[3])
            .map_err(|_| "Corrupted ciphertext encoding in encrypted file.".to_string())?;

        if salt_vec.len() != 16 || nonce_vec.len() != 12 {
            return Err("Invalid cryptographic salt or nonce length.".into());
        }

        let mut salt = [0u8; 16];
        salt.copy_from_slice(&salt_vec);

        let derived_key = derive_hardened_key(pass_guard.as_bytes(), &salt)?;
        let cipher = Aes256Gcm::new_from_slice(derived_key.as_ref()).map_err(|e| e.to_string())?;
        let nonce = Nonce::from_slice(&nonce_vec);

        let payload = Payload {
            msg: ciphertext.as_ref(),
            aad: parts[0].as_bytes(),
        };

        let mut decrypted_bytes = cipher.decrypt(nonce, payload).map_err(|_| {
            "Decryption failed: Incorrect passphrase or file integrity check failed.".to_string()
        })?;

        let result = match String::from_utf8(std::mem::take(&mut decrypted_bytes)) {
            Ok(valid_str) => Ok(valid_str),
            Err(utf8_err) => {
                let mut leaked_bytes = utf8_err.into_bytes();
                leaked_bytes.zeroize();
                Err("Decrypted content is not valid UTF-8 text.".into())
            }
        };

        decrypted_bytes.zeroize();
        result
    }

    fn escape_html_entities(input: &str) -> String {
        input
            .replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('>', "&gt;")
            .replace('"', "&quot;")
            .replace('\'', "&#x27;")
    }

    #[tauri::command]
    pub fn export_to_html(
        target_path: String,
        markdown_content: String,
        title: String,
        theme: String,
    ) -> Result<(), String> {
        let path = validate_secure_path(&target_path, None)?;

        let mut options = pulldown_cmark::Options::empty();
        options.insert(pulldown_cmark::Options::ENABLE_TABLES);
        options.insert(pulldown_cmark::Options::ENABLE_STRIKETHROUGH);
        options.insert(pulldown_cmark::Options::ENABLE_TASKLISTS);

        let parser = pulldown_cmark::Parser::new_ext(&markdown_content, options);
        let mut raw_html = String::new();
        pulldown_cmark::html::push_html(&mut raw_html, parser);

        let safe_html = ammonia::clean(&raw_html);
        let safe_title = escape_html_entities(&title);

        let (bg, text, card_bg, border, accent) = match theme.as_str() {
            "nord" => ("#2e3440", "#d8dee9", "#3b4252", "#4c566a", "#88c0d0"),
            "light" => ("#ffffff", "#24292f", "#f6f8fa", "#d0d7de", "#0969da"),
            "solarized" => ("#fdf6e3", "#586e75", "#eee8d5", "#93a1a1", "#268bd2"),
            _ => ("#0d1117", "#e6edf3", "#161b22", "#30363d", "#58a6ff"),
        };

        let full_document = format!(
            r#"<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <meta http-equiv="Content-Security-Policy" content="default-src 'none'; img-src data: https:; style-src 'unsafe-inline';">
  <title>{safe_title}</title>
  <style>
    body {{
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
      line-height: 1.65;
      background: {bg};
      color: {text};
      margin: 0;
      padding: 40px 20px;
    }}
    .document-container {{
      max-width: 860px;
      margin: 0 auto;
      background: {card_bg};
      padding: 44px;
      border-radius: 10px;
      border: 1px solid {border};
      box-shadow: 0 8px 28px rgba(0, 0, 0, 0.2);
    }}
    h1, h2, h3, h4 {{ color: {text}; border-bottom: 1px solid {border}; padding-bottom: 0.3em; }}
    a {{ color: {accent}; text-decoration: none; }}
    a:hover {{ text-decoration: underline; }}
    pre, code {{
      font-family: "Cascadia Code", "JetBrains Mono", Consolas, monospace;
      background: {bg};
      border-radius: 6px;
    }}
    pre {{ padding: 16px; overflow-x: auto; border: 1px solid {border}; }}
    code {{ padding: 2px 6px; font-size: 0.9em; }}
    table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
    th, td {{ border: 1px solid {border}; padding: 10px 12px; text-align: left; }}
    blockquote {{ border-left: 4px solid {accent}; margin: 0; padding-left: 16px; opacity: 0.85; }}
    img {{ max-width: 100%; height: auto; border-radius: 6px; }}
  </style>
</head>
<body>
  <div class="document-container">
    <h1>{safe_title}</h1>
    {safe_html}
  </div>
</body>
</html>"#
        );

        atomic_write_bytes(&path, full_document.as_bytes())
    }
}

pub use commands::*;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_fs::init())
        .setup(|app| {
            set_app_handle(app.handle().clone());
            if let Some(window) = app.get_webview_window("main") {
                #[cfg(target_os = "windows")]
                {
                    if window_vibrancy::apply_mica(&window, Some(true)).is_err() {
                        let _ = window_vibrancy::apply_acrylic(&window, Some((18, 22, 30, 210)));
                    }
                }
            }
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            commands::set_workspace_root,
            commands::authorize_dialog_path,
            commands::list_markdown_files,
            commands::read_markdown_file,
            commands::save_markdown_file,
            commands::is_encrypted_note,
            commands::delete_note_file,
            commands::secure_shred_file,
            commands::save_pasted_image,
            commands::search_workspace,
            commands::save_encrypted_markdown,
            commands::read_encrypted_markdown,
            commands::export_to_html
        ])
        .run(tauri::generate_context!())
        .expect("error while running MarkForge application");
}