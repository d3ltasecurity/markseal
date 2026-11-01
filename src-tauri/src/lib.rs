use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use argon2::{Algorithm, Argon2, Params, Version};
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Component, Path, PathBuf};
use tauri::Manager;
use zeroize::{Zeroize, Zeroizing};

pub const ENC_HEADER: &str = "MARKFORGE_ENC_V1";

pub fn validate_secure_path(path_str: &str, workspace_root: Option<&str>) -> Result<PathBuf, String> {
    if path_str.is_empty() || path_str.contains('\0') {
        return Err("Security Error: Invalid path or null byte detected.".into());
    }

    let raw_path = Path::new(path_str);
    if raw_path
        .components()
        .any(|c| matches!(c, Component::ParentDir))
    {
        return Err("Security Error: Relative parent directory traversal ('..') is blocked.".into());
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

    if let Some(ws_str) = workspace_root {
        if !ws_str.is_empty() {
            let canon_ws = fs::canonicalize(ws_str)
                .map_err(|e| format!("Invalid workspace root directory: {}", e))?;
            if !resolved_path.starts_with(&canon_ws) {
                return Err(
                    "Security Error: Target path escapes the authorized workspace boundary.".into(),
                );
            }
        }
    }

    Ok(resolved_path)
}

pub(crate) fn atomic_write_bytes(target_path: &Path, data: &[u8]) -> Result<(), String> {
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
        rand_suffix.iter().map(|b| format!("{:02x}", b)).collect::<String>()
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

pub mod commands {
    use super::*;

    #[tauri::command]
    pub fn secure_shred_file(file_path: String) -> Result<(), String> {
    let path = validate_secure_path(&file_path, None)?;
    if !path.exists() {
        return Ok(());
    }
    let len = fs::metadata(&path).map(|m| m.len()).unwrap_or(0) as usize;
    if len > 0 && len <= 50 * 1024 * 1024 {
        if let Ok(mut file) = OpenOptions::new().write(true).open(&path) {
            let zeros = vec![0u8; len];
            let _ = file.write_all(&zeros);
            let _ = file.sync_all();
        }
    }
    fs::remove_file(&path).map_err(|e| format!("Failed to remove shredded file: {}", e))
}

#[derive(Serialize, Deserialize)]
pub struct SearchMatch {
    pub file_path: String,
    pub line_number: usize,
    pub snippet: String,
}

#[tauri::command]
pub fn list_markdown_files(dir_path: String) -> Result<Vec<String>, String> {
    let root = validate_secure_path(&dir_path, None)?;
    if !root.exists() {
        return Err("Directory does not exist.".into());
    }
    let mut results = Vec::new();
    collect_md_files(&root, &root, &mut results)?;
    results.sort_by(|a, b| a.to_lowercase().cmp(&b.to_lowercase()));
    Ok(results)
}

fn collect_md_files(dir: &Path, canon_root: &Path, acc: &mut Vec<String>) -> Result<(), String> {
    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if let Ok(meta) = fs::symlink_metadata(&path) {
                if meta.file_type().is_symlink() {
                    continue;
                }
            }
            let file_name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if file_name.starts_with('.') || file_name == "node_modules" || file_name == "target" {
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
    fs::read_to_string(&path).map_err(|e| format!("Failed to read file: {}", e))
}

#[tauri::command]
pub fn save_markdown_file(file_path: String, content: String) -> Result<(), String> {
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
    if let Ok(content) = fs::read_to_string(&path) {
        return Ok(content.starts_with(ENC_HEADER));
    }
    Ok(false)
}

#[tauri::command]
pub fn save_pasted_image(workspace_root: String, base64_data: String) -> Result<String, String> {
    let ws_path = validate_secure_path(&workspace_root, None)?;
    let assets_dir = ws_path.join("assets");
    fs::create_dir_all(&assets_dir).map_err(|e| e.to_string())?;

    let parts: Vec<&str> = base64_data.split(',').collect();
    let raw_b64 = if parts.len() == 2 { parts[1] } else { parts[0] };
    let bytes = BASE64.decode(raw_b64).map_err(|e| e.to_string())?;

    let filename = format!(
        "img_{}.png",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis()
    );
    let target = assets_dir.join(&filename);
    atomic_write_bytes(&target, &bytes)?;
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
    let files = list_markdown_files(workspace_root)?;
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
        if let Ok(content) = fs::read_to_string(&file) {
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

fn derive_hardened_key(password: &[u8], salt: &[u8; 16]) -> Result<Zeroizing<[u8; 32]>, String> {
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
pub fn read_encrypted_markdown(file_path: String, password: String) -> Result<String, String> {
    let path = validate_secure_path(&file_path, None)?;
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

pub use commands::{
    export_to_html, is_encrypted_note, list_markdown_files, read_encrypted_markdown,
    read_markdown_file, save_encrypted_markdown, save_markdown_file, save_pasted_image,
    search_workspace, secure_shred_file, SearchMatch,
};

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_fs::init())
        .setup(|app| {
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
            commands::list_markdown_files,
            commands::read_markdown_file,
            commands::save_markdown_file,
            commands::is_encrypted_note,
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