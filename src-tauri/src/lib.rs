use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use argon2::{Algorithm, Argon2, Params, Version};
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Component, Path, PathBuf};
use std::sync::{LazyLock, Mutex, RwLock};
use tauri::Manager;
use zeroize::{Zeroize, Zeroizing};

pub const ENC_HEADER: &str = "MARKFORGE_ENC_V1";
pub const IMG_HEADER: &[u8; 16] = b"MARKFORGE_IMG_V1";
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
    match get_active_workspace_bound() {
        // A workspace is open: the target must be inside it. The dialog allowlist is ignored.
        Some(canon_ws) => {
            if !resolved.starts_with(&canon_ws) {
                return Err(
                    "Security Error: Target path escapes the active workspace boundary.".into(),
                );
            }
        }
        // No workspace is open: "no boundary" must not mean "delete anything". Only a path the
        // user picked in a file dialog this session (or a file in that note's folder) qualifies.
        None => {
            if !is_dialog_authorized(&resolved) {
                return Err(
                    "Security Error: No workspace is open and this path was not chosen in a file dialog."
                        .into(),
                );
            }
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
        match get_active_workspace_bound() {
            Some(canon_ws) => {
                if !resolved_path.starts_with(&canon_ws) {
                    return Err(
                        "Security Error: Target path escapes the active workspace boundary."
                            .into(),
                    );
                }
            }
            // No workspace open and not picked in a dialog: there is nothing that authorizes
            // this path, so it is refused rather than treated as unrestricted.
            None => {
                return Err(
                    "Security Error: No workspace is open and this path was not chosen in a file dialog."
                        .into(),
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

/// How many names (hard links) point at this file's data. `None` when it cannot be read.
#[cfg(windows)]
pub fn hard_link_count(path: &Path) -> Option<u64> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{
        GetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION,
    };

    let file = File::open(path).ok()?;
    // SAFETY: `info` is a plain-data struct that the call fills in, and the handle stays valid
    // for the whole call because `file` is alive until the end of this function.
    let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
    let ok = unsafe { GetFileInformationByHandle(file.as_raw_handle() as _, &mut info) };
    (ok != 0).then_some(u64::from(info.nNumberOfLinks))
}

#[cfg(unix)]
pub fn hard_link_count(path: &Path) -> Option<u64> {
    use std::os::unix::fs::MetadataExt;
    fs::metadata(path).ok().map(|m| m.nlink())
}

#[cfg(not(any(windows, unix)))]
pub fn hard_link_count(_path: &Path) -> Option<u64> {
    None
}

/// Lets the webview display images that sit beside a note: the note's own folder and its
/// immediate subfolders. This is the same reach as the dialog allowlist and never goes deeper.
/// Nothing is granted at startup; the static asset scope in `tauri.conf.json` is empty.
pub fn grant_note_asset_scope(note_path: &Path) {
    const MAX_SUBFOLDERS: usize = 256;
    let Some(app) = get_app_handle() else { return };
    let Some(note_dir) = note_path.parent() else { return };
    let scope = app.asset_protocol_scope();
    let _ = scope.allow_directory(note_dir, false);
    if let Ok(entries) = fs::read_dir(note_dir) {
        let subfolders = entries.flatten().filter(|entry| {
            let hidden = entry.file_name().to_string_lossy().starts_with('.');
            // `file_type` does not follow symlinks, so linked folders are never granted.
            !hidden && entry.file_type().map(|t| t.is_dir()).unwrap_or(false)
        });
        for entry in subfolders.take(MAX_SUBFOLDERS) {
            let _ = scope.allow_directory(entry.path(), false);
        }
    }
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
        set_app_handle(app);
        let canon = authorize_dialog_path_inner(&path)?;
        grant_note_asset_scope(&canon);
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
        // Overwrite only when this is the file's single name. Zeroing a hard-linked file would
        // also destroy the data behind its other names, which may lie outside the workspace;
        // such a file (or one whose link count cannot be read) is just unlinked.
        let single_name = hard_link_count(&path) == Some(1);
        if single_name && len > 0 && len <= MAX_FILE_SIZE_BYTES {
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
        let content =
            fs::read_to_string(&path).map_err(|e| format!("Failed to read file: {}", e))?;
        grant_note_asset_scope(&path);
        Ok(content)
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
            let _ = app.asset_protocol_scope().allow_directory(&assets_dir, false);
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

        // An encrypted note can still reference plain images (ones `seal_note` had to skip).
        grant_note_asset_scope(&path);

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

    // ---- Encrypted note assets (images) -------------------------------------------------
    //
    // Images belonging to an encrypted note are stored as binary envelopes:
    //   IMG_HEADER (16) | salt (16) | nonce (12) | AES-256-GCM ciphertext + tag
    // Each image has its own random salt and nonce. The AAD is the header plus the image's own
    // file name, so a note envelope can never be replayed as an image (or the reverse), and an
    // encrypted image cannot be renamed or swapped with another one under the same passphrase
    // without failing authentication.

    /// Each Argon2id derivation needs 64 MiB and the editor requests every image of a note
    /// at once, so image key derivations run one at a time to keep memory bounded.
    static IMAGE_KDF_GATE: Mutex<()> = Mutex::new(());

    const IMAGE_ENVELOPE_OVERHEAD: usize = 16 + 16 + 12 + 16;

    /// Only these file types may be converted (and their originals removed) by `seal_note`.
    /// The allowlist stops crafted Markdown from getting arbitrary files encrypted and deleted.
    const SEALABLE_IMAGE_EXTENSIONS: [&str; 9] = [
        "png", "jpg", "jpeg", "gif", "webp", "bmp", "svg", "avif", "ico",
    ];

    fn image_aad(file_name: &str) -> Vec<u8> {
        let mut aad = Vec::with_capacity(IMG_HEADER.len() + 1 + file_name.len());
        aad.extend_from_slice(&IMG_HEADER[..]);
        aad.push(b':');
        aad.extend_from_slice(file_name.as_bytes());
        aad
    }

    /// The name an encrypted image is bound to: the last component of its path on disk.
    fn asset_file_name(path: &Path) -> Result<&str, String> {
        path.file_name()
            .and_then(|n| n.to_str())
            .filter(|n| !n.is_empty())
            .ok_or_else(|| "Encrypted image has no usable file name.".to_string())
    }

    fn seal_image_bytes(
        plain: &[u8],
        password: &[u8],
        file_name: &str,
    ) -> Result<Vec<u8>, String> {
        let mut salt = [0u8; 16];
        let mut nonce_bytes = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut salt);
        rand::thread_rng().fill_bytes(&mut nonce_bytes);

        let derived_key = {
            let _gate = IMAGE_KDF_GATE.lock().unwrap_or_else(|e| e.into_inner());
            derive_hardened_key(password, &salt)?
        };
        let cipher = Aes256Gcm::new_from_slice(derived_key.as_ref()).map_err(|e| e.to_string())?;
        let ciphertext = cipher
            .encrypt(
                Nonce::from_slice(&nonce_bytes),
                Payload {
                    msg: plain,
                    aad: &image_aad(file_name),
                },
            )
            .map_err(|e| format!("AES-256-GCM image encryption failed: {}", e))?;

        let mut envelope = Vec::with_capacity(IMAGE_ENVELOPE_OVERHEAD + plain.len());
        envelope.extend_from_slice(&IMG_HEADER[..]);
        envelope.extend_from_slice(&salt);
        envelope.extend_from_slice(&nonce_bytes);
        envelope.extend_from_slice(&ciphertext);
        Ok(envelope)
    }

    fn open_image_bytes(
        raw: &[u8],
        password: &[u8],
        file_name: &str,
    ) -> Result<Zeroizing<Vec<u8>>, String> {
        if raw.len() < IMAGE_ENVELOPE_OVERHEAD || raw[..16] != IMG_HEADER[..] {
            return Err("Invalid or tampered MarkForge encrypted image header.".into());
        }
        let mut salt = [0u8; 16];
        salt.copy_from_slice(&raw[16..32]);

        let derived_key = {
            let _gate = IMAGE_KDF_GATE.lock().unwrap_or_else(|e| e.into_inner());
            derive_hardened_key(password, &salt)?
        };
        let cipher = Aes256Gcm::new_from_slice(derived_key.as_ref()).map_err(|e| e.to_string())?;
        let plain = cipher
            .decrypt(
                Nonce::from_slice(&raw[32..44]),
                Payload {
                    msg: &raw[44..],
                    aad: &image_aad(file_name),
                },
            )
            .map_err(|_| {
                "Decryption failed: incorrect passphrase, or the image was changed, renamed or swapped."
                    .to_string()
            })?;
        Ok(Zeroizing::new(plain))
    }

    fn is_image_envelope(path: &Path) -> bool {
        let mut header = [0u8; 16];
        File::open(path)
            .and_then(|mut f| std::io::Read::read_exact(&mut f, &mut header))
            .map(|_| header == IMG_HEADER[..])
            .unwrap_or(false)
    }

    fn random_hex(bytes: usize) -> String {
        let mut buf = vec![0u8; bytes];
        rand::thread_rng().fill_bytes(&mut buf);
        buf.iter().map(|b| format!("{:02x}", b)).collect()
    }

    /// Encrypted counterpart of `save_pasted_image`: the image never touches disk in the clear.
    /// Writes `<note_parent_dir>/assets/img_<timestamp>_<random>.<ext>.enc`.
    #[tauri::command(async)]
    pub fn save_encrypted_image(
        active_md_path: String,
        image_bytes: Vec<u8>,
        extension: String,
        password: String,
    ) -> Result<String, String> {
        let pass_guard = Zeroizing::new(password);
        let bytes_guard = Zeroizing::new(image_bytes);

        if bytes_guard.is_empty() {
            return Err("Image payload is empty.".into());
        }
        if bytes_guard.len() as u64 > MAX_FILE_SIZE_BYTES {
            return Err("Image exceeds the 25 MB size limit.".into());
        }
        if pass_guard.trim().is_empty() {
            return Err("Passphrase cannot be empty.".into());
        }

        let note_path = validate_secure_path(&active_md_path, None)?;
        let note_dir = note_path
            .parent()
            .ok_or_else(|| "Note path has no parent directory.".to_string())?;
        let assets_dir = note_dir.join("assets");
        fs::create_dir_all(&assets_dir)
            .map_err(|e| format!("Failed to create assets directory: {}", e))?;

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
            "img_{}_{}.{}.enc",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_millis())
                .unwrap_or(0),
            random_hex(4),
            ext
        );
        let envelope = seal_image_bytes(&bytes_guard, pass_guard.as_bytes(), &filename)?;
        atomic_write_bytes(&assets_dir.join(&filename), &envelope)?;
        Ok(format!("assets/{}", filename))
    }

    pub fn read_encrypted_image_inner(file_path: &str, password: &str) -> Result<Vec<u8>, String> {
        let path = validate_secure_path(file_path, None)?;
        let len = fs::metadata(&path)
            .map_err(|e| format!("Failed to read file metadata: {}", e))?
            .len();
        if len > MAX_FILE_SIZE_BYTES + IMAGE_ENVELOPE_OVERHEAD as u64 {
            return Err("Encrypted image exceeds the 25 MB safety limit.".into());
        }
        let raw = fs::read(&path).map_err(|e| format!("Failed to read file: {}", e))?;
        let mut plain = open_image_bytes(&raw, password.as_bytes(), asset_file_name(&path)?)?;
        Ok(std::mem::take(&mut *plain))
    }

    /// Decrypts an image in memory and hands the bytes to the webview as a raw binary
    /// response. Nothing is written to disk.
    #[tauri::command(async)]
    pub fn read_encrypted_image(
        file_path: String,
        password: String,
    ) -> Result<tauri::ipc::Response, String> {
        let pass_guard = Zeroizing::new(password);
        read_encrypted_image_inner(&file_path, &pass_guard).map(tauri::ipc::Response::new)
    }

    #[derive(Serialize, Debug)]
    pub struct SealReport {
        /// The note's Markdown with converted image links (`x.png` -> `x.png.enc`).
        pub markdown: String,
        /// Plaintext images that were encrypted.
        pub sealed: usize,
        /// Already-encrypted images moved to the new passphrase.
        pub rekeyed: usize,
        pub originals_removed: usize,
        /// Originals that could not be removed (outside the workspace, or locked).
        pub originals_kept: usize,
        /// Local image references that were left untouched, with the reason.
        pub skipped: Vec<String>,
    }

    fn markdown_options() -> pulldown_cmark::Options {
        let mut options = pulldown_cmark::Options::empty();
        options.insert(pulldown_cmark::Options::ENABLE_TABLES);
        options.insert(pulldown_cmark::Options::ENABLE_STRIKETHROUGH);
        options.insert(pulldown_cmark::Options::ENABLE_TASKLISTS);
        options
    }

    /// Every image in the Markdown: its destination and, when it is written inline as
    /// `![alt](dest)`, the byte span of `dest` in the source. Reference-style images have no
    /// span and are therefore never rewritten.
    fn image_destinations(markdown: &str) -> Vec<(String, Option<(usize, usize)>)> {
        let mut found = Vec::new();
        let parser = pulldown_cmark::Parser::new_ext(markdown, markdown_options());
        for (event, range) in parser.into_offset_iter() {
            if let pulldown_cmark::Event::Start(pulldown_cmark::Tag::Image { dest_url, .. }) = event
            {
                let dest = dest_url.to_string();
                let span = markdown.get(range.clone()).and_then(|segment| {
                    let anchor = segment.rfind("](").map(|i| i + 2)?;
                    let offset = segment[anchor..].find(dest.as_str())?;
                    let start = range.start + anchor + offset;
                    Some((start, start + dest.len()))
                });
                found.push((dest, span));
            }
        }
        found
    }

    /// Resolves an image destination to a real file strictly inside the note's own folder.
    /// Anything with a scheme, a drive letter, an absolute path, `..`, or a symlink is refused.
    fn resolve_note_asset(note_dir: &Path, dest: &str) -> Option<PathBuf> {
        if dest.is_empty()
            || dest.contains('\0')
            || dest.contains(':')
            || dest.starts_with('/')
            || dest.starts_with('\\')
        {
            return None;
        }
        let relative = PathBuf::from(dest.replace('\\', "/"));
        if relative
            .components()
            .any(|c| !matches!(c, Component::Normal(_) | Component::CurDir))
        {
            return None;
        }
        let candidate = note_dir.join(&relative);
        let meta = fs::symlink_metadata(&candidate).ok()?;
        if !meta.file_type().is_file() {
            return None;
        }
        let canonical = fs::canonicalize(&candidate).ok()?;
        canonical.starts_with(note_dir).then_some(canonical)
    }

    fn is_local_reference(dest: &str) -> bool {
        !dest.is_empty() && !dest.contains(':') && !dest.starts_with('#')
    }

    /// Encrypts a note together with its images, as one all-or-nothing operation.
    ///
    /// 1. Images already encrypted under `previous_password` are re-encrypted under `password`
    ///    into NEW files (`pic.png.enc` -> `pic_k<8 hex>.png.enc`); the old files are left alone.
    /// 2. Plaintext images referenced by the note are encrypted next to the originals.
    /// 3. The links are rewritten and the note is written with `save_encrypted_markdown`. That
    ///    single atomic rename is the switch-over.
    /// Until step 3 succeeds nothing that already existed has been changed, so an error or a
    /// crash leaves the old note and its images fully readable. On an error the new files are
    /// removed; after a crash they remain as unreferenced ciphertext.
    /// 4. Only after success are the superseded encrypted images removed and, if asked, the
    ///    plaintext originals, under the same strict-workspace rule as `delete_note_file`.
    #[tauri::command(async)]
    pub fn seal_note(
        file_path: String,
        content: String,
        password: String,
        previous_password: Option<String>,
        remove_plaintext_assets: bool,
    ) -> Result<SealReport, String> {
        let pass_guard = Zeroizing::new(password);
        let previous_guard = previous_password.map(Zeroizing::new);
        let content_guard = Zeroizing::new(content);

        if pass_guard.trim().is_empty() {
            return Err("Passphrase cannot be empty.".into());
        }
        if content_guard.len() as u64 > MAX_FILE_SIZE_BYTES {
            return Err("Note content exceeds the 25 MB maximum size limit.".into());
        }

        let note_path = validate_secure_path(&file_path, None)?;
        let note_dir = note_path
            .parent()
            .ok_or_else(|| "Note path has no parent directory.".to_string())?;
        let note_dir = fs::canonicalize(note_dir)
            .map_err(|e| format!("Note directory is inaccessible: {}", e))?;

        // ---- Plan: no side effects below this line until every reference is classified ----
        let occurrences = image_destinations(&content_guard);
        let unlocatable: HashSet<&str> = occurrences
            .iter()
            .filter(|(_, span)| span.is_none())
            .map(|(dest, _)| dest.as_str())
            .collect();
        let needs_rekey = previous_guard
            .as_ref()
            .is_some_and(|previous| previous.as_str() != pass_guard.as_str());

        let mut seen: HashSet<&str> = HashSet::new();
        // (file as it is now, file to create). One entry per file, however many links use it.
        let mut to_rekey: Vec<(PathBuf, PathBuf)> = Vec::new();
        let mut to_seal: Vec<(PathBuf, PathBuf)> = Vec::new();
        // Link destination as written in the note -> what it becomes.
        let mut replacements: HashMap<&str, String> = HashMap::new();
        let mut skipped: Vec<String> = Vec::new();

        for (dest, _) in &occurrences {
            if !seen.insert(dest.as_str()) || !is_local_reference(dest) {
                continue;
            }
            let Some(source) = resolve_note_asset(&note_dir, dest) else {
                skipped.push(format!("{} (not a file inside the note's folder)", dest));
                continue;
            };
            let file_name = source
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or_default()
                .to_string();
            let lower = file_name.to_lowercase();

            if lower.ends_with(".enc") {
                if !(needs_rekey && is_image_envelope(&source)) {
                    continue;
                }
                // A re-encrypted image gets a new file name, so its link has to be rewritten.
                if unlocatable.contains(dest.as_str()) {
                    return Err(format!(
                        "Cannot change the passphrase: the encrypted image {} is linked with a reference-style link. Change it to an inline link first.",
                        dest
                    ));
                }
                let target = match to_rekey.iter().find(|(current, _)| *current == source) {
                    Some((_, planned)) => planned.clone(),
                    None => {
                        let planned = (0..8)
                            .map(|_| source.with_file_name(rekeyed_file_name(&file_name)))
                            .find(|candidate| !candidate.exists())
                            .ok_or_else(|| {
                                "Could not pick a free file name for a re-encrypted image."
                                    .to_string()
                            })?;
                        to_rekey.push((source.clone(), planned.clone()));
                        planned
                    }
                };
                replacements.insert(
                    dest.as_str(),
                    with_link_file_name(dest, asset_file_name(&target)?),
                );
                continue;
            }
            let extension = lower.rsplit('.').next().unwrap_or_default();
            if !SEALABLE_IMAGE_EXTENSIONS.contains(&extension) {
                skipped.push(format!("{} (not an image type)", dest));
                continue;
            }
            if unlocatable.contains(dest.as_str()) {
                skipped.push(format!("{} (reference-style link, cannot be rewritten)", dest));
                continue;
            }
            if fs::metadata(&source).map(|m| m.len()).unwrap_or(u64::MAX) > MAX_FILE_SIZE_BYTES {
                skipped.push(format!("{} (larger than 25 MB)", dest));
                continue;
            }
            if !to_seal.iter().any(|(planned, _)| *planned == source) {
                let target = source.with_file_name(format!("{}.enc", file_name));
                if target.exists() {
                    skipped.push(format!("{} ({}.enc already exists)", dest, file_name));
                    continue;
                }
                to_seal.push((source, target));
            }
            replacements.insert(dest.as_str(), format!("{}.enc", dest));
        }

        // ---- Execute. Only new files are written here; nothing that already exists is changed
        // until the note itself has been written. A crash or an error at any point therefore
        // leaves the old note and every one of its images readable with the old passphrase. ----
        let mut created: Vec<PathBuf> = Vec::new();

        let outcome = {
            let mut run = || -> Result<String, String> {
                if let Some(previous) = previous_guard.as_ref().filter(|_| needs_rekey) {
                    for (current, target) in &to_rekey {
                        let len = fs::metadata(current)
                            .map_err(|e| format!("Failed to read encrypted image: {}", e))?
                            .len();
                        if len > MAX_FILE_SIZE_BYTES + IMAGE_ENVELOPE_OVERHEAD as u64 {
                            return Err("Encrypted image exceeds the 25 MB safety limit.".into());
                        }
                        let raw = fs::read(current)
                            .map_err(|e| format!("Failed to read encrypted image: {}", e))?;
                        let plain =
                            open_image_bytes(&raw, previous.as_bytes(), asset_file_name(current)?)?;
                        let envelope = seal_image_bytes(
                            &plain,
                            pass_guard.as_bytes(),
                            asset_file_name(target)?,
                        )?;
                        created.push(target.clone());
                        write_verified(target, &envelope)?;
                    }
                }

                for (source, target) in &to_seal {
                    let plain = Zeroizing::new(
                        fs::read(source).map_err(|e| format!("Failed to read image: {}", e))?,
                    );
                    let envelope =
                        seal_image_bytes(&plain, pass_guard.as_bytes(), asset_file_name(target)?)?;
                    created.push(target.clone());
                    // Confirmed on disk before the original may be removed.
                    write_verified(target, &envelope)?;
                }

                let mut rewritten =
                    String::with_capacity(content_guard.len() + 16 * replacements.len());
                let mut cursor = 0;
                for (dest, span) in &occurrences {
                    let Some((start, end)) = *span else { continue };
                    let Some(replacement) = replacements.get(dest.as_str()) else {
                        continue;
                    };
                    if start < cursor {
                        continue;
                    }
                    rewritten.push_str(&content_guard[cursor..start]);
                    rewritten.push_str(replacement);
                    cursor = end;
                }
                rewritten.push_str(&content_guard[cursor..]);

                // The switch-over: one atomic rename moves the note to the new links and the
                // new passphrase together.
                save_encrypted_markdown(
                    file_path.clone(),
                    rewritten.clone(),
                    pass_guard.as_str().to_string(),
                )?;
                Ok(rewritten)
            };
            run()
        };

        let markdown = match outcome {
            Ok(markdown) => markdown,
            Err(error) => {
                // Every path in `created` was checked not to exist before it was written.
                for path in &created {
                    let _ = fs::remove_file(path);
                }
                return Err(error);
            }
        };

        // The note no longer points at the old ciphertext. It is still encrypted under the old
        // passphrase, so a leftover copy (if removal fails) reveals nothing.
        for (current, _) in &to_rekey {
            let _ = fs::remove_file(current);
        }

        let mut originals_removed = 0;
        let mut originals_kept = 0;
        if remove_plaintext_assets {
            for (source, _) in &to_seal {
                match source.to_str().map(|s| delete_note_file(s.to_string())) {
                    Some(Ok(())) => originals_removed += 1,
                    _ => originals_kept += 1,
                }
            }
        }

        Ok(SealReport {
            markdown,
            sealed: to_seal.len(),
            rekeyed: to_rekey.len(),
            originals_removed,
            originals_kept,
            skipped,
        })
    }

    /// Writes an image envelope and reads it back, so nothing is ever removed on the strength
    /// of a write that did not really reach the disk.
    fn write_verified(target: &Path, envelope: &[u8]) -> Result<(), String> {
        atomic_write_bytes(target, envelope)?;
        let written =
            fs::read(target).map_err(|e| format!("Failed to verify encrypted image: {}", e))?;
        if written != envelope {
            return Err("Encrypted image verification failed after write.".into());
        }
        Ok(())
    }

    /// `pic.png.enc` -> `pic_k1a2b3c4d.png.enc`. An earlier `_k<8 hex>` tag is replaced rather
    /// than stacked, so names do not grow with every passphrase change.
    fn rekeyed_file_name(file_name: &str) -> String {
        let cut = file_name.len().saturating_sub(4);
        let inner = if file_name.is_char_boundary(cut)
            && file_name[cut..].eq_ignore_ascii_case(".enc")
        {
            &file_name[..cut]
        } else {
            file_name
        };
        let (stem, extension) = match inner.rfind('.') {
            Some(dot) if dot > 0 => inner.split_at(dot),
            _ => (inner, ""),
        };
        let bytes = stem.as_bytes();
        let stem = if bytes.len() > 10
            && bytes[bytes.len() - 10] == b'_'
            && bytes[bytes.len() - 9] == b'k'
            && bytes[bytes.len() - 8..]
                .iter()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(b))
        {
            &stem[..stem.len() - 10]
        } else {
            stem
        };
        format!("{}_k{}{}.enc", stem, random_hex(4), extension)
    }

    /// Swaps the file name at the end of a Markdown link destination, keeping its folder part.
    fn with_link_file_name(dest: &str, new_name: &str) -> String {
        let cut = dest.rfind(['/', '\\']).map(|i| i + 1).unwrap_or(0);
        format!("{}{}", &dest[..cut], new_name)
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
            "ivory" => ("#f1e2c8", "#22302a", "#f9ebd7", "#d9c9a9", "#046a38"),
            "neon" => ("#080808", "#ededed", "#111111", "#2a2a2a", "#d4ff3f"),
            "nordic" => ("#1c2028", "#d8dee9", "#232832", "#3a4252", "#88c0d0"),
            // "cobalt" and any unknown value fall back to the default dark palette.
            _ => ("#05070c", "#dfe5f0", "#0b0f18", "#222b3d", "#7aa6f5"),
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
            commands::save_encrypted_image,
            commands::read_encrypted_image,
            commands::seal_note,
            commands::export_to_html
        ])
        .run(tauri::generate_context!())
        .expect("error while running MarkForge application");
}