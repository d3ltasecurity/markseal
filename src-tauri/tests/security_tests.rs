use markforge_lib::*;
use std::fs;
use std::sync::Mutex;

static TEST_MUTEX: Mutex<()> = Mutex::new(());

#[test]
fn test_hardened_encryption_and_tamper_detection() {
    let _guard = TEST_MUTEX.lock().unwrap();
    let temp_dir = std::env::temp_dir().join("mf_test_enc");
    let _ = fs::create_dir_all(&temp_dir);
    set_workspace_root_inner(temp_dir.to_str().unwrap()).unwrap();

    let test_file = temp_dir.join("markforge_hardened_vault.md.enc");
    let path_str = test_file.to_str().unwrap().to_string();

    let secret_note = "# Top Secret Vault\nZero-Knowledge Unicode Test: 🔐 🚀 ₹100%";
    let password = "CorrectHorseBatteryStaple#2026!";

    save_encrypted_markdown(path_str.clone(), secret_note.into(), password.into()).unwrap();
    assert!(is_encrypted_note(path_str.clone()).unwrap());

    let decrypted = read_encrypted_markdown(path_str.clone(), password.into()).unwrap();
    assert_eq!(decrypted, secret_note);

    assert!(read_encrypted_markdown(path_str.clone(), "WrongPass!".into()).is_err());

    let raw = fs::read_to_string(&test_file).unwrap();
    let tampered = raw.replacen("MARKFORGE_ENC_V1", "MARKFORGE_ENC_V0", 1);
    fs::write(&test_file, tampered).unwrap();
    assert!(read_encrypted_markdown(path_str.clone(), password.into()).is_err());

    let _ = delete_note_file(path_str);
    set_active_workspace_bound(None);
    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_path_traversal_null_byte_and_workspace_confinement() {
    let _guard = TEST_MUTEX.lock().unwrap();
    assert!(validate_secure_path("../../Windows/System32/cmd.exe", None).is_err());
    assert!(validate_secure_path("C:\\temp\\note.md\0.txt", None).is_err());

    // Test active workspace confinement blocks outside absolute paths
    let temp_ws = std::env::temp_dir().join("markforge_ws_bound_test");
    let _ = fs::create_dir_all(&temp_ws);
    set_workspace_root_inner(temp_ws.to_str().unwrap()).unwrap();

    let outside_file = std::env::temp_dir().join("outside_escape.md");
    assert!(validate_secure_path(outside_file.to_str().unwrap(), None).is_err());

    // Reset workspace bound for other tests
    set_active_workspace_bound(None);
    let _ = fs::remove_dir_all(&temp_ws);
}

#[test]
fn test_pasted_image_contract_saves_relative_to_note() {
    let _guard = TEST_MUTEX.lock().unwrap();
    let temp_dir = std::env::temp_dir().join("markforge_img_test");
    let _ = fs::create_dir_all(&temp_dir);
    set_workspace_root_inner(temp_dir.to_str().unwrap()).unwrap();

    let note_path = temp_dir.join("my_note.md");
    fs::write(&note_path, "# Note").unwrap();

    let rel_path = save_pasted_image(
        note_path.to_str().unwrap().to_string(),
        vec![137, 80, 78, 71, 13, 10, 26, 10], // PNG header bytes
        "PNG".to_string(),
    )
        .unwrap();

    assert!(rel_path.starts_with("assets/img_"));
    assert!(rel_path.ends_with(".png"));
    assert!(temp_dir.join(&rel_path).exists());

    set_active_workspace_bound(None);
    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_html_export_strips_xss_payloads() {
    let _guard = TEST_MUTEX.lock().unwrap();
    let temp_dir = std::env::temp_dir().join("mf_test_xss");
    let _ = fs::create_dir_all(&temp_dir);
    set_workspace_root_inner(temp_dir.to_str().unwrap()).unwrap();

    let out_html = temp_dir.join("markforge_xss_test.html");
    let path_str = out_html.to_str().unwrap().to_string();

    let malicious_md = "# Hello\n<script>alert('pwned')</script>\n<img src=x onerror=alert(1)>";
    let malicious_title = "Doc </title><script>alert(2)</script>";

    export_to_html(
        path_str.clone(),
        malicious_md.into(),
        malicious_title.into(),
        "dark".into(),
    )
        .unwrap();

    let exported = fs::read_to_string(&out_html).unwrap();
    assert!(!exported.contains("<script>alert('pwned')</script>"));
    assert!(!exported.contains("onerror="));
    assert!(exported.contains("&lt;/title&gt;&lt;script&gt;"));

    let _ = fs::remove_file(out_html);
    set_active_workspace_bound(None);
    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_non_dialog_outside_path_rejected() {
    let _guard = TEST_MUTEX.lock().unwrap();
    clear_dialog_authorized_paths();
    let base_temp = std::env::temp_dir().join("mf_test_unauth_outside");
    let ws_dir = base_temp.join("workspace");
    let outside_dir = base_temp.join("outside");
    let _ = fs::create_dir_all(&ws_dir);
    let _ = fs::create_dir_all(&outside_dir);

    set_workspace_root_inner(ws_dir.to_str().unwrap()).unwrap();

    let outside_md = outside_dir.join("unauth.md");
    let outside_md_str = outside_md.to_str().unwrap().to_string();
    let outside_html = outside_dir.join("unauth.html");
    let outside_html_str = outside_html.to_str().unwrap().to_string();
    let outside_enc = outside_dir.join("unauth.md.enc");
    let outside_enc_str = outside_enc.to_str().unwrap().to_string();

    // Verify all operations fail on un-authorized path outside workspace
    assert!(save_markdown_file(outside_md_str.clone(), "# Content".into()).is_err());
    assert!(read_markdown_file(outside_md_str.clone()).is_err());
    assert!(save_encrypted_markdown(outside_enc_str.clone(), "# Secret".into(), "pass".into()).is_err());
    assert!(export_to_html(outside_html_str.clone(), "# HTML".into(), "Title".into(), "dark".into()).is_err());

    set_active_workspace_bound(None);
    clear_dialog_authorized_paths();
    let _ = fs::remove_dir_all(&base_temp);
}

#[test]
fn test_authorized_dialog_path_succeeds_for_save_and_export() {
    let _guard = TEST_MUTEX.lock().unwrap();
    clear_dialog_authorized_paths();
    let base_temp = std::env::temp_dir().join("mf_test_auth_outside");
    let ws_dir = base_temp.join("workspace");
    let outside_dir = base_temp.join("outside");
    let _ = fs::create_dir_all(&ws_dir);
    let _ = fs::create_dir_all(&outside_dir);

    set_workspace_root_inner(ws_dir.to_str().unwrap()).unwrap();

    let outside_md = outside_dir.join("dialog_saved.md");
    let outside_md_str = outside_md.to_str().unwrap().to_string();
    let outside_html = outside_dir.join("dialog_export.html");
    let outside_html_str = outside_html.to_str().unwrap().to_string();

    // Authorize paths via dialog session allowlist
    authorize_dialog_path_inner(&outside_md_str).unwrap();
    authorize_dialog_path_inner(&outside_html_str).unwrap();

    // 1. save_markdown_file should succeed
    assert!(save_markdown_file(outside_md_str.clone(), "# Dialog Content".into()).is_ok());
    assert!(outside_md.exists());

    // 2. read_markdown_file should succeed
    let content = read_markdown_file(outside_md_str.clone()).unwrap();
    assert_eq!(content, "# Dialog Content");

    // 3. export_to_html should succeed
    assert!(export_to_html(outside_html_str.clone(), "# HTML Content".into(), "Doc".into(), "dark".into()).is_ok());
    assert!(outside_html.exists());

    set_active_workspace_bound(None);
    clear_dialog_authorized_paths();
    let _ = fs::remove_dir_all(&base_temp);
}

#[test]
fn test_delete_outside_workspace_always_rejected() {
    let _guard = TEST_MUTEX.lock().unwrap();
    clear_dialog_authorized_paths();
    let base_temp = std::env::temp_dir().join("mf_test_delete_strict");
    let ws_dir = base_temp.join("workspace");
    let outside_dir = base_temp.join("outside");
    let _ = fs::create_dir_all(&ws_dir);
    let _ = fs::create_dir_all(&outside_dir);

    set_workspace_root_inner(ws_dir.to_str().unwrap()).unwrap();

    let outside_file = outside_dir.join("cannot_delete.md");
    fs::write(&outside_file, "# Important Outside Note").unwrap();
    let outside_str = outside_file.to_str().unwrap().to_string();

    // Even if path was authorized by dialog, delete_note_file MUST be rejected
    authorize_dialog_path_inner(&outside_str).unwrap();

    let delete_res = delete_note_file(outside_str.clone());
    assert!(delete_res.is_err(), "delete_note_file must be rejected for outside paths even if dialog-authorized");
    assert!(outside_file.exists(), "Outside file must not have been deleted");

    set_active_workspace_bound(None);
    clear_dialog_authorized_paths();
    let _ = fs::remove_dir_all(&base_temp);
}