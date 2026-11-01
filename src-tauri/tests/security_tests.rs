use markforge_lib::*;
use std::fs;
use std::sync::Mutex;

static TEST_MUTEX: Mutex<()> = Mutex::new(());

#[test]
fn test_hardened_encryption_and_tamper_detection() {
    let _guard = TEST_MUTEX.lock().unwrap();
    let temp_dir = std::env::temp_dir().join("mf_test_enc");
    let _ = fs::create_dir_all(&temp_dir);
    set_workspace_root(temp_dir.to_str().unwrap().to_string()).unwrap();

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
    set_workspace_root(temp_ws.to_str().unwrap().to_string()).unwrap();

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
    set_workspace_root(temp_dir.to_str().unwrap().to_string()).unwrap();

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
    set_workspace_root(temp_dir.to_str().unwrap().to_string()).unwrap();

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