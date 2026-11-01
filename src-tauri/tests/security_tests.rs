use std::fs;
use markforge_lib::*;

#[test]
fn test_hardened_encryption_and_tamper_detection() {
    let temp_dir = std::env::temp_dir();
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

    let _ = secure_shred_file(path_str);
}

#[test]
fn test_path_traversal_and_null_byte_blocked() {
    assert!(validate_secure_path("../../Windows/System32/cmd.exe", None).is_err());
    assert!(validate_secure_path("C:\\temp\\note.md\0.txt", None).is_err());
}

#[test]
fn test_html_export_strips_xss_payloads() {
    let temp_dir = std::env::temp_dir();
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
}
