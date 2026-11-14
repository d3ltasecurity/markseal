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

#[test]
fn test_no_workspace_and_no_dialog_means_no_file_access() {
    let _guard = TEST_MUTEX.lock().unwrap();
    clear_dialog_authorized_paths();
    set_active_workspace_bound(None);

    let base_temp = std::env::temp_dir().join("mf_test_no_workspace_access");
    let _ = fs::remove_dir_all(&base_temp);
    let note_dir = base_temp.join("notes");
    let other_dir = base_temp.join("elsewhere");
    fs::create_dir_all(&note_dir).unwrap();
    fs::create_dir_all(&other_dir).unwrap();

    let existing = note_dir.join("private.md");
    fs::write(&existing, "# Private").unwrap();
    let existing_str = existing.to_str().unwrap().to_string();
    let new_md = note_dir.join("planted.md").to_str().unwrap().to_string();
    let new_enc = note_dir.join("planted.md.enc").to_str().unwrap().to_string();
    let new_html = note_dir.join("planted.html").to_str().unwrap().to_string();

    // Nothing authorizes these paths: every read and write must be refused.
    assert!(validate_secure_path(&existing_str, None).is_err());
    assert!(read_markdown_file(existing_str.clone()).is_err());
    assert!(is_encrypted_note(existing_str.clone()).is_err());
    assert!(save_markdown_file(existing_str.clone(), "# Overwritten".into()).is_err());
    assert!(save_markdown_file(new_md.clone(), "# Planted".into()).is_err());
    assert!(save_encrypted_markdown(new_enc.clone(), "# Secret".into(), "passphrase".into()).is_err());
    assert!(export_to_html(new_html.clone(), "# HTML".into(), "Title".into(), "dark".into()).is_err());
    assert_eq!(fs::read_to_string(&existing).unwrap(), "# Private", "the file must be untouched");
    assert!(!std::path::Path::new(&new_md).exists());
    assert!(!std::path::Path::new(&new_enc).exists());
    assert!(!std::path::Path::new(&new_html).exists());

    // A dialog pick in a different folder does not open this one.
    authorize_dialog_path_inner(other_dir.join("picked.md").to_str().unwrap()).unwrap();
    assert!(read_markdown_file(existing_str.clone()).is_err());
    assert!(save_markdown_file(new_md.clone(), "# Planted".into()).is_err());

    // A dialog pick of the note itself does.
    authorize_dialog_path_inner(&existing_str).unwrap();
    assert_eq!(read_markdown_file(existing_str.clone()).unwrap(), "# Private");
    assert!(save_markdown_file(existing_str.clone(), "# Edited".into()).is_ok());

    clear_dialog_authorized_paths();
    let _ = fs::remove_dir_all(&base_temp);
}

#[test]
fn test_delete_without_workspace_requires_dialog_authorization() {
    let _guard = TEST_MUTEX.lock().unwrap();
    clear_dialog_authorized_paths();
    set_active_workspace_bound(None);

    let base_temp = std::env::temp_dir().join("mf_test_delete_no_workspace");
    let _ = fs::remove_dir_all(&base_temp);
    let note_dir = base_temp.join("notes");
    let other_dir = base_temp.join("elsewhere");
    fs::create_dir_all(&note_dir).unwrap();
    fs::create_dir_all(&other_dir).unwrap();

    let victim = note_dir.join("standalone.md");
    fs::write(&victim, "# Not chosen in any dialog").unwrap();
    let victim_str = victim.to_str().unwrap().to_string();

    // No workspace and no dialog authorization: the delete must be refused.
    assert!(
        delete_note_file(victim_str.clone()).is_err(),
        "with no workspace open, an un-authorized path must not be deletable"
    );
    assert!(victim.exists(), "the un-authorized file must still be on disk");
    assert!(secure_shred_file(victim_str.clone()).is_err());
    assert!(victim.exists());

    // Authorizing a path in a different folder does not help.
    let unrelated = other_dir.join("picked.md");
    authorize_dialog_path_inner(unrelated.to_str().unwrap()).unwrap();
    assert!(delete_note_file(victim_str.clone()).is_err());
    assert!(victim.exists());

    // Once the user has picked this note in a dialog, deleting it works.
    authorize_dialog_path_inner(&victim_str).unwrap();
    assert!(delete_note_file(victim_str.clone()).is_ok());
    assert!(!victim.exists(), "a dialog-authorized note must be deletable");

    clear_dialog_authorized_paths();
    let _ = fs::remove_dir_all(&base_temp);
}
fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|window| window == needle)
}

fn sample_image_payload() -> Vec<u8> {
    let mut payload = vec![137, 80, 78, 71, 13, 10, 26, 10]; // PNG header bytes
    payload.extend_from_slice(b"PLAINTEXT-PIXEL-MARKER-PLAINTEXT-PIXEL-MARKER");
    payload
}

#[test]
fn test_encrypted_image_never_touches_disk_in_plaintext() {
    let _guard = TEST_MUTEX.lock().unwrap();
    let temp_dir = std::env::temp_dir().join("markforge_enc_img_test");
    let _ = fs::remove_dir_all(&temp_dir);
    fs::create_dir_all(&temp_dir).unwrap();
    set_workspace_root_inner(temp_dir.to_str().unwrap()).unwrap();

    let note_path = temp_dir.join("vault.md.enc");
    let note_str = note_path.to_str().unwrap().to_string();
    let password = "CorrectHorseBatteryStaple#2026!";
    let payload = sample_image_payload();

    let rel_path =
        save_encrypted_image(note_str.clone(), payload.clone(), "PNG".into(), password.into())
            .unwrap();
    assert!(rel_path.starts_with("assets/img_"));
    assert!(rel_path.ends_with(".png.enc"));

    let image_path = temp_dir.join(&rel_path);
    let image_str = image_path.to_str().unwrap().to_string();
    let on_disk = fs::read(&image_path).unwrap();
    assert!(on_disk.starts_with(IMG_HEADER), "image envelope must carry the image header");
    assert!(
        !contains_bytes(&on_disk, b"PLAINTEXT-PIXEL-MARKER"),
        "image bytes must not be readable on disk"
    );
    assert!(!contains_bytes(&on_disk, &payload[..8]), "PNG header must not be readable on disk");

    assert_eq!(read_encrypted_image_inner(&image_str, password).unwrap(), payload);
    assert!(read_encrypted_image_inner(&image_str, "WrongPass!").is_err());

    // Integrity: a single flipped bit must fail authentication.
    let mut tampered = on_disk.clone();
    let last = tampered.len() - 1;
    tampered[last] ^= 0x01;
    fs::write(&image_path, &tampered).unwrap();
    assert!(read_encrypted_image_inner(&image_str, password).is_err());

    // Domain separation: a note envelope is never accepted as an image.
    save_encrypted_markdown(note_str.clone(), "# Note".into(), password.into()).unwrap();
    assert!(read_encrypted_image_inner(&note_str, password).is_err());

    // Empty passphrases are refused before anything is written.
    assert!(save_encrypted_image(note_str, payload, "png".into(), "   ".into()).is_err());

    set_active_workspace_bound(None);
    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_seal_note_encrypts_existing_images_and_rewrites_links() {
    let _guard = TEST_MUTEX.lock().unwrap();
    let base = std::env::temp_dir().join("markforge_seal_test");
    let _ = fs::remove_dir_all(&base);
    let ws_dir = base.join("workspace");
    fs::create_dir_all(ws_dir.join("assets")).unwrap();
    set_workspace_root_inner(ws_dir.to_str().unwrap()).unwrap();

    let payload = sample_image_payload();
    let picture = ws_dir.join("assets").join("pic.png");
    let not_an_image = ws_dir.join("assets").join("keep.txt");
    let outside = base.join("outside.png");
    fs::write(&picture, &payload).unwrap();
    fs::write(&not_an_image, "must survive").unwrap();
    fs::write(&outside, &payload).unwrap();

    // A hard link planted in the note folder that shares its data with a file outside it.
    let precious = base.join("precious.png");
    let linked = ws_dir.join("assets").join("linked.png");
    fs::write(&precious, &payload).unwrap();
    fs::hard_link(&precious, &linked).unwrap();
    assert_eq!(hard_link_count(&precious), Some(2));

    let markdown = concat!(
        "# Title\n\n",
        "![a](assets/pic.png)\n\n",
        "![b](assets/pic.png \"assets/pic.png\")\n\n",
        "![c](../outside.png)\n\n",
        "![d](assets/keep.txt)\n\n",
        "![f](assets/linked.png)\n\n",
        "![e](https://example.com/remote.png)\n",
    );
    let note_path = ws_dir.join("note.md.enc");
    let note_str = note_path.to_str().unwrap().to_string();
    let password = "CorrectHorseBatteryStaple#2026!";

    let report = seal_note(note_str.clone(), markdown.into(), password.into(), None, true).unwrap();

    assert_eq!(report.sealed, 2);
    assert_eq!(report.rekeyed, 0);
    assert_eq!(report.originals_removed, 2);
    assert_eq!(report.originals_kept, 0);

    // The hard-linked original is removed from the note folder, but the data it shared with
    // the outside file must not have been zero-overwritten on the way out.
    assert!(!linked.exists(), "hard-linked original must be unlinked from the note folder");
    assert_eq!(
        fs::read(&precious).unwrap(),
        payload,
        "a file sharing data through a hard link must never be zero-overwritten"
    );
    assert_eq!(hard_link_count(&precious), Some(1));
    assert!(report.markdown.contains("![f](assets/linked.png.enc)"));
    assert_eq!(report.skipped.len(), 2, "traversal and non-image references are skipped");

    // Both inline links are rewritten; the title text and remote URL are left alone.
    assert!(report.markdown.contains("![a](assets/pic.png.enc)"));
    assert!(report.markdown.contains("![b](assets/pic.png.enc \"assets/pic.png\")"));
    assert!(report.markdown.contains("![c](../outside.png)"));
    assert!(report.markdown.contains("![d](assets/keep.txt)"));
    assert!(report.markdown.contains("![e](https://example.com/remote.png)"));

    assert!(!picture.exists(), "plaintext original must be removed");
    let sealed = ws_dir.join("assets").join("pic.png.enc");
    assert!(!contains_bytes(&fs::read(&sealed).unwrap(), b"PLAINTEXT-PIXEL-MARKER"));
    assert_eq!(read_encrypted_image_inner(sealed.to_str().unwrap(), password).unwrap(), payload);

    // Crafted references can never get other files encrypted or deleted.
    assert_eq!(fs::read(&outside).unwrap(), payload, "file outside the note folder is untouched");
    assert_eq!(fs::read_to_string(&not_an_image).unwrap(), "must survive");

    // The stored note is the rewritten Markdown.
    assert_eq!(read_encrypted_markdown(note_str, password.into()).unwrap(), report.markdown);

    set_active_workspace_bound(None);
    let _ = fs::remove_dir_all(&base);
}

#[test]
fn test_seal_note_rekeys_images_and_rolls_back_on_failure() {
    let _guard = TEST_MUTEX.lock().unwrap();
    let temp_dir = std::env::temp_dir().join("markforge_rekey_test");
    let _ = fs::remove_dir_all(&temp_dir);
    fs::create_dir_all(&temp_dir).unwrap();
    set_workspace_root_inner(temp_dir.to_str().unwrap()).unwrap();

    let note_path = temp_dir.join("note.md.enc");
    let note_str = note_path.to_str().unwrap().to_string();
    let old_password = "OldPassphrase#2026!";
    let new_password = "NewPassphrase#2027!";
    let payload = sample_image_payload();

    let first = save_encrypted_image(
        note_str.clone(),
        payload.clone(),
        "png".into(),
        old_password.into(),
    )
    .unwrap();
    let foreign = save_encrypted_image(
        note_str.clone(),
        payload.clone(),
        "png".into(),
        "SomeoneElse#1".into(),
    )
    .unwrap();
    let first_str = temp_dir.join(&first).to_str().unwrap().to_string();

    let good_markdown = format!("# Note\n\n![1.00]({})\n", first);
    seal_note(note_str.clone(), good_markdown.clone(), old_password.into(), None, false).unwrap();

    let assets_dir = temp_dir.join("assets");
    let file_count = |dir: &std::path::Path| fs::read_dir(dir).unwrap().count();
    let link_target = |markdown: &str| -> String {
        markdown.split("](").nth(1).unwrap().split(')').next().unwrap().to_string()
    };
    let first_bytes = fs::read(&first_str).unwrap();
    assert_eq!(file_count(&assets_dir), 2);

    // The second image cannot be opened with the old passphrase, so the re-key fails AFTER the
    // first image was already re-encrypted. A re-key only ever writes new files, so the old
    // image must be byte-for-byte untouched (this is also the state a crash would leave), and
    // the half-finished new file must be gone.
    let bad_markdown = format!("# Note\n\n![1.00]({})\n\n![1.00]({})\n", first, foreign);
    let failed = seal_note(
        note_str.clone(),
        bad_markdown,
        new_password.into(),
        Some(old_password.into()),
        false,
    );
    assert!(failed.is_err());
    assert_eq!(
        fs::read(&first_str).unwrap(),
        first_bytes,
        "a re-key must never modify the existing encrypted image"
    );
    assert_eq!(read_encrypted_image_inner(&first_str, old_password).unwrap(), payload);
    assert_eq!(file_count(&assets_dir), 2, "a failed re-key must not leave new files behind");
    assert_eq!(
        read_encrypted_markdown(note_str.clone(), old_password.into()).unwrap(),
        good_markdown,
        "a failed re-key must leave the note untouched"
    );

    // A clean re-key moves the image and the note to the new passphrase together: the image is
    // written under a new name, the link follows it, and the superseded file is removed.
    let report = seal_note(
        note_str.clone(),
        good_markdown.clone(),
        new_password.into(),
        Some(old_password.into()),
        false,
    )
    .unwrap();
    assert_eq!(report.rekeyed, 1);
    assert_eq!(report.sealed, 0);
    let rekeyed_rel = link_target(&report.markdown);
    assert_ne!(rekeyed_rel, first, "a re-keyed image gets a new file name");
    assert!(rekeyed_rel.starts_with("assets/img_") && rekeyed_rel.ends_with(".png.enc"));
    assert!(rekeyed_rel.contains("_k"));
    let rekeyed_str = temp_dir.join(&rekeyed_rel).to_str().unwrap().to_string();
    assert_eq!(read_encrypted_image_inner(&rekeyed_str, new_password).unwrap(), payload);
    assert!(read_encrypted_image_inner(&rekeyed_str, old_password).is_err());
    assert!(
        !std::path::Path::new(&first_str).exists(),
        "the superseded encrypted image is removed once the note points at the new one"
    );
    assert_eq!(file_count(&assets_dir), 2);
    assert_eq!(
        read_encrypted_markdown(note_str.clone(), new_password.into()).unwrap(),
        report.markdown
    );

    // Changing the passphrase again replaces the tag instead of stacking another one.
    let again = seal_note(
        note_str.clone(),
        report.markdown.clone(),
        "ThirdPassphrase#2028!".into(),
        Some(new_password.into()),
        false,
    )
    .unwrap();
    let again_rel = link_target(&again.markdown);
    assert_ne!(again_rel, rekeyed_rel);
    assert_eq!(again_rel.len(), rekeyed_rel.len(), "file names must not grow on every re-key");
    let again_str = temp_dir.join(&again_rel).to_str().unwrap().to_string();
    assert_eq!(
        read_encrypted_image_inner(&again_str, "ThirdPassphrase#2028!").unwrap(),
        payload
    );

    set_active_workspace_bound(None);
    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_encrypted_image_is_bound_to_its_file_name() {
    let _guard = TEST_MUTEX.lock().unwrap();
    let temp_dir = std::env::temp_dir().join("markforge_img_name_test");
    let _ = fs::remove_dir_all(&temp_dir);
    fs::create_dir_all(&temp_dir).unwrap();
    set_workspace_root_inner(temp_dir.to_str().unwrap()).unwrap();

    let note_str = temp_dir.join("vault.md.enc").to_str().unwrap().to_string();
    let password = "CorrectHorseBatteryStaple#2026!";
    let payload_a = sample_image_payload();
    let mut payload_b = sample_image_payload();
    payload_b.extend_from_slice(b"-SECOND-IMAGE");

    let rel_a =
        save_encrypted_image(note_str.clone(), payload_a.clone(), "png".into(), password.into())
            .unwrap();
    let rel_b =
        save_encrypted_image(note_str.clone(), payload_b.clone(), "png".into(), password.into())
            .unwrap();
    let path_a = temp_dir.join(&rel_a);
    let path_b = temp_dir.join(&rel_b);
    let str_a = path_a.to_str().unwrap().to_string();
    let str_b = path_b.to_str().unwrap().to_string();
    let bytes_a = fs::read(&path_a).unwrap();
    let bytes_b = fs::read(&path_b).unwrap();

    // Swap: someone with disk access exchanges two images that share a passphrase.
    fs::write(&path_a, &bytes_b).unwrap();
    fs::write(&path_b, &bytes_a).unwrap();
    assert!(read_encrypted_image_inner(&str_a, password).is_err(), "a swapped image must fail");
    assert!(read_encrypted_image_inner(&str_b, password).is_err(), "a swapped image must fail");

    // Put back: both open again.
    fs::write(&path_a, &bytes_a).unwrap();
    fs::write(&path_b, &bytes_b).unwrap();
    assert_eq!(read_encrypted_image_inner(&str_a, password).unwrap(), payload_a);
    assert_eq!(read_encrypted_image_inner(&str_b, password).unwrap(), payload_b);

    // Rename: the same bytes under another name must fail authentication.
    let renamed = temp_dir.join("assets").join("renamed.png.enc");
    fs::rename(&path_a, &renamed).unwrap();
    assert!(
        read_encrypted_image_inner(renamed.to_str().unwrap(), password).is_err(),
        "a renamed image must fail"
    );
    fs::rename(&renamed, &path_a).unwrap();
    assert_eq!(read_encrypted_image_inner(&str_a, password).unwrap(), payload_a);

    set_active_workspace_bound(None);
    let _ = fs::remove_dir_all(&temp_dir);
}
