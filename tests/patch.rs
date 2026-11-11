//! Интеграционные тесты правки потока `PROJECT`.
//!
//! Данные синтетические: защищённый поток строится самой библиотекой, а случай
//! «без пароля» взят из публичного примера [MS-OVBA] §3.1.6. Реальные
//! пользовательские файлы не используются.

use unlock_macro::ovba::{self, ProtectionKind};
use unlock_macro::{CodePage, Mode};

const CLSID: &str = "{00000000-0000-0000-0000-000000000000}";

fn push_line(stream: &mut Vec<u8>, key: &str, value: &str) {
    stream.extend_from_slice(key.as_bytes());
    stream.extend_from_slice(b"=\"");
    stream.extend_from_slice(value.as_bytes());
    stream.extend_from_slice(b"\"\r\n");
}

/// Синтетический защищённый поток `PROJECT` (пароль хранится в виде хеша).
fn protected_stream(password: &[u8], salt: [u8; 4]) -> Vec<u8> {
    let structure = ovba::build_password_hash_struct(password, salt);
    let cmg = ovba::hex_encode(&ovba::entangle(&[0x05, 0, 0, 0], CLSID, 0x0E));
    let dpb = ovba::hex_encode(&ovba::entangle(&structure, CLSID, 0x0E));
    let gc = ovba::hex_encode(&ovba::entangle(&[0x00], CLSID, 0x0E));

    let mut stream = Vec::new();
    push_line(&mut stream, "ID", CLSID);
    push_line(&mut stream, "Document", "Module1/&H00000000");
    push_line(&mut stream, "CMG", &cmg);
    push_line(&mut stream, "DPB", &dpb);
    push_line(&mut stream, "GC", &gc);
    stream
}

#[test]
fn describe_reports_hash_with_built_salt() {
    let stream = protected_stream(b"hunter2", [1, 2, 3, 4]);
    let info = ovba::describe(&stream);
    assert_eq!(info.kind, ProtectionKind::Hash);
    assert_eq!(info.key, Some([1, 2, 3, 4]));
}

#[test]
fn unlock_marks_project_as_without_password() {
    let stream = protected_stream(b"hunter2", [1, 2, 3, 4]);
    let patched = ovba::patch_vba_project(&stream, &Mode::Unlock, CodePage::Cp1251).unwrap();
    assert_eq!(ovba::describe(&patched).kind, ProtectionKind::NoPassword);
}

#[test]
fn unlock_keeps_protection_line_lengths() {
    let stream = protected_stream(b"hunter2", [1, 2, 3, 4]);
    let patched = ovba::patch_vba_project(&stream, &Mode::Unlock, CodePage::Cp1251).unwrap();
    assert_eq!(stream.len(), patched.len());
}

#[test]
fn set_password_installs_matching_hash() {
    let stream = protected_stream(b"hunter2", [1, 2, 3, 4]);
    let patched = ovba::patch_vba_project(
        &stream,
        &Mode::SetPassword("s3cr3t".to_string()),
        CodePage::Cp1251,
    )
    .unwrap();
    let info = ovba::describe(&patched);
    assert_eq!(info.kind, ProtectionKind::Hash);
    let key = info.key.expect("key");
    let hash = info.hash.expect("hash");
    assert!(ovba::password_matches(b"s3cr3t", &key, &hash));
}

#[test]
fn set_password_rejects_other_password() {
    let stream = protected_stream(b"hunter2", [1, 2, 3, 4]);
    let patched = ovba::patch_vba_project(
        &stream,
        &Mode::SetPassword("s3cr3t".to_string()),
        CodePage::Cp1251,
    )
    .unwrap();
    let info = ovba::describe(&patched);
    let key = info.key.expect("key");
    let hash = info.hash.expect("hash");
    assert!(!ovba::password_matches(b"wrong", &key, &hash));
}

#[test]
fn unlock_fails_without_protection_lines() {
    let mut stream = Vec::new();
    push_line(&mut stream, "ID", CLSID);
    let result = ovba::patch_vba_project(&stream, &Mode::Unlock, CodePage::Cp1251);
    assert!(result.is_err());
}

/// Публичный пример из [MS-OVBA] §3.1.6 — проект без пароля.
fn spec_example_stream() -> Vec<u8> {
    let mut stream = Vec::new();
    push_line(&mut stream, "ID", "{917DED54-440B-4FD1-A5C1-74ACF261E600}");
    push_line(&mut stream, "CMG", "0705D8E3D8EDDBF1DBF1DBF1DBF1");
    push_line(&mut stream, "DPB", "0E0CD1ECDFF4E7F5E7F5E7");
    push_line(&mut stream, "GC", "1517CAF1D6F9D7F9D706");
    stream
}

#[test]
fn describe_decodes_public_spec_example_as_no_password() {
    let info = ovba::describe(&spec_example_stream());
    assert_eq!(info.kind, ProtectionKind::NoPassword);
}
