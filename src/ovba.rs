//! Формат защиты VBA-проекта ([MS-OVBA] §2.4.3 и §2.4.4).

use sha1::{Digest, Sha1};

use crate::codepage::decode_cp1251_lossy;
use crate::error::Error;

/// CLSID проекта, применяемый, когда пароль хранится в виде хеша
/// ([MS-OVBA] §2.3.1.2). Сумма байтов этой строки даёт `ProjKey = 0xAC`.
pub const ALL_ZERO_CLSID: &str = "{00000000-0000-0000-0000-000000000000}";

/// Значения защитных строк потока `PROJECT`.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ProtectionLines {
    /// `ID="…"` — CLSID проекта.
    pub id: Option<String>,
    /// `CMG="…"` — состояние защиты ([MS-OVBA] §2.3.1.15).
    pub cmg: Option<String>,
    /// `DPB="…"` — пароль либо хеш пароля ([MS-OVBA] §2.3.1.16).
    pub dpb: Option<String>,
    /// `GC="…"` — видимость проекта ([MS-OVBA] §2.3.1.17).
    pub gc: Option<String>,
}

/// Расшифрованная Encrypted Data Structure ([MS-OVBA] §2.4.3.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedEds {
    /// Seed.
    pub seed: u8,
    /// Версия (должна быть `2`).
    pub version: u8,
    /// Восстановленный `ProjKey`.
    pub projkey: u8,
    /// `ProjKey`, вычисленный из CLSID строки `ID`.
    pub projkey_expected: u8,
    /// Длина блока игнорируемых байтов.
    pub ignored_len: usize,
    /// Длина полезной нагрузки.
    pub length: usize,
    /// Полезная нагрузка.
    pub data: Vec<u8>,
}

/// Вариант защиты VBA-проекта.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtectionKind {
    /// Пароль не установлен.
    NoPassword,
    /// Хранится SHA-1-хеш пароля.
    Hash,
    /// Хранится пароль открытым текстом (VBA 5.0).
    Plaintext,
    /// Определить не удалось.
    Unknown,
}

/// Расшифрованное поле защиты.
#[derive(Debug, Clone)]
pub struct DecodedField {
    /// Исходное hex-значение строки.
    pub raw: String,
    /// Расшифрованная структура, если разбор удался.
    pub decoded: Option<DecodedEds>,
    /// Текст ошибки разбора, если он не удался.
    pub error: Option<String>,
}

/// Итоговое описание защиты VBA-проекта.
#[derive(Debug, Clone)]
pub struct ProtectionInfo {
    /// CLSID проекта.
    pub clsid: String,
    /// Состояние защиты `CMG`.
    pub cmg: Option<DecodedField>,
    /// Пароль/хеш `DPB`.
    pub dpb: Option<DecodedField>,
    /// Видимость `GC`.
    pub gc: Option<DecodedField>,
    /// Вариант защиты.
    pub kind: ProtectionKind,
    /// Соль (при варианте [`ProtectionKind::Hash`]).
    pub key: Option<[u8; 4]>,
    /// SHA-1-хеш (при варианте [`ProtectionKind::Hash`]).
    pub hash: Option<[u8; 20]>,
    /// Пароль открытым текстом (при варианте [`ProtectionKind::Plaintext`]).
    pub plaintext: Option<String>,
}

/// Самосцепляющийся XOR-поток ([MS-OVBA] §2.4.3).
#[derive(Debug, Clone, Copy)]
struct XorChain {
    unencrypted: u8,
    encrypted1: u8,
    encrypted2: u8,
}

impl XorChain {
    fn new(projkey: u8, projkey_enc: u8, version_enc: u8) -> Self {
        Self {
            unencrypted: projkey,
            encrypted1: projkey_enc,
            encrypted2: version_enc,
        }
    }

    fn step(&mut self, encrypted: u8) -> u8 {
        let plain = encrypted ^ self.encrypted2.wrapping_add(self.unencrypted);
        self.encrypted2 = self.encrypted1;
        self.encrypted1 = encrypted;
        self.unencrypted = plain;
        plain
    }

    fn put(&mut self, plain: u8) -> u8 {
        let encrypted = plain ^ self.encrypted2.wrapping_add(self.unencrypted);
        self.encrypted2 = self.encrypted1;
        self.encrypted1 = encrypted;
        self.unencrypted = plain;
        encrypted
    }
}

/// Контрольная сумма CLSID ([MS-OVBA] §2.4.3.2): сумма байтов по модулю 256.
#[must_use]
pub fn projkey_from_clsid(clsid: &str) -> u8 {
    clsid.bytes().fold(0u8, u8::wrapping_add)
}

/// Разобрать hex-строку в байты (регистр неважен).
#[must_use]
pub fn hex_decode(value: &str) -> Option<Vec<u8>> {
    let bytes = value.as_bytes();
    let (pairs, remainder) = bytes.as_chunks::<2>();
    if !remainder.is_empty() {
        return None;
    }
    let mut out = Vec::with_capacity(pairs.len());
    for &[high, low] in pairs {
        out.push((hex_nibble(high)? << 4) | hex_nibble(low)?);
    }
    Some(out)
}

fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// Закодировать байты в hex-строку верхнего регистра.
#[must_use]
pub fn hex_encode(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789ABCDEF";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        out.push(DIGITS[usize::from(byte >> 4)] as char);
        out.push(DIGITS[usize::from(byte & 0x0F)] as char);
    }
    out
}

/// Расшифровать структуру из hex-значения `CMG`/`DPB`/`GC`.
///
/// # Errors
///
/// [`Error::BadHex`], если значение не hex, и [`Error::Truncated`], если
/// структура обрезана.
pub fn untangle(hex_value: &str, clsid: &str) -> Result<DecodedEds, Error> {
    let bytes = hex_decode(hex_value).ok_or(Error::BadHex)?;
    if bytes.len() < 3 {
        return Err(Error::Truncated);
    }
    let seed = bytes[0];
    let version_enc = bytes[1];
    let projkey_enc = bytes[2];
    let projkey = seed ^ projkey_enc;
    let ignored_len = usize::from((seed & 6) / 2);

    let mut chain = XorChain::new(projkey, projkey_enc, version_enc);
    let mut pos = 3usize;

    let mut take = |chain: &mut XorChain| -> Result<u8, Error> {
        let byte = *bytes.get(pos).ok_or(Error::Truncated)?;
        pos += 1;
        Ok(chain.step(byte))
    };

    for _ in 0..ignored_len {
        take(&mut chain)?;
    }

    let mut length = 0usize;
    for shift in 0..4 {
        length |= usize::from(take(&mut chain)?) << (8 * shift);
    }

    let mut data = Vec::with_capacity(length);
    for _ in 0..length {
        data.push(take(&mut chain)?);
    }

    Ok(DecodedEds {
        seed,
        version: seed ^ version_enc,
        projkey,
        projkey_expected: projkey_from_clsid(clsid),
        ignored_len,
        length,
        data,
    })
}

/// Зашифровать байты в Encrypted Data Structure ([MS-OVBA] §2.4.3.2).
#[must_use]
pub fn entangle(data: &[u8], clsid: &str, seed: u8) -> Vec<u8> {
    let projkey = projkey_from_clsid(clsid);
    let version_enc = seed ^ 2;
    let projkey_enc = seed ^ projkey;
    let ignored_len = usize::from((seed & 6) / 2);

    let mut chain = XorChain::new(projkey, projkey_enc, version_enc);
    let mut out = Vec::with_capacity(7 + ignored_len + data.len());
    out.push(seed);
    out.push(version_enc);
    out.push(projkey_enc);

    for _ in 0..ignored_len {
        out.push(chain.put(0));
    }
    let length_bytes = data.len().to_le_bytes();
    for &byte in length_bytes.iter().take(4) {
        out.push(chain.put(byte));
    }
    for &byte in data {
        out.push(chain.put(byte));
    }
    out
}

/// Закодировать нагрузку так, чтобы hex-значение занимало ровно `total_len`
/// байт. Хвост при необходимости дополняется байтами, которые игнорируются
/// при разборе.
///
/// # Errors
///
/// [`Error::PayloadTooBig`], если нагрузка не помещается в `total_len`.
pub fn encode_padded(payload: &[u8], clsid: &str, total_len: usize) -> Result<String, Error> {
    let spare = total_len
        .checked_sub(7 + payload.len())
        .ok_or(Error::PayloadTooBig {
            payload: payload.len(),
            total: total_len,
        })?;
    let ignored = spare.min(3);
    let seed = u8::try_from(ignored * 2).unwrap_or(0);
    let mut encoded = entangle(payload, clsid, seed);
    debug_assert_eq!(encoded.len(), 7 + ignored + payload.len());
    encoded.resize(total_len, 0);
    Ok(hex_encode(&encoded))
}

/// Собрать 29-байтовую структуру хеша пароля ([MS-OVBA] §2.4.4.1).
///
/// Хеш равен `SHA-1(password ‖ key)`.
#[must_use]
pub fn build_password_hash_struct(password: &[u8], key: [u8; 4]) -> Vec<u8> {
    let mut hasher = Sha1::new();
    hasher.update(password);
    hasher.update(key);
    let digest = hasher.finalize();

    let (key_bits, key_encoded) = encode_nulls(&key);
    let (hash_bits, hash_encoded) = encode_nulls(&digest);
    let packed = (pack_bits(&key_bits) << 20) | pack_bits(&hash_bits);

    let mut out = Vec::with_capacity(29);
    out.push(0xFF);
    out.extend_from_slice(&packed.to_be_bytes()[1..4]);
    out.extend_from_slice(&key_encoded);
    out.extend_from_slice(&hash_encoded);
    out.push(0x00);
    out
}

/// Извлечь соль и хеш из 29-байтовой структуры хеша пароля.
///
/// # Errors
///
/// [`Error::BadHashStruct`], если структура имеет неверный формат.
pub fn verify_hash_struct(raw: &[u8]) -> Result<([u8; 4], [u8; 20]), Error> {
    if raw.len() != 29 || raw[0] != 0xFF || raw[28] != 0x00 {
        return Err(Error::BadHashStruct);
    }
    let packed = (u32::from(raw[1]) << 16) | (u32::from(raw[2]) << 8) | u32::from(raw[3]);
    let key_bits = bits_msb(packed >> 20, 4);
    let hash_bits = bits_msb(packed & 0xF_FFFF, 20);

    let key: [u8; 4] = decode_nulls(&raw[4..8], &key_bits)
        .as_slice()
        .try_into()
        .map_err(|_| Error::BadHashStruct)?;
    let hash: [u8; 20] = decode_nulls(&raw[8..28], &hash_bits)
        .as_slice()
        .try_into()
        .map_err(|_| Error::BadHashStruct)?;
    Ok((key, hash))
}

/// Проверить пароль-кандидат против соли и хеша ([MS-OVBA] §2.4.4.5).
#[must_use]
pub fn password_matches(password: &[u8], key: &[u8; 4], hash: &[u8; 20]) -> bool {
    let mut hasher = Sha1::new();
    hasher.update(password);
    hasher.update(key);
    hasher.finalize().as_slice() == hash.as_slice()
}

fn encode_nulls(input: &[u8]) -> (Vec<bool>, Vec<u8>) {
    let mut bits = Vec::with_capacity(input.len());
    let mut encoded = Vec::with_capacity(input.len());
    for &byte in input {
        if byte == 0 {
            bits.push(false);
            encoded.push(0x01);
        } else {
            bits.push(true);
            encoded.push(byte);
        }
    }
    (bits, encoded)
}

fn decode_nulls(encoded: &[u8], bits: &[bool]) -> Vec<u8> {
    bits.iter()
        .enumerate()
        .map(|(i, &set)| if set { encoded[i] } else { 0x00 })
        .collect()
}

fn pack_bits(bits: &[bool]) -> u32 {
    bits.iter()
        .fold(0u32, |acc, &bit| (acc << 1) | u32::from(bit))
}

fn bits_msb(value: u32, count: usize) -> Vec<bool> {
    (0..count)
        .map(|i| (value >> (count - 1 - i)) & 1 == 1)
        .collect()
}

/// Найти значение строки `KEY="…"` в потоке `PROJECT`.
fn find_line_value(data: &[u8], key: &[u8]) -> Option<String> {
    let (start, end) = *find_spans(data, key).first()?;
    Some(String::from_utf8_lossy(&data[start..end]).into_owned())
}

/// Найти все диапазоны `(начало, конец)` значений строки `KEY="…"`.
fn find_spans(data: &[u8], key: &[u8]) -> Vec<(usize, usize)> {
    let prefix_len = key.len() + 2;
    let mut spans = Vec::new();
    for (index, window) in data.windows(prefix_len).enumerate() {
        let at_line_start = index == 0 || data[index - 1] == b'\n';
        if !at_line_start
            || !window.starts_with(key)
            || window[key.len()] != b'='
            || window[key.len() + 1] != b'"'
        {
            continue;
        }
        let start = index + prefix_len;
        if let Some(rel) = data[start..].iter().position(|&c| c == b'"') {
            spans.push((start, start + rel));
        }
    }
    spans
}

/// Прочитать строки `ID`/`CMG`/`DPB`/`GC` из потока `PROJECT`.
#[must_use]
pub fn read_lines(data: &[u8]) -> ProtectionLines {
    ProtectionLines {
        id: find_line_value(data, b"ID"),
        cmg: find_line_value(data, b"CMG"),
        dpb: find_line_value(data, b"DPB"),
        gc: find_line_value(data, b"GC"),
    }
}

/// Заменить значение строки `KEY="…"`, сохранив её длину.
///
/// # Errors
///
/// [`Error::LineCount`], если строка встречается не ровно один раз, и
/// [`Error::LengthMismatch`], если новая длина отличается от старой.
pub fn replace_value(data: &[u8], key: &[u8], new_value: &str) -> Result<Vec<u8>, Error> {
    let spans = find_spans(data, key);
    if spans.len() != 1 {
        return Err(Error::LineCount(
            String::from_utf8_lossy(key).into_owned(),
            spans.len(),
        ));
    }
    let (start, end) = spans[0];
    if end - start != new_value.len() {
        return Err(Error::LengthMismatch {
            old: end - start,
            new: new_value.len(),
        });
    }
    let mut out = Vec::with_capacity(data.len());
    out.extend_from_slice(&data[..start]);
    out.extend_from_slice(new_value.as_bytes());
    out.extend_from_slice(&data[end..]);
    Ok(out)
}

/// Расшифровать защиту VBA-проекта из содержимого `vbaProject.bin`.
#[must_use]
pub fn describe(data: &[u8]) -> ProtectionInfo {
    let lines = read_lines(data);
    let clsid = lines
        .id
        .clone()
        .unwrap_or_else(|| ALL_ZERO_CLSID.to_string());

    let field = |raw: &Option<String>| {
        raw.as_ref().map(|value| match untangle(value, &clsid) {
            Ok(decoded) => DecodedField {
                raw: value.clone(),
                decoded: Some(decoded),
                error: None,
            },
            Err(err) => DecodedField {
                raw: value.clone(),
                decoded: None,
                error: Some(err.to_string()),
            },
        })
    };

    let cmg = field(&lines.cmg);
    let dpb = field(&lines.dpb);
    let gc = field(&lines.gc);

    let mut kind = ProtectionKind::Unknown;
    let mut key = None;
    let mut hash = None;
    let mut plaintext = None;

    if let Some(decoded) = dpb.as_ref().and_then(|f| f.decoded.as_ref()) {
        if decoded.length == 1 && decoded.data == [0x00] {
            kind = ProtectionKind::NoPassword;
        } else if decoded.length == 29
            && decoded.data.first() == Some(&0xFF)
            && decoded.data.last() == Some(&0x00)
        {
            if let Ok((k, h)) = verify_hash_struct(&decoded.data) {
                kind = ProtectionKind::Hash;
                key = Some(k);
                hash = Some(h);
            }
        } else {
            let end = decoded
                .data
                .iter()
                .position(|&b| b == 0x00)
                .unwrap_or(decoded.data.len());
            kind = ProtectionKind::Plaintext;
            plaintext = Some(decode_cp1251_lossy(&decoded.data[..end]));
        }
    }

    ProtectionInfo {
        clsid,
        cmg,
        dpb,
        gc,
        kind,
        key,
        hash,
        plaintext,
    }
}

/// Пропатчить содержимое `vbaProject.bin`.
///
/// [`Mode::Unlock`] снимает защиту, [`Mode::SetPassword`] оставляет защиту,
/// но заменяет пароль. Длина защитных строк сохраняется, поэтому контейнер
/// не перестраивается.
///
/// # Errors
///
/// Возвращает ошибку, если защитные строки отсутствуют, встречаются не по
/// одному разу или их нельзя закодировать с исходной длиной.
pub fn patch_vba_project(
    data: &[u8],
    mode: &crate::Mode,
    codepage: crate::CodePage,
) -> Result<Vec<u8>, Error> {
    let lines = read_lines(data);
    if lines.cmg.is_none() && lines.dpb.is_none() && lines.gc.is_none() {
        return Err(Error::NoProtection);
    }
    let clsid = lines.id.as_deref().unwrap_or(ALL_ZERO_CLSID);
    let mut out = data.to_vec();

    match mode {
        crate::Mode::Unlock => {
            if let Some(cmg) = &lines.cmg {
                let value = encode_padded(&[0, 0, 0, 0], clsid, cmg.len() / 2)?;
                out = replace_value(&out, b"CMG", &value)?;
            }
            if let Some(dpb) = &lines.dpb {
                let value = encode_padded(&[0x00], clsid, dpb.len() / 2)?;
                out = replace_value(&out, b"DPB", &value)?;
            }
            if let Some(gc) = &lines.gc {
                let value = encode_padded(&[0xFF], clsid, gc.len() / 2)?;
                out = replace_value(&out, b"GC", &value)?;
            }
        }
        crate::Mode::SetPassword(password) => {
            let digest_input = codepage.encode(password)?;
            let structure = build_password_hash_struct(&digest_input, [0x11, 0x22, 0x33, 0x44]);
            if let Some(cmg) = &lines.cmg {
                let value = encode_padded(&[0x05, 0, 0, 0], clsid, cmg.len() / 2)?;
                out = replace_value(&out, b"CMG", &value)?;
            }
            let dpb = lines.dpb.as_ref().ok_or(Error::NoProtection)?;
            let value = encode_padded(&structure, clsid, dpb.len() / 2)?;
            out = replace_value(&out, b"DPB", &value)?;
            if let Some(gc) = &lines.gc {
                let value = encode_padded(&[0x00], clsid, gc.len() / 2)?;
                out = replace_value(&out, b"GC", &value)?;
            }
        }
    }
    Ok(out)
}

/// Проверить реализацию на примере из [MS-OVBA] §3.1.6.
///
/// # Errors
///
/// Сообщение с описанием провалившейся проверки.
pub fn selftest() -> Result<(), String> {
    let clsid = "{917DED54-440B-4FD1-A5C1-74ACF261E600}";

    let cmg = untangle("0705D8E3D8EDDBF1DBF1DBF1DBF1", clsid).map_err(|e| e.to_string())?;
    let dpb = untangle("0E0CD1ECDFF4E7F5E7F5E7", clsid).map_err(|e| e.to_string())?;
    let gc = untangle("1517CAF1D6F9D7F9D706", clsid).map_err(|e| e.to_string())?;

    if cmg.projkey != 0xDF || dpb.projkey != 0xDF || gc.projkey != 0xDF {
        return Err("ProjKey не совпал с примером".into());
    }
    if cmg.data != [0, 0, 0, 0] {
        return Err("CMG не декодировался в 0x00000000".into());
    }
    if dpb.length != 1 || dpb.data != [0x00] {
        return Err("DPB не декодировался как «без пароля»".into());
    }
    if gc.data != [0xFF] {
        return Err("GC не декодировался как «видимый»".into());
    }

    let key = [0x11, 0x22, 0x33, 0x44];
    let structure = build_password_hash_struct(b"secret", key);
    let (key2, hash2) = verify_hash_struct(&structure).map_err(|e| e.to_string())?;
    if key2 != key || !password_matches(b"secret", &key2, &hash2) {
        return Err("круговой тест хеша пароля не прошёл".into());
    }
    if password_matches(b"Secret", &key2, &hash2) {
        return Err("неверный пароль принят как верный".into());
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const SPEC_CLSID: &str = "{917DED54-440B-4FD1-A5C1-74ACF261E600}";

    #[test]
    fn untangle_decodes_spec_example_cmg() {
        let decoded = untangle("0705D8E3D8EDDBF1DBF1DBF1DBF1", SPEC_CLSID).unwrap();
        assert_eq!(decoded.version, 2);
        assert_eq!(decoded.projkey, 0xDF);
        assert_eq!(decoded.data, vec![0, 0, 0, 0]);
    }

    #[test]
    fn untangle_decodes_spec_example_dpb_as_no_password() {
        let decoded = untangle("0E0CD1ECDFF4E7F5E7F5E7", SPEC_CLSID).unwrap();
        assert_eq!(decoded.length, 1);
        assert_eq!(decoded.data, vec![0x00]);
    }

    #[test]
    fn untangle_decodes_spec_example_gc_as_visible() {
        let decoded = untangle("1517CAF1D6F9D7F9D706", SPEC_CLSID).unwrap();
        assert_eq!(decoded.data, vec![0xFF]);
    }

    #[test]
    fn entangle_round_trips_through_untangle() {
        let clsid = ALL_ZERO_CLSID;
        let payload = [0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0xFF];
        let encoded = hex_encode(&entangle(&payload, clsid, 0x0E));
        let decoded = untangle(&encoded, clsid).unwrap();
        assert_eq!(decoded.data, payload);
    }

    #[test]
    fn encode_padded_produces_requested_length() {
        let value = encode_padded(&[0x00], ALL_ZERO_CLSID, 38).unwrap();
        assert_eq!(value.len(), 76);
    }

    #[test]
    fn encode_padded_result_decodes_to_payload() {
        let value = encode_padded(&[0x00], ALL_ZERO_CLSID, 38).unwrap();
        let decoded = untangle(&value, ALL_ZERO_CLSID).unwrap();
        assert_eq!(decoded.data, vec![0x00]);
    }

    #[test]
    fn encode_padded_rejects_payload_larger_than_target() {
        let err = encode_padded(&[0u8; 40], ALL_ZERO_CLSID, 10).unwrap_err();
        assert!(matches!(err, Error::PayloadTooBig { .. }));
    }

    #[test]
    fn password_hash_struct_round_trips() {
        let key = [0x11, 0x22, 0x33, 0x44];
        let structure = build_password_hash_struct(b"secret", key);
        let (decoded_key, decoded_hash) = verify_hash_struct(&structure).unwrap();
        assert_eq!(decoded_key, key);
        assert!(password_matches(b"secret", &decoded_key, &decoded_hash));
    }

    #[test]
    fn password_hash_struct_rejects_wrong_password() {
        let structure = build_password_hash_struct(b"secret", [0x11, 0x22, 0x33, 0x44]);
        let (key, hash) = verify_hash_struct(&structure).unwrap();
        assert!(!password_matches(b"Secret", &key, &hash));
    }

    #[test]
    fn selftest_returns_ok() {
        assert!(selftest().is_ok(), "{}", selftest().unwrap_err());
    }
}
