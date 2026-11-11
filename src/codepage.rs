//! Кодировки MBCS для пароля ([MS-OVBA] §2.3.4.2.1.5).

use encoding_rs::{Encoding, WINDOWS_1251, WINDOWS_1252};

use crate::error::Error;

/// Кодировка, в которой пароль записывается в байты.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CodePage {
    /// Windows-1251 (кириллица) — по умолчанию.
    #[default]
    Cp1251,
    /// Windows-1252 (западноевропейская).
    Cp1252,
    /// UTF-8.
    Utf8,
}

impl CodePage {
    /// Разобрать кодировку из строки: `cp1251`, `windows-1252`, `utf-8` и т. п.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value.to_ascii_lowercase().as_str() {
            "cp1251" | "windows-1251" | "1251" => Some(Self::Cp1251),
            "cp1252" | "windows-1252" | "1252" => Some(Self::Cp1252),
            "utf-8" | "utf8" => Some(Self::Utf8),
            _ => None,
        }
    }

    /// Закодировать строку пароля в байты MBCS.
    ///
    /// # Errors
    ///
    /// [`Error::EncodingFailed`], если строка содержит символы,
    /// непредставимые в выбранной кодировке.
    pub fn encode(self, value: &str) -> Result<Vec<u8>, Error> {
        match self {
            Self::Utf8 => Ok(value.as_bytes().to_vec()),
            Self::Cp1251 => encode_with(WINDOWS_1251, value),
            Self::Cp1252 => encode_with(WINDOWS_1252, value),
        }
    }
}

fn encode_with(encoding: &'static Encoding, value: &str) -> Result<Vec<u8>, Error> {
    let (bytes, _, had_errors) = encoding.encode(value);
    if had_errors {
        return Err(Error::EncodingFailed);
    }
    Ok(bytes.into_owned())
}

/// Декодировать байты как Windows-1251 (для случая пароля открытым текстом).
pub(crate) fn decode_cp1251_lossy(bytes: &[u8]) -> String {
    let (text, _, _) = WINDOWS_1251.decode(bytes);
    text.into_owned()
}
