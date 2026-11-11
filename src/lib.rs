//! # `unlock_macro`
//!
//! Снятие и сброс пароля «Lock project for viewing» в VBA-проектах Excel.
//!
//! Поддерживаются контейнеры OOXML (`.xlsb`, `.xlsm`, `.xlam`, `.docm` …),
//! легаси-файлы (`.xls`, `.doc`, `.ppt`) и одиночный `vbaProject.bin`.
//!
//! Пароль на просмотр VBA-проекта хранится как односторонний хеш SHA-1
//! ([MS-OVBA] §2.4.4), поэтому восстановить его текст невозможно: библиотека
//! снимает защиту целиком либо сбрасывает пароль на известный. Правки
//! выполняются байт-в-байт той же длины, поэтому структура контейнера не
//! перестраивается.
//!
//! ## Пример
//!
//! ```no_run
//! # fn main() -> Result<(), unlock_macro::Error> {
//! use std::path::Path;
//!
//! use unlock_macro::{CodePage, Mode, process_file};
//!
//! process_file(
//!     Path::new("book.xlsb"),
//!     Path::new("book (unlocked).xlsb"),
//!     &Mode::Unlock,
//!     CodePage::Cp1251,
//! )?;
//! # Ok(())
//! # }
//! ```

#![warn(missing_docs)]

pub mod codepage;
pub mod container;
pub mod error;
pub mod ovba;

pub use codepage::CodePage;
pub use container::{Mode, default_out_path, describe_file, process_file};
pub use error::Error;
pub use ovba::{ProtectionInfo, ProtectionKind, selftest};
