//! Работа с контейнерами OOXML (ZIP) и OLE.

use std::fs::{self, File};
use std::io::{Cursor, Read, Seek, Write};
use std::path::{Path, PathBuf};

use zip::write::SimpleFileOptions;
use zip::{CompressionMethod, ZipArchive, ZipWriter};

use crate::codepage::CodePage;
use crate::error::Error;
use crate::ovba::{self, ProtectionInfo};

/// Сигнатура OLE-контейнера (Compound File Binary Format).
const OLE_MAGIC: [u8; 8] = [0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1];

/// Что сделать с защитой VBA-проекта.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Mode {
    /// Снять защиту полностью (проект открывается без пароля).
    Unlock,
    /// Оставить защиту, но заменить пароль на указанный.
    SetPassword(String),
}

/// Является ли имя члена архива `vbaProject.bin`.
#[must_use]
pub fn is_vba_member(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    lower == "vbaproject.bin" || lower.ends_with("/vbaproject.bin")
}

/// Путь выходного файла по умолчанию: `<имя> (unlocked)<расширение>`.
#[must_use]
pub fn default_out_path(src: &Path) -> PathBuf {
    let mut file_name = src.file_stem().map_or_else(
        || std::ffi::OsString::from("output"),
        std::ffi::OsString::from,
    );
    file_name.push(" (unlocked)");
    if let Some(extension) = src.extension() {
        file_name.push(".");
        file_name.push(extension);
    }
    src.parent()
        .map_or_else(|| PathBuf::from(&file_name), |dir| dir.join(&file_name))
}

fn extract_vba<R: Read + Seek>(archive: &mut ZipArchive<R>) -> Result<Vec<u8>, Error> {
    let index = archive
        .file_names()
        .position(|name| name.is_ok_and(|n| is_vba_member(&n)))
        .ok_or(Error::NoVbaMember)?;
    let mut entry = archive.by_index(index)?;
    let mut buffer = Vec::new();
    entry.read_to_end(&mut buffer)?;
    Ok(buffer)
}

/// Описать защиту VBA-проекта в файле.
///
/// # Errors
///
/// [`Error::UnknownFormat`] для неизвестного формата, [`Error::NoVbaMember`],
/// если в архиве нет `vbaProject.bin`, а также ошибки ввода-вывода и ZIP.
pub fn describe_file(path: &Path) -> Result<ProtectionInfo, Error> {
    let data = fs::read(path)?;
    if data.starts_with(b"PK\x03\x04") {
        let mut archive = ZipArchive::new(Cursor::new(&data))?;
        let vba = extract_vba(&mut archive)?;
        Ok(ovba::describe(&vba))
    } else if data.starts_with(&OLE_MAGIC) {
        Ok(ovba::describe(&data))
    } else {
        Err(Error::UnknownFormat)
    }
}

/// Обработать файл и записать результат в `dst`.
///
/// Исходный файл не изменяется.
///
/// # Errors
///
/// [`Error::UnknownFormat`] для неизвестного формата, [`Error::NoVbaMember`],
/// если в архиве нет `vbaProject.bin`, [`Error::NoProtection`], если защита не
/// найдена, а также ошибки ввода-вывода, ZIP и кодирования пароля.
pub fn process_file(src: &Path, dst: &Path, mode: &Mode, codepage: CodePage) -> Result<(), Error> {
    let data = fs::read(src)?;
    if data.starts_with(b"PK\x03\x04") {
        process_zip(&data, dst, mode, codepage)
    } else if data.starts_with(&OLE_MAGIC) {
        let patched = ovba::patch_vba_project(&data, mode, codepage)?;
        fs::write(dst, patched)?;
        Ok(())
    } else {
        Err(Error::UnknownFormat)
    }
}

fn process_zip(data: &[u8], dst: &Path, mode: &Mode, codepage: CodePage) -> Result<(), Error> {
    let mut archive = ZipArchive::new(Cursor::new(data))?;
    if !archive
        .file_names()
        .any(|name| name.is_ok_and(|n| is_vba_member(&n)))
    {
        return Err(Error::NoVbaMember);
    }

    let output = File::create(dst)?;
    let mut writer = ZipWriter::new(output);
    let options = SimpleFileOptions::default().compression_method(CompressionMethod::Deflated);

    for index in 0..archive.len() {
        let mut entry = archive.by_index(index)?;
        let name = entry.name()?.to_string();
        if is_vba_member(&name) {
            let mut buffer = Vec::new();
            entry.read_to_end(&mut buffer)?;
            let patched = ovba::patch_vba_project(&buffer, mode, codepage)?;
            writer.start_file(name, options)?;
            writer.write_all(&patched)?;
        } else if entry.is_dir() {
            writer.add_directory(name, options)?;
        } else {
            writer.raw_copy_file(entry)?;
        }
    }
    writer.finish()?;
    Ok(())
}
