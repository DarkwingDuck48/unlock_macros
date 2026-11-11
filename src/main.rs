//! CLI-утилита для снятия/сброса пароля VBA-проекта.

use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{Context, Result, anyhow};
use clap::{Parser, Subcommand};

use unlock_macro::ovba::DecodedField;
use unlock_macro::{
    CodePage, Mode, ProtectionInfo, ProtectionKind, default_out_path, describe_file, process_file,
};

#[derive(Debug, Parser)]
#[command(
    name = "unlock-macro",
    version,
    about = "Снятие/сброс пароля «Lock project for viewing» в VBA-проектах Excel"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Показать состояние защиты VBA-проекта.
    Info {
        /// Входной файл (.xlsb/.xlsm/.xls/… или vbaProject.bin).
        input: PathBuf,
    },
    /// Снять защиту (проект открывается без пароля).
    Unlock {
        /// Входной файл.
        input: PathBuf,
        /// Выходной файл (по умолчанию «<имя> (unlocked)<расширение>»).
        #[arg(short, long)]
        out: Option<PathBuf>,
        /// Кодировка пароля.
        #[arg(long, default_value = "cp1251")]
        codepage: String,
    },
    /// Оставить защиту, но сбросить пароль на заданный.
    Setpass {
        /// Входной файл.
        input: PathBuf,
        /// Новый пароль.
        #[arg(short, long)]
        password: String,
        /// Выходной файл (по умолчанию «<имя> (unlocked)<расширение>»).
        #[arg(short, long)]
        out: Option<PathBuf>,
        /// Кодировка пароля.
        #[arg(long, default_value = "cp1251")]
        codepage: String,
    },
    /// Проверить реализацию на примере из спецификации.
    Selftest,
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("Ошибка: {err:#}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Info { input } => print_info(&input),
        Command::Unlock {
            input,
            out,
            codepage,
        } => {
            let codepage = parse_codepage(&codepage)?;
            let out = out.unwrap_or_else(|| default_out_path(&input));
            process_file(&input, &out, &Mode::Unlock, codepage)?;
            println!("Защита снята. Результат: {}", out.display());
            Ok(())
        }
        Command::Setpass {
            input,
            password,
            out,
            codepage,
        } => {
            let codepage = parse_codepage(&codepage)?;
            let out = out.unwrap_or_else(|| default_out_path(&input));
            process_file(&input, &out, &Mode::SetPassword(password.clone()), codepage)?;
            println!(
                "Пароль сброшен на {password:?}. Результат: {}",
                out.display()
            );
            Ok(())
        }
        Command::Selftest => {
            unlock_macro::selftest().map_err(anyhow::Error::msg)?;
            println!("selftest: OK ([MS-OVBA] §3.1.6 + круговой тест хеша)");
            Ok(())
        }
    }
}

fn parse_codepage(value: &str) -> Result<CodePage> {
    CodePage::parse(value).ok_or_else(|| anyhow!("неизвестная кодировка: {value}"))
}

fn print_info(path: &Path) -> Result<()> {
    let info =
        describe_file(path).with_context(|| format!("не удалось прочитать {}", path.display()))?;
    println!("Файл        : {}", path.display());
    println!("CLSID (ID)  : {}", info.clsid);
    print_field("CMG", info.cmg.as_ref());
    print_field("DPB", info.dpb.as_ref());
    print_field("GC ", info.gc.as_ref());
    println!("Состояние   : {}", kind_label(info.kind));
    print_state(&info);
    Ok(())
}

fn print_state(info: &ProtectionInfo) {
    match info.kind {
        ProtectionKind::Hash => {
            if let (Some(key), Some(hash)) = (info.key, info.hash) {
                println!("  соль (key) : {}", hex_space(&key));
                println!("  SHA-1 хеш  : {}", hex_space(&hash));
            }
            println!("  -> пароль на просмотр проекта установлен (текст из хеша не восстановить)");
        }
        ProtectionKind::Plaintext => {
            if let Some(text) = &info.plaintext {
                println!("  пароль     : {text:?}");
            }
        }
        ProtectionKind::NoPassword => {
            println!("  -> пароль на просмотр проекта не установлен");
        }
        ProtectionKind::Unknown => {}
    }
}

fn print_field(label: &str, field: Option<&DecodedField>) {
    let Some(field) = field else {
        return;
    };
    if let Some(decoded) = &field.decoded {
        println!(
            "{label}          : ver={} len={} data={}",
            decoded.version,
            decoded.length,
            hex_space(&decoded.data)
        );
    } else if let Some(error) = &field.error {
        println!("{label}          : ошибка: {error}");
    }
}

fn kind_label(kind: ProtectionKind) -> &'static str {
    match kind {
        ProtectionKind::NoPassword => "no-password",
        ProtectionKind::Hash => "hash",
        ProtectionKind::Plaintext => "plaintext",
        ProtectionKind::Unknown => "unknown",
    }
}

fn hex_space(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 3);
    for (index, byte) in bytes.iter().enumerate() {
        if index > 0 {
            out.push(' ');
        }
        let _ = write!(out, "{byte:02x}");
    }
    out
}
