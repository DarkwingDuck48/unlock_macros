[Русский](README.md) · **English**

# unlock-macro

A CLI tool to inspect, remove, and reset the **"Lock project for viewing"** password
of Excel VBA projects. It implements the VBA project protection format from the
[MS-OVBA] §2.4.3 and §2.4.4 specification, in Rust.

## Purpose and lawful use

This tool is intended for files **you own or are authorized to handle** — for example
your own templates and macros, or files within your organization's infrastructure that
you maintain. A typical scenario: the password protecting the source of your own
project has been forgotten and you need to regain access to it.

The "Lock project for viewing" password is a user-interface protection of the VBA
editor, **not encryption**: it is stored as a one-way SHA-1 hash and cannot be
decrypted. The tool restores access to _your_ project; it does not break anyone
else's cryptographic protection.

**Do not** use this tool to access files you are not entitled to. The authors are not
liable for any use contrary to applicable law, license terms, or your organization's
policies.

## Supported containers

- OOXML: `.xlsb`, `.xlsm`, `.xlam`, `.docm`, `.pptm`, macro-enabled `.docx`/`.pptx`;
- legacy OLE: `.xls`, `.doc`, `.ppt`;
- a standalone `vbaProject.bin`.

## How it works

The `CMG`/`DPB`/`GC` values are rewritten **byte-for-byte with the same length**, so
the container structure is never rebuilt. The source file is never modified — the
result is written to a new file.

## Requirements

- Windows — VBA projects and the macro editor exist only in Office for Windows.
- Rust 1.88+ (edition 2024).

## Build

```bash
cargo build --release
```

Binary: `target/release/unlock-macro.exe`.

## Usage

### Show the protection state

```bash
unlock-macro info book.xlsb
```

Prints the decoded `CMG`/`DPB`/`GC`, the state (`no-password` / `hash` / `plaintext`)
and, for the `hash` case, the salt and the SHA-1 hash.

### Remove protection (the project opens without a password)

```bash
unlock-macro unlock book.xlsb
unlock-macro unlock book.xlsb -o out.xlsb
unlock-macro unlock vbaProject.bin -o vbaProject_unlocked.bin
```

By default the result is written next to the source file as
`<name> (unlocked)<extension>`.

### Keep protection but reset the password

```bash
unlock-macro setpass book.xlsb -p s3cr3t
unlock-macro setpass book.xlsb -p passwd --codepage cp1251 -o out.xlsb
```

### Verify the implementation

```bash
unlock-macro selftest
```

Checks decryption against the reference example in [MS-OVBA] §3.1.6 and runs a
round-trip test of the password hash.

## Options

| Option             | Description                                              |
| ------------------ | -------------------------------------------------------- |
| `-o`, `--out`      | output file (default: `<name> (unlocked)<extension>`)    |
| `-p`, `--password` | new password (`setpass`)                                 |
| `--codepage`       | password encoding: `cp1251` (default), `cp1252`, `utf-8` |

## Tests

```bash
cargo test
cargo clippy --all-targets --all-features -- -D warnings
```

## As a library

```rust
use std::path::Path;
use unlock_macro::{CodePage, Mode, process_file};

process_file(
    Path::new("book.xlsb"),
    Path::new("book (unlocked).xlsb"),
    &Mode::Unlock,
    CodePage::Cp1251,
)?;
```

## License

MIT — see [LICENSE](LICENSE).

[MS-OVBA]: https://learn.microsoft.com/openspecs/office_file_formats/ms-ovba/
