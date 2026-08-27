//! Reads the text that a program receives around one exec.
//!
//! The monitor calls this module while the new program is held at the exec
//! stop. At that moment the file descriptors and the arguments of the new
//! program are already in place, but no instruction of the program has run.

use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

use af_core::{Pid, ProcessInfo};

/// Program names that run a script file.
const INTERPRETERS: &[&str] = &[
    "sh", "bash", "zsh", "dash", "ksh", "python", "python3", "perl", "ruby", "node",
];

/// Database clients that can read statements from a file.
const DB_CLIENTS: &[&str] = &["psql", "mysql", "mariadb"];

/// Options that hold program text instead of a file name.
///
/// The text of such an option is already in `argv`, so the monitor does not
/// look for a script file.
const INLINE_CODE_FLAGS: &[&str] = &["-c", "--command", "-e", "--eval", "-m", "--module", "-p"];

/// Reads the text behind file descriptor 0 of a process.
///
/// The function reads only a regular file. A deleted temporary file is also a
/// regular file, so this covers the large here-document of a shell and the
/// `psql < file.sql` pattern.
///
/// The function skips a pipe, a socket and a terminal. Such a stream has no
/// stored content. A read would take the bytes away from the monitored
/// program and would change its behaviour.
///
/// The function opens the path `/proc/<pid>/fd/0`. That open call makes a new
/// file description with its own offset, so the read starts at the beginning
/// of the file and never moves the offset of the monitored program.
pub fn stdin_snapshot(pid: Pid, max_bytes: usize) -> Option<String> {
    read_head(&PathBuf::from(format!("/proc/{pid}/fd/0")), max_bytes)
}

/// Reads the first bytes of the script that a process runs.
///
/// The function works for an interpreter, such as `bash` or `python`, and for
/// a database client that reads statements from a file, such as `psql -f`.
/// It returns `None` for any other program.
pub fn script_snapshot(process: &ProcessInfo, max_bytes: usize) -> Option<String> {
    let argument = script_argument(process)?;
    let path = resolve(process, &argument);
    read_head(&path, max_bytes)
}

/// Returns the script argument of a command line, when there is one.
fn script_argument(process: &ProcessInfo) -> Option<String> {
    let program = process.program_name();
    if DB_CLIENTS.contains(&program) {
        return file_option(&process.argv);
    }
    if !INTERPRETERS.contains(&program) {
        return None;
    }
    let mut arguments = process.argv.iter().skip(1);
    while let Some(argument) = arguments.next() {
        if INLINE_CODE_FLAGS.contains(&argument.as_str()) {
            return None;
        }
        if argument == "--" {
            return arguments.next().cloned();
        }
        if argument.starts_with('-') {
            continue;
        }
        return Some(argument.clone());
    }
    None
}

/// Returns the value of the `-f` or `--file` option of a database client.
fn file_option(argv: &[String]) -> Option<String> {
    let mut arguments = argv.iter().skip(1);
    while let Some(argument) = arguments.next() {
        if argument == "-f" || argument == "--file" {
            return arguments.next().cloned();
        }
        if let Some(rest) = argument.strip_prefix("--file=") {
            return Some(rest.to_string());
        }
        if argument.starts_with("-f") && argument.len() > 2 {
            return Some(argument[2..].to_string());
        }
    }
    None
}

/// Makes a full path from a command-line argument.
///
/// A relative name belongs to the working directory of the process.
fn resolve(process: &ProcessInfo, argument: &str) -> PathBuf {
    let path = PathBuf::from(argument);
    if path.is_absolute() {
        return path;
    }
    match process.cwd.as_deref() {
        Some(cwd) => PathBuf::from(cwd).join(path),
        None => path,
    }
}

/// Reads the first `max_bytes` of a regular file as text.
///
/// The result is always valid text. A byte sequence that is not valid UTF-8
/// becomes the replacement character.
fn read_head(path: &Path, max_bytes: usize) -> Option<String> {
    if max_bytes == 0 {
        return None;
    }
    let metadata = fs::metadata(path).ok()?;
    if !metadata.file_type().is_file() {
        return None;
    }
    let file = fs::File::open(path).ok()?;
    let mut buffer = Vec::new();
    file.take(max_bytes as u64).read_to_end(&mut buffer).ok()?;
    if buffer.is_empty() {
        return None;
    }
    Some(String::from_utf8_lossy(&buffer).into_owned())
}
