//! Reader of process facts from the `/proc` file system.
//!
//! A monitored process can end at any moment. Every function here therefore
//! returns an [`Option`]. A file that is gone is a normal result, never an
//! error, and never a panic.

use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;

use af_core::{Pid, ProcessInfo};

/// Environment names that the monitor always keeps.
///
/// A rule needs these names to see which database, cluster or cloud account a
/// command works on, and `HOME` lets a rule compare a variable of the command
/// line with the home directory that the child shell will expand it to. The
/// list holds no name that normally holds a secret.
pub const DEFAULT_ENV_ALLOWLIST: &[&str] = &[
    "HOME",
    "PGHOST",
    "PGDATABASE",
    "PGUSER",
    "PGPORT",
    "DATABASE_URL",
    "KUBECONFIG",
    "KUBERNETES_SERVICE_HOST",
    "AWS_PROFILE",
    "AWS_REGION",
    "AWS_DEFAULT_REGION",
    "GOOGLE_CLOUD_PROJECT",
    "AZURE_SUBSCRIPTION_ID",
    "GIT_DIR",
    "GIT_WORK_TREE",
    "DOCKER_HOST",
    "NODE_ENV",
    "ENVIRONMENT",
    "ENV",
    "DEPLOY_ENV",
    "TERM",
    // The preload configuration names the sensor a session runs with. A
    // child whose environment holds no copy of it has answered a question by
    // removing the instrument, which is a tamper fact and not a secret.
    "LD_PRELOAD",
];

/// Word parts that mark an environment name as a secret.
const SECRET_MARKERS: &[&str] = &[
    "PASSWORD",
    "PASSWD",
    "TOKEN",
    "SECRET",
    "KEY",
    "CREDENTIAL",
    "AUTH",
];

/// Text that replaces the value of a secret.
pub const REDACTED: &str = "<redacted>";

/// Fields of `/proc/<pid>/stat` that the monitor uses.
pub struct Stat {
    /// Program name that the kernel reports. It can hold spaces.
    pub comm: String,
    /// Identifier of the parent process.
    pub ppid: Pid,
    /// Session identifier of the process.
    ///
    /// Every process of a session shares it until one of them calls `setsid`,
    /// so a value that differs from the session root marks a process that
    /// detached from the session.
    pub sid: Pid,
    /// Start time of the process in clock ticks after boot.
    pub start_ticks: u64,
}

/// Builds the path of one file below `/proc/<pid>`.
fn proc_path(pid: Pid, leaf: &str) -> PathBuf {
    PathBuf::from(format!("/proc/{pid}/{leaf}"))
}

/// Reads `/proc/<pid>/stat`.
///
/// Field 2 holds the program name. That name can hold a space and a round
/// bracket, so the parser cuts the line at the last `)` and counts the fields
/// after that point.
pub fn read_stat(pid: Pid) -> Option<Stat> {
    let text = fs::read_to_string(proc_path(pid, "stat")).ok()?;
    let open = text.find('(')?;
    let close = text.rfind(')')?;
    if close < open {
        return None;
    }
    let comm = text.get(open + 1..close)?.to_string();
    let rest: Vec<&str> = text.get(close + 1..)?.split_whitespace().collect();
    // The first word after the name is field 3, so field N is at index N - 3.
    let ppid = rest.get(1)?.parse::<Pid>().ok()?;
    let sid = rest
        .get(3)
        .and_then(|value| value.parse::<Pid>().ok())
        .unwrap_or(0);
    let start_ticks = rest
        .get(19)
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(0);
    Some(Stat {
        comm,
        ppid,
        sid,
        start_ticks,
    })
}

/// Reads the command line of a process.
///
/// The kernel separates the words with a NUL byte.
pub fn read_cmdline(pid: Pid) -> Option<Vec<String>> {
    let raw = fs::read(proc_path(pid, "cmdline")).ok()?;
    let mut argv: Vec<String> = raw
        .split(|byte| *byte == 0)
        .map(|word| String::from_utf8_lossy(word).into_owned())
        .collect();
    while argv.last().is_some_and(|word| word.is_empty()) {
        argv.pop();
    }
    if argv.is_empty() {
        return None;
    }
    Some(argv)
}

/// Reads the full path of the running program.
pub fn read_exe(pid: Pid) -> Option<String> {
    fs::read_link(proc_path(pid, "exe"))
        .ok()
        .map(|path| path.to_string_lossy().into_owned())
}

/// Returns true when this file is a 32-bit ELF program.
///
/// The answer comes from the fifth byte of the file, which the ELF format
/// calls `EI_CLASS`: 1 is a 32-bit program and 2 is a 64-bit one. A file that
/// is not an ELF program, and a file that the monitor cannot read, both give
/// `false`, because the monitor never guesses.
///
/// The kernel filter of this monitor holds a table of system-call numbers of
/// one architecture. A 32-bit program on a 64-bit machine uses another table,
/// so the filter lets every call of such a program through. The monitor says
/// so at the exec stop instead of watching in silence. See
/// [`crate::SyscallFilter`].
pub fn is_elf32(path: &std::path::Path) -> bool {
    use std::io::Read;

    let Ok(mut file) = fs::File::open(path) else {
        return false;
    };
    let mut header = [0u8; 5];
    if file.read_exact(&mut header).is_err() {
        return false;
    }
    // The first four bytes of every ELF file are 0x7f and "ELF".
    header[..4] == [0x7f, b'E', b'L', b'F'] && header[4] == 1
}

/// Returns whether this file is an ELF program that needs the dynamic
/// linker.
///
/// The answer is `Some(true)` when the program header table holds a
/// `PT_INTERP` entry: the kernel then loads the interpreter named there, and
/// the interpreter loads every `LD_PRELOAD` library of the environment. The
/// answer is `Some(false)` for a static program, which no preload can reach.
/// A file that is not an ELF program, and a file that the monitor cannot
/// read, both give `None`, because the monitor never guesses.
///
/// This is the fact correlation keys on when it asks why a child of a
/// session that carries the sensor preload never reported: a dynamic child
/// must load the sensor, a static child never can.
pub fn is_dynamic_elf(path: &std::path::Path) -> Option<bool> {
    use std::io::{Read, Seek, SeekFrom};

    let mut file = fs::File::open(path).ok()?;
    let mut header = [0u8; 64];
    file.read_exact(&mut header).ok()?;
    // The first four bytes of every ELF file are 0x7f and "ELF".
    if header[..4] != [0x7f, b'E', b'L', b'F'] {
        return None;
    }
    let is_64 = header[4] == 2;
    let (phoff, phentsize, phnum): (u64, usize, usize) = if is_64 {
        (
            u64::from_le_bytes(header[0x20..0x28].try_into().ok()?),
            u16::from_le_bytes(header[0x36..0x38].try_into().ok()?) as usize,
            u16::from_le_bytes(header[0x38..0x3a].try_into().ok()?) as usize,
        )
    } else {
        (
            u32::from_le_bytes(header[0x1c..0x20].try_into().ok()?) as u64,
            u16::from_le_bytes(header[0x2a..0x2c].try_into().ok()?) as usize,
            u16::from_le_bytes(header[0x2c..0x2e].try_into().ok()?) as usize,
        )
    };
    if phnum == 0 || phentsize < 4 || phnum > 256 || phoff > (1 << 30) {
        return Some(false);
    }
    let mut table = vec![0u8; phnum * phentsize];
    file.seek(SeekFrom::Start(phoff)).ok()?;
    file.read_exact(&mut table).ok()?;
    // The first word of every program header entry is its type. `PT_INTERP`
    // names the interpreter, and an interpreter is what a preload needs.
    Some((0..phnum).any(|i| {
        let at = i * phentsize;
        u32::from_le_bytes(table[at..at + 4].try_into().expect("four bytes")) == 3
    }))
}

/// Reads the working directory of a process.
pub fn read_cwd(pid: Pid) -> Option<String> {
    fs::read_link(proc_path(pid, "cwd"))
        .ok()
        .map(|path| path.to_string_lossy().into_owned())
}

/// Reads the short program name that the kernel keeps.
///
/// The kernel cuts this name after 15 characters.
pub fn read_comm(pid: Pid) -> Option<String> {
    fs::read_to_string(proc_path(pid, "comm"))
        .ok()
        .map(|text| text.trim_end().to_string())
}

/// Reads the thread-group identifier of a task.
pub fn read_tgid(pid: Pid) -> Option<Pid> {
    let text = fs::read_to_string(proc_path(pid, "status")).ok()?;
    for line in text.lines() {
        if let Some(value) = line.strip_prefix("Tgid:") {
            return value.trim().parse::<Pid>().ok();
        }
    }
    None
}

/// Returns true when the task is a thread and not a separate process.
///
/// A thread shares its address space with the leader of its thread group, so
/// its own identifier differs from the group identifier.
pub fn is_thread(pid: Pid) -> Option<bool> {
    Some(read_tgid(pid)? != pid)
}

/// Returns true when the name of an environment variable looks like a secret.
fn is_secret_name(name: &str) -> bool {
    let upper = name.to_ascii_uppercase();
    SECRET_MARKERS.iter().any(|marker| upper.contains(marker))
}

/// Decides what the monitor keeps of one environment variable.
///
/// The monitor keeps a name only when the name is on the allow list. It
/// replaces the value with [`REDACTED`] when the name looks like a secret,
/// because a rule can still use the presence of the name.
pub fn keep_env(name: &str, value: &str, extra_allowlist: &[String]) -> Option<String> {
    let allowed =
        DEFAULT_ENV_ALLOWLIST.contains(&name) || extra_allowlist.iter().any(|entry| entry == name);
    if !allowed {
        return None;
    }
    if is_secret_name(name) {
        return Some(REDACTED.to_string());
    }
    Some(value.to_string())
}

/// Reads the environment of a process and keeps only what a rule needs.
pub fn read_environ(pid: Pid, extra_allowlist: &[String]) -> BTreeMap<String, String> {
    let mut kept = BTreeMap::new();
    let Ok(raw) = fs::read(proc_path(pid, "environ")) else {
        return kept;
    };
    for entry in raw.split(|byte| *byte == 0) {
        if entry.is_empty() {
            continue;
        }
        let text = String::from_utf8_lossy(entry);
        let Some((name, value)) = text.split_once('=') else {
            continue;
        };
        if let Some(value) = keep_env(name, value, extra_allowlist) {
            kept.insert(name.to_string(), value);
        }
    }
    kept
}

/// Reads every fact that the monitor keeps about one process.
///
/// Returns `None` when the process no longer exists.
pub fn read_process(pid: Pid, extra_allowlist: &[String]) -> Option<ProcessInfo> {
    let stat = read_stat(pid)?;
    let comm = read_comm(pid).unwrap_or_else(|| stat.comm.clone());
    let argv = read_cmdline(pid).unwrap_or_else(|| vec![comm.clone()]);
    Some(ProcessInfo {
        pid,
        ppid: Some(stat.ppid),
        start_ticks: stat.start_ticks,
        exe: read_exe(pid),
        comm,
        argv,
        cwd: read_cwd(pid),
        env: read_environ(pid, extra_allowlist),
        sid: (stat.sid > 0).then_some(stat.sid),
        dynamic_link: None,
    })
}
