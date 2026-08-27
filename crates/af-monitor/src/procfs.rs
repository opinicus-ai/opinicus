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
/// command works on. The list holds no name that normally holds a secret.
pub const DEFAULT_ENV_ALLOWLIST: &[&str] = &[
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
    let start_ticks = rest
        .get(19)
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(0);
    Some(Stat {
        comm,
        ppid,
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
    })
}
