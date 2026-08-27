//! Normalization of the program that a process really runs.
//!
//! Linux runs a script through its interpreter. When a process runs
//! `/usr/local/bin/psql` and that file starts with `#!/bin/sh`, the kernel
//! loads the shell. `/proc/<pid>/exe` then points at the shell, and the
//! command line starts with the shell.
//!
//! A rule author writes `program: psql`, because that is the tool the agent
//! called. Many real tools are wrapper scripts, for example `npm`, `mvn` and
//! `gradle`. So the firewall must judge the script, and not the interpreter.
//!
//! This module makes a copy of the process facts in which the program is the
//! script. The recorded event always keeps the true facts, so the provenance
//! stays honest.

use std::path::{Path, PathBuf};

use af_core::ProcessInfo;

/// Programs that run a script that another file holds.
const INTERPRETERS: &[&str] = &[
    "sh", "bash", "zsh", "dash", "ksh", "fish", "ash", "busybox", "python", "python2", "python3",
    "perl", "ruby", "node", "php", "tclsh", "lua",
];

/// Returns true when a program runs a script from a file.
pub fn is_interpreter(program: &str) -> bool {
    INTERPRETERS.contains(&program)
}

/// Returns true when a program is a shell.
pub fn is_shell(program: &str) -> bool {
    matches!(
        program,
        "sh" | "bash" | "zsh" | "dash" | "ksh" | "fish" | "ash"
    )
}

/// Returns the process facts that the policy engine must judge.
///
/// The function returns the same facts when the process runs a normal
/// program. It returns a copy with the script as the program when an
/// interpreter runs a script file.
pub fn for_policy(process: &ProcessInfo) -> ProcessInfo {
    let program = process.program_name();
    if !is_interpreter(program) {
        return process.clone();
    }
    let Some(script) = script_argument(process) else {
        return process.clone();
    };
    let Some(name) = file_name(&script) else {
        return process.clone();
    };
    if name == program {
        return process.clone();
    }

    let mut normalized = process.clone();
    normalized.exe = Some(script.display().to_string());
    normalized.comm = name;
    // The kernel puts the interpreter in front of the command line of a
    // script. The user called the script, so the explanation and the rules
    // must start at the script.
    if normalized.argv.len() > 1 {
        normalized.argv.remove(0);
    }
    normalized
}

/// Finds the script file that an interpreter runs.
///
/// The function reads the first argument that is not an option. It then
/// checks that the argument names a file that exists. `bash -c "psql ..."`
/// therefore keeps `bash` as its program, because the text after `-c` is a
/// command and not a file.
fn script_argument(process: &ProcessInfo) -> Option<PathBuf> {
    let base = process.cwd.as_deref().map(Path::new);
    for argument in process.argv.iter().skip(1) {
        if argument.starts_with('-') {
            continue;
        }
        let candidate = Path::new(argument);
        let absolute = if candidate.is_absolute() {
            candidate.to_path_buf()
        } else {
            match base {
                Some(dir) => dir.join(candidate),
                None => candidate.to_path_buf(),
            }
        };
        if absolute.is_file() {
            return Some(absolute);
        }
        return None;
    }
    None
}

/// Returns the name of a file without its directories.
fn file_name(path: &Path) -> Option<String> {
    path.file_name()
        .map(|name| name.to_string_lossy().to_string())
        .filter(|name| !name.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn process(argv: &[&str], exe: &str, cwd: &str) -> ProcessInfo {
        ProcessInfo {
            pid: 1,
            exe: Some(exe.to_string()),
            comm: exe.rsplit('/').next().unwrap_or(exe).to_string(),
            argv: argv.iter().map(|a| a.to_string()).collect(),
            cwd: Some(cwd.to_string()),
            ..Default::default()
        }
    }

    #[test]
    fn a_wrapper_script_reports_the_script_as_the_program() {
        let dir = tempfile::tempdir().unwrap();
        let script = dir.path().join("psql");
        std::fs::write(&script, "#!/bin/sh\n").unwrap();

        let raw = process(
            &["/bin/sh", script.to_str().unwrap(), "-c", "DROP DATABASE x"],
            "/usr/bin/bash",
            dir.path().to_str().unwrap(),
        );
        assert_eq!(raw.program_name(), "bash");

        let judged = for_policy(&raw);
        assert_eq!(judged.program_name(), "psql");
        // The interpreter must not stay in front of the command line.
        assert!(!judged.command_line().starts_with("/bin/sh"));
        assert!(judged.command_line().ends_with("-c DROP DATABASE x"));
    }

    #[test]
    fn a_shell_command_keeps_the_shell_as_the_program() {
        let raw = process(&["bash", "-c", "psql -c 'SELECT 1'"], "/usr/bin/bash", "/tmp");
        assert_eq!(for_policy(&raw).program_name(), "bash");
    }

    #[test]
    fn a_normal_program_does_not_change() {
        let raw = process(&["psql", "-c", "SELECT 1"], "/usr/bin/psql", "/tmp");
        assert_eq!(for_policy(&raw), raw);
    }

    #[test]
    fn a_missing_script_does_not_change_the_program() {
        let raw = process(&["bash", "/does/not/exist.sh"], "/usr/bin/bash", "/tmp");
        assert_eq!(for_policy(&raw).program_name(), "bash");
    }
}
