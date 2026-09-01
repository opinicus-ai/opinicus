//! The kernel floor: Landlock turns "always no" rule classes into kernel
//! enforcement, before the program starts.
//!
//! The two decision points of [`crate::tracer`] hold a process **while the
//! firewall asks**. This module removes the question instead: at session
//! start the child enacts one Landlock ruleset that makes the "always no"
//! rule classes of the built-in pack impossible, in the kernel, with no
//! supervisor in the loop. `research/spikes/landlock/FINDINGS.md` measured
//! the mechanism at 1.0× on all three benchmark workloads and 0 of 6 escape
//! attempts, and this module ships the shape it recommended.
//!
//! # What the floor is
//!
//! Landlock is an allow list with no deny rule. Every handled right is denied
//! everywhere except under a path that a rule grants. The floor therefore
//! grants:
//!
//! | Path | Rights |
//! | --- | --- |
//! | the work tree, `/tmp`, `/var/tmp`, `/var/cache` | everything |
//! | the entries of the home directory | everything, except the hidden paths below |
//! | `/usr`, `/etc`, `/opt`, `/srv`, `/boot`, `/bin`, `/sbin`, `/lib`, `/lib64` | read, list, execute |
//! | `/proc`, `/sys`, `/run`, `/var` | read and list |
//! | `/dev/null`, `/dev/full`, `/dev/tty`, `/dev/ptmx`, `/dev/pts`, `/dev/shm` | read, write, execute, truncate |
//! | `/dev/zero`, `/dev/random`, `/dev/urandom` | read and execute |
//!
//!
//! and grants **nothing** on the credential stores of the user (`~/.ssh`,
//! `~/.aws/credentials`, `~/.netrc`, `~/.git-credentials`), on the raw disk
//! devices of `/dev`, and on the mounted media trees (`/mnt`, `/media`,
//! `/run/media`, `/Volumes`). The tool configuration files that hold tokens
//! (`~/.npmrc`, `~/.pypirc`, `~/.kube/config`, `~/.docker/config.json`,
//! `~/.config/gh/hosts.yml`) keep their read and lose their write, so
//! `kubectl`, `npm` and `gh` keep working. A `LANDLOCK_SCOPE_SIGNAL`
//! restriction (ABI 6) takes the signal to any process outside the session
//! away with it.
//!
//! The hidden set is exactly the home enumeration above. A credential-shaped
//! path (`.ssh`, `.aws/credentials`, …) that sits under a writable tree — the
//! work tree, `/tmp`, `/var/tmp`, `/var/cache` — is **not** hidden: the grant
//! on the tree covers it. No composition of Landlock rules can subtract it,
//! and the mechanism is measured, not guessed (`research/spikes/landlock`,
//! section E, `bin/tmp-scope`): rules within one layer union, a second layer
//! can only intersect, rules attach to objects that exist when the ruleset is
//! built, and a path created later inherits the grant of the directory above
//! it. Carving the tree instead (granting every entry but the shape) denies
//! the shape but also denies every creation the enumeration does not reach,
//! and a make-only grant denies even a fresh `open(O_CREAT|O_WRONLY)`.
//! The protection of such a path is therefore the pack's question, which the
//! session still asks and explains. `docs/LANDLOCK-CONTRACT.md` is the full
//! set-theoretic contract, with the measured holes: a bind mount is judged by
//! its mount path, so a privileged hand can alias a hidden store into a
//! granted tree and the session can read it through the alias; a symlink is
//! resolved to its object, so a link to a hidden store is denied.
//!
//! A rule that names something other than a directory — a file, a device
//! node — may carry the file rights and no directory right, because the
//! kernel rejects such a rule whole. The entries of the home directory
//! therefore carry the full set whether they are a file or a directory.
//!
//! # The price, measured in the spike
//!
//! * A directory that holds a hidden path gets no rule of its own, because a
//!   rule on a directory reaches every file under it and a deeper rule can
//!   only add. `ls ~` and `ls /` therefore fail with `EACCES` while `ls
//!   ~/devel` still works. The build of the ruleset enumerates the home
//!   directory once, at session start: 326 rules on the machine of the
//!   measurement, a build the spike timed at 1.0–1.7 ms for the same shape.
//! * The ruleset cannot be relaxed. "Allow for this session" is impossible;
//!   the only way out is a new session with `--landlock off`. This is why
//!   only rules whose answer is **always no** may ride on the floor, and why
//!   the pack itself does not change: on a machine without Landlock the same
//!   rules keep asking exactly as before.
//! * Landlock does not mediate `chmod` and ioctls, sees no program name, no
//!   argument and no host, and an `execve` from an anonymous file descriptor
//!   runs (measured in the spike directory). The floor carries the classes it
//!   can carry and nothing else.
//!
//! # The explainer
//!
//! A bare `EACCES` loses the user, so the floor names the rule class it
//! enforced. Because the ruleset is fixed before the program starts and can
//! never be relaxed, the denial of an open on a path the floor hides is
//! **certain** — the monitor does not need to observe the failed call to
//! explain it. [`Plan::denies`] maps a path to the rule class the kernel
//! enforces on it, and the tracer reports it whenever it lets an open
//! continue that the kernel will refuse. The monitor probed the alternative
//! — continuing a held open with `PTRACE_SYSCALL` and reading `rax` at a
//! syscall-exit stop — and rejected it: on this kernel the restart delivers
//! the next seccomp stop and no exit stop, so the result is never observable
//! that way.
//!
//! # Soundness
//!
//! The floor never reads a path from the memory of the program it judges.
//! The ruleset is built in the monitor, from the working directory and the
//! home directory, before the child exists, and the kernel then compares its
//! own resolved object against it. This is the "decide on an object" rule of
//! `docs/DETECTION-RESEARCH.md` section 2, followed by construction. The
//! path inside an [`Plan::denies`] answer comes from the seccomp stop, is
//! advisory, and only ever names a rule in a message — the kernel made the
//! decision, not the monitor.

use std::collections::BTreeSet;
use std::io;
use std::os::fd::{AsRawFd, BorrowedFd};
use std::path::{Path, PathBuf};

// ---------------------------------------------------------------------------
// The Landlock ABI of this kernel
// ---------------------------------------------------------------------------

/// Flag of `landlock_create_ruleset` that asks for the ABI version.
const CREATE_RULESET_VERSION: u32 = 1;

/// The filesystem rights, with the bit numbers of `linux/landlock.h`.
///
/// The numbers are the same on every architecture. `IOCTL_DEV` is
/// deliberately not handled: it is checked at `ioctl` time on device files
/// that the session may hold open from its parent, and mediating it would
/// break terminals that normal work uses.
mod right {
    // The bit numbers are the ones of `linux/landlock.h`.
    pub const EXECUTE: u64 = 1 << 0;
    pub const WRITE_FILE: u64 = 1 << 1;
    pub const READ_FILE: u64 = 1 << 2;
    pub const READ_DIR: u64 = 1 << 3;
    pub const REMOVE_DIR: u64 = 1 << 4;
    pub const REMOVE_FILE: u64 = 1 << 5;
    pub const MAKE_CHAR: u64 = 1 << 6;
    pub const MAKE_DIR: u64 = 1 << 7;
    pub const MAKE_REG: u64 = 1 << 8;
    pub const MAKE_SOCK: u64 = 1 << 9;
    pub const MAKE_FIFO: u64 = 1 << 10;
    pub const MAKE_BLOCK: u64 = 1 << 11;
    pub const MAKE_SYM: u64 = 1 << 12;
    /// Linking and renaming across hierarchies. ABI 2.
    pub const REFER: u64 = 1 << 13;
    /// Growing or shrinking an open file. ABI 3.
    pub const TRUNCATE: u64 = 1 << 14;
}

/// Scope flag of ABI 6: no signal to a process outside the sandbox.
const SCOPE_SIGNAL: u64 = 1 << 1;

/// `struct landlock_ruleset_attr` as this kernel knows it.
///
/// The kernel accepts an attribute larger than its own struct and ignores the
/// extra bytes, so one fixed shape is safe on both older and newer kernels.
#[repr(C)]
struct RulesetAttr {
    handled_access_fs: u64,
    handled_access_net: u64,
    scoped: u64,
}

/// `struct landlock_path_beneath_attr`.
#[repr(C)]
struct PathBeneathAttr {
    allowed_access: u64,
    parent_fd: i32,
    _pad: u32,
}

fn create_ruleset(attr: Option<&RulesetAttr>, size: usize, flags: u32) -> io::Result<i32> {
    // SAFETY: the kernel reads `size` bytes from `attr` or nothing at all
    // when only the version is asked for, and returns a file descriptor.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            attr.map_or(std::ptr::null(), |a| a as *const RulesetAttr),
            size,
            flags,
        )
    };
    finish(rc)
}

fn add_rule(fd: BorrowedFd<'_>, attr: &PathBeneathAttr) -> io::Result<()> {
    // SAFETY: the kernel reads the attribute through the pointer and changes
    // only the ruleset behind `fd`.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_landlock_add_rule,
            fd.as_raw_fd(),
            LANDLOCK_RULE_PATH_BENEATH,
            attr as *const PathBeneathAttr,
            0u32,
        )
    };
    finish(rc).map(|_| ())
}

fn restrict_self(fd: BorrowedFd<'_>) -> io::Result<()> {
    // SAFETY: the kernel applies the ruleset of `fd` to the calling thread.
    let rc = unsafe { libc::syscall(libc::SYS_landlock_restrict_self, fd.as_raw_fd(), 0u32) };
    finish(rc).map(|_| ())
}

/// `LANDLOCK_RULE_PATH_BENEATH`.
const LANDLOCK_RULE_PATH_BENEATH: i32 = 1;

/// Turns a raw syscall result into an [`io::Result`].
fn finish(rc: libc::c_long) -> io::Result<i32> {
    if rc < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(rc as i32)
    }
}

/// Reports the Landlock ABI version of this kernel.
///
/// The question never restricts the asking process: the call only names the
/// version and closes the descriptor again.
pub fn abi_version() -> io::Result<i32> {
    let fd = create_ruleset(None, 0, CREATE_RULESET_VERSION)?;
    let version = fd;
    // SAFETY: closing a descriptor this function made.
    unsafe { libc::close(fd) };
    Ok(version)
}

/// Reports whether this machine can carry the kernel floor.
///
/// The answer comes from a real question to the kernel. ABI 1 is enough for
/// the file rights; every higher right and the signal scope are added when
/// the kernel knows them, and [`Plan::enforced_rules`] names only the rule
/// classes the machine really enforces.
pub fn availability() -> Result<i32, String> {
    match abi_version() {
        Ok(version) if version >= 1 => Ok(version),
        Ok(version) => Err(format!(
            "this kernel reports Landlock ABI {version}, and the floor needs at least ABI 1"
        )),
        Err(error) => Err(format!("this kernel offers no Landlock: {error}")),
    }
}

// ---------------------------------------------------------------------------
// The plan: what the floor grants, hides and names
// ---------------------------------------------------------------------------

/// How the floor treats one credential path of the home directory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Hide {
    /// No rule at all: no open, no listing, nothing. The classic credential
    /// stores take this, because the pack carries a read rule for them and a
    /// program that reads a key is the first step of a data theft.
    Everything,
    /// A rule with read and execute and no write: the file stays readable —
    /// `kubectl`, `npm` and `gh` keep working — and no change to it can run.
    /// The tool configuration files take this, because reading them is
    /// normal work and only the write is the danger.
    Writes,
}

/// One credential path of the home directory, with the rule classes of the
/// pack.
#[derive(Debug)]
struct Hidden {
    /// Path below the home directory.
    rel: &'static str,
    /// How deep the denial goes.
    how: Hide,
    /// The rule class that owns the path and whose question the floor
    /// answers on a write.
    rule: &'static str,
    /// The rule class that the pack carries for a **read** of this path, when
    /// it carries one. The floor denies the read only for [`Hide::Everything`];
    /// the name explains the denial when it happens.
    read_rule: Option<&'static str>,
}

/// The credential paths of the user. These are the paths of
/// `filesystem.credentials.write` of the built-in pack.
const HIDDEN: &[Hidden] = &[
    Hidden {
        rel: ".ssh",
        how: Hide::Everything,
        rule: "filesystem.credentials.write",
        read_rule: Some("filesystem.credentials.read"),
    },
    Hidden {
        rel: ".aws/credentials",
        how: Hide::Everything,
        rule: "filesystem.credentials.write",
        read_rule: Some("filesystem.credentials.read"),
    },
    Hidden {
        rel: ".netrc",
        how: Hide::Everything,
        rule: "filesystem.credentials.write",
        read_rule: Some("filesystem.credentials.read"),
    },
    Hidden {
        rel: ".git-credentials",
        how: Hide::Everything,
        rule: "filesystem.credentials.write",
        read_rule: Some("filesystem.credentials.read"),
    },
    Hidden {
        rel: ".npmrc",
        how: Hide::Writes,
        rule: "filesystem.credentials.write",
        read_rule: None,
    },
    Hidden {
        rel: ".pypirc",
        how: Hide::Writes,
        rule: "filesystem.credentials.write",
        read_rule: None,
    },
    Hidden {
        rel: ".kube/config",
        how: Hide::Writes,
        rule: "filesystem.credentials.write",
        read_rule: None,
    },
    Hidden {
        rel: ".docker/config.json",
        how: Hide::Writes,
        rule: "filesystem.credentials.write",
        read_rule: None,
    },
    Hidden {
        rel: ".config/gh/hosts.yml",
        how: Hide::Writes,
        rule: "filesystem.credentials.write",
        read_rule: None,
    },
];

/// System trees that stay readable and executable, and nothing more.
///
/// `/etc` carries its own rule class for a write; the other trees answer with
/// the delete class that made them read-only.
const SYSTEM_RX: &[&str] = &["/usr", "/etc", "/opt", "/srv", "/boot"];

/// System trees that stay readable, and nothing more.
const SYSTEM_RO: &[&str] = &["/proc", "/sys", "/run", "/var"];

/// Symlinked trees of a Fedora-shaped system. On a system where they are real
/// directories they need their own rule; where they resolve into `/usr` the
/// rule is a harmless duplicate.
const SYSTEM_LINKS: &[&str] = &["/bin", "/sbin", "/lib", "/lib64"];

/// Trees that hold mounted drives. Nothing is granted there, so no delete and
/// no write can reach them.
const MEDIA_ROOTS: &[&str] = &["/mnt", "/media", "/run/media", "/Volumes"];

/// Device files that normal work opens, and whether the session may write
/// them. Everything else under `/dev`, a raw disk included, gets no rule.
const DEV_SAFE: &[(&str, bool)] = &[
    ("/dev/null", true),
    ("/dev/full", true),
    ("/dev/tty", true),
    ("/dev/ptmx", true),
    ("/dev/pts", true),
    ("/dev/shm", true),
    ("/dev/zero", false),
    ("/dev/random", false),
    ("/dev/urandom", false),
];

/// What a rule that names something other than a directory may carry.
///
/// The kernel rejects the whole rule when it names a file, a device node or
/// a socket and carries a directory right, so the floor trims those away and
/// keeps the rights of the object itself: read, write, execute, truncate.
const RIGHTS_BENEATH: u64 = right::READ_FILE | right::WRITE_FILE | right::EXECUTE | right::TRUNCATE;

/// Directories that a development session writes outside the work tree.
/// These are also the exception paths that the built-in delete rules name, so
/// the floor keeps what the pack already allows.
const WRITABLE_TMP: &[&str] = &["/tmp", "/var/tmp", "/var/cache"];

/// One rule of the ruleset: a path and the rights the kernel grants under it.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Grant {
    path: PathBuf,
    rights: u64,
}

/// The rule class the kernel enforces on one denied path, for the explainer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Denial {
    /// The path that was asked about.
    pub path: String,
    /// The rule of the built-in pack whose class the kernel enforced, when
    /// one maps to this denial.
    pub rule: Option<&'static str>,
}

/// The ruleset of one session, built in the monitor before the child exists.
///
/// The plan holds the grants, the hidden paths and the ABI it was built for,
/// so the child only opens paths and enacts; it never reads a directory.
#[derive(Debug, Clone, Default)]
pub struct Plan {
    grants: Vec<Grant>,
    /// The hidden stores as absolute paths, paired with their rule classes.
    hidden: Vec<(PathBuf, &'static Hidden)>,
    home: Option<PathBuf>,
    /// The work tree, when the floor granted it.
    work_tree: Option<PathBuf>,
    abi: i32,
    /// True when the work tree sits inside a hidden path and the floor had
    /// to leave it ungranted.
    pub work_tree_ungranted: bool,
}

/// All rights a writable tree grants.
fn rights_full(abi: i32) -> u64 {
    let mut rights = right::READ_FILE
        | right::READ_DIR
        | right::EXECUTE
        | right::WRITE_FILE
        | right::REMOVE_DIR
        | right::REMOVE_FILE
        | right::MAKE_CHAR
        | right::MAKE_DIR
        | right::MAKE_REG
        | right::MAKE_SOCK
        | right::MAKE_FIFO
        | right::MAKE_BLOCK
        | right::MAKE_SYM;
    if abi >= 2 {
        rights |= right::REFER;
    }
    if abi >= 3 {
        rights |= right::TRUNCATE;
    }
    rights
}

/// Read, list and execute, and nothing that changes the tree.
fn rights_read_execute() -> u64 {
    right::READ_FILE | right::READ_DIR | right::EXECUTE
}

/// Read and list only.
fn rights_read() -> u64 {
    right::READ_FILE | right::READ_DIR
}

impl Plan {
    /// Builds the plan for one session.
    ///
    /// `work_tree` is the working directory of the session root and `home`
    /// the home directory of the user, both read by the monitor. The walk
    /// over the home directory happens here, in the monitor process, so the
    /// child between `fork` and `execve` only opens paths and enacts.
    pub fn build(work_tree: &Path, home: Option<&Path>, abi: i32) -> Self {
        let mut plan = Plan {
            abi,
            home: home.map(Path::to_path_buf),
            ..Default::default()
        };
        let full = rights_full(abi);

        if let Some(home) = home {
            plan.hidden = HIDDEN
                .iter()
                .map(|spec| (home.join(spec.rel), spec))
                .collect();
        }

        // The work tree is the one tree the session owns. A work tree that
        // sits inside a hidden path must stay ungranted: a rule on it would
        // reach the credential store underneath, and no right of the session
        // may do that.
        if plan.hidden_beneath(work_tree).is_some() {
            plan.work_tree_ungranted = true;
        } else {
            plan.grant_carved(work_tree.to_path_buf(), full);
            plan.work_tree = Some(work_tree.to_path_buf());
        }
        for dir in WRITABLE_TMP {
            plan.push(PathBuf::from(dir), full);
        }
        for dir in SYSTEM_RX {
            plan.push(PathBuf::from(dir), rights_read_execute());
        }
        for dir in SYSTEM_LINKS {
            plan.push(PathBuf::from(dir), rights_read_execute());
        }
        for dir in SYSTEM_RO {
            plan.push(PathBuf::from(dir), rights_read());
        }
        for (dev, write) in DEV_SAFE {
            plan.push(
                PathBuf::from(dev),
                if *write {
                    RIGHTS_BENEATH
                } else {
                    right::READ_FILE | right::EXECUTE
                },
            );
        }

        // The home directory holds hidden paths, so it gets no rule of its
        // own: the enumeration grants every entry instead, and grants the
        // entries of every directory on the way down to a hidden path. A
        // session whose work tree is the home directory keeps the work-tree
        // grant above, which carves the same paths out.
        if let Some(home) = home {
            if !plan.work_tree_is(home) {
                plan.grant_carved(home.to_path_buf(), full);
            }
        }
        plan
    }

    /// Returns the hidden path that sits at or below `dir`, when there is one.
    fn hidden_beneath(&self, dir: &Path) -> Option<&Path> {
        self.hidden
            .iter()
            .map(|(path, _)| path.as_path())
            .find(|hidden| hidden.starts_with(dir))
    }

    /// True when the floor granted `dir` as the work tree.
    fn work_tree_is(&self, dir: &Path) -> bool {
        self.work_tree.as_deref() == Some(dir)
    }

    /// Grants `dir` with `rights`, carving every hidden path below it out.
    ///
    /// Landlock has no deny rule and a rule on a directory reaches every file
    /// under it, so a directory that holds a hidden path gets no rule of its
    /// own. Instead every entry beside the hidden path is granted, and the
    /// walk repeats one level deeper for every entry that itself holds a
    /// hidden path. A path that hides only its writes gets its own rule with
    /// read and execute and no write. The price, measured in the spike: the
    /// carved directory cannot be listed.
    fn grant_carved(&mut self, dir: PathBuf, rights: u64) {
        let Some(hidden_here) = self.hidden_beneath(&dir).map(|path| path.to_path_buf()) else {
            self.push(dir, rights);
            return;
        };
        let entries = match std::fs::read_dir(&dir) {
            Ok(entries) => entries,
            Err(_) => return, // a grant that cannot be enumerated is skipped
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if hidden_here == path {
                if let Some(Hide::Writes) = self.hidden_kind(&path) {
                    self.push(path, rights_read_execute());
                }
                continue;
            }
            if hidden_here.starts_with(&path) {
                continue;
            }
            if self
                .hidden
                .iter()
                .any(|(hidden, _)| hidden.starts_with(&path))
            {
                self.grant_carved(path, rights);
            } else {
                self.push(path, rights);
            }
        }
    }

    /// How one hidden path hides, when it is one of them.
    fn hidden_kind(&self, path: &Path) -> Option<Hide> {
        self.hidden
            .iter()
            .find(|(hidden, _)| hidden == path)
            .map(|(_, spec)| spec.how)
    }

    /// Adds one grant for a path that exists.
    fn push(&mut self, path: PathBuf, rights: u64) {
        if path.exists() {
            self.grants.push(Grant { path, rights });
        }
    }

    /// How many rules the plan makes.
    pub fn rule_count(&self) -> usize {
        self.grants.len()
    }

    /// True when the plan carries the signal scope.
    pub fn scopes_signals(&self) -> bool {
        self.abi >= 6
    }

    /// The rule classes of the built-in pack that the kernel answers with a
    /// refusal **for every action the rule can match**, so the session never
    /// needs to ask them.
    ///
    /// This list is deliberately narrow, and the bar is soundness: a rule
    /// rides on the floor only when no session shape exists in which the rule
    /// matches and the kernel still allows the action.
    ///
    /// * `filesystem.etc.write` names `/etc` and nothing else, and the floor
    ///   grants no write under `/etc`.
    /// * `filesystem.delete.system-path` names the system trees; the writable
    ///   exception paths of the rule (`/var/tmp`, `/var/cache`, `/dev/shm`)
    ///   are exactly the writable exception paths of the floor.
    /// * `filesystem.delete.mount-root` names the media trees, which get no
    ///   rule at all.
    /// * `filesystem.device.truncate` names raw devices under `/dev`, which
    ///   get no rule at all. It needs the `TRUNCATE` right, so ABI 3.
    /// * `filesystem.credentials.write` names credential stores, which the
    ///   floor hides — but a `.ssh` under the work tree or under `/tmp` is
    ///   **not** hidden, so this class rides on the floor only for a path
    ///   under one of the hidden prefixes ([`Plan::denied_prefixes`]). That
    ///   is a property of the mechanism, measured in `research/spikes/landlock`
    ///   section E: no ruleset composition subtracts a shape from a granted
    ///   tree, so the question stays with the pack (`docs/LANDLOCK-CONTRACT.md`
    ///   §6).
    /// * `process.signal.kill-everything` is the signal scope, which holds
    ///   for every process outside the session. It needs ABI 6.
    ///
    /// Three more classes are backed by the kernel without joining this list:
    /// `filesystem.delete.root`, `filesystem.device.destroy` and
    /// `process.signal.supervision` answer `deny` today, so the exec boundary
    /// keeps stopping them before the program runs and the floor stands under
    /// that decision when the boundary misses. And three classes almost move
    /// but not quite — `filesystem.find.delete-wide`,
    /// `filesystem.interpreter.delete-system-path` and
    /// `filesystem.sensitive.exec-write` match shapes the floor cannot deny
    /// (a sweep over a work tree at the home directory, a `.ssh` under
    /// `/tmp`), so they keep their question.
    pub fn enforced_rules(&self) -> Vec<String> {
        let mut rules = BTreeSet::new();
        rules.insert("filesystem.etc.write".to_string());
        rules.insert("filesystem.delete.system-path".to_string());
        rules.insert("filesystem.delete.mount-root".to_string());
        rules.insert("filesystem.credentials.write".to_string());
        if self.abi >= 3 {
            rules.insert("filesystem.device.truncate".to_string());
        }
        if self.scopes_signals() {
            rules.insert("process.signal.kill-everything".to_string());
        }
        rules.into_iter().collect()
    }

    /// The absolute path prefixes the kernel denies, each with the rule class
    /// it answers.
    ///
    /// The session uses this to know that a held **file open** on one of
    /// these prefixes cannot run, whatever the user would answer. Only the
    /// rule classes of the enforced set that judge a file open are named
    /// here; the other classes of [`Plan::enforced_rules`] judge an exec and
    /// name trees the floor never grants. The prefixes are facts of the
    /// ruleset, fixed before the program started.
    pub fn denied_prefixes(&self) -> Vec<(String, &'static str)> {
        let mut pairs: Vec<(String, &'static str)> = self
            .hidden
            .iter()
            .map(|(path, spec)| (path.display().to_string(), spec.rule))
            .collect();
        pairs.push(("/etc".to_string(), "filesystem.etc.write"));
        pairs
    }

    /// Maps a path to the rule class the kernel enforces on it.
    ///
    /// The answer is certain: the ruleset was fixed before the program
    /// started and can never be relaxed, so an open that the floor denies
    /// fails with `EACCES` whatever the program does. The path itself comes
    /// from the seccomp stop and is advisory — a raced path can name the
    /// wrong rule in a message, never a wrong decision, because the kernel
    /// makes the decision on its own resolved object.
    pub fn denies(&self, asked: &str, write: bool) -> Option<Denial> {
        let path = Path::new(asked);
        let denial = |rule: Option<&'static str>| {
            Some(Denial {
                path: asked.to_string(),
                rule,
            })
        };

        // A hidden credential store denies every access; a store that hides
        // only its writes still answers a read.
        for (hidden, spec) in &self.hidden {
            if path.starts_with(hidden) {
                let rule = if write {
                    Some(spec.rule)
                } else if spec.how == Hide::Everything {
                    spec.read_rule.or(Some(spec.rule))
                } else {
                    return None;
                };
                return denial(rule);
            }
        }
        if self
            .home
            .as_ref()
            .is_some_and(|home| path.starts_with(home))
        {
            // Inside the home, outside the hidden stores: granted.
            return None;
        }

        // A write under a system tree cannot run.
        if path.starts_with("/etc") {
            return if write {
                denial(Some("filesystem.etc.write"))
            } else {
                None
            };
        }
        for tree in SYSTEM_RX.iter().chain(SYSTEM_RO.iter()).chain(SYSTEM_LINKS) {
            if path.starts_with(tree) {
                return if write {
                    denial(Some("filesystem.delete.system-path"))
                } else {
                    None
                };
            }
        }

        // A raw device gets no rule at all. The safe nodes of `/dev` stay
        // open in both directions — the measured rule of a device node
        // allows the write — and everything else under `/dev` answers with
        // the rule class that made the devices unreachable.
        if path.starts_with("/dev") && !DEV_SAFE.iter().any(|(dev, _)| path.starts_with(dev)) {
            return if write {
                denial(Some("filesystem.device.destroy"))
            } else {
                denial(None)
            };
        }
        if DEV_SAFE.iter().any(|(dev, _)| path.starts_with(dev)) {
            return None;
        }
        for tree in MEDIA_ROOTS {
            if path.starts_with(tree) {
                return denial(Some("filesystem.delete.mount-root"));
            }
        }

        // Every other path outside the grants is denied too — the floor is an
        // allow list — but no rule of the pack maps to it, so the explainer
        // names the sandbox and not a rule.
        if write && !self.granted(path) {
            return denial(None);
        }
        None
    }

    /// True when a grant covers `path` for a write.
    fn granted(&self, path: &Path) -> bool {
        self.grants
            .iter()
            .any(|grant| path.starts_with(&grant.path) && grant.rights & right::WRITE_FILE != 0)
    }

    /// Enacts the plan in the calling process.
    ///
    /// The call runs in the child, after `PTRACE_TRACEME` and after the
    /// seccomp filter, before `execve`. It only opens paths and makes two
    /// syscalls per rule, so it needs no directory walk and no allocation
    /// that the monitor has not already made.
    pub fn install(&self) -> io::Result<()> {
        let mut handled = right::READ_FILE
            | right::READ_DIR
            | right::EXECUTE
            | right::WRITE_FILE
            | right::REMOVE_DIR
            | right::REMOVE_FILE
            | right::MAKE_CHAR
            | right::MAKE_DIR
            | right::MAKE_REG
            | right::MAKE_SOCK
            | right::MAKE_FIFO
            | right::MAKE_BLOCK
            | right::MAKE_SYM;
        if self.abi >= 2 {
            handled |= right::REFER;
        }
        if self.abi >= 3 {
            handled |= right::TRUNCATE;
        }
        let attr = RulesetAttr {
            handled_access_fs: handled,
            handled_access_net: 0,
            scoped: if self.scopes_signals() {
                SCOPE_SIGNAL
            } else {
                0
            },
        };
        let ruleset = create_ruleset(Some(&attr), std::mem::size_of::<RulesetAttr>(), 0)?;
        let installed = (|| -> io::Result<()> {
            let fd = unsafe { BorrowedFd::borrow_raw(ruleset) };
            for grant in &self.grants {
                let file = open_path(&grant.path)?;
                // A rule may only name rights that its object can carry, and
                // this kernel rejects the whole rule when it holds one too
                // many. Measured, in the spike directory and on this machine:
                // a write right belongs to a **directory** rule and governs
                // every file beneath it; a rule that names a file or a device
                // node may carry read, execute and truncate, and a write to
                // a device is not a file write that the kernel checks at all
                // (a workload writes to `/dev/null` with no write right). The
                // answer comes from the descriptor the rule will name, and
                // not from a walk the monitor made earlier.
                let mut allowed = grant.rights;
                if object_kind(file.as_raw_fd()) != Object::Directory {
                    allowed &= RIGHTS_BENEATH;
                }
                let attr = PathBeneathAttr {
                    allowed_access: allowed,
                    parent_fd: file.as_raw_fd(),
                    _pad: 0,
                };
                add_rule(fd, &attr)?;
            }
            // An unprivileged process may only enact a ruleset after it
            // promised that it will never gain a privilege. The seccomp
            // filter asks for the same promise when it is installed; the
            // floor needs it on its own, because it must also hold a session
            // that runs with `--syscall-filter off`.
            promise_no_new_privs()?;
            restrict_self(fd)
        })();
        // SAFETY: closing a descriptor this function made.
        unsafe { libc::close(ruleset) };
        installed
    }
}

/// Opens a path for a Landlock rule.
///
/// The flag is `O_PATH|O_CLOEXEC`: the descriptor names the object and reads
/// no byte of it, and `execve` closes it again.
fn open_path(path: &Path) -> io::Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_PATH | libc::O_CLOEXEC)
        .open(path)
}

/// What a descriptor names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Object {
    /// A directory, whose rule may carry every right, the write right
    /// included.
    Directory,
    /// Anything else: a file, a device node, a socket, a pipe. A rule that
    /// names such an object may carry read, execute and truncate, and no
    /// write: the write right belongs to the rule of the directory above it.
    Beneath,
}

/// Reads what kind of object a descriptor names.
fn object_kind(fd: i32) -> Object {
    let mut stat: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: `fstat` writes into a `stat` of the caller and reads nothing.
    if unsafe { libc::fstat(fd, &mut stat) } != 0 {
        return Object::Beneath;
    }
    match stat.st_mode & libc::S_IFMT {
        libc::S_IFDIR => Object::Directory,
        _ => Object::Beneath,
    }
}

/// Promises the kernel that this process never gains a privilege.
fn promise_no_new_privs() -> io::Result<()> {
    // SAFETY: `prctl` changes only the state of the calling process, which is
    // the forked child before its `execve`.
    let rc = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
    if rc != 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plan_with_home(home: &Path) -> Plan {
        Plan::build(Path::new("/tmp/work"), Some(home), 6)
    }

    #[test]
    fn the_floor_hides_the_credential_stores_of_the_home() {
        let home = std::env::temp_dir().join("afw-floor-home");
        std::fs::create_dir_all(home.join(".ssh")).ok();
        std::fs::create_dir_all(home.join(".aws")).ok();
        std::fs::write(home.join(".aws/config"), "x").ok();
        std::fs::create_dir_all(home.join("devel")).ok();

        let plan = plan_with_home(&home);
        assert!(plan
            .denies(&home.join(".ssh/id_ed25519").display().to_string(), false)
            .is_some_and(|d| d.rule == Some("filesystem.credentials.read")));
        assert!(plan
            .denies(
                &home.join(".ssh/authorized_keys").display().to_string(),
                true
            )
            .is_some_and(|d| d.rule == Some("filesystem.credentials.write")));
        assert!(plan
            .denies(&home.join(".aws/credentials").display().to_string(), false)
            .is_some_and(|d| d.rule == Some("filesystem.credentials.read")));
        // The non-secret file beside the secret one stays readable.
        assert!(plan
            .denies(&home.join(".aws/config").display().to_string(), false)
            .is_none());
        assert!(plan
            .denies(&home.join("devel/app/main.rs").display().to_string(), true)
            .is_none());
    }

    #[test]
    fn a_tool_configuration_file_keeps_its_read_and_loses_its_write() {
        let home = std::env::temp_dir().join("afw-floor-kube");
        let _ = std::fs::remove_dir_all(&home);
        std::fs::create_dir_all(home.join(".kube")).expect("make the kube directory");
        std::fs::write(home.join(".kube/config"), "apiVersion: v1").expect("make the config");

        let plan = plan_with_home(&home);
        // The write is denied and named.
        assert!(plan
            .denies(&home.join(".kube/config").display().to_string(), true)
            .is_some_and(|d| d.rule == Some("filesystem.credentials.write")));
        // The read stays: kubectl keeps working.
        assert!(plan
            .denies(&home.join(".kube/config").display().to_string(), false)
            .is_none());
        // The file carries a rule with read and execute and no write, so the
        // kernel really allows the read.
        let kube = plan
            .grants
            .iter()
            .find(|g| g.path == home.join(".kube/config"))
            .expect("the config file carries its own rule");
        assert_eq!(kube.rights, rights_read_execute());
    }

    #[test]
    fn the_floor_names_the_system_trees_and_the_devices() {
        let plan = plan_with_home(Path::new("/home/dev"));
        assert!(plan
            .denies("/etc/passwd", true)
            .is_some_and(|d| d.rule == Some("filesystem.etc.write")));
        assert!(plan.denies("/etc/passwd", false).is_none());
        assert!(plan
            .denies("/usr/share/x", true)
            .is_some_and(|d| d.rule == Some("filesystem.delete.system-path")));
        assert!(plan
            .denies("/dev/sda", true)
            .is_some_and(|d| d.rule == Some("filesystem.device.destroy")));
        assert!(plan
            .denies("/mnt/backup", true)
            .is_some_and(|d| d.rule == Some("filesystem.delete.mount-root")));
        assert!(plan
            .denies("/var/lib/x", true)
            .is_some_and(|d| d.rule == Some("filesystem.delete.system-path")));
        // /tmp stays writable.
        assert!(plan.denies("/tmp/build", true).is_none());
    }

    #[test]
    fn an_unlisted_path_has_no_rule_to_name() {
        let plan = plan_with_home(Path::new("/home/dev"));
        let denial = plan.denies("/srv2/data", true).expect("denied");
        assert!(denial.rule.is_none());
        assert!(plan.denies("/srv2/data", false).is_none());
    }

    #[test]
    fn the_enforced_rules_follow_the_abi_of_the_kernel() {
        let old = Plan::build(Path::new("/tmp/work"), None, 1);
        assert!(!old
            .enforced_rules()
            .contains(&"filesystem.device.truncate".to_string()));
        assert!(!old
            .enforced_rules()
            .contains(&"process.signal.kill-everything".to_string()));

        let now = Plan::build(Path::new("/tmp/work"), None, 8);
        assert!(now
            .enforced_rules()
            .contains(&"filesystem.device.truncate".to_string()));
        assert!(now
            .enforced_rules()
            .contains(&"process.signal.kill-everything".to_string()));
        assert!(now.scopes_signals());
    }

    #[test]
    fn a_work_tree_inside_a_hidden_path_stays_ungranted() {
        let home = std::env::temp_dir().join("afw-floor-hidden-work");
        std::fs::create_dir_all(home.join(".ssh")).ok();
        let work = home.join(".ssh");
        let plan = Plan::build(&work, Some(&home), 6);
        assert!(plan.work_tree_ungranted);
        assert!(plan.work_tree.is_none());
        assert!(!plan
            .grants
            .iter()
            .any(|grant| grant.path.starts_with(&work)));
    }

    #[test]
    fn the_carve_out_grants_the_siblings_and_not_the_hidden_dir() {
        let home = std::env::temp_dir().join("afw-floor-carve");
        let _ = std::fs::remove_dir_all(&home);
        std::fs::create_dir_all(home.join(".ssh")).ok();
        std::fs::create_dir_all(home.join("devel")).ok();
        std::fs::write(home.join(".bashrc"), "x").ok();

        let plan = plan_with_home(&home);
        let granted: Vec<&Path> = plan.grants.iter().map(|g| g.path.as_path()).collect();
        assert!(granted.contains(&home.join("devel").as_path()));
        assert!(granted.contains(&home.join(".bashrc").as_path()));
        assert!(!granted.contains(&home.join(".ssh").as_path()));
        assert!(!granted.contains(&home.as_path()));
    }

    #[test]
    fn a_credential_shape_under_tmp_keeps_its_grant_and_its_question() {
        // The contract of docs/LANDLOCK-CONTRACT.md: the hidden set is the
        // home enumeration and nothing else. A shape under /tmp is covered
        // by the /tmp grant, the plan does not map it to a denial, and no
        // denied prefix reaches it — which is what keeps the pack's
        // question alive for the write (e2e K9–K12).
        let work = std::env::temp_dir().join("afw-floor-tmpshape");
        let _ = std::fs::remove_dir_all(&work);
        std::fs::create_dir_all(work.join("x/.ssh")).ok();

        let plan = plan_with_home(Path::new("/home/dev"));
        let shape = "/tmp/x/.ssh/id_rsa";
        assert!(plan.denies(shape, true).is_none());
        assert!(plan.denies(shape, false).is_none());
        assert!(plan.granted(Path::new(shape)));
        assert!(plan
            .denied_prefixes()
            .iter()
            .all(|(prefix, _)| !prefix.starts_with("/tmp")));
    }

    #[test]
    fn a_credential_shape_in_the_work_tree_keeps_its_question() {
        // The same holds inside the work tree: the grant on the work tree
        // covers a .ssh created there, so the floor cannot answer the
        // credential write — the question stays with the pack.
        let work = std::env::temp_dir().join("afw-floor-workshape");
        let _ = std::fs::remove_dir_all(&work);
        std::fs::create_dir_all(work.join(".ssh")).ok();

        let plan = Plan::build(&work, Some(Path::new("/home/dev")), 6);
        let shape = work.join(".ssh/id_rsa");
        assert!(plan.denies(&shape.display().to_string(), true).is_none());
        assert!(plan.granted(&shape));
        // The floor also granted the work tree itself: a hidden path under
        // it would have left it ungranted, but a shape is not a hidden path.
        assert!(!plan.work_tree_ungranted);
    }
}
