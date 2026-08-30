//! The kernel filter that makes an in-process action visible.
//!
//! The `ptrace` loop of [`crate::tracer`] stops a process when it loads a new
//! program. That stop cannot see what a program does *after* it started. A
//! single Python process can read a key, delete a tree and open a connection
//! without ever running a second program, and the exec boundary sees none of
//! it.
//!
//! This module narrows that gap with a small `seccomp` BPF filter. The filter
//! runs in the kernel, for every process of the session, and answers
//! `SECCOMP_RET_TRACE` for the few calls that a rule can judge. The kernel
//! then makes a `PTRACE_EVENT_SECCOMP` stop and the monitor decides. Every
//! other call runs with no supervisor in the loop, which is the whole reason
//! the layer is cheap: `research/spikes/seccomp-ptrace/FINDINGS.md` measured
//! 1.16× for the write-only filter against 6.42× for a stop at every call.
//!
//! **What this module covers is the open with write intent and the outgoing
//! connection, and nothing else.** The filter holds no `unlink`, no `rmdir`
//! and no `rename`, so a program that deletes a tree from inside itself is
//! still judged only at the command that started it. The event schema has no
//! shape for a delete either. That gap stays open.
//!
//! # What the filter holds
//!
//! | Call | Held when |
//! | --- | --- |
//! | `open` | the `flags` argument asks to change the file |
//! | `openat` | the `flags` argument asks to change the file |
//! | `creat` | always, because it always changes the file |
//! | `openat2` | always, see below |
//! | `connect` | always |
//!
//! [`crate::SyscallFilter::AllOpens`] adds a second rule for `open` and
//! `openat` with no test on the flags, so a read is held too.
//!
//! A BPF filter cannot follow a pointer, so it can test the `flags` scalar of
//! an `open` but never the path. `openat2` keeps its flags inside a
//! `struct open_how` behind a pointer, so the kernel cannot classify it at
//! all and every `openat2` has to reach the monitor.
//!
//! `execve` is deliberately **not** in the filter. The monitor already sees
//! an exec at `PTRACE_EVENT_EXEC`, and a filter that holds `execve` would
//! break its own first `execve`: `SECCOMP_RET_TRACE` returns `ENOSYS` until
//! the monitor has set `PTRACE_O_TRACESECCOMP`, and the monitor can only set
//! that option at a stop that the first `execve` has to reach first.
//!
//! `write` and `sendto` are also out. They are the only place where the
//! content of an open connection appears, and holding them was measured at
//! 8.8× on a chatty program. That price is the same order as the full
//! `PTRACE_SYSCALL` that this design already rejected.
//!
//! # Soundness
//!
//! `docs/DETECTION-RESEARCH.md` section 2 is binding here. The **decision to
//! hold the call at all** is made in the kernel on the call number and on a
//! scalar argument, and that decision cannot be raced. The **path and the
//! socket address** are read out of the memory of the target at the stop, and
//! a second thread of the target can rewrite that memory before the kernel
//! reads it again. Such a value is therefore sound for reporting, for a
//! refusal and for a question to the user, and it must never be the basis of
//! an automatic allow. It is not one here: a path that matches no rule is
//! allowed because nothing matched, not because the monitor trusted the path.

use af_core::{Action, Pid};

/// Which calls the kernel holds for the monitor.
///
/// The value travels from [`crate::MonitorConfig`] into the child process,
/// where the filter is installed.
pub use crate::SyscallFilter;

/// Bits of the `flags` argument that mean "this open can change the file".
///
/// `O_RDONLY` is zero, so a read-only open never carries one of these bits.
/// The kernel tests this mask itself, which is what keeps the write-only
/// filter cheap: the measured file workload fell from 1034 stops to 3.
#[cfg(target_arch = "x86_64")]
const WRITE_FLAGS: u32 =
    (libc::O_WRONLY | libc::O_RDWR | libc::O_CREAT | libc::O_TRUNC | libc::O_APPEND) as u32;

/// The error that a refused call returns to the program.
const REFUSE_ERRNO: i32 = libc::EPERM;

/// Reports whether this machine can run the kernel filter.
///
/// The answer comes from a real question to the kernel and never from a
/// version number.
pub(crate) fn availability() -> Result<(), String> {
    arch_check()?;
    action_available()
}

/// Returns `Err` on an architecture that this filter is not built for.
///
/// A system call number is not the same on two architectures, so a filter
/// table is never portable. The monitor refuses to install a wrong table and
/// keeps the exec boundary instead.
#[cfg(target_arch = "x86_64")]
fn arch_check() -> Result<(), String> {
    Ok(())
}

#[cfg(not(target_arch = "x86_64"))]
fn arch_check() -> Result<(), String> {
    Err(format!(
        "the kernel filter is built for x86_64 only, and this machine is {}; \
         the monitor keeps the exec boundary and observes no file or network action",
        std::env::consts::ARCH
    ))
}

/// Asks the kernel whether it offers `SECCOMP_RET_TRACE`.
fn action_available() -> Result<(), String> {
    let action = libc::SECCOMP_RET_TRACE;
    // SAFETY: SECCOMP_GET_ACTION_AVAIL reads one 32-bit action value through
    // the pointer and changes nothing.
    let answer = unsafe {
        libc::syscall(
            libc::SYS_seccomp,
            libc::SECCOMP_GET_ACTION_AVAIL,
            0u32,
            &action as *const libc::c_uint,
        )
    };
    if answer == 0 {
        return Ok(());
    }
    Err(format!(
        "this kernel does not offer the seccomp trace action: {}",
        std::io::Error::last_os_error()
    ))
}

/// Installs the filter in the calling process, and never fails the session.
///
/// The call happens inside the `pre_exec` closure of the child, after
/// `ptrace::traceme()` and before `execve`. The filter is inherited by every
/// child and it survives `execve`, so this one install covers the whole
/// process tree for the whole session.
///
/// A kernel that refuses the filter leaves the child with the exec boundary
/// alone. The child cannot report that, so it stays quiet: the monitor reads
/// `/proc/<pid>/status` of the root at the first stop and tells the user
/// itself. A child that returned an error here would fail the whole session,
/// which is the one outcome that must never happen.
pub(crate) fn install(filter: SyscallFilter) {
    if filter == SyscallFilter::Off {
        // `no_new_privs` is only set when a filter is really installed, so a
        // session with the layer switched off behaves exactly as before.
        return;
    }
    install_filter(filter);
}

#[cfg(target_arch = "x86_64")]
fn install_filter(filter: SyscallFilter) {
    let program = build_program(filter);
    let prog = libc::sock_fprog {
        len: program.len() as libc::c_ushort,
        filter: program.as_ptr() as *mut libc::sock_filter,
    };

    // SAFETY: both calls only change the state of the calling process, which
    // is the forked child before its `execve`.
    unsafe {
        // An unprivileged process may only install a filter after it promised
        // that it will never gain a privilege. `ptrace` already strips the
        // setuid bit of every traced program, so this promise loses nothing
        // that the monitor had not already taken away.
        if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
            return;
        }
        libc::syscall(
            libc::SYS_seccomp,
            libc::SECCOMP_SET_MODE_FILTER,
            0u32,
            &prog as *const libc::sock_fprog,
        );
    }
}

#[cfg(not(target_arch = "x86_64"))]
fn install_filter(_filter: SyscallFilter) {}

/// Returns true when the kernel really holds a filter for this process.
///
/// The monitor asks this of the root process at its first stop. The answer is
/// the only honest proof that the layer is active, because the child that
/// installed the filter could not report a failure.
pub(crate) fn is_active(pid: Pid) -> bool {
    let Ok(text) = std::fs::read_to_string(format!("/proc/{pid}/status")) else {
        return false;
    };
    // `Seccomp: 2` is SECCOMP_MODE_FILTER. 0 is no filter and 1 is the old
    // strict mode, which this monitor never installs.
    text.lines()
        .find_map(|line| line.strip_prefix("Seccomp:"))
        .map(|value| value.trim() == "2")
        .unwrap_or(false)
}

// ---------------------------------------------------------------------------
// The BPF program
// ---------------------------------------------------------------------------

/// One rule of the filter.
///
/// `arg_mask` of zero means that the rule tests the call number alone. A rule
/// with a mask also tests one scalar argument, which is all that a BPF filter
/// can do, because it cannot follow a pointer.
#[cfg(target_arch = "x86_64")]
struct Rule {
    /// System call number.
    nr: u32,
    /// Index of the argument to test, when there is a mask.
    arg_index: u32,
    /// Bits that must be set in that argument, or zero for "do not test".
    arg_mask: u32,
}

/// Returns the rules of one filter mode.
#[cfg(target_arch = "x86_64")]
fn rules_of(filter: SyscallFilter) -> Vec<Rule> {
    let openat = libc::SYS_openat as u32;
    let open = libc::SYS_open as u32;
    let openat2 = libc::SYS_openat2 as u32;
    let connect = libc::SYS_connect as u32;

    // An open that asks to change the file. The kernel tests the flags, so a
    // read-only open never wakes the monitor.
    let mut rules = vec![
        Rule {
            nr: openat,
            arg_index: 2,
            arg_mask: WRITE_FLAGS,
        },
        Rule {
            nr: open,
            arg_index: 1,
            arg_mask: WRITE_FLAGS,
        },
    ];
    if filter == SyscallFilter::AllOpens {
        // The write rules stand first, but the monitor reads the flags at the
        // stop anyway, so the order only decides which rule answers and not
        // what the monitor sees.
        rules.push(Rule {
            nr: openat,
            arg_index: 0,
            arg_mask: 0,
        });
        rules.push(Rule {
            nr: open,
            arg_index: 0,
            arg_mask: 0,
        });
    }
    // `creat` is an open that always changes the file, so it needs no test
    // on a flag. glibc turns `creat()` into `open`, but a program can call
    // the number itself.
    rules.push(Rule {
        nr: libc::SYS_creat as u32,
        arg_index: 0,
        arg_mask: 0,
    });
    // `openat2` hides its flags in a structure behind a pointer, so the
    // kernel cannot classify it. Every one of them must reach the monitor.
    rules.push(Rule {
        nr: openat2,
        arg_index: 0,
        arg_mask: 0,
    });
    rules.push(Rule {
        nr: connect,
        arg_index: 0,
        arg_mask: 0,
    });
    rules
}

/// The value that the kernel puts in the `arch` field for this machine.
#[cfg(target_arch = "x86_64")]
const AUDIT_ARCH_X86_64: u32 = 0xc000_003e;

/// Offset of the `nr` field of `struct seccomp_data`.
#[cfg(target_arch = "x86_64")]
const OFF_NR: u32 = 0;
/// Offset of the `arch` field of `struct seccomp_data`.
#[cfg(target_arch = "x86_64")]
const OFF_ARCH: u32 = 4;
/// Offset of the first `args` field of `struct seccomp_data`.
#[cfg(target_arch = "x86_64")]
const OFF_ARGS: u32 = 16;

// BPF instruction codes. They come from `linux/bpf_common.h` and they are the
// same on every architecture.
#[cfg(target_arch = "x86_64")]
mod bpf {
    /// Load a 32-bit word from a fixed offset: `BPF_LD | BPF_W | BPF_ABS`.
    pub const LD_W_ABS: u16 = 0x20;
    /// Jump when the accumulator equals the constant: `BPF_JMP | BPF_JEQ | BPF_K`.
    pub const JMP_JEQ_K: u16 = 0x15;
    /// Jump when the accumulator is at least the constant: `BPF_JMP | BPF_JGE | BPF_K`.
    pub const JMP_JGE_K: u16 = 0x35;
    /// Jump when the accumulator shares a bit with the constant: `BPF_JMP | BPF_JSET | BPF_K`.
    pub const JMP_JSET_K: u16 = 0x45;
    /// Return the constant as the answer of the filter: `BPF_RET | BPF_K`.
    pub const RET_K: u16 = 0x06;
}

/// Makes one instruction with no jump.
#[cfg(target_arch = "x86_64")]
fn stmt(code: u16, k: u32) -> libc::sock_filter {
    libc::sock_filter {
        code,
        jt: 0,
        jf: 0,
        k,
    }
}

/// Makes one conditional instruction.
#[cfg(target_arch = "x86_64")]
fn jump(code: u16, k: u32, jt: u8, jf: u8) -> libc::sock_filter {
    libc::sock_filter { code, jt, jf, k }
}

/// Builds the BPF program of one filter mode.
///
/// Every rule block starts with its own load of the call number and falls
/// through to the next block when it does not match, so no jump ever has to
/// count the instructions of another block.
#[cfg(target_arch = "x86_64")]
fn build_program(filter: SyscallFilter) -> Vec<libc::sock_filter> {
    let mut insns = vec![
        // A system call number belongs to one architecture. A program that
        // runs under another one is allowed rather than judged by a wrong
        // table.
        stmt(bpf::LD_W_ABS, OFF_ARCH),
        jump(bpf::JMP_JEQ_K, AUDIT_ARCH_X86_64, 1, 0),
        stmt(bpf::RET_K, libc::SECCOMP_RET_ALLOW),
        // The x32 ABI adds 0x40000000 to every number, so its numbers do not
        // mean what this table says. Those calls are allowed too.
        stmt(bpf::LD_W_ABS, OFF_NR),
        jump(bpf::JMP_JGE_K, 0x4000_0000, 0, 1),
        stmt(bpf::RET_K, libc::SECCOMP_RET_ALLOW),
    ];

    for rule in rules_of(filter) {
        insns.push(stmt(bpf::LD_W_ABS, OFF_NR));
        if rule.arg_mask == 0 {
            insns.push(jump(bpf::JMP_JEQ_K, rule.nr, 0, 1));
            insns.push(stmt(bpf::RET_K, libc::SECCOMP_RET_TRACE));
        } else {
            insns.push(jump(bpf::JMP_JEQ_K, rule.nr, 0, 3));
            // The machine is little endian and a flags argument never needs
            // more than 32 bits, so the low word is enough.
            insns.push(stmt(bpf::LD_W_ABS, OFF_ARGS + 8 * rule.arg_index));
            insns.push(jump(bpf::JMP_JSET_K, rule.arg_mask, 0, 1));
            insns.push(stmt(bpf::RET_K, libc::SECCOMP_RET_TRACE));
        }
    }

    insns.push(stmt(bpf::RET_K, libc::SECCOMP_RET_ALLOW));
    insns
}

// ---------------------------------------------------------------------------
// The stop
// ---------------------------------------------------------------------------

/// Reads what the held process is about to do.
///
/// Returns `None` when the call is not one that this layer reports, when the
/// registers cannot be read, or when the arguments name something that the
/// policy engine has no shape for. The caller then simply lets the call run:
/// the monitor never guesses.
#[cfg(target_arch = "x86_64")]
pub(crate) fn observe(pid: Pid) -> Option<Action> {
    use nix::sys::ptrace;
    use nix::unistd::Pid as NixPid;

    let regs = ptrace::getregs(NixPid::from_raw(pid)).ok()?;
    // At a seccomp stop the call has not run yet, and `orig_rax` still holds
    // the number that the program asked for.
    let nr = regs.orig_rax as i64;
    let args = [regs.rdi, regs.rsi, regs.rdx, regs.r10, regs.r8, regs.r9];

    if nr == libc::SYS_open {
        return file_open(pid, None, args[0], args[1] as u32);
    }
    if nr == libc::SYS_openat {
        return file_open(pid, Some(args[0] as i32), args[1], args[2] as u32);
    }
    if nr == libc::SYS_creat {
        // `creat(path, mode)` is `open(path, O_CREAT|O_WRONLY|O_TRUNC, mode)`.
        return file_open(pid, None, args[0], libc::O_CREAT as u32);
    }
    if nr == libc::SYS_openat2 {
        // `struct open_how` is three 64-bit fields: flags, mode, resolve.
        let mut how = [0u8; 24];
        read_bytes(pid, args[2], &mut how)?;
        let flags = u64::from_ne_bytes(how[0..8].try_into().ok()?);
        return file_open(pid, Some(args[0] as i32), args[1], flags as u32);
    }
    if nr == libc::SYS_connect {
        return network_connect(pid, args[1], args[2] as usize);
    }
    None
}

#[cfg(not(target_arch = "x86_64"))]
pub(crate) fn observe(_pid: Pid) -> Option<Action> {
    None
}

/// Makes the file action of an open that waits at a stop.
fn file_open(pid: Pid, dirfd: Option<i32>, path_addr: u64, flags: u32) -> Option<Action> {
    let raw = read_cstring(pid, path_addr)?;
    let path = absolute(pid, dirfd, &raw);
    Some(Action::FileOpen {
        path,
        write: is_write(flags),
    })
}

/// Returns true when the flags of an open ask to change the file.
fn is_write(flags: u32) -> bool {
    #[cfg(target_arch = "x86_64")]
    {
        flags & WRITE_FLAGS != 0
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        let _ = flags;
        false
    }
}

/// Makes the network action of a `connect` that waits at a stop.
///
/// A local socket carries no address and no port, and a normal program makes
/// many of them, so this layer passes them by in silence.
fn network_connect(pid: Pid, addr: u64, len: usize) -> Option<Action> {
    let mut buf = [0u8; 28];
    let want = len.min(buf.len());
    if want < 4 {
        return None;
    }
    read_bytes(pid, addr, &mut buf[..want])?;
    let family = u16::from_ne_bytes([buf[0], buf[1]]);
    // The port is in network order in both families.
    let port = u16::from_be_bytes([buf[2], buf[3]]);

    if family == libc::AF_INET as u16 && want >= 8 {
        let octets: [u8; 4] = buf[4..8].try_into().ok()?;
        return Some(Action::NetworkConnect {
            host: None,
            addr: std::net::Ipv4Addr::from(octets).to_string(),
            port,
        });
    }
    if family == libc::AF_INET6 as u16 && want >= 24 {
        let octets: [u8; 16] = buf[8..24].try_into().ok()?;
        return Some(Action::NetworkConnect {
            host: None,
            addr: std::net::Ipv6Addr::from(octets).to_string(),
            port,
        });
    }
    None
}

/// Refuses the call that waits at a stop, with `EPERM`.
///
/// The program sees an ordinary permission error and can handle it like any
/// other. This is the right answer for a file or a connection, where
/// `SIGKILL` would take away a chance that the program still has.
///
/// The call number must become `-1`. Any other value makes the kernel run the
/// filter a second time, and the process would stop again for ever.
#[cfg(target_arch = "x86_64")]
pub(crate) fn refuse(pid: Pid) -> Result<(), nix::errno::Errno> {
    use nix::sys::ptrace;
    use nix::unistd::Pid as NixPid;

    let nix_pid = NixPid::from_raw(pid);
    let mut regs = ptrace::getregs(nix_pid)?;
    regs.orig_rax = u64::MAX;
    regs.rax = (-(REFUSE_ERRNO as i64)) as u64;
    ptrace::setregs(nix_pid, regs)
}

#[cfg(not(target_arch = "x86_64"))]
pub(crate) fn refuse(_pid: Pid) -> Result<(), nix::errno::Errno> {
    Err(nix::errno::Errno::ENOSYS)
}

// ---------------------------------------------------------------------------
// Reading the memory of the target
// ---------------------------------------------------------------------------

/// How much of a path the monitor reads.
const MAX_PATH_READ: usize = 4096;

/// Size of one page, which is where a `pread` on `/proc/<pid>/mem` stops.
const PAGE: u64 = 4096;

/// Opens the memory of a traced process.
///
/// The handle is opened again at every stop. A handle holds the address space
/// that the process had when it was opened, so a cached one breaks at every
/// `execve`, and the write-only filter makes too few stops for the saved
/// microsecond to matter.
fn open_mem(pid: Pid) -> Option<std::fs::File> {
    std::fs::File::open(format!("/proc/{pid}/mem")).ok()
}

/// Reads a fixed number of bytes out of the target.
fn read_bytes(pid: Pid, addr: u64, out: &mut [u8]) -> Option<()> {
    use std::os::unix::fs::FileExt;

    if addr == 0 {
        return None;
    }
    let file = open_mem(pid)?;
    file.read_exact_at(out, addr).ok()
}

/// Reads a text that ends with a zero byte out of the target.
///
/// A `pread` on `/proc/<pid>/mem` stops at the end of a page that the target
/// does not have, so the read never walks off the end of a mapping.
fn read_cstring(pid: Pid, addr: u64) -> Option<String> {
    use std::os::unix::fs::FileExt;

    if addr == 0 {
        return None;
    }
    let file = open_mem(pid)?;
    let mut out: Vec<u8> = Vec::new();
    while out.len() < MAX_PATH_READ {
        let at = addr.checked_add(out.len() as u64)?;
        let page_left = (PAGE - (at % PAGE)) as usize;
        let want = page_left.min(MAX_PATH_READ - out.len());
        let mut chunk = vec![0u8; want];
        let got = file.read_at(&mut chunk, at).ok()?;
        if got == 0 {
            break;
        }
        if let Some(end) = chunk[..got].iter().position(|byte| *byte == 0) {
            out.extend_from_slice(&chunk[..end]);
            return Some(String::from_utf8_lossy(&out).into_owned());
        }
        out.extend_from_slice(&chunk[..got]);
    }
    if out.is_empty() {
        return None;
    }
    Some(String::from_utf8_lossy(&out).into_owned())
}

// ---------------------------------------------------------------------------
// Path resolution
// ---------------------------------------------------------------------------

/// The directory descriptor that means "the working directory".
const AT_FDCWD: i32 = -100;

/// Turns the path of an open into an absolute path.
///
/// A rule names a whole path, so a relative one has to be joined with the
/// directory that the call counted from: the working directory of the process
/// for `open` and for `AT_FDCWD`, and the directory behind the descriptor for
/// every other `openat`.
///
/// The join is lexical. It never asks the file system, so it never follows a
/// link and never blocks, and the answer is the same at every replay.
fn absolute(pid: Pid, dirfd: Option<i32>, path: &str) -> String {
    if path.starts_with('/') {
        return clean(path);
    }
    let base = match dirfd {
        None | Some(AT_FDCWD) => std::fs::read_link(format!("/proc/{pid}/cwd")).ok(),
        Some(fd) => std::fs::read_link(format!("/proc/{pid}/fd/{fd}")).ok(),
    };
    let Some(base) = base else {
        return clean(path);
    };
    let joined = base.join(path);
    clean(&joined.to_string_lossy())
}

/// Removes the `.` and `..` parts of a path, without asking the file system.
fn clean(path: &str) -> String {
    let absolute = path.starts_with('/');
    let mut parts: Vec<&str> = Vec::new();
    for part in path.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                if matches!(parts.last(), Some(&last) if last != "..") {
                    parts.pop();
                } else if !absolute {
                    parts.push("..");
                }
            }
            other => parts.push(other),
        }
    }
    let joined = parts.join("/");
    if absolute {
        format!("/{joined}")
    } else if joined.is_empty() {
        ".".to_string()
    } else {
        joined
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_clean_path_keeps_itself() {
        assert_eq!(clean("/home/dev/.ssh/id_rsa"), "/home/dev/.ssh/id_rsa");
    }

    #[test]
    fn the_parts_that_mean_nothing_go_away() {
        assert_eq!(
            clean("/home/dev/./app/../.ssh/id_rsa"),
            "/home/dev/.ssh/id_rsa"
        );
        assert_eq!(clean("/home//dev/"), "/home/dev");
    }

    #[test]
    fn a_walk_above_the_root_stays_at_the_root() {
        assert_eq!(clean("/../../etc/passwd"), "/etc/passwd");
    }

    #[test]
    fn a_relative_path_keeps_the_walk_up() {
        assert_eq!(clean("../secrets/.env"), "../secrets/.env");
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn the_write_mask_names_every_change_flag() {
        // O_RDONLY is zero, so a read-only open carries no bit of the mask.
        assert!(!is_write(libc::O_RDONLY as u32));
        for flag in [
            libc::O_WRONLY,
            libc::O_RDWR,
            libc::O_CREAT,
            libc::O_TRUNC,
            libc::O_APPEND,
        ] {
            assert!(is_write(flag as u32), "flag {flag:#o} must mean a write");
        }
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn the_write_only_program_holds_four_calls() {
        let program = build_program(SyscallFilter::WriteOnly);
        // The prologue is 6 instructions, a rule with a mask is 5, a rule
        // without one is 3, and the program ends with one allow. The rules
        // are openat, open, creat, openat2 and connect.
        assert_eq!(program.len(), 6 + 5 + 5 + 3 + 3 + 3 + 1);
        assert!(program.len() < u16::MAX as usize);
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn the_all_opens_program_adds_the_two_read_rules() {
        let write_only = build_program(SyscallFilter::WriteOnly).len();
        let all_opens = build_program(SyscallFilter::AllOpens).len();
        assert_eq!(all_opens, write_only + 3 + 3);
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn the_filter_never_holds_execve() {
        // A filter that holds `execve` breaks its own first `execve`.
        let execve = libc::SYS_execve as u32;
        let execveat = libc::SYS_execveat as u32;
        for filter in [SyscallFilter::WriteOnly, SyscallFilter::AllOpens] {
            for rule in rules_of(filter) {
                assert_ne!(rule.nr, execve);
                assert_ne!(rule.nr, execveat);
            }
        }
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn the_filter_never_holds_write_or_sendto() {
        // Reading the content of an open connection was measured at 8.8×.
        let write = libc::SYS_write as u32;
        let sendto = libc::SYS_sendto as u32;
        for filter in [SyscallFilter::WriteOnly, SyscallFilter::AllOpens] {
            for rule in rules_of(filter) {
                assert_ne!(rule.nr, write);
                assert_ne!(rule.nr, sendto);
            }
        }
    }

    #[test]
    fn the_machine_that_runs_the_tests_offers_the_trace_action() {
        // The whole layer needs this. A machine that says no here would make
        // every other test of this module meaningless, and the monitor must
        // report it instead of failing quietly.
        if cfg!(target_arch = "x86_64") {
            assert!(availability().is_ok(), "{:?}", availability());
        }
    }
}
