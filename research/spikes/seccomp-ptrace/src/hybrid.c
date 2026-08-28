/* afw-hybrid: a research tracer that joins seccomp and ptrace.
 *
 * The program keeps everything that crates/af-monitor already does. It
 * launches the target with PTRACE_TRACEME, it follows every descendant with
 * PTRACE_O_TRACEFORK, TRACEVFORK, TRACECLONE, TRACEEXEC and TRACEEXIT, and
 * it protects the machine with PTRACE_O_EXITKILL.
 *
 * It adds one option, PTRACE_O_TRACESECCOMP, and one seccomp BPF filter in
 * the target. The filter returns SECCOMP_RET_TRACE for the interesting
 * system calls and SECCOMP_RET_ALLOW for the rest, so the supervisor only
 * wakes for an interesting call.
 *
 * Why the target execs this program a second time
 * -----------------------------------------------
 * A filter that returns SECCOMP_RET_TRACE when no tracer has
 * PTRACE_O_TRACESECCOMP does not run the system call. The kernel skips it
 * and returns ENOSYS. The supervisor can only set that option at a ptrace
 * stop, and the first stop comes after the first execve. So a filter that a
 * child installs before its own execve would break that execve.
 *
 * docs/RESEARCH.md section 3 says why the child must not stop itself with
 * SIGSTOP. This program therefore uses a second stage: the child execs this
 * same binary with --stage2. That first execve carries no filter, so it
 * works. The supervisor sets its options at the stop after it. Stage two
 * then installs the filter and execs the real target, and that execve is
 * the first one that the filter sees.
 */
#define _GNU_SOURCE

#include <ctype.h>
#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/ptrace.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/un.h>
#include <sys/user.h>
#include <sys/wait.h>

#include "filter.h"

/* Values that glibc does not always give. */
#ifndef PTRACE_O_TRACESECCOMP
#define PTRACE_O_TRACESECCOMP 0x00000080
#endif
#ifndef PTRACE_EVENT_SECCOMP
#define PTRACE_EVENT_SECCOMP 7
#endif
#ifndef PTRACE_GET_SYSCALL_INFO
#define PTRACE_GET_SYSCALL_INFO 0x420e
#endif
#define AFW_SYSCALL_INFO_SECCOMP 3

/* A private copy of `struct ptrace_syscall_info`, so that this file does not
 * have to include <linux/ptrace.h> next to <sys/ptrace.h>.
 */
struct afw_syscall_info {
    uint8_t op;
    uint8_t reserved;
    uint16_t flags;
    uint32_t arch;
    uint64_t instruction_pointer;
    uint64_t stack_pointer;
    union {
        struct {
            uint64_t nr;
            uint64_t args[6];
        } entry;
        struct {
            int64_t rval;
            uint8_t is_error;
        } exit;
        struct {
            uint64_t nr;
            uint64_t args[6];
            uint32_t ret_data;
            uint32_t reserved2;
        } seccomp;
    };
};

#define NR_OPEN_ 2
#define NR_CONNECT_ 42
#define NR_EXECVE_ 59
#define NR_RENAME_ 82
#define NR_UNLINK_ 87
#define NR_OPENAT_ 257
#define NR_UNLINKAT_ 263
#define NR_RENAMEAT_ 264
#define NR_RENAMEAT2_ 316
#define NR_EXECVEAT_ 322
#define NR_OPENAT2_ 437

#define MAX_PROCS 4096
#define PATH_MAX_READ 512

struct proc_entry {
    pid_t pid;
    int mem_fd;
    int used;
};

struct options {
    int config;          /* x z a b c d e */
    int quiet;           /* no per-event lines */
    int stats;           /* print counters at the end */
    int no_new_privs;    /* 1 by default */
    int direct;          /* install the filter without stage two */
    int read_paths;      /* read pointer arguments from /proc/<pid>/mem */
    long die_after;      /* supervisor calls _exit after N seccomp stops */
    long detach_after;   /* supervisor detaches after N seccomp stops */
    long reattach_ms;    /* how long the supervisor stays away */
    const char *block;   /* name of a system call to refuse */
    const char *block_path; /* refuse only when the path holds this text */
    const char *log_path;
    char **command;
};

static FILE *g_log;
static struct proc_entry g_procs[MAX_PROCS];
static int g_proc_count;
static unsigned long g_counts[AFW_GROUP_MAX];
static unsigned long g_stops;
static unsigned long g_blocked;
static unsigned long g_execs;
static unsigned long g_forks;
static unsigned long g_exits;
static unsigned long g_syscall_stops;

static void logf_line(const struct options *opt, const char *fmt, ...)
{
    va_list args;

    if (opt->quiet || g_log == NULL)
        return;
    va_start(args, fmt);
    vfprintf(g_log, fmt, args);
    va_end(args);
    fputc('\n', g_log);
}

/* ------------------------------------------------------------------ */
/* The table of live processes                                         */
/* ------------------------------------------------------------------ */

static struct proc_entry *proc_find(pid_t pid, int create)
{
    unsigned slot = ((unsigned)pid * 2654435761u) % MAX_PROCS;
    unsigned tries;

    for (tries = 0; tries < MAX_PROCS; tries++) {
        struct proc_entry *entry = &g_procs[(slot + tries) % MAX_PROCS];

        if (entry->used && entry->pid == pid)
            return entry;
        if (!entry->used) {
            if (!create)
                return NULL;
            entry->used = 1;
            entry->pid = pid;
            entry->mem_fd = -1;
            g_proc_count++;
            return entry;
        }
    }
    return NULL;
}

static void proc_forget(pid_t pid)
{
    struct proc_entry *entry = proc_find(pid, 0);

    if (entry == NULL)
        return;
    if (entry->mem_fd >= 0)
        close(entry->mem_fd);
    entry->mem_fd = -1;
    /* The slot stays used, so that linear probing keeps working. The pid
     * becomes negative, which no real process has.
     */
    entry->pid = -1;
    g_proc_count--;
}

/* Drops the cached handle on the memory of a process.
 *
 * A handle on /proc/<pid>/mem holds the address space that the process had
 * when the supervisor opened it. An execve gives the process a new address
 * space, so every read through the old handle fails. The supervisor must
 * therefore drop the handle at each exec.
 */
static void proc_drop_mem(pid_t pid)
{
    struct proc_entry *entry = proc_find(pid, 0);

    if (entry == NULL || entry->mem_fd < 0)
        return;
    close(entry->mem_fd);
    entry->mem_fd = -1;
}

/* ------------------------------------------------------------------ */
/* Reading memory of the target                                        */
/* ------------------------------------------------------------------ */

static int mem_fd_of(pid_t pid)
{
    struct proc_entry *entry = proc_find(pid, 1);
    char path[64];

    if (entry == NULL)
        return -1;
    if (entry->mem_fd >= 0)
        return entry->mem_fd;
    snprintf(path, sizeof(path), "/proc/%d/mem", (int)pid);
    entry->mem_fd = open(path, O_RDONLY | O_CLOEXEC);
    return entry->mem_fd;
}

/* Reads a text that ends with a zero byte out of the target.
 *
 * The read never crosses a page that the target does not have, because a
 * pread stops at the end of a mapped page.
 */
static int read_cstring(pid_t pid, unsigned long addr, char *out, size_t out_len)
{
    int fd = mem_fd_of(pid);
    size_t got = 0;

    out[0] = '\0';
    if (fd < 0 || addr == 0)
        return 0;
    while (got + 1 < out_len) {
        size_t page_left = 4096u - (size_t)((addr + got) & 4095u);
        size_t want = out_len - 1 - got;
        ssize_t n;

        if (want > page_left)
            want = page_left;
        n = pread(fd, out + got, want, (off_t)(addr + got));
        if (n <= 0)
            break;
        if (memchr(out + got, 0, (size_t)n) != NULL) {
            got += (size_t)n;
            out[out_len - 1] = '\0';
            return 1;
        }
        got += (size_t)n;
    }
    out[got] = '\0';
    return got > 0;
}

static int read_bytes(pid_t pid, unsigned long addr, void *out, size_t len)
{
    int fd = mem_fd_of(pid);
    ssize_t n;

    if (fd < 0 || addr == 0)
        return 0;
    n = pread(fd, out, len, (off_t)addr);
    return n == (ssize_t)len;
}

/* Turns a socket address of the target into text. */
static void describe_sockaddr(pid_t pid, unsigned long addr, unsigned long len, char *out,
                              size_t out_len)
{
    unsigned char buf[128];
    unsigned short family;
    size_t want = len < sizeof(buf) ? (size_t)len : sizeof(buf);

    snprintf(out, out_len, "peer=unknown");
    if (want < sizeof(unsigned short) || !read_bytes(pid, addr, buf, want))
        return;
    memcpy(&family, buf, sizeof(family));
    if (family == AF_INET && want >= sizeof(struct sockaddr_in)) {
        struct sockaddr_in v4;
        char text[INET_ADDRSTRLEN];

        memcpy(&v4, buf, sizeof(v4));
        inet_ntop(AF_INET, &v4.sin_addr, text, sizeof(text));
        snprintf(out, out_len, "peer=%s:%u", text, (unsigned)ntohs(v4.sin_port));
    } else if (family == AF_INET6 && want >= sizeof(struct sockaddr_in6)) {
        struct sockaddr_in6 v6;
        char text[INET6_ADDRSTRLEN];

        memcpy(&v6, buf, sizeof(v6));
        inet_ntop(AF_INET6, &v6.sin6_addr, text, sizeof(text));
        snprintf(out, out_len, "peer=[%s]:%u", text, (unsigned)ntohs(v6.sin6_port));
    } else if (family == AF_UNIX) {
        char text[110];
        size_t copy = want > sizeof(struct sockaddr_un) ? sizeof(struct sockaddr_un) : want;

        memset(text, 0, sizeof(text));
        if (copy > 2)
            memcpy(text, buf + 2, copy - 2 < sizeof(text) - 1 ? copy - 2 : sizeof(text) - 1);
        snprintf(out, out_len, "peer=unix:%s", text[0] ? text : "<abstract>");
    } else {
        snprintf(out, out_len, "peer=family=%u", (unsigned)family);
    }
}

/* ------------------------------------------------------------------ */
/* Facts from /proc                                                    */
/* ------------------------------------------------------------------ */

static void read_exe(pid_t pid, char *out, size_t out_len)
{
    char link[64];
    ssize_t n;

    snprintf(link, sizeof(link), "/proc/%d/exe", (int)pid);
    n = readlink(link, out, out_len - 1);
    if (n < 0)
        n = 0;
    out[n] = '\0';
}

static void read_cmdline(pid_t pid, char *out, size_t out_len)
{
    char path[64];
    int fd;
    ssize_t n;
    ssize_t i;

    out[0] = '\0';
    snprintf(path, sizeof(path), "/proc/%d/cmdline", (int)pid);
    fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return;
    n = read(fd, out, out_len - 1);
    close(fd);
    if (n <= 0) {
        out[0] = '\0';
        return;
    }
    for (i = 0; i < n; i++) {
        if (out[i] == '\0')
            out[i] = ' ';
    }
    out[n] = '\0';
}

/* Reads the effective user identifier out of /proc/<pid>/status.
 *
 * The value proves whether a setuid program kept its privilege.
 */
static long read_euid(pid_t pid)
{
    char path[64];
    FILE *file;
    char line[256];
    long euid = -1;

    snprintf(path, sizeof(path), "/proc/%d/status", (int)pid);
    file = fopen(path, "r");
    if (file == NULL)
        return -1;
    while (fgets(line, sizeof(line), file) != NULL) {
        long real;
        long eff;

        if (sscanf(line, "Uid:\t%ld\t%ld", &real, &eff) == 2) {
            euid = eff;
            break;
        }
    }
    fclose(file);
    return euid;
}

/* ------------------------------------------------------------------ */
/* Register work                                                       */
/* ------------------------------------------------------------------ */

/* Refuses the system call that waits at a seccomp stop.
 *
 * The tracee sits before the call, so nothing happened yet. A system call
 * number of -1 tells the kernel to skip the call, and the value in rax
 * becomes the result that the program sees.
 */
static int refuse_syscall(pid_t pid, int error_number)
{
    struct user_regs_struct regs;
    struct iovec iov;

    iov.iov_base = &regs;
    iov.iov_len = sizeof(regs);
    if (ptrace(PTRACE_GETREGSET, pid, (void *)(long)NT_PRSTATUS, &iov) != 0)
        return -1;
    regs.orig_rax = (unsigned long long)-1;
    regs.rax = (unsigned long long)(-(long long)error_number);
    iov.iov_base = &regs;
    iov.iov_len = sizeof(regs);
    if (ptrace(PTRACE_SETREGSET, pid, (void *)(long)NT_PRSTATUS, &iov) != 0)
        return -1;
    return 0;
}

/* ------------------------------------------------------------------ */
/* The event loop                                                      */
/* ------------------------------------------------------------------ */

static long trace_options(const struct options *opt)
{
    long flags = PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK | PTRACE_O_TRACECLONE |
                 PTRACE_O_TRACEEXEC | PTRACE_O_TRACEEXIT | PTRACE_O_EXITKILL;

    if (opt->config == 'e')
        flags |= PTRACE_O_TRACESYSGOOD;
    else if (opt->config != 'x')
        flags |= PTRACE_O_TRACESECCOMP;
    return flags;
}

static int forwardable(int sig)
{
    switch (sig) {
    case SIGSTOP:
    case SIGTSTP:
    case SIGTTIN:
    case SIGTTOU:
    case SIGTRAP:
        return 0;
    default:
        return sig;
    }
}

static void resume(const struct options *opt, pid_t pid, int sig)
{
    int request = (opt->config == 'e') ? PTRACE_SYSCALL : PTRACE_CONT;

    if (ptrace(request, pid, 0, (void *)(long)sig) != 0 && errno != ESRCH)
        logf_line(opt, "warn pid=%d cannot resume: %s", (int)pid, strerror(errno));
}

static const char *syscall_name(unsigned long nr)
{
    switch (nr) {
    case NR_OPEN_:
        return "open";
    case NR_CONNECT_:
        return "connect";
    case NR_EXECVE_:
        return "execve";
    case NR_RENAME_:
        return "rename";
    case NR_UNLINK_:
        return "unlink";
    case NR_OPENAT_:
        return "openat";
    case NR_UNLINKAT_:
        return "unlinkat";
    case NR_RENAMEAT_:
        return "renameat";
    case NR_RENAMEAT2_:
        return "renameat2";
    case NR_EXECVEAT_:
        return "execveat";
    case NR_OPENAT2_:
        return "openat2";
    default:
        return "other";
    }
}

/* Says which argument of a system call holds a path, or -1. */
static int path_arg_of(unsigned long nr)
{
    switch (nr) {
    case NR_OPENAT_:
    case NR_OPENAT2_:
    case NR_UNLINKAT_:
    case NR_RENAMEAT_:
    case NR_RENAMEAT2_:
        return 1;
    case NR_OPEN_:
    case NR_UNLINK_:
    case NR_RENAME_:
    case NR_EXECVE_:
        return 0;
    default:
        return -1;
    }
}

static int flags_arg_of(unsigned long nr)
{
    switch (nr) {
    case NR_OPENAT_:
        return 2;
    case NR_OPEN_:
        return 1;
    default:
        return -1;
    }
}

/* Handles one PTRACE_EVENT_SECCOMP stop. Returns 1 when it refused the call. */
static int handle_seccomp(const struct options *opt, pid_t pid)
{
    unsigned long group = 0;
    struct afw_syscall_info info;
    char path[PATH_MAX_READ];
    char detail[256];
    unsigned long nr;
    int path_index;
    int flags_index;
    int refused = 0;

    g_stops++;
    memset(&info, 0, sizeof(info));
    if (ptrace(PTRACE_GETEVENTMSG, pid, 0, &group) != 0)
        group = 0;
    if (group < AFW_GROUP_MAX)
        g_counts[group]++;

    if (ptrace(PTRACE_GET_SYSCALL_INFO, pid, (void *)sizeof(info), &info) < 0) {
        logf_line(opt, "warn pid=%d cannot read the call: %s", (int)pid, strerror(errno));
        return 0;
    }
    if (info.op != AFW_SYSCALL_INFO_SECCOMP) {
        logf_line(opt, "warn pid=%d unexpected info op %u", (int)pid, (unsigned)info.op);
        return 0;
    }

    nr = (unsigned long)info.seccomp.nr;
    path[0] = '\0';
    detail[0] = '\0';
    path_index = path_arg_of(nr);
    flags_index = flags_arg_of(nr);

    if (opt->read_paths && path_index >= 0)
        read_cstring(pid, (unsigned long)info.seccomp.args[path_index], path, sizeof(path));
    if (nr == NR_CONNECT_ && opt->read_paths) {
        describe_sockaddr(pid, (unsigned long)info.seccomp.args[1],
                          (unsigned long)info.seccomp.args[2], detail, sizeof(detail));
    }
    if (nr == NR_OPENAT2_ && opt->read_paths) {
        /* openat2 keeps its flags in a structure behind a pointer. A BPF
         * filter cannot follow that pointer, so the kernel cannot tell a
         * read from a write. The supervisor can, but only after it paid for
         * a stop.
         */
        uint64_t how[3];

        if (read_bytes(pid, (unsigned long)info.seccomp.args[2], how, sizeof(how)))
            snprintf(detail, sizeof(detail), "how_flags=0x%llx", (unsigned long long)how[0]);
    }

    if (opt->block != NULL && strcmp(opt->block, syscall_name(nr)) == 0 &&
        (opt->block_path == NULL || strstr(path, opt->block_path) != NULL)) {
        if (refuse_syscall(pid, EPERM) == 0) {
            refused = 1;
            g_blocked++;
        }
    }

    if (!opt->quiet) {
        char flags_text[32];

        flags_text[0] = '\0';
        if (flags_index >= 0)
            snprintf(flags_text, sizeof(flags_text), " flags=0x%lx",
                     (unsigned long)info.seccomp.args[flags_index]);
        logf_line(opt, "seccomp pid=%d group=%s call=%s%s%s%s%s%s", (int)pid,
                  afw_group_name((unsigned)group), syscall_name(nr), flags_text,
                  path[0] ? " path=" : "", path[0] ? path : "", detail[0] ? " " : "",
                  detail[0] ? detail : "");
        if (refused)
            logf_line(opt, "refused pid=%d call=%s errno=EPERM", (int)pid, syscall_name(nr));
    }
    return refused;
}

/* Handles one syscall-entry or syscall-exit stop of configuration (e). */
static void handle_syscall_stop(const struct options *opt, pid_t pid)
{
    struct afw_syscall_info info;

    g_syscall_stops++;
    if (opt->quiet)
        return;
    memset(&info, 0, sizeof(info));
    if (ptrace(PTRACE_GET_SYSCALL_INFO, pid, (void *)sizeof(info), &info) < 0)
        return;
    if (info.op == 1) {
        logf_line(opt, "syscall pid=%d call=%s", (int)pid,
                  syscall_name((unsigned long)info.entry.nr));
    }
}

static void handle_exec(const struct options *opt, pid_t pid)
{
    char exe[PATH_MAX];
    char cmdline[512];

    g_execs++;
    /* The new program has a new address space. */
    proc_drop_mem(pid);
    if (opt->quiet)
        return;
    read_exe(pid, exe, sizeof(exe));
    read_cmdline(pid, cmdline, sizeof(cmdline));
    logf_line(opt, "exec pid=%d euid=%ld exe=%s argv=%s", (int)pid, read_euid(pid), exe, cmdline);
}

static void sleep_ms(long ms)
{
    struct timespec ts;

    ts.tv_sec = ms / 1000;
    ts.tv_nsec = (ms % 1000) * 1000000L;
    nanosleep(&ts, NULL);
}

struct session {
    pid_t root;
    int root_status;
    int alive;
    int detached;
};

/* Leaves the target and comes back, to test a restart of the firewall. */
static void detach_and_reattach(const struct options *opt, struct session *session, pid_t pid)
{
    int status = 0;

    logf_line(opt, "detach pid=%d", (int)pid);
    if (ptrace(PTRACE_DETACH, pid, 0, 0) != 0)
        logf_line(opt, "warn pid=%d cannot detach: %s", (int)pid, strerror(errno));
    sleep_ms(opt->reattach_ms);
    if (ptrace(PTRACE_ATTACH, pid, 0, 0) != 0) {
        logf_line(opt, "warn pid=%d cannot attach again: %s", (int)pid, strerror(errno));
        session->alive = 0;
        return;
    }
    if (waitpid(pid, &status, __WALL) < 0) {
        logf_line(opt, "warn pid=%d no stop after attach: %s", (int)pid, strerror(errno));
        session->alive = 0;
        return;
    }
    if (ptrace(PTRACE_SETOPTIONS, pid, 0, (void *)trace_options(opt)) != 0)
        logf_line(opt, "warn pid=%d cannot set the options again: %s", (int)pid, strerror(errno));
    logf_line(opt, "reattach pid=%d", (int)pid);
    resume(opt, pid, 0);
}

static void print_stats(const struct options *opt)
{
    unsigned group;

    if (!opt->stats)
        return;
    fprintf(stderr, "stats config=%c seccomp_stops=%lu syscall_stops=%lu blocked=%lu execs=%lu "
                    "forks=%lu exits=%lu",
            opt->config, g_stops, g_syscall_stops, g_blocked, g_execs, g_forks, g_exits);
    for (group = 1; group < AFW_GROUP_MAX; group++) {
        if (g_counts[group] > 0)
            fprintf(stderr, " %s=%lu", afw_group_name(group), g_counts[group]);
    }
    fputc('\n', stderr);
}

static int supervise(const struct options *opt, pid_t root)
{
    struct session session;
    int status = 0;
    int first = 1;

    session.root = root;
    session.root_status = 0;
    session.alive = 1;
    session.detached = 0;

    proc_find(root, 1);

    while (session.alive) {
        pid_t pid = waitpid(-1, &status, __WALL);
        int sig;
        int event;

        if (pid < 0) {
            if (errno == EINTR)
                continue;
            break;
        }
        if (WIFEXITED(status) || WIFSIGNALED(status)) {
            proc_forget(pid);
            if (pid == root) {
                session.root_status = status;
                session.alive = 0;
            }
            if (g_proc_count <= 0)
                session.alive = 0;
            continue;
        }
        if (!WIFSTOPPED(status))
            continue;

        sig = WSTOPSIG(status);
        event = status >> 16;

        if (first) {
            /* The first stop is the SIGTRAP after the execve of the child.
             * The image is loaded and no instruction ran, so this is the
             * same moment that af-monitor uses.
             */
            first = 0;
            if (ptrace(PTRACE_SETOPTIONS, pid, 0, (void *)trace_options(opt)) != 0) {
                fprintf(stderr, "afw-hybrid: cannot set the trace options: %s\n", strerror(errno));
                kill(pid, SIGKILL);
                return 125;
            }
            logf_line(opt, "start pid=%d config=%c", (int)pid, opt->config);
            /* af-monitor reports the first exec of the root at this stop.
             * The spike does the same, so the event model does not change.
             */
            handle_exec(opt, pid);
            resume(opt, pid, 0);
            continue;
        }

        if (proc_find(pid, 0) == NULL) {
            proc_find(pid, 1);
            /* A child inherits the options, but a process that the
             * supervisor did not expect may not have them.
             */
            ptrace(PTRACE_SETOPTIONS, pid, 0, (void *)trace_options(opt));
        }

        if (sig == SIGTRAP && event != 0) {
            switch (event) {
            case PTRACE_EVENT_SECCOMP:
                handle_seccomp(opt, pid);
                if (opt->die_after > 0 && (long)g_stops >= opt->die_after) {
                    /* The supervisor dies while the target waits at a
                     * seccomp stop. PTRACE_O_EXITKILL must save the machine.
                     */
                    fprintf(stderr, "afw-hybrid: leaving on purpose at stop %lu\n", g_stops);
                    _exit(70);
                }
                if (opt->detach_after > 0 && (long)g_stops == opt->detach_after) {
                    detach_and_reattach(opt, &session, pid);
                    continue;
                }
                break;
            case PTRACE_EVENT_EXEC:
                handle_exec(opt, pid);
                break;
            case PTRACE_EVENT_FORK:
            case PTRACE_EVENT_VFORK:
            case PTRACE_EVENT_CLONE: {
                unsigned long child = 0;

                if (ptrace(PTRACE_GETEVENTMSG, pid, 0, &child) == 0) {
                    g_forks++;
                    proc_find((pid_t)child, 1);
                    logf_line(opt, "fork pid=%d child=%lu", (int)pid, child);
                }
                break;
            }
            case PTRACE_EVENT_EXIT: {
                unsigned long raw = 0;

                g_exits++;
                if (ptrace(PTRACE_GETEVENTMSG, pid, 0, &raw) == 0)
                    logf_line(opt, "exit pid=%d status=0x%lx", (int)pid, raw);
                break;
            }
            default:
                break;
            }
            resume(opt, pid, 0);
            continue;
        }

        if (opt->config == 'e' && sig == (SIGTRAP | 0x80)) {
            handle_syscall_stop(opt, pid);
            resume(opt, pid, 0);
            continue;
        }

        resume(opt, pid, forwardable(sig));
    }

    print_stats(opt);
    if (WIFEXITED(session.root_status))
        return WEXITSTATUS(session.root_status);
    if (WIFSIGNALED(session.root_status))
        return 128 + WTERMSIG(session.root_status);
    return 0;
}

/* ------------------------------------------------------------------ */
/* Start                                                               */
/* ------------------------------------------------------------------ */

static void usage(void)
{
    fprintf(stderr,
            "afw-hybrid [options] -- program [args...]\n"
            "  --config <x|z|a|b|c|d|e|f|g|w>  which filter (default d)\n"
            "  --quiet                   print no event lines\n"
            "  --stats                   print counters at the end\n"
            "  --log <path>              write the event lines to a file\n"
            "  --no-nnp                  do not set PR_SET_NO_NEW_PRIVS\n"
            "  --direct                  install the filter without stage two\n"
            "  --no-paths                do not read pointer arguments\n"
            "  --block <call>            refuse a system call with EPERM\n"
            "  --block-path <text>       refuse only when the path holds this text\n"
            "  --die-after <n>           leave the supervisor at seccomp stop n\n"
            "  --detach-after <n>        detach at seccomp stop n and come back\n"
            "  --reattach-ms <n>         how long the supervisor stays away\n"
            "  --stage2                  internal: install the filter and exec\n");
}

int main(int argc, char **argv)
{
    struct options opt;
    int stage2 = 0;
    int index = 1;
    pid_t child;

    memset(&opt, 0, sizeof(opt));
    opt.config = 'd';
    opt.no_new_privs = 1;
    opt.read_paths = 1;
    opt.die_after = -1;
    opt.detach_after = -1;
    opt.reattach_ms = 120;

    while (index < argc) {
        const char *arg = argv[index];

        if (strcmp(arg, "--") == 0) {
            index++;
            break;
        }
        if (arg[0] != '-') {
            /* The benchmark harness appends the command with no marker. */
            break;
        }
        if (strcmp(arg, "--stage2") == 0) {
            stage2 = 1;
            index++;
        } else if (strcmp(arg, "--config") == 0 && index + 1 < argc) {
            opt.config = argv[index + 1][0];
            index += 2;
        } else if (strcmp(arg, "--quiet") == 0) {
            opt.quiet = 1;
            index++;
        } else if (strcmp(arg, "--stats") == 0) {
            opt.stats = 1;
            index++;
        } else if (strcmp(arg, "--log") == 0 && index + 1 < argc) {
            opt.log_path = argv[index + 1];
            index += 2;
        } else if (strcmp(arg, "--no-nnp") == 0) {
            opt.no_new_privs = 0;
            index++;
        } else if (strcmp(arg, "--direct") == 0) {
            opt.direct = 1;
            index++;
        } else if (strcmp(arg, "--no-paths") == 0) {
            opt.read_paths = 0;
            index++;
        } else if (strcmp(arg, "--block") == 0 && index + 1 < argc) {
            opt.block = argv[index + 1];
            index += 2;
        } else if (strcmp(arg, "--block-path") == 0 && index + 1 < argc) {
            opt.block_path = argv[index + 1];
            index += 2;
        } else if (strcmp(arg, "--die-after") == 0 && index + 1 < argc) {
            opt.die_after = atol(argv[index + 1]);
            index += 2;
        } else if (strcmp(arg, "--detach-after") == 0 && index + 1 < argc) {
            opt.detach_after = atol(argv[index + 1]);
            index += 2;
        } else if (strcmp(arg, "--reattach-ms") == 0 && index + 1 < argc) {
            opt.reattach_ms = atol(argv[index + 1]);
            index += 2;
        } else {
            fprintf(stderr, "afw-hybrid: unknown option %s\n", arg);
            usage();
            return 2;
        }
    }

    if (index >= argc) {
        usage();
        return 2;
    }
    opt.command = &argv[index];

    if (stage2) {
        /* The tracer already set PTRACE_O_TRACESECCOMP at the stop after the
         * execve that brought this program here. The filter is therefore
         * safe to install now, and the next execve is the first call that
         * the filter sees.
         */
        if (afw_install_filter(opt.config, opt.no_new_privs) != 0) {
            fprintf(stderr, "afw-hybrid: the kernel refused the filter: %s\n", strerror(errno));
            _exit(126);
        }
        execvp(opt.command[0], opt.command);
        fprintf(stderr, "afw-hybrid: cannot run %s: %s\n", opt.command[0], strerror(errno));
        _exit(127);
    }

    g_log = stderr;
    if (opt.log_path != NULL) {
        g_log = fopen(opt.log_path, "w");
        if (g_log == NULL) {
            fprintf(stderr, "afw-hybrid: cannot write %s: %s\n", opt.log_path, strerror(errno));
            return 2;
        }
        setvbuf(g_log, NULL, _IOLBF, 0);
    }

    child = fork();
    if (child < 0) {
        fprintf(stderr, "afw-hybrid: cannot fork: %s\n", strerror(errno));
        return 2;
    }
    if (child == 0) {
        /* Only PTRACE_TRACEME. The child never stops itself with SIGSTOP,
         * because docs/RESEARCH.md section 3 shows that this deadlocks a
         * launcher that waits for the child to reach execve.
         */
        if (ptrace(PTRACE_TRACEME, 0, 0, 0) != 0)
            _exit(125);
        if (opt.direct || opt.config == 'x' || opt.config == 'e') {
            if (afw_install_filter(opt.config, opt.no_new_privs) != 0) {
                fprintf(stderr, "afw-hybrid: the kernel refused the filter: %s\n",
                        strerror(errno));
                _exit(126);
            }
            execvp(opt.command[0], opt.command);
            /* A filter that traces execve when no tracer has
             * PTRACE_O_TRACESECCOMP makes the kernel skip the call and
             * return ENOSYS. That is why the normal path uses stage two.
             */
            fprintf(stderr, "afw-hybrid: cannot run %s: %s\n", opt.command[0], strerror(errno));
            _exit(127);
        } else {
            char config_text[2];
            char *stage_argv[64];
            int n = 0;
            int i;

            config_text[0] = (char)opt.config;
            config_text[1] = '\0';
            stage_argv[n++] = argv[0];
            stage_argv[n++] = (char *)"--stage2";
            stage_argv[n++] = (char *)"--config";
            stage_argv[n++] = config_text;
            if (!opt.no_new_privs)
                stage_argv[n++] = (char *)"--no-nnp";
            stage_argv[n++] = (char *)"--";
            for (i = 0; opt.command[i] != NULL && n < 62; i++)
                stage_argv[n++] = opt.command[i];
            stage_argv[n] = NULL;
            execv("/proc/self/exe", stage_argv);
            _exit(127);
        }
    }

    return supervise(&opt, child);
}
