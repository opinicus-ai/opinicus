/*
 * afw-unotify - a research supervisor that uses seccomp user notification.
 *
 * The program starts a target command under a seccomp filter. The filter
 * returns SECCOMP_RET_USER_NOTIF for a small set of system calls. The
 * supervisor reads each notification, reads the pointer arguments from
 * /proc/<pid>/mem, applies a simple rule, and answers.
 *
 * This is research code. It answers questions. It is not a product.
 *
 * Build: make
 * Use:   afw-unotify [options] -- COMMAND [ARGS...]
 */

#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <sched.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <linux/unistd.h>

#ifndef SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV
#define SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV (1UL << 5)
#endif

/* ------------------------------------------------------------------ */
/* The set of system calls that the filter traps.                      */
/*                                                                     */
/* Each entry says where a path argument is. A value of -1 means that  */
/* the argument does not exist.                                        */
/* ------------------------------------------------------------------ */

enum arg_kind {
    ARG_NONE = 0,
    ARG_PATH,     /* a NUL terminated string in the memory of the target */
    ARG_SOCKADDR, /* a struct sockaddr in the memory of the target       */
};

struct trapped_call {
    int nr;
    const char *name;
    int first_arg;         /* index of the first interesting argument   */
    enum arg_kind kind;
    int second_arg;        /* a second path, for rename; -1 if none     */
    int dirfd_arg;         /* index of a directory descriptor; -1 none  */
};

/* The full set. It covers the rule categories of the product:
 * file read and write, file removal, file rename, network, program start,
 * and process memory access. */
static const struct trapped_call FULL_SET[] = {
    { __NR_openat,           "openat",           1, ARG_PATH,     -1, 0  },
    { __NR_open,             "open",             0, ARG_PATH,     -1, -1 },
    { __NR_openat2,          "openat2",          1, ARG_PATH,     -1, 0  },
    { __NR_unlinkat,         "unlinkat",         1, ARG_PATH,     -1, 0  },
    { __NR_unlink,           "unlink",           0, ARG_PATH,     -1, -1 },
    { __NR_renameat2,        "renameat2",        1, ARG_PATH,      3, 0  },
    { __NR_renameat,         "renameat",         1, ARG_PATH,      3, 0  },
    { __NR_rename,           "rename",           0, ARG_PATH,      1, -1 },
    { __NR_connect,          "connect",          1, ARG_SOCKADDR, -1, -1 },
    { __NR_execve,           "execve",           0, ARG_PATH,     -1, -1 },
    { __NR_execveat,         "execveat",         1, ARG_PATH,     -1, 0  },
    { __NR_ptrace,           "ptrace",          -1, ARG_NONE,     -1, -1 },
    { __NR_process_vm_writev,"process_vm_writev",-1, ARG_NONE,    -1, -1 },
};

/* The content set. It adds the calls that carry the DATA of an action, and
 * not only the name of the object. A statement such as DROP DATABASE that a
 * library sends over an open connection appears in one of these buffers, and
 * nowhere else. */
static const struct trapped_call IO_SET[] = {
    { __NR_openat,           "openat",           1, ARG_PATH,     -1, 0  },
    { __NR_unlinkat,         "unlinkat",         1, ARG_PATH,     -1, 0  },
    { __NR_renameat2,        "renameat2",        1, ARG_PATH,      3, 0  },
    { __NR_connect,          "connect",          1, ARG_SOCKADDR, -1, -1 },
    { __NR_execve,           "execve",           0, ARG_PATH,     -1, -1 },
    { __NR_execveat,         "execveat",         1, ARG_PATH,     -1, 0  },
    { __NR_write,            "write",           -1, ARG_NONE,     -1, -1 },
    { __NR_writev,           "writev",          -1, ARG_NONE,     -1, -1 },
    { __NR_sendto,           "sendto",          -1, ARG_NONE,     -1, -1 },
    /*
     * sendmsg is NOT in this set, and the reason is a measured deadlock.
     * The filter starts to work at the instant of the install, which is
     * before the child passes the listener descriptor to the supervisor.
     * That descriptor travels in an SCM_RIGHTS message, so the pass itself
     * is a sendmsg. A trapped sendmsg therefore waits for a supervisor that
     * cannot exist yet, and the pair hangs for ever.
     *
     * A product that must watch sendmsg has to take the descriptor in
     * another way, for example with pidfd_getfd from the supervisor, or it
     * has to add a rule in the BPF program that lets the one setup call
     * pass.
     */
};

/* The small set. It traps only the boundary that the shipping monitor
 * uses today. */
static const struct trapped_call EXEC_SET[] = {
    { __NR_execve,   "execve",   0, ARG_PATH, -1, -1 },
    { __NR_execveat, "execveat", 1, ARG_PATH, -1,  0 },
};

#define MAX_TRAPPED 32

static struct trapped_call g_set[MAX_TRAPPED];
static size_t g_set_len;

static const struct trapped_call *lookup(int nr)
{
    for (size_t i = 0; i < g_set_len; i++) {
        if (g_set[i].nr == nr) {
            return &g_set[i];
        }
    }
    return NULL;
}

/* ------------------------------------------------------------------ */
/* Options.                                                            */
/* ------------------------------------------------------------------ */

enum allow_mode {
    ALLOW_CONTINUE = 0, /* answer with SECCOMP_USER_NOTIF_FLAG_CONTINUE */
    ALLOW_EMULATE,      /* the supervisor does the work and injects a fd */
};

#define MAX_DENY 8

enum filter_set {
    FILTER_EXEC = 0,
    FILTER_FULL,
    FILTER_IO,
};

struct options {
    enum filter_set filter_set;
    enum allow_mode allow_mode;
    const char *deny_substr[MAX_DENY];
    size_t deny_len;
    const char *deny_call[MAX_DENY];
    size_t deny_call_len;
    const char *log_path;
    long delay_us;          /* sleep before each answer                 */
    long exit_after;        /* the supervisor exits after N answers     */
    bool read_args;         /* read /proc/<pid>/mem                     */
    bool stats;
    bool killable_recv;
    bool no_answer;         /* receive but never answer                 */
    long suicide_ms;        /* the supervisor kills itself after N ms    */
    const char *trigger;    /* delay, hold and exit apply only to a match */
    bool trap_sendmsg;      /* shows the setup deadlock                  */
};

static struct options g_opt = {
    .filter_set = FILTER_FULL,
    .allow_mode = ALLOW_CONTINUE,
    .read_args = true,
};

static FILE *g_log;

static void logline(const char *fmt, ...)
{
    if (g_log == NULL) {
        return;
    }
    va_list ap;
    va_start(ap, fmt);
    vfprintf(g_log, fmt, ap);
    va_end(ap);
    fputc('\n', g_log);
    fflush(g_log);
}

static void die(const char *what)
{
    fprintf(stderr, "afw-unotify: %s: %s\n", what, strerror(errno));
    _exit(127);
}

/* ------------------------------------------------------------------ */
/* The seccomp filter.                                                 */
/* ------------------------------------------------------------------ */

static int seccomp(unsigned int op, unsigned int flags, void *args)
{
    return (int)syscall(__NR_seccomp, op, flags, args);
}

/*
 * Builds the classic BPF program. The layout is:
 *
 *   0: load  arch
 *   1: jeq   AUDIT_ARCH_X86_64 -> 3, else 2
 *   2: ret   ALLOW            (a foreign architecture; see FINDINGS.md)
 *   3: load  nr
 *   4..4+n-1: jeq nr_i -> notify
 *   4+n: ret ALLOW
 *   5+n: ret USER_NOTIF
 */
static size_t build_filter(struct sock_filter *out, size_t out_max)
{
    size_t n = g_set_len;
    size_t need = 6 + n;

    if (need > out_max) {
        fprintf(stderr, "afw-unotify: the filter is too large\n");
        _exit(127);
    }

    size_t i = 0;
    struct sock_filter ld_arch =
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, arch));
    struct sock_filter jeq_arch =
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 1, 0);
    struct sock_filter ret_allow = BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW);
    struct sock_filter ld_nr =
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr));
    struct sock_filter ret_notif =
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF);

    out[i++] = ld_arch;
    out[i++] = jeq_arch;
    out[i++] = ret_allow;
    out[i++] = ld_nr;
    for (size_t k = 0; k < n; k++) {
        struct sock_filter j = BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K,
                                        (unsigned int)g_set[k].nr,
                                        (unsigned char)(n - k), 0);
        out[i++] = j;
    }
    out[i++] = ret_allow;
    out[i++] = ret_notif;
    return i;
}

/* Installs the filter and returns the listener descriptor. */
static int install_filter(void)
{
    struct sock_filter code[MAX_TRAPPED + 8];
    size_t len = build_filter(code, sizeof(code) / sizeof(code[0]));
    struct sock_fprog prog = { .len = (unsigned short)len, .filter = code };

    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
        die("prctl(PR_SET_NO_NEW_PRIVS)");
    }

    unsigned int flags = SECCOMP_FILTER_FLAG_NEW_LISTENER;
    if (g_opt.killable_recv) {
        flags |= SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV;
    }

    int fd = seccomp(SECCOMP_SET_MODE_FILTER, flags, &prog);
    if (fd < 0) {
        die("seccomp(SET_MODE_FILTER, NEW_LISTENER)");
    }
    return fd;
}

/* ------------------------------------------------------------------ */
/* File descriptor passing over a socketpair.                          */
/* ------------------------------------------------------------------ */

static void send_fd(int sock, int fd)
{
    char body = 'L';
    struct iovec iov = { .iov_base = &body, .iov_len = 1 };
    union {
        char buf[CMSG_SPACE(sizeof(int))];
        struct cmsghdr align;
    } control;
    memset(&control, 0, sizeof(control));

    struct msghdr msg = {
        .msg_iov = &iov,
        .msg_iovlen = 1,
        .msg_control = control.buf,
        .msg_controllen = sizeof(control.buf),
    };
    struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type = SCM_RIGHTS;
    cmsg->cmsg_len = CMSG_LEN(sizeof(int));
    memcpy(CMSG_DATA(cmsg), &fd, sizeof(int));

    if (sendmsg(sock, &msg, 0) < 0) {
        die("sendmsg(SCM_RIGHTS)");
    }
}

static int recv_fd(int sock)
{
    char body = 0;
    struct iovec iov = { .iov_base = &body, .iov_len = 1 };
    union {
        char buf[CMSG_SPACE(sizeof(int))];
        struct cmsghdr align;
    } control;
    memset(&control, 0, sizeof(control));

    struct msghdr msg = {
        .msg_iov = &iov,
        .msg_iovlen = 1,
        .msg_control = control.buf,
        .msg_controllen = sizeof(control.buf),
    };
    ssize_t got = recvmsg(sock, &msg, 0);
    if (got <= 0) {
        die("recvmsg(SCM_RIGHTS)");
    }
    struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
    if (cmsg == NULL || cmsg->cmsg_type != SCM_RIGHTS) {
        fprintf(stderr, "afw-unotify: no descriptor in the message\n");
        _exit(127);
    }
    int fd = -1;
    memcpy(&fd, CMSG_DATA(cmsg), sizeof(int));
    return fd;
}

/* ------------------------------------------------------------------ */
/* Memory of the target.                                               */
/*                                                                     */
/* A small cache keeps one open /proc/<pid>/mem for each recent pid.    */
/* The descriptor stays bound to the process that was open. A reused    */
/* pid therefore gives an error and not the memory of another process.  */
/* ------------------------------------------------------------------ */

#define MEM_CACHE 32

static struct {
    pid_t pid;
    int fd;
} g_mem[MEM_CACHE];

static int mem_fd_for(pid_t pid)
{
    size_t slot = (size_t)pid % MEM_CACHE;
    if (g_mem[slot].pid == pid && g_mem[slot].fd >= 0) {
        return g_mem[slot].fd;
    }
    if (g_mem[slot].fd > 0) {
        close(g_mem[slot].fd);
        g_mem[slot].fd = -1;
    }
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/mem", (int)pid);
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    g_mem[slot].pid = pid;
    g_mem[slot].fd = fd;
    return fd;
}

static void mem_forget(pid_t pid)
{
    size_t slot = (size_t)pid % MEM_CACHE;
    if (g_mem[slot].pid == pid && g_mem[slot].fd > 0) {
        close(g_mem[slot].fd);
        g_mem[slot].fd = -1;
        g_mem[slot].pid = 0;
    }
}

/* One attempt to read a NUL terminated string. */
static int read_string_once(pid_t pid, uint64_t addr, char *out, size_t out_len)
{
    int fd = mem_fd_for(pid);
    if (fd < 0) {
        return -1;
    }
    size_t done = 0;
    while (done < out_len - 1) {
        size_t want = out_len - 1 - done;
        if (want > 256) {
            want = 256;
        }
        ssize_t got = pread(fd, out + done, want, (off_t)(addr + done));
        if (got <= 0) {
            if (done == 0) {
                mem_forget(pid);
                return -1;
            }
            break;
        }
        for (ssize_t k = 0; k < got; k++) {
            if (out[done + k] == '\0') {
                return 0;
            }
        }
        done += (size_t)got;
    }
    out[out_len - 1] = '\0';
    return 0;
}

/*
 * Reads a NUL terminated string out of the memory of the target.
 *
 * A cached descriptor of /proc/<pid>/mem holds the address space that the
 * process had when the descriptor was open. An execve gives the process a
 * NEW address space, so the old descriptor reads nothing from that moment.
 * The first attempt therefore drops the cache, and the second attempt opens
 * a fresh descriptor. Without the retry the first openat after every execve
 * arrives with an empty path, which means the rule sees nothing.
 */
static int read_string(pid_t pid, uint64_t addr, char *out, size_t out_len)
{
    if (read_string_once(pid, addr, out, out_len) == 0) {
        return 0;
    }
    return read_string_once(pid, addr, out, out_len);
}

static int read_bytes_once(pid_t pid, uint64_t addr, void *out, size_t len)
{
    int fd = mem_fd_for(pid);
    if (fd < 0) {
        return -1;
    }
    ssize_t got = pread(fd, out, len, (off_t)addr);
    if (got <= 0) {
        mem_forget(pid);
        return -1;
    }
    if ((size_t)got < len) {
        memset((char *)out + got, 0, len - (size_t)got);
    }
    return 0;
}

static int read_bytes(pid_t pid, uint64_t addr, void *out, size_t len)
{
    if (read_bytes_once(pid, addr, out, len) == 0) {
        return 0;
    }
    return read_bytes_once(pid, addr, out, len);
}

/* Turns a struct sockaddr into text. */
static void format_sockaddr(const unsigned char *raw, size_t len, char *out,
                            size_t out_len)
{
    if (len < 2) {
        snprintf(out, out_len, "<short>");
        return;
    }
    unsigned short family = (unsigned short)(raw[0] | (raw[1] << 8));
    if (family == AF_INET && len >= 8) {
        unsigned port = (unsigned)((raw[2] << 8) | raw[3]);
        snprintf(out, out_len, "inet %u.%u.%u.%u:%u", raw[4], raw[5], raw[6],
                 raw[7], port);
    } else if (family == AF_INET6 && len >= 24) {
        unsigned port = (unsigned)((raw[2] << 8) | raw[3]);
        snprintf(out, out_len, "inet6 [%02x%02x:...:%02x%02x]:%u", raw[8],
                 raw[9], raw[22], raw[23], port);
    } else if (family == AF_UNIX && len > 2) {
        char tmp[100];
        size_t n = len - 2;
        if (n > sizeof(tmp) - 1) {
            n = sizeof(tmp) - 1;
        }
        memcpy(tmp, raw + 2, n);
        tmp[n] = '\0';
        snprintf(out, out_len, "unix %s", tmp[0] == '\0' ? "@abstract" : tmp);
    } else {
        snprintf(out, out_len, "family=%u", family);
    }
}

/* ------------------------------------------------------------------ */
/* The rule.                                                           */
/* ------------------------------------------------------------------ */

static bool path_is_denied(const char *path)
{
    for (size_t i = 0; i < g_opt.deny_len; i++) {
        if (strstr(path, g_opt.deny_substr[i]) != NULL) {
            return true;
        }
    }
    return false;
}

static bool call_is_denied(const char *name)
{
    for (size_t i = 0; i < g_opt.deny_call_len; i++) {
        if (strcmp(name, g_opt.deny_call[i]) == 0) {
            return true;
        }
    }
    return false;
}

/* ------------------------------------------------------------------ */
/* Emulation of an allowed openat.                                     */
/*                                                                     */
/* The supervisor opens the file itself and gives the descriptor to the */
/* target. The kernel never reads the path again, so the argument race  */
/* is gone. The cost is that the supervisor must copy the whole context */
/* of the target: the working directory, the directory descriptor, the  */
/* flags and the mode.                                                  */
/* ------------------------------------------------------------------ */

static long emulate_openat(int listener, const struct seccomp_notif *req,
                           const char *path, int *out_errno)
{
    /*
     * The notification reports the raw register. The kernel truncates an
     * argument to the width that the system call declares. AT_FDCWD arrives
     * here as 0x00000000ffffff9c, and only the cast to int makes it the -100
     * that the kernel uses. A supervisor that reads args[N] as 64 bits reads
     * a value that the kernel never sees.
     */
    int dirfd = (int)req->data.args[0];
    int flags = (int)req->data.args[2];
    mode_t mode = (mode_t)req->data.args[3];
    int base = -1;
    char proc[64];

    if (path[0] != '/') {
        if (dirfd == AT_FDCWD) {
            snprintf(proc, sizeof(proc), "/proc/%d/cwd", (int)req->pid);
        } else {
            snprintf(proc, sizeof(proc), "/proc/%d/fd/%d", (int)req->pid,
                     dirfd);
        }
        base = open(proc, O_PATH | O_CLOEXEC | O_DIRECTORY);
        if (base < 0) {
            logline("emulate-base-failed proc=%s errno=%d", proc, errno);
            *out_errno = errno;
            return -1;
        }

    }

    int local;
    if (base >= 0) {
        local = openat(base, path, flags, mode);
    } else {
        local = open(path, flags, mode);
    }
    int saved = errno;
    if (base >= 0) {
        close(base);
    }
    if (local < 0) {
        *out_errno = saved;
        return -1;
    }

    struct seccomp_notif_addfd add;
    memset(&add, 0, sizeof(add));
    add.id = req->id;
    add.srcfd = (unsigned int)local;
    add.newfd = 0;
    add.newfd_flags = (flags & O_CLOEXEC) ? O_CLOEXEC : 0;
    add.flags = SECCOMP_ADDFD_FLAG_SEND;

    long remote = (long)ioctl(listener, SECCOMP_IOCTL_NOTIF_ADDFD, &add);
    saved = errno;
    close(local);
    if (remote < 0) {
        *out_errno = saved;
        return -1;
    }
    *out_errno = 0;
    return remote;
}

/* ------------------------------------------------------------------ */
/* Counters.                                                           */
/* ------------------------------------------------------------------ */

static unsigned long g_count_total;
static unsigned long g_count_denied;
static unsigned long g_count_stale;
static unsigned long g_count_emulated;
static unsigned long g_count_triggered;

/* ------------------------------------------------------------------ */
/* The supervisor loop.                                                */
/* ------------------------------------------------------------------ */

static void supervise(int listener, pid_t child, int *child_status)
{
    size_t sizes_notif = sizeof(struct seccomp_notif);
    size_t sizes_resp = sizeof(struct seccomp_notif_resp);
    struct seccomp_notif_sizes sizes;
    if (seccomp(SECCOMP_GET_NOTIF_SIZES, 0, &sizes) == 0) {
        if (sizes.seccomp_notif > sizes_notif) {
            sizes_notif = sizes.seccomp_notif;
        }
        if (sizes.seccomp_notif_resp > sizes_resp) {
            sizes_resp = sizes.seccomp_notif_resp;
        }
    }

    struct seccomp_notif *req = calloc(1, sizes_notif);
    struct seccomp_notif_resp *resp = calloc(1, sizes_resp);
    if (req == NULL || resp == NULL) {
        die("calloc");
    }

    bool child_reaped = false;
    char path[PATH_MAX];
    char path2[PATH_MAX];

    for (;;) {
        struct pollfd pfd = { .fd = listener, .events = POLLIN };
        int ready = poll(&pfd, 1, 20);
        if (ready < 0) {
            if (errno == EINTR) {
                continue;
            }
            die("poll");
        }
        if (!child_reaped) {
            int status = 0;
            pid_t got = waitpid(child, &status, WNOHANG);
            if (got == child) {
                child_reaped = true;
                *child_status = status;
            }
        }
        if (ready == 0) {
            if (child_reaped && (pfd.revents & POLLHUP)) {
                break;
            }
            continue;
        }
        if (pfd.revents & POLLHUP) {
            /* No process uses the filter any more. */
            break;
        }
        if (!(pfd.revents & POLLIN)) {
            continue;
        }

        memset(req, 0, sizes_notif);
        if (ioctl(listener, SECCOMP_IOCTL_NOTIF_RECV, req) < 0) {
            if (errno == EINTR || errno == ENOENT) {
                continue;
            }
            if (errno == ENOTTY || errno == EINVAL) {
                break;
            }
            die("ioctl(NOTIF_RECV)");
        }

        g_count_total++;

        const struct trapped_call *call = lookup(req->data.nr);
        const char *name = call ? call->name : "?";

        path[0] = '\0';
        path2[0] = '\0';
        bool have_arg = false;

        if (g_opt.read_args && call != NULL && call->first_arg >= 0) {
            if (call->kind == ARG_PATH) {
                if (read_string(req->pid, req->data.args[call->first_arg], path,
                                sizeof(path)) == 0) {
                    have_arg = true;
                }
                if (call->second_arg >= 0) {
                    (void)read_string(req->pid,
                                      req->data.args[call->second_arg], path2,
                                      sizeof(path2));
                }
            } else if (call->kind == ARG_SOCKADDR) {
                unsigned char raw[128];
                size_t len = (size_t)req->data.args[2];
                if (len > sizeof(raw)) {
                    len = sizeof(raw);
                }
                if (len >= 2 &&
                    read_bytes(req->pid, req->data.args[call->first_arg], raw,
                               len) == 0) {
                    format_sockaddr(raw, len, path, sizeof(path));
                    have_arg = true;
                }
            }
        }

        /* Does this notification match the trigger of the failure tests?
         * With no trigger every notification matches. */
        bool triggered = (g_opt.trigger == NULL) ||
                         (path[0] != '\0' && strstr(path, g_opt.trigger) != NULL);

        /* The identifier check. It tells whether the target still waits.
         * It protects against a dead target and a reused identifier. It
         * says nothing about the content of the arguments. */
        uint64_t id = req->id;
        if (ioctl(listener, SECCOMP_IOCTL_NOTIF_ID_VALID, &id) != 0) {
            g_count_stale++;
            logline("stale-before pid=%d call=%s arg=%s a3=%llu", (int)req->pid,
                    name, path, (unsigned long long)req->data.args[3]);
            continue;
        }
        logline("id-valid-before pid=%d call=%s arg=%s ok=1", (int)req->pid,
                name, path);

        bool deny = false;
        if (call_is_denied(name)) {
            deny = true;
        } else if (have_arg && call->kind == ARG_PATH) {
            deny = path_is_denied(path);
            if (!deny && path2[0] != '\0') {
                deny = path_is_denied(path2);
            }
        } else if (have_arg && call->kind == ARG_SOCKADDR) {
            deny = path_is_denied(path);
        }

        if (g_opt.delay_us > 0 && triggered) {
            struct timespec ts = {
                .tv_sec = g_opt.delay_us / 1000000,
                .tv_nsec = (g_opt.delay_us % 1000000) * 1000,
            };
            nanosleep(&ts, NULL);

            /* The second check. The target can have died during the wait.
             * This is the only thing that ID_VALID protects against. */
            id = req->id;
            if (ioctl(listener, SECCOMP_IOCTL_NOTIF_ID_VALID, &id) != 0) {
                g_count_stale++;
                logline("stale-after-wait pid=%d call=%s arg=%s errno=%d",
                        (int)req->pid, name, path, errno);
            } else {
                logline("id-valid-after pid=%d call=%s arg=%s ok=1",
                        (int)req->pid, name, path);
            }
        }

        if (g_opt.no_answer && triggered) {
            logline("hold pid=%d call=%s arg=%s a3=%llu", (int)req->pid, name, path,
                    (unsigned long long)req->data.args[3]);
            continue;
        }

        if (triggered) {
            g_count_triggered++;
        }

        memset(resp, 0, sizes_resp);
        resp->id = req->id;

        if (deny) {
            g_count_denied++;
            resp->error = -EPERM;
            resp->val = 0;
            resp->flags = 0;
            logline("deny pid=%d call=%s arg=%s a3=%llu", (int)req->pid, name, path,
                    (unsigned long long)req->data.args[3]);
        } else if (g_opt.allow_mode == ALLOW_EMULATE &&
                   (req->data.nr == __NR_openat) && have_arg) {
            int err = 0;
            long fd = emulate_openat(listener, req, path, &err);
            g_count_emulated++;
            logline("emulate pid=%d call=%s arg=%s a3=%llu fd=%ld err=%d",
                    (int)req->pid, name, path,
                    (unsigned long long)req->data.args[3], fd, err);
            if (fd >= 0) {
                /* ADDFD with the SEND flag already answered. */
                if (g_opt.exit_after > 0 &&
                    (long)g_count_triggered >= g_opt.exit_after) {
                    logline("supervisor exits after %ld answers",
                            g_opt.exit_after);
                    _exit(90);
                }
                continue;
            }
            resp->error = -err;
            resp->val = 0;
            resp->flags = 0;
        } else {
            resp->error = 0;
            resp->val = 0;
            resp->flags = SECCOMP_USER_NOTIF_FLAG_CONTINUE;
            logline("allow pid=%d call=%s arg=%s a3=%llu", (int)req->pid, name, path,
                    (unsigned long long)req->data.args[3]);
        }

        if (ioctl(listener, SECCOMP_IOCTL_NOTIF_SEND, resp) < 0) {
            if (errno == ENOENT) {
                /* The target went away while we made the decision. The
                 * answer has nowhere to go, and the kernel says so. */
                g_count_stale++;
                logline("send-failed pid=%d call=%s arg=%s errno=ENOENT",
                        (int)req->pid, name, path);
                continue;
            }
            die("ioctl(NOTIF_SEND)");
        }

        if (g_opt.exit_after > 0 && (long)g_count_triggered >= g_opt.exit_after) {
            logline("supervisor exits after %ld answers", g_opt.exit_after);
            _exit(90);
        }
    }

    if (!child_reaped) {
        int status = 0;
        if (waitpid(child, &status, 0) == child) {
            *child_status = status;
        }
    }
    free(req);
    free(resp);
}

/* ------------------------------------------------------------------ */
/* Main.                                                               */
/* ------------------------------------------------------------------ */

static void usage(void)
{
    fprintf(stderr,
        "usage: afw-unotify [options] -- COMMAND [ARGS...]\n"
        "  --filter=exec|full|io  which system calls to trap (default full)\n"
        "  --allow=continue|emulate  how an allowed call proceeds\n"
        "  --deny=TEXT            deny a path or address that holds TEXT\n"
        "  --deny-call=NAME       deny a whole system call\n"
        "  --log=FILE             write one line for each notification\n"
        "  --delay-ms=N           wait N ms before each answer\n"
        "  --exit-after=N         the supervisor exits after N answers\n"
        "  --trigger=TEXT         delay, hold and exit only on a match\n"
        "  --no-answer            receive but never answer\n"
        "  --suicide-ms=N         the supervisor dies after N ms\n"
        "  --trap-sendmsg         add sendmsg; this deadlocks on purpose\n"
        "  --no-read-args         do not read the memory of the target\n"
        "  --killable-recv        add WAIT_KILLABLE_RECV to the filter\n"
        "  --stats                print counters at the end\n");
    _exit(2);
}

int main(int argc, char **argv)
{
    int i = 1;
    for (; i < argc; i++) {
        const char *a = argv[i];
        if (strcmp(a, "--") == 0) {
            i++;
            break;
        }
        if (strncmp(a, "--filter=", 9) == 0) {
            if (strcmp(a + 9, "full") == 0) {
                g_opt.filter_set = FILTER_FULL;
            } else if (strcmp(a + 9, "io") == 0) {
                g_opt.filter_set = FILTER_IO;
            } else {
                g_opt.filter_set = FILTER_EXEC;
            }
        } else if (strncmp(a, "--allow=", 8) == 0) {
            g_opt.allow_mode = (strcmp(a + 8, "emulate") == 0) ? ALLOW_EMULATE
                                                               : ALLOW_CONTINUE;
        } else if (strncmp(a, "--deny=", 7) == 0) {
            if (g_opt.deny_len < MAX_DENY) {
                g_opt.deny_substr[g_opt.deny_len++] = a + 7;
            }
        } else if (strncmp(a, "--deny-call=", 12) == 0) {
            if (g_opt.deny_call_len < MAX_DENY) {
                g_opt.deny_call[g_opt.deny_call_len++] = a + 12;
            }
        } else if (strncmp(a, "--log=", 6) == 0) {
            g_opt.log_path = a + 6;
        } else if (strncmp(a, "--delay-ms=", 11) == 0) {
            g_opt.delay_us = atol(a + 11) * 1000;
        } else if (strncmp(a, "--exit-after=", 13) == 0) {
            g_opt.exit_after = atol(a + 13);
        } else if (strncmp(a, "--trigger=", 10) == 0) {
            g_opt.trigger = a + 10;
        } else if (strcmp(a, "--trap-sendmsg") == 0) {
            g_opt.trap_sendmsg = true;
        } else if (strncmp(a, "--suicide-ms=", 13) == 0) {
            g_opt.suicide_ms = atol(a + 13);
        } else if (strcmp(a, "--no-answer") == 0) {
            g_opt.no_answer = true;
        } else if (strcmp(a, "--no-read-args") == 0) {
            g_opt.read_args = false;
        } else if (strcmp(a, "--killable-recv") == 0) {
            g_opt.killable_recv = true;
        } else if (strcmp(a, "--stats") == 0) {
            g_opt.stats = true;
        } else if (a[0] == '-' && a[1] == '-') {
            usage();
        } else {
            break;
        }
    }
    if (i >= argc) {
        usage();
    }
    char **cmd = &argv[i];

    if (g_opt.filter_set == FILTER_IO) {
        g_set_len = sizeof(IO_SET) / sizeof(IO_SET[0]);
        memcpy(g_set, IO_SET, sizeof(IO_SET));
    } else if (g_opt.filter_set == FILTER_FULL) {
        g_set_len = sizeof(FULL_SET) / sizeof(FULL_SET[0]);
        memcpy(g_set, FULL_SET, sizeof(FULL_SET));
    } else {
        g_set_len = sizeof(EXEC_SET) / sizeof(EXEC_SET[0]);
        memcpy(g_set, EXEC_SET, sizeof(EXEC_SET));
    }

    if (g_opt.trap_sendmsg && g_set_len < MAX_TRAPPED) {
        struct trapped_call sm = { __NR_sendmsg, "sendmsg", -1, ARG_NONE, -1,
                                   -1 };
        g_set[g_set_len++] = sm;
    }

    if (g_opt.log_path != NULL) {
        if (strcmp(g_opt.log_path, "-") == 0) {
            g_log = stderr;
        } else {
            g_log = fopen(g_opt.log_path, "w");
            if (g_log == NULL) {
                die("fopen(log)");
            }
        }
    }

    for (size_t k = 0; k < MEM_CACHE; k++) {
        g_mem[k].fd = -1;
    }

    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sv) != 0) {
        die("socketpair");
    }

    pid_t child = fork();
    if (child < 0) {
        die("fork");
    }
    if (child == 0) {
        close(sv[0]);
        int listener = install_filter();
        send_fd(sv[1], listener);
        close(listener);
        close(sv[1]);
        execvp(cmd[0], cmd);
        fprintf(stderr, "afw-unotify: execvp %s: %s\n", cmd[0],
                strerror(errno));
        _exit(126);
    }

    close(sv[1]);
    int listener = recv_fd(sv[0]);
    close(sv[0]);

    /* The crash test. SIGALRM has no handler here, so the supervisor dies
     * at the moment that the timer runs out, and it can die while a target
     * still waits for an answer. */
    if (g_opt.suicide_ms > 0) {
        struct itimerval it;
        memset(&it, 0, sizeof(it));
        it.it_value.tv_sec = g_opt.suicide_ms / 1000;
        it.it_value.tv_usec = (g_opt.suicide_ms % 1000) * 1000;
        setitimer(ITIMER_REAL, &it, NULL);
    }

    int status = 0;
    supervise(listener, child, &status);

    if (g_opt.stats) {
        fprintf(stderr,
                "afw-unotify: notifications=%lu denied=%lu emulated=%lu "
                "stale=%lu\n",
                g_count_total, g_count_denied, g_count_emulated, g_count_stale);
    }

    if (WIFEXITED(status)) {
        return WEXITSTATUS(status);
    }
    if (WIFSIGNALED(status)) {
        return 128 + WTERMSIG(status);
    }
    return 0;
}
