//
// uring-standin — a ptrace-free stand-in for the io_uring hold of [af-12].
//
// The product holds io_uring_setup and io_uring_enter with SECCOMP_RET_TRACE
// and refuses them with EPERM when the rule denies. That needs a ptrace
// monitor. This stand-in answers the two questions of the compatibility
// matrix (EXP-T1) with seccomp alone, so it runs on hosts where ptrace is
// unavailable (yama ptrace_scope 3 latches on this machine):
//
//   uring-standin count <log-file> <cmd> [args..]
//       SECCOMP_RET_USER_NOTIF on the two calls; every notification is
//       answered with CONTINUE, so the workload behaves exactly as with no
//       filter, and every io_uring call of the whole tree is logged with
//       the pid and the call name. This measures whether the product's
//       filter would hold anything at all — and whether its deny rule
//       would fire — without running the monitor.
//
//   uring-standin deny <cmd> [args..]
//       SECCOMP_RET_ERRNO|EPERM on the two calls; everything else is
//       allowed. The program-visible effect is the same refusal the
//       product's Intercept::Refuse produces, isolated from every other
//       part of the firewall (no ptrace, no Landlock floor, no rules).
//       This measures what breaks when the ring road is denied.
//
// The filter is installed once, before the fork; the child execs the
// workload and inherits the filter over fork and exec, exactly as the
// product's child does. The kernel decides on the call number alone, so
// the selection cannot be raced — the same property the product relies on.
// The listener of `count` answers every notification with CONTINUE and
// logs it; the log is the measurement, the CONTINUE is the honesty: the
// stand-in never changes what the workload sees.
//
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef __NR_io_uring_setup
#define __NR_io_uring_setup 425
#endif
#ifndef __NR_io_uring_enter
#define __NR_io_uring_enter 426
#endif

/* One load-compare-answer block per call number, then the default. The two
 * action slots are filled in at run time, so one program serves both
 * modes. */
static struct sock_filter program[] = {
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, 4), /* arch */
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 1, 0),
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, 0), /* nr */
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_io_uring_setup, 0, 1),
    BPF_STMT(BPF_RET | BPF_K, 0), /* action, filled in at run time */
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, 0),
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_io_uring_enter, 0, 1),
    BPF_STMT(BPF_RET | BPF_K, 0), /* action, filled in at run time */
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
};
/* Offsets of the two action slots above. */
#define ACTION_SETUP 5
#define ACTION_ENTER 8

static const char *call_name(long nr) {
    if (nr == __NR_io_uring_setup) return "io_uring_setup";
    if (nr == __NR_io_uring_enter) return "io_uring_enter";
    return "?";
}

/* The listener child: answers every notification with CONTINUE and logs
 * the call, until the parent kills it when the workload tree has ended.
 *
 * CONTINUE executes the syscall as if no filter existed, which is what
 * makes `count` a pure measurement. The loop blocks in RECV — nothing
 * else needs to happen in this process — so the parent ends it with a
 * signal instead of a flag.
 */
static void listen_and_continue(int listener, FILE *log) {
    for (;;) {
        struct seccomp_notif req;
        memset(&req, 0, sizeof req);
        if (ioctl(listener, SECCOMP_IOCTL_NOTIF_RECV, &req) < 0) {
            if (errno == EINTR) continue;
            return;
        }
        fprintf(log, "pid=%u call=%s\n", req.pid, call_name(req.data.nr));
        fflush(log);
        struct seccomp_notif_resp resp;
        memset(&resp, 0, sizeof resp);
        resp.id = req.id;
        resp.flags = SECCOMP_USER_NOTIF_FLAG_CONTINUE;
        if (ioctl(listener, SECCOMP_IOCTL_NOTIF_SEND, &resp) < 0 &&
            errno != ENOENT && errno != EINVAL) {
            fprintf(stderr, "uring-standin: send failed: %s\n", strerror(errno));
        }
    }
}

int main(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr,
                "usage: uring-standin count <log-file> <cmd> [args..]\n"
                "       uring-standin deny <cmd> [args..]\n");
        return 2;
    }
    int counting = strcmp(argv[1], "count") == 0;
    if (!counting && strcmp(argv[1], "deny") != 0) {
        fprintf(stderr, "uring-standin: unknown mode %s\n", argv[1]);
        return 2;
    }
    FILE *log = NULL;
    char **cmd = &argv[2];
    if (counting) {
        if (argc < 4) {
            fprintf(stderr, "uring-standin: count needs a log file\n");
            return 2;
        }
        log = fopen(argv[2], "a");
        if (!log) {
            fprintf(stderr, "uring-standin: cannot open %s: %s\n", argv[2],
                    strerror(errno));
            return 2;
        }
        cmd = &argv[3];
    }
    __u32 action =
        counting ? SECCOMP_RET_USER_NOTIF : SECCOMP_RET_ERRNO | EPERM;
    program[ACTION_SETUP].k = action;
    program[ACTION_ENTER].k = action;

    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
        fprintf(stderr, "uring-standin: no_new_privs: %s\n", strerror(errno));
        return 2;
    }
    struct sock_fprog prog = {
        .len = (unsigned short)(sizeof program / sizeof program[0]),
        .filter = program,
    };
    int listener = -1;
    if (counting) {
        listener = (int)syscall(__NR_seccomp, SECCOMP_SET_MODE_FILTER,
                                SECCOMP_FILTER_FLAG_NEW_LISTENER, &prog);
        if (listener < 0) {
            fprintf(stderr, "uring-standin: user-notify filter: %s\n",
                    strerror(errno));
            return 2;
        }
        /* The workload must not inherit the listener; the dedicated
         * listener child keeps the only other copy. */
        int flags = fcntl(listener, F_GETFD);
        if (flags >= 0) {
            fcntl(listener, F_SETFD, flags | FD_CLOEXEC);
        }
    } else if (syscall(__NR_seccomp, SECCOMP_SET_MODE_FILTER, 0, &prog) != 0) {
        fprintf(stderr, "uring-standin: errno filter: %s\n", strerror(errno));
        return 2;
    }

    /* The listener runs in its own child, so the parent can wait for the
     * workload and end the listener afterwards. */
    pid_t listener_child = -1;
    if (counting) {
        listener_child = fork();
        if (listener_child < 0) {
            fprintf(stderr, "uring-standin: fork: %s\n", strerror(errno));
            return 2;
        }
        if (listener_child == 0) {
            listen_and_continue(listener, log);
            _exit(0);
        }
    }

    pid_t child = fork();
    if (child < 0) {
        fprintf(stderr, "uring-standin: fork: %s\n", strerror(errno));
        return 2;
    }
    if (child == 0) {
        execvp(cmd[0], cmd);
        fprintf(stderr, "uring-standin: cannot run %s: %s\n", cmd[0],
                strerror(errno));
        _exit(127);
    }
    /* The workload root waits for its own tree, exactly as every harness
     * workload of this repository does, so its exit is the end of the
     * measurement. */
    int status = 0;
    if (waitpid(child, &status, 0) < 0) {
        fprintf(stderr, "uring-standin: waitpid: %s\n", strerror(errno));
        return 2;
    }
    int code = 0;
    if (WIFEXITED(status)) {
        code = WEXITSTATUS(status);
    } else if (WIFSIGNALED(status)) {
        code = 128 + WTERMSIG(status);
    }
    if (listener_child > 0) {
        kill(listener_child, SIGKILL);
        waitpid(listener_child, &status, 0);
    }
    return code;
}
