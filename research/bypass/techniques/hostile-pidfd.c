//
// hostile-pidfd — the pidfd routes to the monitor from outside the tree.
// Ticket [af-12], review P1-6 / EXP-T2 and seccomp.rs:43.
//
// The kernel filter holds kill/tkill/tgkill aimed at the monitor, but a
// pidfd names its target by a descriptor and a BPF filter cannot follow
// one, so pidfd_send_signal is a documented unheld route. The technique
// measures all three pidfd calls against the monitor:
//
//   pidfd_open       takes a handle on the monitor
//   pidfd_getfd      tries to copy one of the monitor's descriptors
//                    (standard output) and closes the copy at once
//   pidfd_send_signal  sends SIGKILL — the destructive step, last
//
// The expected shape: getfd follows the ptrace access check (yama answers
// EPERM at ptrace_scope >= 1), while send_signal follows the signal check,
// which a same-uid process always passes — the monitor dies at every yama
// level, and the fail-closed machinery of PTRACE_O_EXITKILL answers.
//
//   hostile-pidfd <marker-path>
#define _GNU_SOURCE
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

#include "hostile-find.h"

#ifndef SYS_pidfd_open
#define SYS_pidfd_open 434
#endif
#ifndef SYS_pidfd_getfd
#define SYS_pidfd_getfd 438
#endif
#ifndef SYS_pidfd_send_signal
#define SYS_pidfd_send_signal 424
#endif

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "usage: hostile-pidfd <marker-path>\n");
        return 2;
    }
    pid_t payload = 0;
    pid_t monitor = find_monitor(argv[1], &payload);
    if (monitor < 0) {
        printf("ACTION hostile-pidfd no-payload rc=-1\n");
        return 0;
    }
    if (monitor == 0) {
        printf("ACTION hostile-pidfd no-tracer payload=%d\n", payload);
        return 0;
    }
    printf("STEP hostile-pidfd target monitor=%d payload=%d\n", monitor, payload);

    int pidfd = (int)syscall(SYS_pidfd_open, monitor, 0U);
    printf("ACTION hostile-pidfd pidfd_open rc=%d errno=%d (%s)\n", pidfd, errno,
           strerror(errno));
    if (pidfd < 0) {
        return 0;
    }

    errno = 0;
    int copy = (int)syscall(SYS_pidfd_getfd, pidfd, 1, 0U);
    printf("ACTION hostile-pidfd pidfd_getfd rc=%d errno=%d (%s)\n", copy, errno,
           strerror(errno));
    if (copy >= 0) {
        close(copy);
    }

    errno = 0;
    long rc = syscall(SYS_pidfd_send_signal, pidfd, SIGKILL, NULL, 0U);
    printf("ACTION hostile-pidfd pidfd_send_signal signal=%d rc=%ld errno=%d (%s)\n", SIGKILL,
           rc, errno, strerror(errno));
    close(pidfd);
    return 0;
}
