//
// inherit-fd — live descriptors handed to a session process. Review
// finding P0-7 / experiment EXP-T3 (docs/PROJECT-REVIEW.md §5.3.3): a
// capability that is already open needs no `open` and no `connect` to be
// used, and `write`/`send` on it are outside the kernel filter's held
// calls. No catalogue row exists yet for descriptor inheritance itself
// (adjacent: evade-04 fileless memfd, evade-23 sensor descriptor sweep).
//
// Three rows of the descriptor-inheritance matrix:
//
//   inherit-fd launch <victim> <port> <command...>
//       The hostile launcher. This process pre-opens a writable file, a
//       connected TCP socket, a memfd and a pidfd — the file, the socket
//       and the memfd without close-on-exec — exports their numbers as
//       AF_INHERIT_* and execs <command> keeping every one open. The
//       pidfd carries FD_CLOEXEC by kernel design (pidfd_open sets it,
//       measured), so the pidfd row measures the kernel's own exec
//       boundary and the other three measure what the firewall must close
//       itself. Pointing <command> at the firewall runs the launcher
//       vector: the capability predates the session, so no observation
//       point of the firewall ever saw it open.
//
//   inherit-fd payload
//       The traced session root. Counts /proc/self/fd — the proof of what
//       launch hygiene left — and then writes through every inherited
//       descriptor. Expectation with launch hygiene: exactly three
//       descriptors (0,1,2) and EBADF everywhere; without it, the writes
//       land.
//
//   inherit-fd intree <victim> <port>
//       The in-tree vector. A traced process opens and connects itself
//       (both observation points fire, both events exist), then forks a
//       child that writes through the inherited descriptors without
//       opening or connecting anything. Measured question: does any event
//       cover the child's use?
//
// The runner verifies the effects from the filesystem and the listener
// log, never from this program's stdout.
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef SYS_pidfd_open
#define SYS_pidfd_open 434
#endif
#ifndef SYS_pidfd_send_signal
#define SYS_pidfd_send_signal 424
#endif

static const char *verdict(int ok) { return ok ? "ok" : "ebadf"; }

// Counts the descriptors of the calling process. The directory handle of
// the count itself appears in the listing, so it is subtracted again.
static int count_fds(void) {
    DIR *dir = opendir("/proc/self/fd");
    if (!dir) {
        return -1;
    }
    int count = 0;
    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_name[0] >= '0' && entry->d_name[0] <= '9') {
            count++;
        }
    }
    closedir(dir);
    return count - 1;
}

static int fd_of_env(const char *name) {
    const char *text = getenv(name);
    return text ? atoi(text) : -1;
}

// The hostile launcher: opens four capabilities, none close-on-exec, and
// execs the command the runner named. Every descriptor survives the exec.
static int run_launch(int argc, char **argv) {
    if (argc < 5) {
        fprintf(stderr, "usage: inherit-fd launch <victim> <port> <command...>\n");
        return 2;
    }
    const char *victim = argv[2];
    int port = atoi(argv[3]);

    // A writable file. Opened here, outside every observation point.
    int file = open(victim, O_WRONLY | O_CREAT | O_APPEND, 0644);
    // A connected socket. The connect happened before the session began.
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof addr);
    addr.sin_family = AF_INET;
    addr.sin_port = htons((unsigned short)port);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    int connect_rc = sock >= 0 ? connect(sock, (struct sockaddr *)&addr, sizeof addr) : -1;
    // An anonymous file: write access with no path at all.
    long memfd = syscall(SYS_memfd_create, "inherit-fd", 0);
    // A process handle: a signalling capability. pidfd_open sets
    // FD_CLOEXEC itself (measured with fcntl(F_GETFD)), so this one
    // closes at the exec without any help — the kernel's own hygiene,
    // and the control row of this fixture.
    long pidfd = syscall(SYS_pidfd_open, getpid(), 0);

    if (file < 0 || connect_rc != 0 || memfd < 0 || pidfd < 0) {
        fprintf(stderr, "inherit-fd: cannot arm the launcher (file=%d connect=%d "
                        "memfd=%ld pidfd=%ld)\n",
                file, connect_rc, memfd, pidfd);
        return 1;
    }

    char text[64];
    snprintf(text, sizeof text, "%d", file);
    setenv("AF_INHERIT_FILE", text, 1);
    snprintf(text, sizeof text, "%d", sock);
    setenv("AF_INHERIT_SOCK", text, 1);
    snprintf(text, sizeof text, "%ld", memfd);
    setenv("AF_INHERIT_MEMFD", text, 1);
    snprintf(text, sizeof text, "%ld", pidfd);
    setenv("AF_INHERIT_PIDFD", text, 1);
    setenv("AF_INHERIT_VICTIM", victim, 1);

    printf("ACTION inherit-fd armed file=%d sock=%d memfd=%ld pidfd=%ld\n",
           file, sock, memfd, pidfd);
    fflush(stdout);
    execvp(argv[4], &argv[4]);
    perror("execvp");
    return 1;
}

// The session root: counts what launch left, then writes through every
// inherited descriptor. `ebadf` on every one of them is the launch
// hygiene holding; `ok` on any of them is a write that no observation
// point ever saw.
static int run_payload(void) {
    int fds = count_fds();
    int file = fd_of_env("AF_INHERIT_FILE");
    int sock = fd_of_env("AF_INHERIT_SOCK");
    int memfd = fd_of_env("AF_INHERIT_MEMFD");
    int pidfd = fd_of_env("AF_INHERIT_PIDFD");

    errno = 0;
    int file_rc = write(file, "inherit-fd-launch\n", 18) == 18;
    int file_errno = file_rc ? 0 : errno;

    errno = 0;
    int sock_rc = send(sock, "inherit-fd-launch\n", 18, 0) == 18;
    int sock_errno = sock_rc ? 0 : errno;

    errno = 0;
    int memfd_rc = write(memfd, "x", 1) == 1;
    int memfd_errno = memfd_rc ? 0 : errno;

    errno = 0;
    long pidfd_rc = syscall(SYS_pidfd_send_signal, pidfd, 0, NULL, 0);
    int pidfd_errno = pidfd_rc == 0 ? 0 : errno;

    printf("ACTION inherit-fd payload fds=%d file=%s sock=%s memfd=%s "
           "pidfd=%s errno(file=%d sock=%d memfd=%d pidfd=%d)\n",
           fds, verdict(file_rc), verdict(sock_rc), verdict(memfd_rc),
           verdict(pidfd_rc == 0), file_errno, sock_errno, memfd_errno,
           pidfd_errno);
    return 0;
}

// The in-tree vector: open and connect inside the session (both events
// fire), then hand everything to a forked child that uses the inherited
// descriptors without opening or connecting anything of its own.
static int run_intree(int argc, char **argv) {
    if (argc != 4) {
        fprintf(stderr, "usage: inherit-fd intree <victim> <port>\n");
        return 2;
    }
    const char *victim = argv[2];
    int port = atoi(argv[3]);

    int file = open(victim, O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (file < 0) {
        perror("open victim");
        return 1;
    }
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof addr);
    addr.sin_family = AF_INET;
    addr.sin_port = htons((unsigned short)port);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (connect(sock, (struct sockaddr *)&addr, sizeof addr) != 0) {
        perror("connect");
        return 1;
    }
    long memfd = syscall(SYS_memfd_create, "inherit-fd", 0);
    long pidfd = syscall(SYS_pidfd_open, getpid(), 0);

    pid_t pid = fork();
    if (pid < 0) {
        perror("fork");
        return 1;
    }
    if (pid > 0) {
        // The parent opened and connected; every observation point fired
        // here. The question is the child's row below.
        printf("ACTION inherit-fd intree parent file=%d sock=%d memfd=%ld pidfd=%ld\n",
               file, sock, memfd, pidfd);
        fflush(stdout);
        int status = 0;
        waitpid(pid, &status, 0);
        return 0;
    }

    // The child: no open, no connect, no exec — only use.
    errno = 0;
    int file_rc = write(file, "inherit-fd-intree\n", 18) == 18;
    int file_errno = file_rc ? 0 : errno;
    errno = 0;
    int sock_rc = send(sock, "inherit-fd-intree\n", 18, 0) == 18;
    int sock_errno = sock_rc ? 0 : errno;
    errno = 0;
    int memfd_rc = write(memfd, "x", 1) == 1;
    int memfd_errno = memfd_rc ? 0 : errno;
    errno = 0;
    long pidfd_rc = syscall(SYS_pidfd_send_signal, pidfd, 0, NULL, 0);
    int pidfd_errno = pidfd_rc == 0 ? 0 : errno;
    printf("ACTION inherit-fd intree child file=%s sock=%s memfd=%s "
           "pidfd=%s errno(file=%d sock=%d memfd=%d pidfd=%d)\n",
           verdict(file_rc), verdict(sock_rc), verdict(memfd_rc),
           verdict(pidfd_rc == 0), file_errno, sock_errno, memfd_errno,
           pidfd_errno);
    fflush(stdout);
    _exit(0);
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: inherit-fd launch|payload|intree ...\n");
        return 2;
    }
    if (strcmp(argv[1], "launch") == 0) {
        return run_launch(argc, argv);
    }
    if (strcmp(argv[1], "payload") == 0) {
        return run_payload();
    }
    if (strcmp(argv[1], "intree") == 0) {
        return run_intree(argc, argv);
    }
    fprintf(stderr, "inherit-fd: unknown mode %s\n", argv[1]);
    return 2;
}
