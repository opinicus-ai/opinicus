/* fs_probe — a target that runs inside the sandbox and reports the result of
 * each operation with its error number.
 *
 * Every line of output has the shape:
 *     OP <verb> <argument> -> OK
 *     OP <verb> <argument> -> FAIL errno=EACCES
 *
 * The exit status is 0 when every operation succeeded, and 1 when at least
 * one failed. A test asserts on the lines, not on the status.
 *
 * The program never blocks: the network operations use a non-blocking socket
 * with a short poll, so a sandbox that stops a connect cannot stop the test.
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

static int failures;

static const char *errname(int e)
{
    switch (e) {
    case EACCES: return "EACCES";
    case EPERM: return "EPERM";
    case ENOENT: return "ENOENT";
    case EEXIST: return "EEXIST";
    case ENOTEMPTY: return "ENOTEMPTY";
    case ECONNREFUSED: return "ECONNREFUSED";
    case ENETUNREACH: return "ENETUNREACH";
    case EAFNOSUPPORT: return "EAFNOSUPPORT";
    case EISDIR: return "EISDIR";
    case EXDEV: return "EXDEV";
    default: return "OTHER";
    }
}

static void report(const char *verb, const char *arg, int ok, int e)
{
    if (ok)
        printf("OP %s %s -> OK\n", verb, arg);
    else {
        printf("OP %s %s -> FAIL errno=%s(%d) %s\n", verb, arg, errname(e), e,
               strerror(e));
        failures++;
    }
    fflush(stdout);
}

static void do_read(const char *p)
{
    int fd = open(p, O_RDONLY | O_CLOEXEC);
    if (fd < 0) { report("read", p, 0, errno); return; }
    char b[16];
    ssize_t n = read(fd, b, sizeof(b));
    int e = errno;
    close(fd);
    report("read", p, n >= 0, e);
}

static void do_write(const char *p)
{
    int fd = open(p, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0600);
    if (fd < 0) { report("write", p, 0, errno); return; }
    ssize_t n = write(fd, "x\n", 2);
    int e = errno;
    close(fd);
    report("write", p, n == 2, e);
}

static void do_create(const char *p)
{
    int fd = open(p, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    int e = errno;
    if (fd >= 0) close(fd);
    report("create", p, fd >= 0, e);
}

static void do_truncate(const char *p)
{
    int rc = truncate(p, 0);
    report("truncate", p, rc == 0, errno);
}

static void do_unlink(const char *p) { report("unlink", p, unlink(p) == 0, errno); }
static void do_mkdir(const char *p) { report("mkdir", p, mkdir(p, 0700) == 0, errno); }
static void do_rmdir(const char *p) { report("rmdir", p, rmdir(p) == 0, errno); }
static void do_stat(const char *p)
{
    struct stat st;
    report("stat", p, stat(p, &st) == 0, errno);
}

static void do_list(const char *p)
{
    DIR *d = opendir(p);
    int e = errno;
    if (d) closedir(d);
    report("list", p, d != NULL, e);
}

static void do_exec(const char *p)
{
    pid_t pid = fork();
    if (pid == 0) {
        execl(p, p, (char *)NULL);
        _exit(errno);
    }
    int status = 0;
    waitpid(pid, &status, 0);
    int e = WIFEXITED(status) ? WEXITSTATUS(status) : 0;
    report("exec", p, e == 0, e ? e : EPERM);
}

/* A non-blocking connect to 127.0.0.1:port. It never waits longer than
 * 2000 ms, so a denied connect can never hold the test. */
static void do_connect(const char *portstr)
{
    int port = atoi(portstr);
    int fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (fd < 0) { report("connect", portstr, 0, errno); return; }
    struct sockaddr_in sa = {.sin_family = AF_INET, .sin_port = htons((uint16_t)port)};
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    int rc = connect(fd, (struct sockaddr *)&sa, sizeof(sa));
    int e = errno;
    if (rc < 0 && e == EINPROGRESS) {
        struct pollfd pfd = {.fd = fd, .events = POLLOUT};
        int pr = poll(&pfd, 1, 2000);
        if (pr > 0) {
            int soerr = 0;
            socklen_t len = sizeof(soerr);
            getsockopt(fd, SOL_SOCKET, SO_ERROR, &soerr, &len);
            rc = soerr == 0 ? 0 : -1;
            e = soerr;
        } else {
            rc = -1;
            e = ETIMEDOUT;
        }
    }
    close(fd);
    report("connect", portstr, rc == 0, e);
}

static void do_bind(const char *portstr)
{
    int port = atoi(portstr);
    int fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) { report("bind", portstr, 0, errno); return; }
    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    struct sockaddr_in sa = {.sin_family = AF_INET, .sin_port = htons((uint16_t)port)};
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    int rc = bind(fd, (struct sockaddr *)&sa, sizeof(sa));
    int e = errno;
    close(fd);
    report("bind", portstr, rc == 0, e);
}

/* Sends signal 0 to a process. Signal 0 changes nothing; it only asks
 * whether the sender may signal that process. LANDLOCK_SCOPE_SIGNAL makes it
 * fail for a process outside the sandbox. */
static void do_signal(const char *pidstr)
{
    int pid = atoi(pidstr);
    int rc = kill((pid_t)pid, 0);
    report("signal", pidstr, rc == 0, errno);
}

int main(int argc, char **argv)
{
    for (int i = 1; i < argc; i += 2) {
        if (i + 1 >= argc) {
            fprintf(stderr, "fs_probe: %s needs an argument\n", argv[i]);
            return 2;
        }
        const char *verb = argv[i], *arg = argv[i + 1];
        if (!strcmp(verb, "read")) do_read(arg);
        else if (!strcmp(verb, "write")) do_write(arg);
        else if (!strcmp(verb, "create")) do_create(arg);
        else if (!strcmp(verb, "truncate")) do_truncate(arg);
        else if (!strcmp(verb, "unlink")) do_unlink(arg);
        else if (!strcmp(verb, "mkdir")) do_mkdir(arg);
        else if (!strcmp(verb, "rmdir")) do_rmdir(arg);
        else if (!strcmp(verb, "list")) do_list(arg);
        else if (!strcmp(verb, "stat")) do_stat(arg);
        else if (!strcmp(verb, "exec")) do_exec(arg);
        else if (!strcmp(verb, "connect")) do_connect(arg);
        else if (!strcmp(verb, "bind")) do_bind(arg);
        else if (!strcmp(verb, "signal")) do_signal(arg);
        else { fprintf(stderr, "fs_probe: unknown verb %s\n", verb); return 2; }
    }
    return failures ? 1 : 0;
}
