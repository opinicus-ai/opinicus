/*
 * preload.c - an LD_PRELOAD library that interposes four libc functions.
 *
 * The dynamic linker binds a call to execve, openat, unlink or connect to
 * this library first. The wrapper writes a line to the log file and then
 * calls the real function that dlsym(RTLD_NEXT, ...) returns.
 *
 * The logger uses raw system calls. A call to fopen or to printf would go
 * back into libc and could return into this library.
 *
 * Environment:
 *   AFW_PRELOAD_LOG    the path of the log file. No log means no record.
 *   AFW_PRELOAD_DENY   a text. A path or a program name that holds this text
 *                      is refused with EACCES, and the real function never
 *                      runs. This shows that the mechanism can block and not
 *                      only observe.
 */
#define _GNU_SOURCE

#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>

typedef int (*execve_fn)(const char *, char *const[], char *const[]);
typedef int (*openat_fn)(int, const char *, int, ...);
typedef int (*unlink_fn)(const char *);
typedef int (*connect_fn)(int, const struct sockaddr *, socklen_t);

static void write_log(const char *line, size_t length)
{
    /* The file descriptor stays open, so that one event costs one write and
     * not an open, a write and a close. It is moved to a high number and it
     * has the close-on-exec flag, so that it does not collide with a file
     * descriptor of the program. O_APPEND makes a short write atomic, so
     * many processes can share one log file. */
    static int fd = -1;
    static int tried;
    const char *path;

    if (fd < 0) {
        long raw;

        if (tried) {
            return;
        }
        tried = 1;
        path = getenv("AFW_PRELOAD_LOG");
        if (!path || path[0] == '\0') {
            return;
        }
        raw = syscall(SYS_openat, AT_FDCWD, path,
                      O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0644);
        if (raw < 0) {
            return;
        }
        fd = (int)syscall(SYS_fcntl, raw, F_DUPFD_CLOEXEC, 900);
        if (fd < 0) {
            fd = (int)raw;
        } else {
            syscall(SYS_close, raw);
        }
    }
    syscall(SYS_write, fd, line, length);
}

static void log_event(const char *format, ...)
{
    char line[1024];
    va_list arguments;
    int length;

    va_start(arguments, format);
    length = vsnprintf(line, sizeof(line), format, arguments);
    va_end(arguments);
    if (length <= 0) {
        return;
    }
    if ((size_t)length >= sizeof(line)) {
        length = (int)sizeof(line) - 1;
    }
    write_log(line, (size_t)length);
}

/* Returns 1 when the path must be refused. */
static int must_deny(const char *path)
{
    static const char *needle;
    static int looked;

    if (!looked) {
        looked = 1;
        needle = getenv("AFW_PRELOAD_DENY");
        if (needle && needle[0] == '\0') {
            needle = NULL;
        }
    }
    if (!needle || !path) {
        return 0;
    }
    return strstr(path, needle) != NULL;
}

int execve(const char *path, char *const argv[], char *const envp[])
{
    static execve_fn real;

    if (!real) {
        real = (execve_fn)dlsym(RTLD_NEXT, "execve");
    }
    log_event("execve pid=%d path=%s arg1=%s\n", (int)getpid(), path,
              argv[0] && argv[1] ? argv[1] : "");
    if (must_deny(path)) {
        log_event("DENY execve pid=%d path=%s\n", (int)getpid(), path);
        errno = EACCES;
        return -1;
    }
    return real(path, argv, envp);
}

int openat(int dirfd, const char *path, int flags, ...)
{
    static openat_fn real;
    mode_t mode = 0;
    va_list arguments;

    if (!real) {
        real = (openat_fn)dlsym(RTLD_NEXT, "openat");
    }
    if (flags & (O_CREAT | O_TMPFILE)) {
        va_start(arguments, flags);
        mode = (mode_t)va_arg(arguments, int);
        va_end(arguments);
    }
    log_event("openat pid=%d path=%s flags=0x%x\n", (int)getpid(), path,
              (unsigned int)flags);
    if (must_deny(path)) {
        log_event("DENY openat pid=%d path=%s\n", (int)getpid(), path);
        errno = EACCES;
        return -1;
    }
    return real(dirfd, path, flags, mode);
}

int unlink(const char *path)
{
    static unlink_fn real;

    if (!real) {
        real = (unlink_fn)dlsym(RTLD_NEXT, "unlink");
    }
    log_event("unlink pid=%d path=%s\n", (int)getpid(), path);
    if (must_deny(path)) {
        log_event("DENY unlink pid=%d path=%s\n", (int)getpid(), path);
        errno = EACCES;
        return -1;
    }
    return real(path);
}

int connect(int fd, const struct sockaddr *address, socklen_t length)
{
    static connect_fn real;
    char host[64];
    int port = 0;

    if (!real) {
        real = (connect_fn)dlsym(RTLD_NEXT, "connect");
    }
    host[0] = '\0';
    if (address && address->sa_family == AF_INET) {
        const struct sockaddr_in *in = (const struct sockaddr_in *)address;

        inet_ntop(AF_INET, &in->sin_addr, host, sizeof(host));
        port = ntohs(in->sin_port);
    } else if (address && address->sa_family == AF_INET6) {
        const struct sockaddr_in6 *in6 = (const struct sockaddr_in6 *)address;

        inet_ntop(AF_INET6, &in6->sin6_addr, host, sizeof(host));
        port = ntohs(in6->sin6_port);
    } else {
        snprintf(host, sizeof(host), "family=%d",
                 address ? address->sa_family : -1);
    }
    log_event("connect pid=%d host=%s port=%d\n", (int)getpid(), host, port);
    if (must_deny(host)) {
        log_event("DENY connect pid=%d host=%s port=%d\n", (int)getpid(),
                  host, port);
        errno = EACCES;
        return -1;
    }
    return real(fd, address, length);
}
