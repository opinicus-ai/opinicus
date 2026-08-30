//
// rawsys — file and network access through raw syscalls, no libc wrappers.
//
// A static binary and a program that calls syscall() directly never pass
// through libc, so an LD_PRELOAD sensor sees nothing. The kernel filter of
// the firewall selects on the syscall number, so this technique measures
// whether that filter holds the calls anyway.
//
//   rawsys <port> <marker-file>
//
// Two independent actions:
//   connect  — raw socket + connect + write to 127.0.0.1:<port>
//   file     — raw openat (write intent) + write of <marker-file>
//
// Every action reports one line "ACTION <name> ok|blocked ...". A blocked
// action does not stop the next one.
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <unistd.h>

static void report(const char *name, int ok, long rc) {
    printf("ACTION %s %s rc=%ld errno=%d (%s)\n", name, ok ? "ok" : "blocked",
           rc, errno, rc < 0 ? strerror(errno) : "none");
    fflush(stdout);
}

int main(int argc, char **argv) {
    if (argc != 3) {
        fprintf(stderr, "usage: rawsys <port> <marker-file>\n");
        return 2;
    }
    int port = atoi(argv[1]);
    const char *marker = argv[2];

    long fd = syscall(SYS_socket, AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        report("connect", 0, fd);
    } else {
        struct sockaddr_in a;
        memset(&a, 0, sizeof a);
        a.sin_family = AF_INET;
        a.sin_port = htons((unsigned short)port);
        a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        long r = syscall(SYS_connect, fd, &a, sizeof a);
        if (r == 0) {
            long w = syscall(SYS_write, fd, "rawsys-connect\n", 14);
            report("connect", w > 0, w);
        } else {
            report("connect", 0, r);
        }
        syscall(SYS_close, fd);
    }

    long o = syscall(SYS_openat, AT_FDCWD, marker, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (o >= 0) {
        long w = syscall(SYS_write, o, "rawsys-file\n", 12);
        report("file", w > 0, w);
        syscall(SYS_close, o);
    } else {
        report("file", 0, o);
    }
    return 0;
}
