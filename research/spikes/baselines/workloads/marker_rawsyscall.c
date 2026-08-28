/*
 * marker_rawsyscall.c - a workload that does not use the libc wrappers.
 *
 * It is a normal dynamic program, so the LD_PRELOAD library is loaded into
 * the address space. But the program reaches the kernel with syscall(), and
 * syscall() is not the openat symbol, so the interposed wrapper never runs.
 *
 * Usage: marker_rawsyscall MARKER_PATH [PORT]
 */
#define _GNU_SOURCE

#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <unistd.h>

int main(int argc, char **argv)
{
    static const char text[] = "marker written by raw system calls\n";
    char victim[4096];
    long fd;

    if (argc < 2) {
        fprintf(stderr, "usage: marker_rawsyscall MARKER_PATH [PORT]\n");
        return 2;
    }

    fd = syscall(SYS_openat, AT_FDCWD, argv[1],
                 O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) {
        fprintf(stderr, "openat syscall failed\n");
        return 1;
    }
    syscall(SYS_write, fd, text, sizeof(text) - 1);
    syscall(SYS_close, fd);

    snprintf(victim, sizeof(victim), "%s.victim", argv[1]);
    fd = syscall(SYS_openat, AT_FDCWD, victim, O_WRONLY | O_CREAT | O_TRUNC,
                 0644);
    if (fd >= 0) {
        syscall(SYS_close, fd);
        syscall(SYS_unlinkat, AT_FDCWD, victim, 0);
    }

    if (argc > 2) {
        int port = atoi(argv[2]);
        long sock = syscall(SYS_socket, AF_INET, SOCK_STREAM, 0);
        struct sockaddr_in address;

        memset(&address, 0, sizeof(address));
        address.sin_family = AF_INET;
        address.sin_port = htons((unsigned short)port);
        inet_pton(AF_INET, "127.0.0.1", &address.sin_addr);
        if (sock >= 0) {
            syscall(SYS_connect, sock, &address, sizeof(address));
            syscall(SYS_close, sock);
        }
    }
    return 0;
}
