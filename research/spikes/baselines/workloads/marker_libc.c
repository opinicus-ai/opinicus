/*
 * marker_libc.c - the control workload of the LD_PRELOAD test.
 *
 * It writes a marker file with the libc openat function, opens a TCP
 * connection with the libc connect function, and removes a file with the
 * libc unlink function. Every call goes through the dynamic linker, so an
 * LD_PRELOAD library must see all of them.
 *
 * Usage: marker_libc MARKER_PATH [PORT]
 */
#define _GNU_SOURCE

#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

int main(int argc, char **argv)
{
    char victim[4096];
    int fd;

    if (argc < 2) {
        fprintf(stderr, "usage: marker_libc MARKER_PATH [PORT]\n");
        return 2;
    }

    fd = openat(AT_FDCWD, argv[1], O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) {
        perror("openat");
        return 1;
    }
    write(fd, "marker written by libc calls\n", 29);
    close(fd);

    snprintf(victim, sizeof(victim), "%s.victim", argv[1]);
    fd = openat(AT_FDCWD, victim, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd >= 0) {
        close(fd);
        unlink(victim);
    }

    if (argc > 2) {
        int port = atoi(argv[2]);
        int sock = socket(AF_INET, SOCK_STREAM, 0);
        struct sockaddr_in address;

        memset(&address, 0, sizeof(address));
        address.sin_family = AF_INET;
        address.sin_port = htons((unsigned short)port);
        inet_pton(AF_INET, "127.0.0.1", &address.sin_addr);
        if (sock >= 0) {
            if (connect(sock, (struct sockaddr *)&address, sizeof(address)) <
                0) {
                perror("connect");
            }
            close(sock);
        }
    }
    return 0;
}
