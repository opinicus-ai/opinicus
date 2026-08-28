/* tcp_listener — a listener on 127.0.0.1 for the network tests.
 *
 * It prints "LISTEN <port>" when it is ready, and it stops itself after the
 * given number of seconds. A test can therefore never leave it behind.
 *
 * usage: tcp-listener PORT SECONDS
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

int main(int argc, char **argv)
{
    if (argc < 3) {
        fprintf(stderr, "usage: tcp-listener PORT SECONDS\n");
        return 2;
    }
    int port = atoi(argv[1]);
    unsigned seconds = (unsigned)atoi(argv[2]);

    int fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) { perror("socket"); return 1; }
    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    struct sockaddr_in sa = {.sin_family = AF_INET, .sin_port = htons((uint16_t)port)};
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) { perror("bind"); return 1; }
    if (listen(fd, 16) < 0) { perror("listen"); return 1; }

    printf("LISTEN %d\n", port);
    fflush(stdout);

    /* The alarm is the safety net. The listener always ends. */
    signal(SIGALRM, SIG_DFL);
    alarm(seconds ? seconds : 30);

    for (;;) {
        int c = accept(fd, NULL, NULL);
        if (c < 0) {
            if (errno == EINTR) continue;
            break;
        }
        close(c);
    }
    return 0;
}
