//
// inherit-scm — a live socket descriptor passed to a session process
// mid-run over a unix socket. Review finding P0-7 / experiment EXP-T3
// (docs/PROJECT-REVIEW.md §5.3.3): `SCM_RIGHTS` installs a descriptor the
// receiver never opened, so the receiver's use of it crosses no
// observation point at all. No catalogue row exists for descriptor
// passing itself (adjacent: evade-23 sensor descriptor sweep).
//
//   inherit-scm <port>
//
// The traced parent connects a TCP socket to the local listener — the one
// observed open point of this technique — then passes the live descriptor
// to a forked child with sendmsg/SCM_RIGHTS over a socketpair and closes
// its own copy. The child never opens, never connects and never execs; it
// recvmsg's the descriptor and send()s the marker through it. The kernel
// installs a received descriptor without FD_CLOEXEC, so the capability
// would even survive a later exec of the child.
//
// The runner verifies the effect from the listener log, never from this
// program's stdout, and checks the trace for what covered which half: the
// parent's connect is an event, the child's use is the measured question.
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

static const char *verdict(int ok) { return ok ? "ok" : "ebadf"; }

// Sends one descriptor over a unix socket.
static int send_fd(int channel, int fd) {
    char byte = 'f';
    struct iovec iov = {.iov_base = &byte, .iov_len = 1};
    char control[CMSG_SPACE(sizeof(int))];
    memset(control, 0, sizeof control);
    struct msghdr msg;
    memset(&msg, 0, sizeof msg);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control;
    msg.msg_controllen = sizeof control;
    struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type = SCM_RIGHTS;
    cmsg->cmsg_len = CMSG_LEN(sizeof(int));
    memcpy(CMSG_DATA(cmsg), &fd, sizeof(int));
    return sendmsg(channel, &msg, 0) == 1 ? 0 : -1;
}

// Receives one descriptor from a unix socket.
static int recv_fd(int channel) {
    char byte;
    struct iovec iov = {.iov_base = &byte, .iov_len = 1};
    char control[CMSG_SPACE(sizeof(int))];
    struct msghdr msg;
    memset(&msg, 0, sizeof msg);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control;
    msg.msg_controllen = sizeof control;
    if (recvmsg(channel, &msg, 0) != 1) {
        return -1;
    }
    struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
    if (!cmsg || cmsg->cmsg_type != SCM_RIGHTS || cmsg->cmsg_len != CMSG_LEN(sizeof(int))) {
        return -1;
    }
    int fd = -1;
    memcpy(&fd, CMSG_DATA(cmsg), sizeof(int));
    return fd;
}

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "usage: inherit-scm <port>\n");
        return 2;
    }
    int port = atoi(argv[1]);

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

    int pair[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, pair) != 0) {
        perror("socketpair");
        return 1;
    }

    pid_t pid = fork();
    if (pid < 0) {
        perror("fork");
        return 1;
    }
    if (pid > 0) {
        close(pair[1]);
        printf("ACTION inherit-scm parent connected-and-passing fd=%d\n", sock);
        fflush(stdout);
        int pass_rc = send_fd(pair[0], sock);
        // The parent gives its own copy away: from here on only the child
        // can use the capability.
        close(sock);
        int status = 0;
        waitpid(pid, &status, 0);
        printf("ACTION inherit-scm parent pass=%s\n", verdict(pass_rc == 0));
        return 0;
    }

    close(pair[0]);
    close(sock);
    int received = recv_fd(pair[1]);
    close(pair[1]);
    errno = 0;
    int use_rc = received >= 0 && send(received, "inherit-scm\n", 12, 0) == 12;
    int use_errno = use_rc ? 0 : errno;
    printf("ACTION inherit-scm child received=%d use=%s(%d)\n",
           received, verdict(use_rc), use_errno);
    fflush(stdout);
    _exit(0);
}
