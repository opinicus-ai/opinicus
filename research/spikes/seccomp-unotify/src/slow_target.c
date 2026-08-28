/*
 * slow-target - a target that opens files one after the other, with a mark
 * on standard output after each open.
 *
 * The failure tests use it. The marks show exactly how far the target came
 * before the supervisor became slow, or died, or stopped answering.
 *
 * Usage:
 *   slow-target --dir DIR --files N [--pidfile FILE] [--gap-ms M]
 *               [--alarm-ms N]   the process kills itself after N ms
 *
 * Each line on standard output is:
 *   open <index> rc=<fd or -1> errno=<n> elapsed_ms=<n>
 */

#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

static volatile sig_atomic_t g_alarms;

static void on_alarm(int sig)
{
    (void)sig;
    g_alarms++;
}

static long now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

int main(int argc, char **argv)
{
    const char *dir = NULL;
    const char *pidfile = NULL;
    long files = 5;
    long gap_ms = 0;
    long alarm_ms = 0;
    int alarm_handler = 0;
    int alarm_restart = 0;

    for (int i = 1; i < argc; i++) {
        if (strncmp(argv[i], "--dir=", 6) == 0) {
            dir = argv[i] + 6;
        } else if (strncmp(argv[i], "--pidfile=", 10) == 0) {
            pidfile = argv[i] + 10;
        } else if (strncmp(argv[i], "--files=", 8) == 0) {
            files = atol(argv[i] + 8);
        } else if (strncmp(argv[i], "--gap-ms=", 9) == 0) {
            gap_ms = atol(argv[i] + 9);
        } else if (strncmp(argv[i], "--alarm-ms=", 11) == 0) {
            alarm_ms = atol(argv[i] + 11);
        } else if (strcmp(argv[i], "--alarm-handler") == 0) {
            alarm_handler = 1;
        } else if (strcmp(argv[i], "--alarm-restart") == 0) {
            alarm_handler = 1;
            alarm_restart = 1;
        } else {
            fprintf(stderr, "slow-target: bad option %s\n", argv[i]);
            return 2;
        }
    }
    if (dir == NULL) {
        fprintf(stderr, "usage: slow-target --dir=DIR [--files=N] "
                        "[--pidfile=FILE] [--gap-ms=M] [--alarm-ms=N]\n");
        return 2;
    }

    setvbuf(stdout, NULL, _IONBF, 0);

    if (pidfile != NULL) {
        FILE *pf = fopen(pidfile, "w");
        if (pf != NULL) {
            fprintf(pf, "%d\n", (int)getpid());
            fclose(pf);
        }
        /* The mark tells the test that the pid file is complete and that
         * the interesting opens start now. */
        printf("ready pid=%d\n", (int)getpid());
    }

    /*
     * The timer ends the process while it waits for the answer of the
     * supervisor. SIGALRM has no handler, so the default action kills the
     * process. This gives a target that dies inside a notification without
     * any help from outside.
     */
    if (alarm_handler) {
        /* A handler makes the signal harmless. The system call that waits
         * for the supervisor is then interrupted and started again. */
        struct sigaction sa;
        memset(&sa, 0, sizeof(sa));
        sa.sa_handler = on_alarm;
        if (alarm_restart) {
            sa.sa_flags = SA_RESTART;
        }
        sigaction(SIGALRM, &sa, NULL);
    }

    if (alarm_ms > 0) {
        struct itimerval it;
        memset(&it, 0, sizeof(it));
        it.it_value.tv_sec = alarm_ms / 1000;
        it.it_value.tv_usec = (alarm_ms % 1000) * 1000;
        setitimer(ITIMER_REAL, &it, NULL);
    }

    char path[4096];
    for (long i = 0; i < files; i++) {
        snprintf(path, sizeof(path), "%s/hold-me-%ld.txt", dir, i);
        long start = now_ms();
        int fd = open(path, O_RDONLY);
        int err = errno;
        printf("open %ld rc=%d errno=%d elapsed_ms=%ld\n", i, fd, fd < 0 ? err : 0,
               now_ms() - start);
        if (fd >= 0) {
            close(fd);
        }
        if (gap_ms > 0) {
            struct timespec ts = { gap_ms / 1000, (gap_ms % 1000) * 1000000 };
            nanosleep(&ts, NULL);
        }
    }
    printf("done alarms=%d\n", (int)g_alarms);
    return 0;
}
