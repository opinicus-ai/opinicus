//
// outlive — a daemon that detaches with setsid and writes its marker long
// after the session root exited. Scenario behavior-03: detached jobs that
// outlive the session.
//
//   outlive <marker-file>
//
// The daemon sleeps 3 seconds, writes the marker and exits. The runner
// measures whether the firewall waits for it, whether the daemon completes,
// and whether anything in the trace records the detachment.
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "usage: outlive <marker-file>\n");
        return 2;
    }
    const char *marker = argv[1];
    pid_t pid = fork();
    if (pid < 0) {
        perror("fork");
        return 1;
    }
    if (pid > 0) {
        printf("ACTION daemon-started ok rc=0\n");
        fflush(stdout);
        return 0;
    }
    setsid();
    sleep(3);
    FILE *f = fopen(marker, "a");
    if (f) {
        fputs("outlived\n", f);
        fclose(f);
    }
    _exit(0);
}
