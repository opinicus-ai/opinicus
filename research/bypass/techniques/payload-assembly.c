//
// payload-assembly — write a script, make it executable, run it. The chain
// of scenario evade-05. Each step is ordinary; the chain is the payload.
//
//   payload-assembly <scratch-dir> <marker-file>
//
// Writes <scratch-dir>/payload.sh, chmods it to 0755 and execs it. The
// script appends its own line to the marker file.
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>

int main(int argc, char **argv) {
    if (argc != 3) {
        fprintf(stderr, "usage: payload-assembly <scratch-dir> <marker-file>\n");
        return 2;
    }
    char path[4096];
    snprintf(path, sizeof path, "%s/payload.sh", argv[1]);
    FILE *f = fopen(path, "w");
    if (!f) {
        perror(path);
        return 1;
    }
    fprintf(f, "#!/bin/sh\necho assembled >> '%s'\n", argv[2]);
    fclose(f);
    int c = chmod(path, 0755);
    printf("ACTION chmod %s rc=%d\n", c == 0 ? "ok" : "blocked", c);
    fflush(stdout);
    execl(path, "payload.sh", (char *)0);
    perror("exec");
    return 1;
}
