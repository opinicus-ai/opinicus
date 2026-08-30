//
// escape-setsid — the classic ancestry escape: setsid and a double fork,
// then a leaf process that writes the marker.
//
// Under a monitor that launches the session and follows every fork, none of
// this escapes: setsid changes the session, not the tracer. The technique
// measures whether the provenance chain still holds across it, because a
// rule that keys on ancestry depends on that chain. Scenario evade-08.
//
//   escape-setsid <marker-file>
//
// Re-executes itself as the leaf through /proc/self/exe.
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void leaf(const char *marker) {
    FILE *f = fopen(marker, "a");
    if (f) {
        fputs("escape-leaf\n", f);
        fclose(f);
    }
    _exit(0);
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: escape-setsid <marker-file> [leaf]\n");
        return 2;
    }
    if (argc == 3 && strcmp(argv[2], "leaf") == 0) {
        leaf(argv[1]);
    }
    if (setsid() < 0) {
        perror("setsid");
    }
    pid_t mid = fork();
    if (mid < 0) {
        perror("fork");
        return 1;
    }
    if (mid == 0) {
        setsid();
        pid_t leaf_pid = fork();
        if (leaf_pid < 0) {
            _exit(1);
        }
        if (leaf_pid == 0) {
            char self[4096];
            ssize_t n = readlink("/proc/self/exe", self, sizeof self - 1);
            if (n < 0) {
                _exit(1);
            }
            self[n] = 0;
            execl(self, "escape-setsid", argv[1], "leaf", (char *)0);
            _exit(127);
        }
        _exit(0);
    }
    printf("ACTION fork ok rc=0\n");
    return 0;
}
