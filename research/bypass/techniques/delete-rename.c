//
// delete-rename — removal and renaming through libc calls that no sensor
// watches. There is no delete or rename event kind in the schema, and the
// kernel filter holds only open, creat and connect. Scenarios fs-12, fs-05,
// fs-07: the tree is destroyed without a single delete command.
//
//   delete-rename <scratch-dir> <marker-file>
//
// Creates <scratch-dir>/victim/f, unlinks f, renames victim to moved.
// Effect verified by the runner: moved exists, victim/f is gone.
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>

int main(int argc, char **argv) {
    if (argc != 3) {
        fprintf(stderr, "usage: delete-rename <scratch-dir> <marker-file>\n");
        return 2;
    }
    char path[2048], moved[2048];
    snprintf(path, sizeof path, "%s/victim", argv[1]);
    snprintf(moved, sizeof moved, "%s/moved", argv[1]);
    mkdir(path, 0755);
    char file[2052];
    snprintf(file, sizeof file, "%s/f", path);
    FILE *f = fopen(file, "w");
    if (f) {
        fputs("data", f);
        fclose(f);
    }
    int u = unlink(file);
    int r = rename(path, moved);
    printf("ACTION delete-rename %s rc=%d,%d\n", (u == 0 && r == 0) ? "ok" : "failed", u, r);
    FILE *m = fopen(argv[2], "a");
    if (m) {
        fputs("deleted\n", m);
        fclose(m);
    }
    return 0;
}
