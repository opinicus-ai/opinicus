//
// sensor-unlink — an attack on the in-process sensor of [af-2].
//
// The technique deletes the sensor's library file from under a live session
// and then spawns children. The children inherit an environment that still
// names the preload — LD_PRELOAD is intact — and their programs need the
// dynamic linker, but the file the environment names is gone, so the linker
// skips it and no successor image ever loads the sensor. The outside view
// sees the spawns; the semantic view is dark from here on. This is
// DIRECTION.md §6, "removing monitoring libraries", and the discrepancy fact
// `spawn_seen_unreported` of [af-5].
//
//   sensor-unlink <sensor-library> <marker-file>
//
// The harness points LD_PRELOAD (and the session's sensor facts) at a copy
// of the library in the scratch directory, so the attack costs this run
// nothing else. The running instances keep working: a mapped library does
// not need its file, and their record keeps the deletion as evidence.
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

extern char **environ;

int main(int argc, char **argv) {
    if (argc != 3) {
        fprintf(stderr, "usage: sensor-unlink <sensor-library> <marker-file>\n");
        return 2;
    }

    // Remove the library the environment names. The unlink itself crosses
    // libc, so the live sensor reports its own deletion: the last honest
    // event of this subtree.
    if (unlink(argv[1]) != 0) {
        perror("unlink");
        return 1;
    }

    // Two children, both dynamic, both inheriting the intact LD_PRELOAD of
    // a deleted file. No successor image registers.
    for (int round = 0; round < 2; round++) {
        pid_t child = fork();
        if (child < 0) {
            perror("fork");
            return 1;
        }
        if (child == 0) {
            char script[256];
            snprintf(script, sizeof script, "echo unlinked-child >> %s", argv[2]);
            char *const child_argv[] = {"/bin/sh", "-c", script, NULL};
            execve("/bin/sh", child_argv, environ);
            _exit(127);
        }
        int status = 0;
        waitpid(child, &status, 0);
    }

    printf("unlink-done\n");
    return 0;
}
