//
// strip-preload — an attack on the in-process sensor of [af-2].
//
// The session runs with the LD_PRELOAD sensor installed by the harness. The
// technique starts a child whose environment carries no LD_PRELOAD at all,
// so the child runs with none of the sensor's semantics while the outside
// view keeps watching it. This is DIRECTION.md §6, "removing required
// preload configuration", and the M4 tamper fact `preload_stripped`.
//
//   strip-preload <marker-file>
//
// The child writes the marker, proving it ran. The measurement asks whether
// the firewall sensed the stripped configuration at the exec boundary.
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

extern char **environ;

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "usage: strip-preload <marker-file>\n");
        return 2;
    }

    // The kept environment: everything the launcher set, minus the preload
    // configuration of the sensor.
    size_t kept = 0;
    for (char **p = environ; *p; p++) {
        if (strncmp(*p, "LD_PRELOAD=", 11) != 0) {
            kept++;
        }
    }
    char **env = calloc(kept + 1, sizeof(char *));
    size_t at = 0;
    for (char **p = environ; *p; p++) {
        if (strncmp(*p, "LD_PRELOAD=", 11) != 0) {
            env[at++] = *p;
        }
    }

    char script[256];
    snprintf(script, sizeof script, "echo stripped-child >> %s", argv[1]);
    char *const child_argv[] = {"/bin/sh", "-c", script, NULL};
    execve("/bin/sh", child_argv, env);
    perror("execve");
    return 1;
}
