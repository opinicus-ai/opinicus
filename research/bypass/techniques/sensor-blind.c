//
// sensor-blind — an attack on the in-process sensor of [af-2].
//
// The technique closes every file descriptor above the standard three, which
// takes the sensor's trace and its registration record away while the
// process lives on. The instance has proved it talks (an event and a
// heartbeat), then goes dark: no events, no heartbeats, no exit line, while
// the kernel filter of the product still holds its write opens. This raises
// two discrepancy facts of [af-5]: `sensor_silent_subtree` (quiet while the
// process lives) and `action_contradicted` (the external view holds an open
// that the sensor of the acting process never reported).
//
//   sensor-blind <marker-file>
//
// The final open is libc on purpose: it must cross the kernel filter and
// cross libc's absence at the same time, which is the contradiction.
#define _GNU_SOURCE
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "usage: sensor-blind <marker-file>\n");
        return 2;
    }

    // One hooked open, so the instance emits an event and starts its
    // heartbeat thread; then idle long enough for a heartbeat to land.
    int fd = open(argv[1], O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (fd < 0) {
        perror("open");
        return 1;
    }
    close(fd);
    sleep(2);

    // The blinding. The sensor moves its trace and registration record to
    // descriptors near 900 with close-on-exec (a hardening of the M2 spike:
    // the plumbing must not collide with a descriptor the program expects),
    // so the sweep has to cover the whole range a program can hold. Closing
    // them takes both outputs away without touching the library: the hooks
    // stay, but they can report nowhere.
    for (int d = 3; d < 1024; d++) {
        close(d);
    }

    // Live on past the correlation window with the sensor dark.
    sleep(5);

    // A write through libc: the kernel filter holds it, the sensor cannot
    // report it. The contradiction, measured.
    fd = open(argv[1], O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (fd >= 0) {
        if (write(fd, "blinded-write\n", 14) < 0) {
            fprintf(stderr, "write failed\n");
        }
        close(fd);
    }
    printf("blind-done\n");
    return 0;
}
