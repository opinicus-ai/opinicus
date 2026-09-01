//
// hostile-procmem — a /proc/<pid>/mem attack on the monitor from outside
// the tree. Ticket [af-12], review P1-6 / EXP-T2.
//
// The technique opens /proc/<monitor>/mem for read and write, reads one
// byte of the monitor and writes the same byte back, so a successful write
// proves the capability without changing anything. The open itself answers
// first: on a yama machine (ptrace_scope >= 1) it fails with EACCES/EPERM,
// and at ptrace_scope 0 the same-uid attacker holds the monitor's memory.
//
//   hostile-procmem <marker-path>
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#include "hostile-find.h"

/// Returns the start address of the first readable mapping of `pid`, or a
/// conventional fallback when the map cannot be read (see hostile-vmem.c).
static unsigned long first_mapped(pid_t pid) {
    char path[64];
    snprintf(path, sizeof path, "/proc/%d/maps", pid);
    FILE *maps = fopen(path, "r");
    if (!maps) {
        return 0x400000;
    }
    char line[512];
    unsigned long start = 0x400000;
    while (fgets(line, sizeof line, maps)) {
        if (strchr(line, 'r')) {
            start = strtoul(line, NULL, 16);
            break;
        }
    }
    fclose(maps);
    return start;
}

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "usage: hostile-procmem <marker-path>\n");
        return 2;
    }
    pid_t payload = 0;
    pid_t monitor = find_monitor(argv[1], &payload);
    if (monitor < 0) {
        printf("ACTION hostile-procmem no-payload rc=-1\n");
        return 0;
    }
    if (monitor == 0) {
        printf("ACTION hostile-procmem no-tracer payload=%d\n", payload);
        return 0;
    }
    printf("STEP hostile-procmem target monitor=%d payload=%d\n", monitor, payload);

    char path[64];
    snprintf(path, sizeof path, "/proc/%d/mem", monitor);
    int fd = open(path, O_RDWR);
    printf("ACTION hostile-procmem open rc=%d errno=%d (%s)\n", fd, errno, strerror(errno));
    if (fd < 0) {
        return 0;
    }

    unsigned long addr = first_mapped(monitor);
    unsigned char byte = 0;
    errno = 0;
    ssize_t rc = pread(fd, &byte, 1, (off_t)addr);
    printf("ACTION hostile-procmem pread addr=%#lx rc=%zd errno=%d (%s)\n", addr, rc, errno,
           strerror(errno));
    if (rc == 1) {
        errno = 0;
        rc = pwrite(fd, &byte, 1, (off_t)addr);
        printf("ACTION hostile-procmem pwrite addr=%#lx rc=%zd errno=%d (%s)\n", addr, rc,
               errno, strerror(errno));
    }
    close(fd);
    return 0;
}
