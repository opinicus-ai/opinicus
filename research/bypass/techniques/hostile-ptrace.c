//
// hostile-ptrace — a ptrace attack on the monitor from outside the tree.
// Ticket [af-12], review P1-6 / EXP-T2.
//
// The technique attaches to the monitor that traces the payload named by
// the marker, reads one word of the monitor's own program and writes the
// same word back through PTRACE_POKETEXT — a breakpoint-shaped write that
// changes nothing, so the measurement never corrupts the monitor it studies
// — and detaches. What the errno answers say is the finding: yama denies
// the attach at ptrace_scope >= 1, and at ptrace_scope 0 nothing does.
//
//   hostile-ptrace <marker-path>
#define _GNU_SOURCE
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "hostile-find.h"

/// Returns the start address of the first readable mapping of `pid`, or 0
/// when the map cannot be read. The address is only needed on the road the
/// kernel allows, and on that road the map is readable too.
static unsigned long first_mapped(pid_t pid) {
    char path[64];
    snprintf(path, sizeof path, "/proc/%d/maps", pid);
    FILE *maps = fopen(path, "r");
    if (!maps) {
        return 0;
    }
    char line[512];
    unsigned long start = 0;
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
        fprintf(stderr, "usage: hostile-ptrace <marker-path>\n");
        return 2;
    }
    pid_t payload = 0;
    pid_t monitor = find_monitor(argv[1], &payload);
    if (monitor < 0) {
        printf("ACTION hostile-ptrace no-payload rc=-1\n");
        return 0;
    }
    if (monitor == 0) {
        printf("ACTION hostile-ptrace no-tracer payload=%d\n", payload);
        return 0;
    }
    printf("STEP hostile-ptrace target monitor=%d payload=%d\n", monitor, payload);

    long rc = ptrace(PTRACE_ATTACH, monitor, NULL, NULL);
    printf("ACTION hostile-ptrace attach rc=%ld errno=%d (%s)\n", rc, errno,
           strerror(errno));
    if (rc != 0) {
        return 0;
    }
    if (waitpid(monitor, NULL, 0) < 0) {
        printf("ACTION hostile-ptrace wait rc=-1 errno=%d (%s)\n", errno, strerror(errno));
    }

    unsigned long addr = first_mapped(monitor);
    errno = 0;
    long word = ptrace(PTRACE_PEEKTEXT, monitor, (void *)addr, NULL);
    int peek_errno = errno;
    printf("ACTION hostile-ptrace peek addr=%#lx rc=%ld errno=%d (%s)\n", addr, word,
           peek_errno, strerror(peek_errno));
    if (peek_errno == 0 && addr != 0) {
        rc = ptrace(PTRACE_POKETEXT, monitor, (void *)addr, (void *)word);
        printf("ACTION hostile-ptrace poketext addr=%#lx rc=%ld errno=%d (%s)\n", addr, rc,
               errno, strerror(errno));
    }

    rc = ptrace(PTRACE_DETACH, monitor, NULL, NULL);
    printf("ACTION hostile-ptrace detach rc=%ld errno=%d (%s)\n", rc, errno, strerror(errno));
    return 0;
}
