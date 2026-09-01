//
// hostile-vmem — a process_vm_writev attack on the monitor from outside
// the tree. Ticket [af-12], review P1-6 / EXP-T2.
//
// The technique reads one byte of the monitor's memory with
// process_vm_readv and writes the same byte back with process_vm_writev,
// so a successful write proves the capability without changing anything.
// The errno answers separate the two worlds: EPERM is yama denying the
// access (ptrace_scope >= 1), and a number at ptrace_scope 0 means the
// same-uid attacker can rewrite the monitor.
//
//   hostile-vmem <marker-path>
#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>

#include "hostile-find.h"

#ifndef SYS_process_vm_readv
#define SYS_process_vm_readv 310
#endif
#ifndef SYS_process_vm_writev
#define SYS_process_vm_writev 311
#endif

/// Returns the start address of an anonymous writable mapping of `pid` —
/// the heap when there is one — or a conventional fallback. On this
/// kernel `process_vm_writev` answers EFAULT for a file-backed private
/// page and refuses read-only pages outright, so the write test needs an
/// anonymous mapping the target itself writes. A denied access answers
/// EPERM before the address is ever used, so the fallback only names the
/// road the kernel refused.
static unsigned long first_writable(pid_t pid) {
    char path[64];
    snprintf(path, sizeof path, "/proc/%d/maps", pid);
    FILE *maps = fopen(path, "r");
    if (!maps) {
        return 0x400000;
    }
    char line[512];
    unsigned long start = 0x400000;
    while (fgets(line, sizeof line, maps)) {
        if (!strchr(line, 'r') || !strchr(line, 'w') || strchr(line, '/')) {
            continue;
        }
        start = strtoul(line, NULL, 16);
        if (strstr(line, "[heap]")) {
            break;
        }
    }
    fclose(maps);
    return start;
}

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "usage: hostile-vmem <marker-path>\n");
        return 2;
    }
    pid_t payload = 0;
    pid_t monitor = find_monitor(argv[1], &payload);
    if (monitor < 0) {
        printf("ACTION hostile-vmem no-payload rc=-1\n");
        return 0;
    }
    if (monitor == 0) {
        printf("ACTION hostile-vmem no-tracer payload=%d\n", payload);
        return 0;
    }
    printf("STEP hostile-vmem target monitor=%d payload=%d\n", monitor, payload);

    unsigned long addr = first_writable(monitor);
    unsigned char byte = 0;
    struct iovec local = { &byte, 1 };
    struct iovec remote = { (void *)addr, 1 };
    errno = 0;
    ssize_t rc = syscall(SYS_process_vm_readv, monitor, &local, 1UL, &remote, 1UL, 0UL);
    printf("ACTION hostile-vmem readv addr=%#lx rc=%zd errno=%d (%s)\n", addr, rc, errno,
           strerror(errno));
    /* The write happens whatever the read said: a refusal must name the
     * access check (EPERM), not the address, so the matrix reads the
     * kernel's own answer for both sides of the route. */
    errno = 0;
    rc = syscall(SYS_process_vm_writev, monitor, &local, 1UL, &remote, 1UL, 0UL);
    printf("ACTION hostile-vmem writev addr=%#lx rc=%zd errno=%d (%s)\n", addr, rc, errno,
           strerror(errno));
    return 0;
}
