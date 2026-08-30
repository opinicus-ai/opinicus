//
// kill-monitor — an attack on the monitor itself. Scenario evade-07.
//
// The technique reads its own TracerPid out of /proc/self/status and sends
// SIGKILL to the process that traces it — and only to that one, so the
// measurement never touches an unrelated firewall on the machine.
//
//   kill-monitor <marker-file>
//
// What happens afterwards is the finding: whether the attempt left any
// trace event, and whether the fail-closed machinery (PTRACE_O_EXITKILL)
// still killed the tree.
#define _GNU_SOURCE
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "usage: kill-monitor <marker-file>\n");
        return 2;
    }
    FILE *m = fopen(argv[1], "a");
    if (m) {
        fputs("before-kill\n", m);
        fclose(m);
    }
    int tracer = 0;
    FILE *s = fopen("/proc/self/status", "r");
    if (s) {
        char line[256];
        while (fgets(line, sizeof line, s)) {
            if (strncmp(line, "TracerPid:", 10) == 0) {
                tracer = atoi(line + 10);
                break;
            }
        }
        fclose(s);
    }
    if (tracer <= 0) {
        printf("ACTION kill-monitor blocked rc=no-tracer\n");
        return 0;
    }
    int r = kill((pid_t)tracer, SIGKILL);
    printf("ACTION kill-monitor %s rc=%d tracer=%d\n", r == 0 ? "ok" : "blocked", r, tracer);
    fflush(stdout);
    sleep(2);
    return 0;
}
