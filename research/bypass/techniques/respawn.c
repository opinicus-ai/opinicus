//
// respawn — the killed subtree that comes back.
//
// A parent runs a program that the firewall denies; the monitor kills it at
// the exec stop, before it runs one instruction. The parent answers the
// refusal by starting the same program again, which is the B.6 liveness fact
// `killed_subtree_returned`: the thing the firewall killed came back under
// the same parent.
//
//   respawn <count>
//
// The technique needs a program the built-in pack denies. It writes to
// /etc/ld.so.preload through the shell, which `process.system.disable-
// protection` refuses, so no real file of the machine changes: the firewall
// stops every attempt, and the technique counts them.
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <unistd.h>

int main(int argc, char **argv) {
    int rounds = argc == 2 ? atoi(argv[1]) : 3;
    int refused = 0;
    for (int round = 0; round < rounds; round++) {
        pid_t child = fork();
        if (child == 0) {
            // The denied command: a write to the preload list of the loader.
            // Under the firewall it never runs; outside the firewall it also
            // fails, because the file belongs to root. Either way nothing
            // changes on the machine.
            execl("/bin/sh", "sh", "-c",
                  "echo /var/tmp/hook.so > /etc/ld.so.preload", (char *)0);
            _exit(111);
        }
        int status = 0;
        waitpid(child, &status, 0);
        if (WIFEXITED(status) && WEXITSTATUS(status) != 0) {
            refused++;
        }
    }
    printf("ACTION respawn refused=%d of %d\n", refused, rounds);
    return 0;
}
