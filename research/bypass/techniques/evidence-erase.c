//
// evidence-erase — the audit-trail attacks of [af-9] (SC evade-25).
//
// One tool, three verbs, so every case of research/bypass/evidence.sh runs
// the same payload shape against one of the firewall's own evidence files:
//
//   evidence-erase open-trunc <path>    open O_WRONLY|O_TRUNC, forge a line
//   evidence-erase open-append <path>   open O_APPEND, forge a line
//   evidence-erase unlink <path>        unlink the file
//
// The finding of each case is what the firewall did — prevented (the open
// was refused, the file is intact), sensed (the action ran, the trace holds
// the report), or a silent gap (no event covers the loss). The technique
// reports its own outcome on stdout, and the harness verifies the effect
// from the file system, which is the truth the attacker cares about.
//
// The unlink verb exists to measure the named gap, not to succeed: the
// kernel filter holds no unlink (crates/af-monitor/src/seccomp.rs), so the
// technique proves what a same-UID process of the tree can still destroy
// before any sensing exists.
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static const char FORGED[] = "{\"seq\":1,\"type\":\"session_start\",\"note\":\"FORGED-BY-SESSION\"}\n";

int main(int argc, char **argv) {
    if (argc != 3) {
        fprintf(stderr, "usage: evidence-erase open-trunc|open-append|unlink <path>\n");
        return 2;
    }
    const char *verb = argv[1];
    const char *path = argv[2];

    if (strcmp(verb, "unlink") == 0) {
        int r = unlink(path);
        printf("ACTION evidence-erase unlink %s rc=%d\n", r == 0 ? "ok" : "blocked", r);
        return 0;
    }

    int flags;
    if (strcmp(verb, "open-trunc") == 0) {
        flags = O_WRONLY | O_TRUNC;
    } else if (strcmp(verb, "open-append") == 0) {
        flags = O_WRONLY | O_APPEND;
    } else {
        fprintf(stderr, "usage: evidence-erase open-trunc|open-append|unlink <path>\n");
        return 2;
    }

    int fd = open(path, flags);
    if (fd < 0) {
        // EPERM (1) is the firewall refusing the call before it runs; that
        // is the "prevented" outcome, not a failure of the technique.
        int saved = errno;
        printf("ACTION evidence-erase %s blocked errno=%d\n", verb, saved);
        return 0;
    }
    ssize_t w = write(fd, FORGED, sizeof FORGED - 1);
    close(fd);
    printf("ACTION evidence-erase %s %s wrote=%zd\n", verb, w > 0 ? "ok" : "short", w);
    return 0;
}
