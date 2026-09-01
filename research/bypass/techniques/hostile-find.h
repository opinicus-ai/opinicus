//
// hostile-find.h — the shared discovery step of the hostile same-UID
// techniques of [af-12] (review P1-6 / EXP-T2).
//
// Every hostile technique runs OUTSIDE the monitored tree, so it must find
// the monitor the way a real attacker would: scan /proc for the payload of
// the session — its command line names a marker that the harness planted —
// and read the TracerPid of that payload out of /proc/<pid>/status. The
// process behind that number is the monitor itself.
//
// The scan never touches a process whose command line does not name the
// marker, so a measurement cannot hit an unrelated firewall on the machine.
#ifndef HOSTILE_FIND_H
#define HOSTILE_FIND_H

#include <ctype.h>
#include <dirent.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

/// Returns the pid of the process that traces `pid`, or 0 when nothing
/// traces it.
static pid_t tracer_of(pid_t pid) {
    char path[64];
    snprintf(path, sizeof path, "/proc/%d/status", pid);
    FILE *status = fopen(path, "r");
    if (!status) {
        return 0;
    }
    char line[256];
    pid_t tracer = 0;
    while (fgets(line, sizeof line, status)) {
        if (strncmp(line, "TracerPid:", 10) == 0) {
            tracer = (pid_t)atoi(line + 10);
            break;
        }
    }
    fclose(status);
    return tracer;
}

/// Returns the pid of the one process whose command line names `marker`
/// and that a tracer holds, or -1 when no such process lives. `self` is
/// skipped, because the attacker's own command line names the marker too —
/// and so does the command line of the monitor, which carries the whole
/// payload command after `--`. The payload is the match that is traced;
/// `fallback` (unless NULL) receives the first untraced match, so a caller
/// can tell "no payload" from "a payload that nothing traces".
static pid_t find_payload(const char *marker, pid_t self, pid_t *fallback) {
    DIR *proc = opendir("/proc");
    if (!proc) {
        return -1;
    }
    struct dirent *entry;
    pid_t first_match = -1;
    while ((entry = readdir(proc)) != NULL) {
        if (!isdigit((unsigned char)entry->d_name[0])) {
            continue;
        }
        pid_t pid = (pid_t)atoi(entry->d_name);
        if (pid == self) {
            continue;
        }
        char path[64];
        snprintf(path, sizeof path, "/proc/%d/cmdline", pid);
        FILE *cmd = fopen(path, "r");
        if (!cmd) {
            continue;
        }
        char buf[4096];
        size_t len = fread(buf, 1, sizeof buf - 1, cmd);
        fclose(cmd);
        if (len == 0) {
            continue;
        }
        /* The command line is NUL-separated, so the search walks the whole
         * buffer and not one C string. */
        int named = 0;
        for (size_t i = 0; i + strlen(marker) <= len; i++) {
            if (memcmp(buf + i, marker, strlen(marker)) == 0) {
                named = 1;
                break;
            }
        }
        if (!named) {
            continue;
        }
        if (first_match < 0) {
            first_match = pid;
        }
        if (tracer_of(pid) != 0) {
            closedir(proc);
            return pid;
        }
    }
    closedir(proc);
    if (fallback) {
        *fallback = first_match;
    }
    return -1;
}

/// Returns the monitor that traces the payload named by `marker`, and —
/// unless it is NULL — the pid of that payload. The answer is -1 when no
/// payload lives, and 0 when the payload lives untraced (no monitor).
static pid_t find_monitor(const char *marker, pid_t *payload) {
    pid_t fallback = -1;
    pid_t found = find_payload(marker, getpid(), &fallback);
    if (payload) {
        *payload = found >= 0 ? found : fallback;
    }
    if (found < 0) {
        return -1;
    }
    return tracer_of(found);
}

#endif
