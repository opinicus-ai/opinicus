/*
 * procpoll.c - a supervisor that finds descendants by polling /proc.
 *
 * It runs a command, and at a fixed period it reads /proc/<pid>/stat for
 * every process on the machine. It rebuilds the parent-child tree from the
 * ppid field, and it records every process that is a descendant of the
 * command.
 *
 * A process that starts and ends between two polls is never in a snapshot.
 * The tool therefore measures the coverage of the mechanism, and not only
 * its speed.
 *
 * Usage:
 *   procpoll --period-ms 10 [--log FILE] [--summary FILE] -- CMD [ARG...]
 */
#define _GNU_SOURCE

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

/* The machine has a few hundred processes. This is a generous limit. */
#define MAX_SNAPSHOT 32768
/* A power of two, so that the mask works. */
#define SEEN_SLOTS 65536

struct snapshot_entry {
    int pid;
    int ppid;
    unsigned long long starttime;
    char comm[32];
};

struct seen_entry {
    int pid;
    unsigned long long starttime;
    int used;
};

static struct snapshot_entry snapshot[MAX_SNAPSHOT];
static unsigned char is_descendant[MAX_SNAPSHOT];
static struct seen_entry seen[SEEN_SLOTS];

static int snapshot_count;
static int seen_count;
static unsigned long long poll_count;
static FILE *log_file;

static unsigned long long now_ns(void)
{
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (unsigned long long)ts.tv_sec * 1000000000ULL +
           (unsigned long long)ts.tv_nsec;
}

/* Adds a process to the set of processes that the poller saw.
 * The key is the pid together with the start time, so that a reused pid
 * counts as a new process. Returns 1 when the process is new. */
static int remember(int pid, unsigned long long starttime, const char *comm)
{
    unsigned int slot;
    unsigned int step;

    slot = ((unsigned int)pid * 2654435761u) & (SEEN_SLOTS - 1);
    for (step = 0; step < SEEN_SLOTS; step++) {
        struct seen_entry *entry = &seen[(slot + step) & (SEEN_SLOTS - 1)];

        if (!entry->used) {
            entry->used = 1;
            entry->pid = pid;
            entry->starttime = starttime;
            seen_count++;
            if (log_file) {
                fprintf(log_file, "seen pid=%d starttime=%llu comm=%s\n", pid,
                        starttime, comm);
            }
            return 1;
        }
        if (entry->pid == pid && entry->starttime == starttime) {
            return 0;
        }
    }
    return 0;
}

/* Reads one /proc/<pid>/stat file and fills one snapshot entry. */
static int read_stat(int pid, struct snapshot_entry *out)
{
    char path[64];
    char buffer[2048];
    char *open_paren;
    char *close_paren;
    char state;
    int ppid;
    int pgrp;
    int session;
    int tty_nr;
    int tpgid;
    unsigned int flags;
    unsigned long minflt;
    unsigned long cminflt;
    unsigned long majflt;
    unsigned long cmajflt;
    unsigned long utime;
    unsigned long stime;
    long cutime;
    long cstime;
    long priority;
    long nice;
    long threads;
    long itreal;
    unsigned long long starttime;
    ssize_t length;
    size_t comm_length;
    int fd;

    snprintf(path, sizeof(path), "/proc/%d/stat", pid);
    fd = open(path, O_RDONLY);
    if (fd < 0) {
        return 0;
    }
    length = read(fd, buffer, sizeof(buffer) - 1);
    close(fd);
    if (length <= 0) {
        return 0;
    }
    buffer[length] = '\0';

    open_paren = strchr(buffer, '(');
    close_paren = strrchr(buffer, ')');
    if (!open_paren || !close_paren || close_paren < open_paren) {
        return 0;
    }

    if (sscanf(close_paren + 2,
               "%c %d %d %d %d %d %u %lu %lu %lu %lu %lu %lu %ld %ld %ld %ld "
               "%ld %ld %llu",
               &state, &ppid, &pgrp, &session, &tty_nr, &tpgid, &flags,
               &minflt, &cminflt, &majflt, &cmajflt, &utime, &stime, &cutime,
               &cstime, &priority, &nice, &threads, &itreal,
               &starttime) != 20) {
        return 0;
    }

    comm_length = (size_t)(close_paren - open_paren - 1);
    if (comm_length >= sizeof(out->comm)) {
        comm_length = sizeof(out->comm) - 1;
    }
    memcpy(out->comm, open_paren + 1, comm_length);
    out->comm[comm_length] = '\0';
    out->pid = pid;
    out->ppid = ppid;
    out->starttime = starttime;
    return 1;
}

/* Reads every numeric directory of /proc into the snapshot array. */
static void take_snapshot(void)
{
    DIR *dir;
    struct dirent *entry;

    snapshot_count = 0;
    dir = opendir("/proc");
    if (!dir) {
        return;
    }
    while ((entry = readdir(dir)) != NULL) {
        int pid;
        const char *name = entry->d_name;
        size_t index;

        if (!isdigit((unsigned char)name[0])) {
            continue;
        }
        for (index = 0; name[index]; index++) {
            if (!isdigit((unsigned char)name[index])) {
                break;
            }
        }
        if (name[index] != '\0') {
            continue;
        }
        pid = atoi(name);
        if (snapshot_count >= MAX_SNAPSHOT) {
            break;
        }
        if (read_stat(pid, &snapshot[snapshot_count])) {
            snapshot_count++;
        }
    }
    closedir(dir);
    poll_count++;
}

/* Marks the root and every process below it, then remembers them. */
static void collect_descendants(int root)
{
    int index;
    int changed;

    memset(is_descendant, 0, (size_t)snapshot_count);
    for (index = 0; index < snapshot_count; index++) {
        if (snapshot[index].pid == root) {
            is_descendant[index] = 1;
        }
    }

    /* The parent of a process can appear after the process in the array,
     * so the loop runs until nothing changes. */
    do {
        changed = 0;
        for (index = 0; index < snapshot_count; index++) {
            int parent;

            if (is_descendant[index]) {
                continue;
            }
            for (parent = 0; parent < snapshot_count; parent++) {
                if (snapshot[parent].pid == snapshot[index].ppid &&
                    is_descendant[parent]) {
                    is_descendant[index] = 1;
                    changed = 1;
                    break;
                }
            }
        }
    } while (changed);

    for (index = 0; index < snapshot_count; index++) {
        if (is_descendant[index]) {
            remember(snapshot[index].pid, snapshot[index].starttime,
                     snapshot[index].comm);
        }
    }
}

int main(int argc, char **argv)
{
    long period_ms = 10;
    const char *log_path = NULL;
    const char *summary_path = NULL;
    char **command = NULL;
    int index;
    pid_t child;
    int status = 0;
    struct timespec sleep_time;
    struct rusage usage;
    sigset_t child_signals;
    sigset_t saved_signals;
    unsigned long long start_ns;
    unsigned long long end_ns;
    double self_cpu_ms;
    FILE *summary;

    for (index = 1; index < argc; index++) {
        if (strcmp(argv[index], "--period-ms") == 0 && index + 1 < argc) {
            period_ms = atol(argv[++index]);
        } else if (strcmp(argv[index], "--log") == 0 && index + 1 < argc) {
            log_path = argv[++index];
        } else if (strcmp(argv[index], "--summary") == 0 && index + 1 < argc) {
            summary_path = argv[++index];
        } else if (strcmp(argv[index], "--") == 0) {
            command = &argv[index + 1];
            break;
        } else {
            fprintf(stderr, "procpoll: unknown option %s\n", argv[index]);
            return 2;
        }
    }
    if (!command || !command[0]) {
        fprintf(stderr, "usage: procpoll --period-ms N [--log F] "
                        "[--summary F] -- CMD [ARG...]\n");
        return 2;
    }

    if (log_path) {
        log_file = fopen(log_path, "w");
        if (!log_file) {
            fprintf(stderr, "procpoll: cannot write %s\n", log_path);
            return 2;
        }
    }

    start_ns = now_ns();

    /* The supervisor waits for the end of the child with sigtimedwait, and
     * not with a sleep. Without this, the wall-clock time of a short run is
     * the poll period and not the cost of the polling, because the supervisor
     * would learn about the exit only at the next poll. */
    sigemptyset(&child_signals);
    sigaddset(&child_signals, SIGCHLD);
    sigprocmask(SIG_BLOCK, &child_signals, &saved_signals);

    child = fork();
    if (child < 0) {
        perror("fork");
        return 2;
    }
    if (child == 0) {
        sigprocmask(SIG_SETMASK, &saved_signals, NULL);
        execvp(command[0], command);
        _exit(127);
    }

    sleep_time.tv_sec = period_ms / 1000;
    sleep_time.tv_nsec = (period_ms % 1000) * 1000000L;

    for (;;) {
        int signal_number;

        take_snapshot();
        collect_descendants((int)child);

        signal_number = sigtimedwait(&child_signals, NULL, &sleep_time);
        if (signal_number == SIGCHLD) {
            if (waitpid(child, &status, WNOHANG) == child) {
                /* One last poll, so that a process that lives at the end of
                 * the run still has a chance to appear. */
                take_snapshot();
                collect_descendants((int)child);
                break;
            }
            continue;
        }
        if (signal_number < 0 && errno != EAGAIN && errno != EINTR) {
            break;
        }
        if (waitpid(child, &status, WNOHANG) == child) {
            take_snapshot();
            collect_descendants((int)child);
            break;
        }
    }
    end_ns = now_ns();

    getrusage(RUSAGE_SELF, &usage);
    self_cpu_ms = (double)usage.ru_utime.tv_sec * 1000.0 +
                  (double)usage.ru_utime.tv_usec / 1000.0 +
                  (double)usage.ru_stime.tv_sec * 1000.0 +
                  (double)usage.ru_stime.tv_usec / 1000.0;

    if (log_file) {
        fclose(log_file);
    }

    summary = stderr;
    if (summary_path) {
        FILE *file = fopen(summary_path, "w");

        if (file) {
            summary = file;
        }
    }
    fprintf(summary,
            "procpoll period_ms=%ld polls=%llu seen_processes=%d "
            "self_cpu_ms=%.1f wall_ms=%.1f\n",
            period_ms, poll_count, seen_count, self_cpu_ms,
            (double)(end_ns - start_ns) / 1000000.0);
    if (summary != stderr) {
        fclose(summary);
    }

    if (WIFEXITED(status)) {
        return WEXITSTATUS(status);
    }
    return 1;
}
