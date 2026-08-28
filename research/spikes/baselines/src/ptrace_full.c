/*
 * ptrace_full.c - a minimal tracer that stops the target at every system
 * call, and a second mode that stops it only at process events.
 *
 * Mode "syscall" uses PTRACE_SYSCALL. The kernel stops the tracee two times
 * for every system call, once before and once after. This is the highest
 * coverage that an unprivileged process can get, and the highest cost.
 *
 * Mode "events" uses PTRACE_CONT with the fork, clone, vfork and exec
 * options. It is the shape of the shipping monitor. This spike uses it to
 * make a race-free count of the processes, so that the /proc poller has a
 * ground truth to compare against.
 *
 * With --deny the tracer does not only watch. At the entry stop it replaces
 * the system call number with a number that does not exist, so the kernel
 * never runs the call, and at the exit stop it sets the result to EACCES.
 * This shows that a system call monitor can block and not only observe.
 *
 * Usage:
 *   ptrace_full [--mode syscall|events] [--summary FILE] [--histogram FILE]
 *               [--deny NAME,NAME] -- CMD [ARG...]
 */
#define _GNU_SOURCE

#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define TRACEE_SLOTS 8192
#define SYSCALL_NUMBERS 1024

struct tracee {
    pid_t pid;
    int in_syscall;
    int denied;
    int used;
};

/* The calls that --deny understands. The number is the x86_64 number, the
 * same number that /usr/include/asm/unistd_64.h gives. */
struct syscall_name {
    const char *name;
    int number;
};

static const struct syscall_name known_calls[] = {
    { "read", 0 },      { "write", 1 },     { "open", 2 },
    { "close", 3 },     { "socket", 41 },   { "connect", 42 },
    { "execve", 59 },   { "rmdir", 84 },    { "unlink", 87 },
    { "openat", 257 },  { "unlinkat", 263 }, { NULL, 0 },
};

static int deny_numbers[32];
static int deny_count;
static unsigned long long denied_calls;

static struct tracee tracees[TRACEE_SLOTS];
static unsigned long long histogram[SYSCALL_NUMBERS];
static unsigned long long syscall_stops;
static unsigned long long syscalls_entered;
static unsigned long long event_forks;
static unsigned long long event_execs;
static unsigned long long event_exits;
static int distinct_processes;

static struct tracee *find_tracee(pid_t pid, int create)
{
    unsigned int slot = ((unsigned int)pid * 2654435761u) & (TRACEE_SLOTS - 1);
    unsigned int step;

    for (step = 0; step < TRACEE_SLOTS; step++) {
        struct tracee *entry = &tracees[(slot + step) & (TRACEE_SLOTS - 1)];

        if (entry->used && entry->pid == pid) {
            return entry;
        }
        if (!entry->used) {
            if (!create) {
                return NULL;
            }
            entry->used = 1;
            entry->pid = pid;
            entry->in_syscall = 0;
            entry->denied = 0;
            distinct_processes++;
            return entry;
        }
    }
    return NULL;
}

/* Reads a comma-separated list of names into the deny table. */
static int parse_deny_list(char *text)
{
    char *token = strtok(text, ",");

    while (token) {
        int index;
        int found = 0;

        for (index = 0; known_calls[index].name; index++) {
            if (strcmp(known_calls[index].name, token) == 0) {
                if (deny_count <
                    (int)(sizeof(deny_numbers) / sizeof(deny_numbers[0]))) {
                    deny_numbers[deny_count++] = known_calls[index].number;
                }
                found = 1;
                break;
            }
        }
        if (!found) {
            fprintf(stderr, "ptrace_full: unknown call name %s\n", token);
            return -1;
        }
        token = strtok(NULL, ",");
    }
    return 0;
}

static int is_denied(unsigned long long number)
{
    int index;

    for (index = 0; index < deny_count; index++) {
        if ((unsigned long long)deny_numbers[index] == number) {
            return 1;
        }
    }
    return 0;
}

static unsigned long long now_ns(void)
{
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (unsigned long long)ts.tv_sec * 1000000000ULL +
           (unsigned long long)ts.tv_nsec;
}

int main(int argc, char **argv)
{
    int syscall_mode = 1;
    const char *summary_path = NULL;
    const char *histogram_path = NULL;
    char **command = NULL;
    int index;
    pid_t root;
    int root_status = 0;
    int root_done = 0;
    long options;
    enum __ptrace_request restart;
    unsigned long long start_ns;
    unsigned long long end_ns;
    FILE *summary;

    for (index = 1; index < argc; index++) {
        if (strcmp(argv[index], "--mode") == 0 && index + 1 < argc) {
            index++;
            if (strcmp(argv[index], "events") == 0) {
                syscall_mode = 0;
            } else if (strcmp(argv[index], "syscall") == 0) {
                syscall_mode = 1;
            } else {
                fprintf(stderr, "ptrace_full: unknown mode %s\n", argv[index]);
                return 2;
            }
        } else if (strcmp(argv[index], "--summary") == 0 && index + 1 < argc) {
            summary_path = argv[++index];
        } else if (strcmp(argv[index], "--histogram") == 0 &&
                   index + 1 < argc) {
            histogram_path = argv[++index];
        } else if (strcmp(argv[index], "--deny") == 0 && index + 1 < argc) {
            if (parse_deny_list(argv[++index]) < 0) {
                return 2;
            }
        } else if (strcmp(argv[index], "--") == 0) {
            command = &argv[index + 1];
            break;
        } else {
            fprintf(stderr, "ptrace_full: unknown option %s\n", argv[index]);
            return 2;
        }
    }
    if (!command || !command[0]) {
        fprintf(stderr,
                "usage: ptrace_full [--mode syscall|events] [--summary F] "
                "[--histogram F] [--deny NAME,NAME] -- CMD [ARG...]\n");
        return 2;
    }

    start_ns = now_ns();
    root = fork();
    if (root < 0) {
        perror("fork");
        return 2;
    }
    if (root == 0) {
        /* The child asks to be traced and then loads the program. The kernel
         * stops it after the load, before the first instruction runs. */
        if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) < 0) {
            _exit(126);
        }
        execvp(command[0], command);
        _exit(127);
    }

    /* The first stop is the exec stop of the root process. */
    if (waitpid(root, &root_status, 0) < 0) {
        perror("waitpid");
        return 2;
    }
    find_tracee(root, 1);

    options = PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK | PTRACE_O_TRACECLONE |
              PTRACE_O_TRACEEXEC | PTRACE_O_TRACEEXIT | PTRACE_O_EXITKILL;
    if (syscall_mode) {
        options |= PTRACE_O_TRACESYSGOOD;
        restart = PTRACE_SYSCALL;
    } else {
        restart = PTRACE_CONT;
    }
    if (ptrace(PTRACE_SETOPTIONS, root, NULL, (void *)options) < 0) {
        perror("PTRACE_SETOPTIONS");
        return 2;
    }
    ptrace(restart, root, NULL, NULL);

    for (;;) {
        int status;
        pid_t pid;
        int signal_number;
        int event;
        int deliver = 0;

        pid = waitpid(-1, &status, __WALL);
        if (pid < 0) {
            if (errno == EINTR) {
                continue;
            }
            break;
        }

        if (WIFEXITED(status) || WIFSIGNALED(status)) {
            if (pid == root) {
                root_status = status;
                root_done = 1;
            }
            continue;
        }
        if (!WIFSTOPPED(status)) {
            continue;
        }

        signal_number = WSTOPSIG(status);
        event = status >> 16;

        if (!find_tracee(pid, 0)) {
            /* A new child can stop before the event of its parent arrives. */
            find_tracee(pid, 1);
            ptrace(PTRACE_SETOPTIONS, pid, NULL, (void *)options);
            ptrace(restart, pid, NULL, NULL);
            continue;
        }

        if (syscall_mode && signal_number == (SIGTRAP | 0x80)) {
            struct tracee *entry = find_tracee(pid, 1);

            syscall_stops++;
            if (entry && !entry->in_syscall) {
                struct user_regs_struct regs;

                entry->in_syscall = 1;
                entry->denied = 0;
                syscalls_entered++;
                if (ptrace(PTRACE_GETREGS, pid, NULL, &regs) == 0) {
                    unsigned long long number =
                        (unsigned long long)regs.orig_rax;

                    if (number < SYSCALL_NUMBERS) {
                        histogram[number]++;
                    }
                    if (deny_count && is_denied(number)) {
                        /* The kernel reads orig_rax after the entry stop. A
                         * number that does not exist makes the kernel skip
                         * the call. The exit stop then sets the error. */
                        regs.orig_rax = (unsigned long long)-1;
                        ptrace(PTRACE_SETREGS, pid, NULL, &regs);
                        entry->denied = 1;
                        denied_calls++;
                    }
                }
            } else if (entry) {
                entry->in_syscall = 0;
                if (entry->denied) {
                    struct user_regs_struct regs;

                    if (ptrace(PTRACE_GETREGS, pid, NULL, &regs) == 0) {
                        regs.rax = (unsigned long long)(-EACCES);
                        ptrace(PTRACE_SETREGS, pid, NULL, &regs);
                    }
                    entry->denied = 0;
                }
            }
        } else if (signal_number == SIGTRAP && event != 0) {
            switch (event) {
            case PTRACE_EVENT_FORK:
            case PTRACE_EVENT_VFORK:
            case PTRACE_EVENT_CLONE: {
                unsigned long new_pid = 0;

                if (ptrace(PTRACE_GETEVENTMSG, pid, NULL, &new_pid) == 0) {
                    find_tracee((pid_t)new_pid, 1);
                }
                event_forks++;
                break;
            }
            case PTRACE_EVENT_EXEC:
                event_execs++;
                break;
            case PTRACE_EVENT_EXIT:
                event_exits++;
                break;
            default:
                break;
            }
        } else if (signal_number == SIGTRAP) {
            /* A plain trap, for example the first stop of a new tracee. */
            deliver = 0;
        } else {
            deliver = signal_number;
        }

        if (ptrace(restart, pid, NULL, (void *)(long)deliver) < 0) {
            if (errno != ESRCH) {
                /* The tracee left between the stop and the restart. */
            }
        }
    }
    end_ns = now_ns();

    if (histogram_path) {
        FILE *file = fopen(histogram_path, "w");

        if (file) {
            int number;

            for (number = 0; number < SYSCALL_NUMBERS; number++) {
                if (histogram[number]) {
                    fprintf(file, "%d %llu\n", number, histogram[number]);
                }
            }
            fclose(file);
        }
    }

    summary = stderr;
    if (summary_path) {
        FILE *file = fopen(summary_path, "w");

        if (file) {
            summary = file;
        }
    }
    fprintf(summary,
            "ptrace_full mode=%s processes=%d syscall_stops=%llu "
            "syscalls=%llu forks=%llu execs=%llu exits=%llu denied=%llu "
            "wall_ms=%.1f\n",
            syscall_mode ? "syscall" : "events", distinct_processes,
            syscall_stops, syscalls_entered, event_forks, event_execs,
            event_exits, denied_calls,
            (double)(end_ns - start_ns) / 1000000.0);
    if (summary != stderr) {
        fclose(summary);
    }

    if (root_done && WIFEXITED(root_status)) {
        return WEXITSTATUS(root_status);
    }
    return 0;
}
