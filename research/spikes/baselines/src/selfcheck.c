/*
 * selfcheck.c - what can a monitored program learn about its supervision?
 *
 * The program prints the fields of /proc/self/status that name a monitor, the
 * LD_PRELOAD variable of its own environment, and every line of
 * /proc/self/maps that holds an injected library.
 *
 * With --install-seccomp it first installs an allow-all seccomp filter on
 * itself. This needs no root, because PR_SET_NO_NEW_PRIVS is enough. It shows
 * what the Seccomp fields report when a filter is present.
 *
 * Usage: selfcheck [--install-seccomp] [LABEL]
 */
#define _GNU_SOURCE

#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>

static void print_status_fields(void)
{
    FILE *file = fopen("/proc/self/status", "r");
    char line[512];

    if (!file) {
        printf("status: unreadable\n");
        return;
    }
    while (fgets(line, sizeof(line), file)) {
        if (strncmp(line, "TracerPid:", 10) == 0 ||
            strncmp(line, "Seccomp:", 8) == 0 ||
            strncmp(line, "Seccomp_filters:", 16) == 0 ||
            strncmp(line, "NoNewPrivs:", 11) == 0) {
            char *newline = strchr(line, '\n');

            if (newline) {
                *newline = '\0';
            }
            printf("status %s\n", line);
        }
    }
    fclose(file);
}

static void print_preload(void)
{
    const char *preload = getenv("LD_PRELOAD");

    printf("env LD_PRELOAD=%s\n", preload ? preload : "(unset)");
}

static void print_injected_maps(void)
{
    FILE *file = fopen("/proc/self/maps", "r");
    char line[1024];
    int found = 0;

    if (!file) {
        printf("maps: unreadable\n");
        return;
    }
    while (fgets(line, sizeof(line), file)) {
        if (strstr(line, "afwpreload")) {
            char *newline = strchr(line, '\n');

            if (newline) {
                *newline = '\0';
            }
            printf("maps %s\n", line);
            found = 1;
        }
    }
    fclose(file);
    if (!found) {
        printf("maps no injected library found\n");
    }
}

static int install_allow_all_filter(void)
{
    struct sock_filter program[] = {
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };
    struct sock_fprog fprog = {
        .len = (unsigned short)(sizeof(program) / sizeof(program[0])),
        .filter = program,
    };

    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0) {
        perror("PR_SET_NO_NEW_PRIVS");
        return -1;
    }
    if (syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER, 0, &fprog) < 0) {
        perror("seccomp");
        return -1;
    }
    return 0;
}

int main(int argc, char **argv)
{
    const char *label = "selfcheck";
    int install = 0;
    int index;

    for (index = 1; index < argc; index++) {
        if (strcmp(argv[index], "--install-seccomp") == 0) {
            install = 1;
        } else {
            label = argv[index];
        }
    }

    if (install && install_allow_all_filter() < 0) {
        return 1;
    }

    printf("label %s\n", label);
    printf("pid %d\n", (int)getpid());
    print_status_fields();
    print_preload();
    print_injected_maps();
    return 0;
}
