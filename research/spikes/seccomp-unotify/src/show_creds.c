/*
 * show-creds - prints the identity and the no_new_privs state of the process.
 *
 * The no_new_privs test uses it. It answers two questions:
 *   does the flag survive an execve, and does it survive a fork?
 *
 * Usage:
 *   show-creds [--fork]
 */

#define _GNU_SOURCE

#include <stdio.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <unistd.h>

static void print_line(const char *tag)
{
    int nnp = prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0);
    char caps[128] = "?";
    FILE *f = fopen("/proc/self/status", "r");
    if (f != NULL) {
        char line[256];
        while (fgets(line, sizeof(line), f) != NULL) {
            if (strncmp(line, "CapEff:", 7) == 0) {
                char *p = line + 7;
                while (*p == '\t' || *p == ' ') {
                    p++;
                }
                size_t n = strcspn(p, "\n");
                if (n >= sizeof(caps)) {
                    n = sizeof(caps) - 1;
                }
                memcpy(caps, p, n);
                caps[n] = '\0';
                break;
            }
        }
        fclose(f);
    }
    printf("%s pid=%d uid=%d euid=%d gid=%d egid=%d no_new_privs=%d capeff=%s\n",
           tag, (int)getpid(), (int)getuid(), (int)geteuid(), (int)getgid(),
           (int)getegid(), nnp, caps);
    fflush(stdout);
}

int main(int argc, char **argv)
{
    int do_fork = 0;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--fork") == 0) {
            do_fork = 1;
        }
    }

    print_line("self");

    if (do_fork) {
        pid_t pid = fork();
        if (pid == 0) {
            print_line("child");
            _exit(0);
        }
        int status = 0;
        waitpid(pid, &status, 0);
    }
    return 0;
}
