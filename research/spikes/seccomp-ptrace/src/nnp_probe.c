/* nnp-probe: answers whether seccomp needs PR_SET_NO_NEW_PRIVS, and shows
 * what no_new_privs does to a setuid program.
 *
 * Modes:
 *   --check                 try the filter with and without no_new_privs
 *   --with-nnp -- cmd ...    set no_new_privs, then run the command
 *   --plain -- cmd ...       run the command with nothing set
 */
#define _GNU_SOURCE

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <sys/prctl.h>
#include <sys/wait.h>

#include "filter.h"

static int check(void)
{
    pid_t child;
    int status = 0;
    int failures = 0;

    /* A filter changes the process for ever, so each try needs its own
     * process.
     */
    child = fork();
    if (child == 0) {
        if (afw_install_filter('a', 0) != 0) {
            fprintf(stderr, "without-nnp: refused errno=%d (%s)\n", errno, strerror(errno));
            _exit(1);
        }
        fprintf(stderr, "without-nnp: accepted\n");
        _exit(0);
    }
    waitpid(child, &status, 0);
    if (WEXITSTATUS(status) != 0)
        failures++;
    printf("without_nnp_accepted=%d\n", WEXITSTATUS(status) == 0 ? 1 : 0);

    child = fork();
    if (child == 0) {
        if (afw_install_filter('a', 1) != 0) {
            fprintf(stderr, "with-nnp: refused errno=%d (%s)\n", errno, strerror(errno));
            _exit(1);
        }
        fprintf(stderr, "with-nnp: accepted\n");
        _exit(0);
    }
    waitpid(child, &status, 0);
    printf("with_nnp_accepted=%d\n", WEXITSTATUS(status) == 0 ? 1 : 0);

    /* A useful extra fact: does the value of no_new_privs survive an
     * execve? The kernel says yes, and a program cannot clear it.
     */
    prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
    printf("nnp_after_set=%d\n", prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0));
    return failures;
}

int main(int argc, char **argv)
{
    int index = 1;
    int with_nnp = 0;
    int do_check = 0;

    while (index < argc) {
        if (strcmp(argv[index], "--check") == 0) {
            do_check = 1;
            index++;
        } else if (strcmp(argv[index], "--with-nnp") == 0) {
            with_nnp = 1;
            index++;
        } else if (strcmp(argv[index], "--plain") == 0) {
            index++;
        } else if (strcmp(argv[index], "--") == 0) {
            index++;
            break;
        } else {
            break;
        }
    }

    if (do_check)
        return check();

    if (index >= argc) {
        fprintf(stderr, "nnp-probe: no command\n");
        return 2;
    }
    if (with_nnp && prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
        fprintf(stderr, "nnp-probe: cannot set no_new_privs: %s\n", strerror(errno));
        return 2;
    }
    execvp(argv[index], &argv[index]);
    fprintf(stderr, "nnp-probe: cannot run %s: %s\n", argv[index], strerror(errno));
    return 127;
}
