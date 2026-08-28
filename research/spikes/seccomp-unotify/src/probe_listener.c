/*
 * probe-listener - records what this kernel gives to an unprivileged user.
 *
 * The program prints one fact for each line, so the test set and FINDINGS.md
 * can quote real output and not a claim.
 *
 * The filter that it installs traps only uselib, a system call that no modern
 * program uses. Nothing therefore blocks, and the process needs no supervisor.
 */

#define _GNU_SOURCE

#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <unistd.h>

#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>

#ifndef SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV
#define SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV (1UL << 5)
#endif

static int seccomp_call(unsigned int op, unsigned int flags, void *args)
{
    return (int)syscall(__NR_seccomp, op, flags, args);
}

static void print_sysctl(const char *path)
{
    FILE *f = fopen(path, "r");
    if (f == NULL) {
        printf("%s = <unreadable>\n", path);
        return;
    }
    char line[64] = "";
    if (fgets(line, sizeof(line), f) != NULL) {
        line[strcspn(line, "\n")] = '\0';
        printf("%s = %s\n", path, line);
    }
    fclose(f);
}

/*
 * Installs a filter in a child process and prints the result. The child dies
 * at once, so no notification can ever block.
 */
static void probe_install(const char *label, unsigned int flags,
                          struct sock_filter *code, int twice)
{
    pid_t pid = fork();
    if (pid != 0) {
        int status = 0;
        waitpid(pid, &status, 0);
        return;
    }
    struct sock_fprog prog = { .len = 4, .filter = code };
    prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
    int fd = seccomp_call(SECCOMP_SET_MODE_FILTER, flags, &prog);
    if (!twice) {
        printf("%s = %s (fd=%d)\n", label, fd >= 0 ? "yes" : strerror(errno),
               fd);
        _exit(0);
    }
    int fd2 = seccomp_call(SECCOMP_SET_MODE_FILTER, flags, &prog);
    printf("%s = %s (first fd=%d, second fd=%d)\n", label,
           fd2 >= 0 ? "yes" : strerror(errno), fd, fd2);
    _exit(0);
}

int main(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);

    struct utsname u;
    if (uname(&u) == 0) {
        printf("kernel = %s %s %s\n", u.sysname, u.release, u.machine);
    }
    printf("uid = %d\n", (int)getuid());
    printf("euid = %d\n", (int)geteuid());
    print_sysctl("/proc/sys/kernel/unprivileged_bpf_disabled");
    print_sysctl("/proc/sys/kernel/seccomp/actions_avail");

    struct seccomp_notif_sizes sizes;
    memset(&sizes, 0, sizeof(sizes));
    if (seccomp_call(SECCOMP_GET_NOTIF_SIZES, 0, &sizes) == 0) {
        printf("notif_sizes = notif:%u resp:%u data:%u\n", sizes.seccomp_notif,
               sizes.seccomp_notif_resp, sizes.seccomp_data);
    } else {
        printf("notif_sizes = error %s\n", strerror(errno));
    }

    unsigned int action = SECCOMP_RET_USER_NOTIF;
    printf("action_avail(USER_NOTIF) = %s\n",
           seccomp_call(SECCOMP_GET_ACTION_AVAIL, 0, &action) == 0 ? "yes"
                                                                   : "no");

    struct sock_filter code[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_uselib, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };

    /* Each install runs in its own child. A filter cannot be removed, so a
     * second install in the same process would answer a different question
     * from the one that the label says. */
    probe_install("new_listener_unprivileged", SECCOMP_FILTER_FLAG_NEW_LISTENER,
                  code, 0);
    probe_install("wait_killable_recv",
                  SECCOMP_FILTER_FLAG_NEW_LISTENER |
                      SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV,
                  code, 0);
    probe_install("second_listener_in_same_process",
                  SECCOMP_FILTER_FLAG_NEW_LISTENER, code, 1);
    probe_install("plain_filter_no_listener", 0, code, 0);

    return 0;
}
