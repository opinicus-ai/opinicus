/* Builds and installs the seccomp BPF filter. See filter.h. */
#define _GNU_SOURCE

#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <fcntl.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <sys/prctl.h>
#include <sys/syscall.h>

#include "filter.h"

/* System call numbers of x86_64. The spike is one architecture only. */
#define NR_OPEN 2
#define NR_CONNECT 42
#define NR_EXECVE 59
#define NR_RENAME 82
#define NR_UNLINK 87
#define NR_OPENAT 257
#define NR_UNLINKAT 263
#define NR_RENAMEAT 264
#define NR_RENAMEAT2 316
#define NR_EXECVEAT 322
#define NR_OPENAT2 437
#define NR_WRITE 1
#define NR_PWRITE64 18
#define NR_WRITEV 20
#define NR_SENDTO 44
#define NR_SENDMSG 46

/* A file is opened for change when any of these bits is in `flags`.
 * O_RDONLY is zero, so a read-only open never sets one of them.
 */
#define WRITE_FLAGS (O_WRONLY | O_RDWR | O_CREAT | O_TRUNC | O_APPEND)

/* One rule of the filter.
 *
 * `arg_mask` of zero means that the rule matches on the system call number
 * alone. A rule with a mask also tests one scalar argument, which is all
 * that a BPF filter can do: it cannot follow a pointer.
 */
struct rule {
    int nr;
    unsigned group;
    int arg_index;
    unsigned arg_mask;
};

/* (a) The exec boundary alone. This is what af-monitor watches today, but
 * here the kernel filter and not PTRACE_EVENT_EXEC reports it.
 */
static const struct rule rules_a[] = {
    {NR_EXECVE, AFW_GROUP_EXEC, 0, 0},
    {NR_EXECVEAT, AFW_GROUP_EXEC, 0, 0},
};

/* (b) Exec, and only an open that can change a file. The kernel tests the
 * `flags` argument, so a read-only open never reaches the supervisor.
 */
static const struct rule rules_b[] = {
    {NR_EXECVE, AFW_GROUP_EXEC, 0, 0},
    {NR_EXECVEAT, AFW_GROUP_EXEC, 0, 0},
    {NR_OPENAT, AFW_GROUP_OPEN_WRITE, 2, WRITE_FLAGS},
    {NR_OPEN, AFW_GROUP_OPEN_WRITE, 1, WRITE_FLAGS},
    /* openat2 hides its flags behind a pointer, so the kernel cannot test
     * them. Every openat2 must go to the supervisor.
     */
    {NR_OPENAT2, AFW_GROUP_OPEN_HOW, 0, 0},
};

/* (c) Exec and every open. The write rule stands first, so the group number
 * still separates a write from a read.
 */
static const struct rule rules_c[] = {
    {NR_EXECVE, AFW_GROUP_EXEC, 0, 0},
    {NR_EXECVEAT, AFW_GROUP_EXEC, 0, 0},
    {NR_OPENAT, AFW_GROUP_OPEN_WRITE, 2, WRITE_FLAGS},
    {NR_OPENAT, AFW_GROUP_OPEN_READ, 0, 0},
    {NR_OPEN, AFW_GROUP_OPEN_WRITE, 1, WRITE_FLAGS},
    {NR_OPEN, AFW_GROUP_OPEN_READ, 0, 0},
    {NR_OPENAT2, AFW_GROUP_OPEN_HOW, 0, 0},
};

/* (d) The set that the product needs: exec, open, delete, rename, connect. */
static const struct rule rules_d[] = {
    {NR_EXECVE, AFW_GROUP_EXEC, 0, 0},
    {NR_EXECVEAT, AFW_GROUP_EXEC, 0, 0},
    {NR_OPENAT, AFW_GROUP_OPEN_WRITE, 2, WRITE_FLAGS},
    {NR_OPENAT, AFW_GROUP_OPEN_READ, 0, 0},
    {NR_OPEN, AFW_GROUP_OPEN_WRITE, 1, WRITE_FLAGS},
    {NR_OPEN, AFW_GROUP_OPEN_READ, 0, 0},
    {NR_OPENAT2, AFW_GROUP_OPEN_HOW, 0, 0},
    {NR_UNLINKAT, AFW_GROUP_DELETE, 0, 0},
    {NR_UNLINK, AFW_GROUP_DELETE, 0, 0},
    {NR_RENAMEAT2, AFW_GROUP_RENAME, 0, 0},
    {NR_RENAMEAT, AFW_GROUP_RENAME, 0, 0},
    {NR_RENAME, AFW_GROUP_RENAME, 0, 0},
    {NR_CONNECT, AFW_GROUP_CONNECT, 0, 0},
};

/* (f) The set that af-monitor would really install: everything of (d) with
 * no execve.
 *
 * af-monitor already sees an exec at PTRACE_EVENT_EXEC, so the filter does
 * not have to report one. Leaving execve out of the filter also removes the
 * only reason for the second stage: the first execve of the child is then
 * allowed by the filter, so the child can install the filter itself before
 * that execve, exactly where af-monitor calls PTRACE_TRACEME today.
 */
static const struct rule rules_f[] = {
    {NR_OPENAT, AFW_GROUP_OPEN_WRITE, 2, WRITE_FLAGS},
    {NR_OPENAT, AFW_GROUP_OPEN_READ, 0, 0},
    {NR_OPEN, AFW_GROUP_OPEN_WRITE, 1, WRITE_FLAGS},
    {NR_OPEN, AFW_GROUP_OPEN_READ, 0, 0},
    {NR_OPENAT2, AFW_GROUP_OPEN_HOW, 0, 0},
    {NR_UNLINKAT, AFW_GROUP_DELETE, 0, 0},
    {NR_UNLINK, AFW_GROUP_DELETE, 0, 0},
    {NR_RENAMEAT2, AFW_GROUP_RENAME, 0, 0},
    {NR_RENAMEAT, AFW_GROUP_RENAME, 0, 0},
    {NR_RENAME, AFW_GROUP_RENAME, 0, 0},
    {NR_CONNECT, AFW_GROUP_CONNECT, 0, 0},
};

/* (g) The same set as (f), but an open only reaches the supervisor when the
 * flags ask for a change. This is the cheapest useful configuration.
 */
static const struct rule rules_g[] = {
    {NR_OPENAT, AFW_GROUP_OPEN_WRITE, 2, WRITE_FLAGS},
    {NR_OPEN, AFW_GROUP_OPEN_WRITE, 1, WRITE_FLAGS},
    {NR_OPENAT2, AFW_GROUP_OPEN_HOW, 0, 0},
    {NR_UNLINKAT, AFW_GROUP_DELETE, 0, 0},
    {NR_UNLINK, AFW_GROUP_DELETE, 0, 0},
    {NR_RENAMEAT2, AFW_GROUP_RENAME, 0, 0},
    {NR_RENAMEAT, AFW_GROUP_RENAME, 0, 0},
    {NR_RENAME, AFW_GROUP_RENAME, 0, 0},
    {NR_CONNECT, AFW_GROUP_CONNECT, 0, 0},
};

/* (w) What it costs to look for content. A statement that a program sends
 * through a connection that is already open only appears in write and in
 * sendto. This configuration measures that price.
 */
static const struct rule rules_w[] = {
    {NR_WRITE, AFW_GROUP_WRITE, 0, 0},
    {NR_WRITEV, AFW_GROUP_WRITE, 0, 0},
    {NR_PWRITE64, AFW_GROUP_WRITE, 0, 0},
    {NR_SENDTO, AFW_GROUP_WRITE, 0, 0},
    {NR_SENDMSG, AFW_GROUP_WRITE, 0, 0},
    {NR_CONNECT, AFW_GROUP_CONNECT, 0, 0},
};

static const struct rule *rules_of(int config, size_t *count)
{
    switch (config) {
    case 'z':
        *count = 0;
        return rules_a; /* never read */
    case 'a':
        *count = sizeof(rules_a) / sizeof(rules_a[0]);
        return rules_a;
    case 'b':
        *count = sizeof(rules_b) / sizeof(rules_b[0]);
        return rules_b;
    case 'c':
        *count = sizeof(rules_c) / sizeof(rules_c[0]);
        return rules_c;
    case 'd':
        *count = sizeof(rules_d) / sizeof(rules_d[0]);
        return rules_d;
    case 'f':
        *count = sizeof(rules_f) / sizeof(rules_f[0]);
        return rules_f;
    case 'g':
        *count = sizeof(rules_g) / sizeof(rules_g[0]);
        return rules_g;
    case 'w':
        *count = sizeof(rules_w) / sizeof(rules_w[0]);
        return rules_w;
    default:
        *count = 0;
        return NULL;
    }
}

const char *afw_group_name(unsigned group)
{
    switch (group) {
    case AFW_GROUP_EXEC:
        return "exec";
    case AFW_GROUP_OPEN_WRITE:
        return "open_write";
    case AFW_GROUP_OPEN_READ:
        return "open_read";
    case AFW_GROUP_DELETE:
        return "delete";
    case AFW_GROUP_RENAME:
        return "rename";
    case AFW_GROUP_CONNECT:
        return "connect";
    case AFW_GROUP_OPEN_HOW:
        return "open_how";
    case AFW_GROUP_WRITE:
        return "write";
    default:
        return "other";
    }
}

const char *afw_config_description(int config)
{
    switch (config) {
    case 'x':
        return "af-monitor of today: ptrace exec events, no seccomp filter";
    case 'z':
        return "a filter that traces nothing, to show the fixed cost";
    case 'a':
        return "execve and execveat";
    case 'b':
        return "execve, and openat only when the flags ask for a change";
    case 'c':
        return "execve, and every openat";
    case 'd':
        return "execve, openat, unlinkat, renameat2, connect";
    case 'f':
        return "openat, unlinkat, renameat2, connect; exec stays with ptrace";
    case 'g':
        return "openat for change, unlinkat, renameat2, connect; exec stays with ptrace";
    case 'w':
        return "write, writev, sendto, sendmsg, connect: the price of content";
    case 'e':
        return "no filter: PTRACE_SYSCALL stops on every system call";
    default:
        return "unknown";
    }
}

int afw_rule_count(int config)
{
    size_t count = 0;
    rules_of(config, &count);
    return (int)count;
}

/* Offset of one field of `struct seccomp_data`. */
#define OFF_NR offsetof(struct seccomp_data, nr)
#define OFF_ARCH offsetof(struct seccomp_data, arch)
/* The machine is little endian, so the low 32 bits of an argument come
 * first. A flags argument never needs more than 32 bits.
 */
#define OFF_ARG_LOW(index) (offsetof(struct seccomp_data, args) + 8u * (unsigned)(index))

#define MAX_INSNS 128

int afw_install_filter(int config, int set_no_new_privs)
{
    struct sock_filter insns[MAX_INSNS];
    struct sock_fprog prog;
    size_t count = 0;
    size_t n = 0;
    size_t i;
    const struct rule *rules = rules_of(config, &count);

    /* The configurations 'x' and 'e' use no filter at all. */
    if (rules == NULL)
        return 0;

    /* Every rule block starts with a load of the system call number, and it
     * falls through to the next block when it does not match. A block is
     * therefore self-contained, and no jump has to count instructions of
     * another block.
     */

    /* Only x86_64 is filtered. Anything else is allowed, because the spike
     * is a visibility tool and not a sandbox.
     */
    insns[n++] = (struct sock_filter)BPF_STMT(BPF_LD | BPF_W | BPF_ABS, (uint32_t)OFF_ARCH);
    insns[n++] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 1, 0);
    insns[n++] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW);

    /* The x32 ABI adds 0x40000000 to the number. Those calls are allowed. */
    insns[n++] = (struct sock_filter)BPF_STMT(BPF_LD | BPF_W | BPF_ABS, (uint32_t)OFF_NR);
    insns[n++] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JGE | BPF_K, 0x40000000u, 0, 1);
    insns[n++] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW);

    for (i = 0; i < count; i++) {
        const struct rule *rule = &rules[i];
        uint32_t action = SECCOMP_RET_TRACE | (rule->group & SECCOMP_RET_DATA);

        if (n + 5 >= MAX_INSNS) {
            errno = E2BIG;
            return -1;
        }
        insns[n++] = (struct sock_filter)BPF_STMT(BPF_LD | BPF_W | BPF_ABS, (uint32_t)OFF_NR);
        if (rule->arg_mask == 0) {
            insns[n++] =
                (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, (uint32_t)rule->nr, 0, 1);
            insns[n++] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, action);
        } else {
            insns[n++] =
                (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, (uint32_t)rule->nr, 0, 3);
            insns[n++] = (struct sock_filter)BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
                                                      (uint32_t)OFF_ARG_LOW(rule->arg_index));
            insns[n++] =
                (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JSET | BPF_K, rule->arg_mask, 0, 1);
            insns[n++] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, action);
        }
    }

    insns[n++] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW);

    prog.len = (unsigned short)n;
    prog.filter = insns;

    if (set_no_new_privs && prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0)
        return -1;

    if (syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER, 0u, &prog) != 0)
        return -1;
    return 0;
}
