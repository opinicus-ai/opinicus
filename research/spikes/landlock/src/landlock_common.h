/* Shared Landlock helpers for the Agent Firewall research spike.
 *
 * glibc has no wrapper for the three Landlock system calls, so this header
 * declares them through syscall(2). The header also holds the tables that
 * name every access right, and the ABI detection.
 */
#ifndef AFW_LANDLOCK_COMMON_H
#define AFW_LANDLOCK_COMMON_H

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/landlock.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>

#ifndef landlock_create_ruleset
static inline int landlock_create_ruleset(const struct landlock_ruleset_attr *attr,
                                          size_t size, uint32_t flags)
{
    return (int)syscall(__NR_landlock_create_ruleset, attr, size, flags);
}
#endif

#ifndef landlock_add_rule
static inline int landlock_add_rule(int ruleset_fd, enum landlock_rule_type type,
                                    const void *attr, uint32_t flags)
{
    return (int)syscall(__NR_landlock_add_rule, ruleset_fd, type, attr, flags);
}
#endif

#ifndef landlock_restrict_self
static inline int landlock_restrict_self(int ruleset_fd, uint32_t flags)
{
    return (int)syscall(__NR_landlock_restrict_self, ruleset_fd, flags);
}
#endif

/* Fallbacks, so that the spike builds on a kernel header set that is older
 * than the kernel that runs it. */
#ifndef LANDLOCK_ACCESS_FS_REFER
#define LANDLOCK_ACCESS_FS_REFER (1ULL << 13)
#endif
#ifndef LANDLOCK_ACCESS_FS_TRUNCATE
#define LANDLOCK_ACCESS_FS_TRUNCATE (1ULL << 14)
#endif
#ifndef LANDLOCK_ACCESS_FS_IOCTL_DEV
#define LANDLOCK_ACCESS_FS_IOCTL_DEV (1ULL << 15)
#endif
#ifndef LANDLOCK_ACCESS_FS_RESOLVE_UNIX
#define LANDLOCK_ACCESS_FS_RESOLVE_UNIX (1ULL << 16)
#endif
#ifndef LANDLOCK_ACCESS_NET_BIND_TCP
#define LANDLOCK_ACCESS_NET_BIND_TCP (1ULL << 0)
#endif
#ifndef LANDLOCK_ACCESS_NET_CONNECT_TCP
#define LANDLOCK_ACCESS_NET_CONNECT_TCP (1ULL << 1)
#endif
#ifndef LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET
#define LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET (1ULL << 0)
#endif
#ifndef LANDLOCK_SCOPE_SIGNAL
#define LANDLOCK_SCOPE_SIGNAL (1ULL << 1)
#endif
#ifndef LANDLOCK_CREATE_RULESET_ERRATA
#define LANDLOCK_CREATE_RULESET_ERRATA (1U << 1)
#endif
/* ABI 7 added audit logging control on landlock_restrict_self(). */
#ifndef LANDLOCK_RESTRICT_SELF_LOG_SAME_EXEC_OFF
#define LANDLOCK_RESTRICT_SELF_LOG_SAME_EXEC_OFF (1U << 0)
#endif
#ifndef LANDLOCK_RESTRICT_SELF_LOG_NEW_EXEC_ON
#define LANDLOCK_RESTRICT_SELF_LOG_NEW_EXEC_ON (1U << 1)
#endif
#ifndef LANDLOCK_RESTRICT_SELF_LOG_SUBDOMAINS_OFF
#define LANDLOCK_RESTRICT_SELF_LOG_SUBDOMAINS_OFF (1U << 2)
#endif

struct afw_right {
    const char *name;
    uint64_t bit;
    int abi; /* the ABI version that added this right */
};

/* Every filesystem right, with the ABI version that added it. */
static const struct afw_right AFW_FS_RIGHTS[] = {
    {"EXECUTE", LANDLOCK_ACCESS_FS_EXECUTE, 1},
    {"WRITE_FILE", LANDLOCK_ACCESS_FS_WRITE_FILE, 1},
    {"READ_FILE", LANDLOCK_ACCESS_FS_READ_FILE, 1},
    {"READ_DIR", LANDLOCK_ACCESS_FS_READ_DIR, 1},
    {"REMOVE_DIR", LANDLOCK_ACCESS_FS_REMOVE_DIR, 1},
    {"REMOVE_FILE", LANDLOCK_ACCESS_FS_REMOVE_FILE, 1},
    {"MAKE_CHAR", LANDLOCK_ACCESS_FS_MAKE_CHAR, 1},
    {"MAKE_DIR", LANDLOCK_ACCESS_FS_MAKE_DIR, 1},
    {"MAKE_REG", LANDLOCK_ACCESS_FS_MAKE_REG, 1},
    {"MAKE_SOCK", LANDLOCK_ACCESS_FS_MAKE_SOCK, 1},
    {"MAKE_FIFO", LANDLOCK_ACCESS_FS_MAKE_FIFO, 1},
    {"MAKE_BLOCK", LANDLOCK_ACCESS_FS_MAKE_BLOCK, 1},
    {"MAKE_SYM", LANDLOCK_ACCESS_FS_MAKE_SYM, 1},
    {"REFER", LANDLOCK_ACCESS_FS_REFER, 2},
    {"TRUNCATE", LANDLOCK_ACCESS_FS_TRUNCATE, 3},
    {"IOCTL_DEV", LANDLOCK_ACCESS_FS_IOCTL_DEV, 5},
    {"RESOLVE_UNIX", LANDLOCK_ACCESS_FS_RESOLVE_UNIX, 9},
};
#define AFW_FS_RIGHTS_N (sizeof(AFW_FS_RIGHTS) / sizeof(AFW_FS_RIGHTS[0]))

static const struct afw_right AFW_NET_RIGHTS[] = {
    {"BIND_TCP", LANDLOCK_ACCESS_NET_BIND_TCP, 4},
    {"CONNECT_TCP", LANDLOCK_ACCESS_NET_CONNECT_TCP, 4},
};
#define AFW_NET_RIGHTS_N (sizeof(AFW_NET_RIGHTS) / sizeof(AFW_NET_RIGHTS[0]))

static const struct afw_right AFW_SCOPES[] = {
    {"ABSTRACT_UNIX_SOCKET", LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET, 6},
    {"SIGNAL", LANDLOCK_SCOPE_SIGNAL, 6},
};
#define AFW_SCOPES_N (sizeof(AFW_SCOPES) / sizeof(AFW_SCOPES[0]))

/* Asks the kernel for the Landlock ABI version.
 * Returns the version, or a negative errno. */
static inline int afw_landlock_abi(void)
{
    int abi = landlock_create_ruleset(NULL, 0, LANDLOCK_CREATE_RULESET_VERSION);
    if (abi < 0)
        return -errno;
    return abi;
}

/* The union of every filesystem right that the given ABI supports. */
static inline uint64_t afw_fs_rights_for_abi(int abi)
{
    uint64_t mask = 0;
    for (size_t i = 0; i < AFW_FS_RIGHTS_N; i++)
        if (AFW_FS_RIGHTS[i].abi <= abi)
            mask |= AFW_FS_RIGHTS[i].bit;
    return mask;
}

static inline uint64_t afw_net_rights_for_abi(int abi)
{
    uint64_t mask = 0;
    for (size_t i = 0; i < AFW_NET_RIGHTS_N; i++)
        if (AFW_NET_RIGHTS[i].abi <= abi)
            mask |= AFW_NET_RIGHTS[i].bit;
    return mask;
}

static inline uint64_t afw_scopes_for_abi(int abi)
{
    uint64_t mask = 0;
    for (size_t i = 0; i < AFW_SCOPES_N; i++)
        if (AFW_SCOPES[i].abi <= abi)
            mask |= AFW_SCOPES[i].bit;
    return mask;
}

/* The ruleset attribute struct grew with the ABI. This picks the size that
 * matches what the kernel knows, so that an old kernel does not get a struct
 * that is too large. */
struct afw_ruleset_attr_v {
    uint64_t handled_access_fs;
    uint64_t handled_access_net;
    uint64_t scoped;
};

static inline size_t afw_attr_size_for_abi(int abi)
{
    if (abi < 4)
        return sizeof(uint64_t);      /* fs only */
    if (abi < 6)
        return sizeof(uint64_t) * 2;  /* fs + net */
    return sizeof(uint64_t) * 3;      /* fs + net + scoped */
}

#endif /* AFW_LANDLOCK_COMMON_H */
