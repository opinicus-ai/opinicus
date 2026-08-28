/* The seccomp BPF filter of the spike.
 *
 * The filter runs in the kernel. It returns SECCOMP_RET_ALLOW for a boring
 * system call, and SECCOMP_RET_TRACE for an interesting one. Only a TRACE
 * result makes a ptrace stop, so the supervisor never wakes for a read or a
 * write.
 *
 * The low 16 bits of a TRACE result carry a group number. The supervisor
 * reads that number with PTRACE_GETEVENTMSG, so one filter can label many
 * groups of system calls.
 */
#ifndef AFW_FILTER_H
#define AFW_FILTER_H

#include <stdint.h>

/* Group numbers that the filter puts in SECCOMP_RET_DATA. */
enum afw_group {
    AFW_GROUP_NONE = 0,
    AFW_GROUP_EXEC = 1,
    AFW_GROUP_OPEN_WRITE = 2,
    AFW_GROUP_OPEN_READ = 3,
    AFW_GROUP_DELETE = 4,
    AFW_GROUP_RENAME = 5,
    AFW_GROUP_CONNECT = 6,
    AFW_GROUP_OPEN_HOW = 7, /* openat2: the flags sit behind a pointer */
    AFW_GROUP_WRITE = 8,
    AFW_GROUP_MAX = 9
};

/* Returns a short name of a group, for the log. */
const char *afw_group_name(unsigned group);

/* Installs the filter of one configuration in the calling process.
 *
 * `config` is one of the letters 'z', 'a', 'b', 'c', 'd'. The letters 'x'
 * and 'e' install no filter at all.
 *
 * Returns 0 on success. Returns -1 and sets errno when the kernel refuses
 * the filter.
 */
int afw_install_filter(int config, int set_no_new_privs);

/* Returns the number of rules of a configuration, for the report. */
int afw_rule_count(int config);

/* Returns a one-line description of a configuration. */
const char *afw_config_description(int config);

#endif
