/* probe_abi.c — what does this kernel really give us?
 *
 * This program only asks. It creates ruleset descriptors and closes them
 * again. It never calls landlock_restrict_self(), so it cannot restrict the
 * shell that starts it.
 *
 * A right is "supported" when the kernel accepts a ruleset that handles only
 * that right. An unsupported right gives EINVAL.
 */
#include "landlock_common.h"
#include <sys/wait.h>

static int probe_fs_right(uint64_t bit)
{
    struct afw_ruleset_attr_v attr = {.handled_access_fs = bit};
    int fd = landlock_create_ruleset((struct landlock_ruleset_attr *)&attr,
                                     sizeof(uint64_t), 0);
    if (fd < 0)
        return -errno;
    close(fd);
    return 0;
}

static int probe_net_right(uint64_t bit)
{
    struct afw_ruleset_attr_v attr = {
        .handled_access_fs = LANDLOCK_ACCESS_FS_READ_FILE,
        .handled_access_net = bit,
    };
    int fd = landlock_create_ruleset((struct landlock_ruleset_attr *)&attr,
                                     sizeof(uint64_t) * 2, 0);
    if (fd < 0)
        return -errno;
    close(fd);
    return 0;
}

static int probe_scope(uint64_t bit)
{
    struct afw_ruleset_attr_v attr = {
        .handled_access_fs = LANDLOCK_ACCESS_FS_READ_FILE,
        .scoped = bit,
    };
    int fd = landlock_create_ruleset((struct landlock_ruleset_attr *)&attr,
                                     sizeof(uint64_t) * 3, 0);
    if (fd < 0)
        return -errno;
    close(fd);
    return 0;
}

int main(void)
{
    int abi = afw_landlock_abi();

    printf("landlock_abi_version           = ");
    if (abi < 0) {
        printf("ERROR %s\n", strerror(-abi));
        return 1;
    }
    printf("%d\n", abi);

    int errata = landlock_create_ruleset(NULL, 0, LANDLOCK_CREATE_RULESET_ERRATA);
    printf("landlock_errata_bitmask       = ");
    if (errata < 0)
        printf("not supported (%s)\n", strerror(errno));
    else
        printf("0x%x\n", (unsigned)errata);

    printf("no_new_privs_needed           = yes (unprivileged sandbox)\n");
    printf("uid                           = %u\n", (unsigned)getuid());

    printf("\n--- filesystem rights ---\n");
    for (size_t i = 0; i < AFW_FS_RIGHTS_N; i++) {
        int rc = probe_fs_right(AFW_FS_RIGHTS[i].bit);
        printf("fs.%-14s abi>=%d  %s\n", AFW_FS_RIGHTS[i].name,
               AFW_FS_RIGHTS[i].abi,
               rc == 0 ? "SUPPORTED" : "not supported");
    }

    printf("\n--- network rights ---\n");
    for (size_t i = 0; i < AFW_NET_RIGHTS_N; i++) {
        int rc = probe_net_right(AFW_NET_RIGHTS[i].bit);
        printf("net.%-13s abi>=%d  %s\n", AFW_NET_RIGHTS[i].name,
               AFW_NET_RIGHTS[i].abi,
               rc == 0 ? "SUPPORTED" : "not supported");
    }

    printf("\n--- scopes ---\n");
    for (size_t i = 0; i < AFW_SCOPES_N; i++) {
        int rc = probe_scope(AFW_SCOPES[i].bit);
        printf("scope.%-11s abi>=%d  %s\n", AFW_SCOPES[i].name,
               AFW_SCOPES[i].abi,
               rc == 0 ? "SUPPORTED" : "not supported");
    }

    printf("\n--- struct size that the kernel accepts ---\n");
    for (size_t words = 1; words <= 5; words++) {
        struct afw_ruleset_attr_v attr = {.handled_access_fs = LANDLOCK_ACCESS_FS_READ_FILE};
        uint64_t buf[8];
        memset(buf, 0, sizeof(buf));
        memcpy(buf, &attr, sizeof(attr));
        int fd = landlock_create_ruleset((struct landlock_ruleset_attr *)buf,
                                         sizeof(uint64_t) * words, 0);
        printf("attr_size=%zu bytes            %s\n", sizeof(uint64_t) * words,
               fd >= 0 ? "accepted" : strerror(errno));
        if (fd >= 0)
            close(fd);
    }

    printf("\n--- audit log flags of landlock_restrict_self (ABI 7) ---\n");
    /* The probe runs in a forked child. A LOG flag with ruleset_fd = -1 can
     * change the audit setting of the caller, and this process must stay
     * unchanged. The child gives an invalid descriptor, so no domain is ever
     * enacted: EINVAL means the kernel rejected the flag, and any other error
     * means the kernel knows the flag. */
    static const struct afw_right log_flags[] = {
        {"LOG_SAME_EXEC_OFF", LANDLOCK_RESTRICT_SELF_LOG_SAME_EXEC_OFF, 7},
        {"LOG_NEW_EXEC_ON", LANDLOCK_RESTRICT_SELF_LOG_NEW_EXEC_ON, 7},
        {"LOG_SUBDOMAINS_OFF", LANDLOCK_RESTRICT_SELF_LOG_SUBDOMAINS_OFF, 7},
    };
    for (size_t i = 0; i < 3; i++) {
        pid_t pid = fork();
        if (pid == 0) {
            errno = 0;
            landlock_restrict_self(-2, (uint32_t)log_flags[i].bit);
            _exit(errno == EINVAL ? 1 : 0);
        }
        int status = 0;
        waitpid(pid, &status, 0);
        int rejected = WIFEXITED(status) && WEXITSTATUS(status) == 1;
        printf("restrict_self.%-18s abi>=%d  %s\n", log_flags[i].name,
               log_flags[i].abi, rejected ? "not supported" : "SUPPORTED");
    }

    printf("\n--- is a ruleset removable? ---\n");
    printf("no API exists to drop or to widen a ruleset; see test 5\n");
    return 0;
}
