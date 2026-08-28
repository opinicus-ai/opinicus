/* rule_specificity — can a rule deeper in the tree take a right away?
 *
 * The launcher hides a subtree by enumerating the siblings of every directory
 * on the way down, which costs one rule for each entry. A cheaper way would
 * be one broad rule on the parent and one narrow rule on the subtree. This
 * program tests whether that works.
 *
 * It grants every right on the parent directory, and then adds a second rule
 * on the child directory with fewer rights. Then it lists both.
 *
 * usage: rule-specificity PARENT CHILD [EXTRA_GRANT...]
 */
#include "landlock_common.h"
#include <dirent.h>

#include <sys/wait.h>

int main(int argc, char **argv)
{
    if (argc < 3) {
        fprintf(stderr, "usage: rule-specificity PARENT CHILD [EXTRA_GRANT...]\n");
        return 2;
    }
    const char *parent = argv[1];
    const char *child = argv[2];

    int abi = afw_landlock_abi();
    uint64_t all = afw_fs_rights_for_abi(abi) & ~LANDLOCK_ACCESS_FS_RESOLVE_UNIX;
    struct afw_ruleset_attr_v attr = {.handled_access_fs = all};
    int rs = landlock_create_ruleset((struct landlock_ruleset_attr *)&attr,
                                     sizeof(uint64_t), 0);
    if (rs < 0) { perror("landlock_create_ruleset"); return 2; }

    const char *broad[64];
    size_t n_broad = 0;
    broad[n_broad++] = parent;
    for (int i = 3; i < argc && n_broad < 64; i++)
        broad[n_broad++] = argv[i];

    for (size_t i = 0; i < n_broad; i++) {
        struct landlock_path_beneath_attr pb = {.allowed_access = all};
        pb.parent_fd = open(broad[i], O_PATH | O_CLOEXEC);
        if (pb.parent_fd < 0) continue;
        if (landlock_add_rule(rs, LANDLOCK_RULE_PATH_BENEATH, &pb, 0) < 0)
            perror("add broad rule");
        close(pb.parent_fd);
    }

    /* Attempt 1: a rule with no rights at all. */
    struct landlock_path_beneath_attr pb = {.allowed_access = 0};
    pb.parent_fd = open(child, O_PATH | O_CLOEXEC);
    if (pb.parent_fd < 0) { perror("open child"); return 2; }
    int rc = landlock_add_rule(rs, LANDLOCK_RULE_PATH_BENEATH, &pb, 0);
    printf("RULE empty_rule_on_child -> rc=%d errno=%s\n", rc,
           rc < 0 ? strerror(errno) : "-");

    /* Attempt 2: a rule with one right that has nothing to do with reading. */
    pb.allowed_access = LANDLOCK_ACCESS_FS_MAKE_SYM;
    rc = landlock_add_rule(rs, LANDLOCK_RULE_PATH_BENEATH, &pb, 0);
    printf("RULE narrow_rule_on_child -> rc=%d errno=%s\n", rc,
           rc < 0 ? strerror(errno) : "-");
    close(pb.parent_fd);
    fflush(stdout);

    pid_t pid = fork();
    if (pid == 0) {
        prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
        if (landlock_restrict_self(rs, 0) < 0) { perror("restrict_self"); _exit(2); }

        int fd = open(child, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        printf("RESULT list_child_after_narrow_rule -> %s\n",
               fd >= 0 ? "STILL ALLOWED" : "denied");
        if (fd >= 0) close(fd);
        fd = open(parent, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        printf("RESULT list_parent -> %s\n", fd >= 0 ? "allowed" : "denied");
        if (fd >= 0) close(fd);
        fflush(stdout);
        _exit(0);
    }
    int status = 0;
    waitpid(pid, &status, 0);
    return 0;
}
