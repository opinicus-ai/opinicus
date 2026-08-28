/* escape_test — runs INSIDE the sandbox and tries to get out of it.
 *
 * Landlock has no "drop" call, and a new ruleset only ever adds restriction.
 * This program proves that with real attempts. Each attempt prints one line:
 *
 *     ESCAPE <name> -> BLOCKED
 *     ESCAPE <name> -> ESCAPED
 *
 * The exit status is 0 when every attempt was blocked, and 1 when one worked.
 *
 * Argument 1 is a file that the sandbox must not let this program read.
 * Argument 2 is a file that the sandbox must let this program read; it shows
 * that the program itself is not broken.
 */
#include "landlock_common.h"

#include <sched.h>
#include <sys/wait.h>

static int escapes;
static const char *secret;

static int can_read(const char *p)
{
    int fd = open(p, O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return 0;
    char b[8];
    ssize_t n = read(fd, b, sizeof(b));
    close(fd);
    return n >= 0;
}

static void report(const char *name, int escaped, const char *detail)
{
    if (escaped)
        escapes++;
    printf("ESCAPE %-34s -> %s  %s\n", name, escaped ? "ESCAPED" : "BLOCKED",
           detail ? detail : "");
    fflush(stdout);
}

/* Attempt 1: ask for everything. A second ruleset that grants read and write
 * on the whole file system is legal to make. The kernel intersects it with
 * the domain that is already on this thread, so it can only take rights
 * away. */
static void try_wider_ruleset(void)
{
    int abi = afw_landlock_abi();
    struct afw_ruleset_attr_v attr = {
        .handled_access_fs = afw_fs_rights_for_abi(abi) &
                             ~LANDLOCK_ACCESS_FS_RESOLVE_UNIX,
    };
    int fd = landlock_create_ruleset((struct landlock_ruleset_attr *)&attr,
                                     sizeof(uint64_t), 0);
    if (fd < 0) {
        report("create a wider ruleset", 0, "landlock_create_ruleset failed");
        return;
    }
    struct landlock_path_beneath_attr pb = {.allowed_access = attr.handled_access_fs};
    pb.parent_fd = open("/", O_PATH | O_CLOEXEC);
    char detail[128] = "";
    if (pb.parent_fd >= 0) {
        if (landlock_add_rule(fd, LANDLOCK_RULE_PATH_BENEATH, &pb, 0) < 0)
            snprintf(detail, sizeof(detail), "add_rule on / failed: %s", strerror(errno));
        close(pb.parent_fd);
    }
    if (landlock_restrict_self(fd, 0) < 0)
        snprintf(detail, sizeof(detail), "restrict_self failed: %s", strerror(errno));
    else if (!detail[0])
        snprintf(detail, sizeof(detail), "restrict_self said OK, and the read still fails");
    close(fd);
    report("grant / to myself and re-restrict", can_read(secret), detail);
}

/* Attempt 2: is there any call that removes a domain?
 * The Landlock API has three system calls and none of them removes anything.
 * The nearest thing is a flag on landlock_create_ruleset. Every flag value
 * that is not VERSION or ERRATA gives EINVAL. */
static void try_drop_call(void)
{
    int found = 0;
    char detail[160];
    snprintf(detail, sizeof(detail), "every unknown flag of landlock_create_ruleset gives EINVAL");
    for (uint32_t flag = 1U << 2; flag; flag <<= 1) {
        int rc = landlock_create_ruleset(NULL, 0, flag);
        if (rc >= 0) {
            found = 1;
            snprintf(detail, sizeof(detail), "flag 0x%x was accepted", flag);
            close(rc);
            break;
        }
    }
    if (!found && can_read(secret))
        found = 1;
    report("find a call that drops the domain", found, detail);
}

/* Attempt 3: start a new program. no_new_privs and the domain both survive
 * execve, so the new program is restricted too. */
static void try_exec_fresh(void)
{
    pid_t pid = fork();
    if (pid == 0) {
        int fd = open("/dev/null", O_WRONLY);
        if (fd >= 0) { dup2(fd, 1); dup2(fd, 2); close(fd); }
        execl("/bin/cat", "cat", secret, (char *)NULL);
        _exit(126);
    }
    int status = 0;
    waitpid(pid, &status, 0);
    int ok = WIFEXITED(status) && WEXITSTATUS(status) == 0;
    char detail[96];
    snprintf(detail, sizeof(detail), "/bin/cat on the secret exited %d",
             WIFEXITED(status) ? WEXITSTATUS(status) : -1);
    report("exec /bin/cat on the secret", ok, detail);
}

/* Attempt 4: a new user namespace gives a new set of capabilities. It does
 * not give a new Landlock domain. */
static void try_userns(void)
{
    pid_t pid = fork();
    if (pid == 0) {
        if (unshare(CLONE_NEWUSER) < 0)
            _exit(3); /* the namespace itself was refused */
        _exit(can_read(secret) ? 1 : 0);
    }
    int status = 0;
    waitpid(pid, &status, 0);
    int code = WIFEXITED(status) ? WEXITSTATUS(status) : -1;
    char detail[96];
    if (code == 3)
        snprintf(detail, sizeof(detail), "unshare(CLONE_NEWUSER) was refused");
    else
        snprintf(detail, sizeof(detail), "inside a new user namespace the read still fails");
    report("escape through a user namespace", code == 1, detail);
}

/* Attempt 5: no_new_privs cannot be turned off. */
static void try_clear_nnp(void)
{
    int before = prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0);
    int rc = prctl(PR_SET_NO_NEW_PRIVS, 0, 0, 0, 0);
    int after = prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0);
    char detail[128];
    snprintf(detail, sizeof(detail), "before=%d set(0) rc=%d errno=%s after=%d",
             before, rc, rc < 0 ? strerror(errno) : "-", after);
    report("turn no_new_privs off", after == 0 && before == 1, detail);
}

/* Attempt 6: reach the secret through a hard link that this program makes
 * inside a directory it may write. Landlock checks the path of the parent
 * directory, so a link out of the hidden tree needs REFER on both sides. */
static void try_link_out(const char *writable_dir)
{
    if (!writable_dir) return;
    char target[512];
    snprintf(target, sizeof(target), "%s/linked-secret", writable_dir);
    unlink(target);
    int rc = link(secret, target);
    char detail[192];
    if (rc < 0) {
        snprintf(detail, sizeof(detail), "link() failed: %s", strerror(errno));
        report("hard-link the secret into a writable dir", 0, detail);
        return;
    }
    int ok = can_read(target);
    snprintf(detail, sizeof(detail), "link() worked; read of the link %s",
             ok ? "WORKED" : "still fails");
    unlink(target);
    report("hard-link the secret into a writable dir", ok, detail);
}

int main(int argc, char **argv)
{
    if (argc < 3) {
        fprintf(stderr, "usage: escape-test SECRET_FILE READABLE_FILE [WRITABLE_DIR]\n");
        return 2;
    }
    secret = argv[1];

    printf("ESCAPE %-34s -> %s\n", "baseline: read the secret",
           can_read(secret) ? "READABLE (the sandbox is not on)" : "BLOCKED");
    printf("ESCAPE %-34s -> %s\n", "baseline: read the allowed file",
           can_read(argv[2]) ? "READABLE (as it should be)" : "BLOCKED (setup error)");
    fflush(stdout);

    try_wider_ruleset();
    try_drop_call();
    try_exec_fresh();
    try_userns();
    try_clear_nnp();
    try_link_out(argc > 3 ? argv[3] : NULL);

    printf("escapes=%d\n", escapes);
    return escapes ? 1 : 0;
}
