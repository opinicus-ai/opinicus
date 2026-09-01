/* tmp_scope — what a ruleset can and cannot subtract inside a writable tree.
 *
 * The shipped floor grants the work tree, /tmp, /var/tmp and /var/cache in
 * full, so a credential-store PATH SHAPE (.ssh, .aws/credentials, ...) that
 * sits under one of those trees is writable there: the rule on the tree
 * reaches everything beneath it. This program measures, on this kernel,
 * every composition the ABI offers for denying such a shape inside a
 * directory that must stay writable:
 *
 *   covering  one full rule on the tree (what the floor ships today);
 *   carve     no rule on the tree, one full rule per entry, no rule on the
 *             shape (what the floor does to $HOME);
 *   layers    two rulesets: the covering one, then a second layer that
 *             carries the carve (layers can only intersect, never relax);
 *   makeonly  one rule on the tree with every MAKE_* right and no
 *             WRITE_FILE/REMOVE_* right ("create but never edit");
 *   bounded   a carve that stops walking before the shape (an enumeration
 *             that is not complete).
 *
 * Every scenario runs in a forked child that restricts itself and only then
 * attempts the operations; the parent collects the lines. No exec happens
 * after the restriction, so no runtime grants are needed.
 *
 * usage: tmp_scope ROOT
 */
#include "landlock_common.h"

#include <sys/stat.h>
#include <sys/wait.h>

static int ABI;
static uint64_t HANDLED; /* every fs right this kernel knows, minus the ones
                          * that need a newer ABI */

static const char *G_TAG; /* scenario tag, so every result line is unique */

static uint64_t rights_full(void)
{
    return HANDLED;
}

static uint64_t rights_make_only(void)
{
    /* Everything a scratch directory needs to GROW, and nothing that
     * rewrites or removes what is there. */
    uint64_t r = LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR |
                 LANDLOCK_ACCESS_FS_EXECUTE | LANDLOCK_ACCESS_FS_MAKE_DIR |
                 LANDLOCK_ACCESS_FS_MAKE_REG | LANDLOCK_ACCESS_FS_MAKE_SYM |
                 LANDLOCK_ACCESS_FS_MAKE_SOCK | LANDLOCK_ACCESS_FS_MAKE_FIFO |
                 LANDLOCK_ACCESS_FS_MAKE_CHAR | LANDLOCK_ACCESS_FS_MAKE_BLOCK;
    if (ABI >= 2)
        r |= LANDLOCK_ACCESS_FS_REFER;
    if (ABI >= 3)
        r |= LANDLOCK_ACCESS_FS_TRUNCATE;
    return r;
}

/* What a rule that names a FILE may carry: no directory right, or the
 * kernel rejects the whole rule with EINVAL (measured by the shipped
 * floor port). */
static uint64_t rights_file(void)
{
    uint64_t r = LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_WRITE_FILE |
                 LANDLOCK_ACCESS_FS_EXECUTE;
    if (ABI >= 3)
        r |= LANDLOCK_ACCESS_FS_TRUNCATE;
    return r;
}

static void die(const char *what)
{
    fprintf(stderr, "tmp_scope: %s: %s\n", what, strerror(errno));
    exit(2);
}

/* One grant of one ruleset. */
static int add_grant(int rs, const char *path, uint64_t rights)
{
    int fd = open(path, O_PATH | O_CLOEXEC);
    if (fd < 0)
        return -1;
    struct landlock_path_beneath_attr pb = {.allowed_access = rights};
    pb.parent_fd = fd;
    int rc = landlock_add_rule(rs, LANDLOCK_RULE_PATH_BENEATH, &pb, 0);
    close(fd);
    return rc;
}

static int make_ruleset(void)
{
    struct afw_ruleset_attr_v attr = {.handled_access_fs = HANDLED};
    int rs = landlock_create_ruleset((struct landlock_ruleset_attr *)&attr,
                                     afw_attr_size_for_abi(ABI), 0);
    if (rs < 0)
        die("landlock_create_ruleset");
    return rs;
}

static void restrict_both(int rs1, int rs2)
{
    prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
    if (landlock_restrict_self(rs1, 0) < 0)
        die("restrict_self layer 1");
    if (rs2 >= 0 && landlock_restrict_self(rs2, 0) < 0)
        die("restrict_self layer 2");
}

/* --- the operations, each reporting one line ---------------------------- */

static void report(const char *name, int rc, int err)
{
    if (rc == 0)
        printf("RESULT %s_%s -> OK\n", G_TAG, name);
    else
        printf("RESULT %s_%s -> FAIL errno=%d\n", G_TAG, name, err);
}

static void op_read(const char *path, const char *label)
{
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        report(label, -1, errno);
        return;
    }
    char buf[8];
    if (read(fd, buf, sizeof buf) < 0)
        report(label, -1, errno);
    else
        report(label, 0, 0);
    close(fd);
}

static void op_write(const char *path, const char *label)
{
    int fd = open(path, O_WRONLY | O_CLOEXEC);
    if (fd < 0) {
        report(label, -1, errno);
        return;
    }
    ssize_t n = write(fd, "x", 1);
    report(label, n == 1 ? 0 : -1, n == 1 ? 0 : errno);
    close(fd);
}

static void op_create(const char *path, const char *label)
{
    int fd = open(path, O_CREAT | O_WRONLY | O_CLOEXEC, 0600);
    if (fd < 0) {
        report(label, -1, errno);
        return;
    }
    ssize_t n = write(fd, "x", 1);
    report(label, n == 1 ? 0 : -1, n == 1 ? 0 : errno);
    close(fd);
}

static void op_append(const char *path, const char *label)
{
    int fd = open(path, O_WRONLY | O_APPEND | O_CLOEXEC);
    if (fd < 0) {
        report(label, -1, errno);
        return;
    }
    ssize_t n = write(fd, "x", 1);
    report(label, n == 1 ? 0 : -1, n == 1 ? 0 : errno);
    close(fd);
}

static void op_mkdir(const char *path, const char *label)
{
    report(label, mkdir(path, 0700), errno);
}

static void op_unlink(const char *path, const char *label)
{
    report(label, unlink(path), errno);
}

/* Runs one child. `setup` builds the ruleset(s) and restricts; the ops
 * after it print one line each. The child never returns. */
static void run_child(void (*restrict_fn)(void), void (*ops_fn)(const char *),
                      const char *root, const char *name)
{
    pid_t pid = fork();
    if (pid < 0)
        die("fork");
    if (pid == 0) {
        printf("\nSCENARIO %s\n", name);
        fflush(stdout);
        G_TAG = name;
        restrict_fn();
        ops_fn(root);
        fflush(stdout);
        _exit(0);
    }
    int status = 0;
    waitpid(pid, &status, 0);
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
        printf("RESULT scenario_%s -> CHILD FAILED status=%d\n", name, status);
    fflush(stdout);
}

/* The tree the scenarios share, rebuilt by the caller between scenarios. */
static const char *G_ROOT;

static void scenario_covering_restrict(void)
{
    int rs = make_ruleset();
    if (add_grant(rs, G_ROOT, rights_full()) < 0)
        die("add grant root");
    restrict_both(rs, -1);
}

static void scenario_covering_ops(const char *root)
{
    char p[4096];
    snprintf(p, sizeof p, "%s/x/.ssh/id_rsa", root);
    op_read(p, "shape_read");
    op_write(p, "shape_write");
    snprintf(p, sizeof p, "%s/n1", root);
    op_mkdir(p, "fresh_dir");
    snprintf(p, sizeof p, "%s/n1/.ssh", root);
    op_mkdir(p, "fresh_shape_dir");
    snprintf(p, sizeof p, "%s/n1/.ssh/id_rsa", root);
    op_create(p, "fresh_shape_file");
}

static void scenario_carve_restrict(void)
{
    int rs = make_ruleset();
    /* No rule on the tree itself; every entry of x/ except .ssh/ gets the
     * full set. notes.txt is granted as a file of its own. */
    if (add_grant(rs, G_ROOT, 0) == 0) {
        printf("RESULT empty_rule_accepted -> OK (unexpected)\n");
    }
    char p[4096];
    snprintf(p, sizeof p, "%s/x/notes.txt", G_ROOT);
    if (add_grant(rs, p, rights_file()) < 0)
        die("add grant notes");
    restrict_both(rs, -1);
}

static void scenario_carve_ops(const char *root)
{
    char p[4096];
    snprintf(p, sizeof p, "%s/x/.ssh/id_rsa", root);
    op_read(p, "shape_read");
    snprintf(p, sizeof p, "%s/x/notes.txt", root);
    op_read(p, "sibling_read");
    op_write(p, "sibling_write");
    snprintf(p, sizeof p, "%s/newdir", root);
    op_mkdir(p, "mkdir_at_root");
    snprintf(p, sizeof p, "%s/x/inner", root);
    op_mkdir(p, "mkdir_in_enumerated");
    snprintf(p, sizeof p, "%s/x/inner/f", root);
    op_create(p, "create_in_enumerated");
}

static void scenario_layers_restrict(void)
{
    int rs1 = make_ruleset();
    if (add_grant(rs1, G_ROOT, rights_full()) < 0)
        die("add grant root layer 1");
    int rs2 = make_ruleset();
    char p[4096];
    snprintf(p, sizeof p, "%s/x/notes.txt", G_ROOT);
    if (add_grant(rs2, p, rights_file()) < 0)
        die("add grant notes layer 2");
    restrict_both(rs1, rs2);
}

static void scenario_layers_ops(const char *root)
{
    char p[4096];
    snprintf(p, sizeof p, "%s/x/.ssh/id_rsa", root);
    op_read(p, "shape_read");
    snprintf(p, sizeof p, "%s/x/notes.txt", root);
    op_read(p, "sibling_read");
    op_write(p, "sibling_write");
    snprintf(p, sizeof p, "%s/newdir", root);
    op_mkdir(p, "mkdir_at_root");
    snprintf(p, sizeof p, "%s/x/fresh", root);
    op_create(p, "create_in_enumerated_parent");
}

static void scenario_makeonly_restrict(void)
{
    int rs = make_ruleset();
    if (add_grant(rs, G_ROOT, rights_make_only()) < 0)
        die("add make-only grant");
    restrict_both(rs, -1);
}

static void scenario_makeonly_ops(const char *root)
{
    char p[4096];
    snprintf(p, sizeof p, "%s/fresh1", root);
    op_create(p, "fresh_create");
    snprintf(p, sizeof p, "%s/pre.txt", root);
    op_write(p, "preexisting_write");
    op_append(p, "preexisting_append");
    op_unlink(p, "preexisting_unlink");
    snprintf(p, sizeof p, "%s/nd", root);
    op_mkdir(p, "fresh_dir");
    snprintf(p, sizeof p, "%s/nd/f2", root);
    op_create(p, "fresh_dir_create");
    op_append(p, "fresh_dir_create_append");
}

static void scenario_bounded_restrict(void)
{
    int rs = make_ruleset();
    char p[4096];
    /* The enumeration walked x/ but not y/z/: full grants one level deep,
     * and the shape under y/z/ stays covered by its parent's grant. */
    snprintf(p, sizeof p, "%s/x", G_ROOT);
    if (add_grant(rs, p, rights_full()) < 0)
        die("add grant x");
    snprintf(p, sizeof p, "%s/y/z", G_ROOT);
    if (add_grant(rs, p, rights_full()) < 0)
        die("add grant y/z");
    restrict_both(rs, -1);
}

static void scenario_bounded_ops(const char *root)
{
    char p[4096];
    snprintf(p, sizeof p, "%s/x/.ssh/id_rsa", root);
    op_read(p, "walked_parent_shape");
    snprintf(p, sizeof p, "%s/y/z/.ssh/id_rsa", root);
    op_read(p, "unwalked_parent_shape");
}

static void make_tree(const char *root)
{
    char p[4096];
    snprintf(p, sizeof p, "%s/x", root);
    if (mkdir(p, 0700) < 0 && errno != EEXIST)
        die("mkdir x");
    snprintf(p, sizeof p, "%s/y", root);
    if (mkdir(p, 0700) < 0 && errno != EEXIST)
        die("mkdir y");
    snprintf(p, sizeof p, "%s/y/z", root);
    if (mkdir(p, 0700) < 0 && errno != EEXIST)
        die("mkdir y/z");
    snprintf(p, sizeof p, "%s/x/.ssh", root);
    if (mkdir(p, 0700) < 0 && errno != EEXIST)
        die("mkdir x/.ssh");
    snprintf(p, sizeof p, "%s/x/.ssh/id_rsa", root);
    if (access(p, F_OK) != 0) {
        FILE *f = fopen(p, "w");
        if (!f)
            die("make id_rsa");
        fputs("PRIVATE", f);
        fclose(f);
    }
    snprintf(p, sizeof p, "%s/x/notes.txt", root);
    if (access(p, F_OK) != 0) {
        FILE *f = fopen(p, "w");
        if (!f)
            die("make notes");
        fputs("notes", f);
        fclose(f);
    }
    snprintf(p, sizeof p, "%s/y/z/.ssh", root);
    if (mkdir(p, 0700) < 0 && errno != EEXIST)
        die("mkdir y/z/.ssh");
    snprintf(p, sizeof p, "%s/y/z/.ssh/id_rsa", root);
    if (access(p, F_OK) != 0) {
        FILE *f = fopen(p, "w");
        if (!f)
            die("make y/z id_rsa");
        fputs("PRIVATE", f);
        fclose(f);
    }
    snprintf(p, sizeof p, "%s/pre.txt", root);
    if (access(p, F_OK) != 0) {
        FILE *f = fopen(p, "w");
        if (!f)
            die("make pre");
        fputs("pre", f);
        fclose(f);
    }
}

int main(int argc, char **argv)
{
    if (argc != 2) {
        fprintf(stderr, "usage: tmp_scope ROOT\n");
        return 2;
    }
    ABI = afw_landlock_abi();
    if (ABI < 1) {
        fprintf(stderr, "tmp_scope: no Landlock on this kernel\n");
        return 2;
    }
    HANDLED = afw_fs_rights_for_abi(ABI) & ~(uint64_t)LANDLOCK_ACCESS_FS_RESOLVE_UNIX;
    G_ROOT = argv[1];

    make_tree(G_ROOT);
    run_child(scenario_covering_restrict, scenario_covering_ops, G_ROOT,
              "covering");
    make_tree(G_ROOT);
    run_child(scenario_carve_restrict, scenario_carve_ops, G_ROOT, "carve");
    make_tree(G_ROOT);
    run_child(scenario_layers_restrict, scenario_layers_ops, G_ROOT, "layers");
    make_tree(G_ROOT);
    run_child(scenario_makeonly_restrict, scenario_makeonly_ops, G_ROOT,
              "makeonly");
    make_tree(G_ROOT);
    run_child(scenario_bounded_restrict, scenario_bounded_ops, G_ROOT,
              "bounded");
    return 0;
}
