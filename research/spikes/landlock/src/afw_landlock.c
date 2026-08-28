/* afw-landlock — a Landlock sandbox launcher for the Agent Firewall spike.
 *
 * It builds a Landlock ruleset from the command line, forks, applies the
 * ruleset to the CHILD, and then the child calls execve(). The launcher
 * process itself is never restricted, because landlock_restrict_self() can
 * never be undone.
 *
 * Landlock is an allow list. A ruleset names the rights it handles, and
 * every handled right is denied everywhere, except under a path that a rule
 * grants. There is no deny rule. To keep one subtree unreadable inside a
 * readable parent, the launcher "carves out": it walks from the granted
 * directory down to the hidden one, and grants each sibling on the way, but
 * never the hidden path itself. --hide does that.
 *
 * Usage:
 *   afw-landlock [options] -- COMMAND [ARG...]
 *
 * Options:
 *   --ro PATH            read and list and execute under PATH
 *   --rw PATH            read and write and create and delete under PATH
 *   --rw-noexec PATH     the same, but no program may start from PATH
 *   --rx PATH            read and execute under PATH, no write
 *   --hide PATH          carve PATH out of every grant above it
 *   --connect-tcp PORT   allow connect() to this TCP port
 *   --bind-tcp PORT      allow bind() to this TCP port
 *   --handle-net         handle the TCP rights; with no --connect-tcp every
 *                        connect is denied
 *   --scope-signal       deny signals to a process outside the sandbox
 *   --no-sandbox         fork and exec with no ruleset (for the benchmark)
 *   --verbose            print the ruleset to stderr
 */
#include "landlock_common.h"

#include <dirent.h>
#include <limits.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>

#define MAX_PATHS 256
#define MAX_PORTS 32

enum grant_kind { G_RO, G_RW, G_RX, G_RW_NX };

struct grant {
    char path[PATH_MAX];
    enum grant_kind kind;
};

static struct grant grants[MAX_PATHS];
static size_t n_grants;
static char hides[MAX_PATHS][PATH_MAX];
static size_t n_hides;
static uint16_t connect_ports[MAX_PORTS];
static size_t n_connect_ports;
static uint16_t bind_ports[MAX_PORTS];
static size_t n_bind_ports;
static int handle_net;
static int scope_signal;
static int no_sandbox;
static int verbose;
static int abi;
static long n_rules;      /* how many path rules the carve-out really made */
static int print_stats;

static uint64_t FS_READ;   /* read a file, list a directory, execute */
static uint64_t FS_EXEC;
static uint64_t FS_WRITE;  /* everything that changes the tree */

static void die(const char *what)
{
    fprintf(stderr, "afw-landlock: %s: %s\n", what, strerror(errno));
    exit(2);
}

static void set_masks(void)
{
    FS_READ = LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR;
    FS_EXEC = LANDLOCK_ACCESS_FS_EXECUTE;
    FS_WRITE = LANDLOCK_ACCESS_FS_WRITE_FILE | LANDLOCK_ACCESS_FS_REMOVE_DIR |
               LANDLOCK_ACCESS_FS_REMOVE_FILE | LANDLOCK_ACCESS_FS_MAKE_CHAR |
               LANDLOCK_ACCESS_FS_MAKE_DIR | LANDLOCK_ACCESS_FS_MAKE_REG |
               LANDLOCK_ACCESS_FS_MAKE_SOCK | LANDLOCK_ACCESS_FS_MAKE_FIFO |
               LANDLOCK_ACCESS_FS_MAKE_BLOCK | LANDLOCK_ACCESS_FS_MAKE_SYM;
    if (abi >= 2)
        FS_WRITE |= LANDLOCK_ACCESS_FS_REFER;
    if (abi >= 3)
        FS_WRITE |= LANDLOCK_ACCESS_FS_TRUNCATE;
    if (abi >= 5)
        FS_READ |= LANDLOCK_ACCESS_FS_IOCTL_DEV;
}

static uint64_t rights_of(enum grant_kind kind)
{
    switch (kind) {
    case G_RO: return FS_READ;
    case G_RX: return FS_READ | FS_EXEC;
    case G_RW: return FS_READ | FS_EXEC | FS_WRITE;
    case G_RW_NX: return FS_READ | FS_WRITE;
    }
    return 0;
}

/* Makes a path absolute and removes symbolic links, so that a grant and a
 * hide can be compared as text. A path that does not exist keeps its text. */
static void canon(const char *in, char *out)
{
    char *real = realpath(in, NULL);
    if (real) {
        snprintf(out, PATH_MAX, "%s", real);
        free(real);
        return;
    }
    if (in[0] == '/') {
        snprintf(out, PATH_MAX, "%s", in);
        return;
    }
    char cwd[PATH_MAX];
    if (!getcwd(cwd, sizeof(cwd)))
        die("getcwd");
    size_t cwd_len = strlen(cwd);
    size_t in_len = strlen(in);
    if (cwd_len + 1 + in_len + 1 > PATH_MAX) {
        fprintf(stderr, "afw-landlock: path is too long: %s\n", in);
        exit(2);
    }
    memcpy(out, cwd, cwd_len);
    out[cwd_len] = '/';
    memcpy(out + cwd_len + 1, in, in_len + 1);
}

/* True when `child` is `parent` or is below it. */
static int is_beneath(const char *parent, const char *child)
{
    size_t len = strlen(parent);
    if (strcmp(parent, "/") == 0)
        return 1;
    if (strncmp(parent, child, len) != 0)
        return 0;
    return child[len] == '\0' || child[len] == '/';
}

static int add_path_rule(int ruleset_fd, const char *path, uint64_t rights)
{
    struct landlock_path_beneath_attr attr = {.allowed_access = rights};
    int fd = open(path, O_PATH | O_CLOEXEC);
    if (fd < 0) {
        if (verbose)
            fprintf(stderr, "  skip  %-50s (%s)\n", path, strerror(errno));
        return 0; /* a path that is not there needs no rule */
    }
    attr.parent_fd = fd;
    /* A regular file can never carry a directory right. The kernel rejects
     * the whole rule if it does, so trim the mask for a file. */
    struct stat st;
    if (fstat(fd, &st) == 0 && !S_ISDIR(st.st_mode))
        attr.allowed_access &= ~(LANDLOCK_ACCESS_FS_READ_DIR |
                                 LANDLOCK_ACCESS_FS_REMOVE_DIR |
                                 LANDLOCK_ACCESS_FS_REMOVE_FILE |
                                 LANDLOCK_ACCESS_FS_MAKE_CHAR |
                                 LANDLOCK_ACCESS_FS_MAKE_DIR |
                                 LANDLOCK_ACCESS_FS_MAKE_REG |
                                 LANDLOCK_ACCESS_FS_MAKE_SOCK |
                                 LANDLOCK_ACCESS_FS_MAKE_FIFO |
                                 LANDLOCK_ACCESS_FS_MAKE_BLOCK |
                                 LANDLOCK_ACCESS_FS_MAKE_SYM |
                                 LANDLOCK_ACCESS_FS_REFER);
    int rc = landlock_add_rule(ruleset_fd, LANDLOCK_RULE_PATH_BENEATH, &attr, 0);
    int saved = errno;
    close(fd);
    if (rc < 0) {
        errno = saved;
        return -1;
    }
    n_rules++;
    if (verbose)
        fprintf(stderr, "  grant %-50s 0x%llx\n", path,
                (unsigned long long)attr.allowed_access);
    return 0;
}

/* Grants `dir` with `rights`, but leaves every hidden path out.
 *
 * When no hidden path is below `dir`, one rule is enough. When one is, the
 * function grants every entry of `dir` on its own, and it calls itself for
 * the entry that still holds a hidden path below it. The hidden path itself
 * gets no rule, so every handled right on it stays denied.
 */
static int grant_except(int ruleset_fd, const char *dir, uint64_t rights, int depth)
{
    int has_hidden = 0;
    for (size_t i = 0; i < n_hides; i++)
        if (is_beneath(dir, hides[i]) && strcmp(dir, hides[i]) != 0)
            has_hidden = 1;
    for (size_t i = 0; i < n_hides; i++)
        if (strcmp(dir, hides[i]) == 0)
            return 0; /* this is the hidden path; grant nothing */

    if (!has_hidden || depth > 24)
        return add_path_rule(ruleset_fd, dir, rights);

    DIR *d = opendir(dir);
    if (!d)
        return add_path_rule(ruleset_fd, dir, rights);

    struct dirent *ent;
    while ((ent = readdir(d))) {
        if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0)
            continue;
        char child[PATH_MAX];
        int n = snprintf(child, sizeof(child), "%s/%s",
                         strcmp(dir, "/") == 0 ? "" : dir, ent->d_name);
        if (n < 0 || (size_t)n >= sizeof(child))
            continue;
        if (grant_except(ruleset_fd, child, rights, depth + 1) < 0) {
            closedir(d);
            return -1;
        }
    }
    closedir(d);
    return 0;
}

static void usage(void)
{
    fprintf(stderr,
            "usage: afw-landlock [--ro P] [--rw P] [--rx P] [--rw-noexec P] [--hide P]\n"
            "                    [--handle-net] [--connect-tcp N] [--bind-tcp N]\n"
            "                    [--scope-signal] [--no-sandbox] [--verbose] [--stats]\n"
            "                    -- COMMAND [ARG...]\n");
    exit(2);
}

int main(int argc, char **argv)
{
    int i = 1;
    for (; i < argc; i++) {
        const char *a = argv[i];
        if (strcmp(a, "--") == 0) { i++; break; }
        else if (strcmp(a, "--ro") == 0 || strcmp(a, "--rw") == 0 ||
                 strcmp(a, "--rx") == 0 || strcmp(a, "--rw-noexec") == 0) {
            if (i + 1 >= argc || n_grants >= MAX_PATHS) usage();
            if (strcmp(a, "--ro") == 0) grants[n_grants].kind = G_RO;
            else if (strcmp(a, "--rx") == 0) grants[n_grants].kind = G_RX;
            else if (strcmp(a, "--rw") == 0) grants[n_grants].kind = G_RW;
            else grants[n_grants].kind = G_RW_NX;
            canon(argv[++i], grants[n_grants].path);
            n_grants++;
        } else if (strcmp(a, "--hide") == 0) {
            if (i + 1 >= argc || n_hides >= MAX_PATHS) usage();
            canon(argv[++i], hides[n_hides++]);
        } else if (strcmp(a, "--connect-tcp") == 0) {
            if (i + 1 >= argc || n_connect_ports >= MAX_PORTS) usage();
            connect_ports[n_connect_ports++] = (uint16_t)atoi(argv[++i]);
            handle_net = 1;
        } else if (strcmp(a, "--bind-tcp") == 0) {
            if (i + 1 >= argc || n_bind_ports >= MAX_PORTS) usage();
            bind_ports[n_bind_ports++] = (uint16_t)atoi(argv[++i]);
            handle_net = 1;
        } else if (strcmp(a, "--handle-net") == 0) handle_net = 1;
        else if (strcmp(a, "--scope-signal") == 0) scope_signal = 1;
        else if (strcmp(a, "--no-sandbox") == 0) no_sandbox = 1;
        else if (strcmp(a, "--verbose") == 0) verbose = 1;
        else if (strcmp(a, "--stats") == 0) print_stats = 1;
        else usage();
    }
    if (i >= argc) usage();
    char **target = &argv[i];

    abi = afw_landlock_abi();
    if (abi < 0 && !no_sandbox) {
        fprintf(stderr, "afw-landlock: no landlock on this kernel: %s\n",
                strerror(-abi));
        return 2;
    }
    set_masks();

    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);

    int ruleset_fd = -1;
    if (!no_sandbox) {
        struct afw_ruleset_attr_v attr = {0};
        attr.handled_access_fs = afw_fs_rights_for_abi(abi) &
                                 ~LANDLOCK_ACCESS_FS_RESOLVE_UNIX;
        if (handle_net && abi >= 4)
            attr.handled_access_net = afw_net_rights_for_abi(abi);
        if (scope_signal && abi >= 6)
            attr.scoped = LANDLOCK_SCOPE_SIGNAL;

        ruleset_fd = landlock_create_ruleset((struct landlock_ruleset_attr *)&attr,
                                             afw_attr_size_for_abi(abi), 0);
        if (ruleset_fd < 0)
            die("landlock_create_ruleset");
        if (verbose)
            fprintf(stderr, "afw-landlock: abi=%d handled_fs=0x%llx handled_net=0x%llx scoped=0x%llx\n",
                    abi, (unsigned long long)attr.handled_access_fs,
                    (unsigned long long)attr.handled_access_net,
                    (unsigned long long)attr.scoped);

        for (size_t g = 0; g < n_grants; g++)
            if (grant_except(ruleset_fd, grants[g].path, rights_of(grants[g].kind), 0) < 0)
                die("landlock_add_rule");

        for (size_t p = 0; p < n_connect_ports; p++) {
            struct landlock_net_port_attr np = {
                .allowed_access = LANDLOCK_ACCESS_NET_CONNECT_TCP,
                .port = connect_ports[p]};
            if (landlock_add_rule(ruleset_fd, LANDLOCK_RULE_NET_PORT, &np, 0) < 0)
                die("landlock_add_rule net connect");
            if (verbose)
                fprintf(stderr, "  grant connect tcp/%u\n", connect_ports[p]);
        }
        for (size_t p = 0; p < n_bind_ports; p++) {
            struct landlock_net_port_attr np = {
                .allowed_access = LANDLOCK_ACCESS_NET_BIND_TCP,
                .port = bind_ports[p]};
            if (landlock_add_rule(ruleset_fd, LANDLOCK_RULE_NET_PORT, &np, 0) < 0)
                die("landlock_add_rule net bind");
            if (verbose)
                fprintf(stderr, "  grant bind tcp/%u\n", bind_ports[p]);
        }
    }

    clock_gettime(CLOCK_MONOTONIC, &t1);
    if (print_stats)
        fprintf(stderr, "afw-landlock: rules=%ld setup_us=%ld\n", n_rules,
                (t1.tv_sec - t0.tv_sec) * 1000000 +
                    (t1.tv_nsec - t0.tv_nsec) / 1000);

    /* The ruleset goes on the CHILD only. The launcher keeps every right,
     * because landlock_restrict_self() cannot be undone. */
    pid_t pid = fork();
    if (pid < 0)
        die("fork");
    if (pid == 0) {
        if (ruleset_fd >= 0) {
            if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0) {
                fprintf(stderr, "afw-landlock: no_new_privs: %s\n", strerror(errno));
                _exit(2);
            }
            if (landlock_restrict_self(ruleset_fd, 0) < 0) {
                fprintf(stderr, "afw-landlock: landlock_restrict_self: %s\n",
                        strerror(errno));
                _exit(2);
            }
            close(ruleset_fd);
        }
        execvp(target[0], target);
        fprintf(stderr, "afw-landlock: exec %s: %s\n", target[0], strerror(errno));
        _exit(127);
    }
    if (ruleset_fd >= 0)
        close(ruleset_fd);

    int status = 0;
    if (waitpid(pid, &status, 0) < 0)
        die("waitpid");
    if (WIFSIGNALED(status))
        return 128 + WTERMSIG(status);
    return WEXITSTATUS(status);
}
