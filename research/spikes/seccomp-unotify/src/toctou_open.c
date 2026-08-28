/*
 * toctou-open - measures how often the path that the supervisor reads is not
 * the path that the kernel opens.
 *
 * The program runs two threads that share one path buffer.
 *
 *   Thread A calls openat on the buffer in a loop.
 *   Thread B writes a different valid path into the same buffer in a loop.
 *
 * Both paths name an ordinary file in the work directory. The two names have
 * the same length and differ in one byte, so thread B writes one byte. That
 * single byte write is atomic, and the buffer therefore always holds a valid
 * path of an existing file. No torn string can make the result look bad.
 *
 * Correlation with the supervisor is exact, and does not depend on order.
 * The fourth argument of openat is the file mode. The kernel ignores it when
 * the flags hold no O_CREAT, but seccomp still reports it in args[3]. Thread A
 * puts a sequence number there. The supervisor writes that number in its log,
 * so each notification joins exactly one loop step.
 *
 * The ground truth is the file that the process really holds. The program
 * reads /proc/self/fd/<n> after each open. That link comes from the kernel,
 * and not from the buffer.
 *
 * Usage:
 *   toctou-open --dir DIR --iters N --out FILE [--writer|--no-writer]
 *
 * Output lines in FILE:  <seq> <a|b|?|E> <errno>
 */

#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

/* The sequence numbers start high, so that they cannot collide with a real
 * file mode such as 0644 that another openat of the program uses. */
#define SEQ_BASE 1000000ULL

static char g_shared[PATH_MAX];
static volatile char *g_flip;          /* the one byte that thread B writes */
static atomic_int g_run = 1;

struct record {
    unsigned long long seq;
    char actual;
    int err;
};

static void *writer(void *arg)
{
    (void)arg;
    while (atomic_load_explicit(&g_run, memory_order_relaxed)) {
        *g_flip = 'b';
        *g_flip = 'a';
    }
    return NULL;
}

int main(int argc, char **argv)
{
    const char *dir = NULL;
    const char *out = NULL;
    long iters = 2000;
    int use_writer = 1;

    for (int i = 1; i < argc; i++) {
        if (strncmp(argv[i], "--dir=", 6) == 0) {
            dir = argv[i] + 6;
        } else if (strncmp(argv[i], "--out=", 6) == 0) {
            out = argv[i] + 6;
        } else if (strncmp(argv[i], "--iters=", 8) == 0) {
            iters = atol(argv[i] + 8);
        } else if (strcmp(argv[i], "--no-writer") == 0) {
            use_writer = 0;
        } else if (strcmp(argv[i], "--writer") == 0) {
            use_writer = 1;
        } else {
            fprintf(stderr, "toctou-open: bad option %s\n", argv[i]);
            return 2;
        }
    }
    if (dir == NULL || out == NULL) {
        fprintf(stderr, "usage: toctou-open --dir=DIR --out=FILE "
                        "[--iters=N] [--no-writer]\n");
        return 2;
    }

    /* The output file opens before the loop, so that the writes of the
     * result do not add notifications in the middle of the measurement. */
    int out_fd = open(out, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (out_fd < 0) {
        perror("toctou-open: open(out)");
        return 2;
    }

    int n = snprintf(g_shared, sizeof(g_shared), "%s/f_a.txt", dir);
    if (n <= 0 || (size_t)n >= sizeof(g_shared)) {
        fprintf(stderr, "toctou-open: the directory name is too long\n");
        return 2;
    }
    /* The letter sits 5 bytes before the end: ".../f_X.txt". */
    g_flip = &g_shared[n - 5];
    if (*g_flip != 'a') {
        fprintf(stderr, "toctou-open: the flip byte is wrong\n");
        return 2;
    }

    struct record *rec = calloc((size_t)iters, sizeof(*rec));
    if (rec == NULL) {
        perror("calloc");
        return 2;
    }

    pthread_t tid;
    if (use_writer && pthread_create(&tid, NULL, writer, NULL) != 0) {
        perror("pthread_create");
        return 2;
    }

    char link[PATH_MAX];
    char target[PATH_MAX];

    for (long i = 0; i < iters; i++) {
        unsigned long long seq = SEQ_BASE + (unsigned long long)i;
        long fd = syscall(SYS_openat, AT_FDCWD, g_shared, O_RDONLY,
                          (long)seq);
        rec[i].seq = seq;
        if (fd < 0) {
            rec[i].actual = 'E';
            rec[i].err = errno;
            continue;
        }
        rec[i].err = 0;
        snprintf(link, sizeof(link), "/proc/self/fd/%ld", fd);
        ssize_t got = readlink(link, target, sizeof(target) - 1);
        if (got <= 0) {
            rec[i].actual = '?';
        } else {
            target[got] = '\0';
            size_t len = (size_t)got;
            /* The name ends with "f_X.txt". */
            if (len >= 7) {
                rec[i].actual = target[len - 5];
            } else {
                rec[i].actual = '?';
            }
        }
        close((int)fd);
    }

    atomic_store(&g_run, 0);
    if (use_writer) {
        pthread_join(tid, NULL);
    }

    FILE *f = fdopen(out_fd, "w");
    if (f == NULL) {
        perror("fdopen");
        return 2;
    }
    for (long i = 0; i < iters; i++) {
        fprintf(f, "%llu %c %d\n", rec[i].seq, rec[i].actual, rec[i].err);
    }
    fclose(f);
    free(rec);
    return 0;
}
