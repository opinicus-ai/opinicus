/*
 * toctou-execve - the same race, on the program start boundary.
 *
 * The path of the program lives in a shared anonymous mapping. A fork keeps
 * that mapping shared, so a thread in the parent can write into the buffer
 * that the child gives to execve. The child is single threaded, which is the
 * normal case for a program start, and the race still works.
 *
 * The ground truth needs no log: p_a is a copy of /bin/true and exits with 0,
 * p_b is a copy of /bin/false and exits with 1. The exit status says which
 * program the kernel really ran.
 *
 * Usage:
 *   toctou-execve --dir DIR --iters N --out FILE
 *
 * Output lines in FILE:  <seq> <a|b|E> <exit status>
 */

#define _GNU_SOURCE

#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>

static char *g_shared;
static volatile char *g_flip;
static atomic_int g_run = 1;

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
    long iters = 300;

    for (int i = 1; i < argc; i++) {
        if (strncmp(argv[i], "--dir=", 6) == 0) {
            dir = argv[i] + 6;
        } else if (strncmp(argv[i], "--out=", 6) == 0) {
            out = argv[i] + 6;
        } else if (strncmp(argv[i], "--iters=", 8) == 0) {
            iters = atol(argv[i] + 8);
        } else {
            fprintf(stderr, "toctou-execve: bad option %s\n", argv[i]);
            return 2;
        }
    }
    if (dir == NULL || out == NULL) {
        fprintf(stderr, "usage: toctou-execve --dir=DIR --out=FILE "
                        "[--iters=N]\n");
        return 2;
    }

    FILE *f = fopen(out, "w");
    if (f == NULL) {
        perror("toctou-execve: fopen(out)");
        return 2;
    }

    g_shared = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                    MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (g_shared == MAP_FAILED) {
        perror("mmap");
        return 2;
    }
    int n = snprintf(g_shared, 4096, "%s/p_a", dir);
    if (n <= 0) {
        return 2;
    }
    g_flip = &g_shared[n - 1];

    pthread_t tid;
    if (pthread_create(&tid, NULL, writer, NULL) != 0) {
        perror("pthread_create");
        return 2;
    }

    char *const child_argv[] = { (char *)"p", NULL };
    char *const child_env[] = { NULL };

    for (long i = 0; i < iters; i++) {
        pid_t pid = fork();
        if (pid < 0) {
            perror("fork");
            break;
        }
        if (pid == 0) {
            execve(g_shared, child_argv, child_env);
            _exit(127);
        }
        int status = 0;
        waitpid(pid, &status, 0);
        int code = WIFEXITED(status) ? WEXITSTATUS(status) : -1;
        char actual = 'E';
        if (code == 0) {
            actual = 'a';   /* /bin/true ran */
        } else if (code == 1) {
            actual = 'b';   /* /bin/false ran */
        }
        fprintf(f, "%ld %c %d\n", i, actual, code);
    }

    atomic_store(&g_run, 0);
    pthread_join(tid, NULL);
    fclose(f);
    return 0;
}
