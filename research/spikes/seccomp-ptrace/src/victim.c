/* victim: a target that keeps making one traced system call.
 *
 * The program opens a file again and again and reports the result of each
 * try. A supervisor that leaves during the run makes the open fail with
 * ENOSYS, because a SECCOMP_RET_TRACE with no tracer skips the call. The
 * output therefore shows exactly what a restart of the firewall costs.
 *
 * Usage: victim <path> <iterations> <sleep_ms>
 */
#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <string.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

/* The kernel structure of openat2. The flags sit inside it, behind a
 * pointer, so a seccomp BPF filter cannot read them.
 */
struct afw_open_how {
    unsigned long long flags;
    unsigned long long mode;
    unsigned long long resolve;
};

/* Opens a file with openat2, so that the pointer limit of BPF can be shown. */
static int run_openat2(const char *path)
{
    struct afw_open_how how;
    long fd;

    memset(&how, 0, sizeof(how));
    how.flags = (unsigned long long)(O_WRONLY | O_CREAT);
    how.mode = 0644;
    fd = syscall(SYS_openat2, AT_FDCWD, path, &how, sizeof(how));
    if (fd < 0) {
        printf("openat2 result=errno_%d\n", errno);
        return 1;
    }
    printf("openat2 result=ok\n");
    close((int)fd);
    return 0;
}

/* A shared buffer that two threads use at the same time.
 *
 * The supervisor reads the path of the call out of this buffer at the
 * seccomp stop. The kernel reads the same buffer a second time when the
 * call really runs. A second thread that changes the buffer between the two
 * reads can therefore show one path to the supervisor and give another one
 * to the kernel. The `volatile` keyword only stops the compiler from
 * removing the writes; the race is the point of the test.
 */
static volatile char g_shared_path[256];
static volatile int g_race_stop;

static void *flip_thread(void *argument)
{
    const char **names = (const char **)argument;

    while (!g_race_stop) {
        memcpy((void *)g_shared_path, names[0], strlen(names[0]) + 1);
        memcpy((void *)g_shared_path, names[1], strlen(names[1]) + 1);
    }
    return NULL;
}

/* Tries to delete `target` while the buffer often shows `decoy`. */
static int run_race(const char *decoy, const char *target, long iterations)
{
    pthread_t thread;
    const char *names[2];
    long index;
    long deleted = 0;

    if (strlen(decoy) != strlen(target)) {
        printf("race result=bad_setup\n");
        return 2;
    }
    names[0] = decoy;
    names[1] = target;
    memcpy((void *)g_shared_path, decoy, strlen(decoy) + 1);
    if (pthread_create(&thread, NULL, flip_thread, names) != 0) {
        printf("race result=no_thread\n");
        return 2;
    }
    for (index = 0; index < iterations; index++) {
        if (syscall(SYS_unlinkat, AT_FDCWD, (const char *)g_shared_path, 0) == 0)
            deleted++;
        if (access(target, F_OK) != 0)
            break;
    }
    g_race_stop = 1;
    pthread_join(thread, NULL);
    printf("race tries=%ld deleted=%ld target_gone=%d\n", index, deleted,
           access(target, F_OK) != 0 ? 1 : 0);
    return 0;
}

int main(int argc, char **argv)
{
    const char *path;
    long iterations;
    long sleep_ms;
    long ok = 0;
    long enosys = 0;
    long other = 0;
    long index;

    setvbuf(stdout, NULL, _IOLBF, 0);
    if (argc > 2 && strcmp(argv[1], "--openat2") == 0)
        return run_openat2(argv[2]);
    if (argc > 4 && strcmp(argv[1], "--race") == 0)
        return run_race(argv[2], argv[3], atol(argv[4]));

    path = argc > 1 ? argv[1] : "/etc/hostname";
    iterations = argc > 2 ? atol(argv[2]) : 10;
    sleep_ms = argc > 3 ? atol(argv[3]) : 50;

    for (index = 0; index < iterations; index++) {
        struct timespec pause;
        int fd = open(path, O_RDONLY);

        if (fd >= 0) {
            ok++;
            printf("try=%ld result=ok\n", index);
            close(fd);
        } else if (errno == ENOSYS) {
            enosys++;
            printf("try=%ld result=enosys\n", index);
        } else {
            other++;
            printf("try=%ld result=errno_%d\n", index, errno);
        }
        pause.tv_sec = sleep_ms / 1000;
        pause.tv_nsec = (sleep_ms % 1000) * 1000000L;
        nanosleep(&pause, NULL);
    }
    printf("summary ok=%ld enosys=%ld other=%ld\n", ok, enosys, other);
    return 0;
}
