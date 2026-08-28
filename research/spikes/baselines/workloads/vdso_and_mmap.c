/*
 * vdso_and_mmap.c - two actions that never reach a system call.
 *
 * A monitor that uses PTRACE_SYSCALL sees every system call of the target.
 * This program tests whether an ordinary action can avoid a system call.
 *
 * Test 1: clock_gettime. The kernel maps the vDSO into every process. The
 *         call runs in user space, so no system call happens.
 * Test 2: a shared memory map of a file. The program changes the content of
 *         the file with a store instruction. The kernel writes the page back
 *         later, and no write system call happens.
 *
 * Usage: vdso_and_mmap MARKER_PATH ROUNDS
 */
#define _GNU_SOURCE

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <time.h>
#include <unistd.h>

int main(int argc, char **argv)
{
    const char *path;
    long rounds;
    long index;
    struct timespec ts;
    unsigned long long sum = 0;
    int fd;
    char *map;
    static const char payload[] = "PAYLOAD-WRITTEN-THROUGH-A-SHARED-MAPPING";

    if (argc < 3) {
        fprintf(stderr, "usage: vdso_and_mmap MARKER_PATH ROUNDS\n");
        return 2;
    }
    path = argv[1];
    rounds = atol(argv[2]);

    /* Test 1. Many clock reads, and no system call for them. */
    for (index = 0; index < rounds; index++) {
        clock_gettime(CLOCK_MONOTONIC, &ts);
        sum += (unsigned long long)ts.tv_nsec;
    }

    /* Test 2. One open, one mmap, and then a change with no write call. */
    fd = open(path, O_RDWR | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) {
        perror("open");
        return 1;
    }
    if (ftruncate(fd, 4096) < 0) {
        perror("ftruncate");
        return 1;
    }
    map = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (map == MAP_FAILED) {
        perror("mmap");
        return 1;
    }
    close(fd);

    memcpy(map, payload, sizeof(payload));
    munmap(map, 4096);

    fprintf(stderr, "vdso_and_mmap rounds=%ld checksum=%llu\n", rounds, sum);
    return 0;
}
