/*
 * marker_static.c - a statically linked workload with no dynamic linker.
 *
 * Fedora 43 has no static glibc package, and this spike has no root to
 * install one. The program therefore uses no library at all: it has its own
 * entry point and it reaches the kernel with the syscall instruction.
 *
 * The result is an ELF file with no INTERP segment. The dynamic linker never
 * runs, so LD_PRELOAD can inject nothing. This is the same property that any
 * static Go binary, any static Rust musl binary and /usr/sbin/ldconfig have.
 *
 * Build: gcc -static -no-pie -nostdlib -nostartfiles -fno-stack-protector
 *
 * Usage: marker_static MARKER_PATH
 */

#define SYS_write 1
#define SYS_openat 257
#define SYS_close 3
#define SYS_exit_group 231
#define AT_FDCWD (-100)
#define O_WRONLY 1
#define O_CREAT 64
#define O_TRUNC 512

static long syscall3(long number, long a, long b, long c)
{
    long result;

    __asm__ volatile("syscall"
                     : "=a"(result)
                     : "a"(number), "D"(a), "S"(b), "d"(c)
                     : "rcx", "r11", "memory");
    return result;
}

static long syscall4(long number, long a, long b, long c, long d)
{
    long result;
    register long r10 __asm__("r10") = d;

    __asm__ volatile("syscall"
                     : "=a"(result)
                     : "a"(number), "D"(a), "S"(b), "d"(c), "r"(r10)
                     : "rcx", "r11", "memory");
    return result;
}

void c_start(long argc, char **argv) __attribute__((noreturn));

void c_start(long argc, char **argv)
{
    static const char text[] = "marker written by a static program\n";
    long fd;

    if (argc < 2) {
        syscall3(SYS_exit_group, 2, 0, 0);
        __builtin_unreachable();
    }

    fd = syscall4(SYS_openat, AT_FDCWD, (long)argv[1],
                  O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd >= 0) {
        syscall3(SYS_write, fd, (long)text, (long)(sizeof(text) - 1));
        syscall3(SYS_close, fd, 0, 0);
        syscall3(SYS_exit_group, 0, 0, 0);
    }
    syscall3(SYS_exit_group, 1, 0, 0);
    __builtin_unreachable();
}

__asm__(".text\n"
        ".globl _start\n"
        ".type _start,@function\n"
        "_start:\n"
        "  xor %rbp, %rbp\n"
        "  mov (%rsp), %rdi\n"
        "  lea 8(%rsp), %rsi\n"
        "  and $-16, %rsp\n"
        "  call c_start\n"
        "  hlt\n");
