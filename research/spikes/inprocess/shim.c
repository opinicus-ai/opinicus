/*
 * shim.c — the in-process sensor of M2 ([af-2], DIRECTION.md §3.1).
 *
 * An LD_PRELOAD library that interposes the exec family, file access,
 * network libc calls, dlopen and environment manipulation, and writes one
 * JSON line per observed action to a trace file. The lines are af-core
 * `Event` values: the schema the recorder writes, so
 * `agent-firewall tree <trace>` validates a sensor trace.
 *
 * It reports. It never decides, never refuses, never rewrites a call.
 * That is the rule of DIRECTION.md §3.1 and of the decision log: a sensor
 * is not a boundary.
 *
 * Event timing. An exec event is written before the call: it is intent,
 * "this process is about to run that program", which is the semantic an
 * outside observer cannot have. It can therefore describe an exec that
 * then fails. Every other event is written after the real call succeeded,
 * so it describes an action that happened.
 *
 * Propagation. LD_PRELOAD and the AF_SENSOR_* variables are ordinary
 * environment, so every child that inherits the environment and uses the
 * dynamic linker loads the shim and registers itself. A static binary, a
 * setuid program or a process that strips its environment never loads it —
 * measured in research/spikes/baselines/ and research/bypass/.
 *
 * Registration record. Every instance appends a `sensor_register` line to
 * the file named by AF_SENSOR_REG (instance id, pid, ppid, exe, session,
 * time), refreshes a `sensor_heartbeat` line while it lives and talks, and
 * appends `sensor_exit` when it ends. The writes are single raw `write`
 * calls to an O_APPEND descriptor, so the record survives the death of the
 * writing process — the failure that research/bypass/ found in the
 * monitor's own buffered recorder. This is the B.5 fact that M4 and M5 key
 * on: the firewall knows exactly which sensor instances it installed.
 *
 * Environment:
 *   AF_SENSOR_TRACE   path of the JSONL event trace; unset means no trace
 *   AF_SENSOR_REG     path of the registration record; unset means no record
 *   AF_SENSOR_SESSION session id carried by every event; default "sensor"
 *
 * The logger uses raw system calls only, so a hooked libc function never
 * re-enters this library.
 */
#define _GNU_SOURCE

#include <arpa/inet.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#define LINE_MAX_ 4096
#define PATH_MAX_ 256
#define DATA_MAX 256
#define CAPTURE_TABLE 64
#define HEARTBEAT_MS 1000
#define STDIN_CAPTURE_MAX 4

/* ------------------------------------------------------------------ */
/* State of one sensor instance                                        */
/* ------------------------------------------------------------------ */

/* One capture target: a small regular file whose content the sensor may
 * read back. Keyed either by descriptor (open/openat/read path) or by the
 * FILE pointer (fopen/fgets/fread path). */
typedef struct {
    int in_use;
    int is_file; /* 0: keyed by fd, 1: keyed by FILE* */
    int fd;
    void *file;
    int taken; /* bytes already captured for this file */
    char path[PATH_MAX_];
} cap_slot;

static cap_slot g_caps[CAPTURE_TABLE * 2];

static int g_trace_fd = -1;
static int g_reg_fd = -1;
static int g_trace_tried;
static int g_reg_tried;
static char g_session[96] = "sensor";
static char g_instance[64];
static char g_exe[PATH_MAX_];
static char g_comm[96];
static long long g_start_ticks;
static int g_pid;
static int g_ppid;
static unsigned g_seq;
static int g_stdin_captured;
static volatile long long g_last_reg_write_ms;
static volatile int g_beat_started;

typedef int (*open_fn)(const char *, int, ...);
typedef int (*openat_fn)(int, const char *, int, ...);
typedef FILE *(*fopen_fn)(const char *, const char *);
typedef int (*creat_fn)(const char *, mode_t);
typedef int (*close_fn)(int);
typedef int (*unlink_fn)(const char *);
typedef int (*unlinkat_fn)(int, const char *, int);
typedef int (*rmdir_fn)(const char *);
typedef int (*rename_fn)(const char *, const char *);
typedef int (*renameat_fn)(int, const char *, int, const char *);
typedef int (*renameat2_fn)(int, const char *, int, const char *, unsigned);
typedef int (*connect_fn)(int, const struct sockaddr *, socklen_t);
typedef void *(*dlopen_fn)(const char *, int);
typedef void *(*dlmopen_fn)(long, const char *, int);
typedef int (*setenv_fn)(const char *, const char *, int);
typedef int (*unsetenv_fn)(const char *);
typedef int (*putenv_fn)(char *);
typedef int (*execve_fn)(const char *, char *const[], char *const[]);
typedef int (*execvp_fn)(const char *, char *const[]);
typedef ssize_t (*read_fn)(int, void *, size_t);
typedef size_t (*fread_fn)(void *, size_t, size_t, FILE *);
typedef char *(*fgets_fn)(char *, int, FILE *);
typedef int (*fclose_fn)(FILE *);

static open_fn real_open;
static openat_fn real_openat;
static fopen_fn real_fopen;
static creat_fn real_creat;
static close_fn real_close;
static unlink_fn real_unlink;
static unlinkat_fn real_unlinkat;
static rmdir_fn real_rmdir;
static rename_fn real_rename;
static renameat_fn real_renameat;
static renameat2_fn real_renameat2;
static connect_fn real_connect;
static dlopen_fn real_dlopen;
static dlmopen_fn real_dlmopen;
static setenv_fn real_setenv;
static unsetenv_fn real_unsetenv;
static putenv_fn real_putenv;
static execve_fn real_execve;
static execvp_fn real_execvp;
static read_fn real_read;
static fread_fn real_fread;
static fgets_fn real_fgets;
static fclose_fn real_fclose;

/* ------------------------------------------------------------------ */
/* Raw syscall helpers                                                 */
/* ------------------------------------------------------------------ */

static long raw_write(int fd, const void *buf, size_t n)
{
    return syscall(SYS_write, fd, buf, n);
}

static int raw_open_append(const char *path)
{
    long fd = syscall(SYS_openat, AT_FDCWD, path,
                      O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0644);
    if (fd < 0) {
        return -1;
    }
    /* Move the descriptor high, with close-on-exec, so it cannot collide
     * with a descriptor the program expects. One event then costs one
     * write, not an open, a write and a close. */
    long moved = syscall(SYS_fcntl, fd, F_DUPFD_CLOEXEC, 900);
    if (moved >= 0) {
        syscall(SYS_close, fd);
        return (int)moved;
    }
    return (int)fd;
}

static long long now_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (long long)ts.tv_sec * 1000000000LL + ts.tv_nsec;
}

static long long mono_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long long)ts.tv_sec * 1000LL + ts.tv_nsec / 1000000LL;
}

/* ------------------------------------------------------------------ */
/* JSON helpers                                                        */
/* ------------------------------------------------------------------ */

/* Appends at most `max` bytes of `s` as one JSON string (with quotes and
 * escapes) into the buffer that `*p` ends, truncating when the buffer is
 * full. The length is explicit: a read buffer is not NUL-terminated, and
 * an unbounded copy would leak stale bytes past the read. */
static void json_str_len(char **p, const char *end, const char *s, size_t max)
{
    char *out = *p;
    if (out < end) {
        *out++ = '"';
    }
    size_t taken = 0;
    for (const unsigned char *in = (const unsigned char *)(s ? s : "");
         in && taken < max && *in && out + 7 < end; in++, taken++) {
        if (*in == '"' || *in == '\\') {
            *out++ = '\\';
            *out++ = (char)*in;
        } else if (*in == '\n') {
            *out++ = '\\';
            *out++ = 'n';
        } else if (*in == '\r') {
            *out++ = '\\';
            *out++ = 'r';
        } else if (*in == '\t') {
            *out++ = '\\';
            *out++ = 't';
        } else if (*in < 0x20) {
            int n = snprintf(out, (size_t)(end - out), "\\u%04x", *in);
            if (n > 0) {
                out += n < (end - out) ? n : (end - out - 1);
            }
        } else {
            *out++ = (char)*in;
        }
    }
    if (out < end) {
        *out++ = '"';
    }
    *p = out;
}

static void json_string(char **p, const char *end, const char *s)
{
    json_str_len(p, end, s, s ? strlen(s) : 0);
}

/* Appends raw text, truncated at the end of the buffer. */
static void json_raw(char **p, const char *end, const char *s)
{
    size_t room = (size_t)(end - *p);
    if (room == 0) {
        return;
    }
    size_t n = strlen(s);
    if (n > room - 1) {
        n = room - 1;
    }
    memcpy(*p, s, n);
    *p += n;
}

/* ------------------------------------------------------------------ */
/* Registration record and heartbeat                                   */
/* ------------------------------------------------------------------ */

static void reg_write(const char *type)
{
    if (g_reg_fd < 0) {
        return;
    }
    char line[640];
    char *p = line;
    const char *end = line + sizeof(line) - 2;
    char head[128];
    int n = snprintf(head, sizeof(head),
                     "{\"type\":\"%s\",\"instance\":\"%s\",\"pid\":%d,"
                     "\"ppid\":%d,\"exe\":",
                     type, g_instance, g_pid, g_ppid);
    (void)n;
    json_raw(&p, end, head);
    json_string(&p, end, g_exe);
    json_raw(&p, end, ",\"session\":");
    json_string(&p, end, g_session);
    snprintf(head, sizeof(head), ",\"ts\":%lld}\n", now_ns());
    json_raw(&p, end, head);
    raw_write(g_reg_fd, line, (size_t)(p - line));
    g_last_reg_write_ms = mono_ms();
}

static void *beat_main(void *arg)
{
    (void)arg;
    for (;;) {
        struct timespec nap = {0, 100 * 1000 * 1000};
        nanosleep(&nap, NULL);
        if (mono_ms() - g_last_reg_write_ms > HEARTBEAT_MS) {
            /* The thread is detached and dies with the process. It calls
             * nothing but raw syscalls and snprintf, so it is safe while
             * the process tears itself down. */
            reg_write("sensor_heartbeat");
        }
    }
    return NULL;
}

/* Starts the heartbeat thread once, on the first event. A process that
 * never reports anything never pays for a thread, and a quiet process
 * never looks silent: sensor silence is only a signal for an instance
 * that spoke and then stopped while its process lives on. */
static void beat_start(void)
{
    if (g_beat_started) {
        return;
    }
    g_beat_started = 1;
    pthread_t thread;
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    if (pthread_create(&thread, &attr, beat_main, NULL) == 0) {
        g_last_reg_write_ms = mono_ms();
    }
    pthread_attr_destroy(&attr);
}

/* A forked child inherits the statics of the parent, including the parent's
 * instance identity. The constructor does not run again after a plain
 * fork, so the first event of the child notices the new pid and registers
 * a new instance. This covers children without hooking fork itself. */
static void check_pid(void)
{
    int pid = (int)syscall(SYS_getpid);
    if (pid == g_pid) {
        return;
    }
    g_pid = pid;
    g_ppid = (int)syscall(SYS_getppid);
    long n = syscall(SYS_readlinkat, AT_FDCWD, "/proc/self/exe", g_exe,
                     sizeof(g_exe) - 1);
    if (n > 0) {
        g_exe[n] = '\0';
    }
    g_seq = 0;
    snprintf(g_instance, sizeof(g_instance), "i-%llx-%d",
             (unsigned long long)now_ns(), g_pid);
    reg_write("sensor_register");
}

/* ------------------------------------------------------------------ */
/* Event emission                                                      */
/* ------------------------------------------------------------------ */

/* Opens one event line: seq, ts, session, pid, type. Returns the write
 * position and sets *end to the last usable byte. */
static char *event_open(char *line, const char **end, const char *type)
{
    check_pid();
    g_seq++;
    char *p = line;
    *end = line + LINE_MAX_ - 2;
    char head[160];
    snprintf(head, sizeof(head), "{\"seq\":%u,\"ts\":%lld,\"session_id\":",
             g_seq, now_ns());
    json_raw(&p, *end, head);
    json_string(&p, *end, g_session);
    snprintf(head, sizeof(head), ",\"pid\":%d,\"type\":\"%s\",", g_pid, type);
    json_raw(&p, *end, head);
    beat_start();
    return p;
}

static void event_finish(char *line, char *p, const char *end)
{
    if (p < end) {
        *p++ = '}';
    }
    if (p < end + 1) {
        *p++ = '\n';
    }
    *p = '\0';
    raw_write(g_trace_fd, line, (size_t)(p - line));
}

/* The process facts of a `process_exec` event. The path is the program the
 * process is about to run; argv is read from the call. A sensor may read
 * the memory of the process it lives in — it reports, it never decides. */
static void emit_exec(const char *path, char *const argv[], int resolved)
{
    if (g_trace_fd < 0 || !path) {
        return;
    }
    char line[LINE_MAX_];
    const char *end;
    char *p = event_open(line, &end, "process_exec");
    char cwd[192];
    if (syscall(SYS_getcwd, cwd, sizeof(cwd) - 1) < 0) {
        cwd[0] = '\0';
    }
    char head[160];
    snprintf(head, sizeof(head),
             "\"process\":{\"pid\":%d,\"ppid\":%d,\"start_ticks\":%lld",
             g_pid, g_ppid, g_start_ticks);
    json_raw(&p, end, head);
    if (resolved) {
        json_raw(&p, end, ",\"exe\":");
        json_string(&p, end, path);
    }
    const char *slash = strrchr(path, '/');
    json_raw(&p, end, ",\"comm\":");
    json_string(&p, end, slash ? slash + 1 : path);
    json_raw(&p, end, ",\"argv\":[");
    int first = 1;
    for (char *const *a = argv; a && *a && p + 8 < end; a++) {
        if (!first) {
            json_raw(&p, end, ",");
        }
        first = 0;
        json_string(&p, end, *a);
    }
    json_raw(&p, end, "],\"cwd\":");
    json_string(&p, end, cwd);
    json_raw(&p, end, "}");
    event_finish(line, p, end);
}

static void emit_file_open(const char *path, int write)
{
    if (g_trace_fd < 0 || !path) {
        return;
    }
    char line[LINE_MAX_];
    const char *end;
    char *p = event_open(line, &end, "file_open");
    json_raw(&p, end, "\"path\":");
    json_string(&p, end, path);
    json_raw(&p, end, write ? ",\"write\":true" : ",\"write\":false");
    event_finish(line, p, end);
}

/* Returns 1 when the chunk is text that a trace can carry, and trims a
 * multibyte sequence that the read cut in half. A binary chunk (a .pyc, an
 * image, an object file) captures nothing: the trace is UTF-8 JSON, and
 * the sensor does not get to decide what is a secret. */
static int text_chunk(const char *data, size_t *len)
{
    const unsigned char *p = (const unsigned char *)data;
    size_t n = *len;
    size_t i = 0;
    while (i < n) {
        unsigned char c = p[i];
        if (c == 0x09 || c == 0x0A || c == 0x0D || (c >= 0x20 && c <= 0x7E)) {
            i++;
            continue;
        }
        if (c >= 0xC2 && c <= 0xF4) {
            size_t need = c >= 0xF0 ? 3 : c >= 0xE0 ? 2 : 1;
            if (i + need >= n) {
                /* A sequence cut by the end of the chunk: trim it. */
                for (size_t k = i + 1; k < n; k++) {
                    if (p[k] < 0x80 || p[k] > 0xBF) {
                        return 0;
                    }
                }
                *len = i;
                return i > 0;
            }
            for (size_t k = 1; k <= need; k++) {
                if (p[i + k] < 0x80 || p[i + k] > 0xBF) {
                    return 0;
                }
            }
            i += need + 1;
            continue;
        }
        return 0;
    }
    return 1;
}

static void emit_file_read(const char *path, const char *data, size_t len)
{
    if (g_trace_fd < 0 || !data || len == 0) {
        return;
    }
    if (!text_chunk(data, &len) || len == 0) {
        return;
    }
    char line[LINE_MAX_];
    const char *end;
    char *p = event_open(line, &end, "file_read");
    json_raw(&p, end, "\"path\":");
    json_string(&p, end, path);
    json_raw(&p, end, ",\"data\":");
    /* The length bounds the capture to what the process really read. */
    json_str_len(&p, end, data, len);
    event_finish(line, p, end);
}

static void emit_stdin(const char *data, size_t len)
{
    if (g_trace_fd < 0 || !data || len == 0) {
        return;
    }
    if (!text_chunk(data, &len) || len == 0) {
        return;
    }
    char line[LINE_MAX_];
    const char *end;
    char *p = event_open(line, &end, "stdin_write");
    json_raw(&p, end, "\"stream\":\"stdin\",\"data\":");
    json_str_len(&p, end, data, len);
    event_finish(line, p, end);
}

/* ------------------------------------------------------------------ */
/* Content capture: small files read into a process                    */
/* ------------------------------------------------------------------ */

/* Returns 1 when the path must not be content captured (pseudo files, and
 * anything not absolute, where the real name is unknown). The open itself
 * is still reported. */
static int path_skip_capture(const char *path)
{
    if (!path || path[0] != '/') {
        return 1;
    }
    return strncmp(path, "/proc/", 6) == 0 || strncmp(path, "/sys/", 5) == 0 ||
           strncmp(path, "/dev/", 5) == 0;
}

static void fd_track(int fd, const char *path)
{
    if (fd < 0 || path_skip_capture(path)) {
        return;
    }
    cap_slot *slot = NULL;
    for (int i = 0; i < CAPTURE_TABLE * 2; i++) {
        if (g_caps[i].in_use && !g_caps[i].is_file && g_caps[i].fd == fd) {
            slot = &g_caps[i];
            break;
        }
    }
    if (!slot) {
        for (int i = 0; i < CAPTURE_TABLE * 2; i++) {
            if (!g_caps[i].in_use) {
                slot = &g_caps[i];
                break;
            }
        }
    }
    if (!slot) {
        /* Table full: recycle the first slot instead of growing. */
        slot = &g_caps[0];
    }
    slot->in_use = 1;
    slot->is_file = 0;
    slot->fd = fd;
    slot->file = NULL;
    slot->taken = 0;
    snprintf(slot->path, sizeof(slot->path), "%s", path);
}

static cap_slot *fd_find(int fd)
{
    for (int i = 0; i < CAPTURE_TABLE * 2; i++) {
        if (g_caps[i].in_use && !g_caps[i].is_file && g_caps[i].fd == fd) {
            return &g_caps[i];
        }
    }
    return NULL;
}

static void fd_forget(int fd)
{
    for (int i = 0; i < CAPTURE_TABLE * 2; i++) {
        if (g_caps[i].in_use && !g_caps[i].is_file && g_caps[i].fd == fd) {
            g_caps[i].in_use = 0;
        }
    }
}

static cap_slot *file_find(void *f)
{
    for (int i = 0; i < CAPTURE_TABLE * 2; i++) {
        if (g_caps[i].in_use && g_caps[i].is_file && g_caps[i].file == f) {
            return &g_caps[i];
        }
    }
    return NULL;
}

static void file_track(void *f, int fd, const char *path)
{
    if (!f || path_skip_capture(path)) {
        return;
    }
    struct stat st;
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) || st.st_size > 4096) {
        return;
    }
    cap_slot *slot = file_find(f);
    if (!slot) {
        for (int i = 0; i < CAPTURE_TABLE * 2; i++) {
            if (!g_caps[i].in_use) {
                slot = &g_caps[i];
                break;
            }
        }
    }
    if (!slot) {
        slot = &g_caps[0];
    }
    slot->in_use = 1;
    slot->is_file = 1;
    slot->fd = -1;
    slot->file = f;
    slot->taken = 0;
    snprintf(slot->path, sizeof(slot->path), "%s", path);
}

/* Captures one chunk of a tracked file while the per-file budget lasts. */
static void capture_chunk(cap_slot *slot, const char *data, size_t len)
{
    if (!slot || slot->taken >= DATA_MAX || len == 0) {
        return;
    }
    emit_file_read(slot->path, data, len);
    slot->taken += (int)(len > DATA_MAX ? DATA_MAX : len);
}

/* ------------------------------------------------------------------ */
/* Interposed functions                                                */
/* ------------------------------------------------------------------ */

int execve(const char *path, char *const argv[], char *const envp[])
{
    if (!real_execve) {
        real_execve = (execve_fn)dlsym(RTLD_NEXT, "execve");
    }
    /* Before the call: this is the about-to-exec fact. */
    emit_exec(path, argv, 1);
    return real_execve(path, argv, envp);
}

int execv(const char *path, char *const argv[])
{
    extern char **environ;
    return execve(path, argv, environ);
}

int execvp(const char *file, char *const argv[])
{
    if (!real_execvp) {
        real_execvp = (execvp_fn)dlsym(RTLD_NEXT, "execvp");
    }
    /* The search path is not resolved yet, so the event carries the name
     * and the arguments without an exe. */
    emit_exec(file, argv, 0);
    return real_execvp(file, argv);
}

/* Resolves a path the way the kernel would for AT_FDCWD: an absolute path
 * stays as it is, a relative one is joined with the working directory. A
 * sensor report is more useful absolute, and the capture table needs a
 * stable name. */
static void resolve_path(const char *path, char *out, size_t outlen)
{
    if (!path) {
        out[0] = '\0';
        return;
    }
    if (path[0] == '/') {
        snprintf(out, outlen, "%s", path);
        return;
    }
    char cwd[160];
    if (syscall(SYS_getcwd, cwd, sizeof(cwd) - 1) < 0) {
        snprintf(out, outlen, "%s", path);
        return;
    }
    snprintf(out, outlen, "%s/%s", cwd, path);
}

static void open_done(int fd, const char *path, int flags)
{
    if (fd < 0 || !path) {
        return;
    }
    char full[PATH_MAX_];
    resolve_path(path, full, sizeof(full));
    int write = (flags & (O_WRONLY | O_RDWR | O_CREAT | O_TRUNC | O_APPEND)) != 0;
    emit_file_open(full, write);
    if (!(flags & O_DIRECTORY)) {
        struct stat st;
        if (fstat(fd, &st) == 0 && S_ISREG(st.st_mode) && st.st_size <= 4096) {
            fd_track(fd, full);
        }
    }
}

int open(const char *path, int flags, ...)
{
    if (!real_open) {
        real_open = (open_fn)dlsym(RTLD_NEXT, "open");
    }
    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list ap;
        va_start(ap, flags);
        mode = (mode_t)va_arg(ap, int);
        va_end(ap);
    }
    int fd = real_open(path, flags, mode);
    open_done(fd, path, flags);
    return fd;
}

int open64(const char *path, int flags, ...)
{
    if (!real_open) {
        real_open = (open_fn)dlsym(RTLD_NEXT, "open64");
    }
    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list ap;
        va_start(ap, flags);
        mode = (mode_t)va_arg(ap, int);
        va_end(ap);
    }
    int fd = real_open(path, flags, mode);
    open_done(fd, path, flags);
    return fd;
}

int openat(int dirfd, const char *path, int flags, ...)
{
    if (!real_openat) {
        real_openat = (openat_fn)dlsym(RTLD_NEXT, "openat");
    }
    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list ap;
        va_start(ap, flags);
        mode = (mode_t)va_arg(ap, int);
        va_end(ap);
    }
    int fd = real_openat(dirfd, path, flags, mode);
    if (fd >= 0) {
        char full[PATH_MAX_];
        resolve_path(path, full, sizeof(full));
        int write = (flags & (O_WRONLY | O_RDWR | O_CREAT | O_TRUNC | O_APPEND)) != 0;
        emit_file_open(full, write);
        if (!(flags & O_DIRECTORY) && dirfd == AT_FDCWD) {
            struct stat st;
            if (fstat(fd, &st) == 0 && S_ISREG(st.st_mode) &&
                st.st_size <= 4096) {
                fd_track(fd, full);
            }
        }
    }
    return fd;
}

static FILE *fopen_common(FILE *f, const char *path, const char *mode)
{
    if (f && path) {
        char full[PATH_MAX_];
        resolve_path(path, full, sizeof(full));
        int write = mode && strpbrk(mode, "wa+") != NULL;
        emit_file_open(full, write);
        file_track(f, fileno(f), full);
    }
    return f;
}

FILE *fopen(const char *path, const char *mode)
{
    if (!real_fopen) {
        real_fopen = (fopen_fn)dlsym(RTLD_NEXT, "fopen");
    }
    return fopen_common(real_fopen(path, mode), path, mode);
}

FILE *fopen64(const char *path, const char *mode)
{
    if (!real_fopen) {
        real_fopen = (fopen_fn)dlsym(RTLD_NEXT, "fopen64");
    }
    return fopen_common(real_fopen(path, mode), path, mode);
}

int creat(const char *path, mode_t mode)
{
    if (!real_creat) {
        real_creat = (creat_fn)dlsym(RTLD_NEXT, "creat");
    }
    int fd = real_creat(path, mode);
    if (fd >= 0) {
        emit_file_open(path, 1);
    }
    return fd;
}

int close(int fd)
{
    if (!real_close) {
        real_close = (close_fn)dlsym(RTLD_NEXT, "close");
    }
    fd_forget(fd);
    return real_close(fd);
}

int fclose(FILE *f)
{
    if (!real_fclose) {
        real_fclose = (fclose_fn)dlsym(RTLD_NEXT, "fclose");
    }
    cap_slot *slot = file_find(f);
    if (slot) {
        slot->in_use = 0;
    }
    return real_fclose(f);
}

ssize_t read(int fd, void *buf, size_t count)
{
    if (!real_read) {
        real_read = (read_fn)dlsym(RTLD_NEXT, "read");
    }
    ssize_t n = real_read(fd, buf, count);
    if (n > 0 && g_trace_fd >= 0) {
        if (fd == 0) {
            /* What the process feeds on standard input. */
            if (g_stdin_captured < STDIN_CAPTURE_MAX) {
                g_stdin_captured++;
                emit_stdin((const char *)buf, (size_t)n);
            }
        } else {
            cap_slot *slot = fd_find(fd);
            if (slot) {
                capture_chunk(slot, (const char *)buf, (size_t)n);
            }
        }
    }
    return n;
}

size_t fread(void *buf, size_t size, size_t nmemb, FILE *f)
{
    if (!real_fread) {
        real_fread = (fread_fn)dlsym(RTLD_NEXT, "fread");
    }
    size_t n = real_fread(buf, size, nmemb, f);
    if (n > 0 && g_trace_fd >= 0 && size > 0) {
        cap_slot *slot = file_find(f);
        if (slot) {
            capture_chunk(slot, (const char *)buf, n * size);
        }
    }
    return n;
}

char *fgets(char *buf, int size, FILE *f)
{
    if (!real_fgets) {
        real_fgets = (fgets_fn)dlsym(RTLD_NEXT, "fgets");
    }
    char *r = real_fgets(buf, size, f);
    if (r && g_trace_fd >= 0) {
        cap_slot *slot = file_find(f);
        if (slot) {
            capture_chunk(slot, buf, strlen(buf));
        }
    }
    return r;
}

static void emit_path_event(const char *type, const char *path)
{
    if (g_trace_fd < 0 || !path) {
        return;
    }
    char full[PATH_MAX_];
    resolve_path(path, full, sizeof(full));
    char line[LINE_MAX_];
    const char *end;
    char *p = event_open(line, &end, type);
    json_raw(&p, end, "\"path\":");
    json_string(&p, end, full);
    event_finish(line, p, end);
}

int unlink(const char *path)
{
    if (!real_unlink) {
        real_unlink = (unlink_fn)dlsym(RTLD_NEXT, "unlink");
    }
    int r = real_unlink(path);
    if (r == 0) {
        emit_path_event("file_delete", path);
    }
    return r;
}

int unlinkat(int dirfd, const char *path, int flags)
{
    if (!real_unlinkat) {
        real_unlinkat = (unlinkat_fn)dlsym(RTLD_NEXT, "unlinkat");
    }
    int r = real_unlinkat(dirfd, path, flags);
    if (r == 0) {
        emit_path_event("file_delete", path);
    }
    return r;
}

int rmdir(const char *path)
{
    if (!real_rmdir) {
        real_rmdir = (rmdir_fn)dlsym(RTLD_NEXT, "rmdir");
    }
    int r = real_rmdir(path);
    if (r == 0) {
        emit_path_event("file_delete", path);
    }
    return r;
}

static void emit_rename(const char *from, const char *to)
{
    if (g_trace_fd < 0) {
        return;
    }
    char full_from[PATH_MAX_];
    char full_to[PATH_MAX_];
    resolve_path(from, full_from, sizeof(full_from));
    resolve_path(to, full_to, sizeof(full_to));
    char line[LINE_MAX_];
    const char *end;
    char *p = event_open(line, &end, "file_rename");
    json_raw(&p, end, "\"from\":");
    json_string(&p, end, full_from);
    json_raw(&p, end, ",\"to\":");
    json_string(&p, end, full_to);
    event_finish(line, p, end);
}

int rename(const char *from, const char *to)
{
    if (!real_rename) {
        real_rename = (rename_fn)dlsym(RTLD_NEXT, "rename");
    }
    int r = real_rename(from, to);
    if (r == 0) {
        emit_rename(from, to);
    }
    return r;
}

int renameat(int fromfd, const char *from, int tofd, const char *to)
{
    if (!real_renameat) {
        real_renameat = (renameat_fn)dlsym(RTLD_NEXT, "renameat");
    }
    int r = real_renameat(fromfd, from, tofd, to);
    if (r == 0) {
        emit_rename(from, to);
    }
    return r;
}

int renameat2(int fromfd, const char *from, int tofd, const char *to,
              unsigned int flags)
{
    if (!real_renameat2) {
        real_renameat2 = (renameat2_fn)dlsym(RTLD_NEXT, "renameat2");
    }
    int r = real_renameat2(fromfd, from, tofd, to, flags);
    if (r == 0) {
        emit_rename(from, to);
    }
    return r;
}

int connect(int fd, const struct sockaddr *addr, socklen_t len)
{
    if (!real_connect) {
        real_connect = (connect_fn)dlsym(RTLD_NEXT, "connect");
    }
    int r = real_connect(fd, addr, len);
    if (r == 0 && addr && (addr->sa_family == AF_INET ||
                           addr->sa_family == AF_INET6)) {
        char ip[INET6_ADDRSTRLEN];
        int port = 0;
        if (addr->sa_family == AF_INET) {
            const struct sockaddr_in *a = (const struct sockaddr_in *)addr;
            inet_ntop(AF_INET, &a->sin_addr, ip, sizeof(ip));
            port = ntohs(a->sin_port);
        } else {
            const struct sockaddr_in6 *a = (const struct sockaddr_in6 *)addr;
            inet_ntop(AF_INET6, &a->sin6_addr, ip, sizeof(ip));
            port = ntohs(a->sin6_port);
        }
        char line[LINE_MAX_];
        const char *end;
        char *p = event_open(line, &end, "network_connect");
        json_raw(&p, end, "\"addr\":");
        json_string(&p, end, ip);
        char num[32];
        snprintf(num, sizeof(num), ",\"port\":%d", port);
        json_raw(&p, end, num);
        event_finish(line, p, end);
    }
    return r;
}

void *dlopen(const char *path, int flags)
{
    if (!real_dlopen) {
        real_dlopen = (dlopen_fn)dlsym(RTLD_NEXT, "dlopen");
    }
    void *h = real_dlopen(path, flags);
    if (h && path) {
        emit_path_event("library_load", path);
    }
    return h;
}

void *dlmopen(long nsid, const char *path, int flags)
{
    if (!real_dlmopen) {
        real_dlmopen = (dlmopen_fn)dlsym(RTLD_NEXT, "dlmopen");
    }
    void *h = real_dlmopen(nsid, path, flags);
    if (h && path) {
        emit_path_event("library_load", path);
    }
    return h;
}

static void emit_env(const char *name, const char *value)
{
    if (g_trace_fd < 0 || !name) {
        return;
    }
    char line[LINE_MAX_];
    const char *end;
    char *p = event_open(line, &end, "env_change");
    json_raw(&p, end, "\"name\":");
    json_string(&p, end, name);
    if (value) {
        json_raw(&p, end, ",\"value\":");
        json_string(&p, end, value);
    }
    event_finish(line, p, end);
}

int setenv(const char *name, const char *value, int overwrite)
{
    if (!real_setenv) {
        real_setenv = (setenv_fn)dlsym(RTLD_NEXT, "setenv");
    }
    int r = real_setenv(name, value, overwrite);
    if (r == 0) {
        emit_env(name, value);
    }
    return r;
}

int unsetenv(const char *name)
{
    if (!real_unsetenv) {
        real_unsetenv = (unsetenv_fn)dlsym(RTLD_NEXT, "unsetenv");
    }
    int r = real_unsetenv(name);
    if (r == 0) {
        emit_env(name, NULL);
    }
    return r;
}

int putenv(char *entry)
{
    if (!real_putenv) {
        real_putenv = (putenv_fn)dlsym(RTLD_NEXT, "putenv");
    }
    int r = real_putenv(entry);
    if (r == 0) {
        char name[128];
        const char *eq = strchr(entry, '=');
        size_t n = eq ? (size_t)(eq - entry) : strlen(entry);
        if (n >= sizeof(name)) {
            n = sizeof(name) - 1;
        }
        memcpy(name, entry, n);
        name[n] = '\0';
        emit_env(name, eq ? eq + 1 : NULL);
    }
    return r;
}

/* ------------------------------------------------------------------ */
/* Constructor and destructor                                          */
/* ------------------------------------------------------------------ */

/* Reads the process start time (field 22 of /proc/self/stat, in clock
 * ticks after boot) with raw syscalls. This is the same key the
 * provenance graph uses. */
static long long read_start_ticks(void)
{
    char buf[2048];
    long fd = syscall(SYS_openat, AT_FDCWD, "/proc/self/stat", O_RDONLY, 0);
    if (fd < 0) {
        return 0;
    }
    long n = syscall(SYS_read, fd, buf, sizeof(buf) - 1);
    syscall(SYS_close, fd);
    if (n <= 0) {
        return 0;
    }
    buf[n] = '\0';
    char *paren = strrchr(buf, ')');
    if (!paren) {
        return 0;
    }
    /* After the comm parentheses the fields start at 3; starttime is field
     * 22, so it is token 19 of the rest. */
    char *tok = paren + 1;
    for (int i = 0; i < 20; i++) {
        tok = strtok(i == 0 ? tok : NULL, " ");
    }
    return tok ? strtoll(tok, NULL, 10) : 0;
}

__attribute__((constructor)) static void sensor_init(void)
{
    const char *trace = getenv("AF_SENSOR_TRACE");
    const char *reg = getenv("AF_SENSOR_REG");
    const char *session = getenv("AF_SENSOR_SESSION");
    if (!g_trace_tried) {
        g_trace_tried = 1;
        if (trace && trace[0]) {
            g_trace_fd = raw_open_append(trace);
        }
    }
    if (!g_reg_tried) {
        g_reg_tried = 1;
        if (reg && reg[0]) {
            g_reg_fd = raw_open_append(reg);
        }
    }
    if (session && session[0] && strlen(session) < sizeof(g_session)) {
        snprintf(g_session, sizeof(g_session), "%s", session);
    }
    g_pid = (int)syscall(SYS_getpid);
    g_ppid = (int)syscall(SYS_getppid);
    long n = syscall(SYS_readlinkat, AT_FDCWD, "/proc/self/exe", g_exe,
                     sizeof(g_exe) - 1);
    if (n > 0) {
        g_exe[n] = '\0';
    } else {
        snprintf(g_exe, sizeof(g_exe), "(unknown)");
    }
    const char *slash = strrchr(g_exe, '/');
    snprintf(g_comm, sizeof(g_comm), "%.90s", slash ? slash + 1 : g_exe);
    g_start_ticks = read_start_ticks();
    snprintf(g_instance, sizeof(g_instance), "i-%llx-%d",
             (unsigned long long)now_ns(), g_pid);
    reg_write("sensor_register");
}

__attribute__((destructor)) static void sensor_fini(void)
{
    reg_write("sensor_exit");
}
