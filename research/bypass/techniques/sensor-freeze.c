//
// sensor-freeze — an attack on the in-process sensor of [af-2].
//
// A child execs a fresh image of this program (so its constructor arms a
// real heartbeat thread of its own — a plain fork inherits a thread that
// never restarts), proves it talks, freezes itself with SIGSTOP, and stays
// frozen past the correlation window while the parent keeps the session
// alive. The external view shows the process living on; the sensor's record
// shows nothing from it for the whole freeze. This is DIRECTION.md §3.4,
// "a sensor the firewall installed goes quiet or disappears while its
// process lives on", and the discrepancy fact `sensor_silent_subtree` of
// [af-5].
//
//   sensor-freeze <marker-file>          the parent
//   sensor-freeze --child <marker-file>  the frozen child (internal)
//
// The child writes the marker after it continues, proving the freeze was a
// freeze and not a crash.
#define _GNU_SOURCE
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <unistd.h>

static int child_main(const char *marker) {
    // One hooked open, so the instance emits an event and starts its
    // heartbeat thread; then idle long enough for a heartbeat to land.
    int fd = open(marker, O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (fd >= 0) {
        close(fd);
    }
    sleep(2);
    // The freeze: the heartbeat thread stops with the whole process
    // while the process lives on.
    raise(SIGSTOP);
    // Continued by the parent. The marker proves the run.
    fd = open(marker, O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (fd >= 0) {
        if (write(fd, "frozen-child\n", 13) < 0) {
            _exit(3);
        }
        close(fd);
    }
    _exit(0);
}

int main(int argc, char **argv) {
    if (argc == 3 && strcmp(argv[1], "--child") == 0) {
        return child_main(argv[2]);
    }
    if (argc != 2) {
        fprintf(stderr, "usage: sensor-freeze <marker-file>\n");
        return 2;
    }

    pid_t child = fork();
    if (child < 0) {
        perror("fork");
        return 1;
    }
    if (child == 0) {
        // A fresh image of this program: the constructor runs again, and
        // with it a heartbeat thread the freeze can actually stop.
        char self[256];
        ssize_t n = readlink("/proc/self/exe", self, sizeof self - 1);
        if (n < 0) {
            _exit(4);
        }
        self[n] = '\0';
        char *const child_argv[] = {self, "--child", argv[1], NULL};
        extern char **environ;
        execve(self, child_argv, environ);
        _exit(127);
    }

    // The parent holds the session open through the freeze window.
    sleep(8);
    kill(child, SIGCONT);
    int status = 0;
    waitpid(child, &status, 0);
    printf("freeze-done\n");
    return 0;
}
