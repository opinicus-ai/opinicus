//
// cred-read — a read of a credential-shaped file. Scenario secrets-01.
//
// The builtin rule filesystem.credentials.read matches a read-open of a
// path ending in .aws/credentials or .ssh/id_*, but the default kernel
// filter drops read-opens, so the rule can only fire with
// --syscall-filter all-opens. This technique measures both modes with the
// same action.
//
//   cred-read <marker-file>
//
// The runner places the file at <scratch>/.aws/credentials, which matches
// the rule pattern without touching any real credential store.
#define _GNU_SOURCE
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

int main(int argc, char **argv) {
    if (argc != 3) {
        fprintf(stderr, "usage: cred-read <credential-file> <marker-file>\n");
        return 2;
    }
    char buf[64];
    int fd = open(argv[1], O_RDONLY);
    ssize_t n = fd >= 0 ? read(fd, buf, sizeof buf) : -1;
    printf("ACTION cred-read %s rc=%zd\n", fd >= 0 ? "ok" : "blocked", n);
    if (fd >= 0) {
        close(fd);
    }
    FILE *m = fopen(argv[2], "a");
    if (m) {
        fputs("cred-read\n", m);
        fclose(m);
    }
    return 0;
}
