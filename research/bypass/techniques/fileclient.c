//
// fileclient — a client-shaped program that executes statements from a file
// named on its command line, one EXECUTED line per statement, into the
// marker file. It stands in for any tool that reads its payload from a file
// instead of the command line.
//
//   fileclient -f <payload-file> <marker-file>
//
// The runner runs the same binary under two names: as fileclient, and as a
// copy named psql. The monitor snapshots the -f file only for the database
// clients and interpreters of its name lists (crates/af-monitor/src/inspect.rs),
// so the pair measures what the program name alone does to visibility.
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv) {
    if (argc != 4 || strcmp(argv[1], "-f") != 0) {
        fprintf(stderr, "usage: fileclient -f <payload-file> <marker-file>\n");
        return 2;
    }
    FILE *payload = fopen(argv[2], "r");
    if (!payload) {
        perror(argv[2]);
        return 1;
    }
    FILE *marker = fopen(argv[3], "a");
    char line[512];
    while (fgets(line, sizeof line, payload)) {
        line[strcspn(line, "\r\n")] = 0;
        if (line[0] == 0) {
            continue;
        }
        printf("EXECUTED: %s\n", line);
        if (marker) {
            fprintf(marker, "EXECUTED: %s\n", line);
        }
    }
    if (marker) {
        fclose(marker);
    }
    fclose(payload);
    return 0;
}
