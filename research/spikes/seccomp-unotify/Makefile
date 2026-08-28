# Build of the seccomp user notification spike.
#
# make          builds every program into bin/
# make check    builds and runs the whole test set
# make bench    builds and runs the shared benchmark harness
# make run-all  builds, runs every test and then the benchmark
# make clean    removes bin/ and the work directory

CC      ?= gcc
CFLAGS  ?= -O2 -g -Wall -Wextra -Wno-unused-parameter
LDFLAGS ?=
PTHREAD  = -pthread

BIN  = bin
PROGS = $(BIN)/afw-unotify \
        $(BIN)/toctou-open \
        $(BIN)/toctou-execve \
        $(BIN)/probe-listener \
        $(BIN)/slow-target \
        $(BIN)/show-creds

all: $(PROGS)

$(BIN):
	mkdir -p $(BIN)

$(BIN)/afw-unotify: src/afw_unotify.c | $(BIN)
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

$(BIN)/toctou-open: src/toctou_open.c | $(BIN)
	$(CC) $(CFLAGS) $(PTHREAD) -o $@ $< $(LDFLAGS)

$(BIN)/toctou-execve: src/toctou_execve.c | $(BIN)
	$(CC) $(CFLAGS) $(PTHREAD) -o $@ $< $(LDFLAGS)

$(BIN)/probe-listener: src/probe_listener.c | $(BIN)
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

$(BIN)/slow-target: src/slow_target.c | $(BIN)
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

$(BIN)/show-creds: src/show_creds.c | $(BIN)
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

check: all
	./tests/run-tests.sh

bench: all
	./bench/run-bench.sh

# Everything of the spike, in one command.
run-all: check bench

clean:
	rm -rf $(BIN) work

.PHONY: all check bench run-all clean
