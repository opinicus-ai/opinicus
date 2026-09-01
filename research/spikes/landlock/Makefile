# Build of the Landlock spike.
#
# make          builds every program into bin/
# make probe    prints the Landlock ABI of this kernel
# make check    builds and runs the whole test set
# make bench    builds and runs the shared benchmark harness
# make rules    counts the rule pack against what Landlock can carry
# make run-all  builds, runs every test, counts the rules, and benchmarks
# make clean    removes bin/ and the work directory

CC      ?= gcc
CFLAGS  ?= -O2 -g -Wall -Wextra -Wno-unused-parameter
LDFLAGS ?=

BIN   = bin
PROGS = $(BIN)/afw-landlock \
        $(BIN)/probe-abi \
        $(BIN)/fs-probe \
        $(BIN)/escape-test \
        $(BIN)/tcp-listener \
        $(BIN)/rule-specificity \
        $(BIN)/tmp-scope

all: $(PROGS)

$(BIN):
	mkdir -p $(BIN)

$(BIN)/afw-landlock: src/afw_landlock.c src/landlock_common.h | $(BIN)
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

$(BIN)/probe-abi: src/probe_abi.c src/landlock_common.h | $(BIN)
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

$(BIN)/fs-probe: src/fs_probe.c | $(BIN)
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

$(BIN)/escape-test: src/escape_test.c src/landlock_common.h | $(BIN)
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

$(BIN)/tcp-listener: src/tcp_listener.c | $(BIN)
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

$(BIN)/rule-specificity: src/rule_specificity.c src/landlock_common.h | $(BIN)
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

$(BIN)/tmp-scope: src/tmp_scope.c src/landlock_common.h | $(BIN)
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

probe: $(BIN)/probe-abi
	timeout 20 ./$(BIN)/probe-abi

check: all
	./tests/run-tests.sh

bench: all
	./bench/run-bench.sh

rules: 
	python3 tests/count-rules.py

# Everything of the spike, in one command.
run-all: check rules bench

clean:
	rm -rf $(BIN) work

.PHONY: all probe check bench rules run-all clean
