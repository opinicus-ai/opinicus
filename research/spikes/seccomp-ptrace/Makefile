# Build of the seccomp and ptrace spike.
#
# The spike is C on purpose, so that it stays outside the Cargo workspace of
# the product.

CC ?= gcc
CFLAGS ?= -O2 -Wall -Wextra -std=gnu11
BUILD := build

BINARIES := $(BUILD)/afw-hybrid $(BUILD)/nnp-probe $(BUILD)/victim

.PHONY: all clean test bench check

all: $(BINARIES)

$(BUILD):
	mkdir -p $(BUILD)

$(BUILD)/afw-hybrid: src/hybrid.c src/filter.c src/filter.h | $(BUILD)
	$(CC) $(CFLAGS) -Isrc -o $@ src/hybrid.c src/filter.c

$(BUILD)/nnp-probe: src/nnp_probe.c src/filter.c src/filter.h | $(BUILD)
	$(CC) $(CFLAGS) -Isrc -o $@ src/nnp_probe.c src/filter.c

$(BUILD)/victim: src/victim.c | $(BUILD)
	$(CC) $(CFLAGS) -pthread -o $@ src/victim.c

test: all
	./tests/run-tests.sh

bench: all
	./bench/run-bench.sh

check: test bench

clean:
	rm -rf $(BUILD) work
