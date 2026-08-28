# Makefile of the baselines spike.
#
#   make            builds every tool and every workload
#   make clean      removes the built files
#
# Nothing here joins the Cargo workspace. Every tool is C.

CC      ?= gcc
CFLAGS  ?= -O2 -Wall -Wextra -std=gnu11
BIN     := bin

TOOLS := $(BIN)/procpoll $(BIN)/ptrace_full $(BIN)/selfcheck \
         $(BIN)/libafwpreload.so

WORKLOADS := $(BIN)/marker_libc $(BIN)/marker_rawsyscall \
             $(BIN)/marker_static $(BIN)/vdso_and_mmap

all: $(TOOLS) $(WORKLOADS) gomarker

# The static Go program is a second proof of the LD_PRELOAD gap, because a Go
# binary is static by default and a coding agent runs many of them. The build
# is optional: a machine with no Go toolchain still gets every other result,
# and the test script reports the case as skipped.
gomarker:
	@if command -v go >/dev/null 2>&1; then \
	    mkdir -p $(BIN) scratch; \
	    (cd workloads/gomarker && \
	     CGO_ENABLED=0 GOPROXY=off GOFLAGS=-mod=mod \
	     GOCACHE="$(CURDIR)/scratch/go-cache" \
	     GOPATH="$(CURDIR)/scratch/go-path" \
	     go build -o "$(CURDIR)/$(BIN)/gomarker" .) && \
	    echo "built $(BIN)/gomarker"; \
	else \
	    echo "no go toolchain, the static Go case will be skipped"; \
	fi

$(BIN):
	mkdir -p $(BIN)

$(BIN)/procpoll: src/procpoll.c | $(BIN)
	$(CC) $(CFLAGS) -o $@ $<

$(BIN)/ptrace_full: src/ptrace_full.c | $(BIN)
	$(CC) $(CFLAGS) -o $@ $<

$(BIN)/selfcheck: src/selfcheck.c | $(BIN)
	$(CC) $(CFLAGS) -o $@ $<

$(BIN)/libafwpreload.so: src/preload.c | $(BIN)
	$(CC) $(CFLAGS) -fPIC -shared -o $@ $< -ldl

$(BIN)/marker_libc: workloads/marker_libc.c | $(BIN)
	$(CC) $(CFLAGS) -o $@ $<

$(BIN)/marker_rawsyscall: workloads/marker_rawsyscall.c | $(BIN)
	$(CC) $(CFLAGS) -o $@ $<

# Fedora 43 has no glibc-static package and this spike has no root. The
# program therefore uses no library: it brings its own entry point and it
# calls the kernel directly. The result has no INTERP segment, so the dynamic
# linker never runs and LD_PRELOAD cannot apply.
$(BIN)/marker_static: workloads/marker_static.c | $(BIN)
	$(CC) -O2 -Wall -Wextra -std=gnu11 -static -no-pie -nostdlib \
	    -nostartfiles -fno-stack-protector -fno-asynchronous-unwind-tables \
	    -o $@ $<

$(BIN)/vdso_and_mmap: workloads/vdso_and_mmap.c | $(BIN)
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -rf $(BIN)

.PHONY: all clean gomarker
