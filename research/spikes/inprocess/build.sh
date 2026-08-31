#!/usr/bin/env bash
# Builds the in-process sensor of M2 into libafsensor.so.
set -euo pipefail
DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cc -O2 -Wall -Wextra -shared -fPIC -o "$DIR/libafsensor.so" "$DIR/shim.c" \
    -ldl -lpthread
ls -l "$DIR/libafsensor.so"
