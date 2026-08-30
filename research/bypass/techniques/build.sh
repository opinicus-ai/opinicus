#!/usr/bin/env bash
# Builds every bypass technique into research/bypass/bin/.
set -euo pipefail
DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
OUT="$DIR/../bin"
mkdir -p "$OUT"
for src in "$DIR"/*.c; do
    cc -O2 -Wall -o "$OUT/$(basename "${src%.c}")" "$src"
done
for src in "$DIR"/*.sh "$DIR"/pydrop; do
    install -m 0755 "$src" "$OUT/$(basename "$src")"
done
CGO_ENABLED=0 go build -o "$OUT/static-file-net" "$DIR/static-file-net.go"
ls -1 "$OUT"
