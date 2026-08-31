#!/bin/sh
# The benign corpus of [af-1]/[af-2]: a scripted normal dev session that must
# never trigger a question. Shared by research/bypass/benign.sh (under the
# firewall) and research/spikes/inprocess/run-corpus.sh (under the sensor).
set -e
git init -q .
git config user.email probe@example.com
git config user.name probe
echo hello > README.md
git add README.md
git commit -qm "first"
git log --oneline
git status --short
# The cargo crate is created and built OUTSIDE the repository: cargo new
# registers a new crate into any workspace it finds by walking upward, and
# it rewrites that root manifest. A standalone directory in /tmp cannot
# pollute the repository workspace; the built binary is copied back.
CRATE="$(mktemp -d /tmp/af-corpus.XXXXXX)"
cargo new --offline -q "$CRATE/tool"
(cd "$CRATE/tool" && cargo build --offline -q)
mkdir tool
cp "$CRATE/tool/target/debug/tool" tool/tool
./tool/tool
rm -rf "$CRATE"
mkdir web && (cd web && npm init -y >/dev/null 2>&1 && npm --version >/dev/null)
python3 -c 'print("corpus", 6 * 7)'
find . -name '*.md' | sort
grep -r hello README.md
