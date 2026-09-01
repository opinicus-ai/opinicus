#!/usr/bin/env bash
# The io_uring compatibility matrix of [af-12] (EXP-T1): what breaks when
# io_uring_setup and io_uring_enter are denied.
#
# Two engines answer the same two questions — does the workload call the
# ring syscalls at all, and what happens when they are refused with EPERM:
#
#   monitor   the product itself: `agent-firewall run --approve deny` with
#             the built-in deny (`tamper.bypass.io-uring`) active, the full
#             posture (filter, floor, rules). Needs ptrace.
#   standin   research/bypass/standin/uring-standin: a seccomp-only
#             stand-in that holds the same two calls with no monitor. The
#             `deny` mode answers them EPERM — the same refusal the product
#             produces — and the `count` mode continues every call and logs
#             it, which measures whether the product's rule would fire at
#             all. Runs where ptrace is unavailable (yama scope 3).
#
# Every workload runs a baseline (no filter) and both stand-in modes, plus
# the monitor engine when one argument names it. The corpus runs in every
# engine.
#
# The numbers this prints are the source of the default-deny decision in
# docs/DECISIONS.md (2026-09-01); re-run with:
#   ./uring-compat.sh                # stand-in engine
#   ./uring-compat.sh monitor        # the product engine (needs ptrace)
set -euo pipefail
DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd -- "$DIR/../.." && pwd)"
FW="$REPO/target/release/agent-firewall"
STANDIN="$DIR/standin/uring-standin"
OUT="$DIR/results/uring-compat"
WORK_ROOT="$REPO/tmp/uring-compat"
ENGINE="${1:-standin}"

mkdir -p "$OUT"
# One scratch root per invocation, so a re-run measures fresh state.
rm -rf "$WORK_ROOT"
mkdir -p "$WORK_ROOT"

fail() { printf 'uring-compat: %s\n' "$1" >&2; exit 2; }
if [ ! -x "$STANDIN" ]; then
    command -v cc >/dev/null || fail "cc not found; build $STANDIN manually"
    (cd "$(dirname "$STANDIN")" && cc -O2 -Wall -Wextra -o uring-standin uring-standin.c) || \
        fail "cannot build the stand-in"
fi
[ -x "$STANDIN" ] || fail "missing $STANDIN"
if [ "$ENGINE" = monitor ]; then
    [ -x "$FW" ] || fail "missing $FW; run cargo build --release"
fi
command -v sqlite3 >/dev/null || fail "sqlite3 not found"
command -v npm >/dev/null || fail "npm not found"

# Runs one workload under the chosen engine. A non-empty PRE_HOOK runs
# before each sub-run, so a workload that consumes its own work (the cargo
# rebuild) can reset its own precondition.
#   $1 name, $2 workdir, rest: command
# Prints "<exit> <io_uring_calls> <session-exit-or-dash>".
run_engine() {
    local name="$1" dir="$2"; shift 2
    local log="$OUT/$name.count"
    local exit_count=0 exit_deny=0 session="-"
    [ -z "${PRE_HOOK:-}" ] || (cd "$dir" && sh -c "$PRE_HOOK")
    (cd "$dir" && "$STANDIN" count "$log" "$@") >/dev/null 2>&1 || exit_count=$?
    [ -z "${PRE_HOOK:-}" ] || (cd "$dir" && sh -c "$PRE_HOOK")
    (cd "$dir" && "$STANDIN" deny "$@") >"$OUT/$name.deny.out" 2>"$OUT/$name.deny.err" || exit_deny=$?
    if [ "$ENGINE" = monitor ]; then
        local trace="$OUT/$name.trace.jsonl"
        rm -f "$trace"
        [ -z "${PRE_HOOK:-}" ] || (cd "$dir" && sh -c "$PRE_HOOK")
        set +e
        (cd "$dir" && "$FW" run --approve deny --retention all --trace "$trace" "$@") \
            >"$OUT/$name.monitor.out" 2>"$OUT/$name.monitor.err"
        local fw_exit=$?
        set -e
        session=$(grep -o '"exit_code":[0-9]*' "$trace" | tail -1 | cut -d: -f2)
        [ -n "$session" ] || session="-"
    fi
    local calls=0
    [ -f "$log" ] && calls=$(grep -c . "$log" || true)
    printf '%s %s %s' "$exit_deny" "$calls" "$session"
}

# Reports one row: name, deny exit, io_uring calls under count, monitor
# session exit (or -), effect under deny (yes/no).
row() {
    if [ "$4" = yes ]; then local effect=works; else effect=BROKEN; fi
    printf '%-19s deny-exit=%-3s io_uring_calls=%-3s monitor-session=%-4s effect=%s\n' \
        "$1" "$2" "$3" "${5:--}" "$effect"
}

verify_cargo() { [ "$FW" -nt "$REPO/crates/af-core/src/lib.rs" ]; }
verify_git() {
    [ -f "$1/README.md" ] && [ -z "$(git -C "$1" status --short | head -1)" ]
}
verify_venv() { "$1/bin/python" -c 'import af12probe; assert af12probe.probe() == 42' 2>/dev/null; }
verify_tar() {
    # 1001 entries: the directory itself plus the thousand files.
    tar -tf "$1" >/dev/null 2>&1 && [ "$(tar -tf "$1" | wc -l)" -eq 1001 ]
}
verify_sqlite() { [ "$(sqlite3 "$1" 'select count(*) from t;' 2>/dev/null)" = 10000 ]; }
verify_npm() { [ -d "$1/node_modules/is-odd" ]; }

echo "== engine: $ENGINE (stand-in always measured; monitor columns when engine=monitor) =="
echo "== preparation (no filter): scratch trees the workloads consume =="

GIT_SRC="$WORK_ROOT/gitsrc"
mkdir -p "$GIT_SRC"
(
    cd "$GIT_SRC"
    git init -q .
    git config user.email probe@example.com
    git config user.name probe
    mkdir -p src
    for i in $(seq 1 400); do printf 'line %s\n' "$i" > "src/file-$i.txt"; done
    echo "# probe" > README.md
    git add -A >/dev/null
    git commit -qm first
)

NPM_SRC="$WORK_ROOT/npmpkg"
mkdir -p "$NPM_SRC"
(
    cd "$NPM_SRC"
    npm init -y >/dev/null 2>&1
    npm install --package-lock-only is-odd >/dev/null 2>&1
)

WHEELS="$WORK_ROOT/wheels"
WHEELSRC="$WORK_ROOT/wheelsrc"
mkdir -p "$WHEELS" "$WHEELSRC"
printf '[project]\nname = "af12probe"\nversion = "1.0.0"\nrequires-python = ">=3.9"\n' \
    > "$WHEELSRC/pyproject.toml"
printf 'def probe():\n    return 42\n' > "$WHEELSRC/af12probe.py"
python3 -m pip wheel --no-deps -q -w "$WHEELS" "$WHEELSRC" >/dev/null 2>&1

TAR_SRC="$WORK_ROOT/tarsrc"
mkdir -p "$TAR_SRC/src"
for i in $(seq 1 1000); do printf 'payload %s\n' "$i" > "$TAR_SRC/src/file-$i.txt"; done

SQL="$WORK_ROOT/bulk.sql"
{
    echo "create table t (id integer primary key, body text);"
    echo "begin;"
    for i in $(seq 1 10000); do echo "insert into t values ($i, 'row $i');"; done
    echo "commit;"
} > "$SQL"

# cargo: every measurement bumps the mtime of a real source file, so each
# run measures a real incremental rebuild of this repository (af-core and
# every crate below it) and not a no-op.

echo "== baseline (no filter) =="
sleep 1
touch "$REPO/crates/af-core/src/lib.rs"
B_CARGO=0
(cd "$REPO" && cargo build --release -q) || B_CARGO=$?
verify_cargo && B_CARGO_EFFECT=yes || B_CARGO_EFFECT=no

B_GIT=0
git clone -q "$GIT_SRC" "$WORK_ROOT/git-baseline" || B_GIT=$?
[ -z "$(git -C "$WORK_ROOT/git-baseline" status --short | head -1)" ] && B_GIT_EFFECT=yes || B_GIT_EFFECT=no

B_NPM=0
rm -rf "$WORK_ROOT/npm-baseline"
cp -r "$NPM_SRC" "$WORK_ROOT/npm-baseline"
(cd "$WORK_ROOT/npm-baseline" && npm ci >/dev/null 2>&1) || B_NPM=$?
verify_npm "$WORK_ROOT/npm-baseline" && B_NPM_EFFECT=yes || B_NPM_EFFECT=no

B_VENV=0
rm -rf "$WORK_ROOT/venv-baseline"
(python3 -m venv "$WORK_ROOT/venv-baseline" && \
    "$WORK_ROOT/venv-baseline/bin/pip" install --no-index --find-links "$WHEELS" -q af12probe) || B_VENV=$?
verify_venv "$WORK_ROOT/venv-baseline" && B_VENV_EFFECT=yes || B_VENV_EFFECT=no

B_TAR=0
tar -cf "$WORK_ROOT/out-baseline.tar" -C "$TAR_SRC" src || B_TAR=$?
verify_tar "$WORK_ROOT/out-baseline.tar" && B_TAR_EFFECT=yes || B_TAR_EFFECT=no

B_SQL=0
rm -f "$WORK_ROOT/base.db"
sqlite3 "$WORK_ROOT/base.db" < "$SQL" || B_SQL=$?
verify_sqlite "$WORK_ROOT/base.db" && B_SQL_EFFECT=yes || B_SQL_EFFECT=no

printf 'cargo-build         exit=%-3s effect=%s\n' "$B_CARGO" "$B_CARGO_EFFECT"
printf 'git-clone+status    exit=%-3s effect=%s\n' "$B_GIT" "$B_GIT_EFFECT"
printf 'npm-ci              exit=%-3s effect=%s\n' "$B_NPM" "$B_NPM_EFFECT"
printf 'venv+pip-local      exit=%-3s effect=%s\n' "$B_VENV" "$B_VENV_EFFECT"
printf 'tar-cf-1000-files   exit=%-3s effect=%s\n' "$B_TAR" "$B_TAR_EFFECT"
printf 'sqlite-bulk-insert  exit=%-3s effect=%s\n' "$B_SQL" "$B_SQL_EFFECT"

echo
echo "== the deny matrix =="
[ "$B_CARGO_EFFECT" = yes ] || fail "the cargo baseline is broken; the matrix would measure nothing"

# 1. cargo build of this repository: every sub-run bumps the mtime of a
# real source file, so each measures a real incremental rebuild (af-core
# and every crate below it) that must produce a fresh binary.
PRE_HOOK="sleep 1; touch '$REPO/crates/af-core/src/lib.rs'"
read D_CARGO C_CARGO S_CARGO <<<"$(run_engine cargo "$REPO" cargo build --release)"
PRE_HOOK=""
verify_cargo && CARGO_EFFECT=yes || CARGO_EFFECT=no
row cargo-build "$D_CARGO" "$C_CARGO" "$CARGO_EFFECT" "$S_CARGO"

# 2. git clone of the local scratch repository, then status.
PRE_HOOK="rm -rf '$WORK_ROOT/git-deny'"
read D_GIT C_GIT S_GIT <<<"$(run_engine git "$WORK_ROOT" sh -c \
    "git clone -q '$GIT_SRC' '$WORK_ROOT/git-deny' && git -C '$WORK_ROOT/git-deny' status --short")"
PRE_HOOK=""
verify_git "$WORK_ROOT/git-deny" && GIT_EFFECT=yes || GIT_EFFECT=no
row git-clone+status "$D_GIT" "$C_GIT" "$GIT_EFFECT" "$S_GIT"

# 3. npm ci in the scratch package.
rm -rf "$WORK_ROOT/npm-deny"
cp -r "$NPM_SRC" "$WORK_ROOT/npm-deny"
PRE_HOOK="rm -rf '$WORK_ROOT/npm-deny/node_modules'"
read D_NPM C_NPM S_NPM <<<"$(run_engine npm "$WORK_ROOT/npm-deny" npm ci)"
PRE_HOOK=""
verify_npm "$WORK_ROOT/npm-deny" && NPM_EFFECT=yes || NPM_EFFECT=no
row npm-ci "$D_NPM" "$C_NPM" "$NPM_EFFECT" "$S_NPM"

# 4. python venv plus pip install from the local wheel directory.
PRE_HOOK="rm -rf '$WORK_ROOT/venv-deny'"
read D_VENV C_VENV S_VENV <<<"$(run_engine venv "$WORK_ROOT" sh -c \
    "python3 -m venv '$WORK_ROOT/venv-deny' && '$WORK_ROOT/venv-deny/bin/pip' install --no-index --find-links '$WHEELS' af12probe")"
PRE_HOOK=""
verify_venv "$WORK_ROOT/venv-deny" && VENV_EFFECT=yes || VENV_EFFECT=no
row venv+pip-local "$D_VENV" "$C_VENV" "$VENV_EFFECT" "$S_VENV"

# 5. tar of the thousand-file tree.
PRE_HOOK="rm -f '$WORK_ROOT/out-deny.tar'"
read D_TAR C_TAR S_TAR <<<"$(run_engine tar "$WORK_ROOT" tar -cf "$WORK_ROOT/out-deny.tar" -C "$TAR_SRC" src)"
PRE_HOOK=""
verify_tar "$WORK_ROOT/out-deny.tar" && TAR_EFFECT=yes || TAR_EFFECT=no
row tar-cf-1000-files "$D_TAR" "$C_TAR" "$TAR_EFFECT" "$S_TAR"

# 6. sqlite bulk insert.
PRE_HOOK="rm -f '$WORK_ROOT/deny.db'"
read D_SQL C_SQL S_SQL <<<"$(run_engine sqlite "$WORK_ROOT" sh -c "sqlite3 '$WORK_ROOT/deny.db' < '$SQL'")"
PRE_HOOK=""
verify_sqlite "$WORK_ROOT/deny.db" && SQL_EFFECT=yes || SQL_EFFECT=no
row sqlite-bulk-insert "$D_SQL" "$C_SQL" "$SQL_EFFECT" "$S_SQL"

echo
echo "== the corpus: does a normal dev session ever call the ring? =="
CORPUS="$WORK_ROOT/corpus"
rm -rf "$CORPUS"
mkdir -p "$CORPUS"
install -m 0755 "$DIR/corpus.sh" "$CORPUS/corpus.sh"
PRE_HOOK="rm -rf '$CORPUS' && mkdir -p '$CORPUS' && install -m 0755 '$DIR/corpus.sh' '$CORPUS/corpus.sh'"
read D_CORPUS C_CORPUS S_CORPUS <<<"$(run_engine corpus "$CORPUS" sh corpus.sh)"
PRE_HOOK=""
if [ "$D_CORPUS" = 0 ] && [ -f "$CORPUS/README.md" ] && [ -d "$CORPUS/web" ]; then
    CORPUS_EFFECT=yes
else
    CORPUS_EFFECT=no
fi
row corpus "$D_CORPUS" "$C_CORPUS" "$CORPUS_EFFECT" "$S_CORPUS"

echo
echo "outputs: $OUT (regenerable)"
