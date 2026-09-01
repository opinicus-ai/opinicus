#!/usr/bin/env bash
# The Landlock floor stress matrix of [af-12]: every case where the shipped
# floor's grant set meets a path that is not what it looks like.
#
# The contract of the floor is docs/LANDLOCK-CONTRACT.md. Each case here
# runs the real product (`agent-firewall run`, floor on) against one
# boundary of that contract and records the outcome: allowed, denied by the
# kernel, denied by the pack's question, or a hole the contract names. The
# committed table in docs/LANDLOCK-CONTRACT.md §7 is this script's output.
#
# Safety: no real credential is ever touched. Every session runs with a
# FAKE home directory (HOME is overridden for the monitor, which builds the
# plan from it), so the hidden stores are fixtures under
# <repo>/tmp/floor-stress/home. Overriding HOME also means the real home
# gets no grant in these sessions: a technique binary that lives in the
# repository cannot be executed there, so the io_uring technique is copied
# into the fake home first. The bind-mount cases need sudo and are skipped
# (and reported) when sudo -n is unavailable; every mount they make is
# unmounted again before the script ends. Nothing ever rm -rf's a directory
# that holds a mount: a recursive delete walks straight through a bind
# mount and would destroy the mounted source (this harness learned that the
# hard way in its first run).
#
# Usage: research/bypass/floor-stress.sh
set -uo pipefail

DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd -- "$DIR/../.." && pwd)"
FW="$REPO/target/release/agent-firewall"
OUT="$DIR/results/floor-stress"
BUILD="$REPO/research/bypass/bin"

if [ ! -x "$FW" ]; then
    printf 'floor-stress: build the workspace first: cargo build --release\n' >&2
    exit 2
fi
# The product needs ptrace to hold its sessions. At any yama scope other
# than 0 the sessions cannot start, every case fast-fails, and the run
# would overwrite good evidence with garbage (docs/DECISIONS.md,
# 2026-09-01). Refuse instead.
YAMA=$(cat /proc/sys/kernel/yama/ptrace_scope 2>/dev/null || echo unknown)
if [ "$YAMA" != "0" ]; then
    printf 'floor-stress: yama ptrace_scope is %s, and the product cannot start a traced session there;\n' "$YAMA" >&2
    printf 'floor-stress: refusing to run (see docs/DECISIONS.md, 2026-09-01, for the yama incident)\n' >&2
    exit 2
fi
mkdir -p "$OUT"

# --- fixtures ---------------------------------------------------------------

SCRATCH="$REPO/tmp/floor-stress"
HOME_FX="$SCRATCH/home"
if mountpoint -q "$HOME_FX/.ssh" 2>/dev/null; then
    printf 'floor-stress: %s is a mount point; refusing to run\n' "$HOME_FX/.ssh" >&2
    exit 2
fi
rm -rf "$SCRATCH"
mkdir -p "$HOME_FX/.ssh" "$HOME_FX/.aws" "$HOME_FX/proj" "$HOME_FX/repo"
echo "PRIVATE KEY FIXTURE" >"$HOME_FX/.ssh/id_rsa"
echo "ssh-ed25519 FIXTURE" >"$HOME_FX/.ssh/id_rsa.pub"
printf '[default]\naws_secret_access_key = FIXTURE\n' >"$HOME_FX/.aws/credentials"

MOUNTS=""
cleanup() {
    for m in $MOUNTS; do
        sudo -n umount "$m" >/dev/null 2>&1 || true
    done
    rm -rf -- "$SCRATCH" /tmp/afw-fs-* 2>/dev/null
    return 0
}
trap cleanup EXIT

HAVE_SUDO=0
if sudo -n true >/dev/null 2>&1; then
    HAVE_SUDO=1
fi

if [ ! -x "$BUILD/uring" ]; then
    "$DIR/techniques/build.sh" >/dev/null 2>&1 || true
fi
# The technique must live where the floor grants an exec: the fake home.
if [ -x "$BUILD/uring" ]; then
    cp "$BUILD/uring" "$HOME_FX/uring"
fi

# One guarded session in a caller-prepared working directory. The caller
# owns the directory; this function never removes anything.
# Usage: run_case ID MODE WORKDIR CMD...
run_case() {
    local id="$1" mode="$2" work="$3"
    shift 3
    (
        cd "$work" || exit 99
        HOME="$HOME_FX" timeout 60 "$FW" run --approve deny \
            --syscall-filter "$mode" --trace "$OUT/$id.trace.jsonl" -- "$@"
    ) >"$OUT/$id.out" 2>"$OUT/$id.err"
    echo $?
}

# questions ID — how many approval questions the trace of one case holds.
questions() {
    grep -c '"type": *"approval_requested"' "$OUT/$1.trace.jsonl" 2>/dev/null
    true
}
qcount() {
    local n
    n=$(grep -c '"type": *"approval_requested"' "$OUT/$1.trace.jsonl" 2>/dev/null)
    echo "${n:-0}"
}

TABLE=()
PASS=0
FAIL=0

expect() {
    # expect ID DESCRIPTION CONTRACT_OUTCOME COND(0/1) MEASURED
    local id="$1" desc="$2" want="$3" got_cond="$4" measured="$5"
    local verdict
    if [ "$got_cond" -eq 1 ]; then
        verdict="HELD"
        PASS=$((PASS + 1))
        printf '  ok   %s\n' "$id"
    else
        verdict="NOT HELD"
        FAIL=$((FAIL + 1))
        printf '  FAIL %s\n' "$id"
    fi
    TABLE+=("| $id | $desc | $want | $verdict | $measured |")
}

printf '== the Landlock floor stress matrix ==\n'
printf 'machine: %s %s\n' "$(uname -srm)" "$(date -u +%Y-%m-%dT%H:%M:%SZ)"

# ---------------------------------------------------------------------------
printf '\n-- symlinks out of the work tree to a hidden store --\n'
# ---------------------------------------------------------------------------

W="/tmp/afw-fs-s1"
rm -rf -- "$W"; mkdir -p -- "$W"
ln -s "$HOME_FX/.ssh/id_rsa" "$W/ln-key"
rc=$(run_case s1 all-opens "$W" cat "$W/ln-key")
expect "S1" \
    "symlink in the work tree to the hidden key" \
    "denied by the kernel: the rule names the object, not the path" \
    $([ "$rc" -ne 0 ] && [ "$(qcount s1)" -eq 0 ] && echo 1 || echo 0) \
    "exit=$rc questions=$(qcount s1) err=$(grep -c 'Permission denied' "$OUT/s1.err")"

W="/tmp/afw-fs-s2"
rm -rf -- "$W"; mkdir -p -- "$W"
ln -s "$HOME_FX/.ssh" "$W/ln-ssh"
rc=$(run_case s2 all-opens "$W" cat "$W/ln-ssh/id_rsa")
expect "S2" \
    "symlink in the work tree to the hidden .ssh directory" \
    "denied by the kernel: the rule names the object, not the path" \
    $([ "$rc" -ne 0 ] && [ "$(qcount s2)" -eq 0 ] && echo 1 || echo 0) \
    "exit=$rc questions=$(qcount s2) err=$(grep -c 'Permission denied' "$OUT/s2.err")"

W="/tmp/afw-fs-s2c"
rm -rf -- "$W"; mkdir -p -- "$W"
ln -s "$HOME_FX/proj" "$W/ln-proj"
rc=$(run_case s2c all-opens "$W" sh -c "echo x > '$W/ln-proj/f.txt' && cat '$W/ln-proj/f.txt'")
expect "S2c" \
    "control: symlink to a NON-hidden granted home entry" \
    "allowed: the object is a granted home entry" \
    $([ "$rc" -eq 0 ] && [ "$(qcount s2c)" -eq 0 ] && echo 1 || echo 0) \
    "exit=$rc questions=$(qcount s2c)"

# ---------------------------------------------------------------------------
printf '\n-- hard link out of a hidden store --\n'
# ---------------------------------------------------------------------------

W="/tmp/afw-fs-s7"
rm -rf -- "$W"; mkdir -p -- "$W"
rc=$(run_case s7 off "$W" ln "$HOME_FX/.ssh/id_rsa" "$W/key-copy")
expect "S7" \
    "hard link from the hidden key into the work tree" \
    "denied by the kernel: no REFER between the hierarchies" \
    $([ "$rc" -ne 0 ] && [ ! -e "$W/key-copy" ] && echo 1 || echo 0) \
    "exit=$rc copy_exists=$([ -e "$W/key-copy" ] && echo yes || echo no)"

# ---------------------------------------------------------------------------
printf '\n-- credential shapes under /tmp and the work tree --\n'
# ---------------------------------------------------------------------------

SHAPE3="/tmp/afw-fs3-shape"
rm -rf -- "$SHAPE3"
mkdir -p "$SHAPE3/.ssh"
echo "TMP KEY FIXTURE" >"$SHAPE3/.ssh/id_rsa"
W="/tmp/afw-fs-s3"
rm -rf -- "$W"; mkdir -p -- "$W"
rc=$(run_case s3 all-opens "$W" cat "$SHAPE3/.ssh/id_rsa")
expect "S3" \
    "a .ssh pre-placed under /tmp, read" \
    "allowed: the /tmp grant covers the shape; the pack only reports" \
    $([ "$rc" -eq 0 ] && [ "$(qcount s3)" -eq 0 ] && echo 1 || echo 0) \
    "exit=$rc questions=$(qcount s3)"

W="/tmp/afw-fs-s4"
rm -rf -- "$W"; mkdir -p -- "$W"
rc=$(run_case s4 off "$W" sh -c \
    'mkdir -p /tmp/afw-fs4-shape/.ssh && printf NEW > /tmp/afw-fs4-shape/.ssh/id_rsa && cat /tmp/afw-fs4-shape/.ssh/id_rsa')
expect "S4" \
    "a .ssh created under /tmp during the session, filter off" \
    "allowed: the writable-tree hole (the contract names it)" \
    $([ "$rc" -eq 0 ] && [ "$(cat /tmp/afw-fs4-shape/.ssh/id_rsa 2>/dev/null)" = "NEW" ] && echo 1 || echo 0) \
    "exit=$rc content=$(cat /tmp/afw-fs4-shape/.ssh/id_rsa 2>/dev/null || echo none)"

W="/tmp/afw-fs-s5"
rm -rf -- "$W"; mkdir -p -- "$W"
rc=$(run_case s5 write-only "$W" sh -c \
    'mkdir -p /tmp/afw-fs5-shape/.ssh && printf NEW > /tmp/afw-fs5-shape/.ssh/id_rsa')
expect "S5" \
    "a .ssh created under /tmp, write, default filter" \
    "denied by the pack question (the floor does not cover /tmp shapes)" \
    $([ "$rc" -ne 0 ] && [ "$(qcount s5)" -ge 1 ] && [ ! -e /tmp/afw-fs5-shape/.ssh/id_rsa ] && echo 1 || echo 0) \
    "exit=$rc questions=$(qcount s5) written=$([ -e /tmp/afw-fs5-shape/.ssh/id_rsa ] && echo yes || echo no)"

W="/tmp/afw-fs-s6"
rm -rf -- "$W"; mkdir -p -- "$W/work"
rc=$(run_case s6 write-only "$W" sh -c \
    'mkdir -p work/.ssh && printf NEW > work/.ssh/id_rsa')
expect "S6" \
    "a .ssh created in the work tree, write, default filter" \
    "denied by the pack question (the floor does not cover work-tree shapes)" \
    $([ "$rc" -ne 0 ] && [ "$(qcount s6)" -ge 1 ] && [ ! -e "$W/work/.ssh/id_rsa" ] && echo 1 || echo 0) \
    "exit=$rc questions=$(qcount s6)"

# ---------------------------------------------------------------------------
printf '\n-- bind mounts (sudo; unmounted again after each case) --\n'
# ---------------------------------------------------------------------------

if [ "$HAVE_SUDO" -eq 1 ]; then
    W="/tmp/afw-fs-s8"
    rm -rf -- "$W"; mkdir -p -- "$W/mnt-ssh"
    if sudo -n mount --bind "$HOME_FX/.ssh" "$W/mnt-ssh" 2>"$OUT/s8.mount.err"; then
        MOUNTS="$W/mnt-ssh $MOUNTS"
        rc=$(run_case s8 all-opens "$W" cat "$W/mnt-ssh/id_rsa")
        sudo -n umount "$W/mnt-ssh"
        MOUNTS="${MOUNTS//$W\/mnt-ssh/}"
        expect "S8" \
            "the hidden .ssh bind-mounted into the work tree" \
            "named hole: the grant follows the mount path, so an alias a privileged hand made reads the store; the agent itself cannot mount" \
            $([ "$rc" -eq 0 ] && [ "$(qcount s8)" -eq 0 ] && echo 1 || echo 0) \
            "exit=$rc questions=$(qcount s8) (a denial would flip this row and the contract)"

        W="/tmp/afw-fs-s8c"
        rm -rf -- "$W"; mkdir -p -- "$W/mnt-proj"
        if sudo -n mount --bind "$HOME_FX/proj" "$W/mnt-proj" 2>/dev/null; then
            MOUNTS="$W/mnt-proj $MOUNTS"
            rc=$(run_case s8c all-opens "$W" sh -c "echo x > '$W/mnt-proj/f.txt' && cat '$W/mnt-proj/f.txt'")
            sudo -n umount "$W/mnt-proj"
            MOUNTS="${MOUNTS//$W\/mnt-proj/}"
            expect "S8c" \
                "control: a NON-hidden home entry bind-mounted into the work tree" \
                "allowed: the object is a granted home entry" \
                $([ "$rc" -eq 0 ] && [ "$(qcount s8c)" -eq 0 ] && echo 1 || echo 0) \
                "exit=$rc questions=$(qcount s8c)"
        else
            expect "S8c" "control bind mount" "mount failed" 1 "mount-error"
        fi
    else
        expect "S8" "bind mount of .ssh into the work tree" "mount failed" 0 \
            "mount-error=$(head -c 120 "$OUT/s8.mount.err" | tr -d '\n')"
    fi

    MP="/tmp/afw-fs9-mount"
    rm -rf -- "$MP"; mkdir -p -- "$MP"
    if sudo -n mount --bind "$HOME_FX/proj" "$MP" 2>"$OUT/s9.mount.err"; then
        MOUNTS="$MP $MOUNTS"
        rc=$(run_case s9 write-only "$MP" sh -c 'printf x > f.txt && cat f.txt')
        sudo -n umount "$MP"
        MOUNTS="${MOUNTS//$MP/}"
        expect "S9" \
            "the work tree itself is a bind mount of a home entry" \
            "allowed: the session works in its work tree" \
            $([ "$rc" -eq 0 ] && [ "$(qcount s9)" -eq 0 ] && echo 1 || echo 0) \
            "exit=$rc questions=$(qcount s9)"
    else
        expect "S9" "bind-mounted work tree" "mount failed" 0 \
            "mount-error=$(head -c 120 "$OUT/s9.mount.err" | tr -d '\n')"
    fi
else
    expect "S8" "bind mount of .ssh into the work tree" "needs sudo" 1 "SKIPPED: no passwordless sudo"
    expect "S9" "bind-mounted work tree" "needs sudo" 1 "SKIPPED: no passwordless sudo"
fi

# ---------------------------------------------------------------------------
printf '\n-- a git worktree whose repository lives in the home --\n'
# ---------------------------------------------------------------------------

(
    cd "$HOME_FX/repo" || exit 1
    git init -q .
    git config user.email probe@example.com
    git config user.name probe
    echo hello >README.md
    git add README.md
    git commit -qm first
) >/dev/null 2>&1
rm -rf /tmp/afw-fs10-wt
git -C "$HOME_FX/repo" worktree add -q /tmp/afw-fs10-wt >/dev/null 2>&1
W="/tmp/afw-fs-s10"
rm -rf -- "$W"; mkdir -p -- "$W"
rc=$(run_case s10 write-only /tmp/afw-fs10-wt \
    sh -c 'printf x > f.txt && git add f.txt && git commit -qm second')
commits=$(git -C /tmp/afw-fs10-wt rev-list --count HEAD 2>/dev/null)
expect "S10" \
    "a git worktree at /tmp of a repo under the home" \
    "allowed: writes into the repo's .git under the home are granted" \
    $([ "$rc" -eq 0 ] && [ "$(qcount s10)" -eq 0 ] && [ "${commits:-0}" -ge 2 ] && echo 1 || echo 0) \
    "exit=$rc questions=$(qcount s10) commits=${commits:-none}"

# ---------------------------------------------------------------------------
printf '\n-- io_uring: an open the seccomp filter cannot see --\n'
# ---------------------------------------------------------------------------

if [ -x "$HOME_FX/uring" ]; then
    rc=$(run_case s11 off "$HOME_FX" "$HOME_FX/uring" "$HOME_FX/.ssh/id_rsa")
    key=$(cat "$HOME_FX/.ssh/id_rsa" 2>/dev/null)
    expect "S11" \
        "io_uring write-intent open of the hidden key, filter off" \
        "denied by the kernel: the floor mediates the ring-issued open of a hidden store" \
        $([ "$key" = "PRIVATE KEY FIXTURE" ] && grep -q 'blocked rc=-13' "$OUT/s11.out" && echo 1 || echo 0) \
        "exit=$rc key_unchanged=$([ "$key" = "PRIVATE KEY FIXTURE" ] && echo yes || echo no); $(grep -o 'ACTION uring.*' "$OUT/s11.out" | head -1)"
else
    expect "S11" "io_uring write-intent open of the hidden key" "needs the technique build" 0 \
        "SKIPPED: research/bypass/bin/uring missing"
fi

# ---------------------------------------------------------------------------
printf '\n== the table ==\n'
printf '| case | what it tries | the contract says | verdict | measured |\n'
printf '| --- | --- | --- | --- | --- |\n'
for row in "${TABLE[@]}"; do
    printf '%s\n' "$row"
done
printf '\npass=%s fail=%s\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
