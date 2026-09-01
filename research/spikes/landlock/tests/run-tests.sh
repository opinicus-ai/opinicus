#!/usr/bin/env bash
# The whole test set of the Landlock spike.
#
# Every test runs a short-lived child under `timeout`. No test can hang, and
# no test ever applies a ruleset to this shell. The sandbox always goes on a
# forked child of bin/afw-landlock.
#
# Nothing in the real home directory is ever changed. The one test that uses
# the real ~/.ssh only tries to READ it.
set -uo pipefail

HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$HERE"

BIN="$HERE/bin"
WORK="$HERE/work"
LL="$BIN/afw-landlock"
PROBE="$BIN/fs-probe"

# Every sandbox needs a runtime: the loader, the shared libraries and the
# programs. These three grants are the minimum for any dynamically linked
# program on Fedora.
RUNTIME=(--rx /usr --rx /etc --rx "$BIN")

PASS=0
FAIL=0

ok() { PASS=$((PASS + 1)); printf '  ok   %s\n' "$1"; }
no() { FAIL=$((FAIL + 1)); printf '  FAIL %s\n' "$1"; }

# assert_line NAME FILE PATTERN  — the output must hold a line that matches.
assert_line() {
    if grep -qE -- "$3" "$2"; then ok "$1"; else
        no "$1"
        printf '       wanted: %s\n' "$3"
        sed 's/^/       got:    /' "$2"
    fi
}

# assert_no_line NAME FILE PATTERN — the output must NOT hold such a line.
assert_no_line() {
    if grep -qE -- "$3" "$2"; then
        no "$1"
        printf '       must not hold: %s\n' "$3"
    else ok "$1"; fi
}

section() { printf '\n== %s ==\n' "$1"; }

rm -rf "$WORK"
mkdir -p "$WORK"
OUT="$WORK/out.txt"

# ---------------------------------------------------------------------------
section "A. the ABI of this kernel"
# ---------------------------------------------------------------------------
timeout 20 "$BIN/probe-abi" >"$WORK/abi.txt" 2>&1
assert_line "the kernel reports a Landlock ABI version" "$WORK/abi.txt" \
    'landlock_abi_version *= [0-9]+'
ABI="$(sed -n 's/^landlock_abi_version *= //p' "$WORK/abi.txt")"
printf '       ABI = %s\n' "$ABI"
assert_line "ABI 1 filesystem rights are present" "$WORK/abi.txt" 'fs.READ_FILE .*SUPPORTED'
assert_line "ABI 3 truncate is present" "$WORK/abi.txt" 'fs.TRUNCATE .*SUPPORTED'
assert_line "ABI 4 TCP connect is present" "$WORK/abi.txt" 'net.CONNECT_TCP .*SUPPORTED'
assert_line "ABI 5 IOCTL_DEV is present" "$WORK/abi.txt" 'fs.IOCTL_DEV .*SUPPORTED'

# ---------------------------------------------------------------------------
section "B1. a write outside the project fails, and a write inside succeeds"
# ---------------------------------------------------------------------------
mkdir -p "$WORK/project" "$WORK/outside"
echo ORIGINAL >"$WORK/project/inside.txt"
echo OUTSIDE >"$WORK/outside/outside.txt"

timeout 30 "$LL" "${RUNTIME[@]}" --rw "$WORK/project" -- \
    "$PROBE" \
    write "$WORK/project/inside.txt" \
    create "$WORK/project/new.txt" \
    mkdir "$WORK/project/newdir" \
    unlink "$WORK/project/new.txt" \
    write "$WORK/outside/outside.txt" \
    create "$WORK/outside/new.txt" \
    unlink "$WORK/outside/outside.txt" \
    read "$WORK/outside/outside.txt" \
    >"$OUT" 2>&1

assert_line "a write inside the project succeeds" "$OUT" "write $WORK/project/inside.txt -> OK"
assert_line "a create inside the project succeeds" "$OUT" "create $WORK/project/new.txt -> OK"
assert_line "a mkdir inside the project succeeds" "$OUT" "mkdir $WORK/project/newdir -> OK"
assert_line "a delete inside the project succeeds" "$OUT" "unlink $WORK/project/new.txt -> OK"
assert_line "a write outside gives EACCES" "$OUT" "write $WORK/outside/outside.txt -> FAIL errno=EACCES"
assert_line "a create outside gives EACCES" "$OUT" "create $WORK/outside/new.txt -> FAIL errno=EACCES"
assert_line "a delete outside gives EACCES" "$OUT" "unlink $WORK/outside/outside.txt -> FAIL errno=EACCES"
assert_line "a read outside gives EACCES" "$OUT" "read $WORK/outside/outside.txt -> FAIL errno=EACCES"

if [ "$(cat "$WORK/outside/outside.txt")" = "OUTSIDE" ]; then
    ok "the file outside the project is still on disk and unchanged"
else
    no "the file outside the project changed"
fi

# The same commands with no sandbox must all work. Without this the test
# above could pass for the wrong reason.
timeout 30 "$LL" --no-sandbox -- "$PROBE" \
    write "$WORK/outside/outside.txt" \
    read "$WORK/outside/outside.txt" >"$WORK/nosb.txt" 2>&1
assert_line "with no sandbox the same write succeeds" "$WORK/nosb.txt" \
    "write $WORK/outside/outside.txt -> OK"

# ---------------------------------------------------------------------------
section "B2. credentials become unreadable, and the rest of home stays readable"
# ---------------------------------------------------------------------------
# A fake home with the shape of a real one. Nothing real is touched here.
FH="$WORK/fakehome"
mkdir -p "$FH"/{.ssh,.aws,.config,projects/app,Documents}
echo "PRIVATE KEY" >"$FH/.ssh/id_ed25519"
echo "ssh-ed25519 AAAA" >"$FH/.ssh/id_ed25519.pub"
echo "host github.com" >"$FH/.ssh/known_hosts"
echo "aws_secret_access_key = AKIAEXAMPLE" >"$FH/.aws/credentials"
echo "region = eu-west-1" >"$FH/.aws/config"
echo "fn main() {}" >"$FH/projects/app/main.rs"
echo "notes" >"$FH/Documents/notes.txt"
echo "theme=dark" >"$FH/.config/settings"

timeout 30 "$LL" "${RUNTIME[@]}" \
    --ro "$FH" --hide "$FH/.ssh" --hide "$FH/.aws/credentials" -- \
    "$PROBE" \
    read "$FH/projects/app/main.rs" \
    read "$FH/Documents/notes.txt" \
    read "$FH/.config/settings" \
    read "$FH/.aws/config" \
    list "$FH" \
    read "$FH/.ssh/id_ed25519" \
    read "$FH/.ssh/known_hosts" \
    list "$FH/.ssh" \
    read "$FH/.aws/credentials" \
    >"$OUT" 2>&1

assert_line "project source stays readable" "$OUT" "read $FH/projects/app/main.rs -> OK"
assert_line "documents stay readable" "$OUT" "read $FH/Documents/notes.txt -> OK"
assert_line "the config directory stays readable" "$OUT" "read $FH/.config/settings -> OK"
assert_line "the non-secret AWS config stays readable" "$OUT" "read $FH/.aws/config -> OK"
# The carve-out has a price. The parent of a hidden path gets no rule of its
# own, so the parent itself cannot be listed. Landlock has no deny rule, and a
# right on a directory always reaches the whole subtree under it, so this
# price cannot be avoided. Test D4 below proves that.
assert_line "the price: the carved parent cannot be listed" "$OUT" \
    "list $FH -> FAIL errno=EACCES"
assert_line "the private key is unreadable" "$OUT" "read $FH/.ssh/id_ed25519 -> FAIL errno=EACCES"
assert_line "every file in .ssh is unreadable" "$OUT" "read $FH/.ssh/known_hosts -> FAIL errno=EACCES"
assert_line ".ssh cannot even be listed" "$OUT" "list $FH/.ssh -> FAIL errno=EACCES"
assert_line "the AWS credential file is unreadable" "$OUT" "read $FH/.aws/credentials -> FAIL errno=EACCES"

# The write side of the same product rule: filesystem.credentials.write.
timeout 30 "$LL" "${RUNTIME[@]}" \
    --rw "$FH" --hide "$FH/.ssh" --hide "$FH/.aws/credentials" -- \
    "$PROBE" \
    write "$FH/projects/app/main.rs" \
    write "$FH/.ssh/id_ed25519" \
    create "$FH/.ssh/backdoor_key" \
    write "$FH/.aws/credentials" \
    unlink "$FH/.ssh/known_hosts" \
    >"$OUT" 2>&1
assert_line "a write to project source still works" "$OUT" "write $FH/projects/app/main.rs -> OK"
assert_line "a write to the private key is denied" "$OUT" "write $FH/.ssh/id_ed25519 -> FAIL errno=EACCES"
assert_line "a new file in .ssh is denied" "$OUT" "create $FH/.ssh/backdoor_key -> FAIL errno=EACCES"
assert_line "a write to the AWS credential file is denied" "$OUT" "write $FH/.aws/credentials -> FAIL errno=EACCES"
assert_line "a delete inside .ssh is denied" "$OUT" "unlink $FH/.ssh/known_hosts -> FAIL errno=EACCES"
if [ "$(cat "$FH/.ssh/id_ed25519")" = "PRIVATE KEY" ]; then
    ok "the private key file is unchanged on disk"
else
    no "the private key file changed"
fi

# The real ~/.ssh, read only. This test never writes anything.
if [ -d "$HOME/.ssh" ]; then
    timeout 30 "$LL" "${RUNTIME[@]}" \
        --ro "$HOME" --hide "$HOME/.ssh" -- \
        "$PROBE" list "$HOME/.ssh" read "$HOME/.ssh/known_hosts" \
        list "$HOME/devel" >"$OUT" 2>&1
    assert_line "the real ~/.ssh cannot be listed in the sandbox" "$OUT" \
        "list $HOME/.ssh -> FAIL errno=EACCES"
    if [ -f "$HOME/.ssh/known_hosts" ]; then
        assert_line "a real file in ~/.ssh cannot be read in the sandbox" "$OUT" \
            "read $HOME/.ssh/known_hosts -> FAIL errno=EACCES"
    fi
    assert_line "the rest of the real home stays readable" "$OUT" \
        "list $HOME/devel -> OK"
    timeout 30 "$LL" --stats "${RUNTIME[@]}" --ro "$HOME" --hide "$HOME/.ssh" -- \
        /bin/true 2>"$WORK/carve-stats.txt"
    assert_line "the carve-out of the real home reports its cost" \
        "$WORK/carve-stats.txt" 'rules=[0-9]+ setup_us=[0-9]+'
    printf '       %s\n' "$(cat "$WORK/carve-stats.txt")"
else
    printf '  skip ~/.ssh does not exist on this machine\n'
fi

# What Landlock does NOT hide: metadata.
timeout 30 "$LL" "${RUNTIME[@]}" --ro "$FH" --hide "$FH/.ssh" -- \
    "$PROBE" stat "$FH/.ssh/id_ed25519" >"$OUT" 2>&1
assert_line "stat on a hidden file still succeeds (a real limit)" "$OUT" \
    "stat $FH/.ssh/id_ed25519 -> OK"

# ---------------------------------------------------------------------------
section "B3. a TCP connect to a port the ruleset does not allow fails"
# ---------------------------------------------------------------------------
ALLOWED_PORT=18101
DENIED_PORT=18102
timeout 25 "$BIN/tcp-listener" "$ALLOWED_PORT" 20 >"$WORK/l1.txt" 2>&1 &
L1=$!
timeout 25 "$BIN/tcp-listener" "$DENIED_PORT" 20 >"$WORK/l2.txt" 2>&1 &
L2=$!
sleep 1

# Both listeners really run, so a denial cannot be mistaken for "nothing
# listens there".
timeout 30 "$LL" --no-sandbox -- "$PROBE" \
    connect "$ALLOWED_PORT" connect "$DENIED_PORT" >"$WORK/net-open.txt" 2>&1
assert_line "with no sandbox the allowed port answers" "$WORK/net-open.txt" \
    "connect $ALLOWED_PORT -> OK"
assert_line "with no sandbox the other port answers too" "$WORK/net-open.txt" \
    "connect $DENIED_PORT -> OK"

timeout 30 "$LL" "${RUNTIME[@]}" --handle-net --connect-tcp "$ALLOWED_PORT" -- \
    "$PROBE" connect "$ALLOWED_PORT" connect "$DENIED_PORT" >"$OUT" 2>&1
assert_line "the allowed TCP port still answers in the sandbox" "$OUT" \
    "connect $ALLOWED_PORT -> OK"
assert_line "the port that is not in the ruleset gives EACCES" "$OUT" \
    "connect $DENIED_PORT -> FAIL errno=EACCES"

# A bind to a port that no rule allows.
timeout 30 "$LL" "${RUNTIME[@]}" --handle-net --bind-tcp 18103 -- \
    "$PROBE" bind 18103 bind 18104 >"$OUT" 2>&1
assert_line "a bind to the allowed port succeeds" "$OUT" "bind 18103 -> OK"
assert_line "a bind to another port gives EACCES" "$OUT" "bind 18104 -> FAIL errno=EACCES"

kill "$L1" "$L2" 2>/dev/null
wait "$L1" "$L2" 2>/dev/null

# ---------------------------------------------------------------------------
section "B4. the restriction is inherited by children and grandchildren"
# ---------------------------------------------------------------------------
timeout 30 "$LL" "${RUNTIME[@]}" --rw "$WORK/project" -- \
    /bin/sh -c "/bin/sh -c '/bin/sh -c \"$PROBE read $WORK/outside/outside.txt read $WORK/project/inside.txt\"'" \
    >"$OUT" 2>&1
assert_line "a great-grandchild is still denied outside the project" "$OUT" \
    "read $WORK/outside/outside.txt -> FAIL errno=EACCES"
assert_line "a great-grandchild is still allowed inside the project" "$OUT" \
    "read $WORK/project/inside.txt -> OK"

# The same through a real tool chain, so it is not only our own program.
timeout 30 "$LL" "${RUNTIME[@]}" --rw "$WORK/project" -- \
    /bin/sh -c "/bin/sh -c 'cat $WORK/outside/outside.txt'" >"$OUT" 2>&1
assert_line "cat two shells deep cannot read outside" "$OUT" 'Permission denied'

timeout 30 "$LL" "${RUNTIME[@]}" --rw "$WORK/project" -- \
    /bin/sh -c "/bin/sh -c 'rm -rf $WORK/outside'" >"$OUT" 2>&1
if [ -f "$WORK/outside/outside.txt" ]; then
    ok "rm -rf two shells deep could not delete the tree outside"
else
    no "rm -rf deleted the tree outside the project"
fi

# ---------------------------------------------------------------------------
section "B5. the target cannot remove the restriction"
# ---------------------------------------------------------------------------
timeout 30 "$LL" "${RUNTIME[@]}" --ro "$FH" --hide "$FH/.ssh" --rw "$WORK/project" -- \
    "$BIN/escape-test" "$FH/.ssh/id_ed25519" "$FH/Documents/notes.txt" "$WORK/project" \
    >"$OUT" 2>&1
ESC_STATUS=$?
cat "$OUT" | sed 's/^/       /'
assert_line "the baseline read of the secret is blocked" "$OUT" \
    'baseline: read the secret .*-> BLOCKED'
assert_line "the baseline read of an allowed file works" "$OUT" \
    'baseline: read the allowed file .*-> READABLE'
assert_no_line "no attempt escaped the sandbox" "$OUT" '-> ESCAPED'
if [ "$ESC_STATUS" -eq 0 ]; then
    ok "escape-test exited 0 (every attempt was blocked)"
else
    no "escape-test exited $ESC_STATUS"
fi

# ---------------------------------------------------------------------------
section "D2. a ruleset can only add restriction, never remove it"
# ---------------------------------------------------------------------------
# The child gets a sandbox that allows the project. Inside it, the child asks
# for a second ruleset that grants the whole file system. If Landlock could be
# relaxed, the read would work after that. It must not.
timeout 30 "$LL" "${RUNTIME[@]}" --rw "$WORK/project" -- \
    "$BIN/escape-test" "$WORK/outside/outside.txt" "$WORK/project/inside.txt" \
    >"$OUT" 2>&1
assert_line "a second ruleset that grants / does not restore the read" "$OUT" \
    'grant / to myself and re-restrict *-> BLOCKED'
assert_line "no call exists that drops the domain" "$OUT" \
    'find a call that drops the domain *-> BLOCKED'
assert_line "no_new_privs cannot be turned off" "$OUT" \
    'turn no_new_privs off *-> BLOCKED'

# ---------------------------------------------------------------------------
section "B6. a signal cannot leave the sandbox (LANDLOCK_SCOPE_SIGNAL, ABI 6)"
# ---------------------------------------------------------------------------
# This is the rule process.signal.kill-everything of policies/process.yaml.
timeout 25 sleep 20 &
OUTSIDE_PID=$!
sleep 0.3

timeout 30 "$LL" "${RUNTIME[@]}" -- "$PROBE" signal "$OUTSIDE_PID" >"$OUT" 2>&1
assert_line "with no signal scope the outside process can be signalled" "$OUT" \
    "signal $OUTSIDE_PID -> OK"

timeout 30 "$LL" "${RUNTIME[@]}" --scope-signal -- "$PROBE" signal "$OUTSIDE_PID" >"$OUT" 2>&1
assert_line "with the signal scope the outside process gives EPERM" "$OUT" \
    "signal $OUTSIDE_PID -> FAIL errno=EPERM"

timeout 30 "$LL" "${RUNTIME[@]}" --scope-signal -- \
    /bin/sh -c "$PROBE signal \$\$" >"$OUT" 2>&1
assert_line "a signal inside the sandbox still works" "$OUT" 'signal [0-9]+ -> OK'

# The real command of the rule: kill every process of the user.
timeout 30 "$LL" "${RUNTIME[@]}" --scope-signal -- \
    /bin/sh -c 'kill -9 -1; echo SURVIVED' >"$OUT" 2>&1
if kill -0 "$OUTSIDE_PID" 2>/dev/null; then
    ok "kill -9 -1 inside the sandbox did not reach the process outside"
else
    no "kill -9 -1 reached a process outside the sandbox"
fi
kill "$OUTSIDE_PID" 2>/dev/null
wait "$OUTSIDE_PID" 2>/dev/null

# ---------------------------------------------------------------------------
section "B7. a program cannot start from a temporary directory"
# ---------------------------------------------------------------------------
# This is the rule process.exec.from-temp of policies/process.yaml. Landlock
# gives write on /tmp and no execute, which is write-xor-execute for the agent.
cp /bin/true "$WORK/dropped-payload"
chmod +x "$WORK/dropped-payload"
timeout 30 "$LL" "${RUNTIME[@]}" --rw-noexec "$WORK" -- \
    "$PROBE" exec "$WORK/dropped-payload" write "$WORK/scratch.txt" >"$OUT" 2>&1
assert_line "a program in a write-only directory cannot start" "$OUT" \
    "exec $WORK/dropped-payload -> FAIL errno=EACCES"
assert_line "a write to the same directory still works" "$OUT" \
    "write $WORK/scratch.txt -> OK"
timeout 30 "$LL" "${RUNTIME[@]}" --rx "$WORK" -- "$PROBE" exec "$WORK/dropped-payload" \
    >"$OUT" 2>&1
assert_line "the same program starts when the directory has execute" "$OUT" \
    "exec $WORK/dropped-payload -> OK"

# ---------------------------------------------------------------------------
section "D4. a deeper rule cannot take a right away"
# ---------------------------------------------------------------------------
# This is why --hide must enumerate. Landlock has no deny rule: a right that a
# rule gives on a directory reaches every file under it, and a second rule
# deeper in the tree can only add.
timeout 30 "$BIN/rule-specificity" "$FH" "$FH/.ssh" /usr /etc "$BIN" >"$OUT" 2>&1
cat "$OUT" | sed 's/^/       /'
assert_line "a rule with no rights at all is refused (ENOMSG)" "$OUT" \
    'empty_rule_on_child -> rc=-1 errno=No message of desired type'
assert_line "a narrow rule deeper in the tree is accepted" "$OUT" \
    'narrow_rule_on_child -> rc=0'
assert_line "but it does NOT remove the right the parent gave" "$OUT" \
    'list_child_after_narrow_rule -> STILL ALLOWED'

# ---------------------------------------------------------------------------
section "D1. Landlock cannot ask; it can only say no"
# ---------------------------------------------------------------------------
# There is no notification path. The proof is the error the target sees: it is
# an ordinary EACCES, it arrives at once, and no supervisor was involved.
START="$(date +%s%N)"
timeout 30 "$LL" "${RUNTIME[@]}" --rw "$WORK/project" -- \
    "$PROBE" read "$WORK/outside/outside.txt" >"$OUT" 2>&1
END="$(date +%s%N)"
DENY_MS=$(( (END - START) / 1000000 ))
printf '       a denied run took %s ms end to end (no supervisor waits)\n' "$DENY_MS"
assert_line "the denial is a plain EACCES with no reason" "$OUT" \
    'FAIL errno=EACCES\(13\) Permission denied'

# ---------------------------------------------------------------------------
section "D3. what Landlock cannot see"
# ---------------------------------------------------------------------------
# A rule of the pack that names a program and its arguments. Landlock has no
# view of either: `rm -rf /` inside the sandbox is denied because of the PATH,
# and `git push --force` is not a filesystem action at all.
timeout 30 "$LL" "${RUNTIME[@]}" --rw "$WORK/project" -- \
    /bin/sh -c "cd $WORK/project && rm -rf ./newdir && echo REMOVED_INSIDE_OK" \
    >"$OUT" 2>&1
assert_line "the same rm -rf inside the project is allowed" "$OUT" 'REMOVED_INSIDE_OK'

# `git push --force` needs only the network and the repository. A ruleset that
# allows the repository and the network cannot tell a force push from a normal
# one, because both are the same syscalls on the same paths.
timeout 30 "$LL" "${RUNTIME[@]}" --rw "$WORK/project" -- \
    /bin/sh -c "echo 'git push --force' > $WORK/project/cmd.txt && cat $WORK/project/cmd.txt" \
    >"$OUT" 2>&1
assert_line "a command line is only bytes to Landlock" "$OUT" 'git push --force'

# ---------------------------------------------------------------------------
section "E. the writable-tree hole: what a ruleset can and cannot subtract"
# ---------------------------------------------------------------------------
# The shipped floor grants the work tree and /tmp in full, so a credential
# shape (.ssh) under one of them is writable there. tmp-scope measures, on
# this kernel, every composition the ABI offers for closing that: a covering
# grant; a carve (no rule on the root, one rule per entry); a second layer
# (layers intersect); a make-only grant; a bounded carve.
SC="$WORK/tmpscope"
rm -rf "$SC"
mkdir -p "$SC"
timeout 30 "$BIN/tmp-scope" "$SC" >"$WORK/tmpscope.txt" 2>&1

# Covering: the grant on the tree reaches the shape, existing or created.
assert_line "covering: an existing shape under the grant is readable" \
    "$WORK/tmpscope.txt" 'RESULT covering_shape_read -> OK'
assert_line "covering: an existing shape under the grant is writable" \
    "$WORK/tmpscope.txt" 'RESULT covering_shape_write -> OK'
assert_line "covering: a fresh .ssh chain can be created under the grant" \
    "$WORK/tmpscope.txt" 'RESULT covering_fresh_shape_dir -> OK'
assert_line "covering: a fresh key file can be created with write under the grant" \
    "$WORK/tmpscope.txt" 'RESULT covering_fresh_shape_file -> OK'

# Carve: not granting the root and enumerating entries denies the shape —
# and denies creation everywhere the enumeration does not reach.
assert_line "carve: an enumerated shape is denied" \
    "$WORK/tmpscope.txt" 'RESULT carve_shape_read -> FAIL errno=13'
assert_line "carve: an enumerated sibling keeps its read" \
    "$WORK/tmpscope.txt" 'RESULT carve_sibling_read -> OK'
assert_line "carve: an enumerated sibling keeps its write" \
    "$WORK/tmpscope.txt" 'RESULT carve_sibling_write -> OK'
assert_line "carve: creation at the root is denied (the price)" \
    "$WORK/tmpscope.txt" 'RESULT carve_mkdir_at_root -> FAIL errno=13'
assert_line "carve: creation in an unenumerated subtree is denied (the price)" \
    "$WORK/tmpscope.txt" 'RESULT carve_mkdir_in_enumerated -> FAIL errno=13'

# Layers: a second ruleset intersects the first, so it can subtract the
# shape — and denies everything it does not enumerate, creation included.
assert_line "layers: the second layer subtracts the enumerated shape" \
    "$WORK/tmpscope.txt" 'RESULT layers_shape_read -> FAIL errno=13'
assert_line "layers: what the second layer enumerates stays usable" \
    "$WORK/tmpscope.txt" 'RESULT layers_sibling_write -> OK'
assert_line "layers: creation outside the second layer's enumeration is denied" \
    "$WORK/tmpscope.txt" 'RESULT layers_mkdir_at_root -> FAIL errno=13'
assert_line "layers: a fresh file in an enumerated parent is denied too" \
    "$WORK/tmpscope.txt" 'RESULT layers_create_in_enumerated_parent -> FAIL errno=13'

# Make-only: a grant with every MAKE_* right and no WRITE_FILE cannot even
# create a file with content, because the create-with-write open needs
# WRITE_FILE from a covering rule. Scratch use dies with the shape.
assert_line "make-only: a fresh create-with-write is denied" \
    "$WORK/tmpscope.txt" 'RESULT makeonly_fresh_create -> FAIL errno=13'
assert_line "make-only: editing a pre-existing file is denied" \
    "$WORK/tmpscope.txt" 'RESULT makeonly_preexisting_write -> FAIL errno=13'
assert_line "make-only: appending is denied" \
    "$WORK/tmpscope.txt" 'RESULT makeonly_preexisting_append -> FAIL errno=13'
assert_line "make-only: unlink is denied" \
    "$WORK/tmpscope.txt" 'RESULT makeonly_preexisting_unlink -> FAIL errno=13'
assert_line "make-only: mkdir still works" \
    "$WORK/tmpscope.txt" 'RESULT makeonly_fresh_dir -> OK'
assert_line "make-only: writing inside the fresh directory is denied" \
    "$WORK/tmpscope.txt" 'RESULT makeonly_fresh_dir_create -> FAIL errno=13'

# Bounded: an enumeration that grants a directory wholesale leaves every
# shape under it open, so the walk must reach every shape, at any depth.
assert_line "bounded: a shape under a granted-but-unwalked directory is open" \
    "$WORK/tmpscope.txt" 'RESULT bounded_unwalked_parent_shape -> OK'

printf '\n=========================================\n'
printf 'pass=%s fail=%s\n' "$PASS" "$FAIL"
printf '=========================================\n'
[ "$FAIL" -eq 0 ]
