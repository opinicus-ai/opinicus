#!/usr/bin/env bash
# Runs one command inside a disposable Fedora Cloud VM and destroys it.
#
# Usage:
#   research/vm-lab/vm-run.sh <command> [arg...]
#
# The command runs as root on a fresh overlay of the base image; the
# repository is rsynced in (working tree, minus the heavy directories)
# to /root/opinicus. Everything the command writes under /root/artifacts
# is copied back to research/vm-lab/work/artifacts/ on the host. The VM
# is destroyed afterwards — that is the point: its kernel is disposable.
#
# Environment:
#   VM_MEM (4096)   VM_CPUS (4)   VM_SSH_PORT (2222)   VM_IMAGE (path)
#
# Example — the canary:
#   research/vm-lab/vm-run.sh sh -c 'uname -r && cat /proc/sys/kernel/yama/ptrace_scope'
set -euo pipefail

. "$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)/lib/common.sh"

[ "$#" -ge 1 ] || { printf 'usage: vm-run.sh <command> [arg...]\n' >&2; exit 2; }
vm_need_image
vm_need_key
mkdir -p "$WORK/artifacts"

START="$(date +%s)"
trap vm_destroy EXIT
vm_seed
vm_boot
vm_wait_ssh
BOOTED="$(date +%s)"
printf 'vm-lab: ssh up in %ds; syncing the repository\n' "$((BOOTED - START))"

rsync -a --delete -e "ssh -i $LAB_DIR/id_ed25519 -p $SSH_PORT -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR" \
    --exclude target --exclude .git --exclude tmp --exclude research/vm-lab/images \
    "$REPO_ROOT/" root@127.0.0.1:/root/opinicus/

printf 'vm-lab: running the command\n'
if vm_ssh "cd /root/opinicus && mkdir -p /root/artifacts && $(printf '%q ' "$@")"; then
    printf 'vm-lab: command exited 0\n'
else
    rc=$?
    printf 'vm-lab: command exited %d\n' "$rc"
    vm_ssh 'tar -C /root -cf - artifacts' | tar -C "$WORK" -xf - 2>/dev/null || true
    exit "$rc"
fi

vm_ssh 'tar -C /root -cf - artifacts' | tar -C "$WORK" -xf -
printf 'vm-lab: artifacts in %s\n' "$WORK/artifacts"
