#!/usr/bin/env bash
# Shared VM-lab lifecycle: a disposable Fedora Cloud VM under QEMU/KVM.
#
# The lab exists because some measurements write one-way, kernel-global
# state (kernel.yama.ptrace_scope is one-way per boot and latched this
# very host on 2026-09-01). Inside the lab the kernel belongs to the VM:
# the measurement can turn every dial, and the VM is destroyed after.
# A container is NOT a substitute — it shares the host kernel.
set -euo pipefail

LAB_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
REPO_ROOT="$(cd -- "$LAB_DIR/../.." && pwd -P)"
IMAGE="${VM_IMAGE:-$LAB_DIR/images/Fedora-Cloud-Base-Generic-43-1.6.x86_64.qcow2}"
SSH_PORT="${VM_SSH_PORT:-2222}"
MEM="${VM_MEM:-4096}"
CPUS="${VM_CPUS:-4}"
WORK="$LAB_DIR/work"

vm_need_image() {
    [ -f "$IMAGE" ] || {
        printf 'vm-lab: base image missing: %s\n' "$IMAGE" >&2
        printf 'vm-lab: fetch it once with:\n' >&2
        printf '  curl -L -o "%s" "https://download.fedoraproject.org/pub/fedora/linux/releases/43/Cloud/x86_64/images/Fedora-Cloud-Base-Generic-43-1.6.x86_64.qcow2"\n' "$IMAGE" >&2
        exit 2
    }
}

vm_need_key() {
    [ -f "$LAB_DIR/id_ed25519" ] || ssh-keygen -q -t ed25519 -N '' -f "$LAB_DIR/id_ed25519"
}

# Builds the NoCloud seed ISO that authorizes the lab key for root.
vm_seed() {
    local dir; dir="$(mktemp -d)"
    printf '%s\n' 'instance-id: vm-lab-01' 'local-hostname: vm-lab' > "$dir/meta-data"
    cat > "$dir/user-data" <<UD
#cloud-config
disable_root: false
ssh_pwauth: false
ssh_deletekeys: false
users:
  - name: root
    ssh_authorized_keys:
      - $(cat "$LAB_DIR/id_ed25519.pub")
UD
    genisoimage -quiet -output "$WORK/seed.iso" -volid cidata -joliet -rock "$dir/meta-data" "$dir/user-data"
    rm -rf -- "$dir"
}

# Boots a fresh overlay of the base image.
vm_boot() {
    rm -f "$WORK/disk.qcow2" "$WORK/qemu.log"
    qemu-img create -f qcow2 -F qcow2 -b "$IMAGE" "$WORK/disk.qcow2" >/dev/null
    qemu-system-x86_64 \
        -enable-kvm -machine q35 -cpu host -smp "$CPUS" -m "$MEM" \
        -drive file="$WORK/disk.qcow2",if=virtio,format=qcow2 \
        -drive file="$WORK/seed.iso",if=virtio,format=raw,readonly=on \
        -netdev user,id=net0,hostfwd=tcp:127.0.0.1:"$SSH_PORT"-:22 \
        -device virtio-net-pci,netdev=net0 \
        -display none -serial file:"$WORK/qemu.log" -pidfile "$WORK/qemu.pid" &
}

vm_ssh() {
    ssh -i "$LAB_DIR/id_ed25519" -p "$SSH_PORT" \
        -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
        -o ConnectTimeout=5 -o LogLevel=ERROR root@127.0.0.1 "$@"
}

# Waits until the VM answers ssh. Fails after the deadline.
vm_wait_ssh() {
    local deadline=$(( $(date +%s) + 180 ))
    until vm_ssh true 2>/dev/null; do
        if [ "$(date +%s)" -ge "$deadline" ]; then
            printf 'vm-lab: the VM did not answer ssh in 180 s; qemu log tail:\n' >&2
            tail -5 "$WORK/qemu.log" >&2 || true
            return 2
        fi
        sleep 2
    done
}

vm_destroy() {
    if [ -f "$WORK/qemu.pid" ]; then
        local pid; pid="$(cat "$WORK/qemu.pid" 2>/dev/null || true)"
        if [ -n "$pid" ]; then
            kill "$pid" 2>/dev/null || true
            for _ in 1 2 3 4 5 6 7 8 9 10; do
                kill -0 "$pid" 2>/dev/null || break
                sleep 1
            done
            kill -9 "$pid" 2>/dev/null || true
        fi
        rm -f "$WORK/qemu.pid"
    fi
    rm -f "$WORK/disk.qcow2"
}
