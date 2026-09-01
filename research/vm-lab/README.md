# The VM lab

A disposable Fedora Cloud VM under QEMU/KVM, for measurements that must
not touch this host.

**Why it exists.** On 2026-09-01 a workflow agent measured the hostile
same-user matrix across `kernel.yama.ptrace_scope` 0–3 with sudo on the
bare host. Scope 3 is one-way per boot; the host was latched until its
next reboot. The kernel of a VM is as disposable as the VM: the dial can
go anywhere, and the machine is destroyed afterwards. A **container is
not a substitute** — it shares the host kernel, so it shares the dial.

**Contract.** Anything that writes kernel-global, host-global, or
one-way state runs here (or in CI), never on the host. Every lab run
asserts the host's `ptrace_scope` is unchanged; a moved scope fails the
run.

## Layout

| File | What it is |
|---|---|
| `lib/common.sh` | VM lifecycle: seed, boot, ssh wait, destroy |
| `vm-run.sh` | One command inside a fresh VM; repo synced in, `/root/artifacts` copied back |
| `yama-sweep.sh` | The [af-12] hostile matrix, all scopes, host provably untouched |
| `images/`, `work/` | Base image and scratch (gitignored) |

## One-time setup

```sh
curl -L -o research/vm-lab/images/Fedora-Cloud-Base-Generic-43-1.6.x86_64.qcow2 \
  "https://download.fedoraproject.org/pub/fedora/linux/releases/43/Cloud/x86_64/images/Fedora-Cloud-Base-Generic-43-1.6.x86_64.qcow2"
```

(`vm-run.sh` prints the same command if the image is missing.)

## Use

```sh
# The canary: a shell inside the VM
research/vm-lab/vm-run.sh sh -c 'uname -r && cat /proc/sys/kernel/yama/ptrace_scope'

# The yama sweep (AF-fnejbc's exit gate: three green rounds)
research/vm-lab/yama-sweep.sh 3
```

The VM boots in seconds under KVM, gets the repository by rsync (working
tree, minus `target/`, `.git/`, `tmp/`), runs as root, and dies at exit.
Artifacts land in `work/artifacts/`. Sizing via `VM_MEM`, `VM_CPUS`,
`VM_SSH_PORT` if a run needs more.

The abort hunt of AF-a5xn5s can run here too — `vm-run.sh` with a loop
of `cargo test --workspace` (rustup install included in the sweep's
command), and unlike the host, the VM can simply be rebooted between
iterations.
