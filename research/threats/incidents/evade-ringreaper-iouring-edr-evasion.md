# RingReaper used Linux io_uring to do file and network work where EDR hooks cannot see it

- Date: 2025-08 | Agent/tool: RingReaper Linux post-exploitation agent (targets EDR-monitored Linux hosts) | Axis: evade

## What happened

In August 2025 Picus Security published a technical analysis of RingReaper, a Linux post-exploitation agent built to evade endpoint detection and response tools. Its core trick is doing all file, process and network operations through io_uring, the kernel's asynchronous I/O interface, instead of the conventional syscalls that security tools hook. Picus documented seven payloads that live in a working directory on the host: `cmdMe` and `executePs` enumerate processes, `loggedUsers` lists active terminal sessions, `netstatConnections` dumps active network connections, `fileRead` collects `/etc/passwd`, `privescChecker` probes for SUID binaries and kernel weaknesses, and `selfDestruct` deletes the malware's own executable. All of this produces very little telemetry, because the operations never arrive as the individual `read`, `write`, `recv`, `send` or `connect` syscalls that hook-based monitors intercept.

## How it went wrong

io_uring lets a process open a shared submission queue with the kernel and submit batches of I/O operations to it. The kernel then performs open, read, write, connect, send, receive and even directory enumeration asynchronously, on behalf of the process, without a per-operation syscall from the monitored process. A monitor that intercepts the classic syscall entry points sees only the setup calls, not the operations. RingReaper used io_uring primitives (`io_uring_prep_*`) to query `/proc` and `/dev/pts`, read kernel network tables, and read `/etc/passwd` while EDR platforms that rely on syscall hooks recorded almost nothing. Even its cleanup step was invisible: `selfDestruct` removed the binary through io_uring, so no file-deletion event surfaced either.

## What the firewall should learn

A ptrace-based monitor that observes `file_open` and `network_connect` as discrete syscall stops has exactly the same blind spot. The four observables cannot see io_uring operations at all — that is the point of the technique — so the honest detection answer is monitor-side, not rule-side: intercept or deny `io_uring_setup`/`io_uring_enter` from agent-descendant processes (via seccomp or the tracer), since no normal coding-agent workflow needs kernel-side asynchronous I/O. On the exec side the monitor can still correlate: a binary that was written earlier in the session and then exec'd (write-then-exec correlation), or enumeration-shaped activity with an absence of the expected tool execs (process listings with no `ps`, `who`, or `netstat` ever exec'd) are the weak but real signals Picus itself recommends.

## Sources

- [Picus Security: RingReaper Linux Malware - EDR Evasion Tactics and Technical Analysis](https://www.picussecurity.com/resource/blog/ringreaper-linux-malware-edr-evasion-tactics-and-technical-analysis)
