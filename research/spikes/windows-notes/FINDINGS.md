# The Windows survey: the shape of sensor and observer

Survey: `research/spikes/windows-notes/` (`[af-8]`, milestone M7, workstream
W8 of [docs/DIRECTION.md](../../../docs/DIRECTION.md) §3.2 and §11,
[MILESTONES.md](../../../docs/MILESTONES.md) §M7).

**Nothing here was run.** This machine is Fedora 43 (`x86_64`, uid 1000, no
root); it has no Windows host, no Windows SDK and no Windows compiler. This
document is the same kind of artifact as Part 2 of the Landlock spike
(`research/spikes/landlock/FINDINGS.md`, "the privileged tier"): an assessment
on paper, marked as one. Every claim about Windows carries a link to its
primary source — Microsoft documentation unless another is named — and every
repo claim carries its doc or code. No Windows code exists in this repository
(`docs/MILESTONES.md`, "Not yet, on purpose"), and none was added. Nothing in
this survey commits the schema, and nothing here blocks anything.

The gate asked for two things: a chosen candidate for the sensor approach, and
the list of questions only a Windows spike can answer. The chosen candidates
are in the Verdict below; the question list is section 5.

---

## Verdict

**Chosen sensor candidate: a DLL injected at launch that places Detours-style
inline trampolines on the `ntdll` syscall stubs, reports `af-core` events, and
registers every instance durably.** The single chokepoint is why: every
Windows process maps `ntdll.dll` — it is the user-mode side of the
system-service dispatcher, and Microsoft documents its file routines as the
user-mode equivalents of the WDK's `Zw*` routines
([NtCreateFile](https://learn.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntcreatefile)).
Interposing there sees the file, process, registry and pipe families of the
native API from one place, whatever the caller linked against. The Win32 layer
(kernel32/kernelbase/advapi32/ws2_32) is a **per-module** surface: a program
that binds later, loads a second copy, or calls the native API directly never
crosses it. It stays a named fallback for semantics only Win32 reconstructs
(command lines, socket hosts), not the primary. The implementation route is
[Detours](https://github.com/microsoft/Detours) — Microsoft Research's own
package "for monitoring and instrumenting API calls on Windows", MIT-licensed,
still maintained (ARM64EC target support landed in its repo in August 2026) —
which supplies the trampoline machinery and the launch-time injection helpers,
so the spike measures instead of inventing.

**Chosen observer candidate for the developer edition (no admin): the launch
loop — `CreateProcess` with `DEBUG_PROCESS`, plus a job object — with ETW as
the assurance tier wherever privileges allow, and WFP plus minifilters as the
enterprise tier.** The launch loop is the only documented unprivileged
mechanism that holds a process: "When the system notifies the debugger of a
debugging event, it also suspends all threads in the affected process"
([Debugging Events](https://learn.microsoft.com/en-us/windows/win32/debug/debugging-events)),
and the create event fires "before the process begins to execute in user
mode". `DEBUG_PROCESS` covers the tree — "The calling thread starts and
debugs the new process and all child processes created by the new process"
([Process Creation Flags](https://learn.microsoft.com/en-us/windows/win32/procthread/process-creation-flags)).
The job object gives the `PTRACE_O_EXITKILL` analogue:
`JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` "Causes all processes associated with the
job to terminate when the last handle to the job is closed"
([JOBOBJECT_BASIC_LIMIT_INFORMATION](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-jobobject_basic_limit_information)).

**The headline finding is a hole, and the plan must absorb it: Windows has no
unprivileged equivalent of the Linux pair that ships.** The Linux product
holds a call in the kernel (`seccomp` `RET_TRACE`) and enforces "always no"
rules in the kernel (Landlock), both from user space, both unprivileged. On
Windows, every kernel-side observer — ETW kernel providers, WFP callouts,
minifilters — is behind elevation: "Only users running with elevated
administrative privileges, users in the Performance Log Users group, and
applications running as LocalSystem, LocalService or NetworkService can
control event tracing sessions"
([Controlling Event Tracing Sessions](https://learn.microsoft.com/en-us/windows/win32/etw/controlling-event-tracing-sessions));
WFP's network filtering and the minifilter filesystem callbacks are kernel
drivers. So the unprivileged Windows product is weaker *by construction* than
the Linux one: an in-process hook (a sensor, not a boundary), a debug loop
(detectable, event-floodable) and a job object. The kernel-floor candidates
(AppContainer, and the experimental sandbox launch API) are the only
unprivileged road to a "no question" tier, and both carry real friction
(section 3).

The rules that bind the Linux sensor bind this one unchanged: **hooks provide
semantic visibility, independent observation provides assurance**
([DIRECTION.md](../../../docs/DIRECTION.md) §3.2); the sensor reports and
never decides; no allow decision may rest on anything it says; tamper and
correlation signals key on the firewall's own instances and obey the
interruption budget ([DECISIONS.md](../../../docs/DECISIONS.md), 2026-08-30).

---

## 1. The sensor candidates (user-space hooking)

| layer | what it interposes | sees | privilege |
| --- | --- | --- | --- |
| Win32 API hooking (IAT/EAT patch, or inline hooks in `kernel32`/`kernelbase`) | the documented application surface: `CreateFileW`, `CreateProcessW`, `DeleteFileW`, `MoveFileExW`, `RegOpenKeyExW`, Winsock `connect` | program-shaped semantics: paths as given, command lines, hosts | none |
| `ntdll` trampolines (inline hook on the `Nt*` stubs) | the native API every Win32 call resolves into: `NtCreateFile`, `NtOpenFile`, `NtSetInformationFile`, `NtCreateUserProcess`, `NtQueryValueKey`, `NtDeviceIoControlFile` | the syscall boundary as seen from user mode: handles, `DesiredAccess` masks, object attributes | none |
| Detours-style implementation | either of the above: overwrite the first instructions of a target function, jump to the hook, keep a trampoline that calls the original | both; plus launch-time injection helpers | none |

**Why the `ntdll` stubs and not the Win32 surface.** The Win32 layer is
optional in a way `ntdll` is not: a program can `LoadLibrary("ntdll.dll")` and
`GetProcAddress("NtCreateFile")`, or link the native API statically, and never
touch the interposed exports. The import-address table a Win32 hook patches is
per-module and per-import, so a module loaded after the hook ran, a module
with delayed imports, or a second copy of the same DLL is invisible until it
is found and patched again. `ntdll` is mapped into every process by the
kernel, so one hook site per function covers every caller. Microsoft
documents `NtCreateFile` for applications (header `winternl.h`, library
`ntdll.lib`), which makes the boundary public even where the semantics are
thin.

**What each native routine maps to.** `NtCreateFile`/`NtOpenFile` give the
open with a `DesiredAccess` mask (`FILE_WRITE_DATA`, `DELETE`, …) — the
`write` flag of `Action::FileOpen`, with more fidelity than Linux flags give.
Delete and rename are not separate calls: they are
`NtSetInformationFile` with `FileDispositionInformation`/`FileDispositionInformationEx`
("Request to delete the file when it is closed") or `FileRenameInformation`
("Change the current file name")
([NtSetInformationFile](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntsetinformationfile)),
and an open with `FILE_DELETE_ON_CLOSE` deletes at close
([NtCreateFile](https://learn.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntcreatefile)).
The delete/rename event kinds the schema needs already exist — `af-core` grew
`file_delete` and `file_rename` for the M2 sensor — so on Windows the gap is
in the *monitor*, not the schema (section 4).

**The soundness rule ports, and it cuts the same way.** A hook sees
`OBJECT_ATTRIBUTES.ObjectName` — "a buffered Unicode string that names the
file" — which is memory the target owns. The rule of
[DETECTION-RESEARCH.md](../../../docs/DETECTION-RESEARCH.md) §2 applies
unchanged: a value read out of the target's memory may report and may refuse,
and may never carry an allow. The stronger statement for Windows is that an
in-process hook cannot even hold: the process can simply call the service
itself (the table below), so a "refuse" from a hook is advisory in a way the
Linux `seccomp` refusal is not. This is not a new problem — it is the exact reason
the M2 sensor reports and never decides.

### What a capable process does about each layer

| attack | works against | how | named source |
| --- | --- | --- | --- |
| Call the native API directly | Win32 hooks | resolve `Nt*` from `ntdll`, or load `ntdll` fresh | [Detours README](https://github.com/microsoft/Detours) names the layer; the resolution path is documented on [NtCreateFile](https://learn.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntcreatefile) ("You can also use `LoadLibrary` and `GetProcAddress`") |
| Direct syscalls | `ntdll` hooks, and every user-space hook | skip the stubs: resolve the system-service numbers at runtime from intact stubs and issue the `syscall` instruction from the attacker's own code (Hell's Gate and its descendants) | [Exploring Hell's Gate](https://redops.at/en/blog/exploring-hells-gate) |
| Unhook | `ntdll` inline hooks | map a fresh copy of `ntdll.dll` from disk and copy its `.text` section over the hooked one | the same family of techniques is surveyed in [Exploring Hell's Gate](https://redops.at/en/blog/exploring-hells-gate) ("unhooking or bypassing user mode hooks using direct or indirect syscalls") |
| Rewrite the stub while the hook runs | any inline hook | a second thread restores the first bytes between the hook's install and its call | the mechanism is the intra-process race [DETECTION-RESEARCH.md](../../../docs/DETECTION-RESEARCH.md) §2 measured at 47.6% on Linux |
| Unload or ignore the sensor DLL | the injected module | `FreeLibrary`, or spawn a child that strips the injection | the Linux analogue is measured: `env -u LD_PRELOAD` defeats the preload as a boundary (the same doc, §1) |
| Run as a protected process | every sensor | a protected process refuses `PROCESS_VM_READ`, `PROCESS_VM_WRITE`, `PROCESS_DUP_HANDLE` and friends, so no injection and no hook land | [Process Security and Access Rights](https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights) |

The last row is symmetric, and the symmetry matters: `CREATE_PROTECTED_PROCESS`
"requires a special signature… provided by Microsoft but not currently
available for non-Microsoft binaries"
([Process Creation Flags](https://learn.microsoft.com/en-us/windows/win32/procthread/process-creation-flags)),
so the firewall cannot hide its own monitor in one either. On Linux the
monitor is equally visible (`TracerPid`, `Seccomp` in `/proc/self/status`,
[ARCHITECTURE.md](../../../docs/ARCHITECTURE.md) §4) and the product accepts
that; Windows changes nothing about the principle.

**The evasion answer is not a stronger hook.** It is the M2/M5 design: the
sensor registers every instance durably (the B.5 fact), the observer keeps its
own view, and correlation raises the disagreement — a sensor the firewall
installed that goes quiet, a spawn seen but never reported. The Windows sensor
must keep the registration record verbatim; that contract is written against
this table.

---

## 2. The observer candidates (independent views)

| observer | privilege | sees | holds? | tier |
| --- | --- | --- | --- | --- |
| debug events (`DEBUG_PROCESS` + `WaitForDebugEvent`) | none | process create/exit, thread create/exit, DLL load/unload, exceptions, for every process of the tree | yes — all threads of the affected process suspend until the debugger continues | developer |
| job object (`KILL_ON_JOB_CLOSE`, breakaway limits) | none | the tree's membership, its end, its escape attempts | no (it terminates, it does not pause) | developer |
| ETW kernel providers (`Microsoft-Windows-Kernel-Process`/`-File`/`-Registry`/`-Network`) | elevated session control | process, file, registry and image events "logged directly by the kernel" | no | assurance / enterprise |
| security auditing (event 4688, "A new process has been created") | audit policy + elevated read of the Security log | process creation with command line, parent, token label | no | enterprise |
| Sysmon (event ID 1: Process creation) | admin install (driver + service) | command line, `ProcessGUID`, image hashes, parent | no | enterprise |
| WFP (Windows Filtering Platform) | kernel driver, admin install | network traffic at stack layers; can filter and modify packets | yes, in a kernel callout | enterprise |
| minifilter (Filter Manager) | kernel driver, admin install | every filesystem I/O it registers for, pre- and post-operation | yes — a preoperation callback can complete the I/O operation itself, which is a refusal | enterprise |

Sources, in order: debug events and their hold
([Debugging Events](https://learn.microsoft.com/en-us/windows/win32/debug/debugging-events));
the job limit and the breakaway flags
([JOBOBJECT_BASIC_LIMIT_INFORMATION](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-jobobject_basic_limit_information),
[Process Creation Flags](https://learn.microsoft.com/en-us/windows/win32/procthread/process-creation-flags));
the ETW session privilege
([Controlling Event Tracing Sessions](https://learn.microsoft.com/en-us/windows/win32/etw/controlling-event-tracing-sessions))
and the provider name in Microsoft's own tooling
([DTrace ETW](https://learn.microsoft.com/en-us/windows-hardware/drivers/devtest/dtrace-etw));
4688 and its payload, now carrying the acting process and a Process Start Key
that is "a sequence number guaranteed to be unique across boots"
([New security capabilities of Event Tracing for Windows](https://techcommunity.microsoft.com/blog/windows-itpro-blog/new-security-capabilities-in-event-tracing-for-windows/3949941));
Sysmon event 1 with command line, `ProcessGUID` and hashes
([Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon));
WFP as "a set of API and system services that provide a platform for creating
network filtering applications", user-mode API plus kernel-mode callout drivers
([Windows Filtering Platform](https://learn.microsoft.com/en-us/windows/win32/fwp/windows-filtering-platform-start-page));
and the minifilter model, where the filter manager walks registered
preoperation callbacks and an operation is stopped when "a minifilter driver
has completed the I/O operation"
([Filter Manager Concepts](https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/filter-manager-concepts),
[Writing Preoperation and Postoperation Callback Routines](https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/writing-preoperation-and-postoperation-callback-routines)).

**Why ETW is the assurance tier and not the product's floor.** Kernel ETW is
the best of these observers — the events are emitted by the kernel, so the
observed process cannot order its own memory to lie about them
([Elastic Security Labs, "Kernel ETW is the best ETW"](https://www.elastic.co/security-labs/kernel-etw-best-etw))
— and the user-mode half of ETW does not share that property: a process that
owns its memory can silence its own user-mode providers. But starting a
session is elevated work. The developer edition cannot self-provision the
assurance tier, which is why the launch loop carries the product alone and the
question list below asks whether *any* unprivileged live feed exists.

**The debug loop's own weaknesses, stated plainly.** The relationship is
visible to the observed process: the PEB Microsoft documents carries
`BeingDebugged`
([PEB structure](https://learn.microsoft.com/en-us/windows/win32/api/winternl/ns-winternl-peb)),
and the anti-debug literature is decades deep. Every DLL load is a debug event
too (`LOAD_DLL_DEBUG_EVENT`, fired "whenever a process being debugged loads a
DLL"), and a dev session loads hundreds, so the loop must continue them at a
rate the spike has to measure. A hostile process can also *generate* events on
purpose — every debug event suspends the process until the monitor continues,
so a flood of exceptions or `OutputDebugString` calls is a denial of service
aimed at the monitor itself. None of this disqualifies the loop; all of it
belongs in the spike's measurement plan.

**One structural strength worth naming.** At a debug event *all* threads of
the process are suspended — documented, quoted above. The Linux exec stop
suspends the traced thread, which is why a sibling thread could rewrite the
path 47.6% of the time. At a Windows debug event that same rewrite cannot
happen from inside the process, because nothing inside it is running. The
arguments still live in the target's memory and must still be read from it,
and the read is still not a basis for an allow; but the *refusal* half is
stronger than the Linux one at the same launch position. Only a spike can
measure the practical difference.

---

## 3. The kernel-floor candidates (the Landlock counterpart)

The direction's quietest layer is the one that never asks. Two unprivileged
candidates exist on Windows, and both differ from Landlock in a way that
matters:

1. **AppContainer.** "AppContainers are isolated from accessing processes and
   windows belonging to other applications as well as from devices,
   files/directories, registry keys, the network, and credentials"
   ([Launch an AppContainer](https://learn.microsoft.com/en-us/windows/win32/secauthz/implementing-an-appcontainer)).
   A launcher builds the profile and the capability set before the child runs,
   the kernel enforces it through the token and the DACL, and the process
   cannot relax it. That is the Landlock shape. The difference: AppContainer
   grants are ACLs on the user's own files and a per-profile directory, not a
   private ruleset, so making a work tree writable means touching ACLs on the
   user's repository — invasive in a way Landlock's private ruleset is not.
2. **The experimental sandbox launch API.** `Experimental_CreateProcessInSandbox`
   takes a compiled sandbox specification with `app_container`,
   `fs_read_write` / `fs_read_only` path grants, `network_policy`,
   `integrity` and `disallow_win32k_system_calls`, and launches with
   "kernel-level process isolation (default-deny access to most system
   resources)"
   ([Create Process in Sandbox](https://learn.microsoft.com/en-us/windows/win32/secauthz/createprocessinsandbox)).
   It is the closest thing to a Landlock launcher Microsoft has shipped — and
   it is explicitly "experimental and subject to change", Windows 11 only,
   no public header (`GetProcAddress` only). It is a spike target, not a plan.

Integrity levels are the third lever — the engine "refuses to set an integrity
level higher than the caller's token integrity level", so a launcher can lower
a child, and a lowered child cannot write medium-integrity files — but a level
says nothing about paths, so it cannot carry "always no" rule classes by
itself.

Nothing here ships a claim: both candidates need a Windows machine, a dev
toolchain and a permission audit before either can be argued for.

---

## 4. Schema review: can `af-core` carry what Windows produces?

Method: read the schema (`crates/af-core/src/event.rs`,
`process.rs`, `session.rs`) against each Windows source above. This is a
review; no schema change is proposed, and none is committed.

### What carries as-is

| Windows fact | `af-core` home | note |
| --- | --- | --- |
| debug create event, ETW ProcessStart, 4688, Sysmon EID 1 (image, command line, parent, exit) | `ProcessExec` / `ProcessExit` with `ProcessInfo` | the facts line up field for field; Sysmon's image hashes have no home (below) |
| a process identifier, reused after exit ("The identifier is valid until the process terminates", [CreateProcessW](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi-nf-processthreadsapi-createprocessw)) | `ProcessKey { pid, start_ticks }` | the graph already keys on the pair, which is the right design for Windows reuse too; the ETW Process Start Key is exactly this fact ("unique across boots") |
| `NtCreateFile`'s `DesiredAccess` mask | `FileOpen { path, write }` | the mask is richer than the bool; `DELETE` and `FILE_APPEND_DATA` fold away today |
| `NtSetInformationFile` `FileDispositionInformation*` / `FileRenameInformation` | `FileDelete` / `FileRename` | the kinds exist since M2; no product rule matches them yet |
| `LOAD_DLL_DEBUG_EVENT`, `LoadLibrary` | `LibraryLoad` | direct port of the M2 `dlopen` fact |
| `SetEnvironmentVariableW` | `EnvChange` | direct port |
| Winsock `connect` / `NtDeviceIoControlFile` on AFD | `NetworkConnect { addr, port, host }` | the host name is a Win32-layer fact, which is why the Win32 layer survives as a fallback |
| reads with small buffered content | `FileRead` | the M2 content-capture bounds port |
| `TerminateProcess` aimed at the monitor | `SignalSend { target, signal }` | carries the fact; the `signal` number is a Linux-ism a Windows collector would have to synthesize (below) |
| which mechanisms this machine offers | `SessionStart.capabilities` | already platform-neutral by design |
| the sandbox/AppContainer floor's refusals | `KernelDenied { rule, path }` | the explainer idea ports; the mechanism is an ACL check, not an LSM hook, so what the event can honestly claim differs and must be measured |

### The gaps, named

1. **The registry.** No event kind and no action covers
   `NtCreateKey`/`NtSetValueKey`/`RegOpenKeyExW`. This is the largest gap:
   Windows persistence (`Run` keys, services, scheduled tasks) and several
   credential stores live in the registry, and AppContainer isolation names
   "registry keys" among what it restricts. A Windows collector that cannot
   say "this process wrote `HKCU\...\Run`" is blind to an axis the threat
   catalogue already carries. A kind pair (`registry_open`, `registry_write`)
   is the obvious shape; this review names it and commits nothing.
2. **Handles.** NT is handle-centric: an open returns a `HANDLE`, and the
   delete, the rename and the final disposition are set-information calls on
   that handle — sometimes minutes after the open (`FILE_DELETE_ON_CLOSE`).
   The schema has no handle field, so "the open that this delete came from"
   cannot be expressed, and `FileOpen { write: bool }` cannot express an open
   that already carries delete intent. This is also where the object/pointer
   rule lives: the kernel resolves names to objects and hands out handles,
   while a user-space hook sees pointers — the same split as
   `fanotify`-versus-`seccomp` on Linux
   ([DETECTION-RESEARCH.md](../../../docs/DETECTION-RESEARCH.md) §2).
3. **Process-creation providers as facts.** The schema records what a monitor
   saw, not which feed saw it. On Windows the provider is load-bearing for
   assurance (a kernel provider's word differs from a user-mode one), so a
   Windows collector needs a way to say "seen by `Microsoft-Windows-Kernel-Process`"
   — either as a capability at session start, per event, or in the sensor
   registration record. Question, not commitment.
4. **Image hashes and signatures.** Sysmon EID 1 carries full image hashes;
   `ProcessInfo` has no field for one. Hashes are how a Windows trace
   correlates an image across machines, the way `ProcessKey` correlates a
   process across reboots.
5. **Token facts.** Integrity level, AppContainer membership, elevation type —
   the facts the floor and the auditing events key on — have no home in
   `ProcessInfo`. 4688 already carries the mandatory label.
6. **The Linux-isms inside `ProcessInfo`.** `sid` (a Unix session id read
   from `/proc/<pid>/stat`) has no Windows equivalent: the detach facts on
   Windows are a job breakaway (`CREATE_BREAKAWAY_FROM_JOB` against a job that
   allows it) and a process that outlives the root — both already sensed
   shapes here (`detached_descendant`, `outlived_session`), but the field
   itself would have to carry something else or nothing.
   `dynamic_link` — the M5 keying fact — reads `PT_INTERP`, which does not
   exist on Windows: every process maps `ntdll`, so there is no "static
   binary" class that *cannot* carry a sensor. The Windows equivalent of "a
   child that never reported" is "a child our injection never reached"
   (breakaway, pre-injection exit, protected process), which is a different
   key with a different miss rate, and correlation must be re-gated on that
   rate before any rule ships.
7. **Paths.** `path: String` carries a `\Device\HarddiskVolume3\...` NT path
   or a `C:\...` DOS path equally well and equally meaninglessly to rules
   written against POSIX prefixes. A Windows collector must normalize (NT to
   DOS), and the spike must decide where — collector, recorder, or rules.

**The M2 event contract ports; the monitor half is where the Linux-isms
live.** Every kind the in-process sensor emits (`process_exec`, `file_open`,
`file_read`, `file_delete`, `file_rename`, `library_load`, `env_change`,
`network_connect`, the registration record) has a natural Windows source, and
none needs a schema change. What does not port cleanly is what the *monitor*
emits: `kernel_floor` (an LSM concept), `sid`, `dynamic_link`, and the signal
numbers.

---

## 5. Questions only a Windows spike can answer

The exit gate's second half. Each is measurable, and none is answerable from
documentation alone.

1. **Propagation.** There is no environment-driven loader hook on Windows, so
   the sensor reaches a child only by injection at its launch. What fraction
   of a normal dev session's children (shells, `cargo`, `npm`, `git`,
   MSBuild, python) actually receive the DLL, when the monitor injects at the
   debug create event? This number decides whether the M5 correlation keying
   can be ported at all.
2. **The unprivileged feed.** Can a normal user read *any* live process-creation
   feed it did not create — an Autologger session, a session an administrator
   left running, a WMI event subscription? The docs restrict *control* to
   elevated users; what a non-elevated *consumer* can attach to is exactly a
   measurement question. If the answer is nothing, the honest statement is
   that the assurance tier needs one elevation, once, and the product should
   say so.
3. **Debug-loop cost.** Every DLL load is a stop. What does a `DEBUG_PROCESS`
   loop cost on the shared benchmark shape (a build, a test run, a git
   session), against the same loop with immediate continues? And what is the
   cost of the event-flood denial (a target that raises exceptions or
   `OutputDebugString` in a loop) to the monitor's responsiveness — the
   Windows analogue of the M1 "kill the monitor" row?
4. **Trampoline viability.** Do Detours-style inline hooks on the `Nt*` stubs
   hold on current builds with Control-flow Guard and CET shadow stack
   enabled, on `x64` and on ARM64? Detours added ARM64EC *target* hooking in
   2026, which says the surface moves. And since system-service numbers
   differ per Windows release
   ([j00ru's syscall tables](https://j00ru.vexillium.org/syscalls/nt/64/)),
   stub resolution must be per-boot, per-build — measure that the chosen
   resolution survives the update channel.
5. **The launch hold.** The docs suspend all threads at a debug event. Measure
   it: a hostile second thread rewriting the command line while the monitor
   reads it, the Windows re-run of the 47.6% measurement. Expected result is
   0%, and the measurement is the point.
6. **The floor.** Can a whole session tree run inside an AppContainer without
   elevation, does a real toolchain still work there (the write grant is an
   ACL change on the user's own files — what does that do to the repository,
   to git, to anything that later reads the same tree outside the session),
   and does `Experimental_CreateProcessInSandbox` exist and hold on the target
   build? What question does each floor candidate actually remove from the
   pack, measured the way ML measured the 6 of 64?
7. **The kill-the-monitor shape.** Does `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`
   take the whole tree when the monitor dies, including a child that asked
   for `CREATE_BREAKAWAY_FROM_JOB` (it should fail while the job denies
   breakaway — but what does a normal tool that asks for breakaway then do)?
   This is the Windows `EXITKILL` row of the M1 matrix.
8. **Schema in practice.** Run one session per event family through a
   collector prototype and count which of section 4's gaps it actually hits,
   and which it can paper over. A gap never hit is not a gap; a gap hit on
   the first day is a schema change to propose under the normal rules.

---

## 6. What this milestone did not do

No code. No schema change. No claim about a Windows machine, because none was
available. Nothing here blocks anything — M7's gate says so, and
[MILESTONES.md](../../../docs/MILESTONES.md) keeps "any Windows code" under
"Not yet, on purpose". The next Windows step is a spike that answers the eight
questions above on a real host, with runnable code and raw numbers, under the
same rules as every other spike in `research/`.
