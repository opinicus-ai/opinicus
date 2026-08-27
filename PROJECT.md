# Agent Firewall — Project Summary

## 1. Project idea

The project is a behavior-based security layer for coding agents.

Its purpose is to let coding agents run directly on a developer machine while still controlling dangerous side effects.

The system is not primarily a sandbox. It is closer to an agent firewall, behavior monitor, or EDR/antivirus for coding agents.

The main idea is:

Observe what an agent and all of its child processes actually do, correlate those actions with their provenance, and apply deterministic security policies before dangerous actions can complete.

Examples:

* Allow normal shell commands without interruption.
* Allow psql for safe queries.
* Require approval for DROP DATABASE.
* Require approval for git push --force.
* Require approval for access to production infrastructure.
* Detect when a shell script launches another script or binary and continue to track the full process tree.
* Keep enough information to explain where a suspicious action came from.

The system should work independently of the coding agent.

Possible agents include:

* Codex
* Claude Code
* Pi
* Gemini CLI
* OpenCode
* other current or future coding agents

The agent is launched through the monitor, and all descendant processes remain part of the monitored session.

⸻

## 2. Core product principles

### 2.1 Local enforcement

The enforcement path should run locally.

It should:

* work offline;
* have low latency;
* not require a remote model;
* not depend on an external API;
* continue to work for users who run local models;
* avoid recurring inference cost for basic protection.

A remote service can exist later as a control plane, but it should not be required for enforcement.

### 2.2 Deterministic first

The core security decision should be deterministic.

The system should avoid using an LLM as the primary allow/deny decision maker.

Possible decisions:

* allow;
* allow once;
* allow for this session;
* ask for approval;
* deny;
* terminate the process or session.

AI can be added later for advisory functions such as:

* explaining events;
* suggesting rules;
* classifying unknown behavior;
* summarizing logs;
* helping maintain policy sets.

AI should not be necessary for the base product.

### 2.3 Provenance instead of inferred intent

The system should not try to build a full deterministic "intent engine".

Intent is subjective and difficult to reconstruct reliably.

The more useful deterministic concept is provenance.

The system should answer questions such as:

* Which agent session started this process?
* Which parent process created it?
* Which script or command caused it?
* Which tool invocation can be associated with it?
* Which file, command, or subprocess path led to the final action?

Agent logs can enrich this data when available.

The operating-system event stream remains the source of truth.

### 2.4 User-space first

The first implementation should work in user space.

The initial goal is not to require:

* kernel modules;
* root access;
* administrative privileges;
* a container;
* a full endpoint-security installation.

Deeper OS integration can be added later when needed.

This gives the project a low-friction developer experience.

### 2.5 Cross-platform architecture, not immediate feature parity

Linux is the first implementation target.

macOS and Windows should follow later.

The architecture should normalize platform events into one common model, but each operating system can provide different levels of visibility and enforcement.

The target platforms are:

* Linux;
* macOS;
* Windows.

⸻

## 3. High-level architecture

The system can be divided into the following layers.

### 3.1 Session launcher

Starts the coding agent and establishes the root of the monitored process tree.

Responsibilities:

* create a session ID;
* launch the agent;
* track the root PID;
* store metadata about the agent;
* detect the agent type and version when possible;
* maintain session lifecycle state.

### 3.2 OS event collector

Collects low-level events from the monitored process tree.

Possible events include:

* process creation;
* process exit;
* exec;
* parent/child relationships;
* command-line arguments;
* executable path;
* working directory;
* environment metadata where safe and useful;
* file access;
* network connection attempts;
* stdin or IPC data when technically possible;
* debugger or tracing events;
* signals;
* process status changes.

The exact event set must be discovered experimentally.

### 3.3 Event normalization layer

Converts platform-specific events into one stable event format.

For example:

ProcessExec
ProcessFork
FileOpen
NetworkConnect
StdinWrite
ProcessExit
PolicyDecision
ApprovalRequested
ApprovalResolved

The normalized event format becomes one of the most important internal APIs of the project.

### 3.4 Provenance engine

Builds a causal graph from the event stream.

Typical chain:

```
User session
  -> coding agent
    -> shell tool
      -> bash
        -> script
          -> psql
            -> SQL command
```

This graph is more important than a flat command log.

It lets the system explain how a sensitive action was reached.

### 3.5 Agent log adapters

Optional adapters parse logs or session data produced by supported coding agents.

They can add:

* session ID;
* tool call ID;
* tool name;
* command requested by the model;
* agent version;
* log schema version;
* task metadata.

These adapters should be optional.

The core monitor must still work when no agent-specific adapter exists.

### 3.6 Policy engine

Evaluates normalized events and provenance against deterministic rules.

Rules can use several signal types together.

Examples:

* executable name;
* executable path;
* arguments;
* parent process;
* process ancestry;
* working directory;
* destination host;
* destination port;
* file path;
* string patterns;
* SQL statements;
* Git arguments;
* process sequence;
* session metadata.

A rule can use both behavior and signatures.

Example:

```
IF executable == "psql"
AND SQL contains "DROP DATABASE"
THEN approval_required
```

Another example:

```
IF executable == "git"
AND argv contains "--force"
AND remote == "origin"
THEN approval_required
```

### 3.7 Approval and enforcement layer

When a rule requires approval, the system should stop or suspend the dangerous action before it completes, when the OS mechanism permits this.

The user should receive a useful explanation, for example:

```
Claude Code
  -> bash
  -> migrate.sh
  -> psql
Attempted operation:
DROP DATABASE customer_prod
Policy:
database.destructive.drop-database
Decision:
Approval required
```

### 3.8 Event storage

The system should not permanently store every low-level event in full detail.

During early development, it is useful to collect as much data as possible.

Later, retention should depend on risk.

For example:

* harmless events can be compressed or discarded;
* normal process activity can become summary records;
* suspicious events can keep full provenance;
* blocked actions can keep complete evidence;
* approved sensitive operations can keep an audit record.

The system should support trace replay for policy testing.

### 3.9 Policy authoring and compilation

Policies should have a human-readable source format.

Requirements:

* clear enough for developers and security engineers;
* structured enough for coding agents to understand;
* strongly typed;
* versionable;
* lintable;
* testable;
* signable.

The authoring format can later compile into a compact internal representation for fast matching.

The compiled representation can behave like policy bytecode, but the source should remain readable.

### 3.10 Local UI

The first interface can be a CLI or TUI.

Later interfaces can include:

* desktop UI;
* local web UI;
* IDE integration;
* approval notification system;
* trace viewer;
* process tree viewer;
* policy editor.

⸻

## 4. Policy model

The policy system is a major part of the product.

It should support more than simple command blacklists.

### Example policy categories

Filesystem

* destructive recursive deletion;
* modification outside the project;
* writes to sensitive configuration;
* changes to SSH files;
* writes to credential stores.

Git

* force push;
* push to protected branches;
* destructive reset;
* deleting branches;
* rewriting large parts of repository history.

Databases

* DROP DATABASE;
* DROP TABLE;
* TRUNCATE;
* destructive migrations;
* connection to production databases;
* bulk deletion.

Cloud and infrastructure tools

* kubectl;
* oc;
* Terraform;
* AWS CLI;
* Azure CLI;
* GCP CLI;
* Docker;
* Podman.

Rules can use the command together with environment and target context.

Network

* connections to unexpected hosts;
* connections to production endpoints;
* upload of large amounts of data;
* use of sensitive administrative ports.

Process behavior

* unexpected process chains;
* execution from temporary directories;
* downloaded executable followed by execution;
* shell spawning another shell repeatedly;
* encoded shell commands.

⸻

## 5. Threat intelligence and rule updates

A long-term commercial opportunity is a continuously maintained rule feed.

This is similar to antivirus signature updates, but the rules can describe richer behavior.

A rule can combine:

* process tree structure;
* executable names;
* arguments;
* stdin contents;
* known command patterns;
* protocol contents;
* path patterns;
* destination information;
* agent-specific provenance.

The project can collect known failure cases from:

* public coding-agent incidents;
* GitHub issues;
* security reports;
* user reports;
* internal testing;
* deliberately reproduced destructive tasks.

These cases can become regression tests and new policy rules.

⸻

## 6. Possible business model

The project can use an open-core model.

### Free / open-source core

Possible free components:

* local runtime;
* process monitoring;
* basic policy engine;
* local rules;
* CLI;
* offline operation;
* local audit log.

This supports adoption and trust.

### Paid rule intelligence

A subscription can provide:

* continuously maintained policy packs;
* new threat signatures;
* tested rules for popular coding agents;
* rules for cloud and infrastructure tools;
* production safety policies;
* signed rule updates.

### Enterprise control plane

Enterprise features can include:

* centralized policy management;
* organization-wide policy distribution;
* team-specific profiles;
* audit collection;
* compliance reporting;
* policy versioning;
* approvals;
* fleet management;
* SSO and RBAC;
* private rule repositories;
* SIEM integration.

### Other possible outcomes

If the project gains strong adoption, other outcomes become possible:

* commercial partnerships;
* model-provider credits;
* integration with coding-agent vendors;
* acquisition;
* employment or funding from a major AI or security company.

These are possible outcomes, but they should not be the primary business plan.

⸻

## 7. Public development strategy

The project can benefit from a technical engineering blog.

The goal should not be marketing noise.

Useful content includes:

* architecture decisions;
* experiments;
* performance measurements;
* failed approaches;
* OS tracing research;
* policy design;
* security case studies;
* new attack patterns;
* demonstrations;
* benchmark results.

The best time to promote the project heavily is when there is already a working vertical slice.

The first public demonstration should show something concrete.

Example:

A coding agent launches a shell script.
The script launches psql.
The process requests DROP DATABASE.
The monitor detects the full provenance chain.
The destructive action is stopped and requires approval.

This is a stronger launch message than announcing an unfinished concept.

⸻

## 8. Major technical risks

### False positives

Too many approval requests will make users disable the protection.

Policies therefore need risk levels.

Example:

* informational;
* low risk;
* suspicious;
* approval required;
* blocked.

The system should be strict for catastrophic operations but quiet for normal development activity.

### Platform limitations

Linux, macOS, and Windows provide different tracing capabilities.

Some features can require higher privileges.

The project must therefore separate:

* required functionality;
* optional enhanced monitoring;
* privileged integrations.

### Interception

Observation is easier than prevention.

A major research question is:

Can a user-space monitor pause a dangerous action at the correct boundary before the operation is executed?

This must be tested early.

### Agent log formats

Coding-agent logs can change between versions.

Agent-specific log adapters therefore need:

* version detection;
* schema detection;
* graceful degradation;
* test fixtures.

The core product must not depend on them.

### Performance

Tracing can create large amounts of data.

The system needs:

* filtering;
* event aggregation;
* bounded queues;
* compact storage;
* selective retention.

### Trust

Because this is security software, users need to understand why a decision occurred.

Every block or approval request should have an explainable provenance chain and matching policy.

⸻

## 9. First immediate goal: Linux proof of concept

The first goal is not to build the complete product.

The first goal is to prove that the core idea is technically possible in user space on Linux.

### Goal

Build a small Linux program that launches a coding agent or ordinary shell process and tracks its descendant process tree.

The proof of concept should demonstrate that the system can detect a known dangerous operation inside a child process chain.

### Target scenario

Example:

```
monitor
  -> bash
    -> test-script.sh
      -> psql
```

The test script executes a known test command such as a harmless simulated:

DROP DATABASE example;

The prototype should detect:

* that psql was started;
* its parent process;
* the complete ancestry back to the monitored session;
* its command-line arguments;
* the working directory;
* any observable input that contains the SQL statement;
* the time of the event.

No real database should be modified during testing.

⸻

## 10. Linux research questions

Before finalizing the architecture, answer these experimentally.

### Process monitoring

Can the program observe, without root:

* process creation;
* fork;
* clone;
* execve;
* process exit;
* parent PID;
* executable path;
* arguments;
* working directory?

### Descendant tracking

If the monitored process creates:

agent -> bash -> python -> shell -> psql

can the monitor reliably associate every process with the original session?

### Attach versus launch

Compare:

* launching the process under control of the monitor;
* attaching to an already running process.

Launching is likely to be the easier and safer MVP path.

### Data access

Determine which data can be collected from:

* ptrace;
* /proc;
* procfs;
* debugger APIs;
* existing open-source debugger libraries;
* language-specific debugger components.

### Blocking

Determine whether the monitor can:

* intercept an exec before execution;
* suspend a process;
* inspect the pending action;
* wait for approval;
* resume the process;
* terminate it safely.

### Input inspection

Determine what can realistically be inspected for programs such as:

* psql;
* mysql;
* shell;
* Python;
* Git;
* kubectl;
* oc.

In particular, test whether dangerous content appears in:

* argv;
* stdin;
* temporary files;
* environment variables;
* pipes;
* sockets.

This will determine which policy signatures are practical.

⸻

## 11. Linux implementation direction

The first research implementation should stay simple.

A likely structure is:

```
agent-firewall
├── launcher
├── process-monitor
├── event-normalizer
├── provenance-graph
├── policy-engine
├── approval-handler
└── event-recorder
```

Rust is a strong candidate for the core runtime because it provides:

* memory safety;
* strong typing;
* good systems-programming support;
* good concurrency primitives;
* low runtime overhead;
* good cross-platform potential.

C is possible, but Rust reduces risk for a security-sensitive long-running process.

Python can still be useful for:

* research scripts;
* test generation;
* log analysis;
* policy tooling;
* benchmark tooling.

⸻

## 12. First deliverable

The first meaningful milestone is:

A Linux user-space monitor that launches a process, reconstructs its complete descendant execution tree, converts those observations into normalized events, and detects one deterministic dangerous behavior pattern.

A good demo is:

1. Start the monitor.
2. The monitor launches a shell or coding agent.
3. The process runs a script.
4. The script launches another process.
5. That process attempts a simulated dangerous command.
6. The monitor shows the complete provenance tree.
7. A deterministic policy matches the action.
8. The operation is marked as requiring approval.
9. If technically possible in user space, the process is suspended before the dangerous action executes.
10. The user can allow or deny it.

If this works reliably, the project has proven the most important part of the concept.

Only after this proof should the project invest heavily in:

* the final event schema;
* the full policy language;
* agent-specific log adapters;
* Windows;
* macOS;
* remote management;
* threat intelligence feeds;
* commercial packaging.

⸻

## 13. Working project hypothesis

The core hypothesis is:

Coding agents need more freedom than a strict sandbox provides, but developers need stronger guarantees than command-level approval prompts provide.

The proposed solution is a local, deterministic security layer that watches the actual effects of an agent at the operating-system boundary.

Its main differentiators are:

* agent-independent;
* local and offline;
* deterministic;
* process-tree aware;
* provenance aware;
* policy driven;
* behavior and signature based;
* capable of interactive approval;
* designed for developer machines rather than only isolated containers;
* extensible to organization-wide security and threat intelligence later.

The immediate task is to prove that this can be done reliably on Linux without requiring a privileged kernel component.
