#!/usr/bin/env python3
"""Counts how much of the shipping rule pack the kernel floor answers.

ML, 2026-08-31: the re-measurement of the pack against the floor that SHIPS
in af-monitor (crates/af-monitor/src/landlock.rs). The spike of 2026-08-28
measured 10 of the 69-rule pack on paper; the pack now holds 147 rules and
the floor is real code, so every class below says what the enacted ruleset
does, not what it could do.

Classes:

  A  The kernel answers the rule with "always no" for every action the rule
     can match. The session stops asking the rule (`KernelFloor.rules`) and
     the interruption budget shrinks by exactly this count. The bar is
     soundness: no session shape may exist in which the rule matches and the
     kernel still allows the action.

  A' The rule answers `deny` today, so it never asked. The exec boundary
     keeps stopping it, and the floor guarantees the effect when the boundary
     misses. No question is removed — these rules never asked one.

  B  The floor denies part of the ground, or the move is a policy choice.
     The rule keeps its question (or its report).

  C  The floor is blind: the rule matches a program name, an argument, SQL
     text, a host name, a file mode, or acts inside the writable work tree.

The script reads `policies/*.yaml` and fails when a rule of the pack has no
class, so the count can never drift away from the rule pack. Run it from the
spike directory with `make rules` or directly.
"""
import os
import re
import subprocess
import sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", ".."))
POLICY_DIR = os.path.join(ROOT, "policies")
BINARY = os.path.join(ROOT, "target", "release", "agent-firewall")

# rule id -> (class, reason)
CLASSIFICATION = {
    # ---------------- filesystem ----------------
    "filesystem.delete.root": ("A'", "deny today; the floor makes the walk over / fail and no removal outside the granted trees can run, so the exec boundary keeps its block and the floor stands under it"),
    "filesystem.delete.system-path": ("A", "the system trees are read and execute only; the writable exceptions of the rule (/var/tmp, /var/cache, /dev/shm) are exactly the writable exceptions of the floor"),
    "filesystem.delete.mount-root": ("A", "/mnt, /media, /run/media and /Volumes get no rule at all, so no delete and no write can reach a mounted drive"),
    "filesystem.credentials.write": ("A", "the credential stores of the home are hidden, so every write to them fails with EACCES; the class rides on the floor for the paths it hides — a .ssh under /tmp keeps its question"),
    "filesystem.etc.write": ("A", "/etc is granted read and execute only, so every write open gives EACCES"),
    "filesystem.device.truncate": ("A", "the raw devices of /dev get no rule and the TRUNCATE right is handled, so a truncate of a device cannot run"),
    "filesystem.device.destroy": ("A'", "deny today; no rule covers a raw device, so the raw write cannot run and the exec boundary keeps its block"),
    "filesystem.delete.home": ("B", "the home directory itself cannot be removed, but the contents of its top-level directories can still be destroyed, so the question stays"),
    "filesystem.delete.user-data": ("B", "the same split: the Documents directory survives, its contents do not"),
    "filesystem.delete.variable-home-root": ("B", "rm -rf \"$HOME\" destroys the contents of the home and fails at the top level; the question stays"),
    "filesystem.delete.parent-directory": ("B", ".. is read-only in the common shape, and writable when the work tree sits inside /tmp or another writable tree"),
    "filesystem.find.delete-wide": ("B", "the sweep cannot list /, ~ or /home, but a session whose work tree is the home directory can still sweep the home's entries"),
    "filesystem.interpreter.delete-system-path": ("B", "the same split: rmtree over a system tree or the home root fails, a home-rooted work tree does not"),
    "filesystem.sensitive.exec-write": ("B", "the rule also matches a .ssh or /etc path under the work tree or under /tmp, where the floor does not follow it"),
    "filesystem.perm.recursive-system-tree": ("B", "the recursive walk cannot list /, ~ or /home, but the floor does not mediate chmod itself"),
    "filesystem.credentials.read": ("B", "the rule only reports, and the floor enforces the read denial on the hidden stores anyway — the shipped choice, measured: cat of ~/.ssh fails with EACCES and an explanation"),
    "filesystem.shred": ("B", "a shred outside the work tree is already impossible; inside it the rule only reports"),
    "filesystem.delete.git-directory": ("C", "the .git directory is inside the writable work tree"),
    "filesystem.dotenv.write": ("C", "a .env file lives inside the writable work tree"),
    "filesystem.perm.world-writable": ("C", "Landlock has no right over file mode bits"),
    "filesystem.delete.unresolved-variable": ("C", "the rule matches the command line"),
    "filesystem.delete.above-work-tree": ("C", "report only; the paths above the work tree are read-only, which the floor already is"),
    "filesystem.delete.work-tree-self": ("C", "inside the writable work tree"),
    "filesystem.mirror.rsync-delete": ("C", "report only, and the command line decides"),
    "filesystem.move.destructive": ("C", "report only, and the command line decides"),
    "filesystem.interpreter.tree-delete": ("C", "report only, and the code text decides"),
    "filesystem.delete.agent-state": ("C", "the agent state lives under the writable home"),
    "filesystem.dotfile.shell-startup": ("C", "the startup files stay writable under the floor"),
    "filesystem.data.destroy-file": ("C", "report only; a database file inside the work tree stays deletable"),

    # ---------------- git ----------------
    "git.push.force": ("C", "the git verb and the --force flag are command arguments"),
    "git.push.remote-destructive": ("C", "the refspec is a command argument"),
    "git.local.discard-work": ("C", "the effect is a write inside the writable work tree"),
    "git.history.rewrite": ("C", "filter-branch writes inside .git, inside the writable work tree"),
    "git.history.drop-recovery": ("C", "reflog expire writes inside .git"),
    "git.gh.repo-delete": ("C", "the repository name is a command argument"),
    "git.push.protected-branch": ("C", "the branch name is a command argument"),
    "git.refs.delete": ("C", "a branch is a file inside .git"),
    "git.history.local-rewrite": ("C", "the rewrite happens inside .git"),
    "git.rebase.onto": ("C", "the base is a command argument"),
    "git.identity.change": ("C", "~/.gitconfig stays writable under the floor, so the --global half keeps its report"),
    "git.add.secret-file": ("C", "the path is a command argument inside the work tree"),
    "git.export.whole-repository": ("C", "report only, and the command line decides"),
    "git.gh.remote-destructive": ("C", "the verb is a command argument"),
    "git.hooks.bypass": ("C", "the hook path is a command argument"),
    "git.remote.credential-in-url": ("C", "the credential is command-line text"),

    # ---------------- database ----------------
    "database.destructive.drop-database": ("C", "the statement is SQL text inside a client program"),
    "database.destructive.drop-object": ("C", "the statement is SQL text"),
    "database.destructive.truncate": ("C", "the statement is SQL text"),
    "database.destructive.delete-without-where": ("C", "the statement is SQL text"),
    "database.destructive.update-without-where": ("C", "the statement is SQL text"),
    "database.schema.drop-column": ("C", "the statement is SQL text"),
    "database.grant.all": ("C", "the statement is SQL text"),
    "database.redis.flush": ("C", "the command is text on a socket"),
    "database.mongo.drop": ("C", "the command is text on a socket"),
    "database.admin.drop-command": ("C", "the rule matches the program and its arguments"),
    "database.production.connect": ("C", "the rule matches a host name and an environment variable"),
    "database.production.write-statement": ("C", "the rule matches a host name and SQL text"),
    "database.exfil.dump-to-network": ("C", "the rule matches a host name and SQL text"),
    "database.exfil.dump-to-remote-store": ("C", "the destination is a command argument"),
    "database.migration.destructive-reset": ("C", "the migration text decides"),
    "database.sql.result-to-program": ("C", "report only, and the pipeline is command-line text"),

    # ---------------- cloud ----------------
    "cloud.kubectl.delete": ("C", "the object and the verb are command arguments"),
    "cloud.kubectl.delete-durable": ("C", "the object kind is a command argument"),
    "cloud.kubectl.production-context": ("B", "hiding the production kubeconfig from reads would stop a read-only kubectl on it too, so the floor denies only the write and the question stays"),
    "cloud.kubectl.drain": ("C", "the node name is a command argument"),
    "cloud.kubectl.production-access": ("C", "the context name is a command argument"),
    "cloud.openshift.delete-project": ("C", "the project name is a command argument"),
    "cloud.terraform.destroy": ("C", "the verb is a command argument"),
    "cloud.terraform.auto-approve": ("C", "the flag is a command argument"),
    "cloud.terraform.state-change": ("C", "report only, and the command line decides"),
    "cloud.aws.storage-delete": ("C", "the bucket and the verb are command arguments"),
    "cloud.aws.resource-delete": ("C", "the resource and the verb are command arguments"),
    "cloud.azure.group-delete": ("C", "the group name is a command argument"),
    "cloud.gcloud.project-delete": ("C", "the project name is a command argument"),
    "cloud.container.volume-destroy": ("C", "the volume name is a command argument"),
    "cloud.container.force-remove": ("C", "the flag is a command argument"),
    "cloud.helm.uninstall": ("C", "the release name is a command argument"),
    "cloud.paas.destroy-data": ("C", "the verb is a command argument"),
    "cloud.paas.deploy-production": ("C", "report only, and the command line decides"),
    "cloud.controlplane.destructive-http": ("C", "the verb and the path are command arguments"),
    "cloud.capacity.amplify": ("C", "report only, and the command line decides"),
    "cloud.credentials.mint": ("C", "the credential path is a command argument"),
    "cloud.dns.record-change": ("C", "the record is a command argument"),
    "cloud.gh.ci-control": ("C", "the workflow path is a command argument"),

    # ---------------- network ----------------
    "network.download.pipe-to-interpreter": ("C", "the pipe into a shell is a command line"),
    "network.connect.remote-admin": ("B", "ABI 4 could deny the admin ports, but only for every address at once, and the rule is report-only today"),
    "network.connect.remote-database": ("B", "the same: the port can be denied, the host cannot be told apart"),
    "network.connect.production-host": ("C", "the rule matches a host name and Landlock has no address rule"),
    "network.shell.netcat-exec": ("C", "deny today, but the -e flag is a command argument and the floor handles no network right"),
    "network.shell.reverse-shell": ("C", "deny today, and the port of a reverse shell is free; the floor handles no network right"),
    "network.exfil.env-dump-upload": ("C", "deny today, and the destination is command-line text"),
    "network.exfil.credential-file-upload": ("C", "the destination is command-line text; the floor denies the credential read, not the upload"),
    "network.exfil.collector-upload": ("C", "the destination is command-line text"),
    "network.exfil.metadata-service": ("C", "deny today, and the address is a socket argument the floor does not see"),
    "network.exfil.dns-name-payload": ("C", "the payload is command-line text"),
    "network.exfil.dns-name-entropy": ("C", "the payload is command-line text"),
    "network.exfil.git-push-to-address": ("C", "the remote is command-line text"),
    "network.exfil.raw-address-upload": ("C", "the address is command-line text"),
    "network.secrets.token-in-command": ("C", "the token is command-line text"),
    "network.socket.local-admin-api": ("C", "the port is a socket argument"),
    "network.ssh.no-host-key-check": ("C", "the option is a command argument"),
    "network.tunnel.expose-machine": ("C", "the tunnel command line decides"),

    # ---------------- process ----------------
    "process.signal.kill-everything": ("A", "the signal scope (ABI 6) refuses every signal to a process outside the session, so the editor, the other sessions and the monitor survive; measured: pkill -f prints EPERM for each outside target"),
    "process.signal.supervision": ("A'", "deny today; the signal scope makes the kill of the monitor and of the outside agent impossible, and the exec boundary keeps its block"),
    "process.exec.from-temp": ("B", "write-xor-execute for /tmp is a choice the floor does not make: /tmp carries the execute right, so a dropped program still starts"),
    "process.perm.executable-in-temp": ("B", "the chmod is invisible and the run that follows it stays possible, for the same reason"),
    "process.exec.fileless": ("C", "measured: an exec from a memfd runs under the floor, and Landlock has no right over it"),
    "process.encoded.base64-to-shell": ("C", "the payload is a command argument"),
    "process.shell.encoded-payload": ("C", "the payload is a command argument"),
    "process.eval.downloaded-string": ("C", "the payload is a command argument"),
    "process.security.tooling-disable": ("B", "the command breaks on the read-only /run socket, but the missing privilege is the real reason and the rule matches arguments"),
    "process.agent.bypass-flag": ("C", "deny today, and the flag is a command argument"),
    "process.agent.guardrail-config": ("C", "the configuration paths live under the writable home"),
    "process.agent.state-wipe": ("C", "the session records live under the writable home"),
    "process.agent.self-update": ("C", "report only, and the install path is an argument"),
    "process.agent.nested-session": ("C", "report only, and the shape is command-line text"),
    "process.signal.broad-pattern": ("C", "report only, and the pattern is a command argument"),
    "process.system.disable-protection": ("C", "deny today, and the rule matches arguments; the floor makes no promise about where the firewall's own files live"),
    "process.package.publish": ("C", "the registry command line decides"),
    "process.persistence.autostart": ("C", "the autostart paths live under the writable home"),
    "process.persistence.agent-schedule": ("C", "the schedule paths live under the writable home"),
    "process.parent.download-tool": ("C", "the rule matches the process chain"),
    "process.shell.deep-nesting": ("C", "the rule counts shells in the chain"),
    "process.exec.name-masquerade": ("C", "report only, and the name is command-line text"),
    "process.loader.preload-env": ("C", "report only, and the variable is command-line text"),
    "process.namespace.shadow": ("C", "report only, and the namespace flags are arguments"),
    "process.install.hook-child": ("C", "report only, and the path is an argument"),
    "process.interpreter.inline-danger": ("C", "report only, and the code is command-line text"),
    "process.package.ad-hoc-run": ("C", "report only, and the package name is an argument"),
    "process.package.source-override": ("C", "report only, and the registry is an argument"),
    "process.archive.system-directory": ("C", "report only, and the path is an argument"),
    "process.detach.background-job": ("C", "report only, and the shape is command-line text"),
    "process.retry.bypass-fallback": ("C", "report only, and the pattern is command-line text"),
    "process.text.hidden-characters": ("C", "report only, and the characters are in the arguments"),
    "process.encoded.decoder-chain": ("C", "report only, and the chain is command-line text"),

    # ---------------- memory ----------------
    "memory.exfil.after-credential-read": ("B", "the floor refuses the credential read itself, so the chain the rule guards cannot complete; the rule still asks because it cannot see the refusal"),
    "memory.secrets.credential-fan-out": ("B", "the same: the reads it counts were refused by the kernel"),
    "memory.filesystem.delete-burst": ("C", "the burst is command-line text; the deletes it counts mostly fail under the floor but not inside the work tree"),
    "memory.git.push-unknown-remote": ("C", "the remote is command-line text"),
    "memory.git.push-after-remote-change": ("C", "the remote change is command-line text"),
    "memory.credentials.read-mark": ("C", "the mark rule matches command-line text"),
    "memory.git.remote-config-mark": ("C", "the mark rule matches command-line text"),

    # ---------------- allowlist ----------------
    "allowlist.filesystem.build-output": ("B", "the exception disappears: the work tree stays writable, so a delete of build output never raises a question"),
    "allowlist.filesystem.temp-cleanup": ("B", "the same for /tmp and /var/tmp"),
    "allowlist.git.dry-run": ("C", "the exception matches a command argument"),
    "allowlist.cloud.local-cluster": ("C", "the exception matches a context name"),
    "allowlist.database.local-host": ("C", "the exception matches a host argument"),

    # ---------------- tamper (M4, 2026-08-31) ----------------
    "tamper.monitor.signal": ("B", "the signal scope (ABI 6) refuses the call when the ruling allows it, so the monitor survives either way; the quarantine still asks, because a signal aimed at the firewall is a fact the user must rule on, whatever the kernel does with the call"),
    "tamper.process.detached": ("C", "the sensed fact is a session identifier of a process; the floor sees no process at all"),
    "tamper.process.respawned": ("C", "the sensed fact is an act of the monitor itself"),
    "tamper.sensor.preload-stripped": ("C", "the sensed fact is the environment of an exec"),
    "tamper.process.outlived": ("C", "the sensed fact is liveness at the end of the session root"),

    # ---------------- correlation (M5) ----------------
    "correlation.sensor.silent-subtree": ("C", "the judged fact is a discrepancy event replayed from two finished views; a sensor that stopped talking is not a filesystem action, and the floor mediates filesystem rights and the signal scope only"),
    "correlation.action.contradicted": ("C", "the judged fact is a discrepancy event: a connect that crossed the process without crossing libc; the floor handles no network right, and the event is judged after the run, not at a kernel boundary"),
    "correlation.spawn.unreported": ("C", "the judged fact is a discrepancy event: the preload an exec carried and the sensor instance that never registered; an exec's environment and the sensor's registry are nothing the floor sees"),
}


def rules_of_the_pack():
    """Reads the pack the way the product sees it: `policy list --json`."""
    if not os.path.exists(BINARY):
        print(f"count-rules.py: build the workspace first: {BINARY} is missing")
        sys.exit(2)
    out = subprocess.run(
        [BINARY, "policy", "list", "--json"],
        capture_output=True, text=True, check=True,
    ).stdout
    import json
    return json.loads(out)


def main():
    rules = rules_of_the_pack()
    unknown = [r for r in rules if r["rule_id"] not in CLASSIFICATION]
    gone = [rid for rid in CLASSIFICATION if rid not in {r["rule_id"] for r in rules}]
    if unknown or gone:
        for r in unknown:
            print(f"UNCLASSIFIED rule in the pack: {r['rule_id']}")
        for rid in gone:
            print(f"CLASSIFIED rule that the pack no longer holds: {rid}")
        print("give every rule a class, so the count cannot drift away from the pack")
        sys.exit(1)

    counts = {"A": [], "A'": [], "B": [], "C": []}
    for r in rules:
        cls, _ = CLASSIFICATION[r["rule_id"]]
        counts[cls].append(r)

    stopping = [r for r in rules if r["decision"] in ("deny", "approval_required")]
    asking = [r for r in rules if r["decision"] == "approval_required"]

    print(f"the pack holds {len(rules)} rules: "
          f"{len(stopping)} stop the user "
          f"({len([r for r in stopping if r['decision'] == 'deny'])} deny, "
          f"{len(asking)} approval_required), "
          f"{len(rules) - len(stopping)} report only")
    print()
    print(f"A  the kernel answers, the question disappears: {len(counts['A'])}")
    for r in counts["A"]:
        cls, reason = CLASSIFICATION[r["rule_id"]]
        print(f"     {r['rule_id']}  ({r['decision']})  {reason}")
    print()
    backed = counts["A'"]
    print(f"A' deny rules the kernel backs, no question to remove: {len(backed)}")
    for r in counts["A'"]:
        cls, reason = CLASSIFICATION[r["rule_id"]]
        print(f"     {r['rule_id']}  ({r['decision']})  {reason}")
    print()
    print(f"B  the floor denies part of the ground: {len(counts['B'])}")
    print(f"C  the floor is blind: {len(counts['C'])}")
    print()
    removed = len(counts["A"])
    print(f"questions removed: {removed} of {len(asking)} approval_required rules "
          f"({100.0 * removed / max(len(asking), 1):.0f}% of the questions the pack can ask)")
    print(f"deny rules backed by the kernel: {len(backed)} of "
          f"{len([r for r in stopping if r['decision'] == 'deny'])}")


if __name__ == "__main__":
    main()
