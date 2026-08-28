#!/usr/bin/env python3
"""Counts how much of the shipping rule pack could move to Landlock.

The script reads `policies/*.yaml` and puts every rule in one of three
classes. The class of each rule is written down here by hand, with a reason,
because the decision needs an understanding of what Landlock can see. The
script checks that the hand list and the policy files agree, so the count can
never drift away from the rule pack.

Classes:

  A  Landlock removes the question. The rule stops the user today (deny or
     approval_required), Landlock can make the action impossible before the
     program starts, and normal work does not need the action.

  B  Landlock removes the damage, but the move is a choice. The rule only
     reports today, or Landlock covers part of the ground, so the move
     changes what a developer can do.

  C  Landlock is blind. The rule matches a program name, a command argument,
     an SQL statement, a host name or a file mode, and Landlock sees none of
     these. Or the right answer is genuinely "it depends".
"""
import os
import re
import sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", ".."))
POLICY_DIR = os.path.join(ROOT, "policies")

# rule id -> (class, reason)
CLASSIFICATION = {
    # ---------------- filesystem ----------------
    "filesystem.delete.root": ("A", "no REMOVE_DIR or REMOVE_FILE right on /, so rm -rf / cannot run"),
    "filesystem.delete.home": ("A", "the home directory is not granted write, so the delete is impossible"),
    "filesystem.delete.system-path": ("A", "/etc /usr /var are granted read and execute only"),
    "filesystem.delete.parent-directory": ("A", "only the work tree is granted, so .. is outside it"),
    "filesystem.delete.git-directory": ("C", "the .git directory is inside the work tree, which must stay writable for normal work"),
    "filesystem.credentials.write": ("A", "MEASURED: --hide ~/.ssh and ~/.aws/credentials; write and create both give EACCES"),
    "filesystem.sensitive.exec-write": ("A", "the effect is a write to a credential or system file, and that write is impossible"),
    "filesystem.etc.write": ("A", "/etc is granted read and execute only, so every write gives EACCES"),
    "filesystem.credentials.read": ("B", "MEASURED: the read gives EACCES. The rule only reports today, so a deny is a policy choice"),
    "filesystem.dotenv.write": ("C", "a .env file lives inside the work tree, which must stay writable"),
    "filesystem.perm.world-writable": ("C", "Landlock has no right over file mode bits; chmod is invisible to it"),
    "filesystem.device.destroy": ("A", "/dev/sd* and /dev/nvme* are not granted, so a raw write to a disk is impossible"),
    "filesystem.device.truncate": ("A", "the TRUNCATE right (ABI 3) is handled and no rule grants it on a device"),
    "filesystem.shred": ("B", "a shred outside the work tree is already impossible; inside it the rule only reports"),

    # ---------------- git ----------------
    "git.push.force": ("C", "Landlock sees no git verb and no --force flag"),
    "git.push.protected-branch": ("C", "the branch name is a command argument"),
    "git.push.remote-destructive": ("C", "the refspec is a command argument"),
    "git.local.discard-work": ("C", "the effect is a write inside the work tree, which must stay writable"),
    "git.refs.delete": ("C", "a branch is a file inside .git, inside the writable work tree"),
    "git.history.rewrite": ("C", "filter-branch writes inside .git, inside the writable work tree"),
    "git.rebase.onto": ("C", "the base is a command argument"),
    "git.history.drop-recovery": ("C", "reflog expire writes inside .git, inside the writable work tree"),
    "git.identity.change": ("B", "the --global half writes ~/.gitconfig, which is outside the work tree and can be made read-only; the remote set-url half writes .git/config and cannot"),

    # ---------------- network ----------------
    "network.download.pipe-to-interpreter": ("C", "the pipe into a shell is a command line, not a syscall pattern"),
    "network.connect.remote-admin": ("B", "ABI 4 CONNECT_TCP can deny port 22, but only for every address; the rule excludes localhost and Landlock has no address rule"),
    "network.connect.remote-database": ("B", "the same: the port can be denied, the host cannot be told apart from a local one"),
    "network.connect.production-host": ("C", "the rule matches a host name and Landlock has no address rule"),
    "network.shell.netcat-exec": ("C", "the -e flag of netcat is a command argument"),
    "network.shell.reverse-shell": ("B", "under a default-deny egress ruleset the connect fails, but the port of a reverse shell is free, so the allow list must be small"),
    "network.ssh.no-host-key-check": ("C", "the option is a command argument"),

    # ---------------- process ----------------
    "process.exec.from-temp": ("B", "MEASURED: /tmp granted write and no execute; the dropped program gives EACCES on exec. The rule only reports today"),
    "process.perm.executable-in-temp": ("B", "the chmod is invisible, but the run that follows it is impossible under the same write-xor-execute ruleset"),
    "process.encoded.base64-to-shell": ("C", "the payload is a command argument"),
    "process.shell.encoded-payload": ("C", "the payload is a command argument"),
    "process.eval.downloaded-string": ("C", "the payload is a command argument"),
    "process.parent.download-tool": ("C", "the rule matches the process chain, which Landlock does not model"),
    "process.shell.deep-nesting": ("C", "the rule counts shells in the chain, which Landlock does not model"),
    "process.signal.kill-everything": ("A", "MEASURED: LANDLOCK_SCOPE_SIGNAL (ABI 6) gives EPERM for a signal to a process outside the sandbox; kill -9 -1 no longer reaches the editor or the session"),
    "process.persistence.autostart": ("B", "crontab, ~/.config/systemd and ~/.bashrc are outside the work tree and can be read only; the rule only reports today"),

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
    "database.production.connect": ("C", "the rule matches a host name and an environment variable; Landlock has neither"),
    "database.admin.drop-command": ("C", "the rule matches the program and its arguments"),

    # ---------------- cloud ----------------
    "cloud.kubectl.delete": ("C", "the object and the verb are command arguments"),
    "cloud.kubectl.delete-durable": ("C", "the object kind is a command argument"),
    "cloud.kubectl.production-context": ("B", "hiding a production kubeconfig file makes the whole context unreachable; that also stops a read-only kubectl on it"),
    "cloud.kubectl.drain": ("C", "the node name is a command argument"),
    "cloud.openshift.delete-project": ("C", "the project name is a command argument"),
    "cloud.terraform.destroy": ("C", "the verb is a command argument"),
    "cloud.terraform.auto-approve": ("C", "the flag is a command argument"),
    "cloud.aws.storage-delete": ("C", "the bucket and the verb are command arguments"),
    "cloud.aws.resource-delete": ("C", "the resource and the verb are command arguments"),
    "cloud.azure.group-delete": ("C", "the group name is a command argument"),
    "cloud.gcloud.project-delete": ("C", "the project name is a command argument"),
    "cloud.container.volume-destroy": ("C", "the volume name is a command argument"),
    "cloud.container.force-remove": ("C", "the flag is a command argument"),
    "cloud.helm.uninstall": ("C", "the release name is a command argument"),

    # ---------------- allowlist ----------------
    "allowlist.filesystem.build-output": ("B", "the exception disappears: the work tree is writable, so a delete of build output never raises a question"),
    "allowlist.filesystem.temp-cleanup": ("B", "the exception disappears: /tmp is writable, so a delete there never raises a question"),
    "allowlist.git.dry-run": ("C", "the exception matches a command argument"),
    "allowlist.cloud.local-cluster": ("C", "the exception matches a context name"),
    "allowlist.database.local-host": ("C", "the exception matches a host argument"),
}

# The class C reasons fall into a few groups. This keeps the report short.
def coarse(reason):
    r = reason.lower()
    if "sql" in r or "text on a socket" in r:
        return "the action is statement text inside a client program"
    if "work tree" in r:
        return "the path is inside the work tree, which must stay writable"
    if "host name" in r or "address rule" in r:
        return "the rule needs a host name or an address, and Landlock has neither"
    if "process chain" in r or "shells in the chain" in r:
        return "the rule needs the process chain, which Landlock does not model"
    if "mode bits" in r:
        return "the rule needs file mode bits, which Landlock does not control"
    return "the rule needs the program name or its arguments"


CLASS_TITLE = {
    "A": "Landlock removes the question",
    "B": "Landlock removes the damage, but the move is a choice",
    "C": "Landlock is blind to what the rule matches",
}


def read_rules():
    """Returns [(file, rule_id, decision)] from the policy files."""
    out = []
    for name in sorted(os.listdir(POLICY_DIR)):
        if not name.endswith(".yaml"):
            continue
        text = open(os.path.join(POLICY_DIR, name)).read()
        for block in re.split(r"\n  - id: ", text)[1:]:
            rule_id = block.split("\n")[0].strip()
            m = re.search(r"\n    decision: (\S+)", block)
            out.append((name, rule_id, m.group(1) if m else "?"))
    return out


def main():
    rules = read_rules()
    ids = {r[1] for r in rules}
    missing = ids - set(CLASSIFICATION)
    extra = set(CLASSIFICATION) - ids
    if missing or extra:
        print("the hand list and the policy files do not agree", file=sys.stderr)
        for r in sorted(missing):
            print("  not classified: " + r, file=sys.stderr)
        for r in sorted(extra):
            print("  no such rule:   " + r, file=sys.stderr)
        return 1

    print("Rules in the pack: %d" % len(rules))
    stops = [r for r in rules if r[2] in ("deny", "approval_required")]
    quiet = [r for r in rules if r[2] == "allow"]
    print("  stop the user (deny or approval_required): %d" % len(stops))
    print("  report only (allow):                       %d" % len(quiet))

    print("\n--- by policy file ---")
    header = "%-22s %5s %5s %5s %5s" % ("file", "total", "A", "B", "C")
    print(header)
    print("-" * len(header))
    files = sorted({r[0] for r in rules})
    totals = {"A": 0, "B": 0, "C": 0}
    for f in files:
        rows = [r for r in rules if r[0] == f]
        counts = {"A": 0, "B": 0, "C": 0}
        for _, rid, _dec in rows:
            counts[CLASSIFICATION[rid][0]] += 1
            totals[CLASSIFICATION[rid][0]] += 1
        print("%-22s %5d %5d %5d %5d" % (f, len(rows), counts["A"], counts["B"], counts["C"]))
    print("-" * len(header))
    print("%-22s %5d %5d %5d %5d" % ("TOTAL", len(rules), totals["A"], totals["B"], totals["C"]))

    a_stop = [r for r in rules if CLASSIFICATION[r[1]][0] == "A" and r[2] != "allow"]
    print("\nClass A rules that stop the user today: %d of %d (%.0f%% of the "
          "interruption budget)" % (len(a_stop), len(stops), 100.0 * len(a_stop) / len(stops)))

    for cls in ("A", "B", "C"):
        rows = [r for r in rules if CLASSIFICATION[r[1]][0] == cls]
        print("\n=== class %s: %s (%d rules) ===" % (cls, CLASS_TITLE[cls], len(rows)))
        if cls == "C":
            # The long list adds nothing; group it by the reason instead.
            groups = {}
            for _f, rid, _d in rows:
                groups.setdefault(coarse(CLASSIFICATION[rid][1]), []).append(rid)
            for reason in sorted(groups, key=lambda k: -len(groups[k])):
                print("  %2d  %s" % (len(groups[reason]), reason))
                for rid in sorted(groups[reason]):
                    print("        %s" % rid)
            continue
        for _f, rid, dec in rows:
            print("  %-40s [%-17s] %s" % (rid, dec, CLASSIFICATION[rid][1]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
