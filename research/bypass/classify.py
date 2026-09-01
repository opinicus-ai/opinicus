#!/usr/bin/env python3
"""Classifies the bypass matrix runs of [af-1] into held / seen / silent.

Reads results/<pass>-<mode>-<technique>.json (written by orchestrate.py),
re-derives every action's outcome from the run's scratch directory, and
writes results/matrix.json plus a markdown table on stdout.

  held   — the action did not happen (denied, refused, or the session died first)
  seen   — the action happened and the trace carries a witness event for it
  silent — the action happened and no trace event covers it
"""

import json
import sys
from pathlib import Path

RESULTS = Path(__file__).resolve().parent / "results"

DROP_RULE = "database.destructive.drop-database"


def trace_events(scratch):
    trace = scratch / "trace.jsonl"
    if not trace.exists():
        return []
    events = []
    for line in trace.read_text().splitlines():
        line = line.strip()
        if line:
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                pass  # a trace can end mid-line when the monitor was killed
    return events


def rules_of(events):
    out = []
    for e in events:
        if e.get("type") == "policy_decision":
            for m in e.get("verdict", {}).get("matches", []):
                out.append(m.get("rule_id"))
    return sorted(set(r for r in out if r))


def sensor_events(scratch):
    """The trace of the in-process sensor of a preload run."""
    trace = Path(scratch) / "sensor.jsonl"
    if not trace.exists():
        return []
    events = []
    for line in trace.read_text().splitlines():
        line = line.strip()
        if line:
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                pass
    return events


def sensor_witness(tech, action, events):
    """True when the sensor trace carries a witness for the action.

    The shim never holds, so a sensor witness can only move a silent cell to
    seen; the product alone can hold.
    """

    def any_read(token):
        return any(
            e.get("type") == "file_read" and token in str(e.get("data", ""))
            for e in events
        )

    if tech in ("static-file-net", "rawsys", "uring"):
        if action in ("write", "file", "uring"):
            return any(
                e.get("type") == "file_open"
                and str(e.get("path", "")).endswith("marker.txt")
                and e.get("write")
                for e in events
            )
        return any(e.get("type") == "network_connect" for e in events)
    if tech == "escape-setsid":
        return any(
            e.get("type") == "file_open"
            and str(e.get("path", "")).endswith("marker.txt")
            and e.get("write")
            for e in events
        )
    if tech == "outlive":
        return any(
            e.get("type") == "file_open"
            and str(e.get("path", "")).endswith("marker.txt")
            and e.get("write")
            for e in events
        )
    if tech == "delete-rename":
        deleted = any(
            e.get("type") == "file_delete"
            and str(e.get("path", "")).endswith("victim/f")
            for e in events
        )
        renamed = any(
            e.get("type") == "file_rename"
            and str(e.get("from", "")).endswith("victim")
            and str(e.get("to", "")).endswith("moved")
            for e in events
        )
        return deleted or renamed
    if tech == "cred-read":
        return any(
            e.get("type") == "file_open"
            and str(e.get("path", "")).endswith(".aws/credentials")
            and not e.get("write")
            for e in events
        )
    if tech == "fileclient" and action == "byfile-unknown":
        return any_read("DROP DATABASE")
    if tech == "fileclient" and action == "byfile-psql":
        return any_read("DROP DATABASE")
    if tech == "payload-assembly":
        return any(
            e.get("type") == "process_exec"
            and "payload.sh" in json.dumps(e.get("process", {}))
            for e in events
        )
    if tech == "pydrop":
        return any_read("DROP DATABASE")
    return False


def sensor_notes(tech, events):
    notes = []
    if tech == "static-file-net":
        notes.append("static Go binary: the shim never loads, so nothing reports")
    if tech == "rawsys":
        notes.append("raw syscall(): the interposed libc symbols are never called")
    if tech == "uring":
        notes.append("ring operations never cross libc; the shim sees the technique binary itself, not the ring")
    if tech == "kill-monitor":
        scan = any(
            e.get("type") == "file_open" and "/proc/" in str(e.get("path", ""))
            for e in events
        )
        notes.append(
            "the /proc scan is visible to the sensor" if scan else "the /proc scan never crossed libc"
        )
        notes.append("the kill() call is not in the hook set; a signal needs no libc crossing the sensor watches")
    return notes


def decision_levels(events):
    return sorted({e.get("verdict", {}).get("decision") for e in events if e.get("type") == "policy_decision"})


def has_file_open(events, suffix, write):
    return any(
        e.get("type") == "file_open"
        and str(e.get("path", "")).endswith(suffix)
        and bool(e.get("write")) == write
        for e in events
    )


def has_exec(events, needle):
    return any(
        e.get("type") == "process_exec" and needle in json.dumps(e.get("process", {}))
        for e in events
    )


def has_drop_decision(events):
    return any(
        e.get("type") == "policy_decision"
        and any(m.get("rule_id") == DROP_RULE for m in e.get("verdict", {}).get("matches", []))
        for e in events
    )


def marker_has(scratch, name, token):
    p = scratch / name
    return p.exists() and token in p.read_text()


def verdict_for(record, action):
    """Returns (verdict, witness_found, rules, notes)."""
    scratch = Path(record["scratch"])
    events = trace_events(scratch)
    tech = record["technique"]
    mode = record["mode"]
    notes = []
    rules = rules_of(events)

    if record["pass"] == "baseline":
        effect = effect_ok(record, action)
        return ("works" if effect else "broken"), False, [], notes

    effect = effect_ok(record, action)
    fw_died = record["fw_exit"] is not None and record["fw_exit"] < 0
    fw_exit = record["fw_exit"]

    if record["pass"] == "preload":
        # The [af-2] re-run: the product posture plus the in-process sensor.
        # The sensor never holds, so a cell is held only when the product
        # held it; a sensor witness moves a silent cell to seen.
        if not effect:
            held_by_decision = any(
                d in ("approval_required", "deny") for d in decision_levels(events)
            )
            if fw_exit == 3 or held_by_decision or fw_died:
                return "held (product)", False, rules, notes
            return "action-failed", False, rules, notes
        product = witness_ok(record, action, events, notes)
        if product:
            return "seen", True, rules, notes
        sevents = sensor_events(scratch)
        if sensor_witness(tech, action, sevents):
            notes.append("the in-process sensor carried the witness")
            notes.extend(sensor_notes(tech, sevents))
            return "seen (sensor)", True, rules, notes
        notes.extend(sensor_notes(tech, sevents))
        return "silent", False, rules, notes

    if record["pass"] == "probe":
        # The probe pass asks one question: can a rule act on this action's
        # event? A witness in the trace means the event was delivered to the
        # engine, whatever the verdict was.
        witness = witness_ok(record, action, events, notes)
        if witness:
            return "holdable", True, rules, notes
        if effect:
            return "no event", False, rules, notes
        return "held-indirect", False, rules, notes

    if tech == "kill-monitor":
        session_end = any(e.get("type") == "session_end" for e in events)
        notes.append(
            f"fw_exit={fw_exit} session_end={'yes' if session_end else 'no'} "
            f"rules={rules or 'none'}"
        )
        seen_scan = has_file_open(events, "/proc/self/status", False) if mode == "all-opens" else False
        # Since [af-4] the filter holds a signal whose target is the monitor,
        # so the call never runs: the tamper rule fires, the session is
        # quarantined and the ruling (here the auto-deny of the harness)
        # refuses the call. The kill did not happen and the monitor lived.
        if any(r.startswith("tamper.") for r in rules):
            notes.append("the signal was held before it ran; the tamper rule quarantined")
            return ("held", True, rules, notes)
        if not seen_scan and mode in ("write-only", "off"):
            notes.append("the /proc scan and the kill left no event at all")
        return ("silent (fail-closed outcome)", seen_scan, rules, notes)

    if not effect:
        held_by_decision = any(d in ("approval_required", "deny") for d in decision_levels(events))
        if fw_exit == 3 or held_by_decision or fw_died:
            return "held", False, rules, notes
        return "action-failed", False, rules, notes

    witness = witness_ok(record, action, events, notes)
    if witness:
        return "seen", True, rules, notes
    return "silent", False, rules, notes


def effect_ok(record, action):
    scratch = Path(record["scratch"])
    tech = record["technique"]
    if tech == "static-file-net":
        if action == "write":
            return marker_has(scratch, "marker.txt", "go-static")
        return marker_has(scratch, "listen.log", "go-static-connect")
    if tech == "rawsys":
        if action == "file":
            return marker_has(scratch, "marker.txt", "rawsys-file")
        return marker_has(scratch, "listen.log", "rawsys-connect")
    if tech == "escape-setsid":
        return marker_has(scratch, "marker.txt", "escape-leaf")
    if tech == "outlive":
        return marker_has(scratch, "marker.txt", "outlived")
    if tech == "uring":
        return marker_has(scratch, "marker.txt", "uring")
    if tech == "delete-rename":
        moved_ok = (scratch / "moved").is_dir() and not (scratch / "moved" / "f").exists()
        return marker_has(scratch, "marker.txt", "deleted") and moved_ok
    if tech == "cred-read":
        return marker_has(scratch, "marker.txt", "cred-read")
    if tech == "fileclient":
        token = "EXECUTED: DROP DATABASE customer_prod;"
        name = "marker-a.txt" if action == "byfile-unknown" else "marker-b.txt"
        return marker_has(scratch, name, token)
    if tech == "payload-assembly":
        return marker_has(scratch, "marker.txt", "assembled")
    if tech == "pydrop":
        return marker_has(scratch, "marker.txt", "pydrop")
    if tech == "kill-monitor":
        return marker_has(scratch, "marker.txt", "before-kill")
    raise KeyError(f"{tech}/{action}")


def witness_ok(record, action, events, notes):
    tech = record["technique"]
    scratch = Path(record["scratch"])
    if tech == "static-file-net" and action == "write":
        return has_file_open(events, "marker.txt", True)
    if tech == "static-file-net" and action == "connect":
        return any(e.get("type") == "network_connect" for e in events)
    if tech == "rawsys" and action == "file":
        return has_file_open(events, "marker.txt", True)
    if tech == "rawsys" and action == "connect":
        return any(e.get("type") == "network_connect" for e in events)
    if tech == "escape-setsid":
        return has_exec(events, "escape-setsid")
    if tech == "outlive":
        found = has_exec(events, "outlive")
        notes.append("session waited for the daemon" if found else "daemon outside the trace")
        return found
    if tech == "uring":
        # Since [af-12] the filter holds io_uring_setup and io_uring_enter,
        # so the witness is the delivered io_uring event itself; the
        # file_open witness still covers a session whose local rules let a
        # ring through.
        if any(e.get("type") == "io_uring" for e in events):
            notes.append("the filter held the ring call before it ran")
            return True
        ok = has_file_open(events, "marker.txt", True)
        if not ok:
            notes.append(
                "no io_uring event and no file_open witness: "
                "the ring road never reached the engine"
            )
        return ok
    if tech == "delete-rename":
        notes.append("the create was visible, the unlink and the rename are not: no event kind exists")
        return False
    if tech == "cred-read":
        ok = has_file_open(events, ".aws/credentials", False)
        if not ok and record["mode"] == "write-only":
            notes.append("read-open dropped by the kernel filter in write-only mode")
        return ok
    if tech == "fileclient" and action == "byfile-unknown":
        notes.append("fileclient is in no interpreter or database-client list, so no input capture fires")
        return False
    if tech == "fileclient" and action == "byfile-psql":
        return has_drop_decision(events)
    if tech == "payload-assembly":
        return has_exec(events, "payload.sh")
    if tech == "pydrop":
        ok = has_drop_decision(events)
        if not ok:
            notes.append(
                "the program name is python3.14, which is in no interpreter list, "
                "so the script snapshot never fired"
            )
        return ok
    return False


ACTIONS = {
    "static-file-net": ["write", "connect"],
    "rawsys": ["file", "connect"],
    "escape-setsid": ["leaf"],
    "outlive": ["daemon"],
    "uring": ["uring"],
    "delete-rename": ["delete-rename"],
    "cred-read": ["read"],
    "fileclient": ["byfile-unknown", "byfile-psql"],
    "payload-assembly": ["assembled"],
    "pydrop": ["script-content"],
    "kill-monitor": ["kill"],
}

SCENARIOS = {
    "static-file-net": "no catalogue row (adjacent: evade-04, evade-06)",
    "rawsys": "no catalogue row (adjacent: evade-06)",
    "escape-setsid": "evade-08",
    "outlive": "behavior-03",
    "uring": "evade-15",
    "delete-rename": "fs-12 (also fs-05, fs-07)",
    "cred-read": "secrets-01",
    "fileclient": "evade-03 (adjacent)",
    "payload-assembly": "evade-05",
    "pydrop": "new finding (adjacent: evade-03, evade-18)",
    "kill-monitor": "evade-07",
}


def main():
    records = []
    for p in sorted(RESULTS.glob("*-*.json")):
        if p.name in ("matrix.json",):
            continue
        head = json.loads(p.read_text())
        for action in ACTIONS[head["technique"]]:
            verdict, witness, rules, notes = verdict_for(head, action)
            records.append({**head, "action": action, "verdict": verdict, "witness": witness,
                            "rules": rules, "notes": notes})
    (RESULTS / "matrix.json").write_text(json.dumps(records, indent=2))

    modes = ["write-only", "all-opens", "off"]
    has_preload = any(p.name.startswith("preload-") for p in RESULTS.glob("preload-*.json"))
    head = "| technique / action | scenario | baseline | builtin w-o | builtin a-o | builtin off | probe w-o | probe a-o | probe off |"
    if has_preload:
        head += " sensor w-o | sensor a-o | sensor off |"
    head += " rules that fired (any pass) |"
    print(head)
    print("| --- |" + " --- |" * (head.count("|") - 2))

    def cell(pass_name, mode, tech, action):
        for r in records:
            if (r["pass"], r["mode"], r["technique"], r["action"]) == (pass_name, mode, tech, action):
                if pass_name == "probe":
                    return "held" if r["verdict"] == "held" else ("seen" if r["verdict"] == "seen" else r["verdict"])
                return r["verdict"]
        return "?"

    def short(verdict):
        if verdict.startswith("seen"):
            return "seen"
        if verdict.startswith("held"):
            return "held"
        return verdict

    by_key = {(r["pass"], r["mode"], r["technique"], r["action"]): r for r in records}
    for tech, actions in ACTIONS.items():
        for action in actions:
            base = by_key.get(("baseline", "none", tech, action), {}).get("verdict", "?")
            row = [f"{tech} / {action}", SCENARIOS[tech], base]
            for pass_name in ("builtin", "probe"):
                for mode in modes:
                    row.append(cell(pass_name, mode, tech, action))
            if has_preload:
                for mode in modes:
                    before = short(cell("builtin", mode, tech, action))
                    after = cell("preload", mode, tech, action)
                    after_short = short(after)
                    mark = f"{before}\u2192{after_short}" if before != after_short else after_short
                    row.append(mark)
            all_rules = sorted({x for r in records if r["technique"] == tech and r["action"] == action for x in r["rules"]})
            row.append(", ".join(all_rules) if all_rules else "none")
            print("| " + " | ".join(row) + " |")
            notes = [n for r in records if r["technique"] == tech and r["action"] == action for n in r["notes"]]
            for n in sorted(set(notes)):
                print(f"    - {n}")


if __name__ == "__main__":
    main()
