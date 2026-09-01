#!/usr/bin/env python3
"""Reader for the in-process sensor of M2: validates a sensor trace, counts
its events, computes the semantic gain, and checks sensor silence.

  reader.py <sensor-trace.jsonl> [--reg <reg.jsonl>]
      [--gain] [--stale-ms N] [--fw <path-to-agent-firewall>]

What it does:

* Schema validation. Every line of the trace must deserialize as an
  af-core Event. The check is the product's own reader:
  `agent-firewall tree <trace>` fails on any broken line, so a trace that
  passes is schema-valid by the shipped contract, not by a re-implementation.

* Histogram. One line per event kind, with the count.

* Semantic gain (--gain). Of the sensor's interesting actions — every exec,
  write-intent open, captured file content, delete, rename, connect, dlopen,
  environment change and stdin feed — argv alone can describe only the execs
  (the program name and its arguments). The gain is the fraction of the rest.
  Read-only opens are excluded from "interesting" on purpose: they are
  99.7% of the open traffic on the synthetic W2 file workload
  (research/spikes/seccomp-ptrace/FINDINGS.md), and the product's own
  filter drops them for that reason.

* Sensor silence (--reg). An instance the firewall installed is silent when
  its process still lives, the instance spoke at least once (an event or a
  heartbeat), and nothing has arrived from it for --stale-ms. This is the
  DECISIONS test keyed to installed instances: a dead instance is normal
  teardown, and a process that never spoke never looked silent. Exit code 1
  when any instance is silent, so the gate can use this directly.
"""

import argparse
import json
import subprocess
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]

INTERESTING_ARGV_INVISIBLE = (
    "file_open_write",
    "file_read",
    "file_delete",
    "file_rename",
    "network_connect",
    "library_load",
    "env_change",
    "stdin_write",
)


def validate(trace: Path, fw: str) -> bool:
    result = subprocess.run(
        [fw, "tree", str(trace)], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE
    )
    if result.returncode != 0:
        sys.stderr.write(result.stderr.decode(errors="replace"))
        return False
    return True


def histogram(trace: Path):
    counts = {}
    write_opens = 0
    for line in trace.read_text().splitlines():
        if not line.strip():
            continue
        event = json.loads(line)
        kind = event["type"]
        counts[kind] = counts.get(kind, 0) + 1
        if kind == "file_open" and event.get("write"):
            counts["file_open_write"] = counts.get("file_open_write", 0) + 1
    return counts


def gain(counts):
    execs = counts.get("process_exec", 0)
    invisible = sum(counts.get(k, 0) for k in INTERESTING_ARGV_INVISIBLE)
    total = execs + invisible
    return execs, invisible, total


def pid_alive(pid: int) -> bool:
    return Path(f"/proc/{pid}").exists()


def silence(reg: Path, stale_ms: int, trace: Path | None = None):
    """Returns (silent instances, summary lines).

    An instance is silent when its process still lives, the instance spoke
    at least once (an event in the trace or a heartbeat), and nothing has
    arrived from it for stale_ms. An instance that only registered never
    promised a heartbeat: a quiet instance is not a silent one, and a dead
    instance is normal teardown. This is the keyed-to-installed-instances
    rule of the decision log, not the foreign-process rule that never fires.
    """
    instances = {}
    for line in reg.read_text().splitlines():
        if not line.strip():
            continue
        rec = json.loads(line)
        inst = rec["instance"]
        state = instances.setdefault(
            inst,
            {"pid": rec["pid"], "exe": rec["exe"], "register": rec["ts"],
             "spoke": False, "last": rec["ts"], "exit": None},
        )
        if rec["type"] == "sensor_heartbeat":
            state["spoke"] = True
        if rec["type"] == "sensor_exit":
            state["exit"] = rec["ts"]
        state["last"] = max(state["last"], rec["ts"])

    trace_pids = set()
    if trace and trace.exists():
        for line in trace.read_text().splitlines():
            if line.strip():
                trace_pids.add(json.loads(line).get("pid"))

    now_ns = time.time_ns()
    silent, lines = [], []
    for inst, st in sorted(instances.items()):
        if st["exit"] is not None or not pid_alive(st["pid"]):
            continue  # teardown is not silence
        if not (st["spoke"] or st["pid"] in trace_pids):
            continue  # a quiet instance never promised a heartbeat
        age_ms = (now_ns - st["last"]) / 1e6
        if age_ms > stale_ms:
            silent.append(inst)
            lines.append(
                f"SILENT instance={inst} pid={st['pid']} exe={st['exe']} "
                f"last={age_ms:.0f}ms ago"
            )
    return silent, lines


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("trace", type=Path)
    ap.add_argument("--reg", type=Path)
    ap.add_argument("--gain", action="store_true")
    ap.add_argument("--stale-ms", type=int, default=3000)
    ap.add_argument("--fw", default=str(REPO / "target" / "release" / "agent-firewall"))
    args = ap.parse_args()

    if not validate(args.trace, args.fw):
        sys.exit(f"schema check failed: {args.trace} is not a valid af-core trace")
    print(f"schema-valid: {args.trace} reads as an af-core trace")

    counts = histogram(args.trace)
    events = sum(v for k, v in counts.items() if k != "file_open_write")
    for kind in sorted(counts):
        print(f"  {kind:16s} {counts[kind]}")
    print(f"  {'total':16s} {events}")

    if args.gain:
        execs, invisible, total = gain(counts)
        if total:
            frac = invisible / total
            print(
                f"semantic gain: {invisible} of {total} interesting actions "
                f"({frac:.0%}) are invisible to argv; argv sees only the {execs} execs"
            )

    if args.reg:
        silent, lines = silence(args.reg, args.stale_ms, args.trace)
        if lines:
            for line in lines:
                print(line)
        print(f"sensor silence: {len(silent)} silent instance(s)")
        if silent:
            sys.exit(1)


if __name__ == "__main__":
    main()
