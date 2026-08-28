#!/usr/bin/env python3
"""Check that LEDGER.md's count tables agree with incidents/ and scenarios/ on disk.

Run after every threat research run (and before committing one):
    python3 research/threats/check.py

Exits 1 on any mismatch. Warns (exit 0) on things that are expected but worth
eyeballing: numbering gaps, the alternate twin reports.
"""

import re
import subprocess
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent
AXES = ["fs", "vcs", "secrets", "exfil", "supply", "inject", "cloud", "mcp", "behavior", "evade"]

errors, warnings = [], []


def err(msg):
    errors.append(msg)


def warn(msg):
    warnings.append(msg)


ledger = (ROOT / "LEDGER.md").read_text()

# --- incidents: disk vs headline vs per-axis table -------------------------
incident_files = sorted((ROOT / "incidents").glob("*.md"))
disk_axis = Counter(f.name.split("-", 1)[0] for f in incident_files)

m = re.search(r"\| incident reports in `incidents/` \| (\d+) \|", ledger)
if not m:
    err("headline 'incident reports' row not found")
elif int(m.group(1)) != len(incident_files):
    err(f"headline incident count is {m.group(1)}, disk has {len(incident_files)}")

m = re.search(r"## Incident ledger(.*?)## Scenario ledger", ledger, re.S)
if not m:
    err("incident per-axis table not found")
else:
    table = {}
    for line in m.group(1).splitlines():
        rm = re.fullmatch(r"\| (\w+) \| (\d+) \|", line.strip())
        if rm:
            table[rm.group(1)] = int(rm.group(2))
    for axis in AXES:
        want = disk_axis.get(axis, 0)
        got = int(table.get(axis, -1))
        if got != want:
            err(f"incident table axis {axis}: ledger says {got}, disk has {want}")
    if set(table) - set(AXES):
        warn(f"incident table has unknown axes: {sorted(set(table) - set(AXES))}")

# --- scenarios: disk vs headline vs per-axis table -------------------------
catalogs = {a: (ROOT / "scenarios" / f"{a}.md") for a in AXES}
disk_scen, disk_headings = {}, {}
for axis, path in catalogs.items():
    if not path.exists():
        err(f"missing catalog: {path.name}")
        continue
    heads = re.findall(rf"^### SC {axis}-(\d+) ", path.read_text(), re.M)
    disk_headings[axis] = [int(n) for n in heads]
    disk_scen[axis] = len(heads)

m = re.search(r"\| scenarios in `scenarios/` \| (\d+) \|", ledger)
if not m:
    err("headline 'scenarios' row not found")
elif int(m.group(1)) != sum(disk_scen.values()):
    err(f"headline scenario count is {m.group(1)}, disk has {sum(disk_scen.values())}")

m = re.search(r"## Scenario ledger(.*)", ledger, re.S)
if not m:
    err("scenario per-axis table not found")
else:
    for line in m.group(1).splitlines():
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if len(cells) >= 2 and cells[0] in catalogs and all(c.replace(" ", "").isdigit() for c in cells[1:]):
            if int(cells[1]) != disk_scen[cells[0]]:
                err(f"scenario table axis {cells[0]}: ledger says {cells[1]}, disk has {disk_scen[cells[0]]}")

# --- numbering: no duplicate numbers, no gaps ------------------------------
for axis, nums in disk_headings.items():
    dupes = sorted(n for n, c in Counter(nums).items() if c > 1)
    if dupes:
        err(f"{axis}: duplicate scenario numbers {dupes}")
    expected = list(range(1, len(nums) + 1))
    if nums != expected:
        missing = sorted(set(expected) - set(nums))
        if missing:
            warn(f"{axis}: numbering gaps at {missing} (fine if intended)")

# --- observable field sanity on newer sections -----------------------------
for axis, path in catalogs.items():
    body = path.read_text()
    for sec in re.findall(rf"### SC {axis}-\d+ .*?(?=\n### SC |\Z)", body, re.S):
        obs = re.search(r"- observable: (\S+)", sec)
        if obs and obs.group(1) not in ("exec-input", "file-open", "network-connect"):
            title = sec.splitlines()[0][:60]
            err(f"bad observable value {obs.group(1)!r} in: {title}")

# --- the five known twin reports (two angles, same incident) ---------------
twins = [
    "secrets-tj-actions-ci-log-dump.md", "inject-ci-comment-and-control.md",
    "behavior-cursor-pocketos-railway-volume-delete.md", "mcp-glassworm-watercrawl.md",
    "secrets-shai-hulud-2-trufflehog-sweep.md",
]
if not all((ROOT / "incidents" / t).exists() for t in twins):
    warn("a known twin report is missing from incidents/")

# ---------------------------------------------------------------------------
print(f"incidents on disk: {len(incident_files)}  |  scenarios on disk: {sum(disk_scen.values())}")
for w in warnings:
    print(f"warn: {w}")
if errors:
    for e in errors:
        print(f"FAIL: {e}")
    sys.exit(1)
print("ledger agrees with disk")
