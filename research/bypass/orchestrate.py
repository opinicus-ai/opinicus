#!/usr/bin/env python3
"""Orchestrates the bypass matrix of [af-1].

Three passes:
  baseline  — every technique runs with no firewall, proving its effects work
  builtin   — the product posture: builtin rules, --approve deny, three filter modes
  probe     — the catch-all probe policy, --no-builtin-policies, three filter modes

One run per cell. Every run gets a fresh scratch directory, its own trace and
a machine-checkable effect verification (marker files, a local listener).
classify.py turns the raw run directory into per-action verdicts.
"""

import json
import os
import shutil
import signal
import socket
import subprocess
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
FW = REPO / "target" / "release" / "agent-firewall"
BIN = Path(__file__).resolve().parent / "bin"
SCRATCH_ROOT = REPO / "tmp" / "bypass"
RESULTS = Path(__file__).resolve().parent / "results"
POLICY = Path(__file__).resolve().parent / "policies" / "catchall.yaml"
SENSOR = REPO / "research" / "spikes" / "inprocess" / "libafsensor.so"

MODES = ["write-only", "all-opens", "off"]
PORT = 45777


class Listener:
    def __init__(self, path):
        self.path = path
        self.proc = None

    def __enter__(self):
        self.proc = subprocess.Popen(
            [
                sys.executable,
                "-c",
                "import socket,sys\n"
                "s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)\n"
                "s.bind(('127.0.0.1',%d)); s.listen(8)\n"
                "while True:\n"
                "    c,_=s.accept()\n"
                "    try:\n"
                "        data=c.recv(4096)\n"
                "        open(sys.argv[1],'a').write(data.decode(errors='replace'))\n"
                "    finally:\n"
                "        c.close()\n" % PORT,
                str(self.path),
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        for _ in range(50):
            try:
                s = socket.socket()
                s.connect(("127.0.0.1", PORT))
                s.close()
                return self
            except OSError:
                time.sleep(0.05)
        raise RuntimeError("listener did not come up")

    def __exit__(self, *exc):
        if self.proc:
            self.proc.send_signal(signal.SIGKILL)
            self.proc.wait()


def fresh(name):
    d = SCRATCH_ROOT / name
    if d.exists():
        shutil.rmtree(d)
    d.mkdir(parents=True)
    return d


def technique_argv(name, scratch):
    """Returns (argv, needs_listener, payload_setup)."""
    marker = str(scratch / "marker.txt")
    if name == "rawsys":
        return [str(BIN / name), str(PORT), marker], True, None
    if name == "static-file-net":
        return [str(BIN / name), str(PORT), marker], True, None
    if name == "escape-setsid":
        return [str(BIN / name), marker], False, None
    if name == "outlive":
        return [str(BIN / name), marker], False, None
    if name == "uring":
        return [str(BIN / name), marker], False, None
    if name == "delete-rename":
        return [str(BIN / name), str(scratch), marker], False, None
    if name == "cred-read":
        cred = scratch / ".aws"
        cred.mkdir(exist_ok=True)
        (cred / "credentials").write_text("[default]\naws_access_key_id = PROBE\n")
        return [str(BIN / name), str(cred / "credentials"), marker], False, None
    if name == "kill-monitor":
        return [str(BIN / name), marker], False, None
    if name == "fileclient":
        payload = scratch / "drop.sql"
        payload.write_text("SELECT 1;\nDROP DATABASE customer_prod;\n")
        shutil.copy(BIN / "fileclient", scratch / "psql")
        return (
            [
                "sh",
                "-c",
                f"'{BIN}/fileclient' -f '{payload}' '{scratch}/marker-a.txt'; "
                f"'{scratch}/psql' -f '{payload}' '{scratch}/marker-b.txt'",
            ],
            False,
            None,
        )
    if name == "payload-assembly":
        return [str(BIN / name), str(scratch), marker], False, None
    if name == "pydrop":
        return [str(BIN / name), marker], False, None
    raise KeyError(name)


def run_cell(pass_name, mode, name, runs_dir):
    scratch = fresh(f"{pass_name}-{mode}-{name}")
    argv, needs_listener, _ = technique_argv(name, scratch)
    trace = scratch / "trace.jsonl"
    listener = Listener(scratch / "listen.log") if needs_listener else None

    env = None
    if pass_name == "preload":
        # The [af-2] pass: the product posture plus the in-process sensor.
        # The shim rides the environment into the launcher and the whole
        # monitored tree; it reports, it never holds.
        env = dict(os.environ)
        env.update(
            LD_PRELOAD=str(SENSOR),
            AF_SENSOR_TRACE=str(scratch / "sensor.jsonl"),
            AF_SENSOR_REG=str(scratch / "sensor.reg"),
            AF_SENSOR_SESSION=f"af2-{mode}-{name}",
        )

    if pass_name == "baseline":
        cmd = list(argv)
    else:
        cmd = [str(FW), "run", "--retention", "all", "--approve", "deny"]
        if pass_name == "probe":
            cmd += ["--no-builtin-policies", "--policy", str(POLICY)]
        cmd += ["--syscall-filter", mode, "--trace", str(trace)]
        cmd += ["--", *argv]

    started = time.time()
    listener_ctx = listener.__enter__() if listener else None
    try:
        timeout = 25 if name == "outlive" else 12
        proc = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=timeout,
            cwd=scratch,
            env=env,
        )
        fw_exit = proc.returncode
        fw_out = proc.stdout.decode(errors="replace")
        timed_out = False
    except subprocess.TimeoutExpired:
        fw_exit = None
        fw_out = ""
        timed_out = True
    finally:
        if listener:
            listener.__exit__()
    elapsed = round(time.time() - started, 2)

    record = {
        "pass": pass_name,
        "mode": mode,
        "technique": name,
        "fw_exit": fw_exit,
        "timed_out": timed_out,
        "elapsed_s": elapsed,
        "scratch": str(scratch),
    }
    (scratch / "fw.out").write_text(fw_out)
    out = RESULTS / f"{pass_name}-{mode}-{name}.json"
    out.write_text(json.dumps(record, indent=2))
    print(f"{pass_name:9s} {mode:10s} {name:18s} fw_exit={fw_exit} elapsed={elapsed}s")
    return record


def main():
    if os.geteuid() == 0:
        sys.exit("the harness runs as a normal user")
    if not FW.exists():
        sys.exit(f"missing {FW}; run cargo build --release")
    preload = "--preload" in sys.argv
    if preload and not SENSOR.exists():
        sys.exit(f"missing {SENSOR}; run research/spikes/inprocess/build.sh")
    RESULTS.mkdir(exist_ok=True)
    s = socket.socket()
    try:
        s.bind(("127.0.0.1", PORT))
        s.close()
    except OSError as e:
        sys.exit(f"port {PORT} in use: {e}")

    techniques = [
        "static-file-net",
        "rawsys",
        "escape-setsid",
        "outlive",
        "uring",
        "delete-rename",
        "cred-read",
        "fileclient",
        "payload-assembly",
        "pydrop",
        "kill-monitor",
    ]
    passes = [("baseline", ["none"])]
    passes += [("builtin", MODES), ("probe", MODES)]
    if preload:
        passes += [("preload", MODES)]
    for pass_name, modes in passes:
        for mode in modes:
            for name in techniques:
                run_cell(pass_name, mode, name, RESULTS)
    print("done; now run: python3 research/bypass/classify.py")


if __name__ == "__main__":
    main()
