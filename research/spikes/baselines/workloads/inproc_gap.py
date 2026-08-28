#!/usr/bin/env python3
"""The in-process gap workload of the exec-only ptrace monitor.

One process. No new program. The script performs three normal developer
actions and then writes a marker file that describes what it did:

  1. it removes a directory tree with shutil.rmtree;
  2. it removes one file with os.unlink;
  3. it opens a TCP connection to a listener that it starts itself, and it
     sends bytes over that connection.

Nothing here is destructive outside the scratch directory that the script
creates. The listener is on 127.0.0.1 and the script owns both ends.

The point of the workload: a monitor that intercepts PTRACE_EVENT_EXEC sees
the exec of the interpreter and nothing else, because no action after that
exec starts a new program.

Usage: inproc_gap.py SCRATCH_DIR MARKER_PATH
"""

import json
import os
import shutil
import socket
import sys
import threading


def start_listener():
    """Starts a TCP listener on the loopback interface and returns its port."""
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    port = server.getsockname()[1]
    received = {}

    def accept_once():
        connection, _ = server.accept()
        received["bytes"] = connection.recv(64)
        connection.close()
        server.close()

    thread = threading.Thread(target=accept_once, daemon=True)
    thread.start()
    return port, thread, received


def main():
    if len(sys.argv) < 3:
        sys.stderr.write("usage: inproc_gap.py SCRATCH_DIR MARKER_PATH\n")
        return 2

    scratch = os.path.abspath(sys.argv[1])
    marker_path = os.path.abspath(sys.argv[2])

    tree = os.path.join(scratch, "tree-to-remove")
    shutil.rmtree(tree, ignore_errors=True)
    os.makedirs(os.path.join(tree, "nested", "deeper"), exist_ok=True)
    for index in range(5):
        with open(os.path.join(tree, "nested", f"file-{index}.txt"), "w") as f:
            f.write("data\n")
    with open(os.path.join(tree, "nested", "deeper", "leaf.txt"), "w") as f:
        f.write("leaf\n")

    single = os.path.join(scratch, "single-file-to-unlink.txt")
    with open(single, "w") as f:
        f.write("delete me\n")

    files_before = sum(len(names) for _, _, names in os.walk(tree))

    # Action 1 and 2: remove a whole tree, then remove one file.
    shutil.rmtree(tree)
    os.unlink(single)

    # Action 3: open a TCP connection and send bytes over it.
    port, thread, received = start_listener()
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect(("127.0.0.1", port))
    client.sendall(b"payload-from-inside-one-process")
    client.close()
    thread.join(timeout=5.0)

    result = {
        "pid": os.getpid(),
        "executable": sys.executable,
        "tree_path": tree,
        "files_removed": files_before,
        "tree_exists_after": os.path.exists(tree),
        "single_file_path": single,
        "single_file_exists_after": os.path.exists(single),
        "tcp_port": port,
        "tcp_bytes_received": (received.get("bytes") or b"").decode(
            "utf-8", "replace"
        ),
        "new_programs_started": 0,
    }
    with open(marker_path, "w") as f:
        json.dump(result, f, indent=2)
        f.write("\n")
    print(json.dumps(result))
    return 0


if __name__ == "__main__":
    sys.exit(main())
