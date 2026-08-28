#!/usr/bin/env python3
"""A TCP listener that accepts exactly one connection.

It writes the port number to PORT_FILE as soon as the socket is bound, so that
a shell script can wait for the file and then connect. It writes the bytes
that it received to RESULT_FILE and then it ends.

Usage: one_shot_listener.py PORT_FILE RESULT_FILE [TIMEOUT_SECONDS]
"""

import os
import socket
import sys


def main():
    if len(sys.argv) < 3:
        sys.stderr.write(
            "usage: one_shot_listener.py PORT_FILE RESULT_FILE [TIMEOUT]\n"
        )
        return 2

    port_file = sys.argv[1]
    result_file = sys.argv[2]
    timeout = float(sys.argv[3]) if len(sys.argv) > 3 else 10.0

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    server.settimeout(timeout)
    port = server.getsockname()[1]

    temporary = port_file + ".partial"
    with open(temporary, "w") as handle:
        handle.write(str(port))
    os.rename(temporary, port_file)

    try:
        connection, address = server.accept()
    except socket.timeout:
        with open(result_file, "w") as handle:
            handle.write("no connection arrived\n")
        return 1

    data = connection.recv(256)
    connection.close()
    server.close()
    with open(result_file, "w") as handle:
        handle.write(f"accepted from {address[0]}:{address[1]}\n")
        handle.write(data.decode("utf-8", "replace") + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
