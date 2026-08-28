#!/usr/bin/env python3
"""Compares what the supervisor read with what the kernel really did.

Usage:
    compare-toctou.py SUPERVISOR_LOG TARGET_RESULT

The supervisor log holds one line for each notification. The sequence number
sits in the fourth argument of openat, which the kernel ignores but reports.
The target result holds the file that the process really got, from
/proc/self/fd. The join is therefore exact.

The output is one block of plain counters. The test set reads them.
"""

import re
import sys

LINE = re.compile(
    r"^(allow|deny|emulate) pid=(\d+) call=openat arg=(\S*) a3=(\d+)")
SEQ_BASE = 1000000


def letter_of(path):
    """Returns the letter of a name that ends with f_X.txt."""
    if len(path) >= 7 and path.endswith(".txt"):
        return path[-5]
    return "?"


def main():
    if len(sys.argv) != 3:
        print(__doc__)
        return 2

    seen = {}
    with open(sys.argv[1], encoding="utf-8", errors="replace") as handle:
        for line in handle:
            match = LINE.match(line)
            if match is None:
                continue
            seq = int(match.group(4))
            if seq < SEQ_BASE:
                continue
            seen[seq] = (match.group(1), letter_of(match.group(3)))

    real = {}
    with open(sys.argv[2], encoding="utf-8") as handle:
        for line in handle:
            parts = line.split()
            if len(parts) != 3:
                continue
            real[int(parts[0])] = (parts[1], int(parts[2]))

    pairs = 0
    match_count = 0
    mismatch = 0
    detail = {}
    denied = 0
    denied_but_ran = 0
    opened_b = 0
    no_notification = 0

    for seq, (actual, _err) in sorted(real.items()):
        if seq not in seen:
            no_notification += 1
            continue
        verdict, read_letter = seen[seq]
        pairs += 1
        if actual == "b":
            opened_b += 1
        if verdict == "deny":
            denied += 1
            if actual != "E":
                denied_but_ran += 1
            continue
        if actual in ("a", "b"):
            key = "read=%s opened=%s" % (read_letter, actual)
            detail[key] = detail.get(key, 0) + 1
            if read_letter == actual:
                match_count += 1
            else:
                mismatch += 1

    judged = match_count + mismatch
    rate = (100.0 * mismatch / judged) if judged else 0.0

    print("pairs=%d" % pairs)
    print("judged=%d" % judged)
    print("match=%d" % match_count)
    print("mismatch=%d" % mismatch)
    print("mismatch_rate=%.1f" % rate)
    print("denied=%d" % denied)
    print("denied_but_ran=%d" % denied_but_ran)
    print("opened_b_total=%d" % opened_b)
    print("no_notification=%d" % no_notification)
    for key in sorted(detail):
        print("detail %s = %d" % (key, detail[key]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
