#!/usr/bin/env python3
"""Adds the system call name to each line of a histogram file.

The histogram file holds "number count" pairs. The names come from
/usr/include/asm/unistd_64.h, so the mapping is the mapping of this machine
and not a table that was copied from somewhere else.

Usage: annotate-histogram.py HISTOGRAM [NAME ...]

With no NAME the script prints the twenty most frequent calls. With one or
more NAME it prints only those calls, and it prints a count of zero for a name
that is not in the histogram. A count of zero is the interesting result.
"""

import re
import sys

HEADER = "/usr/include/asm/unistd_64.h"


def load_names():
    names = {}
    pattern = re.compile(r"^#define\s+__NR_(\w+)\s+(\d+)")
    try:
        with open(HEADER) as handle:
            for line in handle:
                match = pattern.match(line)
                if match:
                    names[int(match.group(2))] = match.group(1)
    except OSError:
        pass
    return names


def main():
    if len(sys.argv) < 2:
        sys.stderr.write("usage: annotate-histogram.py HISTOGRAM [NAME ...]\n")
        return 2

    names = load_names()
    numbers = {name: number for number, name in names.items()}

    counts = {}
    try:
        with open(sys.argv[1]) as handle:
            for line in handle:
                parts = line.split()
                if len(parts) == 2:
                    counts[int(parts[0])] = int(parts[1])
    except OSError:
        sys.stderr.write(f"cannot read {sys.argv[1]}\n")
        return 1

    wanted = sys.argv[2:]
    if wanted:
        for name in wanted:
            number = numbers.get(name)
            if number is None:
                print(f"{name:<20} unknown on this machine")
                continue
            print(f"{name:<20} number={number:<5} calls={counts.get(number, 0)}")
        return 0

    ordered = sorted(counts.items(), key=lambda item: -item[1])[:20]
    total = sum(counts.values())
    print(f"total system calls: {total}")
    for number, count in ordered:
        print(f"{names.get(number, '?'):<20} number={number:<5} calls={count}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
