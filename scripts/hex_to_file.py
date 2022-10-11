#!/usr/bin/env python3
# Helper script for writing bytes (as an ascii string) to a file
# Useful for only saving certain parts of a Wireshark packet
import sys

if len(sys.argv) != 3:
    print(f"USAGE: {sys.argv[0]} BYTES FILE")
    exit(1)

bytes_stream = sys.argv[1]
out_file = sys.argv[2]

with open(out_file, 'wb') as fd:
    i = 0
    while i < len(bytes_stream):
        s = bytes_stream[i]
        i += 1

        if i < len(bytes_stream):
            s += bytes_stream[i]
            i += 1

        fd.write(int(s, 16).to_bytes(1, byteorder="big"))
    fd.flush()