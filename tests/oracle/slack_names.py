"""Writes deleted-in-slack.txt: which of the files deleted from the written
volume's `docs` folder (report_050..069 and report_200..219) still have
their name in the slack of the folder's INDX blocks, found with Python
alone, independently of this crate: each block's update sequence fixups
undone, then the UTF-16 names searched for past the node's used size.

Run: python3 -I tests/oracle/slack_names.py tests/fixtures/written/docs_I30.bin > tests/oracle/deleted-in-slack.txt
"""

import re
import struct
import sys

data = open(sys.argv[1], "rb").read()
deleted = {f"report_{i:03d}.txt" for i in list(range(50, 70)) + list(range(200, 220))}
found = set()
for start in range(0, len(data), 4096):
    block = bytearray(data[start:start + 4096])
    if block[:4] != b"INDX":
        continue
    array, count = struct.unpack_from("<HH", block, 4)
    for sector in range(1, count):
        saved = block[array + 2 * sector:array + 2 * sector + 2]
        block[sector * 512 - 2:sector * 512] = saved
    used = struct.unpack_from("<I", block, 0x1C)[0]
    slack = bytes(block[0x18 + used:])
    for match in re.finditer(rb"r\x00e\x00p\x00o\x00r\x00t\x00_\x00(?:\d\x00){3}\.\x00t\x00x\x00t\x00", slack):
        name = match.group(0).decode("utf-16-le")
        if name in deleted:
            found.add(name)
for name in sorted(found):
    print(name)
