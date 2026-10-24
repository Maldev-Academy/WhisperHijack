#!/usr/bin/env python3
"""
Generate CRC32B hashes from command-line strings, formatted as aligned
#define CRC32B_* lines ready to drop into Common.h.

Usage:
    <script> string1 string2 ...        (case-sensitive, default)
    <script> -i string1 string2 ...     (case-insensitive, ignore case)

Algorithm: standard CRC-32/ISO-HDLC
    polynomial  : 0xEDB88320  (reversed)
    initial     : 0xFFFFFFFF
    final XOR   : 0xFFFFFFFF  (equivalent to `return ~uHash` in C)
"""

import sys
import os
import re

INITIAL_HASH   = 0xFFFFFFFF
CRC_POLYNOMIAL = 0xEDB88320
MASK32         = 0xFFFFFFFF


def crc32b(data: bytes, fold_case: bool) -> int:
    """Core Crc32b. If fold_case, uppercase ASCII is folded to lowercase
    before mixing (matches HashIStringCrc32bA in ApiStringHashing.c)."""
    h = INITIAL_HASH
    for b in data:
        if fold_case and 0x41 <= b <= 0x5A:   # 'A'..'Z'
            b += 0x20
        h ^= b
        for _ in range(8):
            h = ((h >> 1) ^ (CRC_POLYNOMIAL & (0 - (h & 1)))) & MASK32
    return (~h) & MASK32


def to_token(s: str) -> str:
    """Convert an input string into a #define-safe token: strip anything
    that isn't alphanumeric and uppercase the rest. ntdll.dll -> NTDLLDLL."""
    return re.sub(r'[^A-Za-z0-9]', '', s).upper()


def usage() -> None:
    name = os.path.basename(sys.argv[0]) if sys.argv and sys.argv[0] else "script.py"
    print(f"Usage: {name} [-i] string1 string2 ...", file=sys.stderr)
    print(f"  -i   case-insensitive hashing (default is case-sensitive)", file=sys.stderr)


def main() -> int:
    args = sys.argv[1:]

    case_insensitive = False
    if args and args[0] == "-i":
        case_insensitive = True
        args = args[1:]

    if not args:
        usage()
        return 1

    tokens = [to_token(s) for s in args]
    width  = max(len(t) for t in tokens)

    for s, t in zip(args, tokens):
        val = crc32b(s.encode("latin-1"), fold_case=case_insensitive)
        print(f"#define CRC32B_{t:<{width}}  0x{val:08X}")

    return 0


if __name__ == "__main__":
    sys.exit(main())