#!/usr/bin/env python3
"""
Static Malware Analysis – Self-Unpacking Test Harness
SAFE: no execution, no persistence, no networking
"""

import os
import base64
import random

OUTPUT_DIR = "static_test_samples"


def write_file(name: str, data: bytes):
    path = os.path.join(OUTPUT_DIR, name)
    with open(path, "wb") as f:
        f.write(data)
    print(f"[+] Wrote {name} ({len(data)} bytes)")


def generate_entropy_blob(size=4096):
    return os.urandom(size)


def fake_pe_header():
    """
    Minimal fake PE-like structure to test header parsing
    NOT a valid executable
    """
    data = bytearray(512)
    data[0:2] = b"MZ"
    data[0x3C:0x40] = (0x80).to_bytes(4, "little")
    data[0x80:0x84] = b"PE\x00\x00"
    data[0x84:0x98] = b"\x00" * 20
    return bytes(data)


def api_string_mismatch():
    text = """
LoadLibraryA
GetProcAddress
Sleep
MessageBoxA

--- suspicious strings ---
VirtualAlloc
WriteProcessMemory
CreateRemoteThread
NtQueryInformationProcess
"""
    return text.encode()


def packed_like_data():
    """
    Looks packed, but is just compressed random data
    """
    blob = os.urandom(2048)
    return base64.b64encode(blob)


def polyglot_like():
    """
    ZIP magic + PE magic in one file (not functional)
    """
    data = bytearray()
    data += b"PK\x03\x04"  # ZIP header
    data += os.urandom(60)
    data += b"MZ"
    data += os.urandom(200)
    data += b"PE\x00\x00"
    return bytes(data)


def noise_strings():
    strings = []
    for _ in range(500):
        s = "".join(random.choice("abcdefghijklmnopqrstuvwxyz") for _ in range(16))
        strings.append(s)
    return "\n".join(strings).encode()


def main():
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    write_file("high_entropy_blob.bin", generate_entropy_blob())
    write_file("fake_pe_header.bin", fake_pe_header())
    write_file("api_strings.txt", api_string_mismatch())
    write_file("packed_like_data.bin", packed_like_data())
    write_file("polyglot_like.bin", polyglot_like())
    write_file("noise_strings.txt", noise_strings())

    print("\n[✓] Static analysis test samples generated safely.")


if __name__ == "__main__":
    main()
