import os
import math
import pefile

# -----------------------------
# Helpers
# -----------------------------

def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq = {}
    for b in data:
        freq[b] = freq.get(b, 0) + 1
    entropy = 0.0
    length = len(data)
    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


def read_file_safe(path, max_bytes=2_000_000):
    try:
        with open(path, "rb") as f:
            return f.read(max_bytes)
    except Exception:
        return b""


# -----------------------------
# Indicators
# -----------------------------

SUSPICIOUS_STRINGS = [
    b"http://", b"https://",
    b"/gate.php", b"/panel",
    b"cmd.exe", b"powershell",
    b"Invoke-WebRequest",
    b"base64", b"eval(",
    b"LoadLibrary", b"VirtualAlloc",
    b"CreateRemoteThread"
]

SUSPICIOUS_PE_IMPORTS = {
    "VirtualAlloc",
    "WriteProcessMemory",
    "CreateRemoteThread",
    "WinExec",
    "ShellExecute"
}

SUSPICIOUS_SECTIONS = {
    ".upx", ".packed", ".crypt", ".stub"
}


# -----------------------------
# Main Check
# -----------------------------

def analyze_file(path):
    findings = []
    score = 0

    data = read_file_safe(path)
    size = len(data)

    # Entropy check
    entropy = shannon_entropy(data)
    if entropy > 7.2 and size > 10_000:
        score += 2
        findings.append(f"High entropy ({entropy:.2f})")

    # String indicators
    for s in SUSPICIOUS_STRINGS:
        if s in data:
            score += 1
            findings.append(f"Suspicious string: {s.decode(errors='ignore')}")

    # PE-specific checks
    if data.startswith(b"MZ"):
        try:
            pe = pefile.PE(data=data, fast_load=True)
            pe.parse_data_directories()

            # Imports
            if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    for imp in entry.imports:
                        if imp.name and imp.name.decode(errors="ignore") in SUSPICIOUS_PE_IMPORTS:
                            score += 2
                            findings.append(f"Suspicious import: {imp.name.decode()}")

            # Sections
            for sec in pe.sections:
                name = sec.Name.decode(errors="ignore").strip("\x00").lower()
                if name in SUSPICIOUS_SECTIONS:
                    score += 2
                    findings.append(f"Suspicious section: {name}")

        except Exception:
            score += 1
            findings.append("Malformed or obfuscated PE")

    # Script heuristics
    lower = data.lower()
    if b"#!/usr/bin/env python" in lower or b"import os" in lower:
        if b"exec(" in lower or b"marshal" in lower:
            score += 2
            findings.append("Suspicious Python execution logic")

    if b"powershell" in lower and b"-enc" in lower:
        score += 2
        findings.append("Encoded PowerShell")

    return {
        "file": os.path.basename(path),
        "size": size,
        "entropy": round(entropy, 2),
        "score": score,
        "findings": findings
    }


def analyze_directory(unpacked_dir):
    results = []
    for root, _, files in os.walk(unpacked_dir):
        for name in files:
            full_path = os.path.join(root, name)
            results.append(analyze_file(full_path))
    return results


# -----------------------------
# Example usage
# -----------------------------

if __name__ == "__main__":
    report = analyze_directory("sample_unpacked")

    for r in report:
        print("=" * 60)
        print(f"FILE: {r['file']}")
        print(f"Score: {r['score']} | Entropy: {r['entropy']}")
        for f in r["findings"]:
            print(f" - {f}")
