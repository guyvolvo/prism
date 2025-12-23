import os
import datetime
import string
from colors import PrismColors as PC


def is_signature_legit(preview_bytes):

    if not preview_bytes or len(preview_bytes) < 8:
        return True

    printable_chars = set(string.printable.encode())
    printable_count = sum(1 for byte in preview_bytes if byte in printable_chars)
    printable_ratio = printable_count / len(preview_bytes)

    null_count = preview_bytes.count(b'\x00')
    null_ratio = null_count / len(preview_bytes)

    if printable_ratio < 0.05 and null_ratio < 0.01:
        return False

    return True


def generate_report(data):
    if "error" in data:
        print(f"\n{PC.CRITICAL}[!] ANALYSIS ERROR: {data['error']}")
        return

    filename = os.path.basename(data.get("File", "Unknown"))
    triggers = data.get("Triggers", [])
    results = data.get("Stream_Results", [])

    # Header
    print(f"\n{PC.HEADER}{'=' * 70}")
    print(f"{PC.HEADER}PRISM TRIAGE REPORT | {datetime.datetime.now().strftime('%Y-%m-%d %H:%M')}")
    print(f"{PC.HEADER}TARGET: {filename}")
    print(f"{PC.HEADER}{'=' * 70}")

    print(f"\n{PC.INFO}[!] HEURISTIC TRIGGERS: {len(triggers)}")
    if triggers:
        for t in triggers:
            print(f"    {PC.WARNING}-> DETECTED: {t}")
    else:
        print(f"    {PC.DIM}-> No immediate triggers found.")

    # Structural Analysis
    print(f"\n{PC.INFO}[!] STREAM & SECTION ANALYSIS:")
    critical_risk = False

    for res in results:
        name = res.get("Section_Name") or res.get("Stream_Name") or res.get("Macro_Name") or "Unknown_Object"
        entropy = res.get("Entropy", 0.0)
        preview = res.get("Preview_Bytes", b"")

        status = res.get('Status', 'Scanned')

        if res.get("Requires_Deep_RE"):
            if is_signature_legit(preview):
                color = PC.WARNING
                marker = "[WARN]"
                status = "High Entropy (Likely Resource)"
            else:
                color = PC.CRITICAL
                marker = "[!!!]"
                status = "Critical/Packed (No Valid Structure)"
                critical_risk = True
        else:
            color = PC.SUCCESS
            marker = "[OK ]"

        print(f"    {color}{marker} {name:<18} | Entropy: {entropy:<5} | Status: {status}")

        if res.get("YARA_Matches"):
            print(f"        {PC.CRITICAL}YARA MATCHES: {', '.join(res['YARA_Matches'])}")

    # Final Verdict
    malicious_triggers = [t for t in triggers if "MALFORMED" not in t]

    print(f"\n{PC.HEADER}{'=' * 70}")
    if critical_risk:
        print(f"{PC.CRITICAL}VERDICT: CRITICAL - HIGH ENTROPY & SUSPICIOUS SIGNATURE")
    elif malicious_triggers:  # Only flag if there are real threats (APIs, Macros, etc.)
        print(f"{PC.WARNING}VERDICT: SUSPICIOUS - ACTIVE CONTENT DETECTED")
    elif triggers:  # If only the Malformed Header trigger exists
        print(f"{PC.INFO}VERDICT: INFORMATIONAL - UNUSUAL FILE STRUCTURE")
    else:
        print(f"{PC.SUCCESS}VERDICT: LOW RISK")
    print(f"{PC.HEADER}{'=' * 70}\n")
