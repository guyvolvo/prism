import os
import datetime
from colors import PrismColors as PC


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

    # Heuristics (Behaviors/Intent)
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

        # Entropy logic
        if res.get("Requires_Deep_RE"):
            color = PC.CRITICAL
            marker = "[!!!]"
            critical_risk = True
        else:
            color = PC.SUCCESS
            marker = "[OK ]"

        print(f"    {color}{marker} {name:<18} | Entropy: {entropy:<5} | Status: {res.get('Status', 'Scanned')}")

        if res.get("YARA_Matches"):
            print(f"        {PC.CRITICAL}YARA MATCHES: {', '.join(res['YARA_Matches'])}")

    # Final Verdict
    print(f"\n{PC.HEADER}{'=' * 70}")
    if critical_risk:
        print(f"{PC.CRITICAL}VERDICT: CRITICAL - HIGH ENTROPY DETECTED (Likely Packed)")
        print(f"{PC.DIM}ACTION: Manual de-obfuscation or Dynamic Analysis required.")
    elif triggers:
        print(f"{PC.WARNING}VERDICT: SUSPICIOUS - ACTIVE CONTENT DETECTED")
        print(f"{PC.DIM}ACTION: Review script streams for malicious intent.")
    else:
        print(f"{PC.SUCCESS}VERDICT: LOW RISK")
    print(f"{PC.HEADER}{'=' * 70}\n")