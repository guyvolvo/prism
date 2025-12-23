from colors import PrismColors as PC


def generate_report(data):
    # Extract nested data safely
    info = data.get('file_info', {})
    struct = data.get('structure', {})
    analysis = data.get('analysis', {})

    file_name = info.get('name', 'Unknown')
    entropy = analysis.get('Entropy', 0)
    yara_matches = analysis.get('YARA_Matches', [])

    # Header
    print("=" * 70)
    print(f"PRISM TRIAGE REPORT | {info.get('timestamp', 'N/A')}")
    print(f"TARGET: {PC.HEADER}{file_name}{PC.RESET}")
    print("=" * 70)

    # 1. Threat Indicators (YARA + Entropy)
    trigger_count = len(yara_matches) + (1 if entropy > 7.5 else 0)
    print(f"\n[!] THREAT INDICATORS: {PC.CRITICAL if trigger_count > 0 else PC.SUCCESS}{trigger_count}{PC.RESET}")

    if yara_matches:
        for match in yara_matches:
            print(f"    -> {PC.CRITICAL}YARA MATCH: {match}{PC.RESET}")

    if entropy > 7.5:
        print(f"    -> {PC.WARNING}High Entropy ({entropy}): Potential Packing/Encryption{PC.RESET}")
    elif trigger_count == 0:
        print("    -> No immediate triggers found.")

    # 2. Structure & Heuristics Breakdown
    print(f"\n[!] STRUCTURE ANALYSIS:")

    # Handle 'Triggers' list (Suspicious APIs, Strings found by parser)
    if 'Triggers' in struct and struct['Triggers']:
        print(f"    {PC.WARNING}Heuristic Alerts:{PC.RESET}")
        for trigger in struct['Triggers']:
            print(f"      - {trigger}")

    # Handle 'Stream_Results' (PE Sections / PDF Streams)
    if 'Stream_Results' in struct and struct['Stream_Results']:
        print(f"\n    {PC.INFO}Internal Streams/Sections:{PC.RESET}")
        print(f"      {'Name':<15} | {'Entropy':<8} | {'Status'}")
        print(f"      {'-' * 40}")
        for item in struct['Stream_Results']:
            name = item.get('Section_Name', item.get('Name', 'unknown'))
            ent = item.get('Entropy', 0.0)
            status = "Suspicious" if ent > 7.2 else "Normal"

            # Highlight suspicious sections in yellow
            color = PC.WARNING if ent > 7.2 else PC.RESET
            print(f"      {color}{name:<15} | {ent:<8} | {status}{PC.RESET}")

    # 3. Final Verdict
    verdict = analysis.get('Status', 'UNKNOWN')

    # Determine color based on severity
    if "CRITICAL" in verdict:
        v_color = PC.CRITICAL
    elif "SUSPICIOUS" in verdict:
        v_color = PC.WARNING
    else:
        v_color = PC.SUCCESS

    print("\n" + "=" * 70)
    print(f"VERDICT: {v_color}{verdict}{PC.RESET}")
    print("=" * 70 + "\n")