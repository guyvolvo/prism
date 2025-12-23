from colors import PrismColors as PC


def generate_report(data):
    info = data.get('file_info', {})
    struct = data.get('structure', {})
    analysis = data.get('analysis', {})

    file_name = info.get('name', 'Unknown')
    entropy = analysis.get('Entropy', 0)
    yara_matches = analysis.get('YARA_Matches', [])
    heuristics = analysis.get('Heuristics', [])

    print("=" * 70)
    print(f"PRISM TRIAGE REPORT | {info.get('timestamp', 'N/A')}")
    print(f"TARGET: {PC.HEADER}{file_name}{PC.RESET}")
    print("=" * 70)

    trigger_count = len(yara_matches) + len(heuristics) + (1 if entropy > 7.5 else 0)

    print(f"\n[!] THREAT INDICATORS: {PC.CRITICAL if trigger_count > 0 else PC.SUCCESS}{trigger_count}{PC.RESET}")

    if yara_matches:
        for match in yara_matches:
            print(f"    -> {PC.CRITICAL}YARA MATCH: {match}{PC.RESET}")

    if heuristics:
        for h in heuristics:
            print(f"    -> {PC.WARNING}HEURISTIC: {h}{PC.RESET}")

    if entropy > 7.5:
        print(f"    -> {PC.WARNING}High Entropy ({entropy}): Potential Packing/Encryption{PC.RESET}")

    if trigger_count == 0:
        print("    -> No immediate triggers found.")

    print(f"\n[!] STRUCTURE ANALYSIS:")

    all_struct_alerts = struct.get('Triggers', [])
    if all_struct_alerts:
        print(f"    {PC.WARNING}Heuristic Alerts:{PC.RESET}")
        for trigger in all_struct_alerts:
            print(f"      - {trigger}")
    elif not heuristics and not yara_matches:
        print("    -> Analysis complete (No structural anomalies).")

    if 'Stream_Results' in struct and struct['Stream_Results']:
        print(f"\n    {PC.INFO}Internal Streams/Sections:{PC.RESET}")
        print(f"      {'Name':<15} | {'Entropy':<8} | {'Status'}")
        print(f"      {'-' * 40}")
        for item in struct['Stream_Results']:
            name = item.get('Section_Name', item.get('Name', 'unknown'))
            ent = item.get('Entropy', 0.0)
            status = "Suspicious" if ent > 7.2 else "Normal"
            color = PC.WARNING if ent > 7.2 else PC.RESET
            print(f"      {color}{name:<15} | {ent:<8} | {status}{PC.RESET}")

    verdict = analysis.get('Status', 'UNKNOWN')
    if "CRITICAL" in verdict:
        v_color = PC.CRITICAL
    elif "SUSPICIOUS" in verdict:
        v_color = PC.WARNING
    else:
        v_color = PC.SUCCESS

    print("\n" + "=" * 70)
    print(f"VERDICT: {v_color}{verdict}{PC.RESET}")
    print("=" * 70 + "\n")