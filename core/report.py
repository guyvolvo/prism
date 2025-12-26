from colors import PrismColors as PC


def generate_report(data):
    info = data.get('file_info', {})
    struct = data.get('structure', {})
    analysis = data.get('analysis', {})

    file_name = info.get('name', 'Unknown')
    entropy = analysis.get('Entropy', 0)
    yara_matches = analysis.get('YARA_Matches', []) or analysis.get('Yara_Matches', [])
    heuristics = analysis.get('Heuristics', [])
    reputation = analysis.get('Reputation')
    # check if MalwareBazaar found something
    if not reputation and analysis.get('MalwareBazaar_Found'):
        # Create minimal reputation dict
        reputation = {
            'signature': 'Known Malware (MalwareBazaar)',
            'tags': []
        }

    print("=" * 70)
    print(f"PRISM TRIAGE REPORT | {info.get('timestamp', 'N/A')}")
    print(f"TARGET: {PC.HEADER}{file_name}{PC.RESET}")
    print("=" * 70)

    all_struct_alerts = struct.get('Triggers', [])
    trigger_count = len(yara_matches) + len(heuristics) + len(all_struct_alerts) + (1 if entropy > 7.5 else 0)

    print(f"\n[!] THREAT INDICATORS: {PC.CRITICAL if trigger_count > 0 else PC.SUCCESS}{trigger_count}{PC.RESET}")

    if yara_matches:
        for match in yara_matches:
            print(f"    -> {PC.CRITICAL}YARA MATCH: {match}{PC.RESET}")

    if heuristics:
        for h in heuristics:
            h_color = PC.CRITICAL if "REPUTATION" in h else PC.WARNING
            print(f"    -> {h_color}HEURISTIC: {h}{PC.RESET}")

    if entropy > 7.5:
        print(f"    -> {PC.WARNING}High Entropy ({entropy}): Potential Packing/Encryption{PC.RESET}")
    confidence = analysis.get('Confidence_Metrics', {})
    if confidence:
        intent = confidence.get('Intent_Score', 0)
        uncertainty = confidence.get('Uncertainty_Score', 0)
        fp_risk = analysis.get('FP_Risk', 'UNKNOWN')

        print(f"\n[+] CONFIDENCE ANALYSIS:")
        print(f"    Intent Score:      {intent}/10")
        print(f"    Uncertainty Score: {uncertainty}/10")
        print(f"    False Positive Risk: {PC.WARNING if fp_risk != 'LOW' else PC.SUCCESS}{fp_risk}{PC.RESET}")

    print(f"\n[+] MALWAREBAZAAR: ")
    if reputation:
        print(f"    Status:  {PC.CRITICAL}MATCH FOUND{PC.RESET}")
        print(f"    Sign:    {PC.WARNING}{reputation.get('signature', 'Unknown Signature')}{PC.RESET}")
        print(f"    Tags:    {', '.join(reputation.get('tags', []))}")
        print(f"    Link:    {PC.INFO}https://bazaar.abuse.ch/sample/{reputation.get('sha256_hash')}/{PC.RESET}")
    else:
        print(f"    Status:  {PC.SUCCESS}Not Found in Database{PC.RESET}")

    whitelist_info = analysis.get('Whitelist_Info')
    if whitelist_info:
        print(f"\n[+] WHITELIST STATUS:")
        print(f"    {PC.SUCCESS}[+] TRUSTED FILE (Known Legitimate Software){PC.RESET}")
        print(f"    Source:       {whitelist_info.get('Source', 'Unknown')}")
        print(f"    Identified:   {PC.INFO}{whitelist_info.get('Identified_As', 'System File')}{PC.RESET}")
        print(f"    Hash Match:   {whitelist_info.get('Hash', 'N/A')[:16]}...")

    if trigger_count == 0 and not reputation:
        print("    -> No immediate triggers found.")

    print(f"\n[!] STRUCTURE ANALYSIS:")
    if all_struct_alerts:
        print(f"    {PC.WARNING}Heuristic Alerts:{PC.RESET}")
        for trigger in all_struct_alerts:
            print(f"      - {trigger}")
    elif not heuristics and not yara_matches:
        print("    -> Analysis complete (No structural anomalies).")

    has_high_entropy_stream = False
    if 'Stream_Results' in struct and struct['Stream_Results']:
        print(f"\n    {PC.INFO}Internal Streams/Sections Analysis:{PC.RESET}")
        print(f"    {'-' * 45}")

        for item in struct['Stream_Results']:
            name = item.get('Section_Name', item.get('Name', 'unknown'))
            ent = item.get('Entropy', 0.0)

            if ent > 7.5:
                has_high_entropy_stream = True
                status = "CRITICAL / ENCRYPTED"
                color = PC.CRITICAL
            elif ent > 7.2:
                has_high_entropy_stream = True
                status = "SUSPICIOUS / PACKED"
                color = PC.WARNING
            else:
                status = "NORMAL"
                color = PC.SUCCESS

            print(f"    {PC.HEADER}>> Section:{PC.RESET}  {name}")
            print(f"       {PC.INFO}Entropy:{PC.RESET}  {ent}")
            print(f"       {PC.INFO}Status:{PC.RESET}   {color}{status}{PC.RESET}")
            print(f"    {'-' * 30}")

    verdict = analysis.get('Status', 'CLEAN')
    is_malformed = any("Corrupt" in str(t) or "Malformed" in str(t) for t in all_struct_alerts)

    # Check for whitelist first
    whitelist_info = analysis.get('Whitelist_Info')
    if whitelist_info:
        verdict = f"TRUSTED - {whitelist_info.get('Identified_As', 'Known Legitimate Software')}"
        v_color = PC.SUCCESS
    elif reputation:
        verdict = "MALICIOUS (Known Reputation)"
        v_color = PC.CRITICAL
    elif is_malformed or has_high_entropy_stream:
        if verdict == "CRITICAL":
            verdict = "MALICIOUS (Structural Critical)"
            v_color = PC.CRITICAL
        elif verdict == "CLEAN":
            verdict = "SUSPICIOUS (Structural Anomaly)"
            v_color = PC.WARNING
        else:
            v_color = PC.WARNING if "SUSPICIOUS" in verdict else PC.CRITICAL
    else:
        if "CRITICAL" in verdict or "MALICIOUS" in verdict:
            v_color = PC.CRITICAL
        elif "SUSPICIOUS" in verdict:
            v_color = PC.WARNING
        else:
            v_color = PC.SUCCESS

    print("\n" + "=" * 70)
    print(f"VERDICT: {v_color}{verdict}{PC.RESET}")
    print("=" * 70 + "\n")
