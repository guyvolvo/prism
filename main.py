import os
import sys
import argparse
import json
from datetime import datetime

from colors import PrismColors as PC
from core.scanner import scanner_instance, triage
from core.report import generate_report

from parsers.pdf_parser import analyze_pdf
from parsers.office_parser import analyze_ole
from parsers.pe_parser import analyze_pe


def triage_router(file_path):
    ext = os.path.splitext(file_path)[1].lower()
    if ext == ".pdf":
        return analyze_pdf(file_path)
    elif ext in [".doc", ".docx", ".xls", ".xlsx", ".ppt", ".docm", ".xlsm"]:
        return analyze_ole(file_path)
    elif ext in [".exe", ".dll", ".bin", ".sys", ".com"]:
        return analyze_pe(file_path)
    else:
        return {"Stream_Results": [], "Triggers": [], "Status": "Unknown/Raw"}


def main():
    parser = argparse.ArgumentParser(
        description=f"{PC.HEADER}Prism Triage Framework | Multi-format Malware Analysis{PC.RESET}",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument("target", help="Path to a file or a directory to scan")
    parser.add_argument("-r", "--recursive", action="store_true", help="Recursively scan directories")
    parser.add_argument("-j", "--json", action="store_true", help="Output raw JSON data")
    parser.add_argument("-v", "--verbose", action="store_true", help="Detailed output")
    parser.add_argument("-o", "--log", help="Save results to a JSON file")

    args = parser.parse_args()
    scanner = scanner_instance

    files_to_process = []
    if os.path.isdir(args.target):
        for root, _, files in os.walk(args.target):
            for f in files:
                files_to_process.append(os.path.join(root, f))
            if not args.recursive: break
    elif os.path.isfile(args.target):
        files_to_process.append(args.target)

    print(f"{PC.INFO}[*] Prism engine ready. Triage started on {len(files_to_process)} target(s)...\n")

    all_results = []

    for file_path in files_to_process:
        try:

            parser_data = triage_router(file_path)
            heuristics = parser_data.get("Triggers", [])

            with open(file_path, "rb") as f:
                raw_bytes = f.read()

            triage_data = triage(raw_bytes, scanner, heuristics=heuristics)

            all_triggers = []
            all_triggers.extend(triage_data.get("YARA_Matches", []))
            all_triggers.extend(triage_data.get("Heuristics", []))
            triage_data["Triggers"] = all_triggers

            if file_path.lower().endswith(('.pdf', '.docx', '.xlsx')):
                if triage_data["Status"] == "SUSPICIOUS" and not triage_data["YARA_Matches"]:
                    triage_data["Status"] = "CLEAN (Compressed)"

            final_report = {
                "file_info": {
                    "name": os.path.basename(file_path),
                    "path": file_path,
                    "timestamp": datetime.now().isoformat()
                },
                "structure": parser_data,
                "analysis": triage_data
            }
            if triage_data["YARA_Matches"]:
                triage_data["Trigger_Count"] = len(triage_data["YARA_Matches"]) + len(triage_data.get("Heuristics", []))

            if args.json:
                print(json.dumps(final_report, indent=4))
            else:
                generate_report(final_report)

        except PermissionError:
            print(f"{PC.CRITICAL}[!] Permission Denied: {file_path}")
        except Exception as e:
            print(f"{PC.CRITICAL}[!] Error processing {file_path}: {e}")
            continue

    if args.log:
        with open(args.log, "w") as f:
            json.dump(all_results, f, indent=4)
        print(f"\n{PC.SUCCESS}[+] Scan complete. Log saved to {args.log}")


if __name__ == '__main__':
    main()