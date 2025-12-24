import os
import sys
import argparse
import json
import hashlib
import mimetypes
from datetime import datetime

from colors import PrismColors as PC
from core.scanner import get_scanner, triage
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


def print_metadata_only(file_path, sha256_hash, md5_hash):
    stats = os.stat(file_path)

    print(f"{PC.HEADER}--- PRISM METADATA: {os.path.basename(file_path)} ---{PC.RESET}")
    print(f"{PC.INFO}File Info:{PC.RESET}")
    print(f"  Path:      {file_path}")
    print(f"  Size:      {stats.st_size} bytes")
    print(f"  MIME Type: {mimetypes.guess_type(file_path)[0] or 'application/octet-stream'}")

    print(f"\n{PC.INFO}Timestamps:{PC.RESET}")
    print(f"  Created:   {datetime.fromtimestamp(stats.st_ctime)}")
    print(f"  Modified:  {datetime.fromtimestamp(stats.st_mtime)}")

    print(f"\n{PC.INFO}Fingerprints:{PC.RESET}")
    print(f"  MD5:       {PC.WARNING}{md5_hash}{PC.RESET}")
    print(f"  SHA256:    {PC.WARNING}{sha256_hash}{PC.RESET}")
    print("-" * 55 + "\n")


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
    parser.add_argument("-m", "--metadata", action="store_true", help="Only show file metadata (skips security scan)")
    parser.add_argument("-s", "--scan", action="store_true", help="Force scan even if metadata flag is used")

    args = parser.parse_args()

    files_to_process = []
    if os.path.isdir(args.target):
        for root, _, files in os.walk(args.target):
            for f in files:
                files_to_process.append(os.path.join(root, f))
            if not args.recursive: break
    elif os.path.isfile(args.target):
        files_to_process.append(args.target)

    mode_text = "Metadata Mode" if (args.metadata and not args.scan) else "Full Triage"
    print(f"{PC.INFO}[*] Prism engine ready. Mode: {mode_text} | Targets: {len(files_to_process)}\n")

    for file_path in files_to_process:
        try:
            with open(file_path, "rb") as f:
                raw_bytes = f.read()

            file_sha256 = hashlib.sha256(raw_bytes).hexdigest()
            file_md5 = hashlib.md5(raw_bytes).hexdigest()

            if args.metadata:
                print_metadata_only(file_path, file_sha256, file_md5)
                if not args.scan:
                    continue

            scanner = get_scanner()
            parser_data = triage_router(file_path)
            heuristics = parser_data.get("Triggers", [])

            triage_data = triage(raw_bytes, scanner, heuristics=heuristics, file_hash=file_sha256)

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
                    "timestamp": datetime.now().isoformat(),
                    "sha256": file_sha256
                },
                "structure": parser_data,
                "analysis": triage_data
            }

            if args.json:
                print(json.dumps(final_report, indent=4))
            else:
                generate_report(final_report)

        except PermissionError:
            print(f"{PC.CRITICAL}[!] Permission Denied: {file_path}")
        except Exception as e:
            print(f"{PC.CRITICAL}[!] Error processing {file_path}: {e}")
            continue


if __name__ == '__main__':
    main()