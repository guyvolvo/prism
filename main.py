import os
import sys

current_dir = os.path.dirname(os.path.abspath(__file__))
vendor_path = os.path.join(current_dir, 'vendor')

if os.path.exists(vendor_path) and vendor_path not in sys.path:
    sys.path.insert(0, vendor_path)

import argparse
import json
import hashlib
import mimetypes
from datetime import datetime

MAX_FILE_SIZE = 100 * 1024 * 1024

try:
    from dotenv import load_dotenv, find_dotenv, set_key
    load_dotenv(find_dotenv())
except ImportError:
    pass

from colors import PrismColors as PC
from core.scanner import get_scanner, triage
from core.report import generate_report

from parsers.pdf_parser import analyze_pdf
from parsers.office_parser import analyze_ole
from parsers.pe_parser import analyze_pe


def resolve_api_key(args_api):
    env_path = find_dotenv()
    if not env_path:
        env_path = os.path.join(current_dir, '.env')
    if isinstance(args_api, str):
        clean_key = args_api.strip("'").strip('"')
        print(f"{PC.INFO}[+] API Key provided via command line.")
        print(f"[*] Saving/Updating API Key in {env_path} ...{PC.RESET}")
        try:
            set_key(env_path, "BAZAAR_API_KEY", clean_key)
            os.environ["BAZAAR_API_KEY"] = clean_key
            return clean_key
        except Exception as e:
            print(f"{PC.WARNING}[!] Error saving key to .env: {e}{PC.RESET}")
            return clean_key
    raw_key = os.getenv("BAZAAR_API_KEY")
    return raw_key.strip("'").strip('"') if raw_key else None

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
    print(f"\n{PC.INFO}Fingerprints:{PC.RESET}")
    print(f"  MD5:       {PC.WARNING}{md5_hash}{PC.RESET}")
    print(f"  SHA256:    {PC.WARNING}{sha256_hash}{PC.RESET}")
    print("-" * 55 + "\n")

def main():
    parser = argparse.ArgumentParser(
        description=f"{PC.HEADER}Prism Triage Framework | Multi-format Malware Analysis{PC.RESET}",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument("target", nargs='?', help="Path to a file or a directory to scan")
    parser.add_argument("-r", "--recursive", action="store_true", help="Recursively scan directories")
    parser.add_argument("-j", "--json", action="store_true", help="Output raw JSON data")
    parser.add_argument("-o", "--log", help="Save results to a JSON file")
    parser.add_argument("-m", "--metadata", action="store_true", help="Only show file metadata")
    parser.add_argument("-s", "--scan", action="store_true", help="Force scan with metadata")
    parser.add_argument("--large", action="store_true", help="Bypass 100MB safety limit")
    parser.add_argument("--api", nargs='?', const=True, help="Provide/Save API Key")
    args = parser.parse_args()

    api_key = resolve_api_key(args.api)

    if args.api is not None and not args.target:
        if api_key:
            if isinstance(args.api, str):
                print(f"{PC.SUCCESS}[+] API Configuration updated and saved.{PC.RESET}")
            else:
                print(f"{PC.INFO}[*] Current stored API Key: {api_key}{PC.RESET}")
        else:
            print(f"{PC.WARNING}[!] No API Key found. Run with --api <key> to save one.{PC.RESET}")
        return

    if not args.target:
        print(f"{PC.CRITICAL}[!] Error: No target provided.{PC.RESET}")
        parser.print_help()
        sys.exit(1)

    files_to_process = []
    if os.path.isdir(args.target):
        if args.recursive:
            for root, _, files in os.walk(args.target):
                for f in files:
                    files_to_process.append(os.path.join(root, f))
        else:
            for item in os.listdir(args.target):
                full_path = os.path.join(args.target, item)
                if os.path.isfile(full_path):
                    files_to_process.append(full_path)
    elif os.path.isfile(args.target):
        files_to_process.append(args.target)
    else:
        print(f"{PC.CRITICAL}[!] Error: Target '{args.target}' not found.{PC.RESET}")
        sys.exit(1)

    results_log = []
    stats = {"total": 0, "CRITICAL": 0, "SUSPICIOUS": 0, "CLEAN": 0, "SKIPPED": 0}

    mode_text = "Metadata Mode" if (args.metadata and not args.scan) else "Full Triage"
    print(f"{PC.INFO}[*] Prism engine ready. Mode: {mode_text} | Targets: {len(files_to_process)}\n")

    try:
        for file_path in files_to_process:
            try:
                current_size = os.path.getsize(file_path)
                if current_size > MAX_FILE_SIZE and not args.large:
                    print(f"{PC.WARNING}[!] Skipping {os.path.basename(file_path)}: File exceeds 100MB.{PC.RESET}")
                    stats["SKIPPED"] += 1
                    continue

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

                triage_data = triage(
                    raw_bytes,
                    scanner,
                    heuristics=heuristics,
                    file_hash=file_sha256,
                    api_key=api_key
                )

                all_triggers = triage_data.get("YARA_Matches", []) + triage_data.get("Heuristics", [])
                triage_data["Triggers"] = all_triggers

                final_report = {
                    "file_info": {
                        "name": os.path.basename(file_path),
                        "path": file_path,
                        "timestamp": datetime.now().isoformat(),
                        "sha256": file_sha256,
                        "md5": file_md5,
                        "size": current_size
                    },
                    "structure": parser_data,
                    "analysis": triage_data
                }

                results_log.append(final_report)
                status = triage_data.get("Status", "CLEAN")
                stats[status] = stats.get(status, 0) + 1
                stats["total"] += 1

                if args.json:
                    print(json.dumps(final_report, indent=4))
                else:
                    generate_report(final_report)

            except Exception as e:
                print(f"{PC.CRITICAL}[!] Error processing {file_path}: {e}")
                continue

    except KeyboardInterrupt:
        print(f"\n{PC.WARNING}[!] User interrupted scan. Finalizing results...{PC.RESET}")

    if stats["total"] > 0 or stats["SKIPPED"] > 0:
        print(f"\n{PC.HEADER}{'='*30} SESSION SUMMARY {'='*30}{PC.RESET}")
        print(f"Total Files Found:   {len(files_to_process)}")
        print(f"Files Analyzed:      {stats['total']}")
        print(f"{PC.CRITICAL}Malicious/Critical:  {stats['CRITICAL']}{PC.RESET}")
        print(f"{PC.WARNING}Suspicious:          {stats['SUSPICIOUS']}{PC.RESET}")
        print(f"{PC.SUCCESS}Clean:               {stats['CLEAN']}{PC.RESET}")
        if stats["SKIPPED"] > 0:
            print(f"{PC.WARNING}Skipped (Too Large): {stats['SKIPPED']}{PC.RESET}")
        print(f"{PC.HEADER}{'='*77}{PC.RESET}")

    if args.log:
        try:
            with open(args.log, 'w', encoding='utf-8') as f:
                json.dump(
                    results_log,
                    f,
                    indent=4,
                    default=lambda o: o.decode('utf-8', errors='ignore') if isinstance(o, bytes) else str(o)
                )
            print(f"\n{PC.SUCCESS}[+] Analysis log saved to: {args.log}{PC.RESET}")
        except Exception as e:
            print(f"\n{PC.CRITICAL}[!] Failed to write log file: {e}{PC.RESET}")

if __name__ == '__main__':
    main()