import os
import sys
import argparse
import json
import hashlib
import mimetypes
import threading
import concurrent.futures
from datetime import datetime

current_dir = os.path.dirname(os.path.abspath(__file__))
vendor_path = os.path.join(current_dir, 'vendor')
if os.path.exists(vendor_path) and vendor_path not in sys.path:
    sys.path.insert(0, vendor_path)

try:
    from dotenv import load_dotenv, find_dotenv, set_key

    load_dotenv(find_dotenv())
except ImportError:
    pass

from colors import PrismColors as PC
from core.scanner import get_scanner, triage
from core.report import generate_report
from parsers.pdf_parser import analyze_pdf
from parsers.office_parser import analyze_office
from parsers.pe_parser import analyze_pe

MAX_FILE_SIZE = 100 * 1024 * 1024

stats_lock = threading.Lock()
print_lock = threading.Lock()


def resolve_api_key(args_api):
    env_path = find_dotenv() or os.path.join(current_dir, '.env')
    existing_key = os.getenv("BAZAAR_API_KEY")

    if isinstance(args_api, str):
        clean_key = args_api.strip("'").strip('"')
        with print_lock:
            print(f"{PC.INFO}[+] API Key provided via command line. Saving to {env_path}...{PC.RESET}")
        try:
            set_key(env_path, "BAZAAR_API_KEY", clean_key)
            os.environ["BAZAAR_API_KEY"] = clean_key
            return clean_key
        except Exception as e:
            with print_lock:
                print(f"{PC.CRITICAL}[!] Error saving key: {e}{PC.RESET}")
            return clean_key

    if args_api is True:
        with print_lock:
            if existing_key:
                masked = f"{existing_key[:4]}...{existing_key[-4:]}"
                print(f"{PC.INFO}[*] Current API Key: {PC.WARNING}{masked}{PC.RESET} (Loaded from {env_path})")
            else:
                print(f"{PC.CRITICAL}[!] No keys are loaded. Use --api <KEY> to set one.{PC.RESET}")
        return existing_key

    return existing_key.strip("'").strip('"') if existing_key else None


def triage_router(file_path):
    try:
        with open(file_path, "rb") as f:
            header = f.read(4)
    except Exception:
        header = b""

    if header.startswith(b"%PDF"):
        return analyze_pdf(file_path)

    elif header.startswith(b"PK\x03\x04"):
        return analyze_office(file_path)

    elif header.startswith(b"MZ"):
        return analyze_pe(file_path)
    elif header.startswith(b"\x7fELF"):
        return {"Stream_Results": ["Linux ELF Binary Detected"], "Triggers": ["Hidden Executable"],
                "Status": "SUSPICIOUS"}
    elif header in [b"\xca\xfe\xba\xbe", b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xce"]:
        return {"Stream_Results": ["macOS Mach-O Binary Detected"], "Triggers": ["Hidden Executable"],
                "Status": "SUSPICIOUS"}
    ext = os.path.splitext(file_path)[1].lower()
    if ext == ".pdf":
        return analyze_pdf(file_path)
    elif ext in [".doc", ".docx", ".xls", ".xlsx", ".ppt", ".docm", ".xlsm"]:
        return analyze_office(file_path)
    elif ext in [".exe", ".dll", ".bin", ".sys", ".com"]:
        return analyze_pe(file_path)

    return {"Stream_Results": [], "Triggers": [], "Status": "Unknown"}


def print_metadata_only(file_path, sha256_hash, md5_hash, mime_type):
    stats = os.stat(file_path)
    with print_lock:
        print(f"{PC.HEADER}--- PRISM METADATA: {os.path.basename(file_path)} ---{PC.RESET}")
        print(f"{PC.INFO}File Info:{PC.RESET}")
        print(f"  Path:      {file_path}\n  Size:      {stats.st_size} bytes")
        print(f"  MIME Type: {mime_type}")
        print(f"\n{PC.INFO}Fingerprints:{PC.RESET}")
        print(f"  MD5:       {PC.WARNING}{md5_hash}{PC.RESET}")
        print(f"  SHA256:    {PC.WARNING}{sha256_hash}{PC.RESET}")
        print("-" * 55 + "\n")


def process_file_worker(file_path, args, api_key, stats, results_log):
    try:
        if not os.path.exists(file_path): return
        file_size = os.path.getsize(file_path)

        if file_size > MAX_FILE_SIZE and not args.large:
            with stats_lock: stats["SKIPPED"] += 1
            return

        mime_type, _ = mimetypes.guess_type(file_path)
        mime_type = mime_type or "application/octet-stream"

        with open(file_path, "rb") as f:
            raw_bytes = f.read()

        sha256 = hashlib.sha256(raw_bytes).hexdigest()
        md5 = hashlib.md5(raw_bytes).hexdigest()

        report = {
            "scan_info": {"timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"), "mime_type": mime_type},
            "file_info": {"name": os.path.basename(file_path), "sha256": sha256, "size_bytes": file_size},
            "analysis": {},
            "structure": {}
        }

        if args.metadata:
            print_metadata_only(file_path, sha256, md5, mime_type)
            if not args.scan:
                with stats_lock:
                    results_log.append(report)
                    stats["total"] += 1
                return

        scanner = get_scanner()
        parser_data = triage_router(file_path) or {"Status": "Error"}
        triage_data = triage(file_path=file_path, data=raw_bytes, scanner=scanner, api_key=api_key)

        if not triage_data:
            triage_data = {"Status": "CLEAN", "Score": 0}

        report["analysis"] = triage_data
        report["structure"] = parser_data

        with stats_lock:
            results_log.append(report)
            status = triage_data.get("Status", "CLEAN")
            stats[status] = stats.get(status, 0) + 1
            stats["total"] += 1

        with print_lock:
            if args.json:
                print(json.dumps(report, indent=4, default=str))
            else:
                generate_report(report)

    except Exception as e:
        with print_lock:
            print(f"{PC.CRITICAL}[!] Error processing {file_path}: {e}{PC.RESET}")


def main():
    parser = argparse.ArgumentParser(description=f"{PC.HEADER}Prism Triage Framework{PC.RESET}")
    parser.add_argument("target", nargs='?', help="Path to file or directory")
    parser.add_argument("-r", "--recursive", action="store_true", help="Recursive scan")
    parser.add_argument("-j", "--json", action="store_true", help="Raw JSON output")
    parser.add_argument("-o", "--log", help="Save to JSON file")
    parser.add_argument("-m", "--metadata", action="store_true", help="Metadata only")
    parser.add_argument("-s", "--scan", action="store_true", help="Force scan with metadata")
    parser.add_argument("-t", "--threads", type=int, default=4, help="Threads (Default: 4)")
    parser.add_argument("--large", action="store_true", help="Bypass 100MB limit")
    parser.add_argument("--api", nargs='?', const=True, help="Set, update, or view API key")
    args = parser.parse_args()

    api_key = resolve_api_key(args.api)

    if args.api is not None and not args.target:
        sys.exit(0)

    if not args.target:
        print(f"{PC.CRITICAL}[!] Error: No target provided.{PC.RESET}")
        sys.exit(1)

    files_to_process = []
    if os.path.isdir(args.target):
        for root, _, files in (
                os.walk(args.target) if args.recursive else [(args.target, [], os.listdir(args.target))]):
            for f in files:
                full_p = os.path.join(root, f)
                if os.path.isfile(full_p): files_to_process.append(full_p)
    elif os.path.isfile(args.target):
        files_to_process.append(args.target)

    results_log = []
    stats = {"total": 0, "CRITICAL": 0, "SUSPICIOUS": 0, "CLEAN": 0, "SKIPPED": 0, "TRUSTED": 0}
    start_time = datetime.now()

    print(f"{PC.INFO}[*] Prism Engine Ready. Workers: {args.threads} | Targets: {len(files_to_process)}{PC.RESET}\n")
    if api_key:
        print(f"{PC.SUCCESS}[+] API Connection established.{PC.RESET}")
    else:
        print(f"{PC.WARNING}[!] Running without API Key (Offline Mode).{PC.RESET}")

    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as executor:
            futures = [executor.submit(process_file_worker, f, args, api_key, stats, results_log) for f in
                       files_to_process]
            for future in concurrent.futures.as_completed(futures):
                future.result()
    except KeyboardInterrupt:
        print(f"\n{PC.WARNING}[!] User interrupted scan.{PC.RESET}")

    duration = datetime.now() - start_time
    if stats["total"] > 0 or stats["SKIPPED"] > 0:
        print(f"\n{PC.HEADER}{'=' * 30} SESSION SUMMARY {'=' * 30}{PC.RESET}")
        print(f"Scan Duration:       {duration.total_seconds():.2f} seconds")
        print(f"Files Processed:     {stats['total']}")
        print(f"{PC.CRITICAL}Malicious:           {stats.get('CRITICAL', 0)}{PC.RESET}")
        print(f"{PC.WARNING}Suspicious:          {stats.get('SUSPICIOUS', 0)}{PC.RESET}")
        print(f"{PC.SUCCESS}Clean:               {stats.get('CLEAN', 0)}{PC.RESET}")
        if stats.get('TRUSTED', 0) > 0:
            print(f"{PC.SUCCESS}Whitelisted/Trusted: {stats['TRUSTED']}{PC.RESET}")
        if stats["SKIPPED"] > 0:
            print(f"{PC.WARNING}Skipped (>100MB):    {stats['SKIPPED']}{PC.RESET}")
        print(f"{PC.HEADER}{'=' * 77}{PC.RESET}")

    if args.log:
        with open(args.log, 'w') as f:
            json.dump(results_log, f, indent=4, default=str)
        print(f"{PC.SUCCESS}[+] Log saved: {args.log}{PC.RESET}")

    os._exit(0)


if __name__ == '__main__':
    main()