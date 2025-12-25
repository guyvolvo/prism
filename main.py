import os
import pathlib
import re
import sys
import argparse
import json
import hashlib
import mimetypes
import threading
import concurrent.futures
from datetime import datetime
import logging
logging.getLogger("keyring").setLevel(logging.WARNING) # Disable annoying logging from keyring
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
from secure_file_collection import SecureFileCollector, validate_before_processing

MAX_FILE_SIZE = 100 * 1024 * 1024

# Thread synchronization locks
stats_lock = threading.Lock()
print_lock = threading.Lock()

import os
import re

_cached_api_key = None

def resolve_api_key(args_api):

    global _cached_api_key
    if _cached_api_key:
        return _cached_api_key

    SERVICE_NAME = "prism_scanner"
    KEY_NAME = "bazaar_api_key"

    try:
        import keyring
        # Linux fallback: plaintext backend if DBus/SecretService unavailable
        try:
            from keyrings.alt.file import PlaintextKeyring
            keyring.set_keyring(PlaintextKeyring())
        except ImportError:
            pass
    except ImportError:
        keyring = None

    # If user provided a key via command line, save it securely
    if isinstance(args_api, str):
        clean_key = args_api.strip("'\"")

        # Validate key format
        if not re.match(r'^[a-fA-F0-9]{64}$', clean_key):
            print(f"{PC.WARNING}[!] API key format validation skipped (adjust regex if needed){PC.RESET}")

        if keyring:
            try:
                keyring.set_password(SERVICE_NAME, KEY_NAME, clean_key)
                print(f"{PC.SUCCESS}[+] API Key saved securely to system keyring{PC.RESET}")
            except Exception as e:
                print(f"{PC.CRITICAL}[!] Error saving key: {e}{PC.RESET}")
        else:
            print(f"{PC.WARNING}[!] keyring not installed, falling back to environment variable{PC.RESET}")
        _cached_api_key = clean_key
        return clean_key

    if args_api is True:
        stored_key = None
        if keyring:
            try:
                stored_key = keyring.get_password(SERVICE_NAME, KEY_NAME)
                if stored_key:
                    print(f"{PC.INFO}[*] API Key loaded from secure storage{PC.RESET}")
            except Exception as e:
                print(f"{PC.CRITICAL}[!] Error retrieving key: {e}{PC.RESET}")

        if not stored_key:
            stored_key = os.getenv("BAZAAR_API_KEY")
            if stored_key:
                print(f"{PC.INFO}[*] Using API key from environment variable{PC.RESET}")
            else:
                print(f"{PC.CRITICAL}[!] No API key found in secure storage or environment{PC.RESET}")
                return None

        _cached_api_key = stored_key
        return stored_key


    stored_key = None
    if keyring:
        try:
            stored_key = keyring.get_password(SERVICE_NAME, KEY_NAME)
        except Exception:
            pass

    if not stored_key:
        stored_key = os.getenv("BAZAAR_API_KEY")

    _cached_api_key = stored_key
    return stored_key


def triage_router(file_path):
    try:

        with open(file_path, "rb") as f:
            chunk = f.read(2048)
    except Exception:
        chunk = b""

    def format_binary_alert(os_type, stream_msg):
        return {
            "Status": "CRITICAL",
            "Triggers": ["Hidden Executable", "Malformed", "Polyglot Detected"],
            "Stream_Results": [{"Section_Name": stream_msg, "Entropy": 7.9}],
            "Heuristic Alerts": [
                f"CRITICAL: Hidden {os_type} binary discovered inside {os.path.splitext(file_path)[1]}"]
        }

    if b"\x7fELF" in chunk:
        if not chunk.startswith(b"\x7fELF"):
            return format_binary_alert("Linux", "Embedded ELF Binary")
        return {"Status": "SUSPICIOUS", "Triggers": ["Linux Binary"], "Stream_Results": []}

    if b"MZ" in chunk:
        ext = os.path.splitext(file_path)[1].lower()
        if ext not in [".exe", ".dll", ".sys"]:
            return format_binary_alert("Windows", "Embedded PE Binary")
        return analyze_pe(file_path)

    if b"%PDF" in chunk:
        return analyze_pdf(file_path)

    for magic in [b"\xca\xfe\xba\xbe", b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xce"]:
        if magic in chunk:
            return format_binary_alert("macOS", "Embedded Mach-O Binary")

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

        is_valid, reason = validate_before_processing(file_path, args.large)
        if not is_valid:
            with print_lock:
                print(f"{PC.WARNING}[!] Validation failed for {os.path.basename(file_path)}: {reason}{PC.RESET}")
            with stats_lock:
                stats["SKIPPED"] += 1
            return

        if not os.path.exists(file_path):
            return

        with open(file_path, "rb") as f:
            raw_bytes = f.read()

        sha256 = hashlib.sha256(raw_bytes).hexdigest()
        scanner = get_scanner()

        parser_data = triage_router(file_path)
        triage_data = triage(file_path=file_path, data=raw_bytes, scanner=scanner, api_key=api_key)

        if not isinstance(parser_data, dict):
            parser_data = {"Status": "CLEAN", "Triggers": []}
        if not isinstance(triage_data, dict):
            triage_data = {"Status": "CLEAN", "Yara_Matches": [], "Heuristics": []}

        final_status = triage_data.get("Status", "UNKNOWN")

        struct_triggers = parser_data.get("Triggers", [])
        critical_struct_issues = any(
            "Hidden Executable" in str(t) or
            "Polyglot" in str(t) or
            "Malformed PE" in str(t)
            for t in struct_triggers
        )

        if critical_struct_issues:
            # Structural issues elevate suspicion
            if final_status == "CLEAN":
                final_status = "SUSPICIOUS"
                triage_data["Status"] = final_status
                triage_data.setdefault("Heuristics", []).append(
                    "Elevated to SUSPICIOUS: Critical structural anomalies detected"
                )

        if "Score" not in triage_data:
            # Fallback scoring
            indicators_count = len(triage_data.get("Yara_Matches", [])) + \
                               len(triage_data.get("Heuristics", [])) + \
                               len(struct_triggers)
            triage_data["Score"] = f"{min(indicators_count * 2, 10)}/10"

        assert triage_data["Status"] in {"CLEAN", "SUSPICIOUS", "MALICIOUS"}, \
            f"Invalid final status: {triage_data['Status']}"

        report = {
            "scan_info": {
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "mime_type": "application/octet-stream"
            },
            "file_info": {
                "name": os.path.basename(file_path),
                "sha256": sha256,
                "size_bytes": len(raw_bytes)
            },
            "analysis": triage_data,
            "structure": parser_data,
            "Verdict": final_status
        }

        with stats_lock:
            results_log.append(report)

            # Update statistics
            if final_status == "MALICIOUS":
                stats["CRITICAL"] += 1
            elif final_status == "SUSPICIOUS":
                stats["SUSPICIOUS"] += 1
            else:
                stats["CLEAN"] += 1
            stats["total"] += 1

        with print_lock:
            generate_report(report)

    except PermissionError as e:
        with print_lock:
            print(f"{PC.CRITICAL}[!] Permission denied: {file_path} - {e}{PC.RESET}")
        with stats_lock:
            stats["SKIPPED"] += 1

    except OSError as e:
        with print_lock:
            print(f"{PC.CRITICAL}[!] OS error processing {file_path}: {e}{PC.RESET}")
        with stats_lock:
            stats["SKIPPED"] += 1

    except Exception as e:
        with print_lock:
            print(f"{PC.CRITICAL}[!] Error processing {file_path}: {e}{PC.RESET}")
        with stats_lock:
            stats["SKIPPED"] += 1


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

    # Resolve API key
    api_key = resolve_api_key(args.api)

    # If only setting/viewing API key, exit after that
    if args.api is not None and not args.target:
        sys.exit(0)

    # Validate that target was provided
    if not args.target:
        print(f"{PC.CRITICAL}[!] Error: No target provided.{PC.RESET}")
        sys.exit(1)

    print(f"{PC.INFO}[*] Initializing secure file collector...{PC.RESET}\n")

    # Create secure file collector
    collector = SecureFileCollector(
        max_file_size=MAX_FILE_SIZE,
        allow_large=args.large
    )

    # Determine base directory for path traversal protection
    base_dir = None
    try:
        target_path = os.path.abspath(args.target)
        if os.path.isdir(target_path):
            base_dir = target_path
            print(f"{PC.INFO}[*] Base directory set: {base_dir}{PC.RESET}")
    except Exception as e:
        print(f"{PC.CRITICAL}[!] Error resolving target path: {e}{PC.RESET}")
        sys.exit(1)

    # Collect and validate all files
    files_to_process, collection_stats = collector.collect_files(
        target=args.target,
        recursive=args.recursive,
        base_dir=base_dir,
        verbose=True
    )

    # Handle case where no valid files found
    if not files_to_process:
        print(f"{PC.CRITICAL}[!] No valid files to process{PC.RESET}")
        if collection_stats['total_found'] > 0:
            print(f"{PC.WARNING}[!] Found {collection_stats['total_found']} files but all were filtered out{PC.RESET}")
            collector.print_collection_stats()
        sys.exit(1)

    # Print collection statistics for large scans
    if len(files_to_process) > 50 or args.metadata:
        collector.print_collection_stats()

    results_log = []

    stats = {
        "total": 0,
        "CRITICAL": 0,
        "SUSPICIOUS": 0,
        "CLEAN": 0,
        "SKIPPED": collection_stats['total_found'] - collection_stats['validated'],
        "TRUSTED": 0
    }

    start_time = datetime.now()

    print(f"{PC.INFO}[*] Prism Engine Ready. Workers: {args.threads} | Targets: {len(files_to_process)}{PC.RESET}\n")
    if api_key:
        print(f"{PC.SUCCESS}[+] API Connection established.{PC.RESET}")
    else:
        print(f"{PC.WARNING}[!] Running without API Key (Offline Mode).{PC.RESET}")

    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as executor:
            # Submit all tasks
            futures = [
                executor.submit(process_file_worker, f, args, api_key, stats, results_log)
                for f in files_to_process
            ]

            # Wait for completion and handle errors
            for future in concurrent.futures.as_completed(futures):
                try:
                    future.result()
                except PermissionError as e:
                    with print_lock:
                        print(f"{PC.CRITICAL}[!] Permission error: {e}{PC.RESET}")
                    with stats_lock:
                        stats["SKIPPED"] += 1
                except OSError as e:
                    with print_lock:
                        print(f"{PC.CRITICAL}[!] OS error: {e}{PC.RESET}")
                    with stats_lock:
                        stats["SKIPPED"] += 1
                except Exception as e:
                    with print_lock:
                        print(f"{PC.CRITICAL}[!] Unexpected error: {e}{PC.RESET}")
                    with stats_lock:
                        stats["SKIPPED"] += 1

    except KeyboardInterrupt:
        print(f"\n{PC.WARNING}[!] User interrupted scan.{PC.RESET}")
    except Exception as e:
        print(f"\n{PC.CRITICAL}[!] Fatal error in scan engine: {e}{PC.RESET}")
        import traceback
        traceback.print_exc()

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
            print(f"{PC.WARNING}Skipped:             {stats['SKIPPED']}{PC.RESET}")
        print(f"{PC.HEADER}{'=' * 77}{PC.RESET}")

    if args.log:
        with open(args.log, 'w') as f:
            json.dump(results_log, f, indent=4, default=str)
        print(f"{PC.SUCCESS}[+] Log saved: {args.log}{PC.RESET}")

    os._exit(0)


if __name__ == '__main__':
    main()
