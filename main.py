import os
import sys
import argparse
import json
from datetime import datetime

from parsers.pdf_parser import analyze_pdf
from parsers.office_parser import analyze_ole
from parsers.pe_parser import analyze_pe
from core.report import generate_report
from colors import PrismColors as PC


def triage_router(file_path):

    ext = os.path.splitext(file_path)[1].lower()

    if ext == ".pdf":
        return analyze_pdf(file_path)
    elif ext in [".doc", ".xls", ".ppt", ".docm", ".xlsm"]:
        return analyze_ole(file_path)
    elif ext in [".exe", ".dll", ".bin", ".sys"]:
        return analyze_pe(file_path)
    else:
        return {"error": f"Unsupported file type: {ext}"}


def main():

    parser = argparse.ArgumentParser(
        description=f"{PC.HEADER}Prism Triage Framework | Multi-format Malware Analysis{PC.RESET}",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"{PC.INFO}Example: python main.py samples/ -r -v{PC.RESET}"
    )


    parser.add_argument("target", help="Path to a file or a directory to scan")

    # Options
    parser.add_argument("-r", "--recursive", action="store_true", help="Recursively scan directories")
    parser.add_argument("-j", "--json", action="store_true", help="Output raw JSON data instead of a report")
    parser.add_argument("-v", "--verbose", action="store_true", help="Include detailed stream info in reports")
    parser.add_argument("-o", "--log", help="Save the terminal output to a text file")

    args = parser.parse_args()
    target = args.target
    files_to_process = []

    if os.path.isdir(target):
        if args.recursive:
            for root, _, files in os.walk(target):
                for f in files:
                    files_to_process.append(os.path.join(root, f))
        else:
            print(f"{PC.WARNING}[!] {target} is a directory. Use -r to scan all files inside.")
            sys.exit(1)
    elif os.path.isfile(target):
        files_to_process.append(target)
    else:
        print(f"{PC.CRITICAL}[!] Path not found: {target}")
        sys.exit(1)

    print(f"{PC.INFO}[*] Prism started triage on {len(files_to_process)} target(s)...\n")

    all_results = []

    for file_path in files_to_process:
        # Route the file to the right parser
        data = triage_router(file_path)

        if "error" in data:
            if args.verbose:
                print(f"{PC.DIM}[-] Skipping {os.path.basename(file_path)}: {data['error']}")
            continue

        all_results.append(data)


        if args.json:
            print(json.dumps(data, indent=4))
        else:
            generate_report(data)

    if args.log:
        with open(args.log, "w") as f:
            f.write(f"Prism Scan Log - {datetime.now()}\n")
            f.write(json.dumps(all_results, indent=2))
        print(f"{PC.SUCCESS}[+] Results saved to {args.log}")


if __name__ == '__main__':
    main()
