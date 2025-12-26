#!/usr/bin/env python3
"""
SHA-256 Verification & CIRCL Diagnostic Tool

This tool verifies SHA-256 calculation accuracy and tests CIRCL lookups.
Run this to troubleshoot whitelisting issues.
"""

import hashlib
import os
import sys
import requests
import json
from pathlib import Path


def calculate_sha256_method1(file_path):
    """Method 1: Read entire file at once (used in process_file_worker)"""
    try:
        with open(file_path, "rb") as f:
            raw_bytes = f.read()
        return hashlib.sha256(raw_bytes).hexdigest()
    except Exception as e:
        return f"ERROR: {e}"


def calculate_sha256_method2(file_path):
    """Method 2: Read in chunks (used in get_file_hash)"""
    sha256_hash = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(65536), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except Exception as e:
        return f"ERROR: {e}"


def verify_with_certutil(file_path):
    """Windows only: Use CertUtil to verify SHA-256"""
    if os.name != 'nt':
        return "N/A (Windows only)"

    try:
        import subprocess
        result = subprocess.run(
            ['certutil', '-hashfile', file_path, 'SHA256'],
            capture_output=True,
            text=True,
            timeout=10
        )

        if result.returncode == 0:
            # Parse output (hash is on second line)
            lines = result.stdout.strip().split('\n')
            if len(lines) >= 2:
                return lines[1].strip().lower()

        return f"ERROR: {result.stderr}"
    except Exception as e:
        return f"ERROR: {e}"


def verify_with_powershell(file_path):
    """Windows only: Use PowerShell Get-FileHash"""
    if os.name != 'nt':
        return "N/A (Windows only)"

    try:
        import subprocess
        result = subprocess.run(
            ['powershell', '-Command',
             f'(Get-FileHash -Path "{file_path}" -Algorithm SHA256).Hash'],
            capture_output=True,
            text=True,
            timeout=10
        )

        if result.returncode == 0:
            return result.stdout.strip().lower()

        return f"ERROR: {result.stderr}"
    except Exception as e:
        return f"ERROR: {e}"


def check_circl_api(file_hash):
    """Test CIRCL API lookup"""
    url = f"https://hashlookup.circl.lu/lookup/sha256/{file_hash}"

    print(f"\n{'=' * 70}")
    print(f"CIRCL API Test")
    print(f"{'=' * 70}")
    print(f"URL: {url}")

    try:
        response = requests.get(url, timeout=5)

        print(f"Status Code: {response.status_code}")

        if response.status_code == 404:
            print("Result: Hash NOT found in CIRCL database")
            print("\nThis is NORMAL for:")
            print("  • Files not in their database")
            print("  • Specific Windows build versions")
            print("  • Custom/private software")
            print("  • Recently released software")
            return None

        elif response.status_code == 200:
            data = response.json()
            print("Result: Hash FOUND in CIRCL database")
            print(f"\nDetails:")
            print(f"  Filename: {data.get('FileName', 'N/A')}")
            print(f"  Trust Score: {data.get('hashlookup:trust', 'N/A')}")
            print(f"  File Type: {data.get('FileType', 'N/A')}")

            if 'KnownMalicious' in data:
                print(f"  ⚠️  Known Malicious: {data['KnownMalicious']}")

            print(f"\nFull Response:")
            print(json.dumps(data, indent=2))
            return data

        else:
            print(f"Unexpected status: {response.status_code}")
            print(f"Response: {response.text}")
            return None

    except requests.exceptions.Timeout:
        print("ERROR: Request timed out (network issue)")
        return None
    except requests.exceptions.ConnectionError:
        print("ERROR: Cannot connect to CIRCL (network/firewall issue)")
        return None
    except Exception as e:
        print(f"ERROR: {e}")
        return None


def diagnose_file(file_path):
    """Run complete diagnostic on a file"""
    print(f"\n{'=' * 70}")
    print(f"SHA-256 Diagnostic Tool")
    print(f"{'=' * 70}")
    print(f"File: {file_path}")

    # Check file exists
    if not os.path.exists(file_path):
        print(f"ERROR: File not found!")
        return

    # Get file info
    file_size = os.path.getsize(file_path)
    print(f"Size: {file_size:,} bytes ({file_size / (1024 * 1024):.2f} MB)")

    # Calculate SHA-256 using multiple methods
    print(f"\n{'-' * 70}")
    print("SHA-256 Calculation Methods:")
    print(f"{'-' * 70}")

    hash_method1 = calculate_sha256_method1(file_path)
    print(f"Method 1 (read all):     {hash_method1}")

    hash_method2 = calculate_sha256_method2(file_path)
    print(f"Method 2 (chunked):      {hash_method2}")

    # Windows-specific verification
    if os.name == 'nt':
        hash_certutil = verify_with_certutil(file_path)
        print(f"CertUtil verification:   {hash_certutil}")

        hash_powershell = verify_with_powershell(file_path)
        print(f"PowerShell verification: {hash_powershell}")

    # Verify consistency
    print(f"\n{'-' * 70}")
    print("Consistency Check:")
    print(f"{'-' * 70}")

    hashes = [hash_method1, hash_method2]
    if os.name == 'nt':
        if not hash_certutil.startswith("ERROR"):
            hashes.append(hash_certutil)
        if not hash_powershell.startswith("ERROR"):
            hashes.append(hash_powershell)

    # Remove errors
    valid_hashes = [h for h in hashes if not str(h).startswith("ERROR")]

    if len(set(valid_hashes)) == 1:
        print("✓ All methods agree - SHA-256 calculation is CORRECT")
        final_hash = valid_hashes[0]
    elif len(valid_hashes) == 0:
        print("✗ All calculations failed!")
        return
    else:
        print("✗ WARNING: Hash mismatch detected!")
        print("This should never happen - possible file corruption or race condition")
        return

    # Test CIRCL lookup
    check_circl_api(final_hash)

    # Path-based trust heuristic
    print(f"\n{'-' * 70}")
    print("Trust Heuristics:")
    print(f"{'-' * 70}")

    file_path_lower = file_path.lower()
    if 'windows\\system32' in file_path_lower or 'windows\\syswow64' in file_path_lower:
        print("✓ File is in Windows system directory")
        print("  Recommendation: Even if not in CIRCL, likely legitimate")
    elif 'program files' in file_path_lower:
        print("✓ File is in Program Files")
        print("  Recommendation: Check digital signature")
    else:
        print("ℹ️  File is in non-standard location")
        print("  Recommendation: Higher scrutiny needed")

    print(f"\n{'=' * 70}\n")


def main():
    if len(sys.argv) < 2:
        print("Usage: python diagnostic_tool.py <file_path>")
        print("\nExample:")
        print("  python diagnostic_tool.py C:\\Windows\\System32\\kernel32.dll")
        sys.exit(1)

    file_path = sys.argv[1]
    diagnose_file(file_path)

    print("\nInterpretation Guide:")
    print("-" * 70)
    print("• Hash calculation methods MUST all agree")
    print("• CIRCL 404 = File not in database (NORMAL for many files)")
    print("• CIRCL 200 + low trust = Known but untrusted")
    print("• CIRCL 200 + high trust (>75) = Whitelisted")
    print("• System directory files are usually legitimate even if not in CIRCL")
    print("-" * 70)


if __name__ == "__main__":
    main()