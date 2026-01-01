import base64
import os
import threading
from colors import PrismColors as PC
import yara
import math
import re
import requests
import time
import logging
import shutil
import hashlib
from collections import Counter
from dotenv import load_dotenv
from requests.adapters import HTTPAdapter
from urllib3.util import Retry
import json
import sys
from pathlib import Path
from datetime import datetime, timedelta
from typing import Dict, List, Tuple
from dataclasses import dataclass

load_dotenv()

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_API_KEY = os.getenv("BAZAAR_API_KEY")

_scanner_instance = None

_whitelist_cache = {}
_whitelist_cache_lock = threading.Lock()

LOCAL_WHITELIST_FILE = os.path.join(BASE_DIR, "local_whitelist.json")


class TrustLevel:
    VERIFIED_SIGNED = "VERIFIED_SIGNED"
    SYSTEM_PATH = "SYSTEM_PATH"
    CIRCL_TRUSTED = "CIRCL_TRUSTED"
    LOCAL_WHITELIST = "LOCAL_WHITELIST"
    UNKNOWN = "UNKNOWN"


def get_secure_session():
    session = requests.Session()
    session.headers.update({"User-Agent": "Prism-Scanner/1.0 (UserAgent-2025-12-19)"})
    retry_strategy = Retry(total=3, backoff_factor=1, status_forcelist=[429, 500, 502, 503, 504])
    session.mount("https://", HTTPAdapter(max_retries=retry_strategy))
    return session


_session = get_secure_session()


def load_local_whitelist():
    """Load user-maintained local whitelist"""
    if not os.path.exists(LOCAL_WHITELIST_FILE):
        return {}

    try:
        with open(LOCAL_WHITELIST_FILE, 'r') as f:
            data = json.load(f)
            logger.info(f"Loaded {len(data)} entries from local whitelist")
            return data
    except Exception as e:
        logger.error(f"Failed to load local whitelist: {e}")
        return {}


def save_to_local_whitelist(file_hash: str, file_path: str, reason: str):
    """Add a hash to local whitelist"""
    whitelist = load_local_whitelist()

    whitelist[file_hash] = {
        "path": file_path,
        "added": datetime.now().isoformat(),
        "reason": reason
    }

    try:
        with open(LOCAL_WHITELIST_FILE, 'w') as f:
            json.dump(whitelist, f, indent=2)
        logger.info(f"Added {file_hash[:16]}... to local whitelist")
        return True
    except Exception as e:
        logger.error(f"Failed to save local whitelist: {e}")
        return False


def check_windows_system_path(file_path: str) -> bool:
    """Check if file is in a trusted Windows system directory"""
    file_path_lower = file_path.lower()

    trusted_paths = [
        r'c:\windows\system32',
        r'c:\windows\syswow64',
        r'c:\windows\winsxs',
        r'c:\program files\windows',
        r'c:\windows\system',
    ]

    for trusted_path in trusted_paths:
        if file_path_lower.startswith(trusted_path):
            logger.info(f"{PC.SUCCESS}File in Windows system path: {file_path}{PC.RESET}")
            return True

    return False


def check_microsoft_signature(file_path: str, verbose: bool = False):
    if verbose:
        print(f"    [*] Checking signature (this may take a moment for large files)...")

    if os.name == 'nt':  # Windows only
        try:
            import subprocess

            # Calculate timeout based on file size
            # Large files take longer to verify
            file_size_mb = os.path.getsize(file_path) / (1024 * 1024)
            if file_size_mb > 100:
                timeout = 30  # 30 seconds for files > 100MB
            elif file_size_mb > 50:
                timeout = 20  # 20 seconds for files > 50MB
            else:
                timeout = 10  # 10 seconds for smaller files

            if verbose:
                print(f"    [*] File size: {file_size_mb:.1f}MB, timeout: {timeout}s")

            # Escape path properly for PowerShell

            escaped_path = file_path.replace('"', '`"')

            ps_command = f'''
                        $ErrorActionPreference = 'SilentlyContinue'
                        try {{
                            Import-Module Microsoft.PowerShell.Security -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
                            $sig = Get-AuthenticodeSignature -FilePath "{escaped_path}"

                            if (!$sig) {{ throw "No signature object returned" }}

                            if ($sig.Status -eq 'Valid') {{
                                $subject = $sig.SignerCertificate.Subject
                                if ($subject -match 'Microsoft') {{
                                    Write-Output "VALID_MICROSOFT|$subject"
                                }} else {{
                                    Write-Output "VALID_OTHER|$subject"
                                }}
                            }} elseif ($sig.Status -eq 'NotSigned') {{
                                Write-Output "NOT_SIGNED"
                            }} else {{
                                Write-Output "INVALID|$($sig.Status)"
                            }}
                        }} catch {{
                            # Only output the error message, not the full stack
                            Write-Output "ERROR|$($_.Exception.Message.Split([Environment]::NewLine)[0])"
                        }}
                        '''

            if verbose:
                print(f"    [*] Running PowerShell verification...")

            result = subprocess.run(
                ['powershell', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-Command', ps_command],
                capture_output=True,
                text=True,
                timeout=timeout
            )

            output = result.stdout.strip()

            if verbose:
                print(f"    [*] PowerShell result: {output}")

            if output.startswith("VALID_MICROSOFT|"):
                signer = output.split("|", 1)[1] if "|" in output else "Microsoft Corporation"
                if verbose:
                    print(f"{PC.SUCCESS}    [+] Valid Microsoft signature{PC.RESET}")
                    print(f"        Signer: {signer}")
                logger.info(f"Microsoft signature verified: {file_path}")
                return True, signer, {"type": "microsoft", "status": "valid"}

            elif output.startswith("VALID_OTHER|"):
                signer = output.split("|", 1)[1] if "|" in output else "Unknown Publisher"

                import re
                cn_match = re.search(r'CN=([^,]+)', signer)
                if cn_match:
                    company = cn_match.group(1).strip()
                else:
                    company = signer[:50]

                if verbose:
                    print(f"{PC.SUCCESS}    [+] Valid signature (non-Microsoft){PC.RESET}")
                    print(f"      Signer: {company}")

                logger.info(f"{PC.SUCCESS}Valid signature from: {company}{PC.RESET}")
                return True, company, {"type": "trusted", "status": "valid", "full_subject": signer}

            elif output == "NOT_SIGNED":
                if verbose:
                    print(f"{PC.INFO}    [X] File is not digitally signed{PC.RESET}")
                logger.debug(f"File not signed: {file_path}")
                return False, None, {"type": "none", "status": "not_signed"}

            elif output.startswith("INVALID|"):
                status = output.split("|", 1)[1] if "|" in output else "Unknown"
                if verbose:
                    print(f"{PC.WARNING}    [X] Invalid signature: {status}{PC.RESET}")
                logger.warning(f"Invalid signature ({status}): {file_path}")
                return False, None, {"type": "invalid", "status": status}


            elif output.startswith("ERROR|"):

                error = output.split("|", 1)[1] if "|" in output else "Unknown error"
                if "module" in error.lower() and "could not be loaded" in error.lower():
                    if verbose:
                        print(f"    {PC.WARNING}[!] PowerShell module error (trying alternative){PC.RESET}")
                    return try_certutil_signature_check(file_path, verbose)
                if verbose:
                    print(f"    {PC.WARNING}[X] Signature check error: {error}{PC.RESET}")
                logger.error(f"Signature check error: {error}")
                return False, None, {"type": "error", "status": error}

            else:
                if verbose:
                    print(f"{PC.WARNING}    [X] Unexpected output: {output[:100]}{PC.RESET}")
                logger.warning(f"Unexpected signature check output: {output[:100]}")
                return False, None, {"type": "error", "status": "unexpected_output"}

        except subprocess.TimeoutExpired:
            if verbose:
                print(f"{PC.WARNING}    [X] Signature check timed out (file too large or system busy){PC.RESET}")
            logger.warning(f"Signature check timeout: {file_path}")
            return False, None, {"type": "error", "status": "timeout"}

        except Exception as e:
            if verbose:
                print(f"{PC.WARNING}    [X] Signature check failed: {e}{PC.RESET}")
            logger.error(f"Signature check exception: {e}")
            return False, None, {"type": "error", "status": str(e)}

    else:

        if verbose:
            print(f"{PC.WARNING}    [X] Signature check not available (non-Windows){PC.RESET}")
        return False, None, {"type": "none", "status": "platform_not_supported"}


def try_certutil_signature_check(file_path: str, verbose: bool = False):
    try:
        import subprocess

        if verbose:
            print(f"    {PC.INFO}[*] Trying certutil as fallback...{PC.RESET}")

        result = subprocess.run(
            ['certutil', '-verify', file_path],
            capture_output=True,
            text=True,
            timeout=15
        )

        output = result.stdout + result.stderr

        if 'Signature verified' in output or 'verified successfully' in output.lower():
            if 'Microsoft' in output:
                if verbose:
                    print(f"    {PC.SUCCESS}[+] Microsoft signature verified (certutil){PC.RESET}")
                return True, "Microsoft Corporation", {"type": "microsoft", "status": "valid"}
            else:
                if verbose:
                    print(f"    {PC.SUCCESS}[+] Valid signature found (certutil){PC.RESET}")
                return True, "Verified Publisher", {"type": "trusted", "status": "valid"}
        elif 'not signed' in output.lower():
            if verbose:
                print(f"    {PC.WARNING}[X] Not signed (certutil){PC.RESET}")
            return False, None, {"type": "none", "status": "not_signed"}
        else:
            return False, None, {"type": "error", "status": "certutil_inconclusive"}
    except Exception as e:
        if verbose:
            print(f"    {PC.WARNING}[X] Certutil fallback failed: {e}{PC.RESET}")
        return False, None, {"type": "error", "status": f"certutil_failed: {e}"}


def comprehensive_whitelist_check(file_path: str, file_hash: str, verbose: bool = False):
    """
    Multi-tier whitelist checking with detailed results.
    Now includes installer detection and adjusted scoring.
    """
    results = {
        "is_trusted": False,
        "trust_level": TrustLevel.UNKNOWN,
        "details": "Not whitelisted",
        "confidence": 0.0,
        "checks_performed": [],
        "is_installer": False  # NEW: Track if this looks like an installer
    }

    if verbose:
        print(f"\n{'=' * 70}")
        print(f"CIRCL & WHITELIST DIAGNOSTIC")
        print(f"{'=' * 70}")
        print(f"File: {file_path}")
        print(f"Hash: {file_hash}")
        print(f"\n{'-' * 70}")
        print("Performing multi-tier trust checks...")
        print(f"{'-' * 70}\n")

    # Detect installers by extension and size
    file_ext = os.path.splitext(file_path)[1].lower()
    file_size = os.path.getsize(file_path)
    installer_extensions = ['.exe', '.msi', '.msix', '.appx']

    # Files > 10MB with .exe extension are likely installers
    if file_ext in installer_extensions and file_size > 10 * 1024 * 1024:
        results["is_installer"] = True
        if verbose:
            print(f"[*] Detected potential installer (size: {file_size / (1024 * 1024):.1f}MB)")
            print()

    # Local whitelist
    if verbose:
        print("[*] Checking local whitelist...")

    local_whitelist = load_local_whitelist()
    if file_hash in local_whitelist:
        entry = local_whitelist[file_hash]
        results.update({
            "is_trusted": True,
            "trust_level": TrustLevel.LOCAL_WHITELIST,
            "details": f"User-approved: {entry.get('reason', 'Unknown reason')}",
            "confidence": 1.0,
            "checks_performed": ["local_whitelist"]
        })

        if verbose:
            print(f"    [+] FOUND in local whitelist")
            print(f"        Reason: {entry.get('reason')}")
            print(f"        Added: {entry.get('added')}")
            print(f"        Confidence: 100%")

        logger.info(f"File in local whitelist: {file_path}")
        return results

    if verbose:
        print(f"    [X] Not found in local whitelist")
        print()

    results["checks_performed"].append("local_whitelist")

    # Digital signature
    if verbose:
        print(f"[*] Checking digital signature...")

    is_signed, signer, sig_details = check_microsoft_signature(file_path, verbose=verbose)

    if is_signed and signer:
        sig_type = sig_details.get("type", "unknown")

        if sig_type == "microsoft":
            # Microsoft's signature - highest non-user trust
            results.update({
                "is_trusted": True,
                "trust_level": TrustLevel.VERIFIED_SIGNED,
                "details": f"Valid Microsoft signature: {signer}",
                "confidence": 0.95,
                "checks_performed": results["checks_performed"] + ["digital_signature"],
                "signature_info": sig_details
            })

            if verbose:
                print(f"    [+] VALID Microsoft signature")
                print(f"        Signer: {signer}")
                print(f"        Confidence: 95%")

            logger.info(f"Microsoft-signed file: {file_path}")
            return results

        elif sig_type == "trusted":

            confidence = 0.90 if results["is_installer"] else 0.85

            results.update({
                "is_trusted": True,
                "trust_level": TrustLevel.VERIFIED_SIGNED,
                "details": f"Valid signature: {signer}",
                "confidence": confidence,
                "checks_performed": results["checks_performed"] + ["digital_signature"],
                "signature_info": sig_details
            })

            if verbose:
                print(f"    [+] Valid signature (non-Microsoft)")
                print(f"      Signer: {signer}")
                print(f"      Confidence: {confidence * 100:.0f}%")
                if results["is_installer"]:
                    print(f"      Note: Increased confidence for signed installer")

            logger.info(f"Signed file: {file_path}")
            return results

    if verbose:
        status = sig_details.get("status", "unknown")
        if status == "not_signed":
            print(f"    [X] File is not digitally signed")
        elif status == "timeout":
            print(f"    [X] Signature check timed out (file too large)")
        elif status == "platform_not_supported":
            print(f"    [X] Signature check not available (non-Windows)")
        else:
            print(f"    [X] No valid signature found ({status})")
        print()

    results["checks_performed"].append("digital_signature")

    # CIRCL database
    if verbose:
        print(f"[*] Checking CIRCL database...")

    circl_trusted, circl_name, circl_status = check_circl_whitelist(file_hash, verbose=verbose)

    if circl_status == 'trusted':
        results.update({
            "is_trusted": True,
            "trust_level": TrustLevel.CIRCL_TRUSTED,
            "details": f"CIRCL database: {circl_name}",
            "confidence": 0.80,
            "checks_performed": results["checks_performed"] + ["circl_database"]
        })

        if verbose:
            print(f"    [+] FOUND in CIRCL with high trust")
            print()

        logger.info(f"File in CIRCL database: {circl_name}")
        return results

    elif circl_status == 'not_found':
        results["checks_performed"].append("circl_database")
        results["details"] = "Not found in CIRCL database"

        if verbose:
            print(f"    [X] Not found in CIRCL database (normal for many files)")
            print()

        logger.debug(f"File not in CIRCL: {file_path}")

    elif circl_status == 'untrusted':
        results["checks_performed"].append("circl_database")
        results["details"] = f"CIRCL: Low trust score - {circl_name}"

        if verbose:
            print(f"    [!] Found in CIRCL but LOW trust score")
            print()

        logger.warning(f"Low CIRCL trust: {file_path}")

    elif circl_status == 'error':
        results["checks_performed"].append("circl_database")
        results["details"] = "CIRCL lookup failed (network error)"

        if verbose:
            print(f"    [X] CIRCL lookup failed (network/timeout)")
            print()

    # System path heuristic
    if verbose:
        print(f"[*] Checking system path heuristic...")

    if check_windows_system_path(file_path):
        results.update({
            "is_trusted": True,
            "trust_level": TrustLevel.SYSTEM_PATH,
            "details": "Located in Windows system directory (heuristic)",
            "confidence": 0.60,
            "checks_performed": results["checks_performed"] + ["system_path"],
            "warning": "[!]  Trust based on location only - verify if flagged"
        })

        if verbose:
            print(f"    [+] File in Windows system directory")
            print(f"      Confidence: 60% (heuristic only)")
            print(f"    [!]  Note: Location-based trust, not cryptographic proof")
            print()

        logger.info(f"System path heuristic: {file_path}")
        return results

    if verbose:
        print(f"  [X] Not in Windows system directory")
        print()

    results["checks_performed"].append("system_path")

    if verbose:
        print(f"{'-' * 70}")
        print(f"FINAL RESULT: File is NOT whitelisted")
        print(f"Checks performed: {', '.join(results['checks_performed'])}")
        if results["is_installer"]:
            print(f"\nNote: This appears to be an installer. Installers often trigger")
            print(f"      false positives due to high entropy and large overlays.")
            print(f"      Signature verification is the most reliable check for installers.")
        print(f"{'=' * 70}\n")

    logger.debug(f"File not whitelisted: {file_path}")
    return results


class PrismScanner:
    def __init__(self):
        self.rule_folders = [
            os.path.join(BASE_DIR, "malware"),
            os.path.join(BASE_DIR, "maldocs"),
            os.path.join(BASE_DIR, "antidebug_antivm"),
            os.path.join(BASE_DIR, "capabilities"),
            os.path.join(BASE_DIR, "packers"),
            os.path.join(BASE_DIR, "webshells")
        ]
        self.quarantine_path = os.path.join(BASE_DIR, "broken_rules")
        os.makedirs(self.quarantine_path, exist_ok=True)
        self.rules = self._compile_all_rules()

    # Fixed issue YARA rules are loaded from disk without validation, A malicious YARA rule scould potentially
    # exploit parsing using vulnerabilities.

    def _compile_all_rules(self):
        valid_rules = {}
        for folder in self.rule_folders:
            if not os.path.exists(folder):
                continue
            for root, _, files in os.walk(folder):
                for file in files:
                    if file.endswith(('.yar', '.yara')):
                        path = os.path.join(root, file)

                        # Validate file is not a symlink
                        if os.path.islink(path):
                            print(f"{PC.WARNING}\033[1;31m[!] SECURITY: Skipping symlink rule: {file}\033[0m{PC.RESET}")
                            continue

                        # Basic content validation
                        try:
                            with open(path, 'rb') as f:
                                content = f.read()
                                # Check for null bytes (binary files)
                                if b'\x00' in content:
                                    print(
                                        f"{PC.WARNING}\033[1;31m[!] SECURITY: Binary content in {file}, skipping\033[0m{PC.RESET}")
                                    continue
                        except Exception as e:
                            print(f"{PC.WARNING}\033[1;31m[!] Cannot read {file}: {e}\033[0m{PC.RESET}")
                            continue

                        try:
                            yara.compile(filepath=path)
                            namespace = os.path.basename(root)
                            if namespace in ['rules', 'prism', 'malware', 'maldocs']:
                                namespace = 'gen'
                            valid_rules[f"{namespace}_{file}"] = path
                        except yara.SyntaxError as e:
                            print(f"{PC.WARNING}\033[1;33m[!] Quarantining Broken Rule:\033[0m {file} ({e}){PC.RESET}")
                            # ecure quarantine with unique names
                            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                            quarantine_name = f"{file}.{timestamp}.quarantine"
                            shutil.move(path, os.path.join(self.quarantine_path, quarantine_name))

        if not valid_rules: return None
        return yara.compile(filepaths=valid_rules)

    def scan_bytes(self, data: bytes):
        if not self.rules: return []
        try:
            matches = self.rules.match(data=data, fast=True, timeout=15)
            return [f"{m.namespace}:{m.rule}" for m in matches]
        except Exception as e:
            return [f"error:{str(e)}"]


def get_secure_session():
    session = requests.Session()
    session.headers.update({"User-Agent": "Prism-Scanner/1.0 (UserAgent-2025-12-19)"})
    retry_strategy = Retry(total=3, backoff_factor=1, status_forcelist=[429, 500, 502, 503, 504])
    session.mount("https://", HTTPAdapter(max_retries=retry_strategy))
    return session


def get_file_hash(file_path):
    sha256_hash = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(65536), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except Exception:
        return None

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def check_circl_whitelist(file_hash: str, verbose: bool = False):
    """
    Check if file hash exists in CIRCL HashLookup database.

    Args:
        file_hash: SHA256 hash to lookup
        verbose: If True, print detailed diagnostic info

    Returns:
        (is_trusted, filename, status)
        status: 'trusted', 'not_found', 'untrusted', 'error'
    """

    # Check cache first

    with _whitelist_cache_lock:
        if file_hash in _whitelist_cache:
            cached_result = _whitelist_cache[file_hash]
            if verbose:
                print(f"{PC.INFO}  [!]  Using cached CIRCL result{PC.RESET}")
            return cached_result

    url = f"https://hashlookup.circl.lu/lookup/sha256/{file_hash}"

    if verbose:
        print(f"{PC.INFO}  [*] Querying: {url}{PC.RESET}")

    try:
        response = _session.get(url, timeout=5)

        if verbose:
            print(f"  [*] Response: {response.status_code}")

        # Handle 404 specifically - not in database
        if response.status_code == 404:
            if verbose:
                print(f"{PC.CRITICAL}    [!] Hash not in CIRCL database")
                print(f"        This is NORMAL - CIRCL doesn't have all files")

            logger.debug(f"CIRCL: Hash not in database {file_hash[:16]}...")
            result = (False, None, 'not_found')

            with _whitelist_cache_lock:
                _whitelist_cache[file_hash] = result

            return result

        # Raise for other HTTP errors
        response.raise_for_status()

        data = response.json()

        if verbose:
            print(f"  {PC.SUCCESS}[+] Found in CIRCL database!{PC.RESET}")
            print(f"\n  Raw Response:")
            print(json.dumps(data, indent=4))

        # Extract trust score
        trust_score = data.get("hashlookup:trust", 0)
        filename = data.get("FileName", "Unknown")

        # Higher threshold for trust
        is_trusted = trust_score >= 75
        status = 'trusted' if is_trusted else 'untrusted'

        if verbose:
            print(f"\n  Analysis:")
            print(f"    Filename: {filename}")
            print(f"    Trust Score: {trust_score}/100")
            print(f"    Threshold: 75")
            print(f"    Result: {'[+] TRUSTED' if is_trusted else '[X] UNTRUSTED (low score)'}")

        if is_trusted:
            logger.info(f"{PC.INFO}CIRCL: Trusted - {filename} (trust={trust_score}){PC.RESET}")
        else:
            logger.warning(f"{PC.INFO}CIRCL: Low trust - {filename} (trust={trust_score}){PC.RESET}")

        result = (is_trusted, filename, status)

        # Cache the result
        with _whitelist_cache_lock:
            _whitelist_cache[file_hash] = result

        return result

    except requests.exceptions.Timeout:
        if verbose:
            print(f"  {PC.CRITICAL}[X] Timeout - CIRCL service too slow (>5 seconds){PC.RESET}")
        logger.warning(f"CIRCL lookup timeout for {file_hash[:16]}...")
        return (False, None, 'error')

    except requests.exceptions.ConnectionError:
        if verbose:
            print(f"  {PC.CRITICAL}[X] Connection failed - network or firewall issue{PC.RESET}")
        logger.warning("CIRCL service unavailable")
        return (False, None, 'error')

    except requests.exceptions.HTTPError as e:
        if verbose:
            print(f"  {PC.CRITICAL}[X] HTTP Error: {e.response.status_code}{PC.RESET}")
        logger.error(f"CIRCL HTTP error {e.response.status_code}: {e}")
        return (False, None, 'error')

    except ValueError as e:
        if verbose:
            print(f"  {PC.CRITICAL}[X] Invalid JSON response from CIRCL{PC.RESET}")
        logger.error(f"Invalid JSON from CIRCL: {e}")
        result = (False, None, 'error')
        with _whitelist_cache_lock:
            _whitelist_cache[file_hash] = result
        return result

    except Exception as e:
        if verbose:
            print(f"  {PC.CRITICAL}[X] Unexpected error: {e}{PC.RESET}")
        logger.exception(f"Unexpected error in CIRCL lookup: {e}")
        return (False, None, 'error')


def check_malware_bazaar(file_hash: str, key: str = None):
    active_key = key or DEFAULT_API_KEY
    if not active_key: return None
    url = "https://mb-api.abuse.ch/api/v1/"
    headers = {"Auth-Key": active_key.strip("'\"")}
    try:
        response = _session.post(url, data={'query': 'get_info', 'hash': file_hash}, headers=headers, timeout=5)
        if response.status_code == 200 and response.json().get('query_status') == 'ok':
            return response.json()['data'][0]
    except:
        pass
    return None


def shannon_entropy(data: bytes) -> float:
    if not data: return 0.0
    counts = Counter(data)
    entropy = -sum((count / len(data)) * math.log2(count / len(data)) for count in counts.values())
    return round(entropy, 2)


"""
Universal Context-Aware Analysis Engine
Intelligently distinguishes between documentation and actual threats
"""



@dataclass
class ContentContext:
    """Represents the context analysis of file content"""
    is_documentation: bool
    is_code_sample: bool
    is_configuration: bool
    is_executable: bool
    documentation_score: float
    threat_score: float
    context_markers: List[str]


class ContextAnalyzer:
    # Text-based indicators
    DOCUMENTATION_MARKERS = {
        r'^#{1,6}\s+.+$': 3,  # Headers
        r'```[\w]*\n.*?\n```': 5,  # Code blocks
        r'`[^`]+`': 2,  # Inline code
        r'\[.+\]\(.+\)': 2,  # Links
        r'^\*\s+.+$': 1,  # Bullet points
        r'\b(example|tutorial|guide|readme|documentation|how to)\b': 4,
        r'\b(note:|warning:|important:|tip:)\b': 3,
    }

    # Binary-based indicators
    BINARY_MARKERS = {
        b'^MZ': 10,  # PE header
        b'^\x7fELF': 10,  # ELF header
        b'^%PDF': 5,  # PDF header
        b'^PK\x03\x04': 5,  # ZIP header
        b'^\xca\xfe\xba\xbe': 10,  # Java/Mach-O
    }

    THREAT_PATTERNS = {
        r'[A-Za-z0-9+/]{100,}==': 4,  # Long Base64
        r'eval\(.*?\(.*?\)\)': 6,  # Nested eval
        r'\$[a-z]+\s*=\s*[\'"][^\'"]{50,}[\'"]': 5,  # Obfuscated var
        r'^\s*(powershell|cmd)\.exe\s+[-/]': 8,
    }

    @staticmethod
    def analyze_content(data: bytes, file_path: str) -> ContentContext:
        exec_score = 0.0
        exec_markers = []

        header_slice = data[:1024]
        for pattern, weight in ContextAnalyzer.BINARY_MARKERS.items():
            if re.search(pattern, header_slice):
                exec_score += weight
                exec_markers.append(f"Header:{pattern.decode('latin1', 'ignore')}")

        try:
            content = data.decode('utf-8', errors='ignore')
            is_binary_file = False
        except Exception:
            content = ""
            is_binary_file = True

        doc_score = 0.0
        doc_markers = []

        if content:
            for pattern, weight in ContextAnalyzer.DOCUMENTATION_MARKERS.items():
                matches = re.findall(pattern, content, re.MULTILINE | re.IGNORECASE)
                if matches:
                    doc_score += weight * min(len(matches), 5)
                    doc_markers.append(f"DocPattern:{len(matches)}")

            for pattern, weight in ContextAnalyzer.THREAT_PATTERNS.items():
                matches = re.findall(pattern, content, re.MULTILINE | re.IGNORECASE)
                if matches:
                    exec_score += weight * len(matches)
                    exec_markers.append(f"ThreatPattern:{len(matches)}")

        doc_score = min(doc_score / 50.0, 1.0)
        exec_score = min(exec_score / 50.0, 1.0)

        is_documentation = doc_score > 0.3
        is_executable = exec_score > 0.5 or is_binary_file

        has_code_blocks = '```' in content or '<code>' in content
        is_code_sample = has_code_blocks and doc_score > 0.2

        return ContentContext(
            is_documentation=is_documentation,
            is_code_sample=is_code_sample,
            is_configuration=False,
            is_executable=is_executable,
            documentation_score=doc_score,
            threat_score=exec_score,
            context_markers=doc_markers + exec_markers
        )

    @staticmethod
    def is_pattern_in_safe_context(content: str, pattern_match: str, match_pos: int) -> bool:

        """
        Check if a pattern match is in a safe context (code block, comment, etc.)

        Args:
            content: Full file content
            pattern_match: The matched string
            match_pos: Position in content where match was found

        Returns:
            True if pattern is in safe context (documentation)
        """
        # Extract context around the match (500 chars before/after)

        context_start = max(0, match_pos - 500)
        context_end = min(len(content), match_pos + 500)
        context = content[context_start:context_end]

        before_match = content[:match_pos]
        code_block_starts = before_match.count('```')
        if code_block_starts % 2 == 1:
            return True

        if re.search(r'<(?:code|pre)[^>]*>[^<]*$', before_match[-200:]):
            return True

        line_start = content.rfind('\n', 0, match_pos) + 1
        line = content[line_start:match_pos + 50]
        if re.match(r'^\s*[#/;]', line):
            return True

        explanation_indicators = [
            'example:', 'for example', 'such as', 'like:', 'e.g.',
            'command:', 'usage:', 'syntax:', 'note:', 'warning:',
            'this will', 'you can', 'to do this', 'demonstrates'
        ]
        context_lower = context.lower()
        if any(indicator in context_lower for indicator in explanation_indicators):
            return True

        paragraph = content[max(0, match_pos - 200):min(len(content), match_pos + 200)]
        sentences = re.split(r'[.!?]+', paragraph)
        if len(sentences) > 2:
            return True

        return False


def get_context_aware_heuristics(data: bytes, file_path: str) -> List[Tuple[str, int]]:
    """
    Context-aware heuristic detection.
    Replaces the old get_content_heuristics() with intelligent analysis.

    Args:
        data: File content as bytes
        file_path: Path to the file

    Returns:
        List of (heuristic_description, weight) tuples
    """

    h_list = []

    context = ContextAnalyzer.analyze_content(data, file_path)

    weight_multiplier = 0.1 if context.is_documentation else 1.0

    if context.is_executable:
        weight_multiplier = 1.5

    try:
        content = data.decode('utf-8', errors='ignore')
    except:
        return h_list

    content_lower = content.lower()

    patterns = {
        r"powershell\s+[-/]\w*e\w*\s+[-/]": ("PowerShell Encoded Command", 8),
        r"powershell.+(-enc|-e|-w\s+hidden|-nop|-exec\s+bypass)": ("PowerShell Obfuscated/Hidden", 6),
        r"(invoke-expression|iex)\s*\(": ("PowerShell Dynamic Execution", 5),
        r"downloadstring|downloadfile": ("PowerShell Downloader", 6),

        r"eval\s*\([^)]{50,}\)": ("Dynamic Code Execution (Long)", 5),
        r"exec\s*\([^)]{30,}\)": ("Code Execution (Long)", 5),
        r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}": ("Raw IP URL", 3),
        r"cmd\.exe\s+/c\s+\S+": ("Command Execution", 4),

        r"[A-Za-z0-9+/]{100,}={0,2}": ("Long Base64 String", 3),
        r"powershell": ("PowerShell Reference", 1),
    }

    for pattern, (label, base_weight) in patterns.items():
        matches = list(re.finditer(pattern, content, re.IGNORECASE))

        if matches:
            safe_context_count = 0
            threat_context_count = 0

            for match in matches:
                if ContextAnalyzer.is_pattern_in_safe_context(content, match.group(), match.start()):
                    safe_context_count += 1
                else:
                    threat_context_count += 1

            if threat_context_count > safe_context_count:
                adjusted_weight = int(base_weight * weight_multiplier)
                if adjusted_weight > 0:
                    h_list.append((
                        f"Content Match: {label} ({threat_context_count} threats, {safe_context_count} docs)",
                        adjusted_weight
                    ))
            elif safe_context_count > 0 and context.is_documentation:
                h_list.append((
                    f"[*] Note: {label} found in documentation context ({safe_context_count} instances)", 0
                ))

    return h_list


def get_scanner():
    global _scanner_instance
    if _scanner_instance is None:
        _scanner_instance = PrismScanner()
    return _scanner_instance


def triage(file_path, data: bytes, scanner=None, api_key=None, file_hash=None, verbose_circl=False, **kwargs):
    """
    Args:
        file_path: Path to the file
        data: File content as bytes
        scanner: YARA scanner instance
        api_key: MalwareBazaar API key
        file_hash: Pre-calculated SHA256 (optional)
        verbose_circl: If True, print detailed CIRCL diagnostic info
        **kwargs: Additional arguments (parser_tier, etc.)
    """

    file_hash = file_hash or get_file_hash(file_path)
    scanner = scanner or get_scanner()

    # Perform comprehensive whitelist check
    whitelist_result = comprehensive_whitelist_check(file_path, file_hash, verbose=verbose_circl)

    # If trusted with high confidence, return clean verdict
    if whitelist_result["is_trusted"] and whitelist_result["confidence"] >= 0.80:
        logger.info(f"File trusted ({whitelist_result['trust_level']}): {file_path}")

        return {
            "Status": "TRUSTED",
            "Verdict": "TRUSTED",
            "Score": "0/10",
            "FP_Risk": "NONE",

            "Yara_Matches": [],
            "Heuristics": [],
            "Reputation": None,
            "MalwareBazaar_Found": False,

            "Whitelist_Info": {
                "Source": whitelist_result["trust_level"],
                "Identified_As": whitelist_result["details"],
                "Hash": file_hash,
                "Confidence": f"{whitelist_result['confidence'] * 100:.0f}%",
                "Checks": ", ".join(whitelist_result["checks_performed"])
            },

            "Threat_Indicators": [f"[+] TRUSTED: {whitelist_result['details']}"],
            "Entropy": shannon_entropy(data),
            "Confidence_Metrics": {
                "Intent_Score": 0,
                "Uncertainty_Score": 0
            }
        }

    # If trusted with medium confidence, note but continue analysis
    trust_note = None
    trust_adjustment = 0
    if whitelist_result["is_trusted"] and whitelist_result["confidence"] >= 0.50:
        trust_note = f"{PC.INFO}[!]  {whitelist_result['details']}{PC.RESET}"
        trust_adjustment = 5  # Require higher score to flag
        logger.info(f"Medium trust file, analyzing: {file_path}")

    # Proceed with normal threat analysis
    content_context = ContextAnalyzer.analyze_content(data, file_path)

    # Use context-aware heuristics
    heuristics = get_context_aware_heuristics(data, file_path)
    entropy = shannon_entropy(data)

    # YARA with context filtering
    raw_yara_matches = scanner.scan_bytes(data)

    # Filter YARA based on context
    yara_matches = []
    if content_context.is_documentation or content_context.is_code_sample:
        # Only keep high-confidence matches for documentation
        threat_keywords = ['trojan', 'ransomware', 'backdoor', 'rootkit', 'exploit']
        for match in raw_yara_matches:
            if any(kw in match.lower() for kw in threat_keywords):
                yara_matches.append(match)
    else:
        yara_matches = raw_yara_matches
    reputation = check_malware_bazaar(file_hash, key=api_key)
    parser_tier = str(kwargs.get('parser_tier', 'NONE')).upper()

    intent_score = 0
    uncertainty_score = 0
    indicators = []

    if trust_note:
        indicators.append(trust_note)

    # YARA analysis
    if yara_matches:
        threat_keywords = ['trojan', 'ransomware', 'backdoor', 'rootkit', 'exploit', 'malware', 'webshell']
        suspicious_keywords = ['packer', 'obfuscator', 'crypter', 'upx', 'suspicious']
        capability_keywords = ['network', 'registry', 'file', 'process', 'injection', 'api', 'debug']

        threat_matches = []
        suspicious_matches = []
        capability_matches = []

        for match in yara_matches:
            if match.startswith('error:'):
                logger.error(f"YARA error: {match}")
                continue

            match_lower = match.lower()

            if any(keyword in match_lower for keyword in threat_keywords):
                threat_matches.append(match)
            elif any(keyword in match_lower for keyword in suspicious_keywords):
                suspicious_matches.append(match)
            elif any(keyword in match_lower for keyword in capability_keywords):
                capability_matches.append(match)
            else:
                suspicious_matches.append(match)

        if threat_matches:
            intent_score += 8
            indicators.append(f"YARA THREAT: {', '.join(threat_matches[:3])}")
            if len(threat_matches) > 3:
                indicators.append(f"  ...and {len(threat_matches) - 3} more")

        if suspicious_matches:
            weight = 2 if whitelist_result.get("is_trusted") else 4
            intent_score += weight
            indicators.append(f"YARA SUSPICIOUS: {', '.join(suspicious_matches[:3])}")
            if len(suspicious_matches) > 3:
                indicators.append(f"  ...and {len(suspicious_matches) - 3} more")

        if capability_matches:
            if threat_matches or suspicious_matches:
                intent_score += 2
                indicators.append(f"YARA CAPABILITIES: {', '.join(capability_matches[:5])}")
            else:
                indicators.append(f"YARA CAPABILITIES (informational): {', '.join(capability_matches[:5])}")

    if reputation:
        intent_score += 15
        indicators.append(f"[!] REPUTATION: {reputation.get('signature', 'Known Malware')}")
        whitelist_result["is_trusted"] = False
        trust_adjustment = 0

    for heuristic_tuple in heuristics:
        if isinstance(heuristic_tuple, tuple):
            heuristic_text, weight = heuristic_tuple
            intent_score += weight
            indicators.append(f"Heuristic: {heuristic_text} (weight: {weight})")
        else:
            intent_score += 2
            indicators.append(f"Heuristic: {heuristic_tuple}")

    if parser_tier == 'VERIFIED' and intent_score > 0:
        intent_score += 3
        indicators.append("Executable structure confirms capability")
    elif parser_tier == 'MALFORMED':
        uncertainty_score += 7
        indicators.append("[!] STRUCTURAL ANOMALY: Malformed/Truncated Header")

    # Entropy analysis
    if entropy > 7.9:
        uncertainty_score += 6
        indicators.append(f"Very High Entropy ({entropy:.2f}): Encrypted/packed/random")
    elif entropy > 7.7:
        uncertainty_score += 4
        indicators.append(f"High Entropy ({entropy:.2f}): Compression/packing suspected")
    elif entropy > 7.4:
        uncertainty_score += 2
        indicators.append(f"Moderate-High Entropy ({entropy:.2f}): May indicate packing")

    if entropy > 7.7 and intent_score == 0:
        indicators.append("[!]  Note: High entropy alone often indicates compression")

    # Add trust adjustment note
    if trust_adjustment > 0:
        indicators.append(f"Trust adjustment: +{trust_adjustment} intent threshold (system file)")
    is_installer = whitelist_result.get("is_installer", False)
    installer_adjustment = 0

    if is_installer:

        if entropy > 7.7:
            uncertainty_score = max(0, uncertainty_score - 4)
            indicators.append("[!]  Note: High entropy expected for compressed installers")

        installer_adjustment = 3
        indicators.append(f"Installer detected: +{installer_adjustment} intent threshold")

        logger.info(f"Installer-aware scoring applied: {file_path}")

    trust_adjustment += installer_adjustment

    status = "CLEAN"

    status = "CLEAN"

    if intent_score > (15 + trust_adjustment):
        status = "MALICIOUS"
    elif intent_score > (10 + trust_adjustment):
        if uncertainty_score < 5:
            status = "MALICIOUS"
        else:
            status = "SUSPICIOUS"
    elif intent_score > (5 + trust_adjustment):
        status = "SUSPICIOUS"
    elif intent_score > trust_adjustment:
        if yara_matches or heuristics:
            status = "SUSPICIOUS"
        else:
            status = "CLEAN"

    if uncertainty_score >= 7 and status == "MALICIOUS" and not reputation:
        status = "SUSPICIOUS"
        indicators.append("[-] VERDICT DOWNGRADED: High uncertainty (FP risk)")

    # Calculate FP risk
    fp_risk = "LOW"
    if whitelist_result.get("is_trusted"):
        fp_risk = "MEDIUM"
    if uncertainty_score >= 10:
        fp_risk = "HIGH"
    elif uncertainty_score >= 5:
        fp_risk = "MEDIUM"

    # Format results
    yara_list = [ind for ind in indicators if "YARA" in ind]
    heuristics_list = [ind for ind in indicators
                       if not ind.startswith("YARA")
                       and not "REPUTATION" in ind
                       and not ind.startswith("[!]  Note:")
                       and not ind.startswith("Trust adjustment")]

    reputation_dict = None
    if reputation:
        reputation_dict = {
            'signature': reputation.get('signature', 'Unknown'),
            'sha256_hash': file_hash,
            'tags': reputation.get('tags', [])
        }

    return {
        "Status": status,
        "Verdict": status,
        "Score": f"{min(intent_score, 10)}/10",
        "FP_Risk": fp_risk,

        "Yara_Matches": yara_list,
        "Heuristics": heuristics_list,
        "Reputation": reputation_dict,
        "MalwareBazaar_Found": bool(reputation),
        """
        
        
        "Whitelist_Info": {
            "Checked": True,
            "Status": whitelist_result["trust_level"],
            "Details": whitelist_result["details"],
            "Confidence": f"{whitelist_result['confidence'] * 100:.0f}%"
        } if not whitelist_result.get("is_trusted") or whitelist_result["confidence"] < 0.80 else None,
        """

        # Trying new logic below

        "Whitelist_Info": {
            "Status": whitelist_result["trust_level"],
            "Details": whitelist_result["details"],
            "Confidence": f"{whitelist_result['confidence'] * 100:.0f}%"
        } if whitelist_result["is_trusted"] else None,

        "Threat_Indicators": indicators,
        "Entropy": entropy,
        "Content_Context": {
            "Is_Documentation": content_context.is_documentation,
            "Is_Code_Sample": content_context.is_code_sample,
            "Documentation_Score": f"{content_context.documentation_score:.2f}",
            "Threat_Score": f"{content_context.threat_score:.2f}",
            "Context": "Documentation/Educational" if content_context.is_documentation else "Executable/Unknown"
        },
        "Confidence_Metrics": {
            "Intent_Score": intent_score,
            "Uncertainty_Score": uncertainty_score,
            "Trust_Adjustment": trust_adjustment
        }
    }
