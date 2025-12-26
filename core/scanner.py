import base64
import os
import threading

import yara
import math
import re
import requests
import time
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

load_dotenv()

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_API_KEY = os.getenv("BAZAAR_API_KEY")

_scanner_instance = None

_whitelist_cache = {}
_whitelist_cache_lock = threading.Lock()

LOCAL_WHITELIST_FILE = os.path.join(BASE_DIR, "local_whitelist.json")


# Trust levels
class TrustLevel:
    VERIFIED_SIGNED = "VERIFIED_SIGNED"
    SYSTEM_PATH = "SYSTEM_PATH"
    CIRCL_TRUSTED = "CIRCL_TRUSTED"
    LOCAL_WHITELIST = "LOCAL_WHITELIST"
    UNKNOWN = "UNKNOWN"


# Secure session generator upon request


def get_secure_session():
    session = requests.Session()
    session.headers.update({"User-Agent": "Prism-Scanner/1.0 (UserAgent-2025-12-19)"})
    retry_strategy = Retry(total=3, backoff_factor=1, status_forcelist=[429, 500, 502, 503, 504])
    session.mount("https://", HTTPAdapter(max_retries=retry_strategy))
    return session


_session = get_secure_session()


# ============================================================================
# NEW: Multi-Tier Whitelist Helper Functions
# ============================================================================

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
            logger.info(f"File in Windows system path: {file_path}")
            return True

    return False


def check_microsoft_signature(file_path: str):
    """
    Check if file has a valid Microsoft digital signature.
    Returns: (is_signed, signer_name)
    """
    if os.name == 'nt':  # Windows only
        try:
            import subprocess

            ps_command = f'''
            $sig = Get-AuthenticodeSignature -FilePath '{file_path}'
            if ($sig.Status -eq 'Valid' -and $sig.SignerCertificate.Subject -match 'Microsoft') {{
                Write-Output "VALID_MICROSOFT"
            }} elseif ($sig.Status -eq 'Valid') {{
                Write-Output "VALID_OTHER:$($sig.SignerCertificate.Subject)"
            }} else {{
                Write-Output "INVALID"
            }}
            '''

            result = subprocess.run(
                ['powershell', '-Command', ps_command],
                capture_output=True,
                text=True,
                timeout=5
            )

            output = result.stdout.strip()

            if output == "VALID_MICROSOFT":
                logger.info(f"Microsoft signature verified: {file_path}")
                return True, "Microsoft Corporation"
            elif output.startswith("VALID_OTHER:"):
                signer = output.split(":", 1)[1]
                logger.info(f"Valid signature from: {signer}")
                return True, signer

        except Exception as e:
            logger.debug(f"Signature check failed: {e}")

    return False, None


def comprehensive_whitelist_check(file_path: str, file_hash: str, verbose: bool = False):
    results = {
        "is_trusted": False,
        "trust_level": TrustLevel.UNKNOWN,
        "details": "Not whitelisted",
        "confidence": 0.0,
        "checks_performed": []
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
            print(f"[+] FOUND in local whitelist")
            print(f"    Reason: {entry.get('reason')}")
            print(f"    Added: {entry.get('added')}")
            print(f"    Confidence: 100%")

        logger.info(f"File in local whitelist: {file_path}")
        return results

    if verbose:
        print(f"    [X] Not found in local whitelist")

    results["checks_performed"].append("local_whitelist")

    # Tier 2: Digital signature
    if verbose:
        print(f"\n[*] Checking digital signature...")

    is_signed, signer = check_microsoft_signature(file_path)
    if is_signed and signer:
        if "Microsoft" in signer:
            results.update({
                "is_trusted": True,
                "trust_level": TrustLevel.VERIFIED_SIGNED,
                "details": f"Valid Microsoft signature: {signer}",
                "confidence": 0.95,
                "checks_performed": results["checks_performed"] + ["digital_signature"]
            })

            if verbose:
                print(f"  [+] VALID Microsoft signature")
                print(f"    Signer: {signer}")
                print(f"    Confidence: 95%")

            logger.info(f"Microsoft-signed file: {file_path}")
            return results
        else:
            results.update({
                "is_trusted": True,
                "trust_level": TrustLevel.VERIFIED_SIGNED,
                "details": f"Valid signature: {signer}",
                "confidence": 0.85,
                "checks_performed": results["checks_performed"] + ["digital_signature"]
            })

            if verbose:
                print(f"    [+] Valid signature (non-Microsoft)")
                print(f"        Signer: {signer}")
                print(f"        Confidence: 85%")

            logger.info(f"Signed file: {file_path}")
            return results

    if verbose:
        if os.name != 'nt':
            print(f"    [X] Signature check not available (non-Windows)")
        else:
            print(f"    [X] No valid signature found")

    results["checks_performed"].append("digital_signature")

    # Tier 3: CIRCL database
    if verbose:
        print(f"\n[*] Checking CIRCL database...")

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
            print(f"  [+] FOUND in CIRCL with high trust")

        logger.info(f"File in CIRCL database: {circl_name}")
        return results

    elif circl_status == 'not_found':
        results["checks_performed"].append("circl_database")
        results["details"] = "Not found in CIRCL database"

        if verbose:
            print(f"    [X] Not found in CIRCL database (normal for many files)")

        logger.debug(f"File not in CIRCL: {file_path}")

    elif circl_status == 'untrusted':
        results["checks_performed"].append("circl_database")
        results["details"] = f"CIRCL: Low trust score - {circl_name}"

        if verbose:
            print(f"  [!] Found in CIRCL but LOW trust score")

        logger.warning(f"Low CIRCL trust: {file_path}")

    elif circl_status == 'error':
        results["checks_performed"].append("circl_database")
        results["details"] = "CIRCL lookup failed (network error)"

        if verbose:
            print(f"  [X] CIRCL lookup failed (network/timeout)")

    # Tier 4: System path heuristic
    if verbose:
        print(f"\n[*] Checking system path heuristic...")

    if check_windows_system_path(file_path):
        results.update({
            "is_trusted": True,
            "trust_level": TrustLevel.SYSTEM_PATH,
            "details": "Located in Windows system directory (heuristic)",
            "confidence": 0.60,
            "checks_performed": results["checks_performed"] + ["system_path"],
            "warning": "[!] Trust based on location only - verify if flagged"
        })

        if verbose:
            print(f"    [+] File in Windows system directory")
            print(f"    Confidence: 60% (heuristic only)")
            print(f"    [!] Note: Location-based trust, not cryptographic proof")

        logger.info(f"System path heuristic: {file_path}")
        return results

    if verbose:
        print(f"  [X] Not in Windows system directory")

    results["checks_performed"].append("system_path")

    # No whitelist match
    if verbose:
        print(f"\n{'-' * 70}")
        print(f"FINAL RESULT: File is NOT whitelisted")
        print(f"Checks performed: {', '.join(results['checks_performed'])}")
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
                            print(f"\033[1;31m[!] SECURITY: Skipping symlink rule: {file}\033[0m")
                            continue

                        # Basic content validation
                        try:
                            with open(path, 'rb') as f:
                                content = f.read()
                                # Check for null bytes (binary files)
                                if b'\x00' in content:
                                    print(f"\033[1;31m[!] SECURITY: Binary content in {file}, skipping\033[0m")
                                    continue
                        except Exception as e:
                            print(f"\033[1;31m[!] Cannot read {file}: {e}\033[0m")
                            continue

                        try:
                            yara.compile(filepath=path)
                            namespace = os.path.basename(root)
                            if namespace in ['rules', 'prism', 'malware', 'maldocs']:
                                namespace = 'gen'
                            valid_rules[f"{namespace}_{file}"] = path
                        except yara.SyntaxError as e:
                            print(f"\033[1;33m[!] Quarantining Broken Rule:\033[0m {file} ({e})")
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


import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

"""
def check_circl_whitelist(file_hash):
    with _whitelist_cache_lock:
        if file_hash in _whitelist_cache:
            return _whitelist_cache[file_hash]

    url = f"https://hashlookup.circl.lu/lookup/sha256/{file_hash}"
    try:
        response = _session.get(url, timeout=3)

        # Handle 404 specifically - file not in database
        if response.status_code == 404:
            logger.info(f"CIRCL: Hash not in database {file_hash[:16]}...")
            result = (False, None, 'not_found')
            with _whitelist_cache_lock:
                _whitelist_cache[file_hash] = result
            return result

        # Raise for other HTTP errors (500, 503, etc.)
        response.raise_for_status()

        data = response.json()

        trust = data.get("hashlookup:trust", 0)
        filename = data.get("FileName", "Known System File")

        is_trusted = trust >= 75  # Increased threshold for safety
        status = 'trusted' if is_trusted else 'untrusted'

        if is_trusted:
            logger.info(f"CIRCL: Whitelisted - {filename} (trust={trust})")
        else:
            logger.warning(f"CIRCL: Found but low trust - {filename} (trust={trust})")

        result = (is_trusted, filename, status)

        # Cache the result
        with _whitelist_cache_lock:
            _whitelist_cache[file_hash] = result

        return result

    except requests.exceptions.Timeout:
        logger.warning(f"CIRCL lookup timeout for {file_hash[:16]}... (network issue)")
        result = (False, None, 'error')
        # don't cache errors, allow retry on next scan
        return result

    except requests.exceptions.ConnectionError:
        logger.warning("CIRCL service unavailable (connection error)")
        result = (False, None, 'error')
        return result

    except requests.exceptions.HTTPError as e:
        logger.error(f"CIRCL HTTP error {e.response.status_code}: {e}")
        result = (False, None, 'error')
        return result

    except ValueError as e:
        logger.error(f"Invalid JSON from CIRCL: {e}")
        result = (False, None, 'error')
        with _whitelist_cache_lock:
            _whitelist_cache[file_hash] = result
        return result

    except Exception as e:
        logger.exception(f"Unexpected error in CIRCL lookup: {e}")
        result = (False, None, 'error')
        return result

"""


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
                print(f"  [!]  Using cached CIRCL result")
            return cached_result

    url = f"https://hashlookup.circl.lu/lookup/sha256/{file_hash}"

    if verbose:
        print(f"  → Querying: {url}")

    try:
        response = _session.get(url, timeout=5)

        if verbose:
            print(f"  → Response: {response.status_code}")

        # Handle 404 specifically - not in database
        if response.status_code == 404:
            if verbose:
                print(f"    [!] Hash not in CIRCL database")
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
            print(f"  [+] Found in CIRCL database!")
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
            logger.info(f"CIRCL: Trusted - {filename} (trust={trust_score})")
        else:
            logger.warning(f"CIRCL: Low trust - {filename} (trust={trust_score})")

        result = (is_trusted, filename, status)

        # Cache the result
        with _whitelist_cache_lock:
            _whitelist_cache[file_hash] = result

        return result

    except requests.exceptions.Timeout:
        if verbose:
            print(f"  [X] Timeout - CIRCL service too slow (>5 seconds)")
        logger.warning(f"CIRCL lookup timeout for {file_hash[:16]}...")
        return (False, None, 'error')

    except requests.exceptions.ConnectionError:
        if verbose:
            print(f"  [X] Connection failed - network or firewall issue")
        logger.warning("CIRCL service unavailable")
        return (False, None, 'error')

    except requests.exceptions.HTTPError as e:
        if verbose:
            print(f"  [X] HTTP Error: {e.response.status_code}")
        logger.error(f"CIRCL HTTP error {e.response.status_code}: {e}")
        return (False, None, 'error')

    except ValueError as e:
        if verbose:
            print(f"  [X] Invalid JSON response from CIRCL")
        logger.error(f"Invalid JSON from CIRCL: {e}")
        result = (False, None, 'error')
        with _whitelist_cache_lock:
            _whitelist_cache[file_hash] = result
        return result

    except Exception as e:
        if verbose:
            print(f"  [X] Unexpected error: {e}")
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


def get_content_heuristics(data: bytes):
    h_list = []
    content = data.decode('utf-8', errors='ignore').lower()

    # Context-aware pattern matching
    patterns = {
        r"powershell.+(-enc|-e|-w\s+hidden|-nop|-exec\s+bypass)": ("PowerShell Obfuscated/Hidden", 5),
        r"(invoke-expression|iex)\s*\(": ("PowerShell Dynamic Execution", 4),
        r"downloadstring|downloadfile": ("PowerShell Downloader", 5),

        r"eval\s*\(": ("Dynamic Code Execution", 3),
        r"exec\s*\(": ("Code Execution", 3),
        r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}": ("Raw IP URL", 3),
        r"cmd.exe.+/c": ("Command Execution", 2),

        r"base64": ("Base64 Encoding Found", 1),
        r"powershell": ("PowerShell Reference", 1),
    }

    for pattern, (label, weight) in patterns.items():
        if re.search(pattern, content):
            h_list.append((f"Content Match: {label}", weight))

    return h_list


def get_scanner():
    global _scanner_instance
    if _scanner_instance is None:
        _scanner_instance = PrismScanner()
    return _scanner_instance

"""
def triage(file_path, data: bytes, scanner=None, api_key=None, file_hash=None, **kwargs):
    file_hash = file_hash or get_file_hash(file_path)
    scanner = scanner or get_scanner()
    is_whitelisted, whitelist_name, whitelist_status = check_circl_whitelist(file_hash)

    if is_whitelisted and whitelist_status == 'trusted':
        logger.info(f"File whitelisted by CIRCL: {whitelist_name}")
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
                "Source": "CIRCL HashLookup",
                "Identified_As": whitelist_name or "Known Legitimate Software",
                "Hash": file_hash,
                "Status": "VERIFIED_TRUSTED"
            },

            "Threat_Indicators": [f"[+] WHITELISTED: {whitelist_name}"],
            "Entropy": shannon_entropy(data),
            "Confidence_Metrics": {
                "Intent_Score": 0,
                "Uncertainty_Score": 0
            }
        }
    # Log if CIRCL check failed (for debugging)
    if whitelist_status == 'error':
        logger.debug(f"CIRCL check failed (network/service issue), proceeding with analysis")
    elif whitelist_status == 'untrusted':
        logger.warning(f"File found in CIRCL but marked UNTRUSTED: {whitelist_name}")

    yara_matches = scanner.scan_bytes(data)
    heuristics = get_content_heuristics(data)
    entropy = shannon_entropy(data)
    reputation = check_malware_bazaar(file_hash, key=api_key)
    parser_tier = str(kwargs.get('parser_tier', 'NONE')).upper()

    intent_score = 0
    uncertainty_score = 0
    indicators = []

    if whitelist_status == 'untrusted':
        intent_score += 3
        indicators.append(f"CIRCL: File known but marked untrusted - {whitelist_name}")

    if yara_matches:
        # Categorize YARA matches by severity
        threat_keywords = ['trojan', 'ransomware', 'backdoor', 'rootkit', 'exploit', 'malware', 'webshell']
        suspicious_keywords = ['packer', 'obfuscator', 'crypter', 'upx', 'suspicious']
        capability_keywords = ['network', 'registry', 'file', 'process', 'injection', 'api']

        threat_matches = []
        suspicious_matches = []
        capability_matches = []

        for match in yara_matches:
            # Skip YARA errors
            if match.startswith('error:'):
                logger.error(f"YARA scan error: {match}")
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
            indicators.append(f"YARA THREAT: {', '.join(threat_matches)}")

        if suspicious_matches:
            intent_score += 4
            indicators.append(f"YARA SUSPICIOUS: {', '.join(suspicious_matches)}")

        if capability_matches and (threat_matches or suspicious_matches):
            intent_score += 2
            indicators.append(f"YARA CAPABILITIES: {', '.join(capability_matches)}")
        elif capability_matches:
            indicators.append(f"YARA CAPABILITIES (low risk): {', '.join(capability_matches)}")

    if reputation:
        intent_score += 15
        indicators.append(f"REPUTATION: {reputation.get('signature', 'Known Malware')}")

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

    if parser_tier == 'MALFORMED':
        uncertainty_score += 7
        indicators.append("STRUCTURAL ANOMALY: Malformed/Truncated Header")

        # Entropy analysis with clearer thresholds
    if entropy > 7.9:
        uncertainty_score += 6
        indicators.append(f"Very High Entropy ({entropy:.2f}): Strong encryption/packing/random data")
    elif entropy > 7.7:
        uncertainty_score += 4
        indicators.append(f"High Entropy ({entropy:.2f}): Compression/packing suspected")
    elif entropy > 7.4:
        uncertainty_score += 2
        indicators.append(f"Moderate-High Entropy ({entropy:.2f}): May indicate packing")

    if entropy > 7.7 and intent_score == 0:
        indicators.append("NOTE: High entropy alone - likely legitimate compressed/encrypted data")

        # Determine final status
    status = "CLEAN"

    if intent_score >= 15:
        status = "MALICIOUS"
    elif intent_score >= 10:
        if uncertainty_score < 5:
            status = "MALICIOUS"
        else:
            status = "SUSPICIOUS"
    elif intent_score >= 5:
        status = "SUSPICIOUS"
    elif intent_score > 0:
        if yara_matches or heuristics:
            status = "SUSPICIOUS"
        else:
            status = "CLEAN"

    # Downgrade if high uncertainty without reputation
    if uncertainty_score >= 7 and status == "MALICIOUS":
        if not reputation:
            status = "SUSPICIOUS"
            indicators.append("VERDICT DOWNGRADED: High uncertainty (FP risk)")

    # Calculate false positive risk
    fp_risk = "LOW"
    if uncertainty_score >= 10:
        fp_risk = "HIGH"
    elif uncertainty_score >= 5:
        fp_risk = "MEDIUM"

    # Format results
    yara_list = [ind for ind in indicators if ind.startswith("YARA")]
    reputation_dict = None
    if reputation:
        reputation_dict = {
            'signature': reputation.get('signature', 'Unknown'),
            'sha256_hash': file_hash,
            'tags': reputation.get('tags', [])
        }

    heuristics_list = [ind for ind in indicators if not ind.startswith("YARA") and not ind.startswith("REPUTATION")]

    return {
        "Status": status,
        "Verdict": status,
        "Score": f"{min(intent_score, 10)}/10",
        "FP_Risk": fp_risk,

        "Yara_Matches": yara_list,
        "Heuristics": heuristics_list,
        "Reputation": reputation_dict,
        "MalwareBazaar_Found": bool(reputation),

        "Threat_Indicators": indicators,
        "Entropy": entropy,
        "Confidence_Metrics": {
            "Intent_Score": intent_score,
            "Uncertainty_Score": uncertainty_score
        }
    }
"""


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

            "Threat_Indicators": [f"✓ TRUSTED: {whitelist_result['details']}"],
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
        trust_note = f"[!]  {whitelist_result['details']}"
        trust_adjustment = 5  # Require higher score to flag
        logger.info(f"Medium trust file, analyzing: {file_path}")

    # Proceed with normal threat analysis
    yara_matches = scanner.scan_bytes(data)
    heuristics = get_content_heuristics(data)
    entropy = shannon_entropy(data)
    reputation = check_malware_bazaar(file_hash, key=api_key)
    parser_tier = str(kwargs.get('parser_tier', 'NONE')).upper()

    intent_score = 0
    uncertainty_score = 0
    indicators = []

    # Add trust note
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

    # Determine status with trust adjustment
    status = "CLEAN"

    if intent_score >= (15 + trust_adjustment):
        status = "MALICIOUS"
    elif intent_score >= (10 + trust_adjustment):
        if uncertainty_score < 5:
            status = "MALICIOUS"
        else:
            status = "SUSPICIOUS"
    elif intent_score >= (5 + trust_adjustment):
        status = "SUSPICIOUS"
    elif intent_score > trust_adjustment:
        if yara_matches or heuristics:
            status = "SUSPICIOUS"
        else:
            status = "CLEAN"

    # Downgrade if high uncertainty without reputation
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
                       and not ind.startswith("ℹ️  Note:")
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

        "Whitelist_Info": {
            "Checked": True,
            "Status": whitelist_result["trust_level"],
            "Details": whitelist_result["details"],
            "Confidence": f"{whitelist_result['confidence'] * 100:.0f}%"
        } if not whitelist_result.get("is_trusted") or whitelist_result["confidence"] < 0.80 else None,

        "Threat_Indicators": indicators,
        "Entropy": entropy,
        "Confidence_Metrics": {
            "Intent_Score": intent_score,
            "Uncertainty_Score": uncertainty_score,
            "Trust_Adjustment": trust_adjustment
        }
    }