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

load_dotenv()

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_API_KEY = os.getenv("BAZAAR_API_KEY")

_scanner_instance = None

_whitelist_cache = {}
_whitelist_cache_lock = threading.Lock()


# Secure session generator upon request
def get_secure_session():
    session = requests.Session()
    session.headers.update({"User-Agent": "Prism-Scanner/1.0 (UserAgent-2025-12-19)"})
    retry_strategy = Retry(total=3, backoff_factor=1, status_forcelist=[429, 500, 502, 503, 504])
    session.mount("https://", HTTPAdapter(max_retries=retry_strategy))
    return session


_session = get_secure_session()


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

    def _compile_all_rules(self):
        valid_rules = {}
        for folder in self.rule_folders:
            if not os.path.exists(folder): continue
            for root, _, files in os.walk(folder):
                for file in files:
                    if file.endswith(('.yar', '.yara')):
                        path = os.path.join(root, file)
                        try:
                            yara.compile(filepath=path)
                            namespace = os.path.basename(root)
                            if namespace in ['rules', 'prism', 'malware', 'maldocs']:
                                namespace = 'gen'
                            valid_rules[f"{namespace}_{file}"] = path
                        except yara.SyntaxError as e:
                            print(f"\033[1;33m[!] Quarantining Broken Rule:\033[0m {file} ({e})")
                            shutil.move(path, os.path.join(self.quarantine_path, file))

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


def check_circl_whitelist(file_hash):
    with _whitelist_cache_lock:
        if file_hash in _whitelist_cache:
            return _whitelist_cache[file_hash]

    url = f"https://hashlookup.circl.lu/lookup/sha256/{file_hash}"
    try:
        response = _session.get(url, timeout=3)
        response.raise_for_status()
        data = response.json()
        trust = data.get("hashlookup:trust", 50)
        result = (trust >= 50), data.get("FileName", "Known System File")

        # Cache result
        with _whitelist_cache_lock:
            _whitelist_cache[file_hash] = result

        return result

    except requests.exceptions.Timeout:
        logger.warning(f"CIRCL lookup timeout for {file_hash[:8]}")
    except requests.exceptions.ConnectionError:
        logger.warning("CIRCL service unavailable")
    except requests.exceptions.HTTPError as e:
        if e.response.status_code != 404:
            logger.error(f"CIRCL HTTP error: {e}")
    except ValueError as e:
        logger.error(f"Invalid JSON from CIRCL: {e}")
    except Exception as e:
        logger.exception(f"Unexpected error in CIRCL lookup: {e}")

    result = (False, None)
    with _whitelist_cache_lock:
        _whitelist_cache[file_hash] = result

    return result


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


def triage(file_path, data: bytes, scanner=None, api_key=None, file_hash=None, **kwargs):
    file_hash = file_hash or get_file_hash(file_path)
    scanner = scanner or get_scanner()

    is_whitelisted, whitelist_name = check_circl_whitelist(file_hash)

    if is_whitelisted:
        # File is in CIRCL trusted database
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
                "Source": "CIRCL HasHLookup",
                "Identified_As": whitelist_name,
                "Hash": file_hash
            },

            "Threat_Indicators": [f"WHITELISTED: {whitelist_name}"],
            "Entropy": shannon_entropy(data),
            "Confidence_Metrics": {
                "Intent_Score": 0,
                "Uncertainty_Score": 0
            }
        }

    yara_matches = scanner.scan_bytes(data)
    heuristics = get_content_heuristics(data)
    entropy = shannon_entropy(data)
    reputation = check_malware_bazaar(file_hash, key=api_key)
    parser_tier = str(kwargs.get('parser_tier', 'NONE')).upper()

    intent_score = 0
    uncertainty_score = 0
    indicators = []

    if yara_matches:
        # Categorize YARA matches by severity
        threat_keywords = ['trojan', 'ransomware', 'backdoor', 'rootkit', 'exploit', 'malware', 'webshell']
        suspicious_keywords = ['packer', 'obfuscator', 'crypter', 'upx', 'suspicious']
        capability_keywords = ['network', 'registry', 'file', 'process', 'injection', 'api']

        threat_matches = []
        suspicious_matches = []
        capability_matches = []

        for match in yara_matches:
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

    if entropy > 7.9:
        uncertainty_score += 6
        indicators.append(f"Very High Entropy ({entropy}): Strong encryption/packing/random data")
    elif entropy > 7.7:
        uncertainty_score += 4
        indicators.append(f"High Entropy ({entropy}): Compression/packing suspected")
    elif entropy > 7.4:
        uncertainty_score += 2
        indicators.append(f"Moderate-High Entropy ({entropy}): May indicate packing")

    if entropy > 7.7 and intent_score == 0:
        indicators.append("NOTE: High entropy alone - likely legitimate compressed/encrypted data")

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

    if uncertainty_score >= 7 and status == "MALICIOUS":
        if not reputation:
            status = "SUSPICIOUS"
            indicators.append("VERDICT DOWNGRADED: High uncertainty (FP risk)")

    fp_risk = "LOW"
    if uncertainty_score >= 10:
        fp_risk = "HIGH"
    elif uncertainty_score >= 5:
        fp_risk = "MEDIUM"

    yara_list = [ind for ind in indicators if ind.startswith("YARA:")]
    reputation_dict = None
    if reputation:
        reputation_dict = {
            'signature': reputation.get('signature', 'Unknown'),
            'sha256_hash': file_hash,
            'tags': reputation.get('tags', [])
        }

    heuristics_list = [ind for ind in indicators if not ind.startswith("YARA:") and not ind.startswith("REPUTATION:")]

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
