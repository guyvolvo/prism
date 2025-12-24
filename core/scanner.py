import base64
import os
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


_session = get_secure_session()


def get_file_hash(file_path):
    sha256_hash = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(65536), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except Exception:
        return None


def check_circl_whitelist(file_hash):
    url = f"https://hashlookup.circl.lu/lookup/sha256/{file_hash}"
    try:
        response = _session.get(url, timeout=3)
        if response.status_code == 200:
            data = response.json()
            trust = data.get("hashlookup:trust", 50)
            if trust >= 50:
                return True, data.get("FileName", "Known System File")
    except:
        pass
    return False, None


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
    patterns = {
        r"powershell": "PowerShell",
        r"eval\(": "Dynamic Code",
        r"base64": "Encoded Payload",
        r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}": "Raw IP Downloader"
    }
    for pattern, label in patterns.items():
        if re.search(pattern, content):
            h_list.append(f"Content Match: {label}")
    return h_list


def get_scanner():
    global _scanner_instance
    if _scanner_instance is None:
        _scanner_instance = PrismScanner()
    return _scanner_instance


def triage(file_path, data: bytes, scanner=None, api_key=None, **kwargs):
    file_hash = get_file_hash(file_path)

    is_safe, info = check_circl_whitelist(file_hash)
    if is_safe:
        return {"Status": "TRUSTED", "Verdict": "CLEAN", "Score": "0/10", "Yara_Matches": [], "Heuristics": []}

    scanner = scanner or get_scanner()
    yara_matches = scanner.scan_bytes(data)
    heuristics = get_content_heuristics(data)
    entropy = shannon_entropy(data)
    reputation = check_malware_bazaar(file_hash, key=api_key)


    has_signature = len(yara_matches) > 0
    has_reputation = reputation is not None


    parser_status = str(kwargs.get('parser_status', 'CLEAN')).upper()
    is_anomaly = parser_status in ["CRITICAL", "MALICIOUS", "SUSPICIOUS"]
    is_high_entropy = entropy > 7.5

    if has_signature or has_reputation:
        status = "MALICIOUS"
        score_val = 10
    elif is_anomaly or is_high_entropy or heuristics:
        status = "SUSPICIOUS"
        score_val = 6
    else:
        status = "CLEAN"
        score_val = 0

    return {
        "Status": status,
        "Verdict": status,
        "Score": f"{score_val}/10",
        "score": score_val,
        "Entropy": entropy,
        "Yara_Matches": yara_matches,
        "Heuristics": heuristics,
        "Reputation": reputation
    }