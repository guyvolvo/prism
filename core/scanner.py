import os
import yara
import math
import re
import requests
import time
from collections import Counter
from dotenv import load_dotenv
from requests.adapters import HTTPAdapter
from urllib3.util import Retry

load_dotenv()

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_API_KEY = os.getenv("BAZAAR_API_KEY")


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
        print(f"[*] Initializing Scanner. Rule folders: {', '.join(self.rule_folders)}")
        self.rules = self._compile_all_rules()

    def _compile_all_rules(self):
        rule_map = {}
        valid_rules = {}

        for folder in self.rule_folders:
            if not os.path.exists(folder): continue
            for root, _, files in os.walk(folder):
                for file in files:
                    if file.endswith(('.yar', '.yara')):
                        path = os.path.join(root, file)
                        rule_map[path] = file

        for path, name in rule_map.items():
            try:
                yara.compile(filepath=path)
                namespace = os.path.basename(os.path.dirname(path))
                if namespace in ['rules', 'prism']: namespace = 'general'
                valid_rules[f"{namespace}_{name}"] = path
            except yara.SyntaxError:
                print(f"\033[1;33m[!] Skipping Broken Rule:\033[0m {name}")
                continue

        if not valid_rules:
            return None

        try:
            compiled = yara.compile(filepaths=valid_rules)
            print(f"[+] Successfully compiled {len(valid_rules)} YARA rules.")
            return compiled
        except Exception as e:
            print(f"[!] Critical Compiler Error: {e}")
            return None

    def scan_bytes(self, data: bytes):
        if not self.rules:
            return []
        try:
            matches = self.rules.match(data=data, fast=True, timeout=15)
            return [f"{m.namespace}:{m.rule}" for m in matches]
        except yara.TimeoutError:
            print("[!] YARA Scan timed out.")
            return ["error:scan_timeout"]
        except Exception as e:
            return [f"error:{str(e)}"]


def get_secure_session():
    session = requests.Session()
    retry_strategy = Retry(
        total=3,
        backoff_factor=1,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["POST"]
    )
    adapter = HTTPAdapter(max_retries=retry_strategy)
    session.mount("https://", adapter)
    return session


_session = get_secure_session()


def check_malware_bazaar(file_hash: str, key: str = None):
    """
    Queries MalwareBazaar for hash reputation
    """
    active_key = key or DEFAULT_API_KEY

    if not active_key:
        return None

    active_key = active_key.strip("'").strip('"')

    url = "https://mb-api.abuse.ch/api/v1/"
    headers = {
        "Auth-Key": active_key,
        "User-Agent": "Prism-Malware-Scanner/1.0"
    }

    query_data = {
        'query': 'get_info',
        'hash': file_hash
    }

    try:
        response = _session.post(url, data=query_data, headers=headers, timeout=5)
        if response.status_code == 200:
            res_json = response.json()
            if res_json.get('query_status') == 'ok':
                return res_json['data'][0]
    except Exception as e:
        print(f"[!] MalwareBazaar Connection Error: {e}")

    return None


def shannon_entropy(data: bytes) -> float:
    if not data: return 0.0
    length = len(data)
    counts = Counter(data)
    entropy = 0.0
    for count in counts.values():
        prob = count / length
        entropy -= prob * math.log2(prob)
    return round(entropy, 2)


def get_content_heuristics(data: bytes):
    h_list = []
    content = data.decode('utf-8', errors='ignore')
    patterns = {
        "powershell": "PowerShell Execution",
        "eval(": "Dynamic Code Execution",
        "base64": "Encoded Payload",
        "http": "Network/URL String",
        "cmd.exe": "Shell Spawn",
        "/dev/tcp/": "Potential Reverse Shell"
    }
    if re.search(r'https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', content):
        h_list.append("Critical: Raw IP Downloader Found")
    for key, label in patterns.items():
        if key in content.lower():
            h_list.append(f"Content Match: {label}")
    return h_list


_scanner_instance = None


def get_scanner():
    global _scanner_instance
    if _scanner_instance is None:
        _scanner_instance = PrismScanner()
    return _scanner_instance


def triage(data: bytes, scanner=None, heuristics=None, file_hash=None, api_key=None):
    if scanner is None:
        scanner = get_scanner()
    if heuristics is None:
        heuristics = []

    found_heuristics = get_content_heuristics(data)
    heuristics.extend(found_heuristics)
    entropy_score = shannon_entropy(data)
    yara_matches = scanner.scan_bytes(data)

    score = 0
    reputation_info = None

    if file_hash:
        reputation_info = check_malware_bazaar(file_hash, key=api_key)
        if reputation_info:
            score += 25
            sig = reputation_info.get('signature') or 'Unknown'
            heuristics.append(f"REPUTATION: Known Malware Found ({sig})")
        time.sleep(0.5)

    if yara_matches: score += 10
    if entropy_score > 7.2: score += 2

    status = "CLEAN"
    if score >= 10:
        status = "CRITICAL"
    elif score >= 2:
        status = "SUSPICIOUS"

    return {
        "Entropy": entropy_score,
        "YARA_Matches": yara_matches,
        "Score": score,
        "Heuristics": heuristics,
        "Reputation": reputation_info,
        "Status": status
    }