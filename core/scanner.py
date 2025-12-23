import os
import yara
import math
import re
from collections import Counter

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class PrismScanner:
    def __init__(self):
        self.rule_folders = [
            os.path.join(BASE_DIR, "malware"),
            os.path.join(BASE_DIR, "maldocs")
        ]
        print(f"[*] Initializing Scanner. Searching in: {', '.join(self.rule_folders)}")
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
                if namespace == 'rules' or namespace == 'prism': namespace = 'general'
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
            matches = self.rules.match(data=data)
            return [f"{m.namespace}:{m.rule}" for m in matches]
        except Exception:
            return []


scanner_instance = PrismScanner()


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
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

    # Advanced Patterns for Shell Scripts & Malware
    patterns = {
        "powershell": "PowerShell Execution",
        "eval(": "Dynamic Code Execution",
        "base64": "Encoded Payload",
        "http": "Network/URL String",
        "eicar": "EICAR Test String",
        "cmd.exe": "Shell Spawn",
        "curl": "Downloader (curl)",
        "wget": "Downloader (wget)",
        "chmod +x": "Permission Escalation (chmod)",
        "| sh": "Pipe to Shell",
        "| bash": "Pipe to Shell",
        "/dev/tcp/": "Potential Reverse Shell"
    }

    if re.search(r'https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', content):
        h_list.append("Critical: Raw IP Downloader Found")

    for key, label in patterns.items():
        if key in content.lower():
            h_list.append(f"Content Match: {label}")

    return h_list


def triage(data: bytes, scanner=None, heuristics=None):
    if scanner is None:
        scanner = scanner_instance
    if heuristics is None:
        heuristics = []

    found_heuristics = get_content_heuristics(data)
    heuristics.extend(found_heuristics)
    entropy_score = shannon_entropy(data)
    yara_matches = scanner.scan_bytes(data)

    score = 0

    if yara_matches:
        score += 10

    if entropy_score > 7.8:
        score += 5
    elif entropy_score > 7.2:
        score += 2

    for h in found_heuristics:
        if "Critical" in h:
            score += 6
        elif "Pipe to Shell" in h:
            score += 4
        elif "Downloader" in h:
            score += 3
        else:
            score += 2

    status = "CLEAN"
    if score >= 5:
        status = "CRITICAL"
    elif score >= 2:
        status = "SUSPICIOUS"

    return {
        "Entropy": entropy_score,
        "YARA_Matches": yara_matches,
        "Score": score,
        "Heuristics": heuristics,
        "Requires_Deep_RE": score >= 5,
        "Status": status
    }