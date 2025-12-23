import os
import yara
import math
from collections import Counter


class PrismScanner:
    def __init__(self, rules_dir="rules"):
        self.rules = self._compile_all_rules(rules_dir)

    def _compile_all_rules(self, base_dir):
        rule_map = {}
        if not os.path.exists(base_dir):
            return None

        for root, _, files in os.walk(base_dir):
            for file in files:
                if file.endswith(('.yar', '.yara')):
                    full_path = os.path.join(root, file)
                    namespace = os.path.basename(root)
                    rule_key = f"{namespace}_{file}"
                    rule_map[rule_key] = full_path

        try:
            return yara.compile(filepaths=rule_map) if rule_map else None
        except yara.SyntaxError as e:
            print(f"\033[1;31m[!] YARA Compile Error:\033[0m {e}")
            return None

    def scan_bytes(self, data: bytes):
        if not self.rules:
            return []
        try:
            matches = self.rules.match(data=data)
            return [f"{m.namespace}:{m.rule}" for m in matches]
        except Exception:
            return []


scanner_instance = PrismScanner("rules")


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
    patterns = {
        "powershell": "PowerShell Execution",
        "eval(": "Dynamic Code Execution",
        "base64": "Encoded Payload",
        "http": "Network/URL String",
        "eicar": "EICAR Test String",
        "cmd.exe": "Shell Spawn"
    }

    for key, label in patterns.items():
        if key in content.lower():
            h_list.append(f"Content Match: {label}")

    return h_list


def triage(data: bytes, scanner=None, heuristics=None):
    if scanner is None:
        scanner = scanner_instance
    if heuristics is None:
        heuristics = []
    heuristics.extend(get_content_heuristics(data))

    entropy_score = shannon_entropy(data)
    yara_matches = scanner.scan_bytes(data)
    score = 0

    if len(yara_matches) > 0:
        score += 10

    if entropy_score > 7.8:
        score += 3
    elif entropy_score > 7.2:
        score += 1

    if heuristics:
        score += (len(heuristics) * 2)

    if "MALFORMED PE HEADER" in heuristics:
        score += 4

    is_critical = score >= 7
    is_suspicious = score >= 3

    return {
        "Entropy": entropy_score,
        "YARA_Matches": yara_matches,
        "Score": score,
        "Heuristics": heuristics,
        "Requires_Deep_RE": is_critical,
        "Status": "CRITICAL" if is_critical else ("SUSPICIOUS" if is_suspicious else "CLEAN")
    }