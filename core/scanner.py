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


def triage(data: bytes, scanner=None):
    if scanner is None:
        scanner = scanner_instance

    entropy_score = shannon_entropy(data)
    yara_matches = scanner.scan_bytes(data)
    score = 0
    if entropy_score > 7.8:
        score += 2

    if len(yara_matches) > 0:
        score += 5

    is_critical = score >= 5
    is_suspicious = score >= 2

    return {
        "Entropy": entropy_score,
        "YARA_Matches": yara_matches,
        "Requires_Deep_RE": is_critical,
        "Status": "CRITICAL" if is_critical else ("SUSPICIOUS" if is_suspicious else "CLEAN")
    }