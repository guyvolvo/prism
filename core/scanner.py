# Detection login : YARA + Heuristic scanner
# This is where we implement the Shannon Entropy formula and YARA integration
# https://www.sciencedirect.com/topics/engineering/shannon-entropy
# Although we could use Alexa top 1 million probabilities I think we should
# stick to shannon entropy as it doesn't require pre-calculated probability tables for specific text types
# And we are working with bytes not text'
import yara
import math
from collections import Counter


def shannon_entropy(data: bytes) -> float:
    entropy = 0.0
    if not data:
        return entropy
    length = len(data)
    counts = Counter(data)

    for count in counts.values():
        # P(xi) is probability
        probability = count / length
        entropy -= probability * math.log2(probability)

    return entropy


def yara_scan(data: bytes, rules_path: str):
    try:
        rules = yara.compile(filepath=rules_path)
        matches = rules.match(data=data)
        return matches
    except Exception as e:
        print(f"YARA Error: {e}")
        return []


def triage(data: bytes, yara_rules_path: str = "None"):
    entropy_score = shannon_entropy(data)
    yara_matches = []
    if yara_rules_path and yara_rules_path != "None":
        yara_matches = yara_scan(data, yara_rules_path)

    suspicious = entropy_score > 7.2

    return {
        "Entropy": round(entropy_score, 2),
        "YARA_Matches": [str(m) for m in yara_matches],
        "Requires_Deep_RE": suspicious,
        # Adding a status for better reporting
        "Status": "Critical/Packed" if suspicious else "Standard"
    }
