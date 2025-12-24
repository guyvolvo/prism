import re
import zlib
from PyPDF2 import PdfReader
from core.scanner import triage, get_scanner, shannon_entropy


def brute_force_carve(file_path):
    with open(file_path, "rb") as f:
        data = f.read()

    carved_results = []
    stream_pattern = re.compile(b"stream\r?\n(.*?)\r?\nendstream", re.DOTALL)
    hex_obfuscation = bool(re.search(b"/[#0-9a-fA-F]{2,}", data))

    scanner = get_scanner()

    for idx, match in enumerate(stream_pattern.finditer(data)):
        stream_content = match.group(1)
        try:
            stream_content = zlib.decompress(stream_content)
        except:
            pass

        analysis = triage(file_path=file_path, data=stream_content, scanner=scanner)
        analysis['Section_Name'] = f"Carved_Stream_{idx}"
        analysis['Hex_Obfuscation'] = hex_obfuscation
        carved_results.append(analysis)

    return carved_results


def find_javascript_triggers(reader):
    triggers_found = []
    try:
        catalog = reader.trailer["/Root"]
        if "/Names" in catalog and "/JavaScript" in catalog["/Names"]:
            triggers_found.append("Embedded JavaScript Name")
        if "/OpenAction" in catalog:
            triggers_found.append("Auto-Run OpenAction")

        catalog_keys = str(catalog.keys())
        if "#" in catalog_keys:
            triggers_found.append("Hex-Encoded Catalog Keys (Obfuscation)")
    except Exception:
        pass
    return triggers_found


def analyze_pdf(file_path):
    try:
        reader = PdfReader(file_path)
        triggers = find_javascript_triggers(reader)

        scanner = get_scanner()

        streams_data = []
        for obj_ref in reader.objects:
            try:
                obj = reader.get_object(obj_ref)
                if hasattr(obj, "get_data"):
                    raw_bytes = obj.get_data()
                    analysis = triage(raw_bytes, scanner)
                    analysis['Section_Name'] = f"Object_{obj_ref}"
                    streams_data.append(analysis)
            except:
                continue

        if len(triggers) == 0:
            carved = brute_force_carve(file_path)
            streams_data.extend(carved)

        return {
            "Triggers": triggers,
            "Stream_Results": streams_data
        }
    except Exception as e:
        return {
            "Status": "CRITICAL",
            "Triggers": [f"PDF Structure Corrupt: {str(e)}"],
            "Stream_Results": []
        }
