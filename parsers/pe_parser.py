import pefile
import os
from core.scanner import triage, shannon_entropy


def analyze_pe(file_path):
    try:
        pe = pefile.PE(file_path)
    except (pefile.PEFormatError, Exception):

        try:
            with open(file_path, "rb") as f:
                raw_data = f.read()

            entropy_val = shannon_entropy(raw_data)

            return {
                "File": file_path,
                "Triggers": ["MALFORMED PE HEADER: Analyzed as raw binary"],
                "Stream_Results": [{
                    "Section_Name": "HEADER_CORRUPT_OR_RAW",
                    "Entropy": entropy_val,
                    "Requires_Deep_RE": True if entropy_val > 7.2 else False,
                    "Preview_Bytes": raw_data[:1024]
                }]
            }
        except Exception as e:
            return {"error": f"Critical IO Error: {e}"}

    final_report = {
        "File": file_path,
        "Triggers": [],
        "Stream_Results": []
    }

    suspicious_apis = [
        "VirtualAlloc", "WriteProcessMemory",
        "CreateRemoteThread", "IsDebuggerPresent"
    ]

    if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            for imp in entry.imports:
                if imp.name:
                    name = imp.name.decode('utf-8', errors='ignore')
                    if name in suspicious_apis:
                        final_report["Triggers"].append(f"Suspicious API: {name}")

    # Section Analysis
    for section in pe.sections:
        section_name = section.Name.decode('utf-8', errors='ignore').strip('\x00')
        section_data = section.get_data()

        result = triage(section_data)
        result["Section_Name"] = section_name
        result["Preview_Bytes"] = section_data[:1024]

        if section_name == ".text" and result.get("Requires_Deep_RE"):
            final_report["Triggers"].append("High Entropy Code Section (Likely Packed)")

        final_report["Stream_Results"].append(result)

    return final_report
