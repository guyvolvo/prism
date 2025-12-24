import pefile
import os
from core.scanner import shannon_entropy

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
                "Status": "CRITICAL" if entropy_val > 7.2 else "SUSPICIOUS",  # Added Status
                "Triggers": ["MALFORMED PE HEADER: Analyzed as raw binary"],
                "Stream_Results": [{
                    "Section_Name": "HEADER_CORRUPT_OR_RAW",
                    "Entropy": entropy_val,
                    "Requires_Deep_RE": True if entropy_val > 7.2 else False,
                    "Preview_Bytes": raw_data[:1024]
                }]
            }
        except Exception as e:
            return {"Status": "ERROR", "error": f"Critical IO Error: {e}"}

    final_report = {
        "File": file_path,
        "Triggers": [],
        "Stream_Results": [],
        "Status": "CLEAN"
    }

    overlay_offset = pe.get_overlay_data_start_offset()
    if overlay_offset:
        overlay_size = len(pe.get_overlay())
        if overlay_size > 102400:
            final_report["Triggers"].append(f"LARGE OVERLAY DETECTED: {overlay_size} bytes")

    suspicious_apis = [
        "VirtualAlloc", "WriteProcessMemory",
        "CreateRemoteThread", "IsDebuggerPresent", "VirtualProtect"
    ]

    if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            for imp in entry.imports:
                if imp.name:
                    name = imp.name.decode('utf-8', errors='ignore')
                    if name in suspicious_apis:
                        final_report["Triggers"].append(f"Suspicious API: {name}")

    standard_sections = [".text", ".data", ".rdata", ".idata", ".rsrc", ".reloc"]

    for section in pe.sections:
        section_name = section.Name.decode('utf-8', errors='ignore').strip('\x00')
        section_data = section.get_data()
        entropy = section.get_entropy()

        if section_name and section_name not in standard_sections:
            final_report["Triggers"].append(f"UNUSUAL SECTION NAME: {section_name}")

        result = {
            "Section_Name": section_name,
            "Entropy": round(entropy, 2),
            "Size": len(section_data),
            "Requires_Deep_RE": True if entropy > 7.4 else False,
            "Preview_Bytes": section_data[:64]
        }

        if section_name == ".text" and result["Requires_Deep_RE"]:
            final_report["Triggers"].append(f"Packed/Encrypted Code Section: {section_name}")

        final_report["Stream_Results"].append(result)

    if any("Packed" in t or "Suspicious API" in t for t in final_report["Triggers"]):
        final_report["Status"] = "CRITICAL"
    elif final_report["Triggers"]:
        final_report["Status"] = "SUSPICIOUS"

    return final_report