# Portable executables parser
# extract_sections: Use the pefile library to iterate through .text, .data, and .rsrc.
# check_imports: Look for suspicious API calls like VirtualAlloc or WriteProcessMemory.
# find_overlay: Check for extra data appended to the end of the file, -
# - a common place for malware to hide its payload.

# Integration with scanner.py
# For a PE file, you shouldn't just run entropy on the whole file. You should run it per section:
# .text section (code): High entropy (e.g., > 7.0) here strongly suggests a Packed or Encrypted executable.
# .rsrc section: High entropy here often means an encrypted secondary payload is being stored as a resource.

import pefile
from core.scanner import triage


def analyze_pe(file_path):
    try:
        pe = pefile.PE(file_path)
    except Exception as e:
        return {"error": f"Failed to parse PE {e}"}

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

    # 2. Section Analysis (The Entropy Engine)
    # We scan each section individually to find hidden payloads
    for section in pe.sections:
        # Clean the section name
        section_name = section.Name.decode('utf-8', errors='ignore').strip('\x00')
        section_data = section.get_data()

        # Pass the raw section bytes to triage engine
        result = triage(section_data)
        result["Section_Name"] = section_name

        # If .text is high entropy, it's almost certainly packed
        if section_name == ".text" and result["Requires_Deep_RE"]:
            final_report["Triggers"].append("High Entropy Code Section (Likely Packed)")

        final_report["Stream_Results"].append(result)

    return final_report
