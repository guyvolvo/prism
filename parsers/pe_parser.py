import pefile
import os
from core.scanner import shannon_entropy


def analyze_pe(file_path):
    try:
        pe = pefile.PE(file_path)
    except (pefile.PEFormatError, Exception):
        # Malformed PE - analyze as raw binary
        try:
            with open(file_path, "rb") as f:
                raw_data = f.read()

            entropy_val = shannon_entropy(raw_data)

            return {
                "File": file_path,
                "Status": "CRITICAL" if entropy_val > 7.2 else "SUSPICIOUS",
                "Triggers": ["MALFORMED PE HEADER: Could not parse as valid PE"],
                "Stream_Results": [{
                    "Section_Name": "RAW_BINARY_ANALYSIS",
                    "Entropy": entropy_val,
                    "Requires_Deep_RE": entropy_val > 7.2,
                    "Preview_Bytes": raw_data[:1024]
                }]
            }
        except Exception as e:
            return {
                "Status": "ERROR",
                "error": f"Critical IO Error: {e}",
                "Triggers": ["Cannot read file"]
            }

    final_report = {
        "File": file_path,
        "Triggers": [],
        "Stream_Results": [],
        "Status": "CLEAN",
        "PE_Metadata": {}
    }

    try:
        timestamp = pe.FILE_HEADER.TimeDateStamp
        final_report["PE_Metadata"]["Compilation_Time"] = timestamp

        subsystem = pe.OPTIONAL_HEADER.Subsystem
        final_report["PE_Metadata"]["Subsystem"] = subsystem

        entry_point = pe.OPTIONAL_HEADER.AddressOfEntryPoint
        final_report["PE_Metadata"]["EntryPoint"] = hex(entry_point)

    except Exception:
        pass

    overlay_offset = pe.get_overlay_data_start_offset()
    if overlay_offset:
        overlay_size = len(pe.get_overlay())

        if overlay_size > 102400:  # > 100KB
            final_report["Triggers"].append(
                f"LARGE OVERLAY DETECTED: {overlay_size} bytes (possible packer data)"
            )
        elif overlay_size > 0:
            final_report["Triggers"].append(
                f"Overlay Present: {overlay_size} bytes"
            )

    # HIGH RISK: Memory injection, process manipulation
    high_risk_apis = [
        "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread",
        "NtCreateThreadEx", "RtlCreateUserThread", "QueueUserAPC",
        "SetWindowsHookEx", "VirtualProtect", "VirtualProtectEx"
    ]

    # MEDIUM RISK: Debugging, anti-analysis
    medium_risk_apis = [
        "IsDebuggerPresent", "CheckRemoteDebuggerPresent",
        "NtQueryInformationProcess", "OutputDebugString",
        "GetTickCount", "QueryPerformanceCounter"
    ]

    # LOW RISK: Network, registry
    low_risk_apis = [
        "InternetOpen", "InternetOpenUrl", "URLDownloadToFile",
        "RegSetValue", "RegSetValueEx", "RegDeleteKey"
    ]

    high_risk_found = []
    medium_risk_found = []
    low_risk_found = []

    if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            for imp in entry.imports:
                if imp.name:
                    name = imp.name.decode('utf-8', errors='ignore')

                    if name in high_risk_apis:
                        high_risk_found.append(name)
                    elif name in medium_risk_apis:
                        medium_risk_found.append(name)
                    elif name in low_risk_apis:
                        low_risk_found.append(name)

    if high_risk_found:
        final_report["Triggers"].append(
            f"HIGH RISK APIs: {', '.join(high_risk_found[:5])}"
        )
    if medium_risk_found:
        final_report["Triggers"].append(
            f"MEDIUM RISK APIs (Anti-Debug): {', '.join(medium_risk_found[:3])}"
        )
    if low_risk_found and len(high_risk_found) > 0:
        final_report["Triggers"].append(
            f"Network/Registry APIs: {', '.join(low_risk_found[:3])}"
        )

    standard_sections = [".text", ".data", ".rdata", ".idata", ".edata", ".rsrc", ".reloc",
                         ".pdata",
                         ".didat",
                         ".tls",
                         "BSS", "CODE", "DATA"]

    for section in pe.sections:
        section_name = section.Name.decode('utf-8', errors='ignore').strip('\x00')
        section_data = section.get_data()
        entropy = section.get_entropy()

        if section_name and section_name not in standard_sections:
            packer_sections = ['UPX0', 'UPX1', 'UPX2', '.aspack', '.adata',
                               '.petite', '.packed', '.nsp0', '.nsp1']

            if any(packer in section_name.lower() for packer in packer_sections):
                final_report["Triggers"].append(
                    f"PACKER SECTION DETECTED: {section_name}"
                )
            else:
                final_report["Triggers"].append(
                    f"UNUSUAL SECTION NAME: {section_name}"
                )

        result = {
            "Section_Name": section_name,
            "Entropy": round(entropy, 2),
            "Size": len(section_data),
            "Requires_Deep_RE": entropy > 7.4,
            "Preview_Bytes": section_data[:64]
        }

        if section_name == ".text" and entropy > 7.4:
            final_report["Triggers"].append(
                f"PACKED/ENCRYPTED CODE SECTION (.text): Entropy {entropy:.2f}"
            )

        characteristics = section.Characteristics
        is_executable = characteristics & 0x20000000
        is_writable = characteristics & 0x80000000

        if is_executable and is_writable and section_name != ".text":
            final_report["Triggers"].append(
                f"WRITABLE+EXECUTABLE SECTION: {section_name} (RWX)"
            )

        final_report["Stream_Results"].append(result)

    critical_triggers = [t for t in final_report["Triggers"]
                         if any(x in t for x in ["PACKED", "HIGH RISK", "MALFORMED", "RWX"])]

    suspicious_triggers = [t for t in final_report["Triggers"]
                           if any(x in t for x in ["UNUSUAL", "OVERLAY", "MEDIUM RISK"])]

    if len(critical_triggers) >= 2:
        final_report["Status"] = "SUSPICIOUS"
    elif critical_triggers:
        final_report["Status"] = "SUSPICIOUS"
    elif suspicious_triggers:
        final_report["Status"] = "ANALYZED"
    else:
        final_report["Status"] = "CLEAN"

    return final_report
