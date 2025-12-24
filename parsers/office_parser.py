import olefile
import zipfile
import os

from core.scanner import triage


def analyze_office(file_path):
    if olefile.isOleFile(file_path):
        return analyze_legacy_ole(file_path)
    if zipfile.is_zipfile(file_path):
        return analyze_modern_xml(file_path)
    return {"Status": "CLEAN", "error": "Unsupported or corrupt Office format"}


def analyze_legacy_ole(file_path):
    final_report = {
        "File": os.path.basename(file_path),
        "Format": "OLE2 (Legacy)",
        "Triggers": [],
        "Stream_Results": [],
        "Status": "CLEAN"
    }
    try:
        with olefile.OleFileIO(file_path) as ole:
            if ole.exists('Macros') or ole.exists('_VBA_PROJECT_CUR'):
                final_report["Triggers"].append("VBA Macro Storage Detected")

            for stream_path in ole.listdir():
                if ole.get_type(stream_path) == olefile.STGTY_STREAM:
                    stream_data = ole.openstream(stream_path).read()

                    result = triage(file_path=file_path, data=stream_data)
                    result["Section_Name"] = "/".join(stream_path)
                    final_report["Stream_Results"].append(result)

                    if result.get("Status") == "CRITICAL":
                        final_report["Triggers"].append(f"Malicious Content in Stream: {result['Section_Name']}")

        if any("Macro" in t or "Malicious" in t for t in final_report["Triggers"]):
            final_report["Status"] = "CRITICAL"
        elif final_report["Triggers"]:
            final_report["Status"] = "SUSPICIOUS"

    except Exception as e:
        return {"Status": "ERROR", "error": f"OLE Parsing Error: {e}"}

    return final_report


def analyze_modern_xml(file_path):
    final_report = {
        "File": os.path.basename(file_path),
        "Format": "OOXML (Modern ZIP)",
        "Triggers": [],
        "Stream_Results": [],
        "Status": "CLEAN"
    }
    try:
        with zipfile.ZipFile(file_path, 'r') as z:
            for name in z.namelist():
                if "vbaProject.bin" in name.lower():
                    final_report["Triggers"].append(f"VBA Macro Binary Found: {name}")

                suspicious_parts = ['word/embeddings/', 'xl/embeddings/', 'ppt/embeddings/', 'bin', 'media/']
                if any(target in name.lower() for target in suspicious_parts):
                    data = z.read(name)

                    result = triage(file_path=file_path, data=data)
                    result["Section_Name"] = name
                    final_report["Stream_Results"].append(result)

                    if result.get("Status") != "CLEAN":
                        final_report["Triggers"].append(f"Malicious Content in ZIP Part: {name}")

        if any("Macro" in t or "Malicious" in t for t in final_report["Triggers"]):
            final_report["Status"] = "CRITICAL"
        elif final_report["Triggers"]:
            final_report["Status"] = "SUSPICIOUS"

    except Exception as e:
        return {"Status": "ERROR", "error": f"OOXML Analysis Error: {e}"}

    return final_report