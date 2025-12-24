import olefile
import zipfile
import os
from core.scanner import triage


def analyze_office(file_path):
    """
    Main entry point for Office analysis. 
    """
    if olefile.isOleFile(file_path):
        return analyze_legacy_ole(file_path)

    if zipfile.is_zipfile(file_path):
        return analyze_modern_xml(file_path)

    return {"error": "Unsupported or corrupt Office format"}


def analyze_legacy_ole(file_path):
    final_report = {
        "File": os.path.basename(file_path),
        "Format": "OLE2 (Legacy)",
        "Triggers": [],
        "Stream_Results": []
    }
    try:
        with olefile.OleFileIO(file_path) as ole:
            if ole.exists('Macros') or ole.exists('_VBA_PROJECT_CUR'):
                final_report["Triggers"].append("VBA Macro Storage Detected")

            for stream_path in ole.listdir():
                if ole.get_type(stream_path) == olefile.STGTY_STREAM:
                    stream_data = ole.openstream(stream_path).read()

                    result = triage(stream_data)
                    result["Stream_Name"] = "/".join(stream_path)
                    final_report["Stream_Results"].append(result)

    except Exception as e:
        return {"error": f"OLE Parsing Error: {e}"}

    return final_report


def analyze_modern_xml(file_path):
    final_report = {
        "File": os.path.basename(file_path),
        "Format": "OOXML (Modern ZIP)",
        "Triggers": [],
        "Stream_Results": []
    }
    try:
        with zipfile.ZipFile(file_path, 'r') as z:
            for name in z.namelist():

                if "vbaProject.bin" in name.lower():
                    final_report["Triggers"].append(f"VBA Macro Binary Found: {name}")

                suspicious_parts = ['word/embeddings/', 'xl/embeddings/', 'ppt/embeddings/', 'bin', 'media/']
                if any(target in name.lower() for target in suspicious_parts):
                    data = z.read(name)

                    result = triage(data)
                    result["Part_Name"] = name
                    final_report["Stream_Results"].append(result)

                    if result.get("Status") != "CLEAN":
                        final_report["Triggers"].append(f"Malicious Content in ZIP Part: {name}")

    except Exception as e:
        return {"error": f"OOXML Analysis Error: {e}"}

    return final_report