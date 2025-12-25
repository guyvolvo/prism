import olefile
import zipfile
import os

from core.scanner import triage, get_scanner


def analyze_office(file_path, api_key=None):

    if olefile.isOleFile(file_path):
        return analyze_legacy_ole(file_path, api_key)
    if zipfile.is_zipfile(file_path):
        return analyze_modern_xml(file_path, api_key)
    return {"Status": "CLEAN", "error": "Unsupported or corrupt Office format"}


def analyze_legacy_ole(file_path, api_key=None):

    final_report = {
        "File": os.path.basename(file_path),
        "Format": "OLE2 (Legacy)",
        "Triggers": [],
        "Stream_Results": [],
        "Status": "CLEAN"
    }

    scanner = get_scanner()

    try:
        with olefile.OleFileIO(file_path) as ole:
            # Check for VBA macros
            if ole.exists('Macros') or ole.exists('_VBA_PROJECT_CUR'):
                final_report["Triggers"].append("VBA Macro Storage Detected")

            # Additional macro detection paths
            macro_paths = ['VBA', 'Macros', '_VBA_PROJECT']
            for path in macro_paths:
                if ole.exists(path):
                    final_report["Triggers"].append(f"Macro Storage Found: {path}")

            # Analyze each stream
            for stream_path in ole.listdir():
                if ole.get_type(stream_path) == olefile.STGTY_STREAM:
                    try:
                        stream_data = ole.openstream(stream_path).read()

                        # Skip empty streams
                        if len(stream_data) == 0:
                            continue

                        result = triage(
                            file_path=file_path,
                            data=stream_data,
                            scanner=scanner,
                            api_key=api_key
                        )

                        result["Section_Name"] = "/".join(stream_path)
                        final_report["Stream_Results"].append(result)

                        # Escalate based on stream verdict
                        stream_status = result.get("Status", "CLEAN")
                        if stream_status == "MALICIOUS":
                            final_report["Triggers"].append(
                                f"Malicious Content in Stream: {result['Section_Name']}"
                            )
                        elif stream_status == "SUSPICIOUS":
                            final_report["Triggers"].append(
                                f"Suspicious Content in Stream: {result['Section_Name']}"
                            )

                    except Exception as e:
                        # Log stream parsing errors but continue
                        final_report["Triggers"].append(
                            f"Error parsing stream {'/'.join(stream_path)}: {str(e)[:50]}"
                        )

        # Determine final status based on findings
        malicious_count = sum(1 for r in final_report["Stream_Results"]
                              if r.get("Status") == "MALICIOUS")
        suspicious_count = sum(1 for r in final_report["Stream_Results"]
                               if r.get("Status") == "SUSPICIOUS")

        if malicious_count > 0:
            final_report["Status"] = "MALICIOUS"
        elif suspicious_count > 0 or any("Macro" in t for t in final_report["Triggers"]):
            final_report["Status"] = "SUSPICIOUS"
        elif final_report["Triggers"]:
            final_report["Status"] = "SUSPICIOUS"

    except olefile.OleFileError as e:
        return {
            "Status": "ERROR",
            "error": f"OLE Parsing Error: {e}",
            "Triggers": ["Corrupt OLE Structure"]
        }
    except Exception as e:
        return {
            "Status": "ERROR",
            "error": f"Unexpected error: {e}",
            "Triggers": ["Analysis Failed"]
        }

    return final_report


def analyze_modern_xml(file_path, api_key=None):
    """
    Analyze modern Office files (OOXML format: .docx, .xlsx, .pptx).
    """
    final_report = {
        "File": os.path.basename(file_path),
        "Format": "OOXML (Modern ZIP)",
        "Triggers": [],
        "Stream_Results": [],
        "Status": "CLEAN"
    }

    # Get scanner instance once
    scanner = get_scanner()

    try:
        with zipfile.ZipFile(file_path, 'r') as z:
            # Check for VBA macros in modern format
            for name in z.namelist():
                if "vbaProject.bin" in name.lower():
                    final_report["Triggers"].append(f"VBA Macro Binary Found: {name}")

                # Check for potentially dangerous embedded content
                suspicious_parts = [
                    'word/embeddings/',
                    'xl/embeddings/',
                    'ppt/embeddings/',
                    'word/media/',
                    'xl/media/',
                    'ppt/media/',
                    'activeX',
                    'customUI'
                ]

                if any(target in name.lower() for target in suspicious_parts):
                    try:
                        data = z.read(name)

                        if len(data) < 100:
                            continue

                        result = triage(
                            file_path=file_path,
                            data=data,
                            scanner=scanner,
                            api_key=api_key
                        )

                        result["Section_Name"] = name
                        final_report["Stream_Results"].append(result)

                        stream_status = result.get("Status", "CLEAN")
                        if stream_status == "MALICIOUS":
                            final_report["Triggers"].append(
                                f"Malicious Content in ZIP Part: {name}"
                            )
                        elif stream_status == "SUSPICIOUS":
                            final_report["Triggers"].append(
                                f"Suspicious Content in ZIP Part: {name}"
                            )

                    except Exception as e:
                        final_report["Triggers"].append(
                            f"Error reading {name}: {str(e)[:50]}"
                        )

        # Determine final status
        malicious_count = sum(1 for r in final_report["Stream_Results"]
                              if r.get("Status") == "MALICIOUS")
        suspicious_count = sum(1 for r in final_report["Stream_Results"]
                               if r.get("Status") == "SUSPICIOUS")

        if malicious_count > 0:
            final_report["Status"] = "MALICIOUS"
        elif suspicious_count > 0 or any("Macro" in t for t in final_report["Triggers"]):
            final_report["Status"] = "SUSPICIOUS"
        elif final_report["Triggers"]:
            final_report["Status"] = "SUSPICIOUS"

    except zipfile.BadZipFile:
        return {
            "Status": "ERROR",
            "error": "Corrupt ZIP/OOXML structure",
            "Triggers": ["Bad ZIP Format"]
        }
    except Exception as e:
        return {
            "Status": "ERROR",
            "error": f"OOXML Analysis Error: {e}",
            "Triggers": ["Analysis Failed"]
        }

    return final_report