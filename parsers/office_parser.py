# extract_macros: Search for VBA macros (the Office equivalent of your PDF /JavaScript triggers).
# extract_ole_streams: Use olefile to pull out embedded binary data.
# analyze_xml_parts: For .docx, check word/embeddings/ for hidden payloads.

import olefile
from core.scanner import triage


def analyze_ole(file_path):
    final_report = {
        "File": file_path,
        "Triggers": [],
        "Stream_Results": []
    }
    if not olefile.isOleFile(file_path):
        return {"error": "Not a valid OLE file"}
    try:
        with olefile.OleFileIO(file_path) as ole:
            # euristic Trigger: Look for Macro storage
            if ole.exists('Macros') or ole.exists('_VBA_PROJECT_CUR'):
                final_report["Triggers"].append("VBA Macro Storage Detected")

            # Extract and Scan All Streams
            # This follows the Prism goal of total visibility
            for stream_path in ole.listdir():
                # listdir returns a list (e.g., ['Macros', 'VBA', 'Module1'])
                # We only want to analyze actual streams (files), not storages (folders)
                if ole.get_type(stream_path) == olefile.STGTY_STREAM:
                    stream_data = ole.openstream(stream_path).read()
                    # Pass the raw stream to Shannon Entropy/YARA engine
                    result = triage(stream_data)
                    result["Stream_Name"] = "/".join(stream_path)

                    final_report["Stream_Results"].append(result)

    except Exception as e:
        return {"error": f"OLE Parsing Error: {e}"}

    return final_report
