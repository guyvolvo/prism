import PyPDF2
from PyPDF2 import PdfReader
from core.scanner import triage


def pdf_data(file_path):
    reader = PdfReader(file_path)

    report_data = {"triggers": find_javascript_triggers(reader), "streams_analysis": []}

    for page in reader.pages:
        content = page.get_contents()
        if content:
            try:
                data = content.get_data() if not isinstance(content, list) else b"".join(
                    [c.get_data() for c in content])
                analysis = triage(data)
                report_data["streams_analysis"].append(analysis)
            except Exception:
                continue

    return report_data


def find_javascript_triggers(reader):
    triggers_found = []
    try:
        catalog = reader.trailer["/Root"]

        if "/Names" in catalog and "/JavaScript" in catalog["/Names"]:
            triggers_found.append("Embedded JavaScript Name")
        if "/OpenAction" in catalog:
            triggers_found.append("Auto-Run OpenAction")
        if "/JS" in catalog or "/JavaScript" in catalog:
            triggers_found.append("Direct JavaScript Entry")
    except Exception:
        pass
    return triggers_found


def extract_streams(reader):
    streams_data = []
    for obj_index in range(1, len(reader.xref)):
        try:
            obj = reader.get_object(obj_index)
            # If the object is a stream (contains data)
            if hasattr(obj, "get_data"):
                raw_bytes = obj.get_data()
                streams_data.append(raw_bytes)

        except Exception:
            continue

    return streams_data


def analyze_pdf(file_path):
    reader = PdfReader(file_path)

    # Get triggers (Heuristics)
    triggers = find_javascript_triggers(reader)

    # Get streams and run through scanner.py
    streams = extract_streams(reader)

    final_report = {
        "File": file_path,
        "Triggers": triggers,
        "Stream_Results": []
    }

    for data in streams:
        # calls Shannon Entropy + YARA logic
        result = triage(data)
        final_report["Stream_Results"].append(result)

    return final_report