import PyPDF2
from PyPDF2 import PdfReader
from core.scanner import triage, scanner_instance


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
    for obj in reader.objects:
        try:
            if hasattr(obj, "get_data"):
                raw_bytes = obj.get_data()

                if len(raw_bytes) > 0:
                    stream_info = {
                        "data": raw_bytes,
                        "filter": str(obj.get('/Filter', '/None')),
                        "type": str(obj.get('/Type', '/Unknown'))
                    }
                    streams_data.append(stream_info)
        except Exception:
            continue
    return streams_data


def analyze_pdf(file_path):
    from PyPDF2 import PdfReader
    from core.scanner import triage, scanner_instance

    try:
        reader = PdfReader(file_path)
        from parsers.pdf_parser import find_javascript_triggers
        triggers = find_javascript_triggers(reader)
        streams = extract_streams(reader)
        results = []

        for idx, s in enumerate(streams):
            res = triage(s['data'], scanner_instance)
            res['Section_Name'] = f"Stream_{idx}({s['filter']})"
            results.append(res)

        return {
            "Triggers": triggers,
            "Stream_Results": results
        }
    except Exception as e:
        return {"Triggers": [], "Stream_Results": [], "Error": str(e)}