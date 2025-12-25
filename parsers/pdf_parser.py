import re
import zlib
from pypdf import PdfReader
from core.scanner import triage, get_scanner, shannon_entropy


def brute_force_carve(file_path, scanner, api_key=None):

    try:
        with open(file_path, "rb") as f:
            data = f.read()
    except Exception as e:
        return []

    carved_results = []
    stream_pattern = re.compile(b"stream\r?\n(.*?)\r?\nendstream", re.DOTALL)
    hex_obfuscation = bool(re.search(b"/[#0-9a-fA-F]{2,}", data))

    for idx, match in enumerate(stream_pattern.finditer(data)):
        stream_content = match.group(1)

        # Try to decompress
        try:
            stream_content = zlib.decompress(stream_content)
        except:
            pass

        # Skip empty streams
        if len(stream_content) < 10:
            continue

        analysis = triage(
            file_path=file_path,
            data=stream_content,
            scanner=scanner,
            api_key=api_key
        )

        analysis['Section_Name'] = f"Carved_Stream_{idx}"
        analysis['Hex_Obfuscation'] = hex_obfuscation
        carved_results.append(analysis)

    return carved_results


def find_javascript_triggers(reader):

    triggers_found = []
    try:
        catalog = reader.trailer.get("/Root")
        if not catalog:
            return triggers_found

        # Check for JavaScript
        if "/Names" in catalog:
            names = catalog["/Names"]
            if isinstance(names, dict) and "/JavaScript" in names:
                triggers_found.append("Embedded JavaScript Name")

        # Check for auto-execution
        if "/OpenAction" in catalog:
            triggers_found.append("Auto-Run OpenAction (Executes on Open)")

        if "/AA" in catalog:
            triggers_found.append("Additional Actions (AA) Present")

        # Check for obfuscation
        catalog_keys = str(catalog.keys())
        if "#" in catalog_keys:
            triggers_found.append("Hex-Encoded Catalog Keys (Obfuscation)")

    except Exception as e:
        triggers_found.append(f"Error parsing catalog: {str(e)[:30]}")

    return triggers_found


def analyze_pdf(file_path, api_key=None):

    scanner = get_scanner()

    try:
        reader = PdfReader(file_path)
        triggers = find_javascript_triggers(reader)
        streams_data = []

        object_count = 0
        for obj_ref in reader.objects:
            try:
                obj = reader.get_object(obj_ref)
                if hasattr(obj, "get_data"):
                    raw_bytes = obj.get_data()

                    # Skip small objects (likely metadata)
                    if len(raw_bytes) < 50:
                        continue

                    object_count += 1

                    analysis = triage(
                        file_path=file_path,
                        data=raw_bytes,
                        scanner=scanner,
                        api_key=api_key
                    )

                    analysis['Section_Name'] = f"Object_{obj_ref}"
                    streams_data.append(analysis)
            except Exception:
                continue

        # If standard parsing yielded nothing, try brute force
        if len(streams_data) == 0 or len(triggers) == 0:
            carved = brute_force_carve(file_path, scanner, api_key)
            streams_data.extend(carved)

        malicious_count = sum(1 for r in streams_data if r.get("Status") == "MALICIOUS")
        suspicious_count = sum(1 for r in streams_data if r.get("Status") == "SUSPICIOUS")

        # Determine overall status
        status = "CLEAN"
        if malicious_count > 0:
            status = "MALICIOUS"
        elif suspicious_count > 0 or triggers:
            status = "SUSPICIOUS"

        return {
            "Status": status,
            "Triggers": triggers,
            "Stream_Results": streams_data,
            "Objects_Analyzed": object_count
        }

    except Exception as e:
        # PDF structure is corrupt or unreadable
        error_msg = str(e)

        # Try brute force carving even on error
        try:
            carved = brute_force_carve(file_path, scanner, api_key)

            if carved:
                # Found content via carving
                malicious = sum(1 for r in carved if r.get("Status") == "MALICIOUS")
                suspicious = sum(1 for r in carved if r.get("Status") == "SUSPICIOUS")

                status = "MALICIOUS" if malicious > 0 else (
                    "SUSPICIOUS" if suspicious > 0 else "CRITICAL"
                )

                return {
                    "Status": status,
                    "Triggers": [f"PDF Structure Corrupt: {error_msg[:50]}", "Content Recovered via Carving"],
                    "Stream_Results": carved
                }
        except:
            pass

        # Total failure
        return {
            "Status": "CRITICAL",
            "Triggers": [f"PDF Structure Corrupt: {error_msg[:100]}"],
            "Stream_Results": [],
            "error": "Could not parse PDF"
        }