# engine.py will orchestrate the workflow
# moving a file from Ingestion (loading) to Extraction (parsing) and finally to Scoring.

import os
from parsers.pdf_parser import analyze_pdf
from parsers.pe_parser import analyze_pe
from parsers.office_parser import analyze_ole


class PrismEngine:
    def __init__(self):
        # Map extensions to their respective parser functions
        self.parser_map = {
            ".pdf": analyze_pdf,
            ".exe": analyze_pe,
            ".dll": analyze_pe,
            ".doc": analyze_ole,
            ".xls": analyze_ole,
            ".ppt": analyze_ole
        }

    def triage_file(self, file_path):

        # Determines the file type and executes the correct parser.

        if not os.path.exists(file_path):
            return {"error": "File not found"}

        ext = os.path.splitext(file_path)[1].lower()
        parser_func = self.parser_map.get(ext)

        if not parser_func:
            return {"error": f"Unsupported file type: {ext}"}

        try:
            # Execute the routed parser and return results
            return parser_func(file_path)
        except Exception as e:
            return {"error": f"Engine failure during parsing: {str(e)}"}
