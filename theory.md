# PRISM FRAMEWORK: TECHNICAL THEORY & TRIAGE 

1. THE CORE TECHNICAL THEORY
----------------------------
The technical theory behind Prism is rooted in Static Program Analysis and 
Format-Specific Heuristics. Unlike dynamic analysis, which observes what a 
file *does*, static analysis focuses on what a file *is* and what it *contains*.

The framework operates on three primary layers:

A. STRUCTURAL PARSING
Every file format has a specific specification (ISO 32000 for PDF, OOXML for 
Office). Prism parses these into a tree or object graph. Malicious files 
often violate these specs or use obscure features to hide payloads.

B. INFORMATION THEORY (ENTROPY)
Prism calculates Shannon Entropy, which measures randomness (0.0 to 8.0).
- Low Entropy: Normal text or structured code.
- High Entropy (> 7.2): Encrypted or compressed data. 
If a file's .text (code) section has high entropy, it is almost certainly 
"packed" or "obfuscated" to evade antivirus detection.

C. SIGNATURE MATCHING (YARA)
Prism uses "Swiss Army Knife" pattern matching to find specific byte 
sequences that match known malware families or exploitation techniques.

-------------------------------------------------------------------------------

2. HOW TO CHECK PDF FILES
-------------------------
PDFs are complex databases of "objects." Malware usually hides in Automatic 
Actions or Embedded Scripts.

KEY SEARCH TARGETS:
- /OpenAction & /AA: Specifies commands that run automatically upon opening.
- /JS & /JavaScript: Used for heap-spraying or triggering vulnerabilities.
- /EmbeddedFile: Look for hidden EXEs or ZIPs nested in attachments.
- /Names: Often used to obfuscate the location of malicious objects.

QUICK TRIAGE LOGIC:
(JavaScript Presence) + (OpenAction Presence) = HIGH RISK SCORE

-------------------------------------------------------------------------------

3. HOW TO CHECK OFFICE DOCUMENTS (.DOC, .DOCX, .XLSM)
-----------------------------------------------------
Modern Office files are ZIP archives containing XML files. Prism "unzips" 
these in memory to inspect the internal parts.

KEY SEARCH TARGETS:
- Macros (VBA): Look for 'vbaProject.bin' inside the ZIP structure.
- Suspicious Keywords: 'AutoOpen', 'Shell', 'CreateObject', and 'Base64'.
- DDE (Dynamic Data Exchange): Look for the string 'DDEAUTO' (executes 
  commands without macros).
- External Relationships: Check 'word/_rels/settings.xml.rels' for 
  "Remote Templates" (downloads macros from external servers).
- Object Linking (OLE): Check for embedded .bin or .exe objects disguised 
  as document icons.

-------------------------------------------------------------------------------

4. OTHER DOCUMENT TYPES & GENERAL RULES
---------------------------------------
For RTF, CSV, and others, Prism follows the "Least Entropy, Most Strings" rule:

- STRING EXTRACTION: Harvest URLs (http://), IP addresses, and commands 
  like 'powershell.exe -ExecutionPolicy Bypass'.
- POLYGLOT CHECK: Verify if the file header (e.g., %PDF-) matches the 
  actual file extension.
- HEURISTIC SCORING:
  Example: 10 pts (URL) + 40 pts (Macro) + 20 pts (Obfuscation) = 70 pts.

-------------------------------------------------------------------------------
## Parsing the file into an Object Graph

1. The Parser Architecture\
To build this, we follow a three-stage pipeline:
- The Lexer (Scanner): It reads the raw bytes and identifies "tokens" (e.g., in a PDF, it looks for keywords like obj, endobj, stream, and xref).
- The Parser: It takes those tokens and determines their relationship based on the format's specification (the "Grammar").
- The Object Graph Construction: It maps these relationships into memory as a Tree or Directed Acyclic Graph (DAG).
-------------------------------------------------------------------------------
2. Implementation: PDF (ISO 32000)\
PDFs are "Body-Object" formatted. They aren't read from top to bottom; they are read from the Trailer (the end) backwards.
- The Theory: You find the xref (Cross-Reference) table at the end of the file. This table acts as an index, telling you exactly where every "Object" (like a page, an image, or a script) starts in the binary data.
- The Graph: Once you have the index, Prism follows the pointers.
- Root Object → Pages → Individual Page → Contents → JavaScript Stream.
- Malware Detection: If the parser encounters an object that isn't indexed in the xref table but exists in the data, it's a "hidden" object—a major red flag.
-------------------------------------------------------------------------------
3. Implementation: Office Docs (OOXML)\ 
Modern Office docs (.docx, .xlsx) are actually "Container" formats. \
- The Theory: The "Physical" layer is a standard ZIP file. The "Logical" layer consists of XML files and binary streams.
- The Graph: 1. Decompress: Open the ZIP structure. 2. Map Relationships: Read the .rels files. These files are the "glue" that tells the document how parts connect.
  * Document.xml → Link to Settings → Link to VBA Macro Stream.
- Malware Detection: A "Remote Template" relationship pointing to an external URL instead of a local file is a classic indicator of a Template Injection attack.
-------------------------------------------------------------------------------
4. Why using an "Object Graph" is better than a "String Search"
If you just search a file for the string "JavaScript", a clever attacker can hide it like this: \
_J + a + v + a + S + c + r + i + p + t_

The Parser Theory solves this:
- Instead of looking for words, Prism looks for the Logic Block.
- It finds the /Type /Action object.
- It sees the /S /JavaScript key.
- It extracts the data regardless of how it was "spelled" or broken up in the raw binary.

-------------------------------------------------------------------------------



## Entropy calculation :

<img width="656" height="341" alt="image" src="https://github.com/user-attachments/assets/6e1c8289-0c35-4f0e-a8bf-7028435455bf" /> 

-------------------------------------------------------------------------------
**_So we implement this is by doing the following :_** 

<img width="651" height="262" alt="image" src="https://github.com/user-attachments/assets/52bb0d19-fb63-48fe-b214-53303a89445c" />

-------------------------------------------------------------------------------
<img width="630" height="217" alt="image" src="https://github.com/user-attachments/assets/f57b64f1-d70a-43fc-aa63-8c4777b87a96" />

-------------------------------------------------------------------------------

If Prism detects an entropy of 7.5 in an .exe file's code section, it tells the analyst:
"I cannot read the strings or instructions in this file because they are scrambled. You must send this to Ghidra or x64dbg to see it after it unpacks in memory."  \
This is the "Downstream RE Guidance" feature I mentioned in the README.
