<h1 align="center">$${\color{lightblue}Prism}$$</h1>
<p align="center">══════════════════════════════════════════════</p>
<p align="center">
  <i>Prism is a static malware analysis framework designed to safely inspect suspicious files and generate actionable insights.
It dissects files—PDFs, executables, and Office documents—into metadata, strings, embedded scripts, and structural indicators to reveal hidden threats. It scores risk, highlights suspicious patterns, and produces clear reports, helping security professionals quickly identify which files require deeper investigation or reverse engineering.</i>
</p>
<p align="center">══════════════════════════════════════════════</p>
<p align="center">
  <img src="https://github.com/user-attachments/assets/f1a530e4-6140-41e5-9c95-42bf2bc4241d" width="200">
</p>

## ✨ Key Features

* **🛡️ Safe Static Analysis:** Zero-execution environment. All inspections are strictly read-only, ensuring malware cannot detonate during the triage phase.
* **📂 Multi-Format Support:** Deep parsing capabilities for:
    * **PE (Windows Executables):** Headers, sections, and import tables.
    * **Documents:** PDF structure and OLE/Office (Word, Excel, PowerPoint) streams.
* **🕵️ Indicator Detection:** Automated extraction of embedded scripts (VBA, JS), suspicious URLs, IP addresses, and obfuscation patterns.
* **📊 Entropy & Heuristic Scoring:** Advanced calculation of file entropy to identify packed sections and suspicious structural anomalies.
* **🎯 YARA Integration:** Full support for custom and public YARA rulesets to match known threat families and TTPs.
* **📝 Analyst-Friendly Reports:** Actionable output available in **JSON** (for automation) or **CLI** (for human readability), prioritizing risk levels.
* **🛠️ Downstream RE Guidance:** Intelligent flagging of high-risk samples to streamline your workflow with tools like **Ghidra**, **IDA Pro**, or **Binary Ninja**.

---

## ⚙️ Workflow

<div align="center">
  <p><i>The Prism analysis pipeline is designed to move from raw data to actionable intelligence.</i></p>
</div>

1.  **Ingestion:** Load suspicious artifacts into the framework.
2.  **Extraction:** Prism strips the file into metadata, strings, and structural components.
3.  **Heuristics & YARA:** The engine runs entropy checks and pattern matching.
4.  **Scoring:** A final risk score is calculated based on detected indicators.
5.  **Triage:** Use the generated report to decide: *Discard, Archive, or move to Reverse Engineering.*

---

