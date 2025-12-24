<h1 align="center">$${\Huge \color{lightblue}{Prism}}$$</h1>

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.8+-ED5564?logo=python&logoColor=white">
  <img src="https://img.shields.io/badge/PDF%20Standard-ISO%2032000-FFCE54">
  <img src="https://img.shields.io/badge/Office-OOXML%20Standard-A0D568">
  <img src="https://img.shields.io/badge/YARA-Supported-4FC1E8?logo=yara&logoColor=white">
  <img src="https://img.shields.io/badge/License-MIT-AC92EB">
</p>
<p align="center">
  <i>Prism is a static malware analysis framework designed to safely inspect suspicious files and generate actionable insights.
It dissects files—PDFs, executables, and Office documents—into metadata, strings, embedded scripts, and structural indicators to reveal hidden threats. It scores risk, highlights suspicious patterns, and produces clear reports, helping security professionals quickly identify which files require deeper investigation or reverse engineering.</i>
</p>
    
<p align="center">
  <img src="https://github.com/user-attachments/assets/f1a530e4-6140-41e5-9c95-42bf2bc4241d" width="200">
</p>

<p align="center">





### _To explore the codebase, review the architecture, or test early functionality:_

```bash
git clone https://github.com/guyvolvo/prism
cd prism
python3 main.py -h
python3 main.py malware.exe
```
<p align="center">
  <img src="https://github.com/user-attachments/assets/567975c0-d184-4e01-b5d0-f8434a1eadbc">
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
* **! Prism is OS-agnostic, but designed to be used in a malware-analysis environment. !**
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
## 📂 Project Structure & Setup

```text
prism/
├── main.py
├── malware/          # Place binary/RAT/Toolkit YARA rules here
├── maldocs/          # Place PDF/Office/Macro YARA rules here
├── core/             # Triage engine and report logic
└── parsers/          # Format-specific extraction logic

All `.exe`, `.doc`, `.pdf`, and other sample files included in this repository are safe and do not contain real malware
```
## **_Adding your own YARA rules_**
Prism supports the use of custom YARA rules to extend detection coverage and adapt the framework to specific threat models or environments. 
To ensure correct discovery and loading, custom YARA rules must be placed in the project root directory (alongside the main Prism entry point), or in a clearly defined subdirectory explicitly referenced by the configuration.

  
### Continue to the [Theory Page](https://github.com/guyvolvo/prism/blob/main/theory.md)

_**References :**_ 

[Information Entropy](https://redcanary.com/blog/threat-detection/threat-hunting-entropy/) \
[Entropy (information theory)](https://en.wikipedia.org/wiki/Entropy_(information_theory))

<p align=left">
  <img src="https://media4.giphy.com/media/v1.Y2lkPTc5MGI3NjExNG83cmo5MWgwMGM0N2pjc29qaG8wZGJ2cmM0M3F0bnA4bXV6bTdtdSZlcD12MV9pbnRlcm5hbF9naWZfYnlfaWQmY3Q9Zw/sk6yL9EGVeAcE/giphy.gif" alt="Prism Demo" width="200">
</p>

