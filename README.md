# MyREA - Full-Stack Reverse Engineering Platform

MyREA is a static and dynamic analysis platform for Windows Portable Executable (PE) files. It combines deep static heuristics with a local dynamic sandbox to analyze potential malware behavior.

## 🚀 Live Static Analyzer
**[Click here to try the live web app!](https://huggingface.co/spaces/Darshan764/myrea-demo)**

## Features
### Static Analysis (Cloud)
- **PE Parsing:** Extracts sections, imports, entropy, and headers via LIEF.
- **Disassembly:** Entry-point disassembly using Capstone.
- **Heuristics:** Detects process injection, keylogging API combinations, high entropy, and RWX sections.
- **YARA Scanning:** Scans for known packers and ransomware signatures.
- **Web Interface:** Drag-and-drop UI built with TailwindCSS, hosted on Hugging Face.
- **Markdown Reports:** Generates downloadable triage reports.

### Dynamic Analysis (Local Sandbox)
- **Frida Integration:** Hooks Windows APIs (`NtCreateFile`, `NtSetValueKey`, `CreateProcessW`) to monitor runtime behavior.
- **Cross-Platform Bridge:** Python controller on macOS connects to a Windows 11 ARM VM (UTM) to safely execute and monitor samples.

## Architecture
- **Backend:** Python (FastAPI, LIEF, Capstone, YARA) running in a Docker container on Render.
- **Frontend:** HTML/TailwindCSS/JS hosted on Hugging Face Spaces.
- **Dynamic Engine:** Frida (JavaScript agent + Python controller) targeting a Windows 11 ARM Virtual Machine.
