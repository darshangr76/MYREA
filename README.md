# MyREA - Advanced Static PE Analyzer

A full-stack reverse engineering tool for Windows PE files (`.exe`, `.dll`). It performs deep static analysis using LIEF and Capstone, scans for suspicious indicators with YARA, and checks for malicious behavioral patterns.

## 🚀 Live Demo
**[Click here to try the live web app!](https://huggingface.co/spaces/Darshan764/myrea-demo)**

## Features
- **PE Parsing:** Extracts sections, imports, entropy, and metadata.
- **Disassembly:** Entry-point disassembly via Capstone.
- **Heuristics:** Flags suspicious APIs (`[strong]` / `[weak]`), high entropy (packing), and RWX sections.
- **Behavioral Rules:** Detects complex API sequences (e.g., Process Injection, Keylogging).
- **YARA Scanning:** Built-in ruleset to detect known packers and ransomware indicators.
- **Reporting:** Generates downloadable Markdown triage reports.

## Architecture
- **Backend:** Python (FastAPI, LIEF, Capstone, YARA) running in a Docker container on Render.
- **Frontend:** HTML/TailwindCSS/JS hosted on Hugging Face Spaces.
