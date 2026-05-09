# 🦠 BinaryWatch: Enterprise Automated Malware Triage Platform

![BinaryWatch Platform Architecture](https://via.placeholder.com/1000x400?text=Insert+Dashboard+Screenshot+Here)

**BinaryWatch** is a full-stack, automated malware triage platform designed to bridge the gap between low-level reverse engineering and high-level Security Operations Center (SOC) workflows. It automatically rips apart suspicious binaries, scores their maliciousness, maps behaviors to the MITRE ATT&CK framework, and serves the intelligence via a modern REST API and React SPA.

## 🚀 Key Features

- **Advanced Static Analysis Engine:** Hooks into Binary Ninja's HLIL to calculate Shannon entropy, uncover Base64 candidates, and brute-force single-byte XOR keys.
- **HLIL Function Ranking:** Automatically scores and ranks assembly functions based on cyclomatic complexity and XOR density to instantly highlight encryption and decryption routines.
- **Threat Intelligence Integrations:** Automatically queries **VirusTotal**, **AbuseIPDB**, and local **YARA** rule directories.
- **Automated YARA Generation:** Generates production-ready YARA rules automatically based on the worst IOCs extracted from a sample.
- **SOC Analyst Dashboard:** A modern React/Vite/Tailwind Web UI featuring global metrics and **interactive node-based execution call graphs** (powered by React Flow).
- **Enterprise API:** A FastAPI backend with a custom Dark-Mode Swagger UI, allowing SIEM and SOAR platforms to query the SQLite cache instantly.

## 🏗️ Architecture

1. **The Brain:** `MalwareAnalyzer` (Python / Binary Ninja API)
2. **The Memory:** Local SQLite Deduplication Cache
3. **The API:** FastAPI + Uvicorn
4. **The UI:** React + Tailwind CSS + TanStack Query + React Flow
5. **Deployment:** Multi-container Docker & Nginx pipeline

## 📦 Quick Start (Docker)

The fastest way to spin up the Enterprise API and Web Dashboard is via Docker. *(Note: The core Binary Ninja analysis plugin must be run locally if you have a BN license).*

1. Clone the repository:
   ```bash
   git clone [https://github.com/smartytinker/BinaryTrace_Plugin.git](https://github.com/smartytinker/BinayTrace_Plugin.git)
   cd BinaryWatch
