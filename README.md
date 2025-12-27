# 🛡️ KAVACH (कवच) - AI Malware Defense System

Kavach (Sanskrit for **Armor**) is a multi-tier, AI-driven malware detection and sanitization prototype. It uses a "Filter & Focus" architecture to provide high-speed classification followed by deep semantic AI analysis.

![Kavach Architecture](C:/Users/91858/.gemini/antigravity/brain/e6fda481-1dc1-4cb2-9e56-f2fbd64b66bc/kavach_architecture_diagram.png)

## 🚀 Features

- **6-Tier Defense Pipeline**:
    1.  **CDR Sanitizer**: Content Disarm & Reconstruction for PDFs.
    2.  **ML Bouncer**: Fast pattern and entropy-based classification.
    3.  **LOtL Detector**: Detects Living-Off-The-Land attacks (PowerShell, certutil, etc.).
    4.  **SBOM Scanner**: Scans dependency manifests for known vulnerabilities.
    5.  **PE Analyzer**: Deep static analysis of Windows executables using LIEF.
    6.  **LLM Detective**: Semantic code reasoning using local LLMs (Ollama/DeepSeek).
- **Interactive UI**: Modern glassmorphism web interface with real-time streaming results.
- **Explainable AI (XAI)**: Provides human-readable reasons for why a file was flagged.
- **CDR Capability**: Automatically strips malicious JS from PDFs and provides a clean version for download.

---

## 🛠️ Local Setup

### 1. Prerequisites
- **Python 3.10+**
- **Ollama**: [Download here](https://ollama.com/) (Required for Tier 6)
- **Ollama Models**:
  ```bash
  ollama run deepseek-r1:1.5b
  ```

### 2. Installation
Clone the repository and install dependencies:
```bash
git clone https://github.com/uddeshya-23/kavach.git
cd kavach
pip install -r requirements.txt
```

### 3. Running the System

#### Option A: Interactive Web UI (Recommended)
```bash
# Start the API server
python kavach_api.py

# Open the UI (in a new terminal)
start kavach-demo.html
```

#### Option B: Command Line Interface (CLI)
```bash
# Scan a file (Multi-tier)
python -m defender.cli scan samples/malicious_interview.pdf

# Sanitize a PDF
python -m defender.cli sanitize samples/malicious_interview.pdf

# Explain a script using AI
python -m defender.cli explain samples/malicious_script.py
```

---

## 🔬 Architecture: Filter & Focus
Kavach is designed to intercept sophisticated APT attacks, such as those from the **Lazarus Group**.

1.  **Static Filter**: CDR and ML Bouncer catch known sigs and high-entropy packed files.
2.  **Behavioral Focus**: LOtL and PE Analyzer look for suspicious structural anomalies.
3.  **AI Reasoning**: The LLM Detective reads code intent, catching obfuscated malware that bypasses traditional signatures.

## 🛡️ Case Study: The Bitbyte $1.5B Save
Kavach's multi-tier approach is designed to stop the specific multi-stage attack patterns that led to the $1.5B Bitbyte Exchange breach:
- Intercepts malicious PDF interview tasks via CDR.
- Blocks backdoors via LLM intent analysis.
- Prevents $1.5B wallet drain by blocking LOtL PowerShell commands.

---

## 📜 License
MIT License. Created for education and research into AI-driven defensive security.
