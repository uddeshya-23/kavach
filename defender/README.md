# Defender - AI Malware Detection & Sanitization Tool

A multi-tiered malware defense system with CDR (Content Disarm & Reconstruction), ML-based detection, and LLM semantic analysis.

## Features
- **CDR Sanitizer**: Strips hidden code from PDFs/documents
- **ML Bouncer**: Fast detection using EMBER/LightGBM
- **LLM Detective**: Semantic intent analysis (optional)

## Installation
```bash
pip install -r requirements.txt
```

## Usage
```bash
# Sanitize a PDF
python -m defender.cli sanitize malicious.pdf

# Scan a file (all tiers)
python -m defender.cli scan suspicious.exe

# LLM analysis (requires Ollama)
python -m defender.cli explain script.py
```

## Project Structure
```
defender/
├── __init__.py
├── cli.py          # Unified command line interface
├── cdr.py          # Content Disarm & Reconstruction
├── bouncer.py      # ML-based detection
└── detective.py    # LLM semantic analysis
samples/
├── malicious_interview.pdf   # Test sample with hidden code
└── clean_interview.pdf       # Sanitized output
```
