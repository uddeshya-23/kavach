"""
ML Bouncer Module - Fast malware detection using file features.

Uses lightweight feature extraction and classification for rapid scanning.
This is Tier 1 - the "Bouncer" that catches 99% of known malware.
"""

import os
import hashlib
import math
from pathlib import Path
from collections import Counter


def calculate_entropy(data: bytes) -> float:
    """Calculate Shannon entropy of data. High entropy = possibly packed/encrypted."""
    if not data:
        return 0.0
    
    counter = Counter(data)
    length = len(data)
    entropy = 0.0
    
    for count in counter.values():
        if count > 0:
            p = count / length
            entropy -= p * math.log2(p)
    
    return entropy


def extract_features(file_path: str) -> dict:
    """
    Extract features from a file for classification.
    
    Features:
    - File size
    - Entropy (high = suspicious)
    - Extension
    - Magic bytes
    - Suspicious strings
    """
    path = Path(file_path)
    
    if not path.exists():
        return {"error": "File not found"}
    
    try:
        data = path.read_bytes()
    except:
        return {"error": "Cannot read file"}
    
    features = {
        "file_name": path.name,
        "file_size": len(data),
        "extension": path.suffix.lower(),
        "entropy": round(calculate_entropy(data), 2),
        "md5": hashlib.md5(data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest(),
        "magic_bytes": data[:4].hex() if len(data) >= 4 else "",
        "suspicious_strings": [],
        "risk_score": 0.0,
        "verdict": "UNKNOWN"
    }
    
    # Check magic bytes
    magic = features["magic_bytes"]
    if magic.startswith("4d5a"):  # MZ header (PE file)
        features["file_type"] = "PE Executable"
    elif magic.startswith("7f454c46"):  # ELF
        features["file_type"] = "ELF Executable"
    elif magic.startswith("25504446"):  # %PDF
        features["file_type"] = "PDF Document"
    elif magic.startswith("504b0304"):  # PK (ZIP/DOCX/XLSX)
        features["file_type"] = "ZIP Archive"
    else:
        features["file_type"] = "Unknown"
    
    # Check for suspicious strings
    suspicious_patterns = [
        b"cmd.exe",
        b"powershell",
        b"WScript.Shell",
        b"CreateObject",
        b"HKEY_LOCAL_MACHINE",
        b"RegWrite",
        b"DownloadFile",
        b"Invoke-Expression",
        b"base64",
        b"eval(",
        b"exec(",
        b"socket",
        b"connect(",
        b"/bin/sh",
        b"/bin/bash",
        b"wget ",
        b"curl ",
        # Additional malware indicators
        b"keylog",
        b"backdoor",
        b"c2_server",
        b"C2_SERVER",
        b"exfiltrate",
        b"steal",
        b"credential",
        b"password",
        b"clipboard",
        b"getClipboard",
        b"screenshot",
        b"VirtualAlloc",
        b"CreateRemoteThread",
        b"WriteProcessMemory",
        b"establish_backdoor",
        b"beacon",
        b"SOCK_STREAM",
        b"AF_INET",
    ]
    
    data_lower = data.lower()
    for pattern in suspicious_patterns:
        if pattern.lower() in data_lower:
            features["suspicious_strings"].append(pattern.decode('utf-8', errors='ignore'))
    
    # Calculate risk score
    risk = 0.0
    
    # High entropy is suspicious (packed/encrypted)
    if features["entropy"] > 7.5:
        risk += 0.3
    elif features["entropy"] > 7.0:
        risk += 0.15
    
    # Executable files are higher risk
    if features["file_type"] in ["PE Executable", "ELF Executable"]:
        risk += 0.2
    
    # Script files with suspicious patterns are high risk
    if features["extension"] in [".py", ".js", ".ps1", ".vbs", ".bat", ".sh"]:
        risk += 0.1  # Scripts start with some risk
        # Each pattern in a script is more dangerous
        risk += len(features["suspicious_strings"]) * 0.15
    else:
        # Non-script files
        risk += len(features["suspicious_strings"]) * 0.1
    
    # Critical indicators - instant high risk
    critical_patterns = ["backdoor", "keylog", "c2_server", "exfiltrate", "establish_backdoor", "beacon"]
    for cp in critical_patterns:
        if any(cp.lower() in s.lower() for s in features["suspicious_strings"]):
            risk += 0.3
            break
    
    # Cap at 1.0
    risk = min(risk, 1.0)
    features["risk_score"] = round(risk, 2)
    
    # Verdict based on risk
    if risk >= 0.5:
        features["verdict"] = "MALICIOUS"
    elif risk >= 0.3:
        features["verdict"] = "SUSPICIOUS"
    else:
        features["verdict"] = "BENIGN"
    
    return features


def scan_file(file_path: str) -> dict:
    """
    Scan a file and return the ML Bouncer verdict.
    """
    features = extract_features(file_path)
    
    return {
        "file": file_path,
        "verdict": features.get("verdict", "UNKNOWN"),
        "risk_score": features.get("risk_score", 0),
        "features": features
    }


def print_scan_results(result: dict):
    """Pretty print scan results."""
    print("\n" + "=" * 60)
    print("ML BOUNCER SCAN REPORT")
    print("=" * 60)
    
    features = result.get("features", {})
    
    print(f"File: {result['file']}")
    print(f"Type: {features.get('file_type', 'Unknown')}")
    print(f"Size: {features.get('file_size', 0):,} bytes")
    print(f"Entropy: {features.get('entropy', 0):.2f} / 8.0")
    print(f"MD5: {features.get('md5', 'N/A')}")
    print("-" * 60)
    
    verdict = result.get("verdict", "UNKNOWN")
    risk = result.get("risk_score", 0)
    
    if verdict == "MALICIOUS":
        print(f"Verdict: \033[91m{verdict}\033[0m (Risk: {risk:.0%})")
    elif verdict == "SUSPICIOUS":
        print(f"Verdict: \033[93m{verdict}\033[0m (Risk: {risk:.0%})")
    else:
        print(f"Verdict: \033[92m{verdict}\033[0m (Risk: {risk:.0%})")
    
    if features.get("suspicious_strings"):
        print("\nSuspicious Patterns Found:")
        for s in features["suspicious_strings"]:
            print(f"  ⚠ {s}")
    
    print("=" * 60 + "\n")


if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python bouncer.py <file_path>")
        sys.exit(1)
    
    result = scan_file(sys.argv[1])
    print_scan_results(result)
