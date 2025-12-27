"""
PE/EXE Analyzer Module - Deep analysis of Windows executables.

Uses LIEF library to parse PE headers and detect malicious characteristics.
"""

import lief
import math
from pathlib import Path
from collections import Counter


# Suspicious imports that malware commonly uses
SUSPICIOUS_IMPORTS = {
    "high_risk": [
        "VirtualAlloc", "VirtualAllocEx", "VirtualProtect",
        "CreateRemoteThread", "WriteProcessMemory", "ReadProcessMemory",
        "NtUnmapViewOfSection", "ZwUnmapViewOfSection",
        "CreateProcess", "WinExec", "ShellExecute",
        "URLDownloadToFile", "InternetOpen", "InternetReadFile",
        "LoadLibrary", "GetProcAddress",
        "RegSetValue", "RegCreateKey",
        "CryptEncrypt", "CryptDecrypt",
    ],
    "medium_risk": [
        "OpenProcess", "TerminateProcess",
        "SetWindowsHookEx", "GetAsyncKeyState", "GetKeyState",
        "CreateService", "StartService",
        "socket", "connect", "send", "recv",
        "FindFirstFile", "FindNextFile",
        "GetClipboardData", "SetClipboardData",
    ]
}

# Known packed/protected sections
PACKER_SIGNATURES = {
    "UPX": [".UPX0", ".UPX1", ".UPX2"],
    "Themida": [".themida"],
    "VMProtect": [".vmp0", ".vmp1"],
    "ASPack": [".aspack"],
    "PECompact": [".pec1", ".pec2"],
}


def calculate_entropy(data: bytes) -> float:
    """Calculate Shannon entropy."""
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


def analyze_pe(file_path: str) -> dict:
    """
    Perform deep analysis of a PE/EXE file.
    
    Returns detailed analysis including:
    - Header information
    - Imports analysis
    - Section entropy
    - Packer detection
    - Risk assessment
    """
    path = Path(file_path)
    
    if not path.exists():
        return {"error": "File not found", "verdict": "ERROR"}
    
    try:
        binary = lief.parse(str(path))
    except:
        return {"error": "Not a valid PE file", "verdict": "ERROR"}
    
    if binary is None:
        return {"error": "Failed to parse PE", "verdict": "ERROR"}
    
    results = {
        "file": str(path),
        "file_size": path.stat().st_size,
        "verdict": "UNKNOWN",
        "risk_score": 0.0,
        "findings": [],
        "header": {},
        "imports": {"high_risk": [], "medium_risk": [], "total": 0},
        "sections": [],
        "packer": None,
    }
    
    risk = 0.0
    
    # === Header Analysis ===
    if hasattr(binary, 'header'):
        results["header"] = {
            "machine": str(binary.header.machine),
            "timestamp": binary.header.time_date_stamps if hasattr(binary.header, 'time_date_stamps') else 0,
            "characteristics": str(binary.header.characteristics) if hasattr(binary.header, 'characteristics') else "",
        }
    
    # === Section Analysis ===
    suspicious_sections = 0
    for section in binary.sections:
        sect_data = bytes(section.content) if hasattr(section, 'content') else b""
        entropy = calculate_entropy(sect_data)
        
        sect_info = {
            "name": section.name,
            "size": section.size,
            "entropy": round(entropy, 2),
            "executable": bool(section.characteristics & 0x20000000),
            "writable": bool(section.characteristics & 0x80000000),
        }
        results["sections"].append(sect_info)
        
        # High entropy + executable = suspicious
        if entropy > 7.0 and sect_info["executable"]:
            results["findings"].append(f"Section '{section.name}' has high entropy ({entropy:.2f}) and is executable - possible packing")
            suspicious_sections += 1
            risk += 0.15
        
        # Check for packer signatures
        for packer, signatures in PACKER_SIGNATURES.items():
            if section.name in signatures:
                results["packer"] = packer
                results["findings"].append(f"Packer detected: {packer}")
                risk += 0.2
    
    # === Import Analysis ===
    if hasattr(binary, 'imports'):
        for imp in binary.imports:
            for entry in imp.entries:
                func_name = entry.name if hasattr(entry, 'name') else ""
                results["imports"]["total"] += 1
                
                if func_name in SUSPICIOUS_IMPORTS["high_risk"]:
                    results["imports"]["high_risk"].append(func_name)
                elif func_name in SUSPICIOUS_IMPORTS["medium_risk"]:
                    results["imports"]["medium_risk"].append(func_name)
    
    # Risk from imports
    high_risk_count = len(results["imports"]["high_risk"])
    medium_risk_count = len(results["imports"]["medium_risk"])
    
    if high_risk_count > 5:
        results["findings"].append(f"{high_risk_count} high-risk API imports detected")
        risk += 0.3
    elif high_risk_count > 0:
        results["findings"].append(f"{high_risk_count} suspicious API imports")
        risk += high_risk_count * 0.05
    
    if medium_risk_count > 5:
        risk += 0.1
    
    # === Anomaly Detection ===
    # Check for no imports (packed/encrypted)
    if results["imports"]["total"] == 0:
        results["findings"].append("No imports detected - possibly packed or encrypted")
        risk += 0.25
    
    # Check for small import table
    if 0 < results["imports"]["total"] < 5:
        results["findings"].append("Very few imports - possibly packed")
        risk += 0.15
    
    # === Final Verdict ===
    risk = min(risk, 1.0)
    results["risk_score"] = round(risk, 2)
    
    if risk >= 0.6:
        results["verdict"] = "MALICIOUS"
    elif risk >= 0.3:
        results["verdict"] = "SUSPICIOUS"
    else:
        results["verdict"] = "BENIGN"
    
    return results


def print_pe_analysis(result: dict):
    """Pretty print PE analysis results."""
    print("\n" + "=" * 60)
    print("PE/EXE ANALYZER REPORT")
    print("=" * 60)
    
    print(f"File: {result.get('file', 'N/A')}")
    print(f"Size: {result.get('file_size', 0):,} bytes")
    
    if result.get("packer"):
        print(f"Packer: {result['packer']}")
    
    verdict = result.get("verdict", "UNKNOWN")
    risk = result.get("risk_score", 0)
    
    if verdict == "MALICIOUS":
        print(f"Verdict: \033[91m{verdict}\033[0m (Risk: {risk:.0%})")
    elif verdict == "SUSPICIOUS":
        print(f"Verdict: \033[93m{verdict}\033[0m (Risk: {risk:.0%})")
    else:
        print(f"Verdict: \033[92m{verdict}\033[0m (Risk: {risk:.0%})")
    
    print("-" * 60)
    
    if result.get("findings"):
        print("Findings:")
        for f in result["findings"]:
            print(f"  ⚠ {f}")
    
    imports = result.get("imports", {})
    if imports.get("high_risk"):
        print("\nHigh-Risk Imports:")
        for imp in imports["high_risk"][:10]:
            print(f"  🔴 {imp}")
    
    print("=" * 60 + "\n")


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python pe_analyzer.py <file.exe>")
        sys.exit(1)
    
    result = analyze_pe(sys.argv[1])
    print_pe_analysis(result)
