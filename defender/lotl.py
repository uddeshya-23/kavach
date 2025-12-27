"""
Living-Off-The-Land (LOtL) Detector Module

Detects abuse of legitimate Windows system tools for malicious purposes.
These attacks are hard to detect because they use trusted binaries.
"""

import re
from pathlib import Path


# LOtL binaries and their suspicious usage patterns
LOTL_SIGNATURES = {
    "powershell": {
        "binary": ["powershell.exe", "pwsh.exe"],
        "suspicious_args": [
            r"-enc\s",
            r"-encodedcommand",
            r"-e\s+[A-Za-z0-9+/=]{20,}",  # Base64 encoded command
            r"-nop\s",
            r"-noprofile",
            r"-w\s+hidden",
            r"-windowstyle\s+hidden",
            r"bypass",
            r"IEX\s*\(",
            r"Invoke-Expression",
            r"Invoke-WebRequest",
            r"DownloadString",
            r"DownloadFile",
            r"Net\.WebClient",
            r"Start-BitsTransfer",
            r"-exec\s+bypass",
        ],
        "severity": "HIGH"
    },
    "certutil": {
        "binary": ["certutil.exe"],
        "suspicious_args": [
            r"-urlcache",
            r"-split",
            r"-decode",
            r"-encode",
            r"http://",
            r"https://",
        ],
        "severity": "HIGH"
    },
    "mshta": {
        "binary": ["mshta.exe"],
        "suspicious_args": [
            r"javascript:",
            r"vbscript:",
            r"http://",
            r"https://",
        ],
        "severity": "CRITICAL"
    },
    "regsvr32": {
        "binary": ["regsvr32.exe"],
        "suspicious_args": [
            r"/s\s+/n",
            r"/u\s+/s",
            r"scrobj\.dll",
            r"http://",
            r"https://",
        ],
        "severity": "HIGH"
    },
    "wmic": {
        "binary": ["wmic.exe"],
        "suspicious_args": [
            r"process\s+call\s+create",
            r"os\s+get",
            r"/node:",
        ],
        "severity": "MEDIUM"
    },
    "cmd": {
        "binary": ["cmd.exe"],
        "suspicious_args": [
            r"/c\s+.*powershell",
            r"/c\s+.*certutil",
            r"/c\s+.*bitsadmin",
            r"&&",
            r"\|",
        ],
        "severity": "LOW"
    },
    "bitsadmin": {
        "binary": ["bitsadmin.exe"],
        "suspicious_args": [
            r"/transfer",
            r"/download",
            r"http://",
            r"https://",
        ],
        "severity": "HIGH"
    },
    "rundll32": {
        "binary": ["rundll32.exe"],
        "suspicious_args": [
            r"javascript:",
            r"http://",
            r"shell32\.dll.*ShellExec_RunDLL",
        ],
        "severity": "HIGH"
    },
    "cscript": {
        "binary": ["cscript.exe", "wscript.exe"],
        "suspicious_args": [
            r"//e:vbscript",
            r"//e:jscript",
            r"http://",
        ],
        "severity": "MEDIUM"
    },
}


def analyze_command(command: str) -> dict:
    """
    Analyze a command line for LOtL abuse.
    
    Args:
        command: The command line string to analyze
    
    Returns:
        Analysis result with verdict and findings
    """
    results = {
        "command": command,
        "verdict": "BENIGN",
        "severity": "NONE",
        "findings": [],
        "matched_tool": None,
        "matched_patterns": [],
    }
    
    command_lower = command.lower()
    
    for tool_name, signatures in LOTL_SIGNATURES.items():
        # Check if the tool is in the command
        tool_found = False
        for binary in signatures["binary"]:
            if binary.lower() in command_lower:
                tool_found = True
                results["matched_tool"] = binary
                break
        
        if not tool_found:
            continue
        
        # Check for suspicious arguments
        for pattern in signatures["suspicious_args"]:
            if re.search(pattern, command, re.IGNORECASE):
                results["matched_patterns"].append(pattern)
                results["findings"].append(f"Suspicious pattern: {pattern}")
        
        # If we found suspicious patterns, set verdict
        if results["matched_patterns"]:
            results["verdict"] = "MALICIOUS"
            results["severity"] = signatures["severity"]
            results["findings"].insert(0, f"LOtL attack using {tool_name.upper()}")
    
    return results


def analyze_script_file(file_path: str) -> dict:
    """
    Analyze a script file (BAT, PS1, VBS) for LOtL patterns.
    """
    path = Path(file_path)
    
    if not path.exists():
        return {"error": "File not found", "verdict": "ERROR"}
    
    try:
        content = path.read_text(encoding='utf-8', errors='ignore')
    except:
        return {"error": "Cannot read file", "verdict": "ERROR"}
    
    results = {
        "file": str(path),
        "verdict": "BENIGN",
        "severity": "NONE",
        "findings": [],
        "line_matches": [],
    }
    
    for line_num, line in enumerate(content.split('\n'), 1):
        line = line.strip()
        if not line or line.startswith('#') or line.startswith('REM'):
            continue
        
        analysis = analyze_command(line)
        
        if analysis["verdict"] == "MALICIOUS":
            results["verdict"] = "MALICIOUS"
            if analysis["severity"] in ["CRITICAL", "HIGH"]:
                results["severity"] = analysis["severity"]
            elif results["severity"] == "NONE":
                results["severity"] = analysis["severity"]
            
            results["line_matches"].append({
                "line": line_num,
                "content": line[:100],
                "tool": analysis["matched_tool"],
                "patterns": analysis["matched_patterns"],
            })
            results["findings"].extend(analysis["findings"])
    
    # Deduplicate findings
    results["findings"] = list(set(results["findings"]))
    
    return results


def print_lotl_analysis(result: dict):
    """Pretty print LOtL analysis results."""
    print("\n" + "=" * 60)
    print("LIVING-OFF-THE-LAND DETECTOR REPORT")
    print("=" * 60)
    
    if result.get("file"):
        print(f"File: {result['file']}")
    elif result.get("command"):
        print(f"Command: {result['command'][:80]}...")
    
    verdict = result.get("verdict", "UNKNOWN")
    severity = result.get("severity", "NONE")
    
    if verdict == "MALICIOUS":
        print(f"Verdict: \033[91m{verdict}\033[0m (Severity: {severity})")
    else:
        print(f"Verdict: \033[92m{verdict}\033[0m")
    
    print("-" * 60)
    
    if result.get("findings"):
        print("Findings:")
        for f in result["findings"][:10]:
            print(f"  ⚠ {f}")
    
    if result.get("line_matches"):
        print("\nMatched Lines:")
        for match in result["line_matches"][:5]:
            print(f"  Line {match['line']}: {match['tool']}")
            print(f"    Content: {match['content']}")
    
    print("=" * 60 + "\n")


if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python lotl.py <script_file_or_command>")
        sys.exit(1)
    
    arg = sys.argv[1]
    
    if Path(arg).exists():
        result = analyze_script_file(arg)
    else:
        result = analyze_command(arg)
    
    print_lotl_analysis(result)
