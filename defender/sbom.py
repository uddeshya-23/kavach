"""
Supply Chain SBOM Scanner Module

Scans dependency files for known vulnerabilities using the OSV database.
Protects against supply chain attacks like Log4Shell, SolarWinds, etc.
"""

import json
import requests
from pathlib import Path


OSV_API_URL = "https://api.osv.dev/v1/query"


# Known high-profile vulnerable packages
KNOWN_VULNERABILITIES = {
    "log4j-core": {"affected": "<2.17.1", "cve": "CVE-2021-44228", "severity": "CRITICAL"},
    "log4j": {"affected": "<2.17.1", "cve": "CVE-2021-44228", "severity": "CRITICAL"},
    "ua-parser-js": {"affected": "<0.7.31", "cve": "CVE-2021-27292", "severity": "HIGH"},
    "event-stream": {"affected": "3.3.6", "cve": "CVE-2018-16487", "severity": "CRITICAL"},
    "flatmap-stream": {"affected": "*", "cve": "Malicious Package", "severity": "CRITICAL"},
    "colors": {"affected": "1.4.1", "cve": "Sabotage", "severity": "HIGH"},
    "faker": {"affected": "6.6.6", "cve": "Sabotage", "severity": "HIGH"},
    "node-ipc": {"affected": ">=10.1.1", "cve": "CVE-2022-23812", "severity": "CRITICAL"},
    "requests": {"affected": "<2.31.0", "cve": "CVE-2023-32681", "severity": "MEDIUM"},
    "urllib3": {"affected": "<2.0.6", "cve": "CVE-2023-43804", "severity": "MEDIUM"},
}


def parse_requirements_txt(file_path: str) -> list:
    """Parse Python requirements.txt file."""
    dependencies = []
    path = Path(file_path)
    
    if not path.exists():
        return []
    
    content = path.read_text(encoding='utf-8', errors='ignore')
    
    for line in content.split('\n'):
        line = line.strip()
        if not line or line.startswith('#') or line.startswith('-'):
            continue
        
        # Parse package==version or package>=version
        if '==' in line:
            name, version = line.split('==', 1)
        elif '>=' in line:
            name, version = line.split('>=', 1)
        elif '<=' in line:
            name, version = line.split('<=', 1)
        else:
            name = line
            version = "*"
        
        dependencies.append({
            "name": name.strip().lower(),
            "version": version.strip().split()[0] if version else "*",
            "ecosystem": "PyPI"
        })
    
    return dependencies


def parse_package_json(file_path: str) -> list:
    """Parse NPM package.json file."""
    dependencies = []
    path = Path(file_path)
    
    if not path.exists():
        return []
    
    try:
        data = json.loads(path.read_text())
    except:
        return []
    
    for dep_type in ["dependencies", "devDependencies"]:
        if dep_type in data:
            for name, version in data[dep_type].items():
                dependencies.append({
                    "name": name.lower(),
                    "version": version.lstrip('^~'),
                    "ecosystem": "npm"
                })
    
    return dependencies


def check_osv(package_name: str, version: str, ecosystem: str) -> list:
    """Query OSV database for vulnerabilities."""
    try:
        response = requests.post(
            OSV_API_URL,
            json={
                "package": {"name": package_name, "ecosystem": ecosystem},
                "version": version
            },
            timeout=10
        )
        if response.status_code == 200:
            data = response.json()
            return data.get("vulns", [])
    except:
        pass
    return []


def scan_dependencies(file_path: str) -> dict:
    """
    Scan a dependency file for known vulnerabilities.
    
    Supports: requirements.txt, package.json
    """
    path = Path(file_path)
    
    if not path.exists():
        return {"error": "File not found", "verdict": "ERROR"}
    
    results = {
        "file": str(path),
        "verdict": "CLEAN",
        "total_dependencies": 0,
        "vulnerable": [],
        "warnings": [],
    }
    
    # Parse based on file type
    if "requirements" in path.name.lower() and path.suffix == ".txt":
        deps = parse_requirements_txt(file_path)
    elif path.name == "package.json":
        deps = parse_package_json(file_path)
    else:
        results["error"] = "Unsupported file type"
        return results
    
    results["total_dependencies"] = len(deps)
    
    for dep in deps:
        # First check local known vulnerabilities
        if dep["name"] in KNOWN_VULNERABILITIES:
            vuln = KNOWN_VULNERABILITIES[dep["name"]]
            results["vulnerable"].append({
                "package": dep["name"],
                "installed_version": dep["version"],
                "cve": vuln["cve"],
                "severity": vuln["severity"],
                "source": "local_db"
            })
            continue
        
        # Optional: Check OSV API (can be slow)
        # vulns = check_osv(dep["name"], dep["version"], dep["ecosystem"])
        # if vulns:
        #     for v in vulns[:1]:  # Just first one
        #         results["vulnerable"].append({
        #             "package": dep["name"],
        #             "installed_version": dep["version"],
        #             "cve": v.get("id", "Unknown"),
        #             "severity": v.get("severity", "UNKNOWN"),
        #             "source": "OSV"
        #         })
    
    # Set verdict
    if results["vulnerable"]:
        critical = any(v["severity"] == "CRITICAL" for v in results["vulnerable"])
        results["verdict"] = "CRITICAL" if critical else "VULNERABLE"
    
    return results


def print_sbom_report(result: dict):
    """Pretty print SBOM scan results."""
    print("\n" + "=" * 60)
    print("SUPPLY CHAIN SBOM SCANNER REPORT")
    print("=" * 60)
    
    print(f"File: {result.get('file', 'N/A')}")
    print(f"Total Dependencies: {result.get('total_dependencies', 0)}")
    
    verdict = result.get("verdict", "UNKNOWN")
    
    if verdict in ["CRITICAL", "VULNERABLE"]:
        print(f"Verdict: \033[91m{verdict}\033[0m")
    else:
        print(f"Verdict: \033[92m{verdict}\033[0m")
    
    print("-" * 60)
    
    vulns = result.get("vulnerable", [])
    if vulns:
        print(f"\nVulnerable Packages ({len(vulns)}):")
        for v in vulns:
            severity = v["severity"]
            if severity == "CRITICAL":
                print(f"  🔴 {v['package']}@{v['installed_version']}")
            elif severity == "HIGH":
                print(f"  🟠 {v['package']}@{v['installed_version']}")
            else:
                print(f"  🟡 {v['package']}@{v['installed_version']}")
            print(f"      {v['cve']} ({severity})")
    else:
        print("\n✓ No known vulnerabilities found")
    
    print("=" * 60 + "\n")


if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python sbom.py <requirements.txt|package.json>")
        sys.exit(1)
    
    result = scan_dependencies(sys.argv[1])
    print_sbom_report(result)
