"""
Signature Intelligence Module - Tier 0
Detects known malware using YARA rules and cryptographic hashes.
"""

import os
import hashlib
import yara
from pathlib import Path

# Initial YARA Rules
# These are kept in-code for the prototype simplicity, but can be loaded from .yar files
RULES_SOURCE = """
rule EICAR_Test_File {
    meta:
        description = "Standard Antivirus Test File"
        author = "Kavach"
        severity = "High"
    strings:
        $eicar = "X5O!P%@AP[4\\\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    condition:
        $eicar
}

rule Generic_Python_Backdoor {
    meta:
        description = "Detects common socket-based Python backdoors"
        severity = "High"
    strings:
        $s1 = "socket.socket"
        $s2 = "connect(("
        $s3 = "subprocess.Popen"
        $s4 = "os.dup2"
    condition:
        all of them
}

rule Suspicious_PDF_Javascript {
    meta:
        description = "Detects PDF files with suspicious JS triggers"
        severity = "Medium"
    strings:
        $js = "/JS"
        $js_openAction = "/OpenAction"
        $js_script = "Javascript"
    condition:
        any of them and filesize < 1MB
}

rule Lazarus_Style_Dropper {
    meta:
        description = "Simulates Lazarus Group evasion patterns"
        severity = "Critical"
    strings:
        $str1 = "VirtualAlloc"
        $str2 = "CreateRemoteThread"
        $str3 = "certutil -urlcache"
    condition:
        2 of them
}
"""

class SignatureEngine:
    def __init__(self):
        try:
            self.rules = yara.compile(source=RULES_SOURCE)
        except Exception as e:
            print(f"Error compiling YARA rules: {e}")
            self.rules = None
            
        # Known Bad Hashes (Example: EICAR MD5)
        self.blacklist_hashes = {
            "44d88612fea8a8f36de82e1278abb02f": "EICAR Test File (MD5)",
            "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f": "EICAR Test File (SHA256)"
        }

    def scan_file(self, file_path: str) -> dict:
        """
        Scan a file using hashes and YARA rules.
        """
        path = Path(file_path)
        if not path.exists():
            return {"status": "error", "error": "File not found"}

        data = path.read_bytes()
        md5 = hashlib.md5(data).hexdigest()
        sha256 = hashlib.sha256(data).hexdigest()

        result = {
            "name": "Signature Intelligence",
            "status": "clean",
            "findings": [],
            "verdict": "BENIGN"
        }

        # 1. Check Hashes
        if md5 in self.blacklist_hashes:
            result["findings"].append(f"Hash Match: {self.blacklist_hashes[md5]}")
            result["status"] = "detected"
            result["verdict"] = "MALICIOUS"
        elif sha256 in self.blacklist_hashes:
            result["findings"].append(f"Hash Match: {self.blacklist_hashes[sha256]}")
            result["status"] = "detected"
            result["verdict"] = "MALICIOUS"

        # 2. Check YARA Rules
        if self.rules:
            matches = self.rules.match(data=data)
            for match in matches:
                desc = match.meta.get('description', match.rule)
                severity = match.meta.get('severity', 'High')
                result["findings"].append(f"YARA Hit: [{severity}] {desc}")
                result["status"] = "detected"
                result["verdict"] = "MALICIOUS"

        if not result["findings"]:
            result["findings"].append("No known signatures matched")

        return result

# Singleton instance
engine = SignatureEngine()

def scan_signatures(file_path: str) -> dict:
    return engine.scan_file(file_path)

if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        res = scan_signatures(sys.argv[1])
        print(res)
