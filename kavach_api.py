"""
Kavach API Server - Flask backend for the demo UI.

Provides endpoints for:
- File upload and scanning
- PDF sanitization
- Multi-tier detection results
"""

import os
import tempfile
from pathlib import Path
from flask import Flask, request, jsonify, send_file
from flask_cors import CORS

# Import our detection modules
import sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from defender.cdr import sanitize_pdf, check_has_javascript
from defender.bouncer import scan_file as bouncer_scan
from defender.lotl import analyze_script_file as lotl_scan
from defender.sbom import scan_dependencies as sbom_scan

app = Flask(__name__)
CORS(app)  # Enable CORS for frontend

# Upload folder
UPLOAD_FOLDER = tempfile.mkdtemp(prefix="kavach_")
SANITIZED_FOLDER = os.path.join(UPLOAD_FOLDER, "sanitized")
os.makedirs(SANITIZED_FOLDER, exist_ok=True)


@app.route('/api/health', methods=['GET'])
def health():
    """Health check endpoint."""
    return jsonify({"status": "ok", "service": "Kavach API"})


@app.route('/api/scan', methods=['POST'])
def scan_file():
    """
    Scan an uploaded file with all detection tiers.
    
    Returns JSON with scan results from each tier.
    """
    if 'file' not in request.files:
        return jsonify({"error": "No file provided"}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({"error": "No file selected"}), 400
    
    # Save uploaded file
    filename = file.filename
    filepath = os.path.join(UPLOAD_FOLDER, filename)
    file.save(filepath)
    
    ext = Path(filename).suffix.lower()
    
    results = {
        "filename": filename,
        "filepath": filepath,
        "size": os.path.getsize(filepath),
        "extension": ext,
        "verdict": "BENIGN",
        "can_sanitize": ext == ".pdf",
        "tiers": []
    }
    
    threats_found = False
    
    # === TIER 1: CDR Check (PDFs) ===
    if ext == ".pdf":
        try:
            import fitz
            doc = fitz.open(filepath)
            has_js = check_has_javascript(doc)
            embfiles = doc.embfile_count()
            doc.close()
            
            tier_result = {
                "name": "CDR Sanitizer",
                "status": "clean",
                "findings": []
            }
            
            if has_js:
                tier_result["findings"].append("JavaScript code detected")
                tier_result["status"] = "detected"
                threats_found = True
            if embfiles > 0:
                tier_result["findings"].append(f"{embfiles} embedded file(s) detected")
                tier_result["status"] = "detected"
                threats_found = True
            
            if not tier_result["findings"]:
                tier_result["findings"].append("No active content")
            
            results["tiers"].append(tier_result)
        except Exception as e:
            results["tiers"].append({
                "name": "CDR Sanitizer",
                "status": "error",
                "findings": [str(e)]
            })
    
    # === TIER 2: ML Bouncer ===
    try:
        bouncer_result = bouncer_scan(filepath)
        features = bouncer_result.get("features", {})
        
        tier_result = {
            "name": "ML Bouncer",
            "status": "clean" if bouncer_result.get("verdict") == "BENIGN" else "detected",
            "findings": []
        }
        
        tier_result["findings"].append(f"Entropy: {features.get('entropy', 0):.2f}/8.0")
        tier_result["findings"].append(f"Risk Score: {bouncer_result.get('risk_score', 0):.0%}")
        
        if features.get("suspicious_strings"):
            tier_result["findings"].append(f"Patterns: {', '.join(features['suspicious_strings'][:5])}")
        
        if bouncer_result.get("verdict") != "BENIGN":
            threats_found = True
        
        results["tiers"].append(tier_result)
    except Exception as e:
        results["tiers"].append({
            "name": "ML Bouncer",
            "status": "error",
            "findings": [str(e)]
        })
    
    # === TIER 3: LOtL Detector (for scripts) ===
    if ext in [".bat", ".cmd", ".ps1", ".vbs"]:
        try:
            lotl_result = lotl_scan(filepath)
            
            tier_result = {
                "name": "LOtL Detector",
                "status": "clean" if lotl_result.get("verdict") == "BENIGN" else "detected",
                "findings": lotl_result.get("findings", [])[:5]
            }
            
            if lotl_result.get("verdict") == "MALICIOUS":
                threats_found = True
            
            results["tiers"].append(tier_result)
        except Exception as e:
            results["tiers"].append({
                "name": "LOtL Detector",
                "status": "error",
                "findings": [str(e)]
            })
    
    # === TIER 4: SBOM Scanner (for requirements.txt) ===
    if "requirements" in filename.lower() and ext == ".txt":
        try:
            sbom_result = sbom_scan(filepath)
            
            tier_result = {
                "name": "SBOM Scanner",
                "status": "clean" if sbom_result.get("verdict") == "CLEAN" else "detected",
                "findings": []
            }
            
            tier_result["findings"].append(f"Dependencies: {sbom_result.get('total_dependencies', 0)}")
            
            for vuln in sbom_result.get("vulnerable", [])[:3]:
                tier_result["findings"].append(f"🔴 {vuln['package']}@{vuln['installed_version']} - {vuln['cve']}")
            
            if sbom_result.get("vulnerable"):
                threats_found = True
            
            results["tiers"].append(tier_result)
        except Exception as e:
            results["tiers"].append({
                "name": "SBOM Scanner",
                "status": "error",
                "findings": [str(e)]
            })
    
    # Set final verdict
    if threats_found:
        results["verdict"] = "MALICIOUS"
    
    return jsonify(results)


@app.route('/api/sanitize', methods=['POST'])
def sanitize_file():
    """
    Sanitize an uploaded PDF file using CDR.
    
    Returns the sanitized file.
    """
    if 'file' not in request.files:
        return jsonify({"error": "No file provided"}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({"error": "No file selected"}), 400
    
    filename = file.filename
    if not filename.lower().endswith('.pdf'):
        return jsonify({"error": "Only PDF files can be sanitized"}), 400
    
    # Save uploaded file
    filepath = os.path.join(UPLOAD_FOLDER, filename)
    file.save(filepath)
    
    # Sanitize
    output_path = os.path.join(SANITIZED_FOLDER, f"clean_{filename}")
    result = sanitize_pdf(filepath, output_path)
    
    if result.get("status") == "error":
        return jsonify({"error": result.get("error", "Sanitization failed")}), 500
    
    return jsonify({
        "status": "success",
        "original": filename,
        "sanitized": f"clean_{filename}",
        "threats_removed": result.get("threats_removed", []),
        "download_url": f"/api/download/{os.path.basename(output_path)}"
    })


@app.route('/api/download/<filename>', methods=['GET'])
def download_file(filename):
    """Download a sanitized file."""
    filepath = os.path.join(SANITIZED_FOLDER, filename)
    if os.path.exists(filepath):
        return send_file(filepath, as_attachment=True)
    return jsonify({"error": "File not found"}), 404


if __name__ == '__main__':
    print("=" * 50)
    print("🛡️ KAVACH API Server")
    print("=" * 50)
    print(f"Upload folder: {UPLOAD_FOLDER}")
    print("Starting server on http://localhost:5000")
    print("=" * 50)
    app.run(debug=True, port=5000)
