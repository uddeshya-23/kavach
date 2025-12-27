"""
LLM Detective Module - Semantic analysis using local Ollama.

Uses a local LLM to analyze code snippets and explain WHY they are malicious.
This provides Explainable AI (XAI) for security decisions.
"""

import requests
import json
from pathlib import Path


OLLAMA_URL = "http://localhost:11434/api/generate"
DEFAULT_MODEL = "deepseek-r1:1.5b"  # User's installed model

SYSTEM_PROMPT = """You are a cybersecurity malware analyst. Your job is to analyze code snippets and determine if they are MALICIOUS, SUSPICIOUS, or BENIGN.

For each analysis, you must:
1. State your verdict: MALICIOUS, SUSPICIOUS, or BENIGN
2. Explain WHY in 2-3 sentences
3. Identify specific red flags or concerning patterns

Be concise but thorough. Focus on:
- Network connections to unknown hosts
- File system access (especially to system directories)
- Credential harvesting patterns
- Obfuscation techniques
- Data exfiltration patterns
- Persistence mechanisms
"""


def analyze_code(code: str, model: str = DEFAULT_MODEL) -> dict:
    """
    Analyze a code snippet using the local LLM.
    
    Args:
        code: The code snippet to analyze
        model: Ollama model to use
    
    Returns:
        dict with verdict, explanation, and confidence
    """
    prompt = f"""Analyze this code for malicious intent:

```
{code}
```

Provide your analysis in this exact format:
VERDICT: [MALICIOUS/SUSPICIOUS/BENIGN]
CONFIDENCE: [HIGH/MEDIUM/LOW]
EXPLANATION: [Your detailed explanation]
RED_FLAGS: [List any suspicious patterns found]
"""

    try:
        response = requests.post(
            OLLAMA_URL,
            json={
                "model": model,
                "prompt": prompt,
                "system": SYSTEM_PROMPT,
                "stream": False,
                "options": {
                    "temperature": 0.1,  # Low temp for consistent analysis
                    "num_predict": 500
                }
            },
            timeout=60
        )
        
        if response.status_code != 200:
            return {
                "verdict": "ERROR",
                "explanation": f"Ollama API error: {response.status_code}",
                "raw": None
            }
        
        result = response.json()
        raw_response = result.get("response", "")
        
        # Parse the structured response
        verdict = "UNKNOWN"
        confidence = "UNKNOWN"
        explanation = ""
        red_flags = []
        
        for line in raw_response.split("\n"):
            line = line.strip()
            if line.startswith("VERDICT:"):
                verdict = line.replace("VERDICT:", "").strip()
            elif line.startswith("CONFIDENCE:"):
                confidence = line.replace("CONFIDENCE:", "").strip()
            elif line.startswith("EXPLANATION:"):
                explanation = line.replace("EXPLANATION:", "").strip()
            elif line.startswith("RED_FLAGS:"):
                flags_str = line.replace("RED_FLAGS:", "").strip()
                red_flags = [f.strip() for f in flags_str.split(",") if f.strip()]
        
        return {
            "verdict": verdict,
            "confidence": confidence,
            "explanation": explanation,
            "red_flags": red_flags,
            "raw": raw_response
        }
        
    except requests.exceptions.ConnectionError:
        return {
            "verdict": "ERROR",
            "explanation": "Cannot connect to Ollama. Is it running?",
            "raw": None
        }
    except Exception as e:
        return {
            "verdict": "ERROR",
            "explanation": str(e),
            "raw": None
        }


def analyze_file(file_path: str, model: str = DEFAULT_MODEL) -> dict:
    """
    Analyze a file's contents using the LLM.
    """
    path = Path(file_path)
    
    if not path.exists():
        return {"verdict": "ERROR", "explanation": "File not found"}
    
    # Read file content
    try:
        content = path.read_text(encoding='utf-8', errors='ignore')
    except:
        content = path.read_bytes().decode('utf-8', errors='ignore')
    
    # Truncate if too long (LLM context limit)
    if len(content) > 4000:
        content = content[:4000] + "\n... [TRUNCATED]"
    
    result = analyze_code(content, model)
    result["file"] = str(path)
    return result


def print_analysis(result: dict):
    """Pretty print analysis results."""
    print("\n" + "=" * 60)
    print("LLM DETECTIVE ANALYSIS")
    print("=" * 60)
    
    if result.get("file"):
        print(f"File: {result['file']}")
    
    verdict = result.get("verdict", "UNKNOWN")
    if verdict == "MALICIOUS":
        print(f"Verdict: \033[91m{verdict}\033[0m")  # Red
    elif verdict == "SUSPICIOUS":
        print(f"Verdict: \033[93m{verdict}\033[0m")  # Yellow
    elif verdict == "BENIGN":
        print(f"Verdict: \033[92m{verdict}\033[0m")  # Green
    else:
        print(f"Verdict: {verdict}")
    
    print(f"Confidence: {result.get('confidence', 'N/A')}")
    print("-" * 60)
    print(f"Explanation: {result.get('explanation', 'N/A')}")
    
    if result.get("red_flags"):
        print("\nRed Flags:")
        for flag in result["red_flags"]:
            print(f"  ⚠ {flag}")
    
    print("=" * 60 + "\n")


if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python detective.py <file_path> [model]")
        print(f"Default model: {DEFAULT_MODEL}")
        sys.exit(1)
    
    file_path = sys.argv[1]
    model = sys.argv[2] if len(sys.argv) > 2 else DEFAULT_MODEL
    
    print(f"Analyzing {file_path} with {model}...")
    result = analyze_file(file_path, model)
    print_analysis(result)
