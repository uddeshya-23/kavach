"""
Variant Generator Module - Creates malware variants for testing.

Uses LLM to rewrite malicious code with obfuscation techniques,
generating variants to test detection robustness.
"""

import requests
import json
import random
import string
from pathlib import Path


OLLAMA_URL = "http://localhost:11434/api/generate"
DEFAULT_MODEL = "deepseek-r1:1.5b"


OBFUSCATION_PROMPT = """You are a code obfuscation tool. Your job is to rewrite the given code while preserving its functionality.

Apply these transformations:
1. Rename all variables to random names
2. Split string literals into concatenated parts
3. Add meaningless comment lines
4. Reorder independent statements where possible
5. Use alternative syntax where available

Return ONLY the obfuscated code, no explanations.

Original code:
```
{code}
```

Obfuscated version:"""


def generate_random_name(length: int = 8) -> str:
    """Generate a random variable name."""
    return ''.join(random.choices(string.ascii_lowercase, k=length))


def simple_obfuscate(code: str) -> str:
    """
    Apply simple obfuscation without LLM.
    Faster but less sophisticated.
    """
    lines = code.split('\n')
    obfuscated = []
    
    # Variable name mapping
    var_map = {}
    
    for line in lines:
        # Add random comments
        if random.random() < 0.2:
            obfuscated.append(f"# {generate_random_name(20)}")
        
        # Simple variable renaming (basic pattern)
        words = line.split()
        new_words = []
        for word in words:
            if word.isidentifier() and word not in ['def', 'class', 'import', 'from', 'return', 'if', 'else', 'for', 'while', 'try', 'except', 'with', 'as', 'in', 'and', 'or', 'not', 'True', 'False', 'None']:
                if word not in var_map:
                    var_map[word] = generate_random_name()
                new_words.append(var_map.get(word, word))
            else:
                new_words.append(word)
        
        obfuscated.append(' '.join(new_words))
    
    return '\n'.join(obfuscated)


def llm_obfuscate(code: str, model: str = DEFAULT_MODEL) -> str:
    """
    Use LLM to obfuscate code more naturally.
    """
    try:
        response = requests.post(
            OLLAMA_URL,
            json={
                "model": model,
                "prompt": OBFUSCATION_PROMPT.format(code=code),
                "stream": False,
                "options": {
                    "temperature": 0.7,
                    "num_predict": 2000
                }
            },
            timeout=120
        )
        
        if response.status_code == 200:
            result = response.json()
            obfuscated = result.get("response", "")
            # Clean up markdown if present
            if "```" in obfuscated:
                parts = obfuscated.split("```")
                if len(parts) >= 2:
                    obfuscated = parts[1]
                    if obfuscated.startswith("python"):
                        obfuscated = obfuscated[6:]
            return obfuscated.strip()
    except:
        pass
    
    # Fallback to simple obfuscation
    return simple_obfuscate(code)


def generate_variants(code: str, count: int = 10, use_llm: bool = True) -> list:
    """
    Generate multiple variants of the given code.
    
    Args:
        code: Original code to obfuscate
        count: Number of variants to generate
        use_llm: Whether to use LLM (slower but better)
    
    Returns:
        List of variant codes
    """
    variants = []
    
    for i in range(count):
        if use_llm and i < 5:  # Use LLM for first 5, then fall back
            variant = llm_obfuscate(code)
        else:
            variant = simple_obfuscate(code)
        
        variants.append({
            "index": i + 1,
            "method": "llm" if use_llm and i < 5 else "simple",
            "code": variant,
            "original_hash": hash(code),
            "variant_hash": hash(variant),
        })
    
    return variants


def save_variants(variants: list, output_dir: str):
    """Save generated variants to files."""
    path = Path(output_dir)
    path.mkdir(parents=True, exist_ok=True)
    
    for v in variants:
        file_path = path / f"variant_{v['index']:04d}.py"
        file_path.write_text(v["code"])
    
    # Save metadata
    meta_path = path / "variants_meta.json"
    meta = [{"index": v["index"], "method": v["method"]} for v in variants]
    meta_path.write_text(json.dumps(meta, indent=2))
    
    print(f"Saved {len(variants)} variants to {output_dir}")


if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python variant_gen.py <source_file> [count] [output_dir]")
        sys.exit(1)
    
    source_file = sys.argv[1]
    count = int(sys.argv[2]) if len(sys.argv) > 2 else 10
    output_dir = sys.argv[3] if len(sys.argv) > 3 else "variants"
    
    code = Path(source_file).read_text()
    
    print(f"Generating {count} variants...")
    variants = generate_variants(code, count, use_llm=True)
    
    save_variants(variants, output_dir)
    print(f"Done! Generated {len(variants)} variants.")
