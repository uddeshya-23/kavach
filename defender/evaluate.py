"""
Evaluation Framework Module

Tests the Defender tool against various samples and calculates metrics:
- True Positive Rate (TPR)
- False Positive Rate (FPR)
- Detection latency
- Evasion resistance
"""

import time
import json
from pathlib import Path
from typing import List, Dict


def evaluate_detection(malicious_samples: List[str], benign_samples: List[str], detector_func) -> Dict:
    """
    Evaluate a detector function against labeled samples.
    
    Args:
        malicious_samples: List of paths to known malicious files
        benign_samples: List of paths to known benign files
        detector_func: Function that takes a path and returns {"verdict": "MALICIOUS"/"BENIGN"/"SUSPICIOUS"}
    
    Returns:
        Evaluation metrics
    """
    results = {
        "true_positives": 0,
        "false_positives": 0,
        "true_negatives": 0,
        "false_negatives": 0,
        "total_malicious": len(malicious_samples),
        "total_benign": len(benign_samples),
        "detection_times": [],
        "errors": [],
    }
    
    # Test malicious samples
    for sample in malicious_samples:
        start = time.time()
        try:
            result = detector_func(sample)
            elapsed = time.time() - start
            results["detection_times"].append(elapsed)
            
            verdict = result.get("verdict", "UNKNOWN")
            if verdict in ["MALICIOUS", "SUSPICIOUS"]:
                results["true_positives"] += 1
            else:
                results["false_negatives"] += 1
        except Exception as e:
            results["errors"].append({"file": sample, "error": str(e)})
    
    # Test benign samples
    for sample in benign_samples:
        start = time.time()
        try:
            result = detector_func(sample)
            elapsed = time.time() - start
            results["detection_times"].append(elapsed)
            
            verdict = result.get("verdict", "UNKNOWN")
            if verdict == "BENIGN":
                results["true_negatives"] += 1
            else:
                results["false_positives"] += 1
        except Exception as e:
            results["errors"].append({"file": sample, "error": str(e)})
    
    # Calculate metrics
    tp = results["true_positives"]
    fp = results["false_positives"]
    tn = results["true_negatives"]
    fn = results["false_negatives"]
    
    results["metrics"] = {
        "tpr": tp / (tp + fn) if (tp + fn) > 0 else 0,  # Sensitivity
        "fpr": fp / (fp + tn) if (fp + tn) > 0 else 0,  # False alarm rate
        "precision": tp / (tp + fp) if (tp + fp) > 0 else 0,
        "accuracy": (tp + tn) / (tp + tn + fp + fn) if (tp + tn + fp + fn) > 0 else 0,
        "f1_score": 2 * tp / (2 * tp + fp + fn) if (2 * tp + fp + fn) > 0 else 0,
        "avg_detection_time": sum(results["detection_times"]) / len(results["detection_times"]) if results["detection_times"] else 0,
    }
    
    return results


def evaluate_variant_resistance(original_sample: str, variants_dir: str, detector_func) -> Dict:
    """
    Test how well the detector handles obfuscated variants.
    
    Args:
        original_sample: Path to original malicious sample
        variants_dir: Directory containing generated variants
        detector_func: Detection function
    
    Returns:
        Evasion resistance metrics
    """
    results = {
        "original_detected": False,
        "variants_total": 0,
        "variants_detected": 0,
        "variants_evaded": 0,
        "evasion_rate": 0,
    }
    
    # Test original
    try:
        result = detector_func(original_sample)
        results["original_detected"] = result.get("verdict") in ["MALICIOUS", "SUSPICIOUS"]
    except:
        pass
    
    # Test variants
    variants_path = Path(variants_dir)
    if variants_path.exists():
        for variant_file in variants_path.glob("variant_*.py"):
            results["variants_total"] += 1
            try:
                result = detector_func(str(variant_file))
                if result.get("verdict") in ["MALICIOUS", "SUSPICIOUS"]:
                    results["variants_detected"] += 1
                else:
                    results["variants_evaded"] += 1
            except:
                pass
    
    if results["variants_total"] > 0:
        results["evasion_rate"] = results["variants_evaded"] / results["variants_total"]
        results["detection_rate"] = results["variants_detected"] / results["variants_total"]
    
    return results


def print_evaluation_report(results: Dict):
    """Pretty print evaluation results."""
    print("\n" + "=" * 60)
    print("DEFENDER EVALUATION REPORT")
    print("=" * 60)
    
    metrics = results.get("metrics", {})
    
    print(f"\nSample Counts:")
    print(f"  Malicious tested: {results.get('total_malicious', 0)}")
    print(f"  Benign tested: {results.get('total_benign', 0)}")
    
    print(f"\nConfusion Matrix:")
    print(f"  True Positives:  {results.get('true_positives', 0)}")
    print(f"  False Positives: {results.get('false_positives', 0)}")
    print(f"  True Negatives:  {results.get('true_negatives', 0)}")
    print(f"  False Negatives: {results.get('false_negatives', 0)}")
    
    print(f"\nMetrics:")
    print(f"  Detection Rate (TPR): {metrics.get('tpr', 0):.1%}")
    print(f"  False Alarm Rate (FPR): {metrics.get('fpr', 0):.1%}")
    print(f"  Precision: {metrics.get('precision', 0):.1%}")
    print(f"  Accuracy: {metrics.get('accuracy', 0):.1%}")
    print(f"  F1 Score: {metrics.get('f1_score', 0):.3f}")
    print(f"  Avg Detection Time: {metrics.get('avg_detection_time', 0):.3f}s")
    
    if results.get("errors"):
        print(f"\nErrors: {len(results['errors'])}")
    
    print("=" * 60 + "\n")


def run_full_evaluation(samples_dir: str = "samples"):
    """
    Run a full evaluation using samples in the specified directory.
    
    Expected structure:
    samples/
    ├── malicious/
    │   ├── sample1.py
    │   └── sample2.exe
    └── benign/
        ├── clean1.py
        └── clean2.txt
    """
    from .bouncer import scan_file as bouncer_scan
    
    samples_path = Path(samples_dir)
    
    malicious_samples = []
    benign_samples = []
    
    # Collect samples
    malicious_dir = samples_path / "malicious"
    if malicious_dir.exists():
        malicious_samples = [str(f) for f in malicious_dir.iterdir() if f.is_file()]
    
    benign_dir = samples_path / "benign"
    if benign_dir.exists():
        benign_samples = [str(f) for f in benign_dir.iterdir() if f.is_file()]
    
    # Run evaluation
    results = evaluate_detection(malicious_samples, benign_samples, bouncer_scan)
    
    return results


if __name__ == "__main__":
    import sys
    
    samples_dir = sys.argv[1] if len(sys.argv) > 1 else "samples"
    
    print(f"Running evaluation on {samples_dir}...")
    results = run_full_evaluation(samples_dir)
    print_evaluation_report(results)
    
    # Save results
    output_file = Path(samples_dir) / "evaluation_results.json"
    output_file.write_text(json.dumps(results, indent=2, default=str))
    print(f"Results saved to {output_file}")
