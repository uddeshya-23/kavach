"""
CDR (Content Disarm & Reconstruction) Module

Strips hidden code/scripts from documents and rebuilds clean versions.
This is the primary defense against "Patient Zero" attacks like Lazarus.
"""

import fitz  # pymupdf
import os
from pathlib import Path


def check_has_javascript(doc) -> bool:
    """Check if PDF has any JavaScript by scanning xref objects."""
    for xref in range(1, doc.xref_length()):
        try:
            obj_str = doc.xref_object(xref)
            if "/JavaScript" in obj_str or "/JS" in obj_str:
                return True
        except:
            pass
    return False


def sanitize_pdf(input_path: str, output_path: str = None) -> dict:
    """
    Sanitize a PDF by stripping all JavaScript, embedded files, and actions.
    Rebuilds a clean PDF with only text and images.
    
    Args:
        input_path: Path to the potentially malicious PDF
        output_path: Path for the sanitized PDF (default: adds _clean suffix)
    
    Returns:
        dict with sanitization results
    """
    if output_path is None:
        base = Path(input_path).stem
        output_path = str(Path(input_path).parent / f"{base}_clean.pdf")
    
    results = {
        "input": input_path,
        "output": output_path,
        "threats_removed": [],
        "status": "clean"
    }
    
    try:
        # Open the source PDF
        src_doc = fitz.open(input_path)
        
        # Check for JavaScript using low-level API
        if check_has_javascript(src_doc):
            results["threats_removed"].append("JavaScript code detected and removed")
            results["status"] = "sanitized"
        
        # Check for embedded files
        if src_doc.embfile_count() > 0:
            results["threats_removed"].append(f"{src_doc.embfile_count()} embedded file(s) removed")
            results["status"] = "sanitized"
        
        # Check for form widgets (buttons with scripts)
        widget_count = 0
        for page in src_doc:
            for widget in page.widgets():
                if widget.script:
                    widget_count += 1
        if widget_count > 0:
            results["threats_removed"].append(f"{widget_count} widget(s) with scripts removed")
            results["status"] = "sanitized"
        
        # Create a new clean document
        clean_doc = fitz.open()
        
        for page_num in range(len(src_doc)):
            src_page = src_doc[page_num]
            
            # Create new page with same dimensions
            new_page = clean_doc.new_page(
                width=src_page.rect.width,
                height=src_page.rect.height
            )
            
            # Extract and insert text blocks (safe)
            text_dict = src_page.get_text("dict")
            for block in text_dict.get("blocks", []):
                if block.get("type") == 0:  # Text block
                    for line in block.get("lines", []):
                        for span in line.get("spans", []):
                            text = span.get("text", "")
                            origin = fitz.Point(span.get("origin", (0, 0)))
                            fontsize = span.get("size", 11)
                            try:
                                new_page.insert_text(
                                    origin,
                                    text,
                                    fontsize=fontsize
                                )
                            except:
                                pass  # Skip problematic text
            
            # Extract and insert images (sanitized - just pixel data)
            for img in src_page.get_images():
                try:
                    xref = img[0]
                    base_image = src_doc.extract_image(xref)
                    img_bytes = base_image["image"]
                    img_rect = src_page.get_image_rects(xref)[0]
                    new_page.insert_image(img_rect, stream=img_bytes)
                except:
                    pass  # Skip problematic images
            
            # Check for and remove any links/actions
            links = src_page.get_links()
            action_links = [l for l in links if l.get("kind") == fitz.LINK_LAUNCH]
            if action_links:
                results["threats_removed"].append(f"Page {page_num + 1}: {len(action_links)} launch action(s) removed")
                results["status"] = "sanitized"
        
        # Save the clean document
        clean_doc.save(output_path)
        clean_doc.close()
        src_doc.close()
        
        if not results["threats_removed"]:
            results["threats_removed"].append("No threats detected - file was already clean")
        
        return results
        
    except Exception as e:
        results["status"] = "error"
        results["error"] = str(e)
        return results


def print_results(results: dict):
    """Pretty print sanitization results."""
    print("\n" + "=" * 60)
    print("CDR SANITIZATION REPORT")
    print("=" * 60)
    print(f"Input:  {results['input']}")
    print(f"Output: {results['output']}")
    print(f"Status: {results['status'].upper()}")
    print("-" * 60)
    print("Findings:")
    for threat in results.get("threats_removed", []):
        print(f"  • {threat}")
    if results.get("error"):
        print(f"  ⚠ Error: {results['error']}")
    print("=" * 60 + "\n")


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python cdr.py <input.pdf> [output.pdf]")
        sys.exit(1)
    
    input_file = sys.argv[1]
    output_file = sys.argv[2] if len(sys.argv) > 2 else None
    
    results = sanitize_pdf(input_file, output_file)
    print_results(results)
