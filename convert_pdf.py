import pymupdf4llm
import pathlib

def convert_pdf_to_md(pdf_path, md_path):
    print(f"Converting {pdf_path} to {md_path}...")
    try:
        md_text = pymupdf4llm.to_markdown(pdf_path)
        pathlib.Path(md_path).write_bytes(md_text.encode())
        print("Conversion successful!")
    except Exception as e:
        print(f"Error during conversion: {e}")

if __name__ == "__main__":
    pdf_file = "AI-Driven-Malware-Detection.pdf"
    md_file = "AI-Driven-Malware-Detection.md"
    convert_pdf_to_md(pdf_file, md_file)
