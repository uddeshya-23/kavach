"""
Unified CLI for the Defender malware detection tool.

Usage:
    python -m defender.cli sanitize <file>    # CDR sanitization
    python -m defender.cli scan <file>        # Full scan (all tiers)
    python -m defender.cli explain <file>     # LLM analysis
    python -m defender.cli bouncer <file>     # ML Bouncer only
"""

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from pathlib import Path

console = Console()


@click.group()
def cli():
    """Defender - AI Malware Detection & Sanitization Tool"""
    pass


@cli.command()
@click.argument('file_path', type=click.Path(exists=True))
@click.option('--output', '-o', type=click.Path(), help='Output path for sanitized file')
def sanitize(file_path: str, output: str):
    """Sanitize a file using CDR (Content Disarm & Reconstruction)"""
    from .cdr import sanitize_pdf
    
    file_ext = Path(file_path).suffix.lower()
    
    if file_ext != '.pdf':
        console.print(f"[red]Error: Only PDF files are supported currently. Got: {file_ext}[/red]")
        return
    
    console.print(Panel.fit(
        "[bold cyan]CDR SANITIZATION[/bold cyan]\n"
        f"Input: {file_path}",
        title="🛡️ Defender"
    ))
    
    results = sanitize_pdf(file_path, output)
    
    table = Table(title="Sanitization Results")
    table.add_column("Property", style="cyan")
    table.add_column("Value", style="green")
    
    table.add_row("Input", results["input"])
    table.add_row("Output", results["output"])
    table.add_row("Status", f"[bold]{results['status'].upper()}[/bold]")
    
    console.print(table)
    
    if results["threats_removed"]:
        console.print("\n[bold yellow]Findings:[/bold yellow]")
        for threat in results["threats_removed"]:
            console.print(f"  • {threat}")
    
    if results["status"] == "sanitized":
        console.print("\n[bold green]✅ File sanitized successfully![/bold green]")
    elif results["status"] == "clean":
        console.print("\n[bold green]✅ File was already clean.[/bold green]")
    else:
        console.print(f"\n[bold red]❌ Error: {results.get('error', 'Unknown')}[/bold red]")


@cli.command()
@click.argument('file_path', type=click.Path(exists=True))
def bouncer(file_path: str):
    """Run ML Bouncer scan on a file"""
    from .bouncer import scan_file
    
    console.print(Panel.fit(
        "[bold cyan]ML BOUNCER SCAN[/bold cyan]\n"
        f"Target: {file_path}",
        title="🛡️ Defender - Tier 1"
    ))
    
    result = scan_file(file_path)
    features = result.get("features", {})
    
    table = Table(title="File Analysis")
    table.add_column("Property", style="cyan")
    table.add_column("Value", style="white")
    
    table.add_row("File", features.get("file_name", "N/A"))
    table.add_row("Type", features.get("file_type", "Unknown"))
    table.add_row("Size", f"{features.get('file_size', 0):,} bytes")
    table.add_row("Entropy", f"{features.get('entropy', 0):.2f} / 8.0")
    table.add_row("MD5", features.get("md5", "N/A"))
    
    console.print(table)
    
    verdict = result.get("verdict", "UNKNOWN")
    risk = result.get("risk_score", 0)
    
    if verdict == "MALICIOUS":
        console.print(f"\n[bold red]⚠ VERDICT: {verdict} (Risk: {risk:.0%})[/bold red]")
    elif verdict == "SUSPICIOUS":
        console.print(f"\n[bold yellow]⚠ VERDICT: {verdict} (Risk: {risk:.0%})[/bold yellow]")
    else:
        console.print(f"\n[bold green]✓ VERDICT: {verdict} (Risk: {risk:.0%})[/bold green]")
    
    if features.get("suspicious_strings"):
        console.print("\n[yellow]Suspicious Patterns:[/yellow]")
        for s in features["suspicious_strings"]:
            console.print(f"  ⚠ {s}")


@cli.command()
@click.argument('file_path', type=click.Path(exists=True))
@click.option('--model', '-m', default='qwen3:4b', help='Ollama model to use')
def explain(file_path: str, model: str):
    """Get LLM explanation for a suspicious file"""
    from .detective import analyze_file
    
    console.print(Panel.fit(
        "[bold cyan]LLM DETECTIVE ANALYSIS[/bold cyan]\n"
        f"Target: {file_path}\n"
        f"Model: {model}",
        title="🛡️ Defender - Tier 3"
    ))
    
    console.print("[dim]Analyzing with LLM... (this may take a moment)[/dim]")
    
    result = analyze_file(file_path, model)
    
    verdict = result.get("verdict", "UNKNOWN")
    
    if verdict == "MALICIOUS":
        console.print(f"\n[bold red]⚠ VERDICT: {verdict}[/bold red]")
    elif verdict == "SUSPICIOUS":
        console.print(f"\n[bold yellow]⚠ VERDICT: {verdict}[/bold yellow]")
    elif verdict == "BENIGN":
        console.print(f"\n[bold green]✓ VERDICT: {verdict}[/bold green]")
    else:
        console.print(f"\n[bold]VERDICT: {verdict}[/bold]")
    
    console.print(f"Confidence: {result.get('confidence', 'N/A')}")
    console.print(f"\n[bold]Explanation:[/bold]\n{result.get('explanation', 'N/A')}")
    
    if result.get("red_flags"):
        console.print("\n[yellow]Red Flags:[/yellow]")
        for flag in result["red_flags"]:
            console.print(f"  ⚠ {flag}")


@cli.command()
@click.argument('file_path', type=click.Path(exists=True))
@click.option('--model', '-m', default='qwen3:4b', help='Ollama model for LLM tier')
def scan(file_path: str, model: str):
    """Full multi-tier scan of a file"""
    from .cdr import check_has_javascript
    from .bouncer import scan_file as bouncer_scan
    from .detective import analyze_file
    import fitz
    
    console.print(Panel.fit(
        "[bold cyan]MULTI-TIER SCAN[/bold cyan]\n"
        f"Target: {file_path}",
        title="🛡️ Defender"
    ))
    
    file_ext = Path(file_path).suffix.lower()
    threats_found = []
    
    # === TIER 1: CDR Check ===
    if file_ext in ['.pdf', '.docx', '.xlsx']:
        console.print("\n[bold cyan]━━━ Tier 1: CDR Analysis ━━━[/bold cyan]")
        try:
            doc = fitz.open(file_path)
            has_js = check_has_javascript(doc)
            embfiles = doc.embfile_count()
            doc.close()
            
            if has_js:
                console.print("  [red]⚠ JavaScript detected[/red]")
                threats_found.append("JavaScript in document")
            if embfiles > 0:
                console.print(f"  [red]⚠ {embfiles} embedded file(s) detected[/red]")
                threats_found.append(f"{embfiles} embedded files")
            if not has_js and embfiles == 0:
                console.print("  [green]✓ No active content[/green]")
        except Exception as e:
            console.print(f"  [yellow]⚠ CDR check failed: {e}[/yellow]")
    
    # === TIER 2: ML Bouncer ===
    console.print("\n[bold cyan]━━━ Tier 2: ML Bouncer ━━━[/bold cyan]")
    bouncer_result = bouncer_scan(file_path)
    features = bouncer_result.get("features", {})
    
    console.print(f"  Type: {features.get('file_type', 'Unknown')}")
    console.print(f"  Entropy: {features.get('entropy', 0):.2f}/8.0")
    console.print(f"  Risk Score: {bouncer_result.get('risk_score', 0):.0%}")
    
    b_verdict = bouncer_result.get("verdict", "UNKNOWN")
    if b_verdict == "MALICIOUS":
        console.print(f"  [red]⚠ Verdict: {b_verdict}[/red]")
        threats_found.append("ML Bouncer: MALICIOUS")
    elif b_verdict == "SUSPICIOUS":
        console.print(f"  [yellow]⚠ Verdict: {b_verdict}[/yellow]")
        threats_found.append("ML Bouncer: SUSPICIOUS")
    else:
        console.print(f"  [green]✓ Verdict: {b_verdict}[/green]")
    
    if features.get("suspicious_strings"):
        for s in features["suspicious_strings"][:3]:  # Show first 3
            console.print(f"    ⚠ Pattern: {s}")
    
    # === TIER 3: LLM Detective (only for scripts or suspicious files) ===
    if file_ext in ['.py', '.js', '.ps1', '.sh', '.bat', '.vbs'] or b_verdict != "BENIGN":
        console.print("\n[bold cyan]━━━ Tier 3: LLM Detective ━━━[/bold cyan]")
        console.print(f"  [dim]Model: {model}[/dim]")
        
        try:
            llm_result = analyze_file(file_path, model)
            l_verdict = llm_result.get("verdict", "UNKNOWN")
            
            if l_verdict == "MALICIOUS":
                console.print(f"  [red]⚠ Verdict: {l_verdict}[/red]")
                threats_found.append("LLM Detective: MALICIOUS")
            elif l_verdict == "SUSPICIOUS":
                console.print(f"  [yellow]⚠ Verdict: {l_verdict}[/yellow]")
            else:
                console.print(f"  [green]✓ Verdict: {l_verdict}[/green]")
            
            if llm_result.get("explanation"):
                console.print(f"  [dim]{llm_result['explanation'][:200]}...[/dim]")
        except Exception as e:
            console.print(f"  [yellow]⚠ LLM analysis failed: {e}[/yellow]")
    
    # === FINAL VERDICT ===
    console.print("\n" + "=" * 50)
    if threats_found:
        console.print("[bold red]🚨 THREATS DETECTED:[/bold red]")
        for t in threats_found:
            console.print(f"  • {t}")
        console.print("\n[bold yellow]Recommendation: QUARANTINE or SANITIZE this file[/bold yellow]")
    else:
        console.print("[bold green]✅ FILE APPEARS CLEAN[/bold green]")
    console.print("=" * 50)


if __name__ == '__main__':
    cli()
