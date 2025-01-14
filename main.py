import argparse
import sys
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from scanner import AdvancedSecurityAnalyzer

def main():
    parser = argparse.ArgumentParser(description="vulnurability scanner by gwynbleidd")
    parser.add_argument("url", help="Target URL (e.g., https://example.com)")
    args = parser.parse_args()

    url = args.url
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    console = Console()
    console.print(Panel(f"[bold blue]Scanning Target:[/bold blue] {url}", expand=False))

    analyzer = AdvancedSecurityAnalyzer()
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
        transient=True
    ) as progress:
        task = progress.add_task(description="Scanning...", total=None)
        results = analyzer.comprehensive_scan(url)

    if 'error' in results:
        console.print(f"[bold red]Error:[/bold red] {results['error']}")
        sys.exit(1)

    score = results['security_score']
    color = "green" if score > 80 else "yellow" if score > 50 else "red"
    
    console.print(f"\n[bold]Security Score: [{color}]{score}/100[/{color}][/bold]")

    if not results['findings']:
        console.print("[green]No vulnerabilities found![/green]")
    else:
        table = Table(title="Vulnerabilities Found")
        table.add_column("Severity", style="bold")
        table.add_column("Type", style="cyan")
        table.add_column("Description")

        order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'INFO': 4}
        findings = sorted(results['findings'], key=lambda x: order.get(x['severity'], 5))

        for f in findings:
            sev_color = "red" if f['severity'] in ['CRITICAL', 'HIGH'] else "yellow"
            table.add_row(
                f"[{sev_color}]{f['severity']}[/{sev_color}]",
                f['type'],
                f['desc']
            )
        
        console.print(table)

if __name__ == "__main__":
    main()