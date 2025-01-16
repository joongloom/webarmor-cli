import argparse
import sys
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from scanner import AdvancedSecurityAnalyzer

signature = r"""
 __      __          __       ______                                                               
/\ \  __/\ \        /\ \     /\  _  \                                                              
\ \ \/\ \ \ \     __\ \ \____\ \ \L\ \  _ __    ___ ___     ___   _ __                             
 \ \ \ \ \ \ \  /'__`\ \ '__`\\ \  __ \/\`'__\/' __` __`\  / __`\/\`'__\                           
  \ \ \_/ \_\ \/\  __/\ \ \L\ \\ \ \/\ \ \ \/ /\ \/\ \/\ \/\ \L\ \ \ \/                            
   \ `\___x___/\ \____\\ \_,__/ \ \_\ \_\ \_\ \ \_\ \_\ \_\ \____/\ \_\                            
    '\/__//__/  \/____/ \/___/   \/_/\/_/\/_/  \/_/\/_/\/_/\/___/  \/_/                            
                                                                                                   
                                                                                                   
 __                                                           ___                                  
/\ \                      __                                 /\_ \                                 
\ \ \____  __  __        /\_\    ___     ___     ___      __ \//\ \     ___     ___     ___ ___    
 \ \ '__`\/\ \/\ \       \/\ \  / __`\  / __`\ /' _ `\  /'_ `\ \ \ \   / __`\  / __`\ /' __` __`\  
  \ \ \L\ \ \ \_\ \       \ \ \/\ \L\ \/\ \L\ \/\ \/\ \/\ \L\ \ \_\ \_/\ \L\ \/\ \L\ \/\ \/\ \/\ \ 
   \ \_,__/\/`____ \      _\ \ \ \____/\ \____/\ \_\ \_\ \____ \/\____\ \____/\ \____/\ \_\ \_\ \_\
    \/___/  `/___/> \    /\ \_\ \/___/  \/___/  \/_/\/_/\/___L\ \/____/\/___/  \/___/  \/_/\/_/\/_/
               /\___/    \ \____/                         /\____/                                  
               \/__/      \/___/                          \_/__/                                   
"""

def main():
    parser = argparse.ArgumentParser(description="vulnurability scanner by gwynbleidd")
    parser.add_argument("url", help="Target URL (e.g., https://example.com)")
    args = parser.parse_args()

    url = args.url
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    console = Console()

    console.print(f"[bold green]{signature}[/bold green]")
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