import os
import sys
import click
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

from mqtt_auditor.config import ConfigManager
from mqtt_auditor.orchestrator import ScanOrchestrator
from mqtt_auditor.reporter.html_report import HTMLReporter

console = Console()

@click.group()
def main():
    """MQTT Security Auditor CLI Tool

    Audits and pentests MQTT brokers for misconfigurations.
    """
    pass

@main.command()
@click.option("--target", "-t", required=True, help="IP address or domain of the target MQTT broker.")
@click.option("--config", "-c", type=click.Path(exists=True), help="Path to custom YAML config profile.")
def scan(target, config):
    """Scan and audit a target MQTT broker."""
    console.print(Panel.fit(
        f"[bold cyan]MQTT Security Auditor v1.0.0[/bold cyan]\n[dim]Target: {target}[/dim]",
        border_style="purple"
    ))

    try:
        config_manager = ConfigManager(config_path=config)
        orchestrator = ScanOrchestrator(target, config_manager)
        
        with console.status("[bold green]Performing security audit...") as status:
            scan_results = orchestrator.run_scan()
        
        # Display Results in Terminal
        console.print("\n[bold]Audit Report Summary[/bold]")
        console.print(f"Overall Risk Score: [bold red]{scan_results['overall_score']}/10.0[/bold red] ({scan_results['rating']})")

        table = Table(title="Security Findings", show_header=True, header_style="bold magenta")
        table.add_column("Severity", style="dim", width=12)
        table.add_column("Vulnerability ID")
        table.add_column("Description")
        table.add_column("Evidence")

        for finding in scan_results["findings"]:
            sev = finding["severity"]
            if sev == "CRITICAL":
                sev_styled = f"[bold red]{sev}[/bold red]"
            elif sev == "HIGH":
                sev_styled = f"[bold orange3]{sev}[/bold orange3]"
            elif sev == "MEDIUM":
                sev_styled = f"[bold yellow]{sev}[/bold yellow]"
            else:
                sev_styled = f"[bold blue]{sev}[/bold blue]"

            table.add_row(
                sev_styled,
                finding["id"],
                finding["details"],
                str(finding["evidence"])
            )

        console.print(table)
        
        # Generate the HTML report
        reporter = HTMLReporter(target, scan_results)
        report_path = reporter.generate()
        
        console.print(f"\n[bold green]✔ Scan complete. HTML report saved to:[/bold green]")
        console.print(f"[cyan]file://{report_path}[/cyan]\n")

    except Exception as e:
        console.print(f"[bold red]Error running scan: {str(e)}[/bold red]")
        sys.exit(1)

if __name__ == "__main__":
    main()
