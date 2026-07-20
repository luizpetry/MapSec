"""CLI interface for Mapsec."""

from __future__ import annotations

import asyncio
import json
import sys
from datetime import datetime
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from mapsec import __version__
from mapsec.core.engine import Engine
from mapsec.core.models import ScanConfig, ScanReport

# Import plugins to register them
import mapsec.plugins.nmap_scan  # noqa: F401
import mapsec.plugins.dns_enum  # noqa: F401
import mapsec.plugins.vt_lookup  # noqa: F401
import mapsec.plugins.whois_lookup  # noqa: F401
import mapsec.plugins.banner_grab  # noqa: F401

app = typer.Typer(
    name="mapsec",
    help="Modular mapping and security reconnaissance framework.",
    no_args_is_help=True,
)
console = Console()


@app.command()
def scan(
    target: str = typer.Argument(help="Target to scan (IP, domain, or URL)"),
    plugins: str = typer.Option(
        "",
        "-p",
        "--plugins",
        help="Comma-separated list of plugins to use (default: all)",
    ),
    output: str = typer.Option(
        "",
        "-o",
        "--output",
        help="Output file path (default: stdout)",
    ),
    timeout: int = typer.Option(
        300,
        "-t",
        "--timeout",
        help="Scan timeout in seconds",
    ),
    verbose: bool = typer.Option(
        False,
        "-v",
        "--verbose",
        help="Enable verbose output",
    ),
) -> None:
    """Execute a reconnaissance scan against a target."""
    # Parse plugins list
    plugin_list = [p.strip() for p in plugins.split(",") if p.strip()]

    config = ScanConfig(
        target=target,
        plugins=plugin_list,
        timeout=timeout,
    )

    if verbose:
        console.print(f"[bold cyan]Starting scan against:[/] {target}")
        if plugin_list:
            console.print(f"[bold cyan]Plugins:[/] {', '.join(plugin_list)}")
        else:
            console.print("[bold cyan]Plugins:[/] all available")

    # Run the engine
    engine = Engine()
    report = asyncio.run(engine.run(config))

    # Output results
    output_data = report.to_dict()

    if output:
        output_path = Path(output)
        output_path.write_text(json.dumps(output_data, indent=2, ensure_ascii=False))
        console.print(f"\n[bold green]Report saved to:[/] {output}")
    else:
        console.print("\n[bold green]Scan Results:[/]\n")
        _print_report(report)

    # Summary
    successful = sum(1 for r in report.results if r.success)
    total = len(report.results)
    console.print(f"\n[bold]Completed:[/] {successful}/{total} plugins succeeded")


@app.command()
def plugins() -> None:
    """List all available plugins."""
    from mapsec.core.plugin import get_plugins

    table = Table(title="Available Plugins")
    table.add_column("Name", style="cyan")
    table.add_column("Description", style="white")

    for name, cls in get_plugins().items():
        instance = cls()
        table.add_row(name, instance.description)

    console.print(table)


@app.command()
def version() -> None:
    """Show Mapsec version."""
    console.print(f"[bold]Mapsec[/] version [cyan]{__version__}[/]")


def _print_report(report: ScanReport) -> None:
    """Pretty print a scan report."""
    for result in report.results:
        status = "[bold green]SUCCESS[/]" if result.success else "[bold red]FAILED[/]"
        console.print(f"[bold]{result.plugin}[/] - {status} ({result.duration_seconds}s)")

        if result.error:
            console.print(f"  [red]Error:[/] {result.error}")

        if result.data:
            console.print_json(json.dumps(result.data, indent=2, ensure_ascii=False))
        console.print()


def main() -> None:
    """Entry point for the CLI."""
    app()


if __name__ == "__main__":
    main()
