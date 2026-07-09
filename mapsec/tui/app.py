"""Mapsec TUI Application — Terminal Interface for Security Reconnaissance."""

from __future__ import annotations

import json
import time
from datetime import datetime
from pathlib import Path

from textual.app import App, ComposeResult
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.widgets import (
    Button,
    Checkbox,
    Footer,
    Header,
    Input,
    Label,
    ProgressBar,
    Rule,
    Static,
)
from mapsec.core.engine import Engine
from mapsec.core.models import PluginResult, ScanConfig, ScanReport

# Import plugins to register them
import mapsec.plugins.nmap_scan  # noqa: F401
import mapsec.plugins.dns_enum  # noqa: F401
import mapsec.plugins.vt_lookup  # noqa: F401

from mapsec.tui.widgets import PluginStatus, ResultPanel


class MapsecApp(App):
    """Mapsec TUI — Modular mapping and security reconnaissance."""

    TITLE = "Mapsec"
    SUB_TITLE = "Security Reconnaissance Framework"

    CSS = """
    Screen {
        background: $surface;
    }

    #input_section {
        height: auto;
        padding: 1 2;
        margin: 0 0 1 0;
        border: solid $primary;
    }

    #target_label {
        color: $text-muted;
        margin-bottom: 1;
    }

    #target_input {
        width: 100%;
        height: 3;
        border: solid $accent;
    }

    #plugin_section {
        height: auto;
        padding: 1 2;
        margin: 0 0 1 0;
        border: round $secondary;
    }

    #plugin_label {
        color: $text-muted;
        margin-bottom: 1;
    }

    #plugin_row {
        height: auto;
    }

    Checkbox {
        margin: 0 2 0 0;
    }

    #button_row {
        height: auto;
        padding: 0 2;
        margin: 0 0 1 0;
    }

    Button {
        width: 16;
        margin: 0 1;
    }

    #btn_scan {
        background: $primary;
        color: $text;
    }

    #btn_cancel {
        background: $error;
        color: $text;
    }

    #progress_section {
        height: auto;
        padding: 0 2;
        margin: 0 0 1 0;
    }

    #progress_label {
        color: $text-muted;
        margin-bottom: 1;
    }

    #scan_progress {
        width: 100%;
        height: 1;
        margin-bottom: 1;
    }

    #status_row {
        height: auto;
        padding: 0 2;
        margin: 0 0 1 0;
    }

    PluginStatus {
        height: 1;
    }

    #results_section {
        height: 1fr;
        border: solid $accent;
    }

    #results_scroll {
        height: 1fr;
        padding: 1;
    }

    ResultPanel {
        height: auto;
        margin: 0 0 1 0;
    }

    #export_section {
        height: auto;
        padding: 0 2;
        margin: 0;
    }

    #btn_export {
        background: $success;
        color: $text;
    }
    """

    BINDINGS = [
        ("ctrl+q", "quit", "Quit"),
        ("ctrl+e", "export_results", "Export"),
    ]

    def __init__(self) -> None:
        super().__init__()
        self._scan_report: ScanReport | None = None
        self._is_scanning = False

    def compose(self) -> ComposeResult:
        """Build the UI layout."""
        yield Header()

        # Input section
        with Vertical(id="input_section"):
            yield Label("Target:", id="target_label")
            yield Input(
                placeholder="e.g. example.com or 192.168.1.1",
                id="target_input",
            )

        # Plugin selection
        with Vertical(id="plugin_section"):
            yield Label("Plugins:", id="plugin_label")
            with Horizontal(id="plugin_row"):
                yield Checkbox("nmap", id="chk_nmap", value=True)
                yield Checkbox("dns", id="chk_dns", value=True)
                yield Checkbox("vt", id="chk_vt", value=False)

        # Buttons
        with Horizontal(id="button_row"):
            yield Button("Scan", variant="primary", id="btn_scan")
            yield Button("Cancel", variant="error", id="btn_cancel", disabled=True)

        # Progress section
        with Vertical(id="progress_section"):
            yield Label("Progress:", id="progress_label")
            yield ProgressBar(total=100, show_eta=False, id="scan_progress")

        # Plugin status row
        with Horizontal(id="status_row"):
            yield PluginStatus("nmap", id="status_nmap")
            yield PluginStatus("dns", id="status_dns")
            yield PluginStatus("vt", id="status_vt")

        yield Rule()

        # Results section
        with VerticalScroll(id="results_scroll"):
            pass  # Results will be added dynamically

        # Export section
        with Horizontal(id="export_section"):
            yield Button("Export JSON", variant="success", id="btn_export", disabled=True)

        yield Footer()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle button press events."""
        match event.button.id:
            case "btn_scan":
                self.action_start_scan()
            case "btn_cancel":
                self.action_cancel_scan()
            case "btn_export":
                self.action_export_results()

    def on_input_submitted(self, event: Input.Submitted) -> None:
        """Start scan when Enter is pressed in input field."""
        if not self._is_scanning:
            self.action_start_scan()

    def action_start_scan(self) -> None:
        """Gather inputs and start the scan."""
        target = self.query_one("#target_input", Input).value.strip()
        if not target:
            self._log_error("Enter a scan target.")
            return

        plugins = self._get_selected_plugins()
        if not plugins:
            self._log_error("Select at least one plugin.")
            return

        # Reset UI
        self._scan_report = None
        self._is_scanning = True
        self.query_one("#btn_scan", Button).disabled = True
        self.query_one("#btn_cancel", Button).disabled = False
        self.query_one("#btn_export", Button).disabled = True
        self.query_one("#scan_progress", ProgressBar).update(progress=0)

        # Reset plugin status widgets
        for plugin_name in ["nmap", "dns", "vt"]:
            status = self.query_one(f"#status_{plugin_name}", PluginStatus)
            if plugin_name in plugins:
                status.set_running()
            else:
                status._status = "pending"
                status._update_display()

        # Clear previous results
        results_container = self.query_one("#results_scroll", VerticalScroll)
        results_container.remove_children()

        # Log start
        self._log_info(f"Starting scan: [bold]{target}[/] ({len(plugins)} plugins)")

        # Run scan
        self.run_worker(self._scan_task(target, plugins), exclusive=True, group="scan")

    async def _scan_task(self, target: str, plugins: list[str]) -> None:
        """Execute plugins sequentially for progress tracking."""
        total = len(plugins)
        report = ScanReport(target=target, started_at=datetime.now())
        engine = Engine()

        for i, plugin_name in enumerate(plugins):
            # Update status
            status = self.query_one(f"#status_{plugin_name}", PluginStatus)
            status.set_running()

            # Update progress
            pct = int((i / total) * 100)
            self.query_one("#scan_progress", ProgressBar).update(progress=pct)
            self._log_info(f"Running [bold]{plugin_name.upper()}[/]...")

            # Execute plugin
            config = ScanConfig(target=target, plugins=[plugin_name])
            start = time.time()

            try:
                plugin_report = await engine.run(config)
                if plugin_report.results:
                    result = plugin_report.results[0]
                    report.add_result(result)

                    if result.success:
                        status.set_success(result.duration_seconds)
                        self._log_success(f"{plugin_name.upper()} complete ({result.duration_seconds:.1f}s)")
                    else:
                        status.set_failed(result.error or "Unknown error")
                        self._log_error(f"{plugin_name.upper()} failed: {result.error}")
            except Exception as e:
                result = PluginResult(
                    plugin=plugin_name,
                    target=target,
                    success=False,
                    error=str(e),
                    duration_seconds=time.time() - start,
                )
                report.add_result(result)
                status.set_failed(str(e))
                self._log_error(f"{plugin_name.upper()} exception: {e}")

        # Final progress
        self.query_one("#scan_progress", ProgressBar).update(progress=100)
        report.finished_at = datetime.now()
        self._scan_report = report

        # Render results
        self._render_results(report)

        # Update UI state
        self._is_scanning = False
        self.query_one("#btn_scan", Button).disabled = False
        self.query_one("#btn_cancel", Button).disabled = True
        self.query_one("#btn_export", Button).disabled = False

        # Log summary
        successful = sum(1 for r in report.results if r.success)
        self._log_info(
            f"Scan complete: [bold green]{successful}[/]/{total} plugins succeeded"
        )

    def action_cancel_scan(self) -> None:
        """Cancel the ongoing scan."""
        if self._is_scanning:
            self._is_scanning = False
            self.query_one("#btn_scan", Button).disabled = False
            self.query_one("#btn_cancel", Button).disabled = True
            self._log_error("Scan cancelled by user.")

    def action_export_results(self) -> None:
        """Export scan results to JSON file."""
        if not self._scan_report:
            self._log_error("No results to export.")
            return

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"mapsec_{self._scan_report.target}_{timestamp}.json"
        filepath = Path(filename)

        data = self._scan_report.to_dict()
        filepath.write_text(json.dumps(data, indent=2, ensure_ascii=False))

        self._log_success(f"Report exported to [bold]{filename}[/]")

    def _get_selected_plugins(self) -> list[str]:
        """Get list of selected plugin names from checkboxes."""
        plugins = []
        for name in ["nmap", "dns", "vt"]:
            if self.query_one(f"#chk_{name}", Checkbox).value:
                plugins.append(name)
        return plugins

    def _render_results(self, report: ScanReport) -> None:
        """Render scan results in the results panel."""
        results_container = self.query_one("#results_scroll", VerticalScroll)
        results_container.remove_children()

        for result in report.results:
            panel = ResultPanel(result)
            results_container.mount(panel)

    def _log_info(self, message: str) -> None:
        """Write an info message to the log."""
        log = self.query_one("#results_scroll", VerticalScroll)
        # We use a simple Static for log messages
        widget = Static(f"[dim]ℹ[/] {message}")
        log.mount(widget)

    def _log_success(self, message: str) -> None:
        """Write a success message to the log."""
        log = self.query_one("#results_scroll", VerticalScroll)
        widget = Static(f"[bold green]✓[/] {message}")
        log.mount(widget)

    def _log_error(self, message: str) -> None:
        """Write an error message to the log."""
        log = self.query_one("#results_scroll", VerticalScroll)
        widget = Static(f"[bold red]✗[/] {message}")
        log.mount(widget)


def main() -> None:
    """Entry point — launch the Mapsec TUI."""
    app = MapsecApp()
    app.run()


if __name__ == "__main__":
    main()
