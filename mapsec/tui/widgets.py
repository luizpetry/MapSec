"""Custom TUI widgets for Mapsec."""

from __future__ import annotations

from rich.table import Table
from rich.text import Text
from textual.widgets import Static

from mapsec.core.models import PluginResult


class PluginStatus(Static):
    """Widget that displays the status of a single plugin during scan."""

    STATUS_ICONS = {
        "pending": Text("[ ]", style="dim"),
        "running": Text("[>]", style="bold yellow"),
        "success": Text("[+]", style="bold green"),
        "failed": Text("[x]", style="bold red"),
    }

    def __init__(self, plugin_name: str, **kwargs) -> None:
        super().__init__(**kwargs)
        self.plugin_name = plugin_name
        self._status = "pending"
        self._duration: float | None = None
        self._error: str | None = None
        self._update_display()

    def set_running(self) -> None:
        self._status = "running"
        self._duration = None
        self._error = None
        self._update_display()

    def set_success(self, duration: float) -> None:
        self._status = "success"
        self._duration = duration
        self._error = None
        self._update_display()

    def set_failed(self, error: str) -> None:
        self._status = "failed"
        self._duration = None
        self._error = error
        self._update_display()

    def _update_display(self) -> None:
        icon = self.STATUS_ICONS[self._status]
        label = Text(f" {self.plugin_name}", style="bold")

        if self._status == "pending":
            self.update(icon + label)
        elif self._status == "running":
            self.update(icon + label + Text(" - running...", style="yellow"))
        elif self._status == "success":
            time_str = f" - {self._duration:.1f}s" if self._duration is not None else ""
            self.update(icon + label + Text(time_str, style="green"))
        elif self._status == "failed":
            err = f" - {self._error}" if self._error else ""
            self.update(icon + label + Text(err, style="red"))


class ResultPanel(Static):
    """Widget that renders a PluginResult as a formatted Rich panel."""

    def __init__(self, result: PluginResult, **kwargs) -> None:
        super().__init__(**kwargs)
        self.result = result
        self._update_display()

    def _update_display(self) -> None:
        r = self.result

        if r.success:
            table = Table(
                title=f"{r.plugin.upper()} - {r.target}",
                show_header=True,
                header_style="bold cyan",
                border_style="green",
                title_style="bold",
            )

            data = r.data
            if isinstance(data, dict):
                if "hosts" in data:
                    table.add_column("Port", style="cyan", width=8)
                    table.add_column("State", style="green", width=8)
                    table.add_column("Service", style="white")
                    for host in data.get("hosts", []):
                        for port in host.get("ports", []):
                            svc = port.get("service", {})
                            svc_str = f"{svc.get('name', '')} {svc.get('product', '')} {svc.get('version', '')}".strip()
                            table.add_row(
                                str(port.get("port", "")),
                                port.get("state", ""),
                                svc_str,
                            )
                elif "records" in data:
                    table.add_column("Type", style="cyan", width=8)
                    table.add_column("Value", style="white")
                    for rtype, records in data.get("records", {}).items():
                        if isinstance(records, list):
                            for rec in records:
                                if isinstance(rec, dict):
                                    val = rec.get("exchange", "") or str(rec.get("ips", rec.get("priority", "")))
                                else:
                                    val = str(rec)
                                table.add_row(rtype, val)
                    subs = data.get("total_subdomains", 0)
                    if subs:
                        table.add_row("SUB", f"{subs} subdomains found", style="dim")
                elif "malicious" in data:
                    table.add_column("Metric", style="cyan", width=16)
                    table.add_column("Value", style="white")
                    table.add_row("Malicious", str(data.get("malicious", 0)), style="red" if data.get("malicious", 0) > 0 else "")
                    table.add_row("Suspicious", str(data.get("suspicious", 0)), style="yellow" if data.get("suspicious", 0) > 0 else "")
                    table.add_row("Harmless", str(data.get("harmless", 0)), style="green")
                    if data.get("asn"):
                        table.add_row("ASN", data["asn"])
                    if data.get("country"):
                        table.add_row("Country", data["country"])
                else:
                    table.add_column("Key", style="cyan")
                    table.add_column("Value", style="white")
                    for k, v in data.items():
                        table.add_row(str(k), str(v))

            self.update(table)
        else:
            error_text = Text(f"Error: {r.error}", style="bold red")
            self.update(error_text)
