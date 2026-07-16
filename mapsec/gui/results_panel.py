"""Results panel with tabbed interface — one tab per plugin."""

from __future__ import annotations

import customtkinter as ctk
from typing import Any

# ─── Color Palette ──────────────────────────────────────────────
BG_BASE       = "#0f1117"
BG_SURFACE    = "#1a1d27"
BG_ELEVATED   = "#252836"
BORDER        = "#2d3142"
PRIMARY       = "#6366f1"
PRIMARY_HOVER = "#818cf8"
SUCCESS       = "#22c55e"
WARNING       = "#f59e0b"
ERROR         = "#ef4444"
TEXT          = "#e2e8f0"
TEXT_SEC      = "#cbd5e1"
TEXT_MUTED    = "#94a3b8"
TEXT_DIM      = "#64748b"
NEUTRAL       = "#6b7280"

# ─── Fonts ──────────────────────────────────────────────────────
FONT_HEADING = ("Segoe UI", 18, "bold")
FONT_SECTION = ("Segoe UI", 13, "bold")
FONT_BODY    = ("Segoe UI", 12)
FONT_SMALL   = ("Segoe UI", 11)
FONT_TINY    = ("Segoe UI", 10)
FONT_CODE    = ("Consolas", 11)
FONT_CODE_B  = ("Consolas", 11, "bold")


class ResultCard(ctk.CTkFrame):
    """A styled card for displaying a single result item."""

    def __init__(
        self, master: Any, title: str, value: str, color: str = PRIMARY, **kwargs: Any
    ) -> None:
        super().__init__(
            master,
            fg_color=BG_SURFACE,
            border_width=1,
            border_color=BORDER,
            corner_radius=10,
            **kwargs,
        )

        # Left accent bar
        accent = ctk.CTkFrame(self, fg_color=color, width=3, corner_radius=2)
        accent.pack(side="left", fill="y", padx=(0, 12), pady=10)

        # Content
        content = ctk.CTkFrame(self, fg_color="transparent")
        content.pack(side="left", fill="both", expand=True, padx=(0, 14), pady=10)

        ctk.CTkLabel(
            content, text=title, font=FONT_TINY, text_color=TEXT_MUTED,
        ).pack(anchor="w")

        ctk.CTkLabel(
            content, text=value, font=("Segoe UI", 15, "bold"), text_color=TEXT,
        ).pack(anchor="w")


class PortRow(ctk.CTkFrame):
    """A row displaying a single open port."""

    def __init__(self, master: Any, port: int, service: str, **kwargs: Any) -> None:
        super().__init__(
            master,
            fg_color=BG_SURFACE,
            border_width=1,
            border_color=BORDER,
            corner_radius=8,
            height=40,
            **kwargs,
        )
        self.pack_propagate(False)

        # Port number
        ctk.CTkLabel(
            self,
            text=str(port),
            font=FONT_CODE_B,
            text_color=PRIMARY_HOVER,
            width=70,
        ).pack(side="left", padx=(14, 0))

        # Protocol badge
        badge = ctk.CTkLabel(
            self,
            text="TCP",
            font=("Segoe UI", 9, "bold"),
            fg_color=BG_ELEVATED,
            text_color=TEXT_MUTED,
            corner_radius=4,
            width=42,
        )
        badge.pack(side="left", padx=(10, 0))

        # Service name
        ctk.CTkLabel(
            self, text=service, font=FONT_BODY, text_color=TEXT_SEC,
        ).pack(side="left", padx=(14, 0))


class DnsRecordRow(ctk.CTkFrame):
    """A row displaying a DNS record."""

    def __init__(
        self, master: Any, record_type: str, value: str, **kwargs: Any
    ) -> None:
        super().__init__(
            master,
            fg_color=BG_SURFACE,
            border_width=1,
            border_color=BORDER,
            corner_radius=8,
            height=40,
            **kwargs,
        )
        self.pack_propagate(False)

        # Type badge — tinted background + matching text
        badge_text_colors = {
            "A": SUCCESS,
            "AAAA": SUCCESS,
            "MX": WARNING,
            "NS": "#8b5cf6",
            "TXT": "#06b6d4",
            "CNAME": "#ec4899",
            "SUB": TEXT_DIM,
        }
        badge_bg_colors = {
            "A": "#0f3a24",
            "AAAA": "#0f3a24",
            "MX": "#3d2a06",
            "NS": "#2e1a5e",
            "TXT": "#063a4a",
            "CNAME": "#4a1338",
            "SUB": "#1e2536",
        }

        text_color = badge_text_colors.get(record_type, TEXT_DIM)
        bg_color = badge_bg_colors.get(record_type, BG_ELEVATED)

        badge = ctk.CTkLabel(
            self,
            text=record_type,
            font=("Segoe UI", 9, "bold"),
            fg_color=bg_color,
            text_color=text_color,
            corner_radius=4,
            width=52,
        )
        badge.pack(side="left", padx=(14, 0))

        # Value
        ctk.CTkLabel(
            self, text=value, font=FONT_CODE, text_color=TEXT_SEC,
        ).pack(side="left", padx=(12, 0), fill="x", expand=True)


class ThreatMeter(ctk.CTkFrame):
    """Visual threat level indicator."""

    def __init__(
        self,
        master: Any,
        malicious: int,
        suspicious: int,
        harmless: int,
        **kwargs: Any,
    ) -> None:
        super().__init__(master, fg_color="transparent", **kwargs)

        total = malicious + suspicious + harmless
        if total == 0:
            total = 1

        # Threat level
        if malicious > 0:
            level_text = "DANGEROUS"
            level_color = ERROR
            desc = (
                f"{malicious} engine{'s' if malicious != 1 else ''} "
                f"flagged as malicious"
            )
        elif suspicious > 0:
            level_text = "SUSPICIOUS"
            level_color = WARNING
            desc = (
                f"{suspicious} engine{'s' if suspicious != 1 else ''} "
                f"flagged as suspicious"
            )
        else:
            level_text = "CLEAN"
            level_color = SUCCESS
            desc = "No threats detected"

        # Level badge
        badge_frame = ctk.CTkFrame(self, fg_color="transparent")
        badge_frame.pack(fill="x", pady=(0, 10))

        ctk.CTkLabel(
            badge_frame,
            text=level_text,
            font=("Segoe UI", 20, "bold"),
            text_color=level_color,
        ).pack(side="left")

        ctk.CTkLabel(
            badge_frame, text=desc, font=FONT_SMALL, text_color=TEXT_MUTED,
        ).pack(side="left", padx=(14, 0))

        # Bar segments
        bar_frame = ctk.CTkFrame(self, fg_color="transparent", height=28)
        bar_frame.pack(fill="x")
        bar_frame.pack_propagate(False)

        if malicious > 0:
            ctk.CTkLabel(
                bar_frame,
                text=f"{malicious} malicious",
                font=("Segoe UI", 10, "bold"),
                fg_color=ERROR,
                text_color="#ffffff",
                corner_radius=6,
            ).pack(side="left", fill="x", expand=True, padx=(0, 3))

        if suspicious > 0:
            ctk.CTkLabel(
                bar_frame,
                text=f"{suspicious} suspicious",
                font=("Segoe UI", 10, "bold"),
                fg_color=WARNING,
                text_color="#ffffff",
                corner_radius=6,
            ).pack(side="left", fill="x", expand=True, padx=(0, 3))

        ctk.CTkLabel(
            bar_frame,
            text=f"{harmless} clean",
            font=("Segoe UI", 10, "bold"),
            fg_color=SUCCESS,
            text_color="#ffffff",
            corner_radius=6,
        ).pack(side="left", fill="x", expand=True)


class NmapTab(ctk.CTkScrollableFrame):
    """Tab displaying nmap scan results."""

    def __init__(self, master: Any, data: dict[str, Any], **kwargs: Any) -> None:
        super().__init__(
            master,
            fg_color="transparent",
            scrollbar_fg_color=BG_ELEVATED,
            scrollbar_button_color=BORDER,
            scrollbar_button_hover_color=PRIMARY,
            **kwargs,
        )

        hosts = data.get("hosts", [])
        if not hosts:
            ctk.CTkLabel(
                self, text="No hosts found", font=FONT_BODY, text_color=TEXT_MUTED,
            ).pack(pady=24)
            return

        for host in hosts:
            ip = host.get("ip", "unknown")
            hostname = host.get("hostname", "")
            ports = host.get("ports", [])

            # Summary cards
            cards_frame = ctk.CTkFrame(self, fg_color="transparent")
            cards_frame.pack(fill="x", pady=(0, 14))

            cards_frame.columnconfigure(0, weight=1)
            cards_frame.columnconfigure(1, weight=1)
            cards_frame.columnconfigure(2, weight=1)

            ResultCard(cards_frame, "TARGET", ip, PRIMARY).grid(
                row=0, column=0, sticky="ew", padx=(0, 6)
            )
            if hostname:
                ResultCard(cards_frame, "HOSTNAME", hostname, "#8b5cf6").grid(
                    row=0, column=1, sticky="ew", padx=(0, 6)
                )
            ResultCard(
                cards_frame, "OPEN PORTS", str(len(ports)), SUCCESS
            ).grid(row=0, column=2, sticky="ew")

            # Port list header
            header = ctk.CTkFrame(self, fg_color="transparent")
            header.pack(fill="x", pady=(10, 6))
            ctk.CTkLabel(
                header, text="Open Ports", font=FONT_SECTION, text_color=TEXT,
            ).pack(anchor="w")

            # Port rows
            for port_info in sorted(ports, key=lambda p: p.get("port", 0)):
                svc = port_info.get("service", {})
                PortRow(self, port_info["port"], svc.get("name", "unknown")).pack(
                    fill="x", pady=3
                )


class DnsTab(ctk.CTkScrollableFrame):
    """Tab displaying DNS enumeration results."""

    def __init__(self, master: Any, data: dict[str, Any], **kwargs: Any) -> None:
        super().__init__(
            master,
            fg_color="transparent",
            scrollbar_fg_color=BG_ELEVATED,
            scrollbar_button_color=BORDER,
            scrollbar_button_hover_color=PRIMARY,
            **kwargs,
        )

        domain = data.get("domain", "")
        records = data.get("records", {})
        subdomains = data.get("subdomains", [])

        # Domain header
        ctk.CTkLabel(
            self, text=domain, font=FONT_HEADING, text_color=PRIMARY_HOVER,
        ).pack(anchor="w", pady=(0, 14))

        # Summary cards
        total_records = sum(
            len(v) if isinstance(v, list) else 0 for v in records.values()
        )
        cards_frame = ctk.CTkFrame(self, fg_color="transparent")
        cards_frame.pack(fill="x", pady=(0, 18))

        cards_frame.columnconfigure(0, weight=1)
        cards_frame.columnconfigure(1, weight=1)
        cards_frame.columnconfigure(2, weight=1)

        ResultCard(
            cards_frame, "DNS RECORDS", str(total_records), PRIMARY
        ).grid(row=0, column=0, sticky="ew", padx=(0, 6))
        ResultCard(
            cards_frame, "SUBDOMAINS", str(len(subdomains)), "#8b5cf6"
        ).grid(row=0, column=1, sticky="ew", padx=(0, 6))
        a_count = len(records.get("A", []))
        ResultCard(
            cards_frame, "IP ADDRESSES", str(a_count), SUCCESS
        ).grid(row=0, column=2, sticky="ew")

        # Records by type
        for rtype in ["A", "AAAA", "MX", "NS", "TXT"]:
            values = records.get(rtype, [])
            if not values:
                continue

            ctk.CTkLabel(
                self, text=f"{rtype} Records", font=FONT_SECTION, text_color=TEXT,
            ).pack(anchor="w", pady=(12, 6))

            for item in values[:20]:
                if isinstance(item, dict):
                    value = item.get("data", str(item))
                else:
                    value = str(item)
                DnsRecordRow(self, rtype, value).pack(fill="x", pady=3)

        # Subdomains
        if subdomains:
            ctk.CTkLabel(
                self,
                text="Discovered Subdomains",
                font=FONT_SECTION,
                text_color=TEXT,
            ).pack(anchor="w", pady=(18, 8))

            for sub in subdomains[:30]:
                name = sub.get("subdomain", "")
                ips = ", ".join(sub.get("ips", []))
                DnsRecordRow(self, "SUB", f"{name}  \u2192  {ips}").pack(
                    fill="x", pady=3
                )


class VtTab(ctk.CTkScrollableFrame):
    """Tab displaying VirusTotal threat intelligence results."""

    def __init__(self, master: Any, data: dict[str, Any], **kwargs: Any) -> None:
        super().__init__(
            master,
            fg_color="transparent",
            scrollbar_fg_color=BG_ELEVATED,
            scrollbar_button_color=BORDER,
            scrollbar_button_hover_color=PRIMARY,
            **kwargs,
        )

        # Error state
        if "error" in data:
            ctk.CTkLabel(
                self,
                text="Error",
                font=("Segoe UI", 16, "bold"),
                text_color=ERROR,
            ).pack(anchor="w", pady=(0, 8))
            ctk.CTkLabel(
                self,
                text=data["error"],
                font=FONT_BODY,
                text_color=TEXT_MUTED,
                wraplength=500,
            ).pack(anchor="w")
            return

        target = data.get("target", "")
        type_name = data.get("type", "").upper()
        malicious = data.get("malicious", 0)
        suspicious = data.get("suspicious", 0)
        harmless = data.get("harmless", 0)

        # Target header
        ctk.CTkLabel(
            self,
            text=f"{type_name}: {target}",
            font=("Segoe UI", 16, "bold"),
            text_color=PRIMARY_HOVER,
        ).pack(anchor="w", pady=(0, 18))

        # Threat meter
        ThreatMeter(self, malicious, suspicious, harmless).pack(
            fill="x", pady=(0, 18)
        )

        # Summary cards
        cards_frame = ctk.CTkFrame(self, fg_color="transparent")
        cards_frame.pack(fill="x", pady=(0, 18))

        cards_frame.columnconfigure(0, weight=1)
        cards_frame.columnconfigure(1, weight=1)
        cards_frame.columnconfigure(2, weight=1)

        ResultCard(
            cards_frame, "MALICIOUS", str(malicious), ERROR
        ).grid(row=0, column=0, sticky="ew", padx=(0, 6))
        ResultCard(
            cards_frame, "SUSPICIOUS", str(suspicious), WARNING
        ).grid(row=0, column=1, sticky="ew", padx=(0, 6))
        ResultCard(
            cards_frame, "CLEAN", str(harmless), SUCCESS
        ).grid(row=0, column=2, sticky="ew")

        # Additional info
        registrar = data.get("registrar", "")
        creation_date = data.get("creation_date", "")
        categories = data.get("categories", {})

        if registrar or creation_date:
            info_frame = ctk.CTkFrame(
                self,
                fg_color=BG_SURFACE,
                border_width=1,
                border_color=BORDER,
                corner_radius=10,
            )
            info_frame.pack(fill="x", pady=(0, 10))

            if registrar:
                row = ctk.CTkFrame(info_frame, fg_color="transparent")
                row.pack(fill="x", padx=14, pady=(10, 0))
                ctk.CTkLabel(
                    row, text="Registrar", font=FONT_SMALL, text_color=TEXT_MUTED,
                ).pack(side="left")
                ctk.CTkLabel(
                    row,
                    text=registrar,
                    font=("Segoe UI", 11, "bold"),
                    text_color=TEXT,
                ).pack(side="left", padx=(10, 0))

            if creation_date:
                row = ctk.CTkFrame(info_frame, fg_color="transparent")
                row.pack(fill="x", padx=14, pady=(4, 10))
                ctk.CTkLabel(
                    row, text="Created", font=FONT_SMALL, text_color=TEXT_MUTED,
                ).pack(side="left")
                ctk.CTkLabel(
                    row,
                    text=str(creation_date),
                    font=("Segoe UI", 11, "bold"),
                    text_color=TEXT,
                ).pack(side="left", padx=(10, 0))

        # Categories
        if categories:
            cat_frame = ctk.CTkFrame(
                self,
                fg_color=BG_SURFACE,
                border_width=1,
                border_color=BORDER,
                corner_radius=10,
            )
            cat_frame.pack(fill="x", pady=(0, 10))

            ctk.CTkLabel(
                cat_frame,
                text="Categories",
                font=FONT_SMALL,
                text_color=TEXT_MUTED,
            ).pack(anchor="w", padx=14, pady=(10, 6))

            for source, category in list(categories.items())[:10]:
                row = ctk.CTkFrame(cat_frame, fg_color="transparent")
                row.pack(fill="x", padx=14, pady=2)
                ctk.CTkLabel(
                    row, text=f"{source}:", font=FONT_TINY, text_color=TEXT_DIM,
                ).pack(side="left")
                ctk.CTkLabel(
                    row, text=str(category), font=FONT_SMALL, text_color=TEXT_SEC,
                ).pack(side="left", padx=(8, 0))

            # Bottom padding
            ctk.CTkFrame(cat_frame, fg_color="transparent", height=10).pack()


class ResultsPanel(ctk.CTkFrame):
    """Tabbed results panel — one tab per plugin with formatted results."""

    def __init__(self, master: Any, **kwargs: Any) -> None:
        super().__init__(
            master,
            fg_color=BG_SURFACE,
            border_width=1,
            border_color=BORDER,
            corner_radius=10,
            **kwargs,
        )

        self._tabview: ctk.CTkTabview | None = None

    def clear(self) -> None:
        """Remove all tabs."""
        if self._tabview:
            self._tabview.destroy()
            self._tabview = None

    def render(self, results: list[dict[str, Any]]) -> None:
        """Render results in a tabbed interface."""
        self.clear()

        if not results:
            ctk.CTkLabel(
                self, text="No results", font=FONT_BODY, text_color=TEXT_DIM,
            ).pack(expand=True)
            return

        # Create tabview
        self._tabview = ctk.CTkTabview(
            self,
            fg_color=BG_SURFACE,
            border_width=0,
            corner_radius=8,
            segmented_button_fg_color=BG_ELEVATED,
            segmented_button_selected_color=PRIMARY,
            segmented_button_unselected_color=BG_SURFACE,
            segmented_button_selected_hover_color=PRIMARY_HOVER,
            text_color=TEXT,
        )
        self._tabview.pack(fill="both", expand=True, padx=6, pady=6)

        # Tab info
        tab_info = {
            "nmap": ("Port Scan", PRIMARY),
            "dns": ("DNS Enum", "#8b5cf6"),
            "vt": ("Threat Intel", SUCCESS),
        }

        for result in results:
            plugin = result.get("plugin", "unknown")
            display_name, color = tab_info.get(
                plugin, (plugin.capitalize(), TEXT_DIM)
            )
            success = result.get("success", False)

            tab = self._tabview.add(display_name)

            if not success:
                error_frame = ctk.CTkFrame(tab, fg_color="transparent")
                error_frame.pack(expand=True, fill="both")

                ctk.CTkLabel(
                    error_frame,
                    text="Scan Failed",
                    font=("Segoe UI", 16, "bold"),
                    text_color=ERROR,
                ).pack(expand=True)
                ctk.CTkLabel(
                    error_frame,
                    text=result.get("error", "Unknown error"),
                    font=FONT_BODY,
                    text_color=TEXT_MUTED,
                    wraplength=500,
                ).pack(expand=True)
                continue

            data = result.get("data", {})

            if plugin == "nmap":
                NmapTab(tab, data).pack(fill="both", expand=True)
            elif plugin == "dns":
                DnsTab(tab, data).pack(fill="both", expand=True)
            elif plugin == "vt":
                VtTab(tab, data).pack(fill="both", expand=True)
            else:
                ctk.CTkLabel(
                    tab,
                    text=f"Unknown plugin: {plugin}",
                    font=FONT_BODY,
                    text_color=TEXT_MUTED,
                ).pack(expand=True)
