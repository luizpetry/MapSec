"""Results panel with expandable summary cards — one card per plugin."""

from __future__ import annotations

import customtkinter as ctk
from typing import Any, Callable

# ─── Color Palette ──────────────────────────────────────────────
BG_BASE       = "#0c0e14"
BG_SURFACE    = "#161922"
BG_ELEVATED   = "#1e2230"
BG_INPUT      = "#111420"
BORDER        = "#2a2e3e"
BORDER_FOCUS  = "#7c7fff"
PRIMARY       = "#6c63ff"
PRIMARY_HOVER = "#8b84ff"
PRIMARY_DIM   = "#4f48b2"
SUCCESS       = "#34d399"
SUCCESS_DIM   = "#10b981"
WARNING       = "#fbbf24"
WARNING_DIM   = "#f59e0b"
ERROR         = "#f87171"
ERROR_DIM     = "#ef4444"
TEXT          = "#eef0f6"
TEXT_SEC      = "#c4c9d8"
TEXT_MUTED    = "#8890a4"
TEXT_DIM      = "#555c72"
NEUTRAL       = "#6b7280"
ACCENT_CYAN   = "#22d3ee"
ACCENT_PURPLE = "#a78bfa"
ACCENT_PINK   = "#f472b6"

# ─── Fonts ──────────────────────────────────────────────────────
FONT_HEADING   = ("Segoe UI", 18, "bold")
FONT_SECTION   = ("Segoe UI", 13, "bold")
FONT_BODY      = ("Segoe UI", 12)
FONT_SMALL     = ("Segoe UI", 11)
FONT_TINY      = ("Segoe UI", 10)
FONT_CODE      = ("Consolas", 11)
FONT_CODE_B    = ("Consolas", 11, "bold")
FONT_CODE_SM   = ("Consolas", 10)
FONT_BADGE     = ("Segoe UI", 9, "bold")
FONT_BADGE_SM  = ("Segoe UI", 8, "bold")


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
            corner_radius=12,
            height=52,
            **kwargs,
        )
        self.pack_propagate(False)

        # Left accent bar
        accent = ctk.CTkFrame(self, fg_color=color, width=3, corner_radius=2)
        accent.pack(side="left", fill="y", padx=(0, 8), pady=4)

        # Content
        content = ctk.CTkFrame(self, fg_color="transparent")
        content.pack(side="left", fill="x", padx=(0, 10), pady=4)

        ctk.CTkLabel(
            content, text=title, font=FONT_BADGE_SM, text_color=TEXT_MUTED,
        ).pack(anchor="w")

        ctk.CTkLabel(
            content, text=value, font=("Segoe UI", 12, "bold"), text_color=TEXT,
        ).pack(anchor="w")


class PortRow(ctk.CTkFrame):
    """A row displaying a single open port."""

    def __init__(self, master: Any, port: int, service: str, **kwargs: Any) -> None:
        super().__init__(
            master,
            fg_color=BG_SURFACE,
            border_width=1,
            border_color=BORDER,
            corner_radius=10,
            height=44,
            **kwargs,
        )
        self.pack_propagate(False)

        # Port number as styled badge
        port_badge = ctk.CTkLabel(
            self,
            text=str(port),
            font=FONT_CODE_B,
            text_color="#ffffff",
            fg_color=PRIMARY_DIM,
            corner_radius=6,
            width=64,
            height=24,
        )
        port_badge.pack(side="left", padx=(16, 0), pady=0)

        # Protocol badge
        badge = ctk.CTkLabel(
            self,
            text="TCP",
            font=FONT_BADGE_SM,
            fg_color=BG_ELEVATED,
            text_color=TEXT_MUTED,
            corner_radius=6,
            width=40,
            height=20,
        )
        badge.pack(side="left", padx=(12, 0))

        # Service name — more prominent
        ctk.CTkLabel(
            self, text=service, font=("Segoe UI", 12, "bold"), text_color=TEXT_SEC,
        ).pack(side="left", padx=(16, 0))


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
            corner_radius=10,
            height=42,
            **kwargs,
        )
        self.pack_propagate(False)

        # Type badge — tinted background + matching text
        badge_text_colors = {
            "A": SUCCESS,
            "AAAA": SUCCESS,
            "MX": WARNING,
            "NS": ACCENT_PURPLE,
            "TXT": ACCENT_CYAN,
            "CNAME": ACCENT_PINK,
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
            font=FONT_BADGE,
            fg_color=bg_color,
            text_color=text_color,
            corner_radius=6,
            width=58,
            height=24,
        )
        badge.pack(side="left", padx=(16, 0))

        # Value
        ctk.CTkLabel(
            self, text=value, font=FONT_CODE, text_color=TEXT_SEC,
        ).pack(side="left", padx=(14, 0), fill="x", expand=True)


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
        badge_frame.pack(fill="x", pady=(0, 14))

        # Level indicator dot
        level_dot = ctk.CTkFrame(badge_frame, fg_color=level_color, width=10, height=10, corner_radius=5)
        level_dot.pack(side="left", padx=(0, 10))

        ctk.CTkLabel(
            badge_frame,
            text=level_text,
            font=("Segoe UI", 20, "bold"),
            text_color=level_color,
        ).pack(side="left")

        ctk.CTkLabel(
            badge_frame, text=desc, font=FONT_SMALL, text_color=TEXT_MUTED,
        ).pack(side="left", padx=(16, 0))

        # Bar segments — taller with gap for visual distinctness
        bar_frame = ctk.CTkFrame(self, fg_color="transparent", height=34)
        bar_frame.pack(fill="x")
        bar_frame.pack_propagate(False)

        if malicious > 0:
            seg = ctk.CTkFrame(bar_frame, fg_color=ERROR, corner_radius=8)
            seg.pack(side="left", fill="both", expand=True, padx=(0, 4))
            ctk.CTkLabel(
                seg,
                text=f"{malicious} malicious",
                font=FONT_BADGE,
                text_color="#ffffff",
                fg_color="transparent",
            ).pack(expand=True)

        if suspicious > 0:
            seg = ctk.CTkFrame(bar_frame, fg_color=WARNING, corner_radius=8)
            seg.pack(side="left", fill="both", expand=True, padx=(0, 4))
            ctk.CTkLabel(
                seg,
                text=f"{suspicious} suspicious",
                font=FONT_BADGE,
                text_color="#ffffff",
                fg_color="transparent",
            ).pack(expand=True)

        seg_clean = ctk.CTkFrame(bar_frame, fg_color=SUCCESS, corner_radius=8)
        seg_clean.pack(side="left", fill="both", expand=True)
        ctk.CTkLabel(
            seg_clean,
            text=f"{harmless} clean",
            font=FONT_BADGE,
            text_color="#ffffff",
            fg_color="transparent",
        ).pack(expand=True)


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
            empty_frame = ctk.CTkFrame(self, fg_color="transparent")
            empty_frame.pack(expand=True, fill="both", pady=40)
            ctk.CTkLabel(
                empty_frame, text="No hosts found", font=FONT_BODY, text_color=TEXT_DIM,
            ).pack()
            return

        for host in hosts:
            ip = host.get("ip", "unknown")
            hostname = host.get("hostname", "")
            ports = host.get("ports", [])

            # Summary cards
            cards_frame = ctk.CTkFrame(self, fg_color="transparent")
            cards_frame.pack(fill="x", pady=(0, 16))

            cards_frame.columnconfigure(0, weight=1)
            cards_frame.columnconfigure(1, weight=1)
            cards_frame.columnconfigure(2, weight=1)

            ResultCard(cards_frame, "TARGET", ip, PRIMARY).grid(
                row=0, column=0, sticky="ew", padx=(0, 8)
            )
            if hostname:
                ResultCard(cards_frame, "HOSTNAME", hostname, ACCENT_PURPLE).grid(
                    row=0, column=1, sticky="ew", padx=(0, 8)
                )
            ResultCard(
                cards_frame, "OPEN PORTS", str(len(ports)), SUCCESS
            ).grid(row=0, column=2, sticky="ew")

            # Port list header with accent
            header = ctk.CTkFrame(self, fg_color="transparent")
            header.pack(fill="x", pady=(12, 8))

            header_dot = ctk.CTkFrame(header, fg_color=PRIMARY, width=4, height=14, corner_radius=2)
            header_dot.pack(side="left", padx=(0, 8))
            header_dot.pack_propagate(False)

            ctk.CTkLabel(
                header, text="Open Ports", font=FONT_SECTION, text_color=TEXT,
            ).pack(side="left")

            # Port rows
            for port_info in sorted(ports, key=lambda p: p.get("port", 0)):
                svc = port_info.get("service", {})
                PortRow(self, port_info["port"], svc.get("name", "unknown")).pack(
                    fill="x", pady=4
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
        ).pack(anchor="w", pady=(0, 16))

        # Summary cards
        total_records = sum(
            len(v) if isinstance(v, list) else 0 for v in records.values()
        )
        cards_frame = ctk.CTkFrame(self, fg_color="transparent")
        cards_frame.pack(fill="x", pady=(0, 20))

        cards_frame.columnconfigure(0, weight=1)
        cards_frame.columnconfigure(1, weight=1)
        cards_frame.columnconfigure(2, weight=1)

        ResultCard(
            cards_frame, "DNS RECORDS", str(total_records), PRIMARY
        ).grid(row=0, column=0, sticky="ew", padx=(0, 8))
        ResultCard(
            cards_frame, "SUBDOMAINS", str(len(subdomains)), ACCENT_PURPLE
        ).grid(row=0, column=1, sticky="ew", padx=(0, 8))
        a_count = len(records.get("A", []))
        ResultCard(
            cards_frame, "IP ADDRESSES", str(a_count), SUCCESS
        ).grid(row=0, column=2, sticky="ew")

        # Records by type
        for rtype in ["A", "AAAA", "MX", "NS", "TXT"]:
            values = records.get(rtype, [])
            if not values:
                continue

            # Section header with accent
            section_header = ctk.CTkFrame(self, fg_color="transparent")
            section_header.pack(fill="x", pady=(14, 8))

            rtype_colors = {
                "A": SUCCESS,
                "AAAA": SUCCESS,
                "MX": WARNING,
                "NS": ACCENT_PURPLE,
                "TXT": ACCENT_CYAN,
            }
            rtype_color = rtype_colors.get(rtype, TEXT_DIM)

            header_dot = ctk.CTkFrame(section_header, fg_color=rtype_color, width=4, height=14, corner_radius=2)
            header_dot.pack(side="left", padx=(0, 8))
            header_dot.pack_propagate(False)

            ctk.CTkLabel(
                section_header, text=f"{rtype} Records", font=FONT_SECTION, text_color=TEXT,
            ).pack(side="left")

            for item in values[:20]:
                if isinstance(item, dict):
                    value = item.get("data", str(item))
                else:
                    value = str(item)
                DnsRecordRow(self, rtype, value).pack(fill="x", pady=4)

        # Subdomains
        if subdomains:
            sub_header = ctk.CTkFrame(self, fg_color="transparent")
            sub_header.pack(fill="x", pady=(20, 10))

            header_dot = ctk.CTkFrame(sub_header, fg_color=ACCENT_PINK, width=4, height=14, corner_radius=2)
            header_dot.pack(side="left", padx=(0, 8))
            header_dot.pack_propagate(False)

            ctk.CTkLabel(
                sub_header,
                text="Discovered Subdomains",
                font=FONT_SECTION,
                text_color=TEXT,
            ).pack(side="left")

            for sub in subdomains[:30]:
                name = sub.get("subdomain", "")
                ips = ", ".join(sub.get("ips", []))
                DnsRecordRow(self, "SUB", f"{name}  \u2192  {ips}").pack(
                    fill="x", pady=4
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
        ).pack(anchor="w", pady=(0, 20))

        # Threat meter
        ThreatMeter(self, malicious, suspicious, harmless).pack(
            fill="x", pady=(0, 20)
        )

        # Summary cards
        cards_frame = ctk.CTkFrame(self, fg_color="transparent")
        cards_frame.pack(fill="x", pady=(0, 20))

        cards_frame.columnconfigure(0, weight=1)
        cards_frame.columnconfigure(1, weight=1)
        cards_frame.columnconfigure(2, weight=1)

        ResultCard(
            cards_frame, "MALICIOUS", str(malicious), ERROR
        ).grid(row=0, column=0, sticky="ew", padx=(0, 8))
        ResultCard(
            cards_frame, "SUSPICIOUS", str(suspicious), WARNING
        ).grid(row=0, column=1, sticky="ew", padx=(0, 8))
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
                corner_radius=12,
            )
            info_frame.pack(fill="x", pady=(0, 12))

            # Info section header
            info_header = ctk.CTkFrame(info_frame, fg_color="transparent")
            info_header.pack(fill="x", padx=16, pady=(14, 0))

            info_dot = ctk.CTkFrame(info_header, fg_color=ACCENT_CYAN, width=4, height=14, corner_radius=2)
            info_dot.pack(side="left", padx=(0, 8))
            info_dot.pack_propagate(False)

            ctk.CTkLabel(
                info_header, text="Registration Info", font=FONT_SMALL, text_color=TEXT_MUTED,
            ).pack(side="left")

            if registrar:
                row = ctk.CTkFrame(info_frame, fg_color="transparent")
                row.pack(fill="x", padx=16, pady=(10, 0))
                ctk.CTkLabel(
                    row, text="Registrar", font=FONT_SMALL, text_color=TEXT_DIM,
                ).pack(side="left")
                ctk.CTkLabel(
                    row,
                    text=registrar,
                    font=("Segoe UI", 11, "bold"),
                    text_color=TEXT,
                ).pack(side="left", padx=(12, 0))

            if creation_date:
                row = ctk.CTkFrame(info_frame, fg_color="transparent")
                row.pack(fill="x", padx=16, pady=(6, 14))
                ctk.CTkLabel(
                    row, text="Created", font=FONT_SMALL, text_color=TEXT_DIM,
                ).pack(side="left")
                ctk.CTkLabel(
                    row,
                    text=str(creation_date),
                    font=("Segoe UI", 11, "bold"),
                    text_color=TEXT,
                ).pack(side="left", padx=(12, 0))

        # Categories
        if categories:
            cat_frame = ctk.CTkFrame(
                self,
                fg_color=BG_SURFACE,
                border_width=1,
                border_color=BORDER,
                corner_radius=12,
            )
            cat_frame.pack(fill="x", pady=(0, 12))

            # Categories header
            cat_header = ctk.CTkFrame(cat_frame, fg_color="transparent")
            cat_header.pack(fill="x", padx=16, pady=(14, 0))

            cat_dot = ctk.CTkFrame(cat_header, fg_color=ACCENT_PINK, width=4, height=14, corner_radius=2)
            cat_dot.pack(side="left", padx=(0, 8))
            cat_dot.pack_propagate(False)

            ctk.CTkLabel(
                cat_header,
                text="Categories",
                font=FONT_SMALL,
                text_color=TEXT_MUTED,
            ).pack(side="left")

            for source, category in list(categories.items())[:10]:
                row = ctk.CTkFrame(cat_frame, fg_color="transparent")
                row.pack(fill="x", padx=16, pady=3)
                ctk.CTkLabel(
                    row, text=f"{source}:", font=FONT_TINY, text_color=TEXT_DIM,
                ).pack(side="left")
                ctk.CTkLabel(
                    row, text=str(category), font=FONT_SMALL, text_color=TEXT_SEC,
                ).pack(side="left", padx=(10, 0))

            # Bottom padding
            ctk.CTkFrame(cat_frame, fg_color="transparent", height=12).pack()


class WhoisTab(ctk.CTkScrollableFrame):
    """Tab displaying WHOIS lookup results."""

    def __init__(self, master: Any, data: dict[str, Any], **kwargs: Any) -> None:
        super().__init__(
            master,
            fg_color="transparent",
            scrollbar_fg_color=BG_ELEVATED,
            scrollbar_button_color=BORDER,
            scrollbar_button_hover_color=PRIMARY,
            **kwargs,
        )

        target = data.get("target", "")
        target_type = data.get("type", "domain")
        registrar = data.get("registrar", "")
        creation_date = data.get("creation_date", "")
        expiration_date = data.get("expiration_date", "")
        name_servers = data.get("name_servers", [])
        registrant = data.get("registrant", {})

        # Target header
        ctk.CTkLabel(
            self,
            text=f"{target_type.upper()}: {target}",
            font=("Segoe UI", 16, "bold"),
            text_color=PRIMARY_HOVER,
        ).pack(anchor="w", pady=(0, 16))

        # Summary cards
        cards_frame = ctk.CTkFrame(self, fg_color="transparent")
        cards_frame.pack(fill="x", pady=(0, 16))
        cards_frame.columnconfigure(0, weight=1)
        cards_frame.columnconfigure(1, weight=1)
        cards_frame.columnconfigure(2, weight=1)

        ResultCard(cards_frame, "REGISTRAR", registrar or "--", PRIMARY).grid(
            row=0, column=0, sticky="ew", padx=(0, 8)
        )
        ResultCard(
            cards_frame, "NAME SERVERS", str(len(name_servers)), ACCENT_PURPLE
        ).grid(row=0, column=1, sticky="ew", padx=(0, 8))
        ResultCard(
            cards_frame, "TYPE", target_type.upper(), ACCENT_CYAN
        ).grid(row=0, column=2, sticky="ew")

        # Registration info
        info_frame = ctk.CTkFrame(
            self, fg_color=BG_SURFACE, border_width=1,
            border_color=BORDER, corner_radius=12,
        )
        info_frame.pack(fill="x", pady=(0, 12))

        info_header = ctk.CTkFrame(info_frame, fg_color="transparent")
        info_header.pack(fill="x", padx=16, pady=(14, 0))
        info_dot = ctk.CTkFrame(info_header, fg_color=ACCENT_CYAN, width=4, height=14, corner_radius=2)
        info_dot.pack(side="left", padx=(0, 8))
        info_dot.pack_propagate(False)
        ctk.CTkLabel(info_header, text="Registration Info", font=FONT_SMALL, text_color=TEXT_MUTED).pack(side="left")

        if registrar:
            row = ctk.CTkFrame(info_frame, fg_color="transparent")
            row.pack(fill="x", padx=16, pady=(10, 0))
            ctk.CTkLabel(row, text="Registrar", font=FONT_SMALL, text_color=TEXT_DIM).pack(side="left")
            ctk.CTkLabel(row, text=registrar, font=("Segoe UI", 11, "bold"), text_color=TEXT).pack(side="left", padx=(12, 0))

        if creation_date:
            row = ctk.CTkFrame(info_frame, fg_color="transparent")
            row.pack(fill="x", padx=16, pady=(6, 0))
            ctk.CTkLabel(row, text="Created", font=FONT_SMALL, text_color=TEXT_DIM).pack(side="left")
            ctk.CTkLabel(row, text=str(creation_date), font=("Segoe UI", 11, "bold"), text_color=TEXT).pack(side="left", padx=(12, 0))

        if expiration_date:
            row = ctk.CTkFrame(info_frame, fg_color="transparent")
            row.pack(fill="x", padx=16, pady=(6, 14))
            ctk.CTkLabel(row, text="Expires", font=FONT_SMALL, text_color=TEXT_DIM).pack(side="left")
            ctk.CTkLabel(row, text=str(expiration_date), font=("Segoe UI", 11, "bold"), text_color=TEXT).pack(side="left", padx=(12, 0))

        # Registrant info
        org = registrant.get("org", "")
        country = registrant.get("country", "")
        if org or country:
            reg_frame = ctk.CTkFrame(
                self, fg_color=BG_SURFACE, border_width=1,
                border_color=BORDER, corner_radius=12,
            )
            reg_frame.pack(fill="x", pady=(0, 12))

            reg_header = ctk.CTkFrame(reg_frame, fg_color="transparent")
            reg_header.pack(fill="x", padx=16, pady=(14, 0))
            reg_dot = ctk.CTkFrame(reg_header, fg_color=ACCENT_PURPLE, width=4, height=14, corner_radius=2)
            reg_dot.pack(side="left", padx=(0, 8))
            reg_dot.pack_propagate(False)
            ctk.CTkLabel(reg_header, text="Registrant", font=FONT_SMALL, text_color=TEXT_MUTED).pack(side="left")

            if org:
                row = ctk.CTkFrame(reg_frame, fg_color="transparent")
                row.pack(fill="x", padx=16, pady=(10, 0))
                ctk.CTkLabel(row, text="Organization", font=FONT_SMALL, text_color=TEXT_DIM).pack(side="left")
                ctk.CTkLabel(row, text=org, font=("Segoe UI", 11, "bold"), text_color=TEXT).pack(side="left", padx=(12, 0))

            if country:
                row = ctk.CTkFrame(reg_frame, fg_color="transparent")
                row.pack(fill="x", padx=16, pady=(6, 14))
                ctk.CTkLabel(row, text="Country", font=FONT_SMALL, text_color=TEXT_DIM).pack(side="left")
                ctk.CTkLabel(row, text=country, font=("Segoe UI", 11, "bold"), text_color=TEXT).pack(side="left", padx=(12, 0))

        # Name servers
        if name_servers:
            ns_header = ctk.CTkFrame(self, fg_color="transparent")
            ns_header.pack(fill="x", pady=(14, 8))
            ns_dot = ctk.CTkFrame(ns_header, fg_color=ACCENT_PURPLE, width=4, height=14, corner_radius=2)
            ns_dot.pack(side="left", padx=(0, 8))
            ns_dot.pack_propagate(False)
            ctk.CTkLabel(ns_header, text="Name Servers", font=FONT_SECTION, text_color=TEXT).pack(side="left")

            for ns in name_servers:
                DnsRecordRow(self, "NS", ns).pack(fill="x", pady=4)


class BannerTab(ctk.CTkScrollableFrame):
    """Tab displaying banner grabbing results."""

    def __init__(self, master: Any, data: dict[str, Any], **kwargs: Any) -> None:
        super().__init__(
            master,
            fg_color="transparent",
            scrollbar_fg_color=BG_ELEVATED,
            scrollbar_button_color=BORDER,
            scrollbar_button_hover_color=PRIMARY,
            **kwargs,
        )

        target = data.get("target", "")
        ip = data.get("ip", "")
        banners = data.get("banners", [])

        # Target header
        ctk.CTkLabel(
            self,
            text=f"{target}" + (f" ({ip})" if ip and ip != target else ""),
            font=("Segoe UI", 16, "bold"),
            text_color=PRIMARY_HOVER,
        ).pack(anchor="w", pady=(0, 16))

        # Summary
        cards_frame = ctk.CTkFrame(self, fg_color="transparent")
        cards_frame.pack(fill="x", pady=(0, 16))
        cards_frame.columnconfigure(0, weight=1)
        cards_frame.columnconfigure(1, weight=1)

        ResultCard(
            cards_frame, "SERVICES FOUND", str(len(banners)), WARNING
        ).grid(row=0, column=0, sticky="ew", padx=(0, 8))

        http_count = sum(1 for b in banners if b.get("port") in (80, 443, 8080, 8443))
        ResultCard(
            cards_frame, "HTTP SERVICES", str(http_count), ACCENT_CYAN
        ).grid(row=0, column=1, sticky="ew")

        # Banner list header
        if banners:
            list_header = ctk.CTkFrame(self, fg_color="transparent")
            list_header.pack(fill="x", pady=(12, 8))
            list_dot = ctk.CTkFrame(list_header, fg_color=WARNING, width=4, height=14, corner_radius=2)
            list_dot.pack(side="left", padx=(0, 8))
            list_dot.pack_propagate(False)
            ctk.CTkLabel(list_header, text="Service Banners", font=FONT_SECTION, text_color=TEXT).pack(side="left")

        # Banner rows
        for banner in banners:
            port = banner.get("port", 0)
            service = banner.get("service", "unknown")
            banner_text = banner.get("banner", "No banner")
            headers = banner.get("headers", {})

            row_frame = ctk.CTkFrame(
                self, fg_color=BG_SURFACE, border_width=1,
                border_color=BORDER, corner_radius=10, height=44,
            )
            row_frame.pack(fill="x", pady=4)
            row_frame.pack_propagate(False)

            # Port badge
            port_badge = ctk.CTkLabel(
                row_frame, text=str(port), font=FONT_CODE_B,
                text_color="#ffffff", fg_color=PRIMARY_DIM,
                corner_radius=6, width=64, height=24,
            )
            port_badge.pack(side="left", padx=(16, 0), pady=0)

            # Service badge
            svc_badge = ctk.CTkLabel(
                row_frame, text=service.upper(), font=FONT_BADGE_SM,
                fg_color=BG_ELEVATED, text_color=TEXT_MUTED,
                corner_radius=6, width=50, height=20,
            )
            svc_badge.pack(side="left", padx=(12, 0))

            # Banner text
            ctk.CTkLabel(
                row_frame, text=banner_text, font=FONT_CODE_SM,
                text_color=TEXT_SEC,
            ).pack(side="left", padx=(14, 0), fill="x", expand=True)


# ─── Expandable Result Card ─────────────────────────────────────


class ExpandableResultCard(ctk.CTkFrame):
    """Expandable card showing a plugin result summary with a collapsible detail section."""

    def __init__(
        self,
        master: Any,
        plugin_name: str,
        summary_items: list[str],
        accent_color: str,
        detail_factory: Callable[[Any], Any],
        **kwargs: Any,
    ) -> None:
        super().__init__(
            master,
            fg_color=BG_SURFACE,
            border_width=1,
            border_color=BORDER,
            corner_radius=12,
            height=48,
            **kwargs,
        )
        self.pack_propagate(False)
        self._expanded = False

        # ── Left accent bar ─────────────────────────────────────
        accent = ctk.CTkFrame(self, fg_color=accent_color, width=4, corner_radius=2)
        accent.pack(side="left", fill="y", padx=(0, 0), pady=8)

        # ── Main content area ───────────────────────────────────
        main_area = ctk.CTkFrame(self, fg_color="transparent")
        main_area.pack(side="left", fill="both", expand=True, padx=(14, 10), pady=8)

        # ── Summary row (clickable) ─────────────────────────────
        summary_row = ctk.CTkFrame(main_area, fg_color="transparent")
        summary_row.pack(fill="x")
        summary_row.bind("<Button-1>", lambda _e: self.toggle())

        # Plugin name
        ctk.CTkLabel(
            summary_row,
            text=plugin_name,
            font=("Segoe UI", 14, "bold"),
            text_color=TEXT,
        ).pack(side="left")

        # Summary metrics
        for item in summary_items:
            ctk.CTkLabel(
                summary_row,
                text=item,
                font=FONT_SMALL,
                text_color=TEXT_SEC,
            ).pack(side="left", padx=(16, 0))

        # Toggle button
        self._toggle_btn = ctk.CTkButton(
            summary_row,
            text="\u25b6  Details",
            width=105,
            height=28,
            font=FONT_SMALL,
            fg_color="transparent",
            border_width=1,
            border_color=BORDER,
            hover_color=BG_ELEVATED,
            text_color=TEXT_MUTED,
            corner_radius=8,
            command=self.toggle,
        )
        self._toggle_btn.pack(side="right")

        # ── Separator line (hidden initially) ───────────────────
        self._separator = ctk.CTkFrame(main_area, fg_color=BORDER, height=1)
        self._separator.pack_forget()

        # ── Detail frame (hidden initially) ─────────────────────
        self._detail_frame = ctk.CTkFrame(
            main_area,
            fg_color=BG_ELEVATED,
            corner_radius=8,
            border_width=1,
            border_color=BORDER,
        )
        self._detail_frame.pack_forget()

        # Build detail content inside the frame
        detail_widget = detail_factory(self._detail_frame)
        detail_widget.pack(fill="both", expand=True, padx=6, pady=6)

    def toggle(self) -> None:
        """Expand or collapse the detail section."""
        if self._expanded:
            self._separator.pack_forget()
            self._detail_frame.pack_forget()
            self._toggle_btn.configure(text="\u25b6  Details")
            self.configure(height=48)
        else:
            self._separator.pack(fill="x", pady=(8, 0))
            self._detail_frame.pack(fill="both", expand=True, pady=(8, 0))
            self._toggle_btn.configure(text="\u25bc  Details")
            self.configure(height=420)
        self._expanded = not self._expanded


# ─── Results Panel ──────────────────────────────────────────────


class ResultsPanel(ctk.CTkFrame):
    """Results panel that renders plugin results as expandable summary cards."""

    def __init__(
        self,
        master: Any,
        on_rendered: Callable[[dict[str, Any]], None] | None = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(
            master,
            fg_color="transparent",
            **kwargs,
        )
        self._on_rendered = on_rendered
        self._cards: list[ExpandableResultCard] = []

    def clear(self) -> None:
        """Remove all cards."""
        for card in self._cards:
            card.destroy()
        self._cards.clear()

    def render(self, results: list[dict[str, Any]]) -> None:
        """Render results as expandable summary cards — one per plugin."""
        self.clear()

        if not results:
            ctk.CTkLabel(
                self,
                text="No results yet",
                font=FONT_BODY,
                text_color=TEXT_DIM,
            ).pack(expand=True, pady=40)
            return

        for result in results:
            plugin = result.get("plugin", "unknown")
            success = result.get("success", False)
            data = result.get("data", {})

            # Extract summary info for the collapsed card row
            display_name, summary_items, accent_color = self._extract_summary(
                plugin, result, data
            )

            # Build a factory that creates the right detail widget
            factory = self._make_detail_factory(plugin, data, success)

            card = ExpandableResultCard(
                self,
                plugin_name=display_name,
                summary_items=summary_items,
                accent_color=accent_color,
                detail_factory=factory,
            )
            card.pack(fill="x", pady=(0, 10))
            self._cards.append(card)

        # Notify the host app that rendering is done
        if self._on_rendered:
            successful = sum(1 for r in results if r.get("success", False))
            target = results[0].get("target", "") if results else ""
            self._on_rendered({
                "successful": successful,
                "total": len(results),
                "target": target,
            })

    # ── Summary extraction ──────────────────────────────────────

    @staticmethod
    def _extract_summary(
        plugin: str, result: dict[str, Any], data: dict[str, Any]
    ) -> tuple[str, list[str], str]:
        """Return (display_name, [metric_strings], accent_color) for a result."""
        if not result.get("success", False):
            return (
                plugin.upper(),
                [result.get("error", "Unknown error")],
                ERROR,
            )

        if plugin == "nmap":
            hosts = data.get("hosts", [])
            total_ports = sum(len(h.get("ports", [])) for h in hosts)
            first_ip = hosts[0].get("ip", "?") if hosts else "?"
            return "Port Scan", [f"{total_ports} open ports", first_ip], PRIMARY

        if plugin == "dns":
            records = data.get("records", {})
            subdomains = data.get("subdomains", [])
            total_records = sum(
                len(v) if isinstance(v, list) else 0 for v in records.values()
            )
            return (
                "DNS Enum",
                [f"{total_records} records", f"{len(subdomains)} subdomains"],
                ACCENT_PURPLE,
            )

        if plugin == "vt":
            malicious = data.get("malicious", 0)
            suspicious = data.get("suspicious", 0)
            if malicious > 0:
                return "Threat Intel", [f"{malicious} malicious"], ERROR
            if suspicious > 0:
                return "Threat Intel", [f"{suspicious} suspicious"], WARNING
            return "Threat Intel", ["CLEAN"], SUCCESS

        if plugin == "whois":
            registrar = data.get("registrar", "")
            ns_count = len(data.get("name_servers", []))
            items = []
            if registrar:
                items.append(registrar)
            if ns_count:
                items.append(f"{ns_count} name servers")
            return "Whois Lookup", items if items else ["--"], ACCENT_CYAN

        if plugin == "banner":
            banners = data.get("banners", [])
            return "Banners", [f"{len(banners)} services found"], WARNING

        return plugin.capitalize(), ["\u2014"], TEXT_DIM

    # ── Detail widget factory ───────────────────────────────────

    @staticmethod
    def _make_detail_factory(
        plugin: str, data: dict[str, Any], success: bool
    ) -> Callable[[Any], Any]:
        """Return a callable that builds the detail widget for a given result."""

        def _factory(parent: Any) -> Any:
            if not success:
                return _build_error_detail(parent, data.get("error", "Unknown error"))

            if plugin == "nmap":
                return NmapTab(parent, data)
            if plugin == "dns":
                return DnsTab(parent, data)
            if plugin == "vt":
                return VtTab(parent, data)
            if plugin == "whois":
                return WhoisTab(parent, data)
            if plugin == "banner":
                return BannerTab(parent, data)

            return ctk.CTkLabel(
                parent,
                text=f"Unknown plugin: {plugin}",
                font=FONT_BODY,
                text_color=TEXT_MUTED,
            )

        return _factory


def _build_error_detail(parent: Any, message: str) -> ctk.CTkFrame:
    """Build a small error-state widget for a failed plugin."""
    frame = ctk.CTkFrame(parent, fg_color="transparent")
    frame.pack(fill="both", expand=True)

    icon = ctk.CTkFrame(
        frame, fg_color=ERROR, width=48, height=48, corner_radius=24
    )
    icon.pack(pady=(24, 12))
    icon.pack_propagate(False)
    ctk.CTkLabel(
        icon,
        text="\u2717",
        font=("Segoe UI", 22, "bold"),
        text_color="#ffffff",
        fg_color="transparent",
    ).pack(expand=True)

    ctk.CTkLabel(
        frame,
        text="Scan Failed",
        font=("Segoe UI", 16, "bold"),
        text_color=ERROR,
    ).pack()
    ctk.CTkLabel(
        frame,
        text=message,
        font=FONT_BODY,
        text_color=TEXT_MUTED,
        wraplength=500,
    ).pack(pady=(4, 0))

    return frame
