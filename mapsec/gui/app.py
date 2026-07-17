"""Mapsec GUI Application — customtkinter-based graphical interface."""

from __future__ import annotations

import asyncio
import json
import os
import sys
import threading
import time
import tkinter as tk
from datetime import datetime
from pathlib import Path
from typing import Any

import customtkinter as ctk

from mapsec.core.engine import Engine
from mapsec.core.models import PluginResult, ScanConfig, ScanReport
from mapsec.gui.results_panel import ResultsPanel

# Import plugins to register them
import mapsec.plugins.nmap_scan  # noqa: F401
import mapsec.plugins.dns_enum  # noqa: F401
import mapsec.plugins.vt_lookup  # noqa: F401

# ─── Theme ──────────────────────────────────────────────────────
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

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
NEUTRAL_HOVER = "#4b5563"
ACCENT_CYAN   = "#22d3ee"
ACCENT_PURPLE = "#a78bfa"
ACCENT_PINK   = "#f472b6"

# ─── Fonts ──────────────────────────────────────────────────────
FONT_APP_TITLE = ("Segoe UI", 22, "bold")
FONT_APP_SUB   = ("Segoe UI", 11)
FONT_TITLE     = ("Segoe UI", 16, "bold")
FONT_SECTION   = ("Segoe UI", 13, "bold")
FONT_BODY      = ("Segoe UI", 12)
FONT_SMALL     = ("Segoe UI", 11)
FONT_TINY      = ("Segoe UI", 10)
FONT_CODE      = ("Consolas", 11)
FONT_CODE_SM   = ("Consolas", 10)

# Config file path
CONFIG_DIR = Path.home() / ".mapsec"
CONFIG_FILE = CONFIG_DIR / "config.json"


def load_config() -> dict:
    """Load config from file."""
    if CONFIG_FILE.exists():
        try:
            return json.loads(CONFIG_FILE.read_text(encoding="utf-8"))
        except Exception:
            pass
    return {}


def save_config(config: dict) -> None:
    """Save config to file."""
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    CONFIG_FILE.write_text(json.dumps(config, indent=2), encoding="utf-8")


class MapsecGUI(ctk.CTk):
    """Main GUI window for Mapsec."""

    def __init__(self) -> None:
        super().__init__()

        # Window config
        self.title("Mapsec \u2014 Security Reconnaissance")
        self.geometry("920x720")
        self.minsize(720, 520)
        self.configure(fg_color=BG_BASE)

        # Set window icon
        try:
            if getattr(sys, 'frozen', False):
                icon_path = Path(sys._MEIPASS) / "mapsec.ico"
            else:
                icon_path = Path(__file__).parent.parent.parent / "mapsec.ico"
            if icon_path.exists():
                self.iconbitmap(str(icon_path))
        except Exception:
            pass

        # Load saved config
        self._config = load_config()

        # Apply saved VT API key
        vt_key = self._config.get("vt_api_key", "")
        if vt_key:
            os.environ["VT_API_KEY"] = vt_key

        # State
        self._scan_report: ScanReport | None = None
        self._is_scanning = False
        self._scan_thread: threading.Thread | None = None

        # Build UI
        self._build_ui()

    # ══════════════════════════════════════════════════════════════
    #  UI LAYOUT — Two-tab design
    # ══════════════════════════════════════════════════════════════

    def _build_ui(self) -> None:
        """Build the complete two-tab UI layout."""

        # ── Main container ──────────────────────────────────────
        self._main_frame = ctk.CTkFrame(self, fg_color=BG_BASE)
        self._main_frame.pack(fill="both", expand=True, padx=24, pady=18)

        # ── Branding Header ─────────────────────────────────────
        self._build_header()

        # ── Tabview ─────────────────────────────────────────────
        self._tabview = ctk.CTkTabview(
            self._main_frame,
            fg_color=BG_BASE,
            corner_radius=10,
            segmented_button_fg_color=BG_ELEVATED,
            segmented_button_selected_color=PRIMARY,
            segmented_button_unselected_color=BG_SURFACE,
            segmented_button_selected_hover_color=PRIMARY_HOVER,
            text_color=TEXT,
        )
        self._tabview.pack(fill="both", expand=True, pady=(0, 4))

        # ── Scan Tab ────────────────────────────────────────────
        self._scan_tab = self._tabview.add("Scan")
        self._build_target_section()
        self._build_middle_section()
        self._build_activity_log_section()

        # ── Results Tab ─────────────────────────────────────────
        self._results_tab = self._tabview.add("Results")
        self._build_results_tab()

        # ── Version footer ──────────────────────────────────────
        footer = ctk.CTkFrame(self._main_frame, fg_color="transparent")
        footer.pack(fill="x")

        self._version_label = ctk.CTkLabel(
            footer, text="v0.1.0", font=FONT_TINY, text_color=TEXT_DIM,
        )
        self._version_label.pack(side="left")

    # ── Header ──────────────────────────────────────────────────

    def _build_header(self) -> None:
        """Branded header with app title and accent line."""
        header_wrapper = ctk.CTkFrame(self._main_frame, fg_color="transparent")
        header_wrapper.pack(fill="x", pady=(0, 20))

        # Accent line — thin gradient-like bar using stacked colored segments
        accent_bar = ctk.CTkFrame(header_wrapper, fg_color="transparent", height=3)
        accent_bar.pack(fill="x", pady=(0, 14))
        accent_bar.pack_propagate(False)

        segments = [
            (PRIMARY, 0.35),
            (ACCENT_PURPLE, 0.25),
            (ACCENT_CYAN, 0.20),
            (SUCCESS, 0.20),
        ]
        for color, weight in segments:
            seg = ctk.CTkFrame(accent_bar, fg_color=color, corner_radius=0)
            seg.pack(side="left", fill="both", expand=True, padx=(0, 1))

        # Title row
        title_row = ctk.CTkFrame(header_wrapper, fg_color="transparent")
        title_row.pack(fill="x")

        # App icon indicator — small colored square
        icon_dot = ctk.CTkFrame(title_row, fg_color=PRIMARY, width=8, height=32, corner_radius=3)
        icon_dot.pack(side="left", padx=(0, 12))
        icon_dot.pack_propagate(False)

        # App title
        ctk.CTkLabel(
            title_row,
            text="Mapsec",
            font=FONT_APP_TITLE,
            text_color=TEXT,
        ).pack(side="left")

        # Version + subtitle
        subtitle_frame = ctk.CTkFrame(title_row, fg_color="transparent")
        subtitle_frame.pack(side="left", padx=(12, 0), pady=(4, 0))

        ctk.CTkLabel(
            subtitle_frame,
            text="v0.1.0",
            font=("Consolas", 10, "bold"),
            text_color=PRIMARY_HOVER,
            fg_color=BG_ELEVATED,
            corner_radius=4,
            width=42,
            height=18,
        ).pack(side="left")

        ctk.CTkLabel(
            subtitle_frame,
            text="Security Reconnaissance Toolkit",
            font=FONT_SMALL,
            text_color=TEXT_DIM,
        ).pack(side="left", padx=(8, 0))

    # ── Scan Tab — Target Section ───────────────────────────────

    def _build_target_section(self) -> None:
        """Target input and scan buttons."""
        frame = ctk.CTkFrame(
            self._scan_tab,
            fg_color=BG_SURFACE,
            border_width=1,
            border_color=BORDER,
            corner_radius=12,
        )
        frame.pack(fill="x", pady=(0, 14))

        # Section label with icon feel
        header_row = ctk.CTkFrame(frame, fg_color="transparent")
        header_row.pack(fill="x", padx=20, pady=(16, 8))

        section_dot = ctk.CTkFrame(header_row, fg_color=PRIMARY, width=4, height=16, corner_radius=2)
        section_dot.pack(side="left", padx=(0, 8))
        section_dot.pack_propagate(False)

        ctk.CTkLabel(
            header_row, text="Target", font=FONT_SECTION, text_color=TEXT,
        ).pack(side="left")

        # Input row
        input_row = ctk.CTkFrame(frame, fg_color="transparent")
        input_row.pack(fill="x", padx=20, pady=(0, 18))

        self._target_entry = ctk.CTkEntry(
            input_row,
            placeholder_text="e.g. example.com  or  192.168.1.0/24",
            placeholder_text_color=TEXT_DIM,
            height=44,
            font=FONT_CODE,
            fg_color=BG_INPUT,
            border_width=1,
            border_color=BORDER,
            text_color=TEXT,
            corner_radius=10,
        )
        self._target_entry.pack(side="left", fill="x", expand=True, padx=(0, 12))
        self._target_entry.bind("<Return>", lambda e: self._start_scan())
        self._target_entry.bind(
            "<FocusIn>", lambda e: self._target_entry.configure(border_color=BORDER_FOCUS)
        )
        self._target_entry.bind(
            "<FocusOut>", lambda e: self._target_entry.configure(border_color=BORDER)
        )

        self._scan_btn = ctk.CTkButton(
            input_row,
            text="\u25b6  Scan",
            width=110,
            height=44,
            font=("Segoe UI", 13, "bold"),
            fg_color=PRIMARY,
            hover_color=PRIMARY_HOVER,
            text_color="#ffffff",
            corner_radius=10,
            command=self._start_scan,
        )
        self._scan_btn.pack(side="right")

        self._cancel_btn = ctk.CTkButton(
            input_row,
            text="\u2715  Cancel",
            width=95,
            height=44,
            font=FONT_BODY,
            fg_color=ERROR,
            hover_color=ERROR_DIM,
            text_color="#ffffff",
            corner_radius=10,
            state="disabled",
            command=self._cancel_scan,
        )
        self._cancel_btn.pack(side="right", padx=(0, 10))

    # ── Scan Tab — Plugins & Progress Section ───────────────────

    def _build_middle_section(self) -> None:
        """Plugin selection and progress bar."""
        frame = ctk.CTkFrame(
            self._scan_tab,
            fg_color=BG_SURFACE,
            border_width=1,
            border_color=BORDER,
            corner_radius=12,
        )
        frame.pack(fill="x", pady=(0, 14))

        # Plugins header
        header_row = ctk.CTkFrame(frame, fg_color="transparent")
        header_row.pack(fill="x", padx=20, pady=(16, 8))

        section_dot = ctk.CTkFrame(header_row, fg_color=ACCENT_PURPLE, width=4, height=16, corner_radius=2)
        section_dot.pack(side="left", padx=(0, 8))
        section_dot.pack_propagate(False)

        ctk.CTkLabel(
            header_row, text="Plugins", font=FONT_SECTION, text_color=TEXT,
        ).pack(side="left")

        # Plugins in subtle card background
        plugins_outer = ctk.CTkFrame(
            frame,
            fg_color=BG_ELEVATED,
            border_width=1,
            border_color=BORDER,
            corner_radius=8,
        )
        plugins_outer.pack(fill="x", padx=20, pady=(0, 14))

        option_row = ctk.CTkFrame(plugins_outer, fg_color="transparent")
        option_row.pack(fill="x", padx=14, pady=10)

        self._chk_nmap = ctk.CTkCheckBox(
            option_row,
            text="\u2022 nmap \u2014 port scan",
            font=FONT_BODY,
            text_color=TEXT_SEC,
            fg_color=PRIMARY,
            hover_color=PRIMARY_HOVER,
            border_color=BORDER,
            corner_radius=4,
            checkmark_color="#ffffff",
        )
        self._chk_nmap.pack(side="left", padx=(0, 24))
        self._chk_nmap.select()

        self._chk_dns = ctk.CTkCheckBox(
            option_row,
            text="\u2022 dns \u2014 enumeration",
            font=FONT_BODY,
            text_color=TEXT_SEC,
            fg_color=PRIMARY,
            hover_color=PRIMARY_HOVER,
            border_color=BORDER,
            corner_radius=4,
            checkmark_color="#ffffff",
        )
        self._chk_dns.pack(side="left", padx=(0, 24))
        self._chk_dns.select()

        self._chk_vt = ctk.CTkCheckBox(
            option_row,
            text="\u2022 vt \u2014 threat intel",
            font=FONT_BODY,
            text_color=TEXT_SEC,
            fg_color=PRIMARY,
            hover_color=PRIMARY_HOVER,
            border_color=BORDER,
            corner_radius=4,
            checkmark_color="#ffffff",
        )
        self._chk_vt.pack(side="left", padx=(0, 24))
        self._update_vt_status()

        self._settings_btn = ctk.CTkButton(
            option_row,
            text="\u2699  Settings",
            width=100,
            height=32,
            font=FONT_SMALL,
            fg_color="transparent",
            border_width=1,
            border_color=BORDER,
            hover_color=BG_ELEVATED,
            text_color=TEXT_MUTED,
            corner_radius=8,
            command=self._open_settings,
        )
        self._settings_btn.pack(side="right")

        # Progress area
        progress_frame = ctk.CTkFrame(frame, fg_color="transparent")
        progress_frame.pack(fill="x", padx=20, pady=(0, 6))

        self._progress_label = ctk.CTkLabel(
            progress_frame, text="Ready", font=FONT_SMALL, text_color=TEXT_MUTED,
        )
        self._progress_label.pack(anchor="w")

        self._progress_bar = ctk.CTkProgressBar(
            progress_frame,
            height=5,
            fg_color=BG_ELEVATED,
            progress_color=PRIMARY,
            corner_radius=3,
            border_width=0,
        )
        self._progress_bar.pack(fill="x", pady=(8, 0))
        self._progress_bar.set(0)

        # Per-plugin status
        status_frame = ctk.CTkFrame(frame, fg_color="transparent")
        status_frame.pack(fill="x", padx=20, pady=(10, 16))

        self._status_nmap = ctk.CTkLabel(
            status_frame, text="\u25cb nmap", font=FONT_CODE_SM, text_color=TEXT_DIM,
        )
        self._status_nmap.pack(side="left", padx=(0, 24))

        self._status_dns = ctk.CTkLabel(
            status_frame, text="\u25cb dns", font=FONT_CODE_SM, text_color=TEXT_DIM,
        )
        self._status_dns.pack(side="left", padx=(0, 24))

        self._status_vt = ctk.CTkLabel(
            status_frame, text="\u25cb vt", font=FONT_CODE_SM, text_color=TEXT_DIM,
        )
        self._status_vt.pack(side="left")

    # ── Scan Tab — Activity Log ─────────────────────────────────

    def _build_activity_log_section(self) -> None:
        """Activity log showing scan progress messages."""
        log_header = ctk.CTkFrame(self._scan_tab, fg_color="transparent")
        log_header.pack(fill="x", pady=(0, 6))

        section_dot = ctk.CTkFrame(
            log_header, fg_color=ACCENT_CYAN, width=4, height=16, corner_radius=2,
        )
        section_dot.pack(side="left", padx=(0, 8))
        section_dot.pack_propagate(False)

        ctk.CTkLabel(
            log_header, text="Activity Log", font=FONT_SECTION, text_color=TEXT,
        ).pack(side="left")

        self._results_text = ctk.CTkTextbox(
            self._scan_tab,
            font=FONT_CODE,
            fg_color=BG_INPUT,
            text_color=TEXT_MUTED,
            border_width=1,
            border_color=BORDER,
            corner_radius=10,
            wrap="word",
            state="disabled",
            height=120,
        )
        self._results_text.pack(fill="x")

    # ── Results Tab ─────────────────────────────────────────────

    def _build_results_tab(self) -> None:
        """Build the Results tab with summary header, cards, and export."""

        # ── Summary header card ─────────────────────────────────
        summary_card = ctk.CTkFrame(
            self._results_tab,
            fg_color=BG_SURFACE,
            border_width=1,
            border_color=BORDER,
            corner_radius=12,
        )
        summary_card.pack(fill="x", padx=0, pady=(0, 10))

        summary_row = ctk.CTkFrame(summary_card, fg_color="transparent")
        summary_row.pack(fill="x", padx=20, pady=16)

        section_dot = ctk.CTkFrame(
            summary_row, fg_color=ACCENT_CYAN, width=4, height=16, corner_radius=2,
        )
        section_dot.pack(side="left", padx=(0, 8))
        section_dot.pack_propagate(False)

        self._results_status_label = ctk.CTkLabel(
            summary_row,
            text="Results",
            font=FONT_SECTION,
            text_color=TEXT,
        )
        self._results_status_label.pack(side="left")

        self._results_target_label = ctk.CTkLabel(
            summary_row,
            text="",
            font=FONT_SMALL,
            text_color=TEXT_MUTED,
        )
        self._results_target_label.pack(side="left", padx=(16, 0))

        # ── Scrollable area for result cards ────────────────────
        self._results_scroll = ctk.CTkScrollableFrame(
            self._results_tab,
            fg_color="transparent",
            scrollbar_fg_color=BG_ELEVATED,
            scrollbar_button_color=BORDER,
            scrollbar_button_hover_color=PRIMARY,
        )
        self._results_scroll.pack(fill="both", expand=True)

        # ── Results panel (populated after scan) ────────────────
        self._results_panel = ResultsPanel(
            self._results_scroll,
            on_rendered=self._on_results_rendered,
        )
        self._results_panel.pack(fill="x")

        # ── Export button ───────────────────────────────────────
        export_frame = ctk.CTkFrame(self._results_tab, fg_color="transparent")
        export_frame.pack(fill="x", padx=0, pady=(10, 0))

        self._export_btn = ctk.CTkButton(
            export_frame,
            text="\u2b07  Export JSON",
            width=140,
            height=38,
            font=("Segoe UI", 12, "bold"),
            fg_color=SUCCESS,
            hover_color=SUCCESS_DIM,
            text_color="#ffffff",
            corner_radius=10,
            state="disabled",
            command=self._export_results,
        )
        self._export_btn.pack(side="right")

    def _on_results_rendered(self, info: dict[str, Any]) -> None:
        """Callback fired after ResultsPanel finishes rendering cards."""
        # Update summary header
        successful = info.get("successful", 0)
        total = info.get("total", 0)
        target = info.get("target", "")
        self._results_status_label.configure(
            text=f"Scan complete \u2014 {successful}/{total} succeeded"
        )
        self._results_target_label.configure(text=f"Target: {target}")

        # Auto-switch to Results tab
        self._tabview.set("Results")

    # ── Settings / VT API Key ──────────────────────────────────

    def _update_vt_status(self) -> None:
        """Update VT checkbox appearance based on API key status."""
        vt_key = self._config.get("vt_api_key", "")
        if vt_key:
            self._chk_vt.configure(text_color=SUCCESS)
            masked = vt_key[:4] + "\u00b7\u00b7\u00b7" + vt_key[-4:] if len(vt_key) > 8 else "\u2022\u2022\u2022\u2022"
            self._chk_vt.configure(text=f"\u2022 vt \u2014 {masked}")
        else:
            self._chk_vt.configure(text_color=ERROR)
            self._chk_vt.configure(text="\u2022 vt \u2014 no API key")
            self._chk_vt.deselect()

    def _open_settings(self) -> None:
        """Open settings dialog for API key configuration."""
        dialog = ctk.CTkToplevel(self)
        dialog.title("Settings")
        dialog.geometry("460x300")
        dialog.configure(fg_color=BG_BASE)
        dialog.transient(self)
        dialog.grab_set()

        # Center on parent
        dialog.update_idletasks()
        x = self.winfo_x() + (self.winfo_width() - 460) // 2
        y = self.winfo_y() + (self.winfo_height() - 300) // 2
        dialog.geometry(f"+{x}+{y}")

        # Dialog card
        card = ctk.CTkFrame(
            dialog,
            fg_color=BG_SURFACE,
            border_width=1,
            border_color=BORDER,
            corner_radius=14,
        )
        card.pack(fill="both", expand=True, padx=18, pady=18)

        # Accent line in dialog
        dialog_accent = ctk.CTkFrame(card, fg_color=PRIMARY, height=3, corner_radius=2)
        dialog_accent.pack(fill="x", padx=18, pady=(18, 0))

        # Title
        ctk.CTkLabel(
            card, text="API Key Configuration", font=FONT_TITLE, text_color=TEXT,
        ).pack(pady=(20, 4))

        ctk.CTkLabel(
            card,
            text="Configure integrations for enhanced scanning",
            font=FONT_SMALL,
            text_color=TEXT_MUTED,
        ).pack(pady=(0, 18))

        # VT API Key
        ctk.CTkLabel(
            card, text="VirusTotal API Key", font=FONT_BODY, text_color=TEXT_SEC,
        ).pack(anchor="w", padx=22)

        vt_entry = ctk.CTkEntry(
            card,
            placeholder_text="Paste your API key here",
            width=390,
            height=42,
            font=FONT_CODE,
            fg_color=BG_INPUT,
            border_width=1,
            border_color=BORDER,
            text_color=TEXT,
            corner_radius=10,
            show="\u2022",
        )
        vt_entry.pack(padx=22, pady=(8, 4))

        # Pre-fill if key exists
        current_key = self._config.get("vt_api_key", "")
        if current_key:
            vt_entry.insert(0, current_key)

        # Status label
        status_label = ctk.CTkLabel(
            card,
            text="Get a free key at virustotal.com",
            font=FONT_TINY,
            text_color=TEXT_DIM,
        )
        status_label.pack(anchor="w", padx=22, pady=(2, 0))

        # Buttons
        btn_frame = ctk.CTkFrame(card, fg_color="transparent")
        btn_frame.pack(pady=(22, 22))

        def save_key() -> None:
            key = vt_entry.get().strip()
            if key:
                self._config["vt_api_key"] = key
                os.environ["VT_API_KEY"] = key
            else:
                self._config.pop("vt_api_key", None)
                os.environ.pop("VT_API_KEY", None)
            save_config(self._config)
            self._update_vt_status()
            status_label.configure(text="Saved", text_color=SUCCESS)
            dialog.after(800, dialog.destroy)

        def clear_key() -> None:
            vt_entry.delete(0, "end")
            self._config.pop("vt_api_key", None)
            os.environ.pop("VT_API_KEY", None)
            save_config(self._config)
            self._update_vt_status()
            status_label.configure(text="API key removed", text_color=ERROR)
            dialog.after(800, dialog.destroy)

        ctk.CTkButton(
            btn_frame,
            text="Save",
            width=105,
            height=36,
            font=FONT_BODY,
            fg_color=PRIMARY,
            hover_color=PRIMARY_HOVER,
            text_color="#ffffff",
            corner_radius=10,
            command=save_key,
        ).pack(side="left", padx=(0, 10))

        ctk.CTkButton(
            btn_frame,
            text="Clear",
            width=85,
            height=36,
            font=FONT_BODY,
            fg_color=ERROR,
            hover_color=ERROR_DIM,
            text_color="#ffffff",
            corner_radius=10,
            command=clear_key,
        ).pack(side="left", padx=(0, 10))

        ctk.CTkButton(
            btn_frame,
            text="Cancel",
            width=85,
            height=36,
            font=FONT_BODY,
            fg_color="transparent",
            border_width=1,
            border_color=BORDER,
            hover_color=BG_ELEVATED,
            text_color=TEXT_MUTED,
            corner_radius=10,
            command=dialog.destroy,
        ).pack(side="left")

    # ── Actions ────────────────────────────────────────────────

    def _start_scan(self) -> None:
        """Validate inputs and start the scan in a background thread."""
        target = self._target_entry.get().strip()
        if not target:
            self._log_error("Enter a scan target.")
            return

        plugins = self._get_selected_plugins()
        if not plugins:
            self._log_error("Select at least one plugin.")
            return

        # Reset state
        self._scan_report = None
        self._is_scanning = True
        self._scan_btn.configure(state="disabled")
        self._cancel_btn.configure(state="normal")
        self._export_btn.configure(state="disabled")
        self._progress_bar.set(0)
        self._progress_label.configure(text="Scanning...")

        # Reset status labels
        for name, label in [
            ("nmap", self._status_nmap),
            ("dns", self._status_dns),
            ("vt", self._status_vt),
        ]:
            if name in plugins:
                label.configure(text=f"\u25b6 {name}", text_color=WARNING)
            else:
                label.configure(text=f"\u25cb {name}", text_color=TEXT_DIM)

        # Clear results
        self._clear_results()
        self._log_info(
            f"Starting scan: {target} ({len(plugins)} plugin"
            f"{'s' if len(plugins) != 1 else ''})"
        )

        # Run in thread
        self._scan_thread = threading.Thread(
            target=self._run_scan_thread, args=(target, plugins), daemon=True
        )
        self._scan_thread.start()

    def _run_scan_thread(self, target: str, plugins: list[str]) -> None:
        """Execute scan in background thread (blocking)."""
        import pathlib
        dbg = pathlib.Path.home() / ".mapsec" / "debug.log"
        def _dlog(msg):
            from datetime import datetime as dt
            with open(dbg, "a", encoding="utf-8") as f:
                f.write(f"{dt.now().strftime('%H:%M:%S.%f')}  {msg}\n")

        _dlog(f"Thread started: target={target}, plugins={plugins}")
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        try:
            _dlog("Calling _execute_scan...")
            report = loop.run_until_complete(self._execute_scan(target, plugins))
            _dlog(f"Scan done, results={len(report.results)}, calling _on_scan_complete")
            self.after(0, self._on_scan_complete, report)
            _dlog("self.after(_on_scan_complete) scheduled")
        except Exception as e:
            _dlog(f"EXCEPTION: {e}")
            self.after(0, self._on_scan_error, str(e))
        finally:
            loop.close()
            _dlog("Thread finished")

    async def _execute_scan(self, target: str, plugins: list[str]) -> ScanReport:
        """Execute plugins sequentially for progress tracking."""
        total = len(plugins)
        report = ScanReport(target=target, started_at=datetime.now())
        engine = Engine()

        for i, plugin_name in enumerate(plugins):
            if not self._is_scanning:
                break

            pct = i / total
            self.after(0, self._update_progress, pct, f"Running {plugin_name.upper()}...")

            config = ScanConfig(target=target, plugins=[plugin_name])
            start = time.time()

            try:
                plugin_report = await engine.run(config)
                if plugin_report.results:
                    result = plugin_report.results[0]
                    report.add_result(result)

                    if result.success:
                        self.after(
                            0,
                            self._update_plugin_status,
                            plugin_name,
                            "success",
                            result.duration_seconds,
                        )
                        self.after(
                            0,
                            self._log_success,
                            f"{plugin_name.upper()} complete ({result.duration_seconds:.1f}s)",
                        )
                    else:
                        self.after(
                            0,
                            self._update_plugin_status,
                            plugin_name,
                            "failed",
                            0,
                            result.error,
                        )
                        self.after(
                            0,
                            self._log_error,
                            f"{plugin_name.upper()} failed: {result.error}",
                        )
            except Exception as e:
                duration = time.time() - start
                result = PluginResult(
                    plugin=plugin_name,
                    target=target,
                    success=False,
                    error=str(e),
                    duration_seconds=duration,
                )
                report.add_result(result)
                self.after(0, self._update_plugin_status, plugin_name, "failed", 0, str(e))
                self.after(0, self._log_error, f"{plugin_name.upper()} exception: {e}")

        report.finished_at = datetime.now()
        self.after(0, self._update_progress, 1.0, "Complete")
        return report

    def _on_scan_complete(self, report: ScanReport) -> None:
        """Handle scan completion on the main thread."""
        import pathlib
        dbg = pathlib.Path.home() / ".mapsec" / "debug.log"
        def _dlog(msg):
            from datetime import datetime as dt
            with open(dbg, "a", encoding="utf-8") as f:
                f.write(f"{dt.now().strftime('%H:%M:%S.%f')}  {msg}\n")

        _dlog(f"_on_scan_complete called: results={len(report.results)}")
        self._scan_report = report
        self._is_scanning = False

        self._scan_btn.configure(state="normal")
        self._cancel_btn.configure(state="disabled")
        self._export_btn.configure(state="normal")

        successful = sum(1 for r in report.results if r.success)
        total = len(report.results)
        self._progress_label.configure(text=f"Complete \u2014 {successful}/{total} succeeded")

        try:
            _dlog("Calling _render_results...")
            self._render_results(report)
            _dlog("_render_results done")
        except Exception as e:
            _dlog(f"_render_results EXCEPTION: {e}")
            import traceback
            traceback.print_exc()

    def _on_scan_error(self, error: str) -> None:
        """Handle scan error on the main thread."""
        self._is_scanning = False
        self._scan_btn.configure(state="normal")
        self._cancel_btn.configure(state="disabled")
        self._progress_label.configure(text="Error")
        self._log_error(f"Scan failed: {error}")

    def _cancel_scan(self) -> None:
        """Cancel the ongoing scan."""
        self._is_scanning = False
        self._scan_btn.configure(state="normal")
        self._cancel_btn.configure(state="disabled")
        self._progress_label.configure(text="Cancelled")
        self._log_error("Scan cancelled by user.")

    def _export_results(self) -> None:
        """Export scan results to JSON file via dialog."""
        if not self._scan_report:
            self._log_error("No results to export.")
            return

        from tkinter import filedialog

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        default_name = f"mapsec_{self._scan_report.target}_{timestamp}.json"

        filepath = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
            initialfile=default_name,
            title="Export Scan Results",
        )

        if filepath:
            data = self._scan_report.to_dict()
            Path(filepath).write_text(json.dumps(data, indent=2, ensure_ascii=False))
            self._log_success(f"Report saved: {filepath}")

    # ── UI Helpers ─────────────────────────────────────────────

    def _get_selected_plugins(self) -> list[str]:
        """Get list of selected plugin names."""
        plugins = []
        if self._chk_nmap.get():
            plugins.append("nmap")
        if self._chk_dns.get():
            plugins.append("dns")
        if self._chk_vt.get():
            plugins.append("vt")
        return plugins

    def _update_progress(self, pct: float, text: str) -> None:
        """Update progress bar and label (thread-safe via after())."""
        self._progress_bar.set(pct)
        self._progress_label.configure(text=text)

    def _update_plugin_status(
        self, name: str, status: str, duration: float = 0, error: str | None = None
    ) -> None:
        """Update a plugin's status label."""
        label = getattr(self, f"_status_{name}", None)
        if not label:
            return

        if status == "running":
            label.configure(text=f"\u25b6 {name}", text_color=WARNING)
        elif status == "success":
            label.configure(text=f"\u2713 {name} ({duration:.1f}s)", text_color=SUCCESS)
        elif status == "failed":
            label.configure(text=f"\u2717 {name}", text_color=ERROR)

    def _clear_results(self) -> None:
        """Clear the results panel and status log."""
        self._results_panel.clear()
        self._results_text.configure(state="normal")
        self._results_text.delete("1.0", "end")
        self._results_text.configure(state="disabled")

    def _append_result(self, text: str) -> None:
        """Append text to the results textbox."""
        self._results_text.configure(state="normal")
        self._results_text.insert("end", text + "\n")
        self._results_text.see("end")
        self._results_text.configure(state="disabled")

    def _log_info(self, msg: str) -> None:
        self._append_result(f"\u25cf  {msg}")

    def _log_success(self, msg: str) -> None:
        self._append_result(f"\u2713  {msg}")

    def _log_error(self, msg: str) -> None:
        self._append_result(f"\u2717  {msg}")

    def _render_results(self, report: ScanReport) -> None:
        """Render final scan results in the tabbed panel."""
        import pathlib
        dbg = pathlib.Path.home() / ".mapsec" / "debug.log"
        def _dlog(msg):
            from datetime import datetime as dt
            with open(dbg, "a", encoding="utf-8") as f:
                f.write(f"{dt.now().strftime('%H:%M:%S.%f')}  {msg}\n")

        _dlog(f"_render_results: {len(report.results)} results")
        for r in report.results:
            _dlog(f"  plugin={r.plugin}, success={r.success}, data_keys={list(r.data.keys()) if r.data else 'None'}")

        results_dicts = [r.model_dump() for r in report.results]
        _dlog(f"model_dump done: {len(results_dicts)} dicts")

        try:
            self._results_panel.render(results_dicts)
            _dlog("results_panel.render() done")
        except Exception as e:
            _dlog(f"results_panel.render() EXCEPTION: {e}")
            import traceback
            traceback.print_exc()

        successful = sum(1 for r in report.results if r.success)
        total = len(report.results)
        self._log_success(f"Scan complete \u2014 {successful}/{total} plugins succeeded")


def main() -> None:
    """Entry point — launch the Mapsec GUI."""
    app = MapsecGUI()
    app.mainloop()


if __name__ == "__main__":
    main()
