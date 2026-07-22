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

from mapsec.core.engine import Engine, _needs_context
from mapsec.core.models import PluginResult, ScanConfig, ScanReport
from mapsec.core.plugin import get_plugins
from mapsec.analysis.engine import AnalysisEngine
from mapsec.gui.results_panel import ResultsPanel
from mapsec.i18n import t, set_language, get_language, save_language, load_language, get_available_languages

# Import plugins to register them
import mapsec.plugins.nmap_scan  # noqa: F401
import mapsec.plugins.dns_enum  # noqa: F401
import mapsec.plugins.vt_lookup  # noqa: F401
import mapsec.plugins.whois_lookup  # noqa: F401
import mapsec.plugins.banner_grab  # noqa: F401
import mapsec.plugins.ssl_check  # noqa: F401
import mapsec.plugins.http_headers  # noqa: F401
import mapsec.plugins.shodan_lookup  # noqa: F401
import mapsec.plugins.cve_lookup  # noqa: F401

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
        load_language()

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

        # Apply saved Shodan API key
        shodan_key = self._config.get("shodan_api_key", "")
        if shodan_key:
            os.environ["SHODAN_API_KEY"] = shodan_key

        # State
        self._scan_report: ScanReport | None = None
        self._analysis_report = None  # AnalysisReport | None
        self._is_scanning = False
        self._scan_thread: threading.Thread | None = None
        self._analysis_engine = AnalysisEngine()

        # Configure LLM from saved config
        llm_provider = self._config.get("llm_provider", "")
        llm_key = self._config.get("llm_api_key", "")
        llm_model = self._config.get("llm_model", "")
        if llm_provider and llm_key:
            self._analysis_engine.configure_llm(llm_provider, llm_key, llm_model or None)

        # Translatable widgets — must be initialized BEFORE _build_ui
        self._translatable: dict[str, Any] = {}
        self._last_results_dicts: list[dict[str, Any]] | None = None

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
            footer, text=t("version"), font=FONT_TINY, text_color=TEXT_DIM,
        )
        self._version_label.pack(side="left")
        self._translatable["version_footer"] = self._version_label

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

        self._version_badge = ctk.CTkLabel(
            subtitle_frame,
            text=t("version"),
            font=("Consolas", 10, "bold"),
            text_color=PRIMARY_HOVER,
            fg_color=BG_ELEVATED,
            corner_radius=4,
            width=42,
            height=18,
        )
        self._version_badge.pack(side="left")
        self._translatable["version"] = self._version_badge

        self._subtitle_label = ctk.CTkLabel(
            subtitle_frame,
            text=t("subtitle"),
            font=FONT_SMALL,
            text_color=TEXT_DIM,
        )
        self._subtitle_label.pack(side="left", padx=(8, 0))
        self._translatable["subtitle"] = self._subtitle_label

        # Language toggle button
        self._lang_btn = ctk.CTkButton(
            title_row,
            text="EN" if get_language() == "en" else "PT",
            width=40,
            height=28,
            font=FONT_SMALL,
            fg_color=BG_ELEVATED,
            border_width=1,
            border_color=BORDER,
            hover_color=PRIMARY_DIM,
            text_color=TEXT,
            corner_radius=8,
            command=self._toggle_language,
        )
        self._lang_btn.pack(side="right", padx=(0, 12))

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

        self._target_label = ctk.CTkLabel(
            header_row, text=t("target_label"), font=FONT_SECTION, text_color=TEXT,
        )
        self._target_label.pack(side="left")
        self._translatable["target_label"] = self._target_label

        # Input row
        input_row = ctk.CTkFrame(frame, fg_color="transparent")
        input_row.pack(fill="x", padx=20, pady=(0, 18))

        self._target_entry = ctk.CTkEntry(
            input_row,
            placeholder_text=t("target_placeholder"),
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
        self._target_entry.bind("<Return>", lambda e: self._on_enter_pressed())
        self._target_entry.bind(
            "<FocusIn>", lambda e: self._target_entry.configure(border_color=BORDER_FOCUS)
        )
        self._target_entry.bind(
            "<FocusOut>", lambda e: self._target_entry.configure(border_color=BORDER)
        )

        self._scan_btn = ctk.CTkButton(
            input_row,
            text=t("btn_scan"),
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
        self._translatable["btn_scan"] = self._scan_btn

        self._cancel_btn = ctk.CTkButton(
            input_row,
            text=t("btn_cancel"),
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
        self._translatable["btn_cancel"] = self._cancel_btn

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

        self._plugins_label = ctk.CTkLabel(
            header_row, text=t("plugins_label"), font=FONT_SECTION, text_color=TEXT,
        )
        self._plugins_label.pack(side="left")
        self._translatable["plugins_label"] = self._plugins_label

        # Plugins in subtle card background
        plugins_outer = ctk.CTkFrame(
            frame,
            fg_color=BG_ELEVATED,
            border_width=1,
            border_color=BORDER,
            corner_radius=8,
        )
        plugins_outer.pack(fill="x", padx=20, pady=(0, 14))

        option_row1 = ctk.CTkFrame(plugins_outer, fg_color="transparent")
        option_row1.pack(fill="x", padx=14, pady=(10, 0))

        self._chk_nmap = ctk.CTkCheckBox(
            option_row1,
            text=t("plugin_nmap"),
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
        self._translatable["plugin_nmap"] = self._chk_nmap

        self._chk_dns = ctk.CTkCheckBox(
            option_row1,
            text=t("plugin_dns"),
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
        self._translatable["plugin_dns"] = self._chk_dns

        self._chk_vt = ctk.CTkCheckBox(
            option_row1,
            text=t("plugin_vt"),
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
        self._translatable["plugin_vt"] = self._chk_vt

        self._settings_btn = ctk.CTkButton(
            option_row1,
            text=t("btn_settings"),
            width=100,
            height=32,
            font=FONT_SMALL,
            fg_color="transparent",
            border_width=1,
            border_color=BORDER,
            text_color=TEXT_MUTED,
            hover_color=BG_ELEVATED,
            corner_radius=8,
            command=self._open_settings,
        )
        self._settings_btn.pack(side="right")
        self._translatable["btn_settings"] = self._settings_btn

        option_row2 = ctk.CTkFrame(plugins_outer, fg_color="transparent")
        option_row2.pack(fill="x", padx=14, pady=(6, 10))

        self._chk_whois = ctk.CTkCheckBox(
            option_row2,
            text=t("plugin_whois"),
            font=FONT_BODY,
            text_color=TEXT_SEC,
            fg_color=PRIMARY,
            hover_color=PRIMARY_HOVER,
            border_color=BORDER,
            corner_radius=4,
            checkmark_color="#ffffff",
        )
        self._chk_whois.pack(side="left", padx=(0, 24))
        self._translatable["plugin_whois"] = self._chk_whois

        self._chk_banner = ctk.CTkCheckBox(
            option_row2,
            text=t("plugin_banner"),
            font=FONT_BODY,
            text_color=TEXT_SEC,
            fg_color=PRIMARY,
            hover_color=PRIMARY_HOVER,
            border_color=BORDER,
            corner_radius=4,
            checkmark_color="#ffffff",
        )
        self._chk_banner.pack(side="left", padx=(0, 24))
        self._translatable["plugin_banner"] = self._chk_banner

        self._chk_ssl = ctk.CTkCheckBox(
            option_row2,
            text=t("plugin_ssl"),
            font=FONT_BODY,
            text_color=TEXT_SEC,
            fg_color=PRIMARY,
            hover_color=PRIMARY_HOVER,
            border_color=BORDER,
            corner_radius=4,
            checkmark_color="#ffffff",
        )
        self._chk_ssl.pack(side="left", padx=(0, 24))
        self._translatable["plugin_ssl"] = self._chk_ssl

        # Row 3: headers + shodan + cve
        option_row3 = ctk.CTkFrame(plugins_outer, fg_color="transparent")
        option_row3.pack(fill="x", padx=14, pady=(0, 10))

        self._chk_headers = ctk.CTkCheckBox(
            option_row3,
            text=t("plugin_headers"),
            font=FONT_BODY,
            text_color=TEXT_SEC,
            fg_color=PRIMARY,
            hover_color=PRIMARY_HOVER,
            border_color=BORDER,
            corner_radius=4,
            checkmark_color="#ffffff",
        )
        self._chk_headers.pack(side="left", padx=(0, 24))
        self._translatable["plugin_headers"] = self._chk_headers

        self._chk_shodan = ctk.CTkCheckBox(
            option_row3,
            text=t("plugin_shodan"),
            font=FONT_BODY,
            text_color=TEXT_SEC,
            fg_color=PRIMARY,
            hover_color=PRIMARY_HOVER,
            border_color=BORDER,
            corner_radius=4,
            checkmark_color="#ffffff",
        )
        self._chk_shodan.pack(side="left", padx=(0, 24))
        self._update_shodan_status()
        self._translatable["plugin_shodan"] = self._chk_shodan

        self._chk_cve = ctk.CTkCheckBox(
            option_row3,
            text=t("plugin_cve"),
            font=FONT_BODY,
            text_color=TEXT_SEC,
            fg_color=PRIMARY,
            hover_color=PRIMARY_HOVER,
            border_color=BORDER,
            corner_radius=4,
            checkmark_color="#ffffff",
        )
        self._chk_cve.pack(side="left", padx=(0, 24))
        self._translatable["plugin_cve"] = self._chk_cve

        # Progress area
        progress_frame = ctk.CTkFrame(frame, fg_color="transparent")
        progress_frame.pack(fill="x", padx=20, pady=(0, 6))

        self._progress_label = ctk.CTkLabel(
            progress_frame, text=t("ready"), font=FONT_SMALL, text_color=TEXT_MUTED,
        )
        self._progress_label.pack(anchor="w")
        self._translatable["ready"] = self._progress_label

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
            status_frame, text=t("status_nmap"), font=FONT_CODE_SM, text_color=TEXT_DIM,
        )
        self._status_nmap.pack(side="left", padx=(0, 24))

        self._status_dns = ctk.CTkLabel(
            status_frame, text=t("status_dns"), font=FONT_CODE_SM, text_color=TEXT_DIM,
        )
        self._status_dns.pack(side="left", padx=(0, 24))

        self._status_vt = ctk.CTkLabel(
            status_frame, text=t("status_vt"), font=FONT_CODE_SM, text_color=TEXT_DIM,
        )
        self._status_vt.pack(side="left", padx=(0, 24))

        self._status_whois = ctk.CTkLabel(
            status_frame, text=t("status_whois"), font=FONT_CODE_SM, text_color=TEXT_DIM,
        )
        self._status_whois.pack(side="left", padx=(0, 24))

        self._status_banner = ctk.CTkLabel(
            status_frame, text=t("status_banner"), font=FONT_CODE_SM, text_color=TEXT_DIM,
        )
        self._status_banner.pack(side="left", padx=(0, 24))

        self._status_ssl = ctk.CTkLabel(
            status_frame, text=t("status_ssl"), font=FONT_CODE_SM, text_color=TEXT_DIM,
        )
        self._status_ssl.pack(side="left", padx=(0, 24))

        self._status_headers = ctk.CTkLabel(
            status_frame, text=t("status_headers"), font=FONT_CODE_SM, text_color=TEXT_DIM,
        )
        self._status_headers.pack(side="left", padx=(0, 24))

        self._status_shodan = ctk.CTkLabel(
            status_frame, text=t("status_shodan"), font=FONT_CODE_SM, text_color=TEXT_DIM,
        )
        self._status_shodan.pack(side="left", padx=(0, 24))

        self._status_cve = ctk.CTkLabel(
            status_frame, text=t("status_cve"), font=FONT_CODE_SM, text_color=TEXT_DIM,
        )
        self._status_cve.pack(side="left")

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

        self._activity_log_label = ctk.CTkLabel(
            log_header, text=t("activity_log"), font=FONT_SECTION, text_color=TEXT,
        )
        self._activity_log_label.pack(side="left")
        self._translatable["activity_log"] = self._activity_log_label

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
            text=t("tab_results"),
            font=FONT_SECTION,
            text_color=TEXT,
        )
        self._results_status_label.pack(side="left")
        self._translatable["tab_results"] = self._results_status_label

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

        # ── Action buttons ──────────────────────────────────────
        action_frame = ctk.CTkFrame(self._results_tab, fg_color="transparent")
        action_frame.pack(fill="x", padx=0, pady=(10, 0))

        self._analyze_btn = ctk.CTkButton(
            action_frame,
            text=t("btn_analyze"),
            width=130,
            height=38,
            font=("Segoe UI", 12, "bold"),
            fg_color=ACCENT_PURPLE,
            hover_color="#8b6bff",
            text_color="#ffffff",
            corner_radius=10,
            state="disabled",
            command=self._start_analysis,
        )
        self._analyze_btn.pack(side="left")
        self._translatable["btn_analyze"] = self._analyze_btn

        # Export format buttons (right side)
        export_frame = ctk.CTkFrame(action_frame, fg_color="transparent")
        export_frame.pack(side="right")

        self._export_json_btn = ctk.CTkButton(
            export_frame, text=t("btn_export_json"), width=130, height=30,
            font=("Segoe UI", 10, "bold"), fg_color="#2563eb",
            hover_color="#1d4ed8", text_color="#ffffff", corner_radius=8,
            state="disabled", command=self._export_json,
        )
        self._export_json_btn.pack(side="left", padx=(0, 3))
        self._translatable["btn_export_json"] = self._export_json_btn

        self._export_html_btn = ctk.CTkButton(
            export_frame, text=t("btn_export_html"), width=150, height=30,
            font=("Segoe UI", 10, "bold"), fg_color="#7c3aed",
            hover_color="#6d28d9", text_color="#ffffff", corner_radius=8,
            state="disabled", command=self._export_html,
        )
        self._export_html_btn.pack(side="left", padx=(0, 3))
        self._translatable["btn_export_html"] = self._export_html_btn

        self._export_pdf_btn = ctk.CTkButton(
            export_frame, text=t("btn_export_pdf"), width=150, height=30,
            font=("Segoe UI", 10, "bold"), fg_color="#dc2626",
            hover_color="#b91c1c", text_color="#ffffff", corner_radius=8,
            state="disabled", command=self._export_pdf,
        )
        self._export_pdf_btn.pack(side="left")
        self._translatable["btn_export_pdf"] = self._export_pdf_btn

    # ── Language Support ────────────────────────────────────────

    def _toggle_language(self) -> None:
        """Toggle between English and Portuguese."""
        current = get_language()
        new_lang = "pt_BR" if current == "en" else "en"
        set_language(new_lang)
        save_language(new_lang)
        self._apply_translations()

    def _apply_translations(self) -> None:
        """Update all translatable widgets with current language."""
        # Update all stored translatable widgets
        for key, widget in self._translatable.items():
            try:
                widget.configure(text=t(key))
            except Exception:
                pass

        # Update target entry placeholder
        try:
            self._target_entry.configure(placeholder_text=t("target_placeholder"))
        except Exception:
            pass

        # Update status labels
        status_map = {
            "nmap": self._status_nmap,
            "dns": self._status_dns,
            "vt": self._status_vt,
            "whois": self._status_whois,
            "banner": self._status_banner,
            "ssl": self._status_ssl,
            "headers": self._status_headers,
            "shodan": self._status_shodan,
            "cve": self._status_cve,
        }
        for name, label in status_map.items():
            try:
                current_text = label.cget("text")
                # If currently idle (○), update with new translation
                if "\u25cb" in current_text:
                    label.configure(text=t(f"status_{name}"))
            except Exception:
                pass

        # Update language button
        self._lang_btn.configure(text="EN" if get_language() == "en" else "PT")

        # Update tab labels in the CTkTabview
        try:
            self._tabview.tab("Scan").configure(text=t("tab_scan"))
            self._tabview.tab("Results").configure(text=t("tab_results"))
        except Exception:
            pass

        # Re-render results panel with new language
        if self._last_results_dicts:
            try:
                self._results_panel.clear()
                self._results_panel.render(self._last_results_dicts)
                if self._analysis_report:
                    self._results_panel.render_analysis(self._analysis_report)
            except Exception:
                pass

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

        # Enable Analyze button
        self._analyze_btn.configure(state="normal")

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
            self._chk_vt.configure(text=t("plugin_vt_no_key"))
            self._chk_vt.deselect()

    def _update_shodan_status(self) -> None:
        """Update Shodan checkbox appearance based on API key status."""
        key = self._config.get("shodan_api_key", "")
        if key:
            self._chk_shodan.configure(text_color=SUCCESS)
            masked = key[:4] + "\u00b7\u00b7\u00b7" + key[-4:] if len(key) > 8 else "\u2022\u2022\u2022\u2022"
            self._chk_shodan.configure(text=f"\u2022 shodan \u2014 {masked}")
        else:
            self._chk_shodan.configure(text_color=ERROR)
            self._chk_shodan.configure(text=t("plugin_shodan_no_key"))
            self._chk_shodan.deselect()

    def _open_settings(self) -> None:
        """Open settings dialog for API key configuration."""
        dialog = ctk.CTkToplevel(self)
        dialog.title(t("settings_title"))
        dialog.geometry("460x520")
        dialog.configure(fg_color=BG_BASE)
        dialog.transient(self)
        dialog.grab_set()

        # Center on parent
        dialog.update_idletasks()
        x = self.winfo_x() + (self.winfo_width() - 460) // 2
        y = self.winfo_y() + (self.winfo_height() - 520) // 2
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
            card, text=t("settings_title"), font=FONT_TITLE, text_color=TEXT,
        ).pack(pady=(20, 4))

        ctk.CTkLabel(
            card,
            text=t("settings_api_key"),
            font=FONT_SMALL,
            text_color=TEXT_MUTED,
        ).pack(pady=(0, 14))

        # Scrollable content
        scroll = ctk.CTkScrollableFrame(
            card, fg_color="transparent",
            scrollbar_fg_color=BG_ELEVATED,
            scrollbar_button_color=BORDER,
            scrollbar_button_hover_color=PRIMARY,
        )
        scroll.pack(fill="both", expand=True, padx=4)

        # ── VT API Key ─────────────────────────────────────────
        ctk.CTkLabel(
            scroll, text=t("settings_vt_key"), font=FONT_BODY, text_color=TEXT_SEC,
        ).pack(anchor="w", padx=18)

        vt_entry = ctk.CTkEntry(
            scroll,
            placeholder_text=t("settings_paste_key"),
            width=370,
            height=36,
            font=FONT_CODE,
            fg_color=BG_INPUT,
            border_width=1,
            border_color=BORDER,
            text_color=TEXT,
            corner_radius=10,
            show="\u2022",
        )
        vt_entry.pack(padx=18, pady=(6, 2))

        current_vt = self._config.get("vt_api_key", "")
        if current_vt:
            vt_entry.insert(0, current_vt)

        ctk.CTkLabel(
            scroll, text=t("settings_vt_hint"),
            font=FONT_TINY, text_color=TEXT_DIM,
        ).pack(anchor="w", padx=18, pady=(0, 10))

        # ── Separator ──────────────────────────────────────────
        ctk.CTkFrame(scroll, fg_color=BORDER, height=1).pack(
            fill="x", padx=18, pady=(4, 10),
        )

        # ── Shodan API Key ────────────────────────────────────
        ctk.CTkLabel(
            scroll, text=t("settings_shodan_key"), font=FONT_BODY, text_color=TEXT_SEC,
        ).pack(anchor="w", padx=18)

        shodan_entry = ctk.CTkEntry(
            scroll,
            placeholder_text=t("settings_paste_shodan_key"),
            width=370,
            height=36,
            font=FONT_CODE,
            fg_color=BG_INPUT,
            border_width=1,
            border_color=BORDER,
            text_color=TEXT,
            corner_radius=10,
            show="\u2022",
        )
        shodan_entry.pack(padx=18, pady=(6, 2))

        current_shodan = self._config.get("shodan_api_key", "")
        if current_shodan:
            shodan_entry.insert(0, current_shodan)

        ctk.CTkLabel(
            scroll, text=t("settings_shodan_hint"),
            font=FONT_TINY, text_color=TEXT_DIM,
        ).pack(anchor="w", padx=18, pady=(0, 10))

        # ── Separator ──────────────────────────────────────────
        ctk.CTkFrame(scroll, fg_color=BORDER, height=1).pack(
            fill="x", padx=18, pady=(4, 10),
        )

        # ── LLM Provider ───────────────────────────────────────
        ctk.CTkLabel(
            scroll, text=t("settings_llm_provider"),
            font=FONT_BODY, text_color=TEXT_SEC,
        ).pack(anchor="w", padx=18)

        ctk.CTkLabel(
            scroll,
            text=t("settings_llm_hint"),
            font=FONT_TINY, text_color=TEXT_DIM,
        ).pack(anchor="w", padx=18, pady=(0, 6))

        # Provider dropdown
        provider_frame = ctk.CTkFrame(scroll, fg_color="transparent")
        provider_frame.pack(fill="x", padx=18, pady=(0, 6))

        ctk.CTkLabel(
            provider_frame, text="Provider", font=FONT_SMALL, text_color=TEXT_MUTED,
        ).pack(side="left")

        provider_var = ctk.StringVar(value=self._config.get("llm_provider", "none"))
        provider_menu = ctk.CTkOptionMenu(
            provider_frame,
            variable=provider_var,
            values=["none", "claude", "gemini", "openai"],
            width=140,
            height=32,
            font=FONT_SMALL,
            fg_color=BG_INPUT,
            button_color=BORDER,
            button_hover_color=PRIMARY_DIM,
            dropdown_fg_color=BG_ELEVATED,
            dropdown_hover_color=PRIMARY_DIM,
            corner_radius=8,
        )
        provider_menu.pack(side="right")

        # Model entry
        model_frame = ctk.CTkFrame(scroll, fg_color="transparent")
        model_frame.pack(fill="x", padx=18, pady=(0, 6))

        ctk.CTkLabel(
            model_frame, text=t("settings_model"), font=FONT_SMALL, text_color=TEXT_MUTED,
        ).pack(side="left")

        model_entry = ctk.CTkEntry(
            model_frame,
            placeholder_text="e.g. claude-sonnet-4-20250514",
            width=220,
            height=32,
            font=FONT_CODE_SM,
            fg_color=BG_INPUT,
            border_width=1,
            border_color=BORDER,
            text_color=TEXT,
            corner_radius=8,
        )
        model_entry.pack(side="right")
        current_model = self._config.get("llm_model", "")
        if current_model:
            model_entry.insert(0, current_model)

        # API Key entry
        llm_key_entry = ctk.CTkEntry(
            scroll,
            placeholder_text=t("settings_paste_llm_key"),
            width=370,
            height=36,
            font=FONT_CODE,
            fg_color=BG_INPUT,
            border_width=1,
            border_color=BORDER,
            text_color=TEXT,
            corner_radius=10,
            show="\u2022",
        )
        llm_key_entry.pack(padx=18, pady=(6, 2))

        current_llm_key = self._config.get("llm_api_key", "")
        if current_llm_key:
            llm_key_entry.insert(0, current_llm_key)

        # ── Save / Cancel ──────────────────────────────────────
        status_label = ctk.CTkLabel(
            scroll, text="", font=FONT_TINY, text_color=SUCCESS,
        )
        status_label.pack(anchor="w", padx=18, pady=(8, 4))

        btn_frame = ctk.CTkFrame(scroll, fg_color="transparent")
        btn_frame.pack(pady=(10, 14))

        def save_all() -> None:
            # VT key
            vt_val = vt_entry.get().strip()
            if vt_val:
                self._config["vt_api_key"] = vt_val
                os.environ["VT_API_KEY"] = vt_val
            else:
                self._config.pop("vt_api_key", None)
                os.environ.pop("VT_API_KEY", None)

            # Shodan key
            shodan_val = shodan_entry.get().strip()
            if shodan_val:
                self._config["shodan_api_key"] = shodan_val
                os.environ["SHODAN_API_KEY"] = shodan_val
            else:
                self._config.pop("shodan_api_key", None)
                os.environ.pop("SHODAN_API_KEY", None)

            # LLM config
            prov_val = provider_var.get()
            llm_val = llm_key_entry.get().strip()
            mdl_val = model_entry.get().strip()

            if prov_val and prov_val != "none" and llm_val:
                self._config["llm_provider"] = prov_val
                self._config["llm_api_key"] = llm_val
                self._config["llm_model"] = mdl_val
                self._analysis_engine.configure_llm(
                    prov_val, llm_val, mdl_val or None
                )
            else:
                self._config.pop("llm_provider", None)
                self._config.pop("llm_api_key", None)
                self._config.pop("llm_model", None)
                self._analysis_engine.configure_llm(None, None)

            save_config(self._config)
            self._update_vt_status()
            self._update_shodan_status()
            status_label.configure(text=t("settings_saved"), text_color=SUCCESS)
            dialog.after(800, dialog.destroy)

        def clear_all() -> None:
            vt_entry.delete(0, "end")
            shodan_entry.delete(0, "end")
            llm_key_entry.delete(0, "end")
            model_entry.delete(0, "end")
            provider_var.set("none")
            for key in ("vt_api_key", "shodan_api_key", "llm_provider", "llm_api_key", "llm_model"):
                self._config.pop(key, None)
            os.environ.pop("VT_API_KEY", None)
            os.environ.pop("SHODAN_API_KEY", None)
            save_config(self._config)
            self._update_vt_status()
            self._update_shodan_status()
            self._analysis_engine.configure_llm(None, None)
            status_label.configure(text=t("settings_all_cleared"), text_color=ERROR)
            dialog.after(800, dialog.destroy)

        ctk.CTkButton(
            btn_frame, text=t("btn_save"), width=105, height=36,
            font=FONT_BODY, fg_color=PRIMARY, hover_color=PRIMARY_HOVER,
            text_color="#ffffff", corner_radius=10, command=save_all,
        ).pack(side="left", padx=(0, 10))

        ctk.CTkButton(
            btn_frame, text=t("btn_clear_all"), width=85, height=36,
            font=FONT_BODY, fg_color=ERROR, hover_color=ERROR_DIM,
            text_color="#ffffff", corner_radius=10, command=clear_all,
        ).pack(side="left", padx=(0, 10))

        ctk.CTkButton(
            btn_frame, text=t("btn_cancel_action"), width=85, height=36,
            font=FONT_BODY, fg_color="transparent", border_width=1,
            border_color=BORDER, hover_color=BG_ELEVATED,
            text_color=TEXT_MUTED, corner_radius=10, command=dialog.destroy,
        ).pack(side="left")

    # ── Actions ────────────────────────────────────────────────

    def _on_enter_pressed(self) -> None:
        """Only start scan if the target entry actually has focus."""
        focused = self.focus_get()
        if focused == self._target_entry:
            self._start_scan()

    def _start_scan(self) -> None:
        """Validate inputs and start the scan in a background thread."""
        if self._is_scanning:
            return

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
        self._analysis_report = None
        self._is_scanning = True
        self._scan_btn.configure(state="disabled")
        self._cancel_btn.configure(state="normal")
        self._export_btn_state("disabled")
        self._progress_bar.set(0)
        self._progress_label.configure(text=t("scanning"))

        # Reset status labels
        for name, label in [
            ("nmap", self._status_nmap),
            ("dns", self._status_dns),
            ("vt", self._status_vt),
            ("whois", self._status_whois),
            ("banner", self._status_banner),
            ("ssl", self._status_ssl),
            ("headers", self._status_headers),
            ("shodan", self._status_shodan),
            ("cve", self._status_cve),
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
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        try:
            report = loop.run_until_complete(self._execute_scan(target, plugins))
            self.after(0, self._on_scan_complete, report)
        except Exception as e:
            self.after(0, self._on_scan_error, str(e))
        finally:
            loop.close()

    async def _execute_scan(self, target: str, plugins: list[str]) -> ScanReport:
        """Execute plugins sequentially for progress tracking."""
        total = len(plugins)
        report = ScanReport(target=target, started_at=datetime.now())
        engine = Engine()

        # Accumulate context for context-dependent plugins (e.g. CVE)
        accumulated_context: dict[str, Any] = {}

        for i, plugin_name in enumerate(plugins):
            if not self._is_scanning:
                break

            pct = i / total
            self.after(0, self._update_progress, pct, f"Running {plugin_name.upper()}...")

            config = ScanConfig(target=target, plugins=[plugin_name])
            start = time.time()

            try:
                result = None
                # For context-dependent plugins (e.g. CVE), run directly with accumulated context
                plugin_cls = get_plugins().get(plugin_name)
                if plugin_cls and _needs_context(plugin_cls) and accumulated_context:
                    plugin_instance = plugin_cls()
                    start_inner = time.time()
                    if plugin_instance.validate_target(target):
                        data = await plugin_instance.run(target, context=accumulated_context)
                        duration_inner = time.time() - start_inner
                        result = PluginResult(
                            plugin=plugin_name, target=target, data=data,
                            success=True, duration_seconds=round(duration_inner, 2),
                        )
                    else:
                        result = PluginResult(
                            plugin=plugin_name, target=target, success=False,
                            error=f"Target validation failed for plugin '{plugin_name}'",
                        )
                    report.add_result(result)
                    if result.success and result.data:
                        accumulated_context[plugin_name] = result.data
                else:
                    plugin_report = await engine.run(config)
                    if plugin_report.results:
                        result = plugin_report.results[0]
                        report.add_result(result)
                        # Accumulate successful results for context-dependent plugins
                        if result.success and result.data:
                            accumulated_context[plugin_name] = result.data
                    else:
                        result = None

                if result and result.success:
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
                elif result:
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
        self._scan_report = report
        self._is_scanning = False

        self._scan_btn.configure(state="normal")
        self._cancel_btn.configure(state="disabled")
        self._export_btn_state("normal")

        successful = sum(1 for r in report.results if r.success)
        total = len(report.results)
        self._progress_label.configure(text=f"Complete \u2014 {successful}/{total} succeeded")

        self._render_results(report)

    def _on_scan_error(self, error: str) -> None:
        """Handle scan error on the main thread."""
        self._is_scanning = False
        self._scan_btn.configure(state="normal")
        self._cancel_btn.configure(state="disabled")
        self._progress_label.configure(text=t("error"))
        self._log_error(f"Scan failed: {error}")

    def _cancel_scan(self) -> None:
        """Cancel the ongoing scan."""
        self._is_scanning = False
        self._scan_btn.configure(state="normal")
        self._cancel_btn.configure(state="disabled")
        self._progress_label.configure(text=t("cancelled"))
        self._log_error("Scan cancelled by user.")

    def _start_analysis(self) -> None:
        """Start security analysis of scan results."""
        if not self._scan_report:
            self._log_error("No scan results to analyze.")
            return

        self._analyze_btn.configure(state="disabled", text=t("btn_analyzing"))
        self._log_info("Starting security analysis...")

        thread = threading.Thread(target=self._run_analysis_thread, daemon=True)
        thread.start()

    def _run_analysis_thread(self) -> None:
        """Run analysis in background thread."""
        try:
            # Build results dict from scan report
            results: dict[str, Any] = {}
            plugins_used: list[str] = []
            for r in self._scan_report.results:
                if r.success and r.data:
                    results[r.plugin] = r.data
                    plugins_used.append(r.plugin)

            # Run analysis
            report = self._analysis_engine.analyze(
                results=results,
                target=self._scan_report.target,
                plugins_used=plugins_used,
            )

            # Update UI on main thread
            self.after(0, self._on_analysis_complete, report)
        except Exception as e:
            self.after(0, self._on_analysis_error, str(e))

    def _on_analysis_complete(self, report) -> None:
        """Handle analysis completion on main thread."""
        self._analysis_report = report
        self._analyze_btn.configure(state="normal", text=t("btn_analyze"))

        # Render analysis results
        self._results_panel.render_analysis(report)

        # Log summary
        self._log_success(
            f"Analysis complete \u2014 Score: {report.score}/100 "
            f"({len(report.findings)} findings)"
        )

        # Switch to Analysis tab
        self._tabview.set("Results")

    def _on_analysis_error(self, error: str) -> None:
        """Handle analysis error on main thread."""
        self._analyze_btn.configure(state="normal", text=t("btn_analyze"))
        self._log_error(f"Analysis failed: {error}")

    def _export_btn_state(self, state: str) -> None:
        """Enable or disable all export buttons."""
        for btn in (self._export_json_btn, self._export_html_btn, self._export_pdf_btn):
            btn.configure(state=state)

    def _export_json(self) -> None:
        """Export scan results to JSON file."""
        if not self._scan_report:
            self._log_error("No results to export.")
            return
        from tkinter import filedialog
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        fp = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON files", "*.json")],
            initialfile=f"mapsec_{self._scan_report.target}_{ts}.json",
            title="Export JSON",
        )
        if fp:
            Path(fp).write_text(json.dumps(self._scan_report.to_dict(), indent=2, ensure_ascii=False))
            self._log_success(f"JSON saved: {fp}")

    def _export_html(self) -> None:
        """Export scan results to HTML report."""
        if not self._scan_report:
            self._log_error("No results to export.")
            return
        from tkinter import filedialog
        from mapsec.output.html_report import write_html
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        fp = filedialog.asksaveasfilename(
            defaultextension=".html",
            filetypes=[("HTML files", "*.html")],
            initialfile=f"mapsec_{self._scan_report.target}_{ts}.html",
            title="Export HTML Report",
        )
        if fp:
            write_html(self._scan_report, fp, analysis=self._analysis_report)
            self._log_success(f"HTML report saved: {fp}")

    def _export_pdf(self) -> None:
        """Export scan results to PDF report."""
        if not self._scan_report:
            self._log_error("No results to export.")
            return
        from tkinter import filedialog
        from mapsec.output.pdf_export import write_pdf
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        fp = filedialog.asksaveasfilename(
            defaultextension=".pdf",
            filetypes=[("PDF files", "*.pdf")],
            initialfile=f"mapsec_{self._scan_report.target}_{ts}.pdf",
            title="Export PDF Report",
        )
        if fp:
            write_pdf(self._scan_report, fp, analysis=self._analysis_report)
            self._log_success(f"PDF report saved: {fp}")

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
        if self._chk_whois.get():
            plugins.append("whois")
        if self._chk_banner.get():
            plugins.append("banner")
        if self._chk_ssl.get():
            plugins.append("ssl")
        if self._chk_headers.get():
            plugins.append("headers")
        if self._chk_shodan.get():
            plugins.append("shodan")
        if self._chk_cve.get():
            plugins.append("cve")
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
        results_dicts = [r.model_dump() for r in report.results]
        self._last_results_dicts = results_dicts

        # Log current language for debug
        from mapsec.i18n import get_language
        current_lang = get_language()
        self._log_info(f"[i18n] Language at render time: {current_lang}")

        self._results_panel.render(results_dicts)

        successful = sum(1 for r in report.results if r.success)
        total = len(report.results)
        self._log_success(f"Scan complete \u2014 {successful}/{total} plugins succeeded")


def main() -> None:
    """Entry point — launch the Mapsec GUI."""
    app = MapsecGUI()
    app.mainloop()


if __name__ == "__main__":
    main()
