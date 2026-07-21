"""
PDF report generator for MapSec security scan results.

Uses reportlab under the hood — imported lazily to keep the module-level
namespace clean and avoid import overhead when PDF generation is not used.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from mapsec.analysis.models import AnalysisReport
    from mapsec.core.models import ScanReport


SEVERITY_COLORS = {
    "critical": "#e94560",
    "high": "#ff6b35",
    "medium": "#f0a500",
    "low": "#53d769",
    "info": "#4a90d9",
}

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def write_pdf(
    report: ScanReport,
    output_path: str | Path,
    analysis: AnalysisReport | None = None,
) -> Path:
    """Render a professional PDF report from a MapSec scan.

    Args:
        report: The raw scan results (mandatory).
        output_path: Filesystem path for the generated PDF.
        analysis: Optional analysis/enrichment layer with findings and score.

    Returns:
        The absolute path of the generated PDF file.
    """
    # ------------------------------------------------------------------
    # Lazy imports — reportlab is only needed when this function is called
    # ------------------------------------------------------------------
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import cm, mm
    from reportlab.platypus import (
        PageBreak,
        Paragraph,
        SimpleDocTemplate,
        Spacer,
        Table,
        TableStyle,
    )

    # ------------------------------------------------------------------
    # Resolve output path and ensure parent directory exists
    # ------------------------------------------------------------------
    output_path = Path(output_path).resolve()
    output_path.parent.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------------
    # Build styles
    # ------------------------------------------------------------------
    styles = getSampleStyleSheet()

    title_style = ParagraphStyle(
        "ReportTitle",
        parent=styles["Title"],
        fontSize=26,
        leading=32,
        spaceAfter=6,
        textColor=colors.HexColor("#1a1a2e"),
        alignment=TA_CENTER,
    )

    subtitle_style = ParagraphStyle(
        "ReportSubtitle",
        parent=styles["Normal"],
        fontSize=13,
        leading=18,
        spaceAfter=4,
        textColor=colors.HexColor("#555555"),
        alignment=TA_CENTER,
    )

    section_style = ParagraphStyle(
        "SectionHeading",
        parent=styles["Heading1"],
        fontSize=18,
        leading=24,
        spaceBefore=20,
        spaceAfter=10,
        textColor=colors.HexColor("#1a1a2e"),
        borderPadding=(0, 0, 4, 0),
    )

    subsection_style = ParagraphStyle(
        "SubsectionHeading",
        parent=styles["Heading2"],
        fontSize=14,
        leading=18,
        spaceBefore=14,
        spaceAfter=6,
        textColor=colors.HexColor("#16213e"),
    )

    body_style = ParagraphStyle(
        "ReportBody",
        parent=styles["Normal"],
        fontSize=10,
        leading=14,
        spaceAfter=6,
        alignment=TA_LEFT,
    )

    small_style = ParagraphStyle(
        "SmallText",
        parent=body_style,
        fontSize=8,
        leading=10,
        textColor=colors.HexColor("#888888"),
    )

    cell_style = ParagraphStyle(
        "CellText",
        parent=body_style,
        fontSize=9,
        leading=12,
        spaceAfter=0,
    )

    footer_style = ParagraphStyle(
        "Footer",
        parent=small_style,
        alignment=TA_CENTER,
        spaceBefore=0,
        spaceAfter=0,
    )

    score_style = ParagraphStyle(
        "ScoreBadge",
        parent=styles["Normal"],
        fontSize=28,
        leading=34,
        textColor=colors.white,
        alignment=TA_CENTER,
    )

    score_label_style = ParagraphStyle(
        "ScoreLabel",
        parent=styles["Normal"],
        fontSize=10,
        leading=14,
        textColor=colors.white,
        alignment=TA_CENTER,
        spaceAfter=2,
    )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
    def _severity_hex(severity: str) -> str:
        return SEVERITY_COLORS.get(severity.lower(), "#888888")

    def _severity_bg(severity: str) -> colors.HexColor:
        return colors.HexColor(_severity_hex(severity))

    def _fmt(val) -> str:
        """Safely format a value for PDF display."""
        if val is None:
            return "—"
        return str(val)

    def _wrap(text: str, max_len: int = 600) -> str:
        """Truncate extremely long strings to avoid reportlab buffer issues."""
        if len(text) > max_len:
            return text[:max_len] + "…"
        return text

    def _p(text: str, style=cell_style) -> Paragraph:
        return Paragraph(_wrap(text), style)

    # ------------------------------------------------------------------
    # Document setup
    # ------------------------------------------------------------------
    doc = SimpleDocTemplate(
        str(output_path),
        pagesize=A4,
        leftMargin=2 * cm,
        rightMargin=2 * cm,
        topMargin=2 * cm,
        bottomMargin=2.5 * cm,
        title="MapSec Security Report",
        author="Mapsec",
    )

    story: list = []

    # ==================================================================
    # TITLE PAGE
    # ==================================================================
    story.append(Spacer(1, 6 * cm))
    story.append(Paragraph("MapSec Security Report", title_style))

    target_str = _fmt(getattr(report, "target", None))
    story.append(Paragraph(target_str, subtitle_style))

    started = getattr(report, "started_at", None)
    if started:
        story.append(Paragraph(f"Scan date: {started}", subtitle_style))

    story.append(Spacer(1, 2 * cm))

    # -- Score badge (if analysis is available) --
    if analysis is not None:
        score = getattr(analysis, "score", None)
        if score is not None:
            badge_color = _severity_bg(
                "critical" if score < 40 else "high" if score < 60 else "medium" if score < 80 else "low"
            )
            score_table = Table(
                [
                    [Paragraph("SECURITY SCORE", score_label_style)],
                    [Paragraph(str(score), score_style)],
                    [Paragraph(f"/ 100", score_label_style)],
                ],
                colWidths=[6 * cm],
            )
            score_table.setStyle(
                TableStyle(
                    [
                        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                        ("BACKGROUND", (0, 0), (-1, -1), badge_color),
                        ("TOPPADDING", (0, 0), (-1, -1), 10),
                        ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
                        ("LEFTPADDING", (0, 0), (-1, -1), 20),
                        ("RIGHTPADDING", (0, 0), (-1, -1), 20),
                        ("ROUNDEDCORNERS", [6, 6, 6, 6]),
                    ]
                )
            )
            story.append(score_table)

    story.append(Spacer(1, 4 * cm))
    story.append(Paragraph("Generated by Mapsec", small_style))
    story.append(PageBreak())

    # ==================================================================
    # EXECUTIVE SUMMARY
    # ==================================================================
    story.append(Paragraph("Executive Summary", section_style))
    story.append(Spacer(1, 4 * mm))

    if analysis is not None:
        summary = getattr(analysis, "summary", None) or getattr(
            analysis, "llm_analysis", None
        ) or "No analysis summary available."
        story.append(Paragraph(_wrap(summary), body_style))

        plugins_used = getattr(analysis, "plugins_used", None)
        if plugins_used:
            story.append(Spacer(1, 3 * mm))
            story.append(
                Paragraph(
                    f"<b>Plugins executed:</b> {', '.join(plugins_used)}",
                    body_style,
                )
            )
    else:
        story.append(
            Paragraph(
                "No analysis data was provided. The report below reflects raw plugin "
                "results without severity scoring or recommendations.",
                body_style,
            )
        )

    # Count results
    results_list = getattr(report, "results", None) or []
    story.append(Spacer(1, 3 * mm))
    story.append(
        Paragraph(
            f"<b>Total plugin checks:</b> {len(results_list)}",
            body_style,
        )
    )
    success_count = sum(1 for r in results_list if getattr(r, "success", False))
    fail_count = len(results_list) - success_count
    story.append(
        Paragraph(
            f"<b>Passed:</b> {success_count} &nbsp;&nbsp; <b>Failed:</b> {fail_count}",
            body_style,
        )
    )

    story.append(Spacer(1, 6 * mm))

    # ==================================================================
    # FINDINGS TABLE  (only if analysis is available)
    # ==================================================================
    if analysis is not None:
        findings = getattr(analysis, "findings", None) or []
        if findings:
            story.append(Paragraph("Findings", section_style))
            story.append(Spacer(1, 4 * mm))

            # Sort findings by severity (critical first)
            sorted_findings = sorted(
                findings,
                key=lambda f: SEVERITY_ORDER.get(
                    getattr(f, "severity", "info").lower(), 99
                ),
            )

            # Prepare table data
            header = [
                _p("<b>Severity</b>"),
                _p("<b>Title</b>"),
                _p("<b>Description</b>"),
                _p("<b>Recommendation</b>"),
            ]

            # Column widths (A4 = 16 cm usable with 2 cm margins)
            col_widths = [2.2 * cm, 3.8 * cm, 4.8 * cm, 4.8 * cm]

            table_data = [header]
            row_colors = []

            for finding in sorted_findings:
                severity = getattr(finding, "severity", "info") or "info"
                title = _fmt(getattr(finding, "title", ""))
                description = _fmt(getattr(finding, "description", ""))
                recommendation = _fmt(getattr(finding, "recommendation", ""))

                bg = _severity_bg(severity)
                row_colors.append(bg)

                table_data.append(
                    [
                        Paragraph(f"<b>{severity.upper()}</b>", cell_style),
                        _p(title),
                        _p(description),
                        _p(recommendation),
                    ]
                )

            findings_table = Table(table_data, colWidths=col_widths, repeatRows=1)

            # Build style commands
            table_style_cmds = [
                # Header row
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1a1a2e")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, 0), 9),
                ("ALIGN", (0, 0), (-1, 0), "CENTER"),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                # Grid
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cccccc")),
                ("TOPPADDING", (0, 0), (-1, -1), 5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                ("LEFTPADDING", (0, 0), (-1, -1), 4),
                ("RIGHTPADDING", (0, 0), (-1, -1), 4),
            ]

            # Severity column background
            for i, bg in enumerate(row_colors):
                row_idx = i + 1  # +1 for header
                table_style_cmds.append(
                    ("BACKGROUND", (0, row_idx), (0, row_idx), bg)
                )
                table_style_cmds.append(
                    ("TEXTCOLOR", (0, row_idx), (0, row_idx), colors.white)
                )

            findings_table.setStyle(TableStyle(table_style_cmds))
            story.append(findings_table)
            story.append(Spacer(1, 6 * mm))

    # ==================================================================
    # PLUGIN RESULTS
    # ==================================================================
    story.append(Paragraph("Plugin Results", section_style))
    story.append(Spacer(1, 4 * mm))

    if not results_list:
        story.append(
            Paragraph("No plugin results were recorded in this scan.", body_style)
        )
    else:
        for idx, result in enumerate(results_list, start=1):
            plugin = _fmt(getattr(result, "plugin", f"Plugin #{idx}"))
            result_target = _fmt(getattr(result, "target", ""))
            success = getattr(result, "success", False)
            error = getattr(result, "error", None)
            duration = getattr(result, "duration_seconds", None)
            data = getattr(result, "data", None) or {}

            # Subsection heading
            status_icon = "✓" if success else "✗"
            story.append(
                Paragraph(
                    f"{idx}. <b>{plugin}</b>  "
                    f'<font color="{"#53d769" if success else "#e94560"}">[{status_icon}]</font>',
                    subsection_style,
                )
            )

            # Metadata
            meta_parts = [f"Target: {result_target}"]
            if duration is not None:
                meta_parts.append(f"Duration: {duration:.2f}s" if isinstance(duration, (int, float)) else f"Duration: {duration}")
            if error:
                meta_parts.append(f'Error: <font color="#e94560">{error}</font>')

            story.append(Paragraph(" &nbsp;·&nbsp; ".join(meta_parts), small_style))
            story.append(Spacer(1, 2 * mm))

            # Data table (if present)
            if data and isinstance(data, dict):
                flat_rows = _flatten_dict(data)
                if flat_rows:
                    data_header = [_p("<b>Key</b>"), _p("<b>Value</b>")]
                    data_rows = [data_header]
                    for key, value in flat_rows:
                        data_rows.append([_p(key), _p(value)])

                    data_col_widths = [5.5 * cm, 10 * cm]
                    data_table = Table(data_rows, colWidths=data_col_widths)

                    data_table.setStyle(
                        TableStyle(
                            [
                                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#16213e")),
                                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                                ("FONTSIZE", (0, 0), (-1, 0), 8),
                                ("FONTSIZE", (0, 1), (-1, -1), 8),
                                ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#dddddd")),
                                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                                ("TOPPADDING", (0, 0), (-1, -1), 3),
                                ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
                                ("LEFTPADDING", (0, 0), (-1, -1), 3),
                                ("RIGHTPADDING", (0, 0), (-1, -1), 3),
                                (
                                    "BACKGROUND",
                                    (0, 1),
                                    (-1, -1),
                                    colors.HexColor("#f8f9fa"),
                                ),
                            ]
                        )
                    )
                    story.append(data_table)
                else:
                    story.append(
                        Paragraph("<i>No structured data returned.</i>", small_style)
                    )
            elif data:
                story.append(
                    Paragraph(f"<i>Data:</i> {_fmt(data)}", body_style)
                )

            story.append(Spacer(1, 4 * mm))

    # ==================================================================
    # FOOTER (page numbers) — handled via onPage
    # ==================================================================
    def _footer(canvas, doc):
        canvas.saveState()
        canvas.setFont("Helvetica", 8)
        canvas.setFillColor(colors.HexColor("#888888"))
        page_num = canvas.getPageNumber()
        text = f"Page {page_num}  |  Generated by Mapsec"
        canvas.drawCentredString(
            A4[0] / 2, 1.5 * cm, text
        )
        canvas.restoreState()

    # ------------------------------------------------------------------
    # Build the PDF
    # ------------------------------------------------------------------
    doc.build(story, onFirstPage=_footer, onLaterPages=_footer)

    return output_path


# ------------------------------------------------------------------
# Internal helpers
# ------------------------------------------------------------------


def _flatten_dict(
    d: dict, parent_key: str = "", sep: str = "."
) -> list[tuple[str, str]]:
    """Recursively flatten a nested dict into a list of (key, value) tuples.

    Lists and dicts deeper than one level are JSON-serialised for display.
    """
    import json

    rows: list[tuple[str, str]] = []
    for k, v in d.items():
        composite_key = f"{parent_key}{sep}{k}" if parent_key else k
        if isinstance(v, dict) and v:
            rows.extend(_flatten_dict(v, composite_key, sep=sep))
        elif isinstance(v, (list, tuple)):
            if len(v) > 0 and all(isinstance(item, (str, int, float, bool)) for item in v):
                rows.append((composite_key, ", ".join(str(i) for i in v)))
            else:
                rows.append((composite_key, json.dumps(v, ensure_ascii=False, default=str)))
        else:
            rows.append((composite_key, str(v) if v is not None else "—"))
    return rows
