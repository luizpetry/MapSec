"""
Gerador de relatório HTML profissional para o MapSec.

Gera um relatório autossuficiente (CSS inline, sem dependências externas)
 a partir de um ``ScanReport`` e, opcionalmente, um ``AnalysisReport``.
"""

from __future__ import annotations

import html
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from mapsec.analysis.models import AnalysisReport, Finding
from mapsec.core.models import ScanReport

# ──────────────────────────────────────────────────────────────
#  Constantes de estilo
# ──────────────────────────────────────────────────────────────

BG_PRIMARY = "#1a1a2e"
BG_CARD = "#16213e"
BG_ACCENT = "#0f3460"
COLOR_CRITICAL = "#e94560"
COLOR_SUCCESS = "#53d769"
COLOR_WARNING = "#f5a623"
COLOR_INFO = "#54a0ff"
COLOR_TEXT = "#e0e0e0"
COLOR_MUTED = "#8892b0"
COLOR_WHITE = "#ffffff"
SEVERITY_COLORS: Dict[str, str] = {
    "critical": COLOR_CRITICAL,
    "high": "#ff6b6b",
    "medium": COLOR_WARNING,
    "low": "#f7d794",
    "info": COLOR_INFO,
}
SEVERITY_ORDER: Dict[str, int] = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "info": 4,
}


# ──────────────────────────────────────────────────────────────
#  Utilitários
# ──────────────────────────────────────────────────────────────


def _esc(text: Any) -> str:
    """Escapa texto para uso seguro em HTML."""
    return html.escape(str(text or ""), quote=True)


def _fmt_duration(seconds: float) -> str:
    """Formata duração em segundos para exibição legível."""
    if seconds < 1:
        return f"{seconds * 1000:.0f}ms"
    if seconds < 60:
        return f"{seconds:.1f}s"
    mins, secs = divmod(int(seconds), 60)
    return f"{mins}m {secs}s"


def _fmt_dt(dt: datetime | None) -> str:
    """Formata datetime para string legível."""
    if dt is None:
        return "—"
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.strftime("%d/%m/%Y %H:%M:%S UTC")


def _sev_label(severity: str) -> str:
    return severity.capitalize() if severity else "Info"


# ──────────────────────────────────────────────────────────────
#  CSS (inline, autossuficiente)
# ──────────────────────────────────────────────────────────────


def _get_css() -> str:
    return f"""\
* {{
    margin: 0;
    padding: 0;
    box-sizing: border-box;
}}

body {{
    font-family: 'Segoe UI', -apple-system, BlinkMacSystemFont, Roboto,
        Oxygen, Ubuntu, Cantarell, 'Helvetica Neue', Arial, sans-serif;
    background: {BG_PRIMARY};
    color: {COLOR_TEXT};
    line-height: 1.6;
    padding: 2rem 1rem;
}}

.container {{
    max-width: 1100px;
    margin: 0 auto;
}}

/* ── Header ──────────────────────────────────────────────── */

.header {{
    text-align: center;
    padding: 2.5rem 1.5rem;
    background: linear-gradient(135deg, {BG_CARD}, {BG_ACCENT});
    border-radius: 16px;
    margin-bottom: 2rem;
    border: 1px solid rgba(255,255,255,0.06);
}}

.header h1 {{
    font-size: 2rem;
    font-weight: 700;
    color: {COLOR_WHITE};
    letter-spacing: 0.5px;
    margin-bottom: 0.5rem;
}}

.header h1::before {{
    content: "🛡️ ";
}}

.header .target {{
    font-size: 1.15rem;
    color: {COLOR_INFO};
    font-weight: 600;
    word-break: break-all;
}}

.header .meta {{
    display: flex;
    justify-content: center;
    flex-wrap: wrap;
    gap: 1.5rem;
    margin-top: 0.75rem;
    font-size: 0.9rem;
    color: {COLOR_MUTED};
}}

.meta-item {{
    display: inline-flex;
    align-items: center;
    gap: 0.35rem;
}}

.meta-item strong {{
    color: {COLOR_TEXT};
}}

/* ── Cards genéricos ─────────────────────────────────────── */

.card {{
    background: {BG_CARD};
    border-radius: 12px;
    padding: 1.5rem;
    margin-bottom: 1.5rem;
    border: 1px solid rgba(255,255,255,0.06);
}}

.card h2 {{
    font-size: 1.25rem;
    font-weight: 600;
    margin-bottom: 1rem;
    color: {COLOR_WHITE};
    display: flex;
    align-items: center;
    gap: 0.5rem;
}}

/* ── Gauge (pontuação) ────────────────────────────────────── */

.gauge-wrapper {{
    display: flex;
    align-items: center;
    gap: 2rem;
    flex-wrap: wrap;
}}

.gauge {{
    flex-shrink: 0;
    position: relative;
    width: 140px;
    height: 140px;
}}

.gauge svg {{
    transform: rotate(-90deg);
}}

.gauge-bg {{
    fill: none;
    stroke: rgba(255,255,255,0.08);
    stroke-width: 10;
}}

.gauge-fill {{
    fill: none;
    stroke: {COLOR_SUCCESS};
    stroke-width: 10;
    stroke-linecap: round;
    transition: stroke-dashoffset 1s ease-in-out;
}}

.gauge-text {{
    position: absolute;
    top: 50%;
    left: 50%;
    transform: translate(-50%, -50%);
    font-size: 2.2rem;
    font-weight: 700;
    color: {COLOR_WHITE};
}}

.gauge-text small {{
    font-size: 1rem;
    font-weight: 400;
    color: {COLOR_MUTED};
}}

.summary-text {{
    flex: 1;
    min-width: 200px;
    color: {COLOR_TEXT};
    font-size: 0.95rem;
    line-height: 1.7;
}}

/* ── Badges ───────────────────────────────────────────────── */

.badge {{
    display: inline-block;
    padding: 0.2rem 0.7rem;
    border-radius: 20px;
    font-size: 0.75rem;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.5px;
}}

.badge-critical {{ background: {COLOR_CRITICAL}; color: #fff; }}
.badge-high    {{ background: #ff6b6b; color: #fff; }}
.badge-medium  {{ background: {COLOR_WARNING}; color: #1a1a2e; }}
.badge-low     {{ background: #f7d794; color: #1a1a2e; }}
.badge-info    {{ background: {COLOR_INFO}; color: #fff; }}
.badge-grade-a {{ background: {COLOR_SUCCESS}; color: #fff; }}
.badge-grade-b {{ background: #8bc34a; color: #1a1a2e; }}
.badge-grade-c {{ background: {COLOR_WARNING}; color: #1a1a2e; }}
.badge-grade-d {{ background: #ff9800; color: #1a1a2e; }}
.badge-grade-e {{ background: #ff5722; color: #fff; }}
.badge-grade-f {{ background: {COLOR_CRITICAL}; color: #fff; }}

/* ── Finding cards ────────────────────────────────────────── */

.finding {{
    border-left: 4px solid {COLOR_CRITICAL};
    padding: 1rem 1.25rem;
    margin-bottom: 1rem;
    border-radius: 0 8px 8px 0;
    background: rgba(255,255,255,0.03);
}}

.finding.severity-critical {{ border-left-color: {COLOR_CRITICAL}; }}
.finding.severity-high    {{ border-left-color: #ff6b6b; }}
.finding.severity-medium  {{ border-left-color: {COLOR_WARNING}; }}
.finding.severity-low     {{ border-left-color: #f7d794; }}
.finding.severity-info    {{ border-left-color: {COLOR_INFO}; }}

.finding-header {{
    display: flex;
    align-items: flex-start;
    justify-content: space-between;
    gap: 0.75rem;
    margin-bottom: 0.4rem;
}}

.finding h3 {{
    font-size: 1rem;
    font-weight: 600;
    color: {COLOR_WHITE};
    flex: 1;
}}

.finding p {{
    font-size: 0.9rem;
    color: {COLOR_MUTED};
    margin-bottom: 0.5rem;
}}

.finding .recommendation {{
    background: rgba(15,52,96,0.4);
    padding: 0.5rem 0.75rem;
    border-radius: 6px;
    font-size: 0.88rem;
    color: {COLOR_TEXT};
    margin-top: 0.25rem;
}}

.finding .source {{
    font-size: 0.8rem;
    color: {COLOR_MUTED};
    margin-top: 0.25rem;
}}

/* ── Tabelas ──────────────────────────────────────────────── */

table {{
    width: 100%;
    border-collapse: collapse;
    font-size: 0.88rem;
}}

thead th {{
    text-align: left;
    padding: 0.6rem 0.75rem;
    background: {BG_ACCENT};
    color: {COLOR_MUTED};
    font-weight: 600;
    text-transform: uppercase;
    font-size: 0.75rem;
    letter-spacing: 0.4px;
    border-bottom: 2px solid rgba(255,255,255,0.06);
}}

tbody td {{
    padding: 0.55rem 0.75rem;
    border-bottom: 1px solid rgba(255,255,255,0.04);
    vertical-align: top;
}}

tbody tr:hover {{
    background: rgba(255,255,255,0.03);
}}

.table-wrap {{
    overflow-x: auto;
}}

/* ── Plugin cards ─────────────────────────────────────────── */

.plugin-card {{
    background: {BG_CARD};
    border-radius: 12px;
    padding: 1.5rem;
    margin-bottom: 1.25rem;
    border: 1px solid rgba(255,255,255,0.06);
}}

.plugin-card h3 {{
    font-size: 1.05rem;
    font-weight: 600;
    color: {COLOR_WHITE};
    margin-bottom: 1rem;
    display: flex;
    align-items: center;
    gap: 0.5rem;
}}

.plugin-card .success {{
    color: {COLOR_SUCCESS};
}}

.plugin-card .error-msg {{
    color: {COLOR_CRITICAL};
    background: rgba(233,69,96,0.1);
    padding: 0.75rem;
    border-radius: 6px;
    margin-bottom: 0.5rem;
    font-size: 0.9rem;
}}

.plugin-meta {{
    font-size: 0.82rem;
    color: {COLOR_MUTED};
    margin-bottom: 1rem;
}}

.plugin-meta strong {{
    color: {COLOR_TEXT};
}}

/* ── Listas ───────────────────────────────────────────────── */

.tag-list {{
    display: flex;
    flex-wrap: wrap;
    gap: 0.4rem;
    list-style: none;
}}

.tag-list li {{
    background: {BG_ACCENT};
    color: {COLOR_INFO};
    padding: 0.2rem 0.6rem;
    border-radius: 4px;
    font-size: 0.8rem;
}}

.info-grid {{
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(200px, 1fr));
    gap: 0.75rem;
}}

.info-grid .field {{
    font-size: 0.82rem;
    color: {COLOR_MUTED};
}}

.info-grid .field strong {{
    display: block;
    color: {COLOR_TEXT};
    font-weight: 600;
    margin-bottom: 0.15rem;
}}

/* ── Threat summary ───────────────────────────────────────── */

.threat-bars {{
    display: flex;
    gap: 1.5rem;
    flex-wrap: wrap;
    margin-bottom: 1rem;
}}

.threat-bar {{
    flex: 1;
    min-width: 100px;
}}

.threat-bar .label {{
    font-size: 0.8rem;
    color: {COLOR_MUTED};
    margin-bottom: 0.15rem;
}}

.threat-bar .bar {{
    height: 8px;
    border-radius: 4px;
    background: rgba(255,255,255,0.06);
    overflow: hidden;
}}

.threat-bar .fill {{
    height: 100%;
    border-radius: 4px;
    transition: width 0.8s ease;
}}

.threat-bar .fill.malicious   {{ background: {COLOR_CRITICAL}; }}
.threat-bar .fill.suspicious  {{ background: {COLOR_WARNING}; }}
.threat-bar .fill.clean       {{ background: {COLOR_SUCCESS}; }}
.threat-bar .fill.undetected  {{ background: {COLOR_INFO}; }}
.threat-bar .fill.timeout     {{ background: #888; }}

.threat-bar .count {{
    font-size: 0.9rem;
    font-weight: 600;
    color: {COLOR_WHITE};
    margin-top: 0.1rem;
}}

/* ── Footer ───────────────────────────────────────────────── */

.footer {{
    text-align: center;
    padding: 1.5rem;
    color: {COLOR_MUTED};
    font-size: 0.85rem;
    border-top: 1px solid rgba(255,255,255,0.06);
    margin-top: 2rem;
}}

.footer strong {{
    color: {COLOR_INFO};
}}

/* ── Collapsible sections ─────────────────────────────────── */

.collapsible {{
    cursor: pointer;
    user-select: none;
    position: relative;
}}

.collapsible::after {{
    content: "▶";
    font-size: 0.7rem;
    color: {COLOR_MUTED};
    margin-left: 0.5rem;
    transition: transform 0.2s ease;
    display: inline-block;
}}

.collapsible.open::after {{
    transform: rotate(90deg);
}}

.collapsible-content {{
    max-height: 0;
    overflow: hidden;
    transition: max-height 0.3s ease;
}}

.collapsible-content.open {{
    max-height: 50000px;
}}

/* ── Grade badge grande ─────────────────────────────────── */

.grade-badge {{
    display: inline-flex;
    align-items: center;
    justify-content: center;
    width: 56px;
    height: 56px;
    border-radius: 50%;
    font-size: 1.6rem;
    font-weight: 700;
    margin-bottom: 0.5rem;
}}

.grade-a {{ background: {COLOR_SUCCESS}; color: #fff; }}
.grade-b {{ background: #8bc34a; color: #fff; }}
.grade-c {{ background: {COLOR_WARNING}; color: #1a1a2e; }}
.grade-d {{ background: #ff9800; color: #fff; }}
.grade-e {{ background: #ff5722; color: #fff; }}
.grade-f {{ background: {COLOR_CRITICAL}; color: #fff; }}

/* ── Responsivo ───────────────────────────────────────────── */

@media (max-width: 640px) {{
    body {{ padding: 1rem 0.5rem; }}
    .header h1 {{ font-size: 1.5rem; }}
    .gauge-wrapper {{ flex-direction: column; align-items: center; text-align: center; }}
    .meta {{ flex-direction: column; gap: 0.5rem; align-items: center; }}
    .finding-header {{ flex-direction: column; }}
    .info-grid {{ grid-template-columns: 1fr; }}
    .threat-bars {{ flex-direction: column; }}
}}

/* ── Impressão ────────────────────────────────────────────── */

@media print {{
    body {{
        background: #fff;
        color: #222;
        padding: 0.5in;
        font-size: 11pt;
    }}
    .header {{
        background: #f5f5f5 !important;
        border: 1px solid #ddd;
        -webkit-print-color-adjust: exact;
        print-color-adjust: exact;
    }}
    .header h1 {{ color: #111; }}
    .header h1::before {{ content: ""; }}
    .card, .plugin-card, .finding {{
        background: #fafafa !important;
        border: 1px solid #ccc;
        break-inside: avoid;
        -webkit-print-color-adjust: exact;
        print-color-adjust: exact;
    }}
    .card h2, .plugin-card h3, .finding h3 {{ color: #111; }}
    .finding {{ border-left-width: 4px; }}
    .finding p, .finding .recommendation {{ color: #333; }}
    .badge, .grade-badge {{
        -webkit-print-color-adjust: exact;
        print-color-adjust: exact;
    }}
    table thead th {{
        background: #ddd !important;
        color: #111;
        -webkit-print-color-adjust: exact;
        print-color-adjust: exact;
    }}
    table tbody td {{
        border-bottom: 1px solid #ccc;
        color: #222;
    }}
    table tbody tr:hover {{ background: transparent; }}
    .meta-item, .meta-item strong, .header .target {{
        color: #333 !important;
    }}
    .gauge-wrapper {{ page-break-inside: avoid; }}
    .gauge-text {{ color: #111; }}
    .gauge-text small {{ color: #666; }}
    .gauge-bg {{ stroke: #ddd; }}
    .gauge-fill {{ -webkit-print-color-adjust: exact; print-color-adjust: exact; }}
    .footer {{ color: #666; border-top-color: #ccc; }}
    .footer strong {{ color: #0f3460; }}
    .summary-text {{ color: #333; }}
    .info-grid .field {{ color: #555; }}
    .info-grid .field strong {{ color: #111; }}
    .tag-list li {{
        background: #e0e0e0 !important;
        color: #111;
    }}
    .finding .source {{ color: #555; }}
    .finding .recommendation {{
        background: #eee !important;
        color: #111;
    }}
    .plugin-meta {{ color: #555; }}
    .plugin-meta strong {{ color: #111; }}
    .threat-bar .fill {{
        -webkit-print-color-adjust: exact;
        print-color-adjust: exact;
    }}
    .threat-bar .label {{ color: #555; }}
    .threat-bar .count {{ color: #111; }}
    .grade-badge {{
        -webkit-print-color-adjust: exact;
        print-color-adjust: exact;
    }}
}}"""


# ──────────────────────────────────────────────────────────────
#  Funções auxiliares de renderização
# ──────────────────────────────────────────────────────────────


def _row(tag: str, cells: List[str], header: bool = False) -> str:
    cell_tag = "th" if header else "td"
    cells_html = "".join(f"<{cell_tag}>{c}</{cell_tag}>" for c in cells)
    return f"<tr>{cells_html}</tr>"


def _table(headers: List[str], rows: List[List[str]]) -> str:
    if not rows:
        return '<p style="color:#8892b0;font-style:italic;padding:0.5rem 0;">Nenhum dado disponível.</p>'
    thead = _row("tr", headers, header=True)
    tbody = "\n".join(_row("tr", r) for r in rows)
    return f"""\
<div class="table-wrap">
<table><thead>{thead}</thead><tbody>{tbody}</tbody></table>
</div>"""


def _threat_bar(count: int, total: int, label: str, css_class: str) -> str:
    pct = (count / total * 100) if total > 0 else 0
    return f"""\
<div class="threat-bar">
  <div class="label">{_esc(label)}</div>
  <div class="bar"><div class="fill {_esc(css_class)}" style="width:{pct:.0f}%"></div></div>
  <div class="count">{count}</div>
</div>"""


# ──────────────────────────────────────────────────────────────
#  Renderizadores de plugin
# ──────────────────────────────────────────────────────────────


def _render_nmap(data: Dict[str, Any]) -> str:
    ports = data.get("ports") or data.get("tcp_ports") or []
    if not ports:
        return _table(["Porta", "Protocolo", "Estado", "Serviço"], [])

    rows = []
    for p in ports:
        rows.append([
            str(p.get("port", p.get("portid", "?"))),
            _esc(p.get("protocol", p.get("proto", "tcp"))),
            _esc(p.get("state", "?")),
            _esc(p.get("service", p.get("name", "?"))),
        ])
    return _table(["Porta", "Protocolo", "Estado", "Serviço"], rows)


def _render_dns(data: Dict[str, Any]) -> str:
    parts = []

    # Records
    records = data.get("records") or []
    if records:
        rows = []
        for r in records:
            rows.append([
                _esc(r.get("type", "?")),
                _esc(r.get("value", r.get("data", "?"))),
            ])
        parts.append("<h4 style='color:#e0e0e0;font-size:0.95rem;margin:0.75rem 0 0.4rem;'>Registros DNS</h4>")
        parts.append(_table(["Tipo", "Valor"], rows))

    # Subdomains
    subs = data.get("subdomains") or []
    if subs:
        items = "".join(f"<li>{_esc(s)}</li>" for s in subs)
        parts.append("<h4 style='color:#e0e0e0;font-size:0.95rem;margin:0.75rem 0 0.4rem;'>Subdomínios</h4>")
        parts.append(f"<ul class='tag-list'>{items}</ul>")
    else:
        parts.append('<p style="color:#8892b0;font-style:italic;">Nenhum subdomínio encontrado.</p>')

    return "\n".join(parts)


def _render_vt(data: Dict[str, Any]) -> str:
    stats = data.get("stats") or data.get("last_analysis_stats") or {}
    total = sum(stats.values()) or 1
    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    clean = stats.get("harmless", stats.get("clean", 0))
    undetected = stats.get("undetected", 0)

    parts = [
        "<div class='threat-bars'>",
        _threat_bar(malicious, total, "Malicioso", "malicious"),
        _threat_bar(suspicious, total, "Suspeito", "suspicious"),
        _threat_bar(clean, total, "Limpo", "clean"),
        _threat_bar(undetected, total, "Não detectado", "undetected"),
        "</div>",
    ]

    categories = data.get("categories") or {}
    if categories:
        items = "".join(f"<li>{_esc(v)}</li>" for v in categories.values())
        parts.append("<h4 style='color:#e0e0e0;font-size:0.95rem;margin:0.75rem 0 0.4rem;'>Categorias</h4>")
        parts.append(f"<ul class='tag-list'>{items}</ul>")

    return "\n".join(parts)


def _render_ssl(data: Dict[str, Any]) -> str:
    cert = data.get("certificate") or data.get("cert") or {}

    fields: List[Tuple[str, str]] = [
        ("Emissor", _esc(cert.get("issuer", cert.get("issued_by", "—")))),
        ("Sujeito", _esc(cert.get("subject", cert.get("issued_to", "—")))),
        ("Válido até", _esc(cert.get("expiry", cert.get("valid_to", "—")))),
        ("Emissor CA", _esc(cert.get("ca", cert.get("CA", "—")))),
    ]

    proto = data.get("protocol") or data.get("tls_version") or "—"
    cipher = data.get("cipher") or data.get("cipher_suite") or "—"

    grid_items = "".join(
        f'<div class="field"><strong>{k}</strong>{v}</div>' for k, v in fields
    )
    parts = [
        f'<div class="info-grid">{grid_items}</div>',
        f"<p style='margin-top:0.75rem;font-size:0.9rem;'><strong>Protocolo:</strong> {_esc(proto)} &nbsp; <strong>Cipher:</strong> {_esc(cipher)}</p>",
    ]

    weak = data.get("weak_protocols") or data.get("weak_versions") or []
    if weak:
        items = "".join(f"<li>{_esc(p)}</li>" for p in weak)
        parts.append(
            "<h4 style='color:#e94560;font-size:0.9rem;margin:0.75rem 0 0.25rem;'>"
            "Protocolos fracos</h4>"
            f"<ul class='tag-list'>{items}</ul>"
        )

    warnings = data.get("warnings") or []
    if warnings:
        for w in warnings:
            parts.append(
                f'<div style="color:#f5a623;font-size:0.88rem;margin-top:0.3rem;">⚠ {_esc(w)}</div>'
            )

    return "\n".join(parts)


def _render_headers(data: Dict[str, Any]) -> str:
    parts = []

    grade = data.get("grade") or data.get("rating") or ""
    if grade:
        grade_lower = grade.lower()[0] if grade else "?"
        cls = f"grade-badge grade-{grade_lower}" if grade_lower in "abcdef" else "grade-badge"
        parts.append(
            f'<div style="text-align:center;margin-bottom:1rem;">'
            f'<div class="{cls}">{_esc(grade.upper())}</div>'
            f"<div style='font-size:0.85rem;color:#8892b0;'>Grade</div></div>"
        )

    hdrs = data.get("headers") or data.get("response_headers") or []
    if hdrs and isinstance(hdrs, dict):
        hdrs = [{"name": k, "value": v, "status": ""} for k, v in hdrs.items()]
    if hdrs:
        rows = []
        for h in hdrs:
            rows.append([
                _esc(h.get("name", "?")),
                _esc(h.get("value", "?")),
                _esc(h.get("status", h.get("state", ""))),
            ])
        parts.append("<h4 style='color:#e0e0e0;font-size:0.95rem;margin:0 0 0.4rem;'>Cabeçalhos HTTP</h4>")
        parts.append(_table(["Nome", "Valor", "Status"], rows))

    leaked = data.get("leaked_info") or data.get("leaks") or []
    if leaked:
        items = "".join(f"<li>{_esc(i)}</li>" for i in leaked)
        parts.append(
            "<h4 style='color:#e94560;font-size:0.9rem;margin:0.75rem 0 0.25rem;'>"
            "Informações vazadas</h4>"
            f"<ul class='tag-list'>{items}</ul>"
        )

    warnings = data.get("warnings") or data.get("issues") or []
    if warnings:
        for w in warnings:
            parts.append(
                f'<div style="color:#f5a623;font-size:0.88rem;margin-top:0.3rem;">⚠ {_esc(w)}</div>'
            )

    return "\n".join(parts) if parts else '<p style="color:#8892b0;font-style:italic;">Nenhum dado disponível.</p>'


def _render_whois(data: Dict[str, Any]) -> str:
    fields: List[Tuple[str, str]] = [
        ("Domínio", _esc(data.get("domain", data.get("name", "—")))),
        ("Registrador", _esc(data.get("registrar", "—"))),
        ("Criação", _esc(data.get("creation_date", data.get("created", "—")))),
        ("Expiração", _esc(data.get("expiration_date", data.get("expires", "—")))),
        ("Última atualização", _esc(data.get("updated_date", data.get("updated", "—")))),
        ("Servidores DNS", _esc(data.get("name_servers", data.get("ns", "—")))),
        ("E-mail do registrante", _esc(data.get("emails", data.get("registrant_email", "—")))),
        ("Organização", _esc(data.get("org", data.get("organization", "—")))),
        ("País", _esc(data.get("country", "—"))),
        ("Status", _esc(data.get("status", "—"))),
    ]
    grid_items = "".join(
        f'<div class="field"><strong>{k}</strong>{v}</div>' for k, v in fields
    )
    return f'<div class="info-grid">{grid_items}</div>'


def _render_banner(data: Dict[str, Any]) -> str:
    banners = data.get("banners") or data.get("results") or []
    if not banners:
        return _table(["Porta", "Banner"], [])

    rows = []
    for b in banners:
        rows.append([
            str(b.get("port", b.get("portid", "?"))),
            _esc(b.get("banner", b.get("data", "?"))),
        ])
    return _table(["Porta", "Banner"], rows)


_PLUGIN_RENDERERS: Dict[str, Any] = {
    "nmap": _render_nmap,
    "dns": _render_dns,
    "vt": _render_vt,
    "virustotal": _render_vt,
    "ssl": _render_ssl,
    "headers": _render_headers,
    "http_headers": _render_headers,
    "whois": _render_whois,
    "banner": _render_banner,
    "banner_grab": _render_banner,
}


def _render_plugin_data(plugin_name: str, data: Dict[str, Any]) -> str:
    """Delega a renderização para o renderizador específico do plugin."""
    key = plugin_name.lower().replace(" ", "_")
    renderer = _PLUGIN_RENDERERS.get(key) or _PLUGIN_RENDERERS.get(
        key.replace("_plugin", "").replace("plugin_", "")
    )
    if renderer:
        try:
            return renderer(data)
        except Exception:
            pass
    # Fallback: renderiza como pares chave-valor
    return _render_fallback(data)


def _render_fallback(data: Dict[str, Any]) -> str:
    """Renderiza dados genéricos como pares chave-valor."""
    if not data:
        return '<p style="color:#8892b0;font-style:italic;">Nenhum dado disponível.</p>'
    rows = []
    for k, v in data.items():
        if isinstance(v, (dict, list)):
            continue  # ignora estruturas complexas no fallback
        rows.append([_esc(k), _esc(v)])
    if not rows:
        # Tenta exibir como JSON simples -
        # exibe a estrutura mais superficial
        rows = []
        for k, v in data.items():
            display = str(v)
            if isinstance(v, dict):
                display = ", ".join(f"{kk}: {vv}" for kk, vv in list(v.items())[:5])
                if len(v) > 5:
                    display += " …"
            elif isinstance(v, list):
                display = ", ".join(str(i) for i in v[:5])
                if len(v) > 5:
                    display += " …"
            rows.append([_esc(k), _esc(display)])
        if not rows:
            return '<p style="color:#8892b0;font-style:italic;">Nenhum dado disponível.</p>'
    return _table(["Campo", "Valor"], rows)


# ──────────────────────────────────────────────────────────────
#  Montagem das seções
# ──────────────────────────────────────────────────────────────


def _build_header(report: ScanReport) -> str:
    duration = ""
    if report.started_at and report.finished_at:
        diff = (report.finished_at - report.started_at).total_seconds()
        duration = _fmt_duration(diff)

    return f"""\
<div class="header">
  <h1>MapSec Security Report</h1>
  <div class="target">{_esc(report.target)}</div>
  <div class="meta">
    <span class="meta-item">📅 <strong>Início:</strong> {_fmt_dt(report.started_at)}</span>
    <span class="meta-item">⏱️ <strong>Duração:</strong> {duration}</span>
    <span class="meta-item">📦 <strong>Plugins:</strong> {len(report.results)}</span>
  </div>
</div>"""


def _build_executive_summary(
    analysis: AnalysisReport | None, report: ScanReport
) -> str:
    if not analysis:
        # Sem análise — mostra apenas metadados do scan
        success_count = sum(1 for r in report.results if r.success)
        total = len(report.results) or 1
        pct = int(success_count / total * 100)
        score = pct
        summary = (
            f"Scan concluído com {success_count} de {total} plugins executados com "
            f"sucesso."
        )
    else:
        score = analysis.score
        summary = analysis.summary or ""

    # Gauge SVG
    radius = 54
    circumference = 2 * 3.14159265 * radius
    offset = circumference - (score / 100 * circumference)

    # Cor do gauge baseada no score
    if score >= 80:
        gauge_color = COLOR_SUCCESS
    elif score >= 60:
        gauge_color = COLOR_WARNING
    elif score >= 40:
        gauge_color = "#ff9800"
    else:
        gauge_color = COLOR_CRITICAL

    return f"""\
<div class="card">
  <h2>📊 Executive Summary</h2>
  <div class="gauge-wrapper">
    <div class="gauge">
      <svg width="140" height="140" viewBox="0 0 140 140">
        <circle class="gauge-bg" cx="70" cy="70" r="{radius}" />
        <circle class="gauge-fill" cx="70" cy="70" r="{radius}"
          stroke="{gauge_color}"
          stroke-dasharray="{circumference}"
          stroke-dashoffset="{offset}" />
      </svg>
      <div class="gauge-text">{score}<small>/100</small></div>
    </div>
    <div class="summary-text">{_esc(summary) if summary else "Nenhuma análise disponível."}</div>
  </div>
</div>"""


def _build_findings(analysis: AnalysisReport) -> str:
    if not analysis.findings:
        return ""

    # Agrupa por severidade
    groups: Dict[str, List[Finding]] = {}
    for f in analysis.findings:
        sev = (f.severity or "info").lower()
        groups.setdefault(sev, []).append(f)

    sections = []
    for sev in sorted(groups, key=lambda s: SEVERITY_ORDER.get(s, 99)):
        findings = groups[sev]
        label = _sev_label(sev)
        badge_class = f"badge badge-{sev}"
        color = SEVERITY_COLORS.get(sev, COLOR_INFO)

        items_html = []
        for f in findings:
            rec_html = ""
            if f.recommendation:
                rec_html = f'<div class="recommendation"><strong>Recomendação:</strong> {_esc(f.recommendation)}</div>'

            source_html = ""
            if f.source_plugins:
                source_html = (
                    f'<div class="source"><strong>Plugins:</strong> '
                    f'{", ".join(_esc(s) for s in f.source_plugins)}</div>'
                )

            items_html.append(f"""\
<div class="finding severity-{sev}">
  <div class="finding-header">
    <h3>{_esc(f.title)}</h3>
    <span class="{badge_class}">{label}</span>
  </div>
  <p>{_esc(f.description)}</p>
  {rec_html}
  {source_html}
</div>""")

        sections.append(f"""\
<div style="margin-bottom:1.5rem;">
  <h3 style="color:{color};font-size:1.05rem;margin-bottom:0.75rem;display:flex;align-items:center;gap:0.5rem;">
    <span>{label}</span>
    <span class="{badge_class}" style="font-size:0.7rem;">{len(findings)}</span>
  </h3>
  {"".join(items_html)}
</div>""")

    return f"""\
<div class="card">
  <h2 class="collapsible">🔍 Findings ({len(analysis.findings)})</h2>
  <div class="collapsible-content">
  {"".join(sections)}
  </div>
</div>"""


def _build_plugin_results(report: ScanReport) -> str:
    if not report.results:
        return ""

    cards = []
    for pr in report.results:
        name = _esc(pr.plugin)
        dur = ""
        if pr.duration_seconds is not None:
            dur = f' &middot; <strong>Duração:</strong> {_fmt_duration(pr.duration_seconds)}'

        status_icon = "✅" if pr.success else "❌"
        error_html = ""
        if pr.error:
            error_html = f'<div class="error-msg">❌ {_esc(pr.error)}</div>'

        data_section = ""
        if pr.success and pr.data:
            data_section = _render_plugin_data(pr.plugin, pr.data)
        elif not pr.success:
            data_section = ""

        alt = data_section or '<p style="color:#8892b0;font-style:italic;padding:0.5rem 0;">Nenhum dado retornado.</p>'

        cards.append(f"""\
<div class="plugin-card">
  <h3 class="collapsible">
    <span class="success">{status_icon}</span>
    {name}
  </h3>
  <div class="collapsible-content">
  <div class="plugin-meta">
    <strong>Alvo:</strong> {_esc(pr.target)}{dur}
  </div>
  {error_html}
  {alt}
  </div>
</div>""")

    return f"""\
<div class="card">
  <h2 class="collapsible">🔬 Plugin Results ({len(report.results)})</h2>
  <div class="collapsible-content">
  {"".join(cards)}
  </div>
</div>"""


def _build_footer() -> str:
    now = datetime.now(timezone.utc).strftime("%d/%m/%Y %H:%M:%S UTC")
    return f"""\
<div class="footer">
  <p>Generated by <strong>Mapsec</strong> &mdash; {now}</p>
</div>"""


# ──────────────────────────────────────────────────────────────
#  Função pública principal
# ──────────────────────────────────────────────────────────────


def write_html(
    report: ScanReport,
    output_path: str | Path,
    analysis: AnalysisReport | None = None,
) -> Path:
    """Gera um relatório HTML autossuficiente para um ``ScanReport``.

    Args:
        report:   Relatório de scan a ser exibido.
        output_path: Caminho (diretório ou arquivo) onde o HTML será salvo.
        analysis: Relatório de análise opcional (findings + score).

    Returns:
        ``Path`` absoluto para o arquivo HTML gerado.

    Raises:
        OSError: Se o diretório de saída não puder ser criado ou o
            arquivo não puder ser escrito.
    """
    output = Path(output_path)

    # Se for diretório, cria nome de arquivo baseado no target
    if output.suffix.lower() not in (".html", ".htm"):
        output.mkdir(parents=True, exist_ok=True)
        safe_name = "".join(c if c.isalnum() or c in "-_." else "_" for c in report.target)
        output = output / f"mapsec_report_{safe_name}.html"
    else:
        # Garante que o diretório pai existe
        output.parent.mkdir(parents=True, exist_ok=True)

    css = _get_css()
    header = _build_header(report)
    summary = _build_executive_summary(analysis, report)
    findings = _build_findings(analysis) if analysis else ""
    plugins = _build_plugin_results(report)
    footer = _build_footer()

    html_content = f"""\
<!DOCTYPE html>
<html lang="pt-BR">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>MapSec Security Report — {_esc(report.target)}</title>
<style>
{css}
</style>
</head>
<body>
<div class="container">
{header}
{summary}
{findings}
{plugins}
{footer}
</div>
<script>
document.querySelectorAll('.collapsible').forEach(function(el) {{
  el.addEventListener('click', function() {{
    this.classList.toggle('open');
    var content = this.nextElementSibling;
    if (content && content.classList.contains('collapsible-content')) {{
      content.classList.toggle('open');
    }}
  }});
}});
</script>
</body>
</html>"""

    output.write_text(html_content, encoding="utf-8")
    return output.resolve()
