"""Tests for export modules: HTML, PDF."""

import os
import tempfile
from pathlib import Path
from datetime import datetime

import pytest

from mapsec.core.models import ScanReport, PluginResult
from mapsec.analysis.models import AnalysisReport, Finding
from mapsec.output.html_report import write_html
from mapsec.output.pdf_export import write_pdf


# ═══════════════════════════════════════════════════════════════
# Test data factories
# ═══════════════════════════════════════════════════════════════

_SAMPLE_DATA = {
    "nmap": {
        "ports": [
            {"port": 22, "protocol": "tcp", "state": "open", "service": "ssh"},
            {"port": 80, "protocol": "tcp", "state": "open", "service": "http"},
        ],
        "hostname": "test-host",
    },
    "dns": {
        "records": [
            {"type": "A", "value": "192.168.1.1"},
            {"type": "MX", "value": "mail.example.com"},
        ],
        "subdomains": ["www", "mail"],
    },
    "vt": {
        "malicious": 2,
        "suspicious": 1,
        "undetected": 90,
        "categories": {"category1": "malware"},
    },
    "ssl": {
        "certificate": {
            "issuer": "Let's Encrypt",
            "subject": "example.com",
            "not_after": "2027-01-01",
        },
        "protocol": "TLSv1.3",
        "cipher": "AES-256-GCM",
        "warnings": [],
    },
    "headers": {
        "grade": "B",
        "present": ["X-Content-Type-Options"],
        "missing": ["Content-Security-Policy"],
        "warnings": ["Server header leaked"],
    },
    "whois": {
        "registrar": "GoDaddy",
        "creation_date": "2020-01-01",
        "expiration_date": "2025-01-01",
    },
    "banner": {
        "ports": [
            {"port": 22, "banner": "SSH-2.0-OpenSSH_8.9"},
            {"port": 80, "banner": "Apache/2.4.52"},
        ]
    },
}


def _make_report(target="192.168.1.1", plugins=None):
    """Create a ScanReport with sample plugin results."""
    report = ScanReport(target=target, started_at=datetime(2026, 1, 15, 10, 0, 0))
    report.finished_at = datetime(2026, 1, 15, 10, 5, 30)
    for name in plugins or ["nmap", "dns"]:
        data = _SAMPLE_DATA.get(name, {})
        report.add_result(
            PluginResult(plugin=name, target=target, data=data, success=True, duration_seconds=1.5)
        )
    return report


def _make_analysis(target="192.168.1.1"):
    """Create an AnalysisReport with sample findings."""
    return AnalysisReport(
        findings=[
            Finding(
                severity="critical",
                title="Expired cert",
                description="Certificate expired",
                recommendation="Renew",
                source_plugins=["ssl"],
            ),
            Finding(
                severity="high",
                title="No HSTS",
                description="Missing HSTS header",
                recommendation="Add HSTS",
                source_plugins=["headers"],
            ),
            Finding(
                severity="medium",
                title="Server leak",
                description="Server header exposed",
                recommendation="Remove header",
                source_plugins=["headers"],
            ),
            Finding(
                severity="low",
                title="Info disclosure",
                description="X-Powered-By exposed",
                recommendation="Remove",
                source_plugins=["headers"],
            ),
            Finding(
                severity="info",
                title="Open ports",
                description="Several ports open",
                recommendation="Review",
                source_plugins=["nmap"],
            ),
        ],
        score=45,
        summary="Critical issues found.",
        target=target,
        plugins_used=["nmap", "dns", "ssl", "headers"],
    )


# ═══════════════════════════════════════════════════════════════
# HTML Report Tests
# ═══════════════════════════════════════════════════════════════


class TestHtmlReport:
    def test_html_creates_file(self, tmp_path):
        """write_html creates a valid file at the path."""
        report = _make_report()
        output = tmp_path / "report.html"
        result = write_html(report, output)
        assert result.exists()
        assert result.is_file()
        assert result.suffix == ".html"

    def test_html_returns_path(self, tmp_path):
        """Return value is a Path object."""
        report = _make_report()
        output = tmp_path / "report.html"
        result = write_html(report, output)
        assert isinstance(result, Path)

    def test_html_contains_title(self, tmp_path):
        """Output contains 'MapSec' in the HTML."""
        report = _make_report()
        output = tmp_path / "report.html"
        write_html(report, output)
        content = output.read_text(encoding="utf-8")
        assert "MapSec" in content

    def test_html_contains_target(self, tmp_path):
        """Output contains the scan target."""
        report = _make_report(target="10.0.0.1")
        output = tmp_path / "report.html"
        write_html(report, output)
        content = output.read_text(encoding="utf-8")
        assert "10.0.0.1" in content

    def test_html_without_analysis(self, tmp_path):
        """Works with analysis=None (no findings section)."""
        report = _make_report()
        output = tmp_path / "report.html"
        write_html(report, output, analysis=None)
        content = output.read_text(encoding="utf-8")
        # Should not contain the Findings header
        assert "Findings" not in content
        # Should still contain plugin results
        assert "Plugin Results" in content

    def test_html_with_analysis(self, tmp_path):
        """Includes findings when analysis is provided."""
        report = _make_report()
        analysis = _make_analysis()
        output = tmp_path / "report.html"
        write_html(report, output, analysis=analysis)
        content = output.read_text(encoding="utf-8")
        assert "Findings" in content
        assert "Executive Summary" in content
        assert "Critical issues found" in content

    def test_html_with_findings_by_severity(self, tmp_path):
        """All severity levels appear in output."""
        report = _make_report()
        analysis = _make_analysis()
        output = tmp_path / "report.html"
        write_html(report, output, analysis=analysis)
        content = output.read_text(encoding="utf-8")
        for sev in ("critical", "high", "medium", "low", "info"):
            assert sev in content.lower()

    def test_html_plugin_nmap_results(self, tmp_path):
        """nmap port data appears in HTML."""
        report = _make_report(plugins=["nmap"])
        output = tmp_path / "report.html"
        write_html(report, output)
        content = output.read_text(encoding="utf-8")
        assert "22" in content
        assert "ssh" in content.lower()
        assert "80" in content
        assert "http" in content.lower()

    def test_html_plugin_dns_results(self, tmp_path):
        """DNS records appear in HTML."""
        report = _make_report(plugins=["dns"])
        output = tmp_path / "report.html"
        write_html(report, output)
        content = output.read_text(encoding="utf-8")
        assert "192.168.1.1" in content
        assert "MX" in content
        assert "www" in content
        assert "mail" in content

    def test_html_escapes_html(self, tmp_path):
        """Malicious HTML in data is escaped (e.g. <script> becomes &lt;script&gt;)."""
        report = _make_report()
        # Add a result with malicious data
        malicious_data = {"xss": '<script>alert("xss")</script>'}
        report.add_result(
            PluginResult(
                plugin="test_xss",
                target="xss.test",
                data=malicious_data,
                success=True,
                duration_seconds=0.1,
            )
        )
        output = tmp_path / "report.html"
        write_html(report, output)
        content = output.read_text(encoding="utf-8")
        # The malicious <script> from data should be escaped; our own collapsible JS <script> is allowed
        assert 'alert("xss")' not in content  # XSS payload not rendered raw
        assert "&lt;script&gt;" in content  # escaped version present

    def test_html_with_directory_output(self, tmp_path):
        """When output_path is a directory, write_html creates a file inside it."""
        report = _make_report(target="target-host")
        # Pass a directory path (no .html suffix)
        result = write_html(report, tmp_path)
        assert result.exists()
        assert result.is_file()
        assert result.suffix == ".html"
        assert "target-host" in result.name

    def test_html_multiple_plugins(self, tmp_path):
        """All plugins appear in the rendered HTML."""
        report = _make_report(plugins=["nmap", "dns", "ssl"])
        output = tmp_path / "report.html"
        write_html(report, output)
        content = output.read_text(encoding="utf-8")
        for plugin in ("nmap", "dns", "ssl"):
            assert plugin in content.lower()


# ═══════════════════════════════════════════════════════════════
# PDF Report Tests
# ═══════════════════════════════════════════════════════════════


class TestPdfReport:
    def test_pdf_creates_file(self, tmp_path):
        """write_pdf creates a valid file."""
        report = _make_report()
        output = tmp_path / "report.pdf"
        result = write_pdf(report, output)
        assert result.exists()
        assert result.is_file()

    def test_pdf_returns_path(self, tmp_path):
        """Return value is a Path."""
        report = _make_report()
        output = tmp_path / "report.pdf"
        result = write_pdf(report, output)
        assert isinstance(result, Path)

    def test_pdf_file_size(self, tmp_path):
        """Generated PDF is > 1KB (not empty/corrupt)."""
        report = _make_report()
        output = tmp_path / "report.pdf"
        write_pdf(report, output)
        size = output.stat().st_size
        assert size > 1024, f"PDF file too small: {size} bytes"

    def test_pdf_without_analysis(self, tmp_path):
        """Works with analysis=None."""
        report = _make_report()
        output = tmp_path / "report.pdf"
        write_pdf(report, output, analysis=None)
        assert output.exists()
        assert output.stat().st_size > 1024

    def test_pdf_with_analysis(self, tmp_path):
        """Includes findings when analysis provided."""
        report = _make_report()
        analysis = _make_analysis()
        output = tmp_path / "report.pdf"
        write_pdf(report, output, analysis=analysis)
        assert output.exists()
        # With analysis the PDF should be larger (more content)
        assert output.stat().st_size > 1024

    def test_pdf_with_multiple_plugins(self, tmp_path):
        """Handles multiple plugin results."""
        report = _make_report(plugins=["nmap", "dns", "ssl", "headers", "whois", "banner"])
        output = tmp_path / "report.pdf"
        write_pdf(report, output)
        assert output.exists()
        assert output.stat().st_size > 2048

    def test_pdf_invalid_path(self, tmp_path):
        """Raises exception for invalid path (parent is a file, not a directory)."""
        report = _make_report()
        # Create a file to block directory creation
        block_file = tmp_path / "not_a_dir"
        block_file.write_text("i am a file, not a folder")
        bad_path = block_file / "report.pdf"
        with pytest.raises((OSError, NotADirectoryError, FileNotFoundError)):
            write_pdf(report, bad_path)


# ═══════════════════════════════════════════════════════════════
# CSV Export Tests
# ═══════════════════════════════════════════════════════════════

