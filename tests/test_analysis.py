"""Tests for mapsec.analysis module."""
import datetime
import json
import pytest
from unittest.mock import patch, MagicMock

from mapsec.analysis.models import Finding, AnalysisReport
from mapsec.analysis.rules import run_rules, ALL_RULES
from mapsec.analysis.engine import AnalysisEngine
from mapsec.analysis.llm_providers import (
    get_provider,
    ClaudeProvider,
    GeminiProvider,
    OpenAIProvider,
)


# ═══════════════════════════════════════════════════
# Helpers
# ═══════════════════════════════════════════════════

def _finding(severity: str) -> Finding:
    """Quick helper to build a finding with minimal fields."""
    return Finding(
        severity=severity,
        title="dummy",
        description="dummy description",
        recommendation="dummy rec",
        source_plugins=["test"],
    )


# ═══════════════════════════════════════════════════
# Models
# ═══════════════════════════════════════════════════

class TestFinding:
    def test_finding_creation(self):
        """Finding can be created with required fields."""
        f = Finding(
            severity="high",
            title="Test finding",
            description="A description",
            recommendation="Fix it",
            source_plugins=["nmap"],
        )
        assert f.severity == "high"
        assert f.title == "Test finding"
        assert f.description == "A description"
        assert f.recommendation == "Fix it"
        assert f.source_plugins == ["nmap"]

    def test_finding_defaults(self):
        """Finding has correct defaults (no optional fields — all required)."""
        f = Finding(
            severity="info",
            title="Info item",
            description="desc",
            recommendation="rec",
            source_plugins=[],
        )
        assert f.severity == "info"
        assert f.source_plugins == []


class TestAnalysisReport:
    def test_report_creation(self):
        """AnalysisReport can be created."""
        report = AnalysisReport(
            findings=[],
            score=100,
            summary="No issues",
            target="example.com",
            plugins_used=["nmap"],
        )
        assert report.score == 100
        assert report.target == "example.com"
        assert report.llm_analysis is None

    def test_report_with_llm(self):
        """AnalysisReport accepts optional llm_analysis."""
        report = AnalysisReport(
            findings=[],
            score=85,
            summary="Minor issues",
            target="example.com",
            plugins_used=["ssl"],
            llm_analysis="Raw LLM text here",
        )
        assert report.llm_analysis == "Raw LLM text here"
        assert report.score == 85


# ═══════════════════════════════════════════════════
# Rules Engine
# ═══════════════════════════════════════════════════

class TestRules:
    def test_all_rules_list_not_empty(self):
        """ALL_RULES contains rule functions."""
        assert len(ALL_RULES) >= 15
        names = [r.__name__ for r in ALL_RULES]
        assert "check_certificate_expired" in names
        assert "check_certificate_self_signed" in names
        assert "check_weak_tls" in names
        assert "check_hsts_missing" in names
        assert "check_csp_weak" in names
        assert "check_server_header_leak" in names
        assert "check_dangerous_ports" in names
        assert "check_vt_malicious" in names
        assert "check_vt_suspicious" in names
        assert "check_dns_subdomains" in names
        assert "check_banner_information_disclosure" in names
        assert "check_whois_expiring" in names
        assert "check_weak_ciphers" in names
        assert "check_missing_headers" in names
        assert "check_no_plugins_ran" in names

    def test_run_rules_with_empty_results(self):
        """Rules handle empty results dict gracefully."""
        findings = run_rules({})
        # Empty results -> check_no_plugins_ran fires with severity info
        assert len(findings) >= 1
        assert any(f.title == "No scan results to analyse" for f in findings)

    def test_check_certificate_expired(self):
        """Detects expired SSL certificate."""
        results = {
            "ssl": {
                "certificate": {"is_expired": True, "subject": "CN=example.com"}
            }
        }
        findings = run_rules(results)
        expired = [f for f in findings if "expired" in f.title.lower()]
        assert len(expired) == 1
        assert expired[0].severity == "critical"

    def test_check_certificate_self_signed(self):
        """Detects self-signed certificate."""
        results = {
            "ssl": {
                "certificate": {"is_self_signed": True, "subject": "CN=example.com"}
            }
        }
        findings = run_rules(results)
        self_signed = [f for f in findings if "self-signed" in f.title.lower()]
        assert len(self_signed) == 1
        assert self_signed[0].severity == "high"

    def test_check_weak_tls(self):
        """Detects TLS 1.0/1.1 in weak_protocols."""
        results = {
            "ssl": {
                "protocol": {
                    "weak_protocols": ["TLSv1.0", "TLSv1.1"],
                }
            }
        }
        findings = run_rules(results)
        weak_tls = [f for f in findings if "weak tls" in f.title.lower()]
        assert len(weak_tls) == 1, f"Expected weak TLS finding, got: {[f.title for f in findings]}"
        assert weak_tls[0].severity == "high"

    def test_check_hsts_missing(self):
        """Detects missing HSTS header."""
        results = {
            "headers": {
                "headers": {
                    "Strict-Transport-Security": {"present": False},
                }
            }
        }
        findings = run_rules(results)
        hsts = [f for f in findings if "HSTS" in f.title or "Strict-Transport-Security" in f.title]
        assert len(hsts) == 1
        assert hsts[0].severity == "medium"

    def test_check_csp_weak(self):
        """Detects unsafe-inline in CSP."""
        results = {
            "headers": {
                "headers": {
                    "Content-Security-Policy": {
                        "present": True,
                        "value": "default-src 'unsafe-inline'",
                    },
                }
            }
        }
        findings = run_rules(results)
        csp = [f for f in findings if "CSP" in f.title or "Content Security Policy" in f.title]
        assert len(csp) == 1
        assert csp[0].severity == "medium"

    def test_check_server_leak(self):
        """Detects Server header leak."""
        results = {
            "headers": {
                "leaked_headers": {
                    "Server": "nginx/1.18.0",
                    "X-Powered-By": "PHP/7.4",
                }
            }
        }
        findings = run_rules(results)
        leak = [f for f in findings if "Server" in f.title or "leak" in f.title.lower()]
        assert len(leak) == 1
        assert leak[0].severity == "low"

    def test_check_dangerous_ports(self):
        """Detects dangerous ports (21, 23, 3389)."""
        results = {
            "nmap": {
                "hosts": [
                    {
                        "ip": "10.0.0.1",
                        "ports": [
                            {"port": 21, "state": "open", "service": "ftp"},
                            {"port": 80, "state": "open", "service": "http"},
                            {"port": 3389, "state": "open", "service": "ms-wbt-server"},
                        ],
                    }
                ]
            }
        }
        findings = run_rules(results)
        dangerous = [f for f in findings if "dangerous" in f.title.lower()]
        assert len(dangerous) == 1
        assert dangerous[0].severity == "high"

    def test_check_vt_malicious(self):
        """Detects VT malicious > 0."""
        results = {"vt": {"malicious": 3, "suspicious": 1, "total": 80}}
        findings = run_rules(results)
        malicious = [f for f in findings if "malicious" in f.title.lower()]
        assert len(malicious) == 1
        assert malicious[0].severity == "critical"

    def test_check_vt_suspicious(self):
        """Detects VT suspicious > 0."""
        results = {"vt": {"malicious": 0, "suspicious": 5, "total": 80}}
        findings = run_rules(results)
        suspicious = [f for f in findings if "suspicious" in f.title.lower()]
        assert len(suspicious) == 1
        assert suspicious[0].severity == "medium"

    def test_check_dns_subdomains(self):
        """Detects subdomains found."""
        results = {
            "dns": {
                "total_subdomains": 3,
                "subdomains": [
                    {"subdomain": "www"},
                    {"subdomain": "mail"},
                    {"subdomain": "api"},
                ],
            }
        }
        findings = run_rules(results)
        sub = [f for f in findings if "subdomain" in f.title.lower()]
        assert len(sub) == 1
        assert sub[0].severity == "info"

    def test_check_banner_disclosure(self):
        """Detects version info in banners."""
        results = {
            "banner": {
                "banners": [
                    {"port": 22, "banner": "SSH-2.0-OpenSSH_8.9p1 Ubuntu"},
                    {"port": 80, "banner": "Apache httpd"},
                ]
            }
        }
        findings = run_rules(results)
        banner = [f for f in findings if "banner" in f.title.lower()]
        assert len(banner) == 1
        assert banner[0].severity == "low"

    def test_check_whois_expiring(self):
        """Detects domain expiring within 90 days."""
        # Use a date ~30 days from now
        future = datetime.datetime.now() + datetime.timedelta(days=30)
        results = {"whois": {"expiration_date": future.strftime("%Y-%m-%d")}}
        findings = run_rules(results)
        expiring = [f for f in findings if "expiring" in f.title.lower()]
        assert len(expiring) == 1
        assert expiring[0].severity == "medium"

    def test_check_whois_already_expired(self):
        """Detects domain already expired."""
        results = {"whois": {"expiration_date": "2020-01-01"}}
        findings = run_rules(results)
        expired = [f for f in findings if "expired" in f.title.lower()]
        assert len(expired) == 1
        assert expired[0].severity == "high"

    def test_check_weak_ciphers(self):
        """Detects weak ciphers."""
        results = {
            "ssl": {
                "cipher": {
                    "name": "RC4-SHA",
                    "is_weak": True,
                }
            }
        }
        findings = run_rules(results)
        weak_ciphers = [f for f in findings if "weak cipher" in f.title.lower()]
        assert len(weak_ciphers) == 1
        assert weak_ciphers[0].severity == "high"

    def test_check_missing_critical_headers(self):
        """Detects missing X-Frame-Options and X-Content-Type-Options."""
        results = {
            "headers": {
                "headers": {
                    "X-Frame-Options": {"present": False},
                    "X-Content-Type-Options": {"present": False},
                    "Strict-Transport-Security": {"present": True, "value": "max-age=31536000"},
                }
            }
        }
        findings = run_rules(results)
        missing = [f for f in findings if "missing" in f.title.lower()]
        assert len(missing) >= 1, f"Expected missing header findings, got: {[f.title for f in findings]}"
        # Check description mentions the specific header names
        descs = " ".join(f.description for f in missing)
        assert "X-Frame-Options" in descs or "X-Content-Type-Options" in descs

    def test_rules_handle_missing_plugin_data(self):
        """Rules don't crash when plugin data is missing."""
        findings = run_rules({"ssl": {}, "headers": {}, "nmap": {}, "vt": {}, "dns": {}, "banner": {}, "whois": {}})
        # Should not crash; may return some findings but at least no exceptions
        assert isinstance(findings, list)

    def test_run_rules_multiple_findings(self):
        """Multiple rules can fire on same results."""
        results = {
            "ssl": {
                "certificate": {"is_expired": True, "is_self_signed": True},
                "protocol": {"weak_protocols": ["TLSv1.0"]},
                "cipher": {"name": "DES-CBC3-SHA", "is_weak": True},
            },
            "headers": {
                "headers": {
                    "Strict-Transport-Security": {"present": False},
                    "Content-Security-Policy": {
                        "present": True,
                        "value": "default-src 'unsafe-inline'",
                    },
                    "X-Frame-Options": {"present": False},
                    "X-Content-Type-Options": {"present": False},
                },
                "leaked_headers": {"Server": "nginx/1.18"},
            },
            "nmap": {
                "hosts": [
                    {
                        "ip": "10.0.0.1",
                        "ports": [
                            {"port": 21, "state": "open", "service": "ftp"},
                            {"port": 443, "state": "open", "service": "https"},
                        ],
                    }
                ]
            },
            "vt": {"malicious": 2, "suspicious": 1},
        }
        findings = run_rules(results)
        # Should have at least 6 distinct findings
        assert len(findings) >= 6
        severities = {f.severity for f in findings}
        assert "critical" in severities
        assert "high" in severities
        assert "medium" in severities
        assert "low" in severities


# ═══════════════════════════════════════════════════
# Analysis Engine
# ═══════════════════════════════════════════════════

class TestAnalysisEngine:
    def test_engine_default_state(self):
        """Engine starts without LLM configured."""
        engine = AnalysisEngine()
        assert engine._provider is None

    def test_engine_analyze_without_llm(self, monkeypatch):
        """Engine runs rules-only analysis."""
        engine = AnalysisEngine()
        # Mock run_rules to return predictable findings
        findings_in = [
            _finding("medium"),
            _finding("low"),
        ]

        import mapsec.analysis.engine as engine_mod
        original_run_rules = engine_mod.run_rules

        def mock_run_rules(results):
            return findings_in

        monkeypatch.setattr(engine_mod, "run_rules", mock_run_rules)

        report = engine.analyze(
            results={"ssl": {"certificate": {"is_expired": True}}},
            target="example.com",
            plugins_used=["ssl"],
        )

        assert isinstance(report, AnalysisReport)
        assert len(report.findings) == 2
        assert 0 <= report.score <= 100
        assert report.summary != ""
        assert report.target == "example.com"
        assert report.llm_analysis is None

    def test_engine_score_calculation(self):
        """Score decreases with severity of findings."""
        engine = AnalysisEngine()

        # No findings -> 100
        score0 = engine._calculate_score([])
        assert score0 == 100

        # 1 critical -> 75
        score1 = engine._calculate_score([_finding("critical")])
        assert score1 == 75

        # 1 critical + 1 high -> 60
        score2 = engine._calculate_score([_finding("critical"), _finding("high")])
        assert score2 == 60

        # 5 criticals -> 0 (clamped)
        score3 = engine._calculate_score([_finding("critical") for _ in range(5)])
        assert score3 == 0

        # Mix
        score4 = engine._calculate_score([_finding("high"), _finding("medium"), _finding("low")])
        assert score4 == 100 - 15 - 8 - 3  # = 74

        # Info has no penalty
        score5 = engine._calculate_score([_finding("info"), _finding("info")])
        assert score5 == 100

    def test_engine_configure_llm(self):
        """Engine accepts LLM configuration."""
        engine = AnalysisEngine()
        engine.configure_llm("openai", "sk-test-key", "gpt-4o")
        assert engine._provider is not None
        assert isinstance(engine._provider, OpenAIProvider)
        assert engine._provider.api_key == "sk-test-key"
        assert engine._provider.model == "gpt-4o"

    def test_engine_configure_llm_disabled(self):
        """Engine LLM is disabled when called with empty args."""
        engine = AnalysisEngine()
        engine.configure_llm("", "")
        assert engine._provider is None

        engine.configure_llm(None, None)
        assert engine._provider is None

    def test_engine_analyze_with_llm_success(self, monkeypatch):
        """Engine merges LLM findings with rule findings."""
        import mapsec.analysis.engine as engine_mod

        # Mock rule findings
        rule_findings = [_finding("medium")]

        def mock_run_rules(results):
            return rule_findings

        monkeypatch.setattr(engine_mod, "run_rules", mock_run_rules)

        # Mock LLM provider
        llm_json = json.dumps({
            "findings": [
                {
                    "severity": "high",
                    "title": "LLM finding",
                    "description": "Found by LLM",
                    "recommendation": "Fix it",
                }
            ],
            "summary": "LLM summary here",
        })

        engine = AnalysisEngine()
        engine._provider = MagicMock()
        engine._provider.analyze.return_value = llm_json

        report = engine.analyze(
            results={"ssl": {"certificate": {"is_expired": True}}},
            target="example.com",
            plugins_used=["ssl"],
        )

        # Should contain both rule finding and LLM finding
        assert len(report.findings) == 2
        assert report.llm_analysis == llm_json
        titles = [f.title for f in report.findings]
        assert "LLM finding" in titles
        assert "dummy" in titles

    def test_engine_analyze_with_llm_failure(self, monkeypatch):
        """Engine continues if LLM fails."""
        import mapsec.analysis.engine as engine_mod

        rule_findings = [_finding("medium")]

        def mock_run_rules(results):
            return rule_findings

        monkeypatch.setattr(engine_mod, "run_rules", mock_run_rules)

        engine = AnalysisEngine()
        engine._provider = MagicMock()
        engine._provider.analyze.side_effect = RuntimeError("API failure")

        report = engine.analyze(
            results={"ssl": {"certificate": {"is_expired": True}}},
            target="example.com",
            plugins_used=["ssl"],
        )

        # Rule findings still present, LLM analysis is None
        assert len(report.findings) == 1
        assert report.llm_analysis is None

    def test_engine_analyze_empty_results(self, monkeypatch):
        """Engine handles empty results gracefully."""
        import mapsec.analysis.engine as engine_mod

        def mock_run_rules(results):
            return []

        monkeypatch.setattr(engine_mod, "run_rules", mock_run_rules)

        engine = AnalysisEngine()
        report = engine.analyze(results={}, target="example.com", plugins_used=[])
        assert isinstance(report, AnalysisReport)
        assert report.score == 100
        assert len(report.findings) == 0
        assert "No security issues" in report.summary

    def test_engine_score_minimum_zero(self):
        """Score never goes below 0."""
        engine = AnalysisEngine()
        many_criticals = [_finding("critical") for _ in range(10)]
        score = engine._calculate_score(many_criticals)
        assert score == 0

    def test_engine_generate_summary_various_cases(self):
        """_generate_summary produces correct text for different finding sets."""
        engine = AnalysisEngine()
        # No findings
        s0 = engine._generate_summary([], 100)
        assert "No security issues" in s0

        # Critical findings
        s1 = engine._generate_summary([_finding("critical")], 75)
        assert "critical" in s1
        assert "immediate action" in s1

        # High findings
        s2 = engine._generate_summary([_finding("high"), _finding("high")], 70)
        assert "high risk" in s2

        # Medium
        s3 = engine._generate_summary([_finding("medium")], 92)
        assert "moderate risk" in s3

        # Low
        s4 = engine._generate_summary([_finding("low")], 97)
        assert "low risk" in s4

        # Info only
        s5 = engine._generate_summary([_finding("info")], 100)
        assert "informational" in s5

    def test_engine_parse_llm_findings(self):
        """_parse_llm_findings correctly parses valid JSON."""
        engine = AnalysisEngine()
        llm_output = json.dumps({
            "findings": [
                {
                    "severity": "high",
                    "title": "Test LLM finding",
                    "description": "Some description",
                    "recommendation": "Some recommendation",
                }
            ],
            "summary": "Overall summary",
        })
        findings = engine._parse_llm_findings(llm_output)
        assert len(findings) == 1
        assert findings[0].severity == "high"
        assert findings[0].title == "Test LLM finding"
        assert findings[0].source_plugins == ["llm"]

    def test_engine_parse_llm_findings_malformed(self):
        """_parse_llm_findings returns empty list on malformed JSON."""
        engine = AnalysisEngine()
        assert engine._parse_llm_findings("") == []
        assert engine._parse_llm_findings("not json") == []
        assert engine._parse_llm_findings("{}") == []  # missing findings key

    def test_engine_parse_llm_findings_markdown_fence(self):
        """_parse_llm_findings handles markdown code fences."""
        engine = AnalysisEngine()
        llm_output = """Here is the analysis:
```json
{
  "findings": [
    {
      "severity": "medium",
      "title": "Fenced finding",
      "description": "In markdown fence",
      "recommendation": "Remove fence"
    }
  ],
  "summary": "Done"
}
```
"""
        findings = engine._parse_llm_findings(llm_output)
        assert len(findings) == 1
        assert findings[0].title == "Fenced finding"

    def test_engine_parse_llm_findings_invalid_items_skipped(self):
        """_parse_llm_findings skips invalid items gracefully."""
        engine = AnalysisEngine()
        llm_output = json.dumps({
            "findings": [
                {"severity": "high", "title": "Good", "description": "desc", "recommendation": "rec"},
                {"severity": "medium"},  # missing required fields
                "not a dict",
            ]
        })
        findings = engine._parse_llm_findings(llm_output)
        # Pydantic constructs Finding from partial data with empty-string defaults;
        # the valid item passes, and the partial one also results in a Finding with empty title.
        # The `"not a dict"` string is skipped.
        assert len(findings) == 2, f"Expected 2 findings, got {len(findings)}: {findings}"
        assert findings[0].title == "Good"


# ═══════════════════════════════════════════════════
# LLM Providers
# ═══════════════════════════════════════════════════

class TestLLMProviders:
    def test_get_provider_claude(self):
        """Factory returns ClaudeProvider."""
        provider = get_provider("claude", "key123")
        assert isinstance(provider, ClaudeProvider)
        assert provider.api_key == "key123"

    def test_get_provider_gemini(self):
        """Factory returns GeminiProvider."""
        provider = get_provider("gemini", "key456")
        assert isinstance(provider, GeminiProvider)
        assert provider.api_key == "key456"

    def test_get_provider_openai(self):
        """Factory returns OpenAIProvider."""
        provider = get_provider("openai", "key789")
        assert isinstance(provider, OpenAIProvider)
        assert provider.api_key == "key789"

    def test_get_provider_unknown(self):
        """Factory raises ValueError for unknown provider."""
        with pytest.raises(ValueError, match="Unknown provider"):
            get_provider("unknown_provider", "key")

    def test_get_provider_case_insensitive(self):
        """Factory is case-insensitive."""
        provider = get_provider("ClAuDe", "key")
        assert isinstance(provider, ClaudeProvider)

    def test_claude_provider_init(self):
        """ClaudeProvider stores api_key and model."""
        provider = ClaudeProvider(api_key="test-key", model="claude-opus-4")
        assert provider.api_key == "test-key"
        assert provider.model == "claude-opus-4"

    def test_claude_provider_default_model(self):
        """ClaudeProvider uses default model when not specified."""
        provider = ClaudeProvider(api_key="test-key")
        assert provider.model == "claude-sonnet-4-20250514"

    def test_gemini_provider_init(self):
        """GeminiProvider stores api_key and model."""
        provider = GeminiProvider(api_key="test-key", model="gemini-2.0-pro")
        assert provider.api_key == "test-key"
        assert provider.model == "gemini-2.0-pro"

    def test_gemini_provider_default_model(self):
        """GeminiProvider uses default model when not specified."""
        provider = GeminiProvider(api_key="test-key")
        assert provider.model == "gemini-2.0-flash"

    def test_openai_provider_init(self):
        """OpenAIProvider stores api_key, model, and base_url."""
        provider = OpenAIProvider(
            api_key="test-key",
            model="gpt-4-turbo",
            base_url="https://custom.openai.com/v1",
        )
        assert provider.api_key == "test-key"
        assert provider.model == "gpt-4-turbo"
        assert provider.base_url == "https://custom.openai.com/v1"

    def test_openai_provider_defaults(self):
        """OpenAIProvider uses defaults."""
        provider = OpenAIProvider(api_key="test-key")
        assert provider.model == "gpt-4o"
        assert provider.base_url == "https://api.openai.com/v1"

    @patch("mapsec.analysis.llm_providers.urllib.request.urlopen")
    def test_claude_provider_analyze(self, mock_urlopen):
        """ClaudeProvider sends correct request format."""
        mock_response = MagicMock()
        mock_response.read.return_value = json.dumps({
            "content": [{"type": "text", "text": "Analysis result"}]
        }).encode("utf-8")
        mock_urlopen.return_value.__enter__.return_value = mock_response

        provider = ClaudeProvider(api_key="sk-claude", model="claude-sonnet-4-20250514")
        result = provider.analyze({"nmap": {"hosts": []}}, [])

        assert result == "Analysis result"

        # Verify correct URL and headers
        # Note: urllib.request.Request.add_header capitalizes first letter
        call_args = mock_urlopen.call_args
        req = call_args[0][0]  # first positional arg is the Request object
        assert req.full_url == "https://api.anthropic.com/v1/messages"
        assert req.method == "POST"
        assert req.headers["X-api-key"] == "sk-claude"
        assert req.headers["Anthropic-version"] == "2023-06-01"
        assert req.headers["Content-type"] == "application/json"

        # Verify body contains model and messages
        body = json.loads(req.data.decode("utf-8"))
        assert body["model"] == "claude-sonnet-4-20250514"
        assert len(body["messages"]) == 1
        assert body["messages"][0]["role"] == "user"

    @patch("mapsec.analysis.llm_providers.urllib.request.urlopen")
    def test_gemini_provider_analyze(self, mock_urlopen):
        """GeminiProvider sends correct request format."""
        mock_response = MagicMock()
        mock_response.read.return_value = json.dumps({
            "candidates": [
                {
                    "content": {
                        "parts": [{"text": "Gemini analysis"}]
                    }
                }
            ]
        }).encode("utf-8")
        mock_urlopen.return_value.__enter__.return_value = mock_response

        provider = GeminiProvider(api_key="sk-gemini", model="gemini-2.0-flash")
        result = provider.analyze({"nmap": {"hosts": []}}, [])

        assert result == "Gemini analysis"

        call_args = mock_urlopen.call_args
        req = call_args[0][0]
        assert req.method == "POST"
        assert "generativelanguage.googleapis.com" in req.full_url
        assert "key=sk-gemini" in req.full_url
        assert req.headers["Content-type"] == "application/json"

    @patch("mapsec.analysis.llm_providers.urllib.request.urlopen")
    def test_openai_provider_analyze(self, mock_urlopen):
        """OpenAIProvider sends correct request format."""
        mock_response = MagicMock()
        mock_response.read.return_value = json.dumps({
            "choices": [
                {
                    "message": {"content": "OpenAI analysis"}
                }
            ]
        }).encode("utf-8")
        mock_urlopen.return_value.__enter__.return_value = mock_response

        provider = OpenAIProvider(api_key="sk-openai", model="gpt-4o")
        result = provider.analyze({"nmap": {"hosts": []}}, [])

        assert result == "OpenAI analysis"

        call_args = mock_urlopen.call_args
        req = call_args[0][0]
        assert req.full_url == "https://api.openai.com/v1/chat/completions"
        assert req.method == "POST"
        assert req.headers["Authorization"] == "Bearer sk-openai"
        assert req.headers["Content-type"] == "application/json"

        # Verify body contains model and messages
        body = json.loads(req.data.decode("utf-8"))
        assert body["model"] == "gpt-4o"
        assert len(body["messages"]) == 1
        assert body["messages"][0]["role"] == "user"

    @patch("mapsec.analysis.llm_providers.urllib.request.urlopen")
    def test_claude_provider_http_error(self, mock_urlopen):
        """ClaudeProvider handles HTTP error gracefully."""
        import urllib.error

        error_response = MagicMock()
        error_response.read.return_value = b'{"error": {"message": "Invalid API key"}}'
        error_response.code = 401

        mock_urlopen.side_effect = urllib.error.HTTPError(
            url="https://api.anthropic.com/v1/messages",
            code=401,
            msg="Unauthorized",
            hdrs={},
            fp=error_response,
        )

        provider = ClaudeProvider(api_key="bad-key")
        result = provider.analyze({}, [])
        assert "API error" in result
        assert "401" in result

    @patch("mapsec.analysis.llm_providers.urllib.request.urlopen")
    def test_gemini_provider_exception(self, mock_urlopen):
        """GeminiProvider handles generic exception gracefully."""
        mock_urlopen.side_effect = RuntimeError("Connection timeout")

        provider = GeminiProvider(api_key="key")
        result = provider.analyze({}, [])
        assert "API error" in result

    @patch("mapsec.analysis.llm_providers.urllib.request.urlopen")
    def test_openai_provider_empty_choices(self, mock_urlopen):
        """OpenAIProvider handles empty choices list."""
        mock_response = MagicMock()
        mock_response.read.return_value = json.dumps({"choices": []}).encode("utf-8")
        mock_urlopen.return_value.__enter__.return_value = mock_response

        provider = OpenAIProvider(api_key="key")
        result = provider.analyze({}, [])
        assert result == "No response from OpenAI"

    def test_get_provider_with_custom_model(self):
        """Factory passes custom model to provider."""
        provider = get_provider("claude", "key", "claude-opus-4-20260506")
        assert provider.model == "claude-opus-4-20260506"
        assert isinstance(provider, ClaudeProvider)
