"""Analysis engine — orchestrates rules + LLM."""

from __future__ import annotations

import json
import logging
from typing import Any

from mapsec.analysis.models import Finding, AnalysisReport
from mapsec.analysis.rules import run_rules
from mapsec.analysis.llm_providers import get_provider, LLMProvider

logger = logging.getLogger(__name__)


class AnalysisEngine:
    """Orchestrates security analysis of scan results.

    Usage::

        engine = AnalysisEngine()
        engine.configure_llm("openai", "sk-...")
        report = engine.analyze(
            results={"nmap": {...}, "ssl": {...}},
            target="example.com",
            plugins_used=["nmap", "ssl"],
        )
    """

    def __init__(self) -> None:
        self._provider: LLMProvider | None = None

    # ------------------------------------------------------------------
    # Configuration
    # ------------------------------------------------------------------

    def configure_llm(
        self,
        provider_name: str | None = None,
        api_key: str | None = None,
        model: str | None = None,
    ) -> None:
        """Configure an LLM provider for deep analysis.

        Call with ``None`` or empty strings to disable LLM analysis.

        Parameters
        ----------
        provider_name : str or None
            Provider name (``"claude"``, ``"gemini"``, ``"openai"``).
        api_key : str or None
            API key for the provider.
        model : str or None
            Optional model override.  Uses the provider default when ``None``.
        """
        if not provider_name or not api_key:
            self._provider = None
            logger.info("LLM analysis disabled")
            return
        self._provider = get_provider(provider_name, api_key, model)
        logger.info(
            "LLM provider configured: %s (model: %s)",
            provider_name,
            model or "(default)",
        )

    # ------------------------------------------------------------------
    # Public analysis entry point
    # ------------------------------------------------------------------

    def analyze(
        self,
        results: dict[str, Any],
        target: str,
        plugins_used: list[str],
    ) -> AnalysisReport:
        """Run full security analysis: rules engine + optional LLM.

        Parameters
        ----------
        results : dict
            Dictionary keyed by plugin name containing each plugin's output.
        target : str
            The hostname or IP that was scanned.
        plugins_used : list[str]
            Names of plugins whose results are present in *results*.

        Returns
        -------
        AnalysisReport
            Complete analysis report with findings, score, and summary.
        """
        # 1. Run rules engine
        findings = run_rules(results)

        # 2. Calculate base score
        score = self._calculate_score(findings)

        # 3. Generate summary from rules findings
        summary = self._generate_summary(findings, score)

        # 4. Run LLM analysis if a provider is configured
        llm_analysis: str | None = None
        if self._provider:
            try:
                llm_analysis = self._provider.analyze(results, findings)
                # Parse LLM findings and merge with rules findings
                llm_findings = self._parse_llm_findings(llm_analysis)
                if llm_findings:
                    findings.extend(llm_findings)
                    # Recalculate score and summary with LLM findings
                    score = self._calculate_score(findings)
                    summary = self._generate_summary(findings, score)
            except Exception:
                logger.exception("LLM analysis failed — continuing with rules only")

        return AnalysisReport(
            findings=findings,
            score=score,
            summary=summary,
            target=target,
            plugins_used=plugins_used,
            llm_analysis=llm_analysis,
        )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _calculate_score(findings: list[Finding]) -> int:
        """Calculate security score 0–100 based on findings.

        Each finding deducts points depending on its severity:

        - critical: -25
        - high:     -15
        - medium:    -8
        - low:       -3
        - info:       0

        The score is clamped to the [0, 100] range.
        """
        penalties: dict[str, int] = {
            "critical": 25,
            "high": 15,
            "medium": 8,
            "low": 3,
            "info": 0,
        }
        total = sum(penalties.get(f.severity, 0) for f in findings)
        return max(0, 100 - total)

    @staticmethod
    def _generate_summary(findings: list[Finding], score: int) -> str:
        """Generate a one-paragraph executive summary.

        Parameters
        ----------
        findings : list[Finding]
            All findings to summarise.
        score : int
            Numeric security score (0–100).

        Returns
        -------
        str
            Human-readable summary paragraph.
        """
        if not findings:
            return (
                f"Security score: {score}/100.  "
                "No security issues detected."
            )

        # Count by severity
        by_severity: dict[str, int] = {}
        for f in findings:
            by_severity[f.severity] = by_severity.get(f.severity, 0) + 1

        parts: list[str] = []
        for sev in ("critical", "high", "medium", "low", "info"):
            count = by_severity.get(sev, 0)
            if count > 0:
                parts.append(f"{count} {sev}")

        severity_desc = ", ".join(parts) if parts else "no issues"

        # Severity-level qualifier
        if by_severity.get("critical", 0) > 0:
            rating = "critical risk — immediate action required"
        elif by_severity.get("high", 0) > 0:
            rating = "high risk — prompt remediation needed"
        elif by_severity.get("medium", 0) > 0:
            rating = "moderate risk — plan remediation"
        elif by_severity.get("low", 0) > 0:
            rating = "low risk — informational"
        else:
            rating = "informational findings only"

        return (
            f"Security score: {score}/100.  "
            f"Found {severity_desc}.  "
            f"Overall assessment: {rating}."
        )

    @staticmethod
    def _parse_llm_findings(llm_output: str) -> list[Finding]:
        """Parse LLM JSON response into a list of Finding objects.

        Handles malformed responses gracefully — returns an empty list
        on any parse failure.

        Parameters
        ----------
        llm_output : str
            Raw text response from the LLM.

        Returns
        -------
        list[Finding]
            Parsed findings, or an empty list if parsing failed.
        """
        if not llm_output or not llm_output.strip():
            return []

        # Attempt to extract JSON from the response — the LLM may wrap it
        # in markdown code fences or add commentary.
        text = llm_output.strip()

        # Try stripping markdown code fences first
        if text.startswith("```"):
            # Remove opening fence (possibly with language tag)
            first_newline = text.find("\n")
            if first_newline != -1:
                text = text[first_newline + 1 :]
            # Remove closing fence
            if text.endswith("```"):
                text = text[:-3].strip()
            elif "```" in text:
                text = text[: text.rindex("```")].strip()

        # Try to extract a JSON object from the text
        json_start = text.find("{")
        json_end = text.rfind("}")

        if json_start == -1 or json_end == -1 or json_end <= json_start:
            logger.warning("No JSON object found in LLM response")
            return []

        json_str = text[json_start : json_end + 1]

        try:
            data = json.loads(json_str)
        except json.JSONDecodeError:
            logger.warning("Failed to parse LLM response as JSON")
            return []

        raw_findings = data.get("findings", [])
        if not isinstance(raw_findings, list):
            logger.warning("LLM response 'findings' is not a list")
            return []

        findings: list[Finding] = []
        for item in raw_findings:
            if not isinstance(item, dict):
                continue
            try:
                findings.append(
                    Finding(
                        severity=str(item.get("severity", "info")),
                        title=str(item.get("title", "")),
                        description=str(item.get("description", "")),
                        recommendation=str(item.get("recommendation", "")),
                        source_plugins=["llm"],
                    )
                )
            except Exception:
                logger.debug("Skipping malformed LLM finding item: %s", item)

        return findings
