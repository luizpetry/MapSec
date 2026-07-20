"""Pydantic models for analysis results."""

from pydantic import BaseModel
from typing import Optional


class Finding(BaseModel):
    """A single security finding.

    Attributes:
        severity: One of "critical", "high", "medium", "low", "info".
        title: Short human-readable title for the finding.
        description: Detailed explanation of the issue.
        recommendation: Actionable remediation advice.
        source_plugins: List of plugin names that contributed to this finding.
    """

    severity: str  # "critical", "high", "medium", "low", "info"
    title: str
    description: str
    recommendation: str
    source_plugins: list[str]  # which plugins contributed to this finding


class AnalysisReport(BaseModel):
    """Complete analysis report for a scan target.

    Attributes:
        findings: List of all security findings (rules + optional LLM).
        score: Numeric security score from 0 (worst) to 100 (no issues).
        summary: One-paragraph executive summary of the analysis.
        target: The target host or domain that was scanned.
        plugins_used: Names of plugins whose results were analysed.
        llm_analysis: Raw LLM output text if an LLM provider was configured.
    """

    findings: list[Finding]
    score: int  # 0-100 (100 = no issues)
    summary: str  # one-paragraph executive summary
    target: str
    plugins_used: list[str]
    llm_analysis: Optional[str] = None  # raw LLM output if available
