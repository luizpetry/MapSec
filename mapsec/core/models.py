"""Pydantic models for Mapsec data structures."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


class PluginResult(BaseModel):
    """Result from a single plugin execution."""

    plugin: str
    target: str
    data: dict[str, Any] = Field(default_factory=dict)
    success: bool = True
    error: str | None = None
    duration_seconds: float = 0.0


class ScanConfig(BaseModel):
    """Configuration for a scan operation."""

    target: str
    plugins: list[str] = Field(default_factory=list)
    output_format: str = "json"
    timeout: int = 300


class ScanReport(BaseModel):
    """Complete scan report with all plugin results."""

    target: str
    started_at: datetime = Field(default_factory=datetime.now)
    finished_at: datetime | None = None
    results: list[PluginResult] = Field(default_factory=list)

    def add_result(self, result: PluginResult) -> None:
        """Add a plugin result to the report."""
        self.results.append(result)

    def to_dict(self) -> dict[str, Any]:
        """Convert report to dictionary."""
        return self.model_dump(mode="json")
