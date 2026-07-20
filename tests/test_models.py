"""Tests for Pydantic models: PluginResult, ScanConfig, ScanReport."""

from datetime import datetime

import pytest

from mapsec.core.models import PluginResult, ScanConfig, ScanReport


# ── PluginResult ──────────────────────────────────────────────────────────


class TestPluginResult:
    """Unit tests for PluginResult model."""

    def test_defaults_to_success_with_empty_data(self):
        """PluginResult with only required fields defaults to success=True and data={}."""
        result = PluginResult(plugin="nmap", target="127.0.0.1")
        assert result.success is True
        assert result.data == {}
        assert result.error is None
        assert result.duration_seconds == 0.0

    def test_created_with_error_sets_success_false(self):
        """PluginResult with an explicit error message sets success=False."""
        result = PluginResult(
            plugin="nmap",
            target="127.0.0.1",
            success=False,
            error="Connection refused",
        )
        assert result.success is False
        assert result.error == "Connection refused"

    def test_model_dump_returns_correct_dict(self):
        """model_dump() returns a serializable dictionary with expected keys."""
        result = PluginResult(
            plugin="nmap",
            target="example.com",
            data={"hosts": [{"ip": "93.184.216.34"}]},
            success=True,
            duration_seconds=1.23,
        )
        dumped = result.model_dump()
        assert dumped["plugin"] == "nmap"
        assert dumped["target"] == "example.com"
        assert dumped["data"] == {"hosts": [{"ip": "93.184.216.34"}]}
        assert dumped["success"] is True
        assert dumped["duration_seconds"] == 1.23
        assert dumped["error"] is None

    def test_model_dump_json_mode_serializable(self):
        """model_dump(mode='json') produces JSON-compatible types."""
        result = PluginResult(plugin="test", target="127.0.0.1")
        dumped = result.model_dump(mode="json")
        assert isinstance(dumped["duration_seconds"], float)
        assert dumped["error"] is None

    def test_error_field_is_optional(self):
        """PluginResult can be created without error (defaults to None)."""
        result = PluginResult(plugin="dns", target="example.com")
        assert result.error is None

    def test_data_field_defaults_to_empty_dict(self):
        """PluginResult data field defaults to an empty dict, not None."""
        result = PluginResult(plugin="nmap", target="10.0.0.1")
        assert result.data == {}
        assert isinstance(result.data, dict)


# ── ScanConfig ────────────────────────────────────────────────────────────


class TestScanConfig:
    """Unit tests for ScanConfig model."""

    def test_created_with_target_and_plugins(self):
        """ScanConfig stores target and plugins list."""
        config = ScanConfig(target="example.com", plugins=["nmap", "dns"])
        assert config.target == "example.com"
        assert config.plugins == ["nmap", "dns"]

    def test_default_output_format_is_json(self):
        """ScanConfig output_format defaults to 'json'."""
        config = ScanConfig(target="example.com")
        assert config.output_format == "json"

    def test_default_timeout_is_300(self):
        """ScanConfig timeout defaults to 300 seconds."""
        config = ScanConfig(target="example.com")
        assert config.timeout == 300

    def test_plugins_defaults_to_empty_list(self):
        """ScanConfig plugins defaults to an empty list when not provided."""
        config = ScanConfig(target="example.com")
        assert config.plugins == []

    def test_custom_output_format(self):
        """ScanConfig accepts a custom output_format."""
        config = ScanConfig(target="example.com", output_format="yaml")
        assert config.output_format == "yaml"

    def test_custom_timeout(self):
        """ScanConfig accepts a custom timeout value."""
        config = ScanConfig(target="example.com", timeout=60)
        assert config.timeout == 60


# ── ScanReport ────────────────────────────────────────────────────────────


class TestScanReport:
    """Unit tests for ScanReport model."""

    def test_add_result_appends_to_results(self):
        """add_result() appends a PluginResult to the results list."""
        report = ScanReport(target="example.com")
        result = PluginResult(plugin="nmap", target="example.com")
        report.add_result(result)
        assert len(report.results) == 1
        assert report.results[0] is result

    def test_add_result_multiple(self):
        """add_result() handles multiple results correctly."""
        report = ScanReport(target="example.com")
        r1 = PluginResult(plugin="nmap", target="example.com")
        r2 = PluginResult(plugin="dns", target="example.com", success=False, error="fail")
        report.add_result(r1)
        report.add_result(r2)
        assert len(report.results) == 2

    def test_to_dict_returns_serializable_dict(self):
        """to_dict() returns a JSON-serializable dictionary."""
        report = ScanReport(target="example.com")
        report.add_result(PluginResult(plugin="nmap", target="example.com"))
        d = report.to_dict()
        assert d["target"] == "example.com"
        assert isinstance(d["started_at"], str)  # ISO datetime string
        assert isinstance(d["results"], list)
        assert len(d["results"]) == 1
        assert d["results"][0]["plugin"] == "nmap"

    def test_finished_at_defaults_to_none(self):
        """finished_at defaults to None before the report is finalized."""
        report = ScanReport(target="example.com")
        assert report.finished_at is None

    def test_started_at_is_set_on_creation(self):
        """started_at is automatically set to the current datetime on creation."""
        report = ScanReport(target="example.com")
        assert isinstance(report.started_at, datetime)
        # Should be very recent (within the last second)
        assert (datetime.now() - report.started_at).total_seconds() < 1

    def test_finished_at_can_be_set_explicitly(self):
        """finished_at can be set to a datetime value."""
        now = datetime(2025, 1, 1, 12, 0, 0)
        report = ScanReport(target="example.com", finished_at=now)
        assert report.finished_at == now

    def test_to_dict_includes_finished_at_when_set(self):
        """to_dict() includes finished_at when it has been set."""
        now = datetime(2025, 6, 15, 10, 30, 0)
        report = ScanReport(target="example.com", finished_at=now)
        d = report.to_dict()
        assert d["finished_at"] is not None
        assert isinstance(d["finished_at"], str)

    def test_to_dict_finished_at_none_when_not_set(self):
        """to_dict() keeps finished_at as None when not set."""
        report = ScanReport(target="example.com")
        d = report.to_dict()
        assert d["finished_at"] is None

    def test_empty_results_by_default(self):
        """ScanReport starts with an empty results list."""
        report = ScanReport(target="example.com")
        assert report.results == []
