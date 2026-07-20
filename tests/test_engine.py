"""Tests for the Engine orchestrator."""

import pytest

from mapsec.core.engine import Engine
from mapsec.core.models import PluginResult, ScanConfig, ScanReport
from mapsec.core.plugin import BasePlugin


# ── Stub plugins for testing ──────────────────────────────────────────────


class GoodPlugin(BasePlugin):
    """A plugin that always succeeds."""
    name = "good"
    description = "Always succeeds"

    async def run(self, target: str) -> dict:
        return {"result": f"scanned_{target}"}

    def validate_target(self, target: str) -> bool:
        return True


class BadPlugin(BasePlugin):
    """A plugin that always raises an exception."""
    name = "bad"
    description = "Always fails"

    async def run(self, target: str) -> dict:
        raise RuntimeError("Something went wrong")

    def validate_target(self, target: str) -> bool:
        return True


class StrictPlugin(BasePlugin):
    """A plugin that rejects certain targets."""
    name = "strict"
    description = "Rejects loopback"

    async def run(self, target: str) -> dict:
        return {"result": "ok"}

    def validate_target(self, target: str) -> bool:
        return target != "127.0.0.1"


# ── Fixtures ──────────────────────────────────────────────────────────────


@pytest.fixture
def engine_with_plugins():
    """Return an Engine whose internal plugin registry is replaced with test plugins."""
    eng = Engine()
    eng._plugins = {
        "good": GoodPlugin,
        "bad": BadPlugin,
        "strict": StrictPlugin,
    }
    return eng


# ── Engine.run() ──────────────────────────────────────────────────────────


@pytest.mark.asyncio
class TestEngineRun:
    """Integration-style tests for Engine.run()."""

    async def test_run_returns_scan_report(self, engine_with_plugins):
        """Engine.run() returns a ScanReport instance."""
        config = ScanConfig(target="example.com", plugins=["good"])
        report = await engine_with_plugins.run(config)
        assert isinstance(report, ScanReport)

    async def test_run_with_selected_plugin_returns_result(self, engine_with_plugins):
        """Running a selected plugin produces one result in the report."""
        config = ScanConfig(target="example.com", plugins=["good"])
        report = await engine_with_plugins.run(config)
        assert len(report.results) == 1
        assert report.results[0].plugin == "good"
        assert report.results[0].success is True

    async def test_run_with_empty_plugin_list_returns_report_no_results(self, engine_with_plugins):
        """When no plugins match the requested list, the report has zero results."""
        config = ScanConfig(target="example.com", plugins=["nonexistent"])
        report = await engine_with_plugins.run(config)
        assert len(report.results) == 0
        # Engine returns early without setting finished_at when no plugins are selected
        assert report.finished_at is None

    async def test_run_with_no_plugins_argument_runs_all(self, engine_with_plugins):
        """When plugins list is empty in config, all registered plugins are executed."""
        config = ScanConfig(target="example.com")  # plugins defaults to []
        report = await engine_with_plugins.run(config)
        assert len(report.results) == 3  # good, bad, strict

    async def test_run_records_timing_on_report(self, engine_with_plugins):
        """The report has started_at and finished_at populated after run()."""
        config = ScanConfig(target="example.com", plugins=["good"])
        report = await engine_with_plugins.run(config)
        assert report.started_at is not None
        assert report.finished_at is not None
        assert report.finished_at >= report.started_at

    async def test_run_handles_plugin_exception_gracefully(self, engine_with_plugins):
        """When a plugin raises, its result is captured as an error, not a crash."""
        config = ScanConfig(target="example.com", plugins=["bad"])
        report = await engine_with_plugins.run(config)
        assert len(report.results) == 1
        assert report.results[0].success is False
        assert "Something went wrong" in report.results[0].error

    async def test_run_mixed_success_and_failure(self, engine_with_plugins):
        """A mix of successful and failing plugins both appear in results."""
        config = ScanConfig(target="example.com", plugins=["good", "bad"])
        report = await engine_with_plugins.run(config)
        assert len(report.results) == 2
        results_by_plugin = {r.plugin: r for r in report.results}
        assert results_by_plugin["good"].success is True
        assert results_by_plugin["bad"].success is False

    async def test_run_validation_failure_records_error(self, engine_with_plugins):
        """A plugin that fails validation produces a PluginResult with success=False."""
        config = ScanConfig(target="127.0.0.1", plugins=["strict"])
        report = await engine_with_plugins.run(config)
        assert len(report.results) == 1
        assert report.results[0].success is False
        assert "validation failed" in report.results[0].error.lower()

    async def test_run_target_is_preserved_in_all_results(self, engine_with_plugins):
        """Every result in the report references the original target."""
        config = ScanConfig(target="scanme.org", plugins=["good", "bad", "strict"])
        report = await engine_with_plugins.run(config)
        for result in report.results:
            assert result.target == "scanme.org"

    async def test_run_returns_report_even_with_no_selected_plugins(self, engine_with_plugins):
        """Engine.run() returns a ScanReport even when no plugins are available."""
        eng = Engine()
        eng._plugins = {}
        config = ScanConfig(target="example.com", plugins=["ghost"])
        report = await eng.run(config)
        assert isinstance(report, ScanReport)
        assert len(report.results) == 0
        # Engine returns early without setting finished_at when no plugins are selected
        assert report.finished_at is None


# ── Engine._execute_plugin() ──────────────────────────────────────────────


@pytest.mark.asyncio
class TestEngineExecutePlugin:
    """Unit tests for Engine._execute_plugin()."""

    async def test_successful_execution_returns_plugin_result(self, engine_with_plugins):
        """_execute_plugin returns PluginResult with success=True on valid target."""
        result = await engine_with_plugins._execute_plugin("good", GoodPlugin, "example.com")
        assert isinstance(result, PluginResult)
        assert result.success is True
        assert result.plugin == "good"
        assert result.target == "example.com"

    async def test_successful_execution_includes_data(self, engine_with_plugins):
        """_execute_plugin includes the data returned by plugin.run()."""
        result = await engine_with_plugins._execute_plugin("good", GoodPlugin, "example.com")
        assert result.data == {"result": "scanned_example.com"}

    async def test_successful_execution_records_duration(self, engine_with_plugins):
        """_execute_plugin sets a non-negative duration_seconds for successful runs."""
        result = await engine_with_plugins._execute_plugin("good", GoodPlugin, "example.com")
        assert result.duration_seconds >= 0
        assert isinstance(result.duration_seconds, float)

    async def test_validation_failure_returns_error_result(self, engine_with_plugins):
        """_execute_plugin returns PluginResult with success=False on validation failure."""
        result = await engine_with_plugins._execute_plugin(
            "strict", StrictPlugin, "127.0.0.1"
        )
        assert result.success is False
        assert "validation failed" in result.error.lower()
        assert result.plugin == "strict"

    async def test_validation_failure_records_duration(self, engine_with_plugins):
        """Validation failure still records timing as a non-negative float."""
        result = await engine_with_plugins._execute_plugin(
            "strict", StrictPlugin, "127.0.0.1"
        )
        assert result.duration_seconds >= 0
        assert isinstance(result.duration_seconds, float)

    async def test_exception_during_run_returns_error_result(self, engine_with_plugins):
        """_execute_plugin returns PluginResult with success=False on exception."""
        result = await engine_with_plugins._execute_plugin("bad", BadPlugin, "example.com")
        assert result.success is False
        assert "Something went wrong" in result.error

    async def test_exception_result_includes_plugin_name(self, engine_with_plugins):
        """Error result preserves the plugin name."""
        result = await engine_with_plugins._execute_plugin("bad", BadPlugin, "example.com")
        assert result.plugin == "bad"

    async def test_exception_result_records_duration(self, engine_with_plugins):
        """Exception path records duration_seconds as a non-negative float."""
        result = await engine_with_plugins._execute_plugin("bad", BadPlugin, "example.com")
        assert result.duration_seconds >= 0
        assert isinstance(result.duration_seconds, float)
