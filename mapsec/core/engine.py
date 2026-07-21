"""Pipeline engine for orchestrating plugin execution."""

from __future__ import annotations

import asyncio
import inspect
import logging
import time
from datetime import datetime
from typing import Any

from mapsec.core.models import PluginResult, ScanConfig, ScanReport
from mapsec.core.plugin import BasePlugin, get_plugins

logger = logging.getLogger(__name__)


def _needs_context(plugin_cls: type[BasePlugin]) -> bool:
    """Check if a plugin's run() method accepts a 'context' parameter."""
    sig = inspect.signature(plugin_cls.run)
    return "context" in sig.parameters


class Engine:
    """Orchestrates plugin execution in parallel."""

    def __init__(self) -> None:
        self._plugins = get_plugins()

    async def run(self, config: ScanConfig) -> ScanReport:
        """Execute the scan pipeline.

        Plugins that do NOT need context run in parallel first.
        Plugins that DO need context (e.g. CVE) run afterward with
        the accumulated results from the first batch.

        Args:
            config: Scan configuration with target and plugin selection.

        Returns:
            Complete scan report with all results.
        """
        report = ScanReport(target=config.target, started_at=datetime.now())

        # Determine which plugins to run
        if config.plugins:
            selected = {
                name: cls
                for name, cls in self._plugins.items()
                if name in config.plugins
            }
        else:
            selected = self._plugins.copy()

        if not selected:
            logger.warning("No plugins selected or available")
            return report

        # Split into independent and context-dependent plugins
        independent: dict[str, type[BasePlugin]] = {}
        context_dependent: dict[str, type[BasePlugin]] = {}
        for name, cls in selected.items():
            if _needs_context(cls):
                context_dependent[name] = cls
            else:
                independent[name] = cls

        # Phase 1: Run independent plugins in parallel
        if independent:
            tasks = [
                self._execute_plugin(name, cls, config.target)
                for name, cls in independent.items()
            ]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            for result in results:
                if isinstance(result, Exception):
                    logger.error("Plugin failed with exception: %s", result)
                    report.add_result(
                        PluginResult(
                            plugin="unknown",
                            target=config.target,
                            success=False,
                            error=str(result),
                        )
                    )
                elif isinstance(result, PluginResult):
                    report.add_result(result)

        # Phase 2: Run context-dependent plugins with accumulated results
        if context_dependent:
            # Build context dict from successful results
            context: dict[str, Any] = {}
            for pr in report.results:
                if pr.success and pr.data:
                    context[pr.plugin] = pr.data

            context_tasks = [
                self._execute_plugin(name, cls, config.target, context=context)
                for name, cls in context_dependent.items()
            ]
            ctx_results = await asyncio.gather(*context_tasks, return_exceptions=True)
            for result in ctx_results:
                if isinstance(result, Exception):
                    logger.error("Context plugin failed: %s", result)
                    report.add_result(
                        PluginResult(
                            plugin="unknown",
                            target=config.target,
                            success=False,
                            error=str(result),
                        )
                    )
                elif isinstance(result, PluginResult):
                    report.add_result(result)

        report.finished_at = datetime.now()
        return report

    async def _execute_plugin(
        self,
        name: str,
        plugin_cls: type[BasePlugin],
        target: str,
        context: dict | None = None,
    ) -> PluginResult:
        """Execute a single plugin with timing and error handling."""
        plugin = plugin_cls()
        start_time = time.time()

        try:
            if not plugin.validate_target(target):
                return PluginResult(
                    plugin=name,
                    target=target,
                    success=False,
                    error=f"Target validation failed for plugin '{name}'",
                )

            if context is not None:
                data = await plugin.run(target, context=context)
            else:
                data = await plugin.run(target)
            duration = time.time() - start_time

            return PluginResult(
                plugin=name,
                target=target,
                data=data,
                success=True,
                duration_seconds=round(duration, 2),
            )
        except Exception as e:
            duration = time.time() - start_time
            logger.error(f"Plugin '{name}' failed: {e}")
            return PluginResult(
                plugin=name,
                target=target,
                success=False,
                error=str(e),
                duration_seconds=round(duration, 2),
            )
