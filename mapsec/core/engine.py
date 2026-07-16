"""Pipeline engine for orchestrating plugin execution."""

from __future__ import annotations

import asyncio
import logging
import time
from datetime import datetime

from mapsec.core.models import PluginResult, ScanConfig, ScanReport
from mapsec.core.plugin import BasePlugin, get_plugins

logger = logging.getLogger(__name__)


class Engine:
    """Orchestrates plugin execution in parallel."""

    def __init__(self) -> None:
        self._plugins = get_plugins()

    async def run(self, config: ScanConfig) -> ScanReport:
        """Execute the scan pipeline.

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

        # Execute plugins in parallel
        tasks = [
            self._execute_plugin(name, cls, config.target)
            for name, cls in selected.items()
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

        report.finished_at = datetime.now()
        return report

    async def _execute_plugin(
        self, name: str, plugin_cls: type[BasePlugin], target: str
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
