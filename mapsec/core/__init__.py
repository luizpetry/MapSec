"""Core module for Mapsec."""

from mapsec.core.plugin import BasePlugin, register_plugin, get_plugins
from mapsec.core.engine import Engine
from mapsec.core.models import ScanConfig, ScanReport, PluginResult

__all__ = [
    "BasePlugin",
    "register_plugin",
    "get_plugins",
    "Engine",
    "ScanConfig",
    "ScanReport",
    "PluginResult",
]
