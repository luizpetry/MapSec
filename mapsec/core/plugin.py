"""Plugin base class and registry system."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    pass

# Plugin registry
_plugins: dict[str, type[BasePlugin]] = {}


def register_plugin(cls: type[BasePlugin]) -> type[BasePlugin]:
    """Decorator to register a plugin class."""
    if not hasattr(cls, "name") or not cls.name:
        raise ValueError(f"Plugin {cls.__name__} must define a 'name' attribute")
    _plugins[cls.name] = cls
    return cls


def get_plugins() -> dict[str, type[BasePlugin]]:
    """Return all registered plugins."""
    return _plugins.copy()


class BasePlugin(ABC):
    """Base class for all Mapsec plugins."""

    name: str = ""
    description: str = ""

    @abstractmethod
    async def run(self, target: str) -> dict:
        """Execute the plugin against a target.

        Args:
            target: The target to scan (IP, domain, URL).

        Returns:
            Dictionary with plugin results.
        """
        ...

    def validate_target(self, target: str) -> bool:
        """Validate if the plugin can handle this target type.

        Override for custom validation (IP, domain, URL patterns).
        """
        return True
