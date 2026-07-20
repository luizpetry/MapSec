"""Tests for the plugin registry and BasePlugin abstract class."""

import pytest

from mapsec.core.plugin import BasePlugin, register_plugin, get_plugins


# ── Fixtures ──────────────────────────────────────────────────────────────


@pytest.fixture
def clean_registry():
    """Provide a clean plugin registry for each test and restore afterwards."""
    import mapsec.core.plugin as plugin_mod

    saved = plugin_mod._plugins.copy()
    plugin_mod._plugins.clear()
    yield plugin_mod._plugins
    plugin_mod._plugins.clear()
    plugin_mod._plugins.update(saved)


# ── Registry (register_plugin / get_plugins) ─────────────────────────────


class TestRegistry:
    """Tests for plugin registration and retrieval."""

    def test_register_plugin_adds_to_registry(self, clean_registry):
        """A class decorated with @register_plugin appears in the registry."""

        @register_plugin
        class MyPlugin(BasePlugin):
            name = "my_test"
            description = "A test plugin"

            async def run(self, target: str) -> dict:
                return {"result": "ok"}

        registry = get_plugins()
        assert "my_test" in registry
        assert registry["my_test"] is MyPlugin

    def test_plugin_without_name_raises_value_error(self, clean_registry):
        """Registering a plugin without a 'name' attribute raises ValueError."""

        with pytest.raises(ValueError, match="must define a 'name' attribute"):

            @register_plugin
            class NamelessPlugin(BasePlugin):  # noqa: F841
                name = ""  # empty string — also falsy
                description = "missing name"

                async def run(self, target: str) -> dict:
                    return {}

    def test_get_plugins_returns_copy_not_reference(self, clean_registry):
        """get_plugins() returns a copy that does not affect the internal registry."""

        @register_plugin
        class P1(BasePlugin):
            name = "p1"
            description = "plugin one"

            async def run(self, target: str) -> dict:
                return {}

        registry_copy = get_plugins()
        registry_copy.clear()

        # Internal registry should still have the plugin
        assert "p1" in get_plugins()

    def test_multiple_plugins_registered(self, clean_registry):
        """Multiple decorated plugins all appear in the registry."""

        @register_plugin
        class Alpha(BasePlugin):
            name = "alpha"
            description = "first"

            async def run(self, target: str) -> dict:
                return {}

        @register_plugin
        class Beta(BasePlugin):
            name = "beta"
            description = "second"

            async def run(self, target: str) -> dict:
                return {}

        registry = get_plugins()
        assert set(registry.keys()) == {"alpha", "beta"}

    def test_register_plugin_returns_the_class(self, clean_registry):
        """The @register_plugin decorator returns the original class unchanged."""

        @register_plugin
        class SamplePlugin(BasePlugin):
            name = "sample"
            description = "a sample"

            async def run(self, target: str) -> dict:
                return {}

        # The decorated class should still be usable as a normal class
        instance = SamplePlugin()
        assert isinstance(instance, BasePlugin)

    def test_late_registration_separation(self, clean_registry):
        """Plugins registered at different times are all visible in get_plugins()."""

        @register_plugin
        class Early(BasePlugin):
            name = "early"
            description = ""
            async def run(self, target: str) -> dict:
                return {}

        assert "early" in get_plugins()

        @register_plugin
        class Late(BasePlugin):
            name = "late"
            description = ""
            async def run(self, target: str) -> dict:
                return {}

        assert "late" in get_plugins()
        assert len(get_plugins()) == 2


# ── BasePlugin ────────────────────────────────────────────────────────────


class TestBasePlugin:
    """Tests for BasePlugin abstract class behavior."""

    def test_cannot_instantiate_abstract_class(self):
        """BasePlugin cannot be instantiated directly because run() is abstract."""
        with pytest.raises(TypeError):
            BasePlugin()  # type: ignore[abstract]

    def test_concrete_subclass_can_be_instantiated(self):
        """A subclass that implements run() can be instantiated."""

        class GoodPlugin(BasePlugin):
            name = "good"
            description = ""

            async def run(self, target: str) -> dict:
                return {}

        instance = GoodPlugin()
        assert isinstance(instance, BasePlugin)

    def test_validate_target_defaults_to_true(self):
        """BasePlugin.validate_target() returns True by default."""

        class WidePlugin(BasePlugin):
            name = "wide"
            description = ""

            async def run(self, target: str) -> dict:
                return {}

        instance = WidePlugin()
        assert instance.validate_target("anything") is True
        assert instance.validate_target("") is True
        assert instance.validate_target("!@#$%^") is True

    def test_validate_target_can_be_overridden(self):
        """Subclasses can override validate_target for custom validation."""

        class StrictPlugin(BasePlugin):
            name = "strict"
            description = ""

            async def run(self, target: str) -> dict:
                return {}

            def validate_target(self, target: str) -> bool:
                return target.startswith("valid_")

        instance = StrictPlugin()
        assert instance.validate_target("valid_example") is True
        assert instance.validate_target("invalid") is False

    def test_name_and_description_attributes(self):
        """Subclasses set name and description as class attributes."""

        class NamedPlugin(BasePlugin):
            name = "my_name"
            description = "My description"

            async def run(self, target: str) -> dict:
                return {}

        assert NamedPlugin.name == "my_name"
        assert NamedPlugin.description == "My description"
