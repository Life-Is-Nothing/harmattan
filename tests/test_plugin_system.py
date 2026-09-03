"""Tests for plugin system."""
from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from core.plugins import PluginBase, discover_plugins, load_plugin


class TestPluginBase:
    def test_plugin_base_has_default_attributes(self):
        p = PluginBase()
        assert p.name == "unnamed"
        assert p.version == "0.1.0"
        assert p.description == ""

    def test_plugin_base_hooks_do_nothing(self):
        p = PluginBase()
        assert p.on_startup(None) is None
        assert p.on_shutdown() is None
        assert p.on_scan_complete("arp", {}) is None
        assert p.on_export("csv", {}) is None
        assert p.on_event("test", {}) is None


class TestDiscoverPlugins:
    def test_discover_empty_dir(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            plugins = discover_plugins(tmpdir)
            assert plugins == []

    def test_discover_with_plugin_file(self):
        plugin_code = """
from core.plugins import PluginBase

class MyPlugin(PluginBase):
    name = "test-plugin"
    version = "1.0.0"
    description = "A test plugin"
    author = "Tester"
"""
        with tempfile.TemporaryDirectory() as tmpdir:
            plugin_file = Path(tmpdir) / "my_plugin.py"
            plugin_file.write_text(plugin_code)
            plugins = discover_plugins(tmpdir)
            assert len(plugins) == 1
            assert plugins[0]["name"] == "test-plugin"
            assert plugins[0]["version"] == "1.0.0"

    def test_discover_ignores_init(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            init_file = Path(tmpdir) / "__init__.py"
            init_file.write_text("# empty")
            plugins = discover_plugins(tmpdir)
            assert len(plugins) == 0


class TestLoadPlugin:
    def test_load_plugin_from_discovered(self):
        plugin_code = """
from core.plugins import PluginBase

class MyPlugin(PluginBase):
    name = "test-plugin"
    version = "1.0.0"

    def on_startup(self, app):
        self.started = True
"""
        with tempfile.TemporaryDirectory() as tmpdir:
            plugin_file = Path(tmpdir) / "my_plugin.py"
            plugin_file.write_text(plugin_code)
            plugins = discover_plugins(tmpdir)
            assert len(plugins) == 1
            instance = load_plugin(plugins[0])
            assert instance is not None
            assert instance.name == "test-plugin"

    def test_load_plugin_nonexistent_file(self):
        result = load_plugin({"file": "/nonexistent/plugin.py", "name": "bad"})
        assert result is None
