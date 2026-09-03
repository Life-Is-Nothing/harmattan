"""
HARMATTAN — Plugin system.
Discover, load, and manage plugins from a configurable directory.
"""
from __future__ import annotations

import importlib
import importlib.util
import inspect
import logging
import os
import sys
from pathlib import Path
from typing import Any

from core.config import DATA_DIR

log = logging.getLogger("harmattan.plugins")

PLUGINS_DIR = Path(os.environ.get("HARMATTAN_PLUGINS_DIR", DATA_DIR / "plugins"))


class PluginBase:
    """Base class for all HARMATTAN plugins.

    Subclass this and implement the hooks you need.
    """

    name: str = "unnamed"
    version: str = "0.1.0"
    description: str = ""
    author: str = ""

    def on_startup(self, app: Any) -> None:
        """Called when the application starts."""
        pass

    def on_scan_complete(self, scan_type: str, results: dict) -> None:
        """Called after a scan completes."""
        pass

    def on_export(self, export_format: str, data: dict) -> dict | None:
        """Called during export. Return modified data or None."""
        return None

    def on_event(self, event_type: str, payload: dict) -> None:
        """Called when a notification event is published."""
        pass

    def on_shutdown(self) -> None:
        """Called when the application shuts down."""
        pass


def _current_base() -> type:
    """Return the currently-living PluginBase class from sys.modules.

    Other modules (tests, suite) may reload/purge ``core.plugins`` at runtime,
    which creates a *new* PluginBase class object.  A plugin file does
    ``from core.plugins import PluginBase`` which resolves through
    ``sys.modules`` — so we must resolve the same way, re-importing the module
    if it has been purged.  Otherwise the ``issubclass`` check compares the
    plugin's base (fresh) against a stale global and silently fails.
    """
    import importlib as _imp

    mod = sys.modules.get(__name__)
    if mod is None:
        mod = _imp.import_module(__name__)
    return mod.PluginBase


def discover_plugins(plugins_dir: str | Path | None = None) -> list[dict]:
    """Scan the plugins directory and return metadata for each plugin."""
    if plugins_dir is None:
        plugins_dir = PLUGINS_DIR
    plugins_dir = Path(plugins_dir)
    plugins_dir.mkdir(parents=True, exist_ok=True)

    base = _current_base()

    discovered = []
    for entry in sorted(plugins_dir.iterdir()):
        if entry.suffix == ".py" and not entry.name.startswith("_"):
            try:
                spec = importlib.util.spec_from_file_location(entry.stem, entry)
                if not spec or not spec.loader:
                    continue
                mod = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(mod)
                for name, obj in inspect.getmembers(mod, inspect.isclass):
                    if (
                        issubclass(obj, base)
                        and obj is not base
                        and not inspect.isabstract(obj)
                    ):
                        discovered.append({
                            "name": getattr(obj, "name", entry.stem),
                            "version": getattr(obj, "version", "0.1.0"),
                            "description": getattr(obj, "description", ""),
                            "author": getattr(obj, "author", ""),
                            "class_name": name,
                            "file": str(entry),
                            "loaded": False,
                        })
            except Exception as e:
                log.warning("Failed to load plugin %s: %s", entry.name, e)

    return discovered


def load_plugin(plugin_info: dict) -> PluginBase | None:
    """Load a plugin by its metadata dict (from discover_plugins)."""
    try:
        file_path = plugin_info.get("file", "")
        if not file_path:
            return None
        spec = importlib.util.spec_from_file_location(
            f"harmattan_plugin_{plugin_info['name']}", file_path
        )
        if not spec or not spec.loader:
            return None
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        # The plugin file did `from core.plugins import PluginBase`, which
        # resolved through sys.modules. Use the SAME class that exec_module
        # just bound, so the issubclass check is against the live base.
        cp = sys.modules.get("core.plugins")
        base = cp.PluginBase if cp is not None else _current_base()
        for _name, obj in inspect.getmembers(mod, inspect.isclass):
            if issubclass(obj, base) and obj is not base:
                instance = obj()
                plugin_info["loaded"] = True
                plugin_info["instance"] = instance
                log.info("Plugin loaded: %s v%s", instance.name, instance.version)
                return instance
    except Exception as e:
        log.error("Failed to load plugin %s: %s", plugin_info.get("name"), e)
    return None


def load_all_plugins(plugins_dir: str | Path | None = None) -> list[PluginBase]:
    """Discover and load all plugins. Returns list of instances."""
    instances = []
    for info in discover_plugins(plugins_dir):
        instance = load_plugin(info)
        if instance:
            instances.append(instance)
    return instances


class PluginManager:
    """Manages plugin lifecycle."""

    def __init__(self):
        self._plugins: dict[str, PluginBase] = {}
        self._discovered: list[dict] = []

    def discover(self, plugins_dir: str | Path | None = None) -> list[dict]:
        self._discovered = discover_plugins(plugins_dir)
        return self._discovered

    def load_all(self) -> list[PluginBase]:
        instances = []
        for info in self._discovered:
            inst = load_plugin(info)
            if inst:
                self._plugins[inst.name] = inst
                instances.append(inst)
        return instances

    def get(self, name: str) -> PluginBase | None:
        return self._plugins.get(name)

    def list_loaded(self) -> list[dict]:
        return [
            {"name": p.name, "version": p.version, "description": p.description}
            for p in self._plugins.values()
        ]

    def on_startup(self, app: Any) -> None:
        for p in self._plugins.values():
            try:
                p.on_startup(app)
            except Exception as e:
                log.error("Plugin %s on_startup failed: %s", p.name, e)

    def on_shutdown(self) -> None:
        for p in self._plugins.values():
            try:
                p.on_shutdown()
            except Exception as e:
                log.error("Plugin %s on_shutdown failed: %s", p.name, e)

    def on_scan_complete(self, scan_type: str, results: dict) -> None:
        for p in self._plugins.values():
            try:
                p.on_scan_complete(scan_type, results)
            except Exception as e:
                log.error("Plugin %s on_scan_complete: %s", p.name, e)


manager = PluginManager()
