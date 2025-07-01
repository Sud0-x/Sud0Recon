"""
Base plugin system for Sud0Recon

This module defines the base classes for creating plugins.
"""

from abc import ABC, abstractmethod
from typing import Dict, Any, List
import asyncio


class BasePlugin(ABC):
    """
    Base class for all Sud0Recon plugins.

    All plugins should inherit from this class and implement
    the required abstract methods.
    """

    def __init__(self, name: str, description: str):
        """
        Initialize the plugin.

        Args:
            name: The name of the plugin
            description: A brief description of what the plugin does
        """
        self.name = name
        self.description = description
        self.enabled = True

    @abstractmethod
    async def scan(self, target: str, **kwargs) -> Dict[str, Any]:
        """
        Main scanning method for the plugin.

        Args:
            target: The target to scan (IP, domain, etc.)
            **kwargs: Additional configuration options

        Returns:
            Dict containing scan results
        """
        pass

    @abstractmethod
    def get_plugin_info(self) -> Dict[str, str]:
        """
        Get information about the plugin.

        Returns:
            Dict containing plugin metadata
        """
        pass

    def is_enabled(self) -> bool:
        """Check if the plugin is enabled."""
        return self.enabled

    def enable(self) -> None:
        """Enable the plugin."""
        self.enabled = True

    def disable(self) -> None:
        """Disable the plugin."""
        self.enabled = False


class ReconPlugin(BasePlugin):
    """Base class for reconnaissance plugins."""

    def __init__(self, name: str, description: str):
        super().__init__(name, description)
        self.plugin_type = "reconnaissance"


class VulnPlugin(BasePlugin):
    """Base class for vulnerability scanning plugins."""

    def __init__(self, name: str, description: str):
        super().__init__(name, description)
        self.plugin_type = "vulnerability"


class PluginManager:
    """
    Manages loading and execution of plugins.
    """

    def __init__(self):
        self.plugins: List[BasePlugin] = []

    def register_plugin(self, plugin: BasePlugin) -> None:
        """
        Register a plugin with the manager.

        Args:
            plugin: The plugin instance to register
        """
        self.plugins.append(plugin)

    def get_plugins(self, plugin_type: str = None) -> List[BasePlugin]:
        """
        Get all registered plugins, optionally filtered by type.

        Args:
            plugin_type: Optional filter by plugin type

        Returns:
            List of plugins matching the criteria
        """
        if plugin_type:
            return [p for p in self.plugins if hasattr(
                p, 'plugin_type') and p.plugin_type == plugin_type]
        return self.plugins

    def get_enabled_plugins(self) -> List[BasePlugin]:
        """Get all enabled plugins."""
        return [p for p in self.plugins if p.is_enabled()]

    async def run_plugins(
            self, target: str, plugin_type: str = None) -> Dict[str, Any]:
        """
        Run all enabled plugins of a specific type against a target.

        Args:
            target: The target to scan
            plugin_type: Optional filter by plugin type

        Returns:
            Dict containing results from all plugins
        """
        plugins = self.get_plugins(plugin_type)
        enabled_plugins = [p for p in plugins if p.is_enabled()]

        results = {}
        tasks = []

        for plugin in enabled_plugins:
            task = asyncio.create_task(plugin.scan(target))
            tasks.append((plugin.name, task))

        for plugin_name, task in tasks:
            try:
                result = await task
                results[plugin_name] = result
            except Exception as e:
                results[plugin_name] = {
                    "error": str(e),
                    "status": "failed"
                }

        return results
