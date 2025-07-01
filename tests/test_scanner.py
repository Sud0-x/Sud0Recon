"""
Unit tests for Sud0Recon scanner module
"""

import pytest
import asyncio
import sys
import os

# Add the src directory to the Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from sud0recon.core.scanner import Scanner
from sud0recon.core.config import Config
from sud0recon.plugins.base import PluginManager, BasePlugin


class TestScanner:
    """Test cases for the Scanner class."""
    
    def test_scanner_initialization(self):
        """Test scanner initialization with targets."""
        targets = ["example.com", "google.com"]
        scanner = Scanner(targets)
        
        assert scanner.targets == targets
        assert scanner.results == []
    
    @pytest.mark.asyncio
    async def test_scan_target(self):
        """Test scanning a single target."""
        scanner = Scanner(["example.com"])
        result = await scanner.scan_target("example.com")
        
        assert isinstance(result, dict)
        assert "target" in result
        assert "status" in result
        assert "timestamp" in result
        assert result["target"] == "example.com"
    
    @pytest.mark.asyncio
    async def test_run_scanner(self):
        """Test running the scanner on multiple targets."""
        targets = ["example.com", "google.com"]
        scanner = Scanner(targets)
        
        await scanner.run()
        results = scanner.get_results()
        
        assert len(results) == len(targets)
        assert all(isinstance(result, dict) for result in results)


class TestConfig:
    """Test cases for the Config class."""
    
    def test_default_config(self):
        """Test default configuration values."""
        config = Config()
        
        assert config.database.type == "sqlite"
        assert config.database.path == "sud0recon.db"
        assert config.scanning.max_concurrent == 50
        assert config.scanning.timeout == 30
        assert config.reporting.output_dir == "reports"
    
    def test_config_serialization(self):
        """Test configuration serialization to dict."""
        config = Config()
        config_dict = config.model_dump()
        
        assert isinstance(config_dict, dict)
        assert "database" in config_dict
        assert "scanning" in config_dict
        assert "reporting" in config_dict


class MockPlugin(BasePlugin):
    """Mock plugin for testing."""
    
    def __init__(self):
        super().__init__("MockPlugin", "Test plugin")
    
    async def scan(self, target: str, **kwargs):
        """Mock scan method."""
        return {"target": target, "status": "scanned", "mock": True}
    
    def get_plugin_info(self):
        """Get plugin information."""
        return {
            "name": self.name,
            "description": self.description
        }


class TestPluginManager:
    """Test cases for the PluginManager class."""
    
    def test_plugin_registration(self):
        """Test plugin registration."""
        manager = PluginManager()
        plugin = MockPlugin()
        
        manager.register_plugin(plugin)
        plugins = manager.get_plugins()
        
        assert len(plugins) == 1
        assert plugins[0] == plugin
    
    def test_enabled_plugins(self):
        """Test getting enabled plugins."""
        manager = PluginManager()
        plugin = MockPlugin()
        
        manager.register_plugin(plugin)
        enabled_plugins = manager.get_enabled_plugins()
        
        assert len(enabled_plugins) == 1
        assert enabled_plugins[0].is_enabled()
    
    @pytest.mark.asyncio
    async def test_run_plugins(self):
        """Test running plugins on a target."""
        manager = PluginManager()
        plugin = MockPlugin()
        
        manager.register_plugin(plugin)
        results = await manager.run_plugins("example.com")
        
        assert "MockPlugin" in results
        assert results["MockPlugin"]["target"] == "example.com"
        assert results["MockPlugin"]["mock"] is True


if __name__ == "__main__":
    pytest.main([__file__])
