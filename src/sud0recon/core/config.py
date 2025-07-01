"""
Configuration management for Sud0Recon

This module handles all configuration settings for the application.
"""

import json
import os
from pathlib import Path
from pydantic import BaseModel, Field


class DatabaseConfig(BaseModel):
    """Database configuration settings."""

    type: str = Field(default="sqlite", description="Database type")
    path: str = Field(default="sud0recon.db", description="Database file path")


class ScanConfig(BaseModel):
    """Scanning configuration settings."""

    max_concurrent: int = Field(default=50,
                                description="Maximum concurrent scans")
    timeout: int = Field(default=30, description="Scan timeout in seconds")
    retries: int = Field(
        default=3,
        description="Number of retries for failed scans")
    delay: float = Field(
        default=0.1,
        description="Delay between scans in seconds")


class ReportConfig(BaseModel):
    """Report generation configuration."""

    output_dir: str = Field(default="reports",
                            description="Output directory for reports")
    formats: list = Field(
        default=[
            "json",
            "html"],
        description="Report formats to generate")


class Config(BaseModel):
    """Main configuration class for Sud0Recon."""

    database: DatabaseConfig = DatabaseConfig()
    scanning: ScanConfig = ScanConfig()
    reporting: ReportConfig = ReportConfig()

    @classmethod
    def load_from_file(cls, config_path: str) -> "Config":
        """Load configuration from JSON file."""
        try:
            with open(config_path, 'r') as f:
                config_data = json.load(f)
            return cls(**config_data)
        except FileNotFoundError:
            return cls()  # Return default config if file not found
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid JSON in config file: {e}")

    def save_to_file(self, config_path: str) -> None:
        """Save configuration to JSON file."""
        os.makedirs(os.path.dirname(config_path), exist_ok=True)
        with open(config_path, 'w') as f:
            json.dump(self.dict(), f, indent=2)

    @classmethod
    def get_default_config_path(cls) -> str:
        """Get the default configuration file path."""
        home_dir = Path.home()
        config_dir = home_dir / ".sud0recon"
        config_dir.mkdir(exist_ok=True)
        return str(config_dir / "config.json")
