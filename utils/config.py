import json
import os
from pathlib import Path
from typing import Dict, Any, Optional

class ConfigManager:
    def __init__(self, config_path: Optional[str] = None):
        """
        Initialize config manager with explicit path.
        Default: project_root/config.json
        """
        self.config_path = config_path or str(Path(__file__).parent.parent / "config.json")
        self._config = self._load_config()

    def _load_config(self) -> Dict[str, Any]:
        """Strict config loader - fails if file is missing or invalid"""
        try:
            with open(self.config_path) as f:
                config = json.load(f)
                self._validate_config(config)
                return config
        except FileNotFoundError:
            raise RuntimeError(
                f"Config file not found at {self.config_path}\n"
                "Create it manually with your API keys"
            )
        except json.JSONDecodeError as e:
            raise RuntimeError(f"Invalid JSON in config: {str(e)}")

    def _validate_config(self, config: Dict[str, Any]):
        """Ensure required keys exist"""
        if not config.get("virustotal"):
            raise ValueError("Missing required 'virustotal' API key in config")

    def get(self, key: str, default: Any = None) -> Any:
        """Get config value with optional default"""
        return self._config.get(key, default)

    def get_nested(self, *keys: str, default: Any = None) -> Any:
        """Access nested config values (e.g., 'google_api.key')"""
        value = self._config
        for key in keys:
            if isinstance(value, dict):
                value = value.get(key)
            else:
                return default
        return value if value is not None else default

# Global instance
config = ConfigManager()
