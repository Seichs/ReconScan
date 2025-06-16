"""
ReconScan System Configuration Loader

Handles loading and accessing static system configuration from config.yaml.
Provides centralized access to application settings, paths, and defaults.
"""

import yaml
import os
from pathlib import Path

class SystemConfig:
    """
    System configuration loader and accessor for static YAML settings.
    
    Provides centralized access to application version, paths, module settings,
    and other static configuration that rarely changes during runtime.
    """
    
    def __init__(self, config_path="config/config.yaml"):
        """
        Initialize system configuration loader.
        
        Args:
            config_path (str): Path to the system configuration YAML file
        """
        self.config_path = Path(config_path)
        self.config = self._load_config()
    
    def _load_config(self):
        """
        Load system configuration from YAML file.
        
        Returns:
            dict: Configuration dictionary or defaults if loading fails
        """
        try:
            if self.config_path.exists():
                with open(self.config_path, 'r', encoding='utf-8') as f:
                    return yaml.safe_load(f) or {}
            else:
                print(f"Warning: System config file {self.config_path} not found. Using minimal defaults.")
                return self._get_minimal_defaults()
        except yaml.YAMLError as e:
            print(f"Error parsing YAML config: {e}. Using minimal defaults.")
            return self._get_minimal_defaults()
        except Exception as e:
            print(f"Error loading system config: {e}. Using minimal defaults.")
            return self._get_minimal_defaults()
    
    def _get_minimal_defaults(self):
        """
        Provide minimal default configuration if YAML loading fails.
        
        Returns:
            dict: Minimal default configuration
        """
        return {
            "app": {
                "name": "ReconScan",
                "version": "1.0.0-unknown",
                "build": "unknown",
                "description": "Web Application Vulnerability Scanner"
            },
            "system": {
                "min_python_version": "3.8"
            }
        }
    
    def get(self, key_path, default=None):
        """
        Get configuration value using dot notation path.
        
        Args:
            key_path (str): Dot-separated path to config value (e.g., "app.version")
            default: Default value if key not found
            
        Returns:
            Configuration value or default
        """
        try:
            keys = key_path.split('.')
            value = self.config
            
            for key in keys:
                if isinstance(value, dict) and key in value:
                    value = value[key]
                else:
                    return default
            
            return value
        except Exception:
            return default
    
    def get_app_info(self):
        """
        Get application information (name, version, etc.).
        
        Returns:
            dict: Application information
        """
        return self.config.get('app', {})
    
    def get_version(self):
        """
        Get application version string.
        
        Returns:
            str: Version string
        """
        return self.get('app.version', '1.0.0-unknown')
    
    def get_build(self):
        """
        Get application build string.
        
        Returns:
            str: Build string
        """
        return self.get('app.build', 'unknown')
    
    def get_python_requirement(self):
        """
        Get minimum Python version requirement.
        
        Returns:
            str: Python version requirement
        """
        return self.get('system.min_python_version', '3.8+')
    
    def get_paths(self):
        """
        Get all configured file paths.
        
        Returns:
            dict: Path configurations
        """
        return self.config.get('paths', {})
    
    def get_defaults(self, category=None):
        """
        Get default configuration values.
        
        Args:
            category (str, optional): Specific category (network, scanning, output)
            
        Returns:
            dict: Default values for category or all defaults
        """
        defaults = self.config.get('defaults', {})
        if category:
            return defaults.get(category, {})
        return defaults
    
    def get_modules_config(self):
        """
        Get module configuration settings.
        
        Returns:
            dict: Module configuration
        """
        return self.config.get('modules', {})
    
    def get_payload_defaults(self, payload_type=None):
        """
        Get default payload configurations.
        
        Args:
            payload_type (str, optional): Specific payload type
            
        Returns:
            dict: Payload defaults for type or all payload defaults
        """
        payload_defaults = self.config.get('payload_defaults', {})
        if payload_type:
            return payload_defaults.get(payload_type, {})
        return payload_defaults

# Global system configuration instance
# NOTE: Single instance for application-wide access
_system_config = None

def get_system_config():
    """
    Get global system configuration instance.
    
    Returns:
        SystemConfig: Global system configuration instance
    """
    global _system_config
    if _system_config is None:
        _system_config = SystemConfig()
    return _system_config 