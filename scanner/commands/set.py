"""
ReconScan Set Command Module

Enhanced configuration setting with convenient shortcuts and full validation.
Provides both shorthand (set proxy) and full syntax (set network.proxy).
"""

import json
import os
from pathlib import Path

class SetCommand:
    """
    Enhanced configuration setter for ReconScan.
    
    Supports both shorthand commands (set proxy) and full syntax (set network.proxy)
    with comprehensive validation and type conversion.
    """
    
    # Command metadata - self-documenting for help system
    description = "Set configuration values with shorthand support"
    usage = "set <setting|shorthand> <value>"
    example = "set proxy http://127.0.0.1:8080"
    category = "Configuration"
    
    def __init__(self):
        """Initialize set command with config system and shorthand mappings."""
        
        # Define where to store the configuration file
        self.config_dir = Path("config")
        self.config_file = self.config_dir / "scanner_config.json"
        
        # Load system defaults
        from scanner.config_loader import get_system_config
        system_config = get_system_config()
        yaml_defaults = system_config.get_defaults()
        
        # Define configuration defaults (copied from ConfigCommand)
        self.default_config = {
            "network": yaml_defaults.get('network', {
                "proxy": None,
                "timeout": 10,
                "user_agent": "ReconScan/1.0",
                "max_redirects": 5,
                "verify_ssl": False,
                "retry_attempts": 3
            }),
            "scanning": yaml_defaults.get('scanning', {
                "threads": 5,
                "delay": 0.5,
                "deep_scan": False,
                "follow_redirects": True,
                "scan_timeout": 300,
                "max_urls": 1000
            }),
            "payloads": {
                "sql_injection_level": "basic",
                "xss_encoding": "standard",
                "command_injection_os": "auto",
                "payload_delay": 2,
                "blind_sql_timeout": 5
            },
            "output": yaml_defaults.get('output', {
                "verbose": True,
                "save_responses": False,
                "report_format": "json",
                "log_level": "INFO",
                "color_output": True
            })
        }
        
        # Load existing configuration
        self.config = self._load_config()
        
        # Define shorthand mappings for convenience
        self.shortcuts = {
            # Network shortcuts
            "proxy": "network.proxy",
            "timeout": "network.timeout",
            "useragent": "network.user_agent",
            "user_agent": "network.user_agent",
            "ssl": "network.verify_ssl",
            "verify_ssl": "network.verify_ssl",
            "redirects": "network.max_redirects",
            "retry": "network.retry_attempts",
            
            # Scanning shortcuts  
            "threads": "scanning.threads",
            "delay": "scanning.delay",
            "deep": "scanning.deep_scan",
            "deep_scan": "scanning.deep_scan",
            "follow": "scanning.follow_redirects",
            "follow_redirects": "scanning.follow_redirects",
            "scan_timeout": "scanning.scan_timeout",
            "max_urls": "scanning.max_urls",
            
            # Payload shortcuts
            "sql_level": "payloads.sql_injection_level",
            "xss_encoding": "payloads.xss_encoding",
            "cmd_os": "payloads.command_injection_os",
            "payload_delay": "payloads.payload_delay",
            "blind_timeout": "payloads.blind_sql_timeout",
            
            # Output shortcuts
            "verbose": "output.verbose",
            "save": "output.save_responses",
            "save_responses": "output.save_responses",
            "format": "output.report_format",
            "report_format": "output.report_format",
            "log_level": "output.log_level",
            "color": "output.color_output",
            "color_output": "output.color_output"
        }
        
    def execute(self, args=None):
        """
        Execute set command with setting and value.
        
        Args:
            args (str, optional): Setting and value arguments
            
        Returns:
            bool: True if setting was applied successfully
        """
        try:
            if not args or not args.strip():
                self._show_usage()
                return False
            
            # Parse arguments
            parts = args.strip().split()
            
            if len(parts) < 2:
                print("Error: Missing value for setting.")
                self._show_usage()
                return False
            
            # Extract setting and value
            original_setting = parts[0]
            value = " ".join(parts[1:])  # Join remaining parts for values with spaces
            
            # Resolve shorthand to full setting name
            full_setting = self._resolve_setting(original_setting)
            
            return self._set_config(full_setting, value, original_setting)
            
        except Exception as e:
            print(f"Error executing set command: {str(e)}")
            return False
    
    def _resolve_setting(self, setting):
        """
        Resolve shorthand setting to full category.setting format.
        
        Args:
            setting (str): Setting name (shorthand or full)
            
        Returns:
            str: Full setting name in category.setting format
        """
        # If it's already in full format, return as-is
        if "." in setting:
            return setting
        
        # Check if it's a known shorthand
        if setting.lower() in self.shortcuts:
            return self.shortcuts[setting.lower()]
        
        # Not a known shorthand, return as-is (will be validated later)
        return setting
    
    def _show_usage(self):
        """Display usage information with shortcuts."""
        print("Usage: set <setting|shorthand> <value>")
        print("\nCommon shortcuts:")
        print("  proxy         - network.proxy")
        print("  threads       - scanning.threads")
        print("  verbose       - output.verbose")
        print("  timeout       - network.timeout")
        print("  delay         - scanning.delay")
        print("  ssl           - network.verify_ssl")
        print("\nExamples:")
        print("  set proxy http://127.0.0.1:8080")
        print("  set threads 10")
        print("  set verbose false")
        print("  set network.proxy none      - Full syntax")
        print("\nUse 'config show' to view all settings")
    
    def _load_config(self):
        """Load configuration from file or create with defaults."""
        try:
            if self.config_file.exists():
                with open(self.config_file, 'r') as f:
                    loaded_config = json.load(f)
                return self._merge_configs(self.default_config, loaded_config)
            else:
                self._save_config(self.default_config)
                return self.default_config.copy()
        except (json.JSONDecodeError, IOError) as e:
            print(f"Warning: Config file corrupted ({e}). Using defaults.")
            return self.default_config.copy()
    
    def _save_config(self, config):
        """Save configuration to persistent storage."""
        try:
            self.config_dir.mkdir(exist_ok=True)
            with open(self.config_file, 'w') as f:
                json.dump(config, f, indent=2, sort_keys=True)
        except IOError as e:
            print(f"Error saving configuration: {e}")
    
    def _merge_configs(self, default, loaded):
        """Merge loaded config with defaults to handle missing keys."""
        merged = default.copy()
        for category, settings in loaded.items():
            if category in merged and isinstance(settings, dict):
                merged[category].update(settings)
            else:
                merged[category] = settings
        return merged
    
    def _set_config(self, setting, value, original_setting=None):
        """
        Set a configuration value with validation.
        
        Args:
            setting (str): Setting name in format 'category.setting'
            value (str): New value to set
            original_setting (str, optional): Original setting name user typed
            
        Returns:
            bool: True if setting was successful
        """
        try:
            # Parse setting path (e.g., "network.proxy")
            if "." not in setting:
                print(f"Error: Invalid setting '{setting}'.")
                print("Try a shorthand like: proxy, threads, verbose")
                print("Or use full format: category.setting")
                return False
            
            category, setting_name = setting.split(".", 1)
            
            # Validate category exists
            if category not in self.config:
                print(f"Error: Unknown category '{category}'.")
                print(f"Available categories: {', '.join(self.config.keys())}")
                return False
            
            # Validate setting exists in category
            if setting_name not in self.config[category]:
                print(f"Error: Unknown setting '{setting_name}' in '{category}'.")
                print(f"Available settings: {', '.join(self.config[category].keys())}")
                return False
            
            # Convert and validate value
            old_value = self.config[category][setting_name]
            new_value = self._convert_value(value, type(old_value))
            
            if new_value is None and value.lower() not in ["none", "null", ""]:
                print(f"Error: Invalid value '{value}' for '{setting}'.")
                print(f"Expected type: {type(old_value).__name__}")
                if type(old_value) == bool:
                    print("Valid boolean values: true, false, 1, 0, yes, no")
                elif type(old_value) == int:
                    print("Expected: whole number (e.g., 10, 5, 100)")
                elif type(old_value) == float:
                    print("Expected: decimal number (e.g., 1.5, 0.5, 2.0)")
                return False
            
            # Update configuration
            self.config[category][setting_name] = new_value
            
            # Save to file
            self._save_config(self.config)
            
            # Confirm change using original setting name if provided
            display_setting = original_setting if original_setting else setting
            print(f"Set {display_setting} = {new_value}")
            return True
            
        except KeyError:
            print(f"Error: Setting '{setting}' not found.")
            return False
        except Exception as e:
            print(f"Error setting configuration: {e}")
            return False
    
    def _convert_value(self, value, target_type):
        """Convert string value to appropriate type with validation."""
        try:
            if value.lower() in ["none", "null", ""]:
                return None
            
            if target_type == bool:
                return value.lower() in ["true", "1", "yes", "on", "enabled"]
            elif target_type == int:
                result = int(value)
                if result < 0:
                    print("Warning: Negative values may cause issues.")
                return result
            elif target_type == float:
                result = float(value)
                if result < 0:
                    print("Warning: Negative values may cause issues.")
                return result
            else:
                return value
        except ValueError:
            return None
