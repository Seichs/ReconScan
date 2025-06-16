"""
ReconScan Configuration Command Module

Manages all scanner configuration settings including network options,
scan parameters, and runtime preferences. Provides persistent storage
and validation for all configuration values.
"""

import json
import os
import sys
from pathlib import Path

class ConfigCommand:
    """
    Professional configuration management for ReconScan.
    
    Handles reading, writing, validation, and display of all scanner
    configuration options with persistent file-based storage.
    """
    
    # Command metadata - self-documenting for help system
    description = "Configure scanner settings and preferences"
    usage = "config [show|set|reset] [setting] [value]"
    example = "config set proxy http://127.0.0.1:8080"
    category = "Configuration"
    
    def __init__(self):
        """Initialize configuration management system."""
        
        # Define where to store the configuration file
        # NOTE: Using project root/config directory for organization
        self.config_dir = Path("config")
        self.config_file = self.config_dir / "scanner_config.json"
        
        # Ensure config directory exists
        # HACK: Creating directory if it doesn't exist - should be in setup
        self.config_dir.mkdir(exist_ok=True)
        
        # Load system defaults from YAML configuration
        from scanner.config_loader import get_system_config
        system_config = get_system_config()
        yaml_defaults = system_config.get_defaults()
        
        # Define all available configuration options with YAML defaults
        # NOTE: This is the "toy box" - all the settings we can change
        # Runtime settings that merge with YAML system defaults
        self.default_config = {
            # Network and HTTP settings (runtime customizable)
            "network": yaml_defaults.get('network', {
                "proxy": None,                    # HTTP proxy for all requests (e.g., "http://127.0.0.1:8080")
                "timeout": 10,                    # Request timeout in seconds
                "user_agent": "ReconScan/1.0",    # User-Agent header for requests
                "max_redirects": 5,               # Maximum number of redirects to follow
                "verify_ssl": False,              # Whether to verify SSL certificates
                "retry_attempts": 3               # Number of retry attempts for failed requests
            }),
            
            # Scanning behavior settings (runtime customizable)
            "scanning": yaml_defaults.get('scanning', {
                "threads": 5,                     # Number of concurrent scanning threads
                "delay": 0.5,                     # Delay between requests (seconds) 
                "deep_scan": False,               # Enable comprehensive scanning mode
                "follow_redirects": True,         # Follow HTTP redirects automatically
                "scan_timeout": 300,              # Maximum time for entire scan (seconds)
                "max_urls": 1000                  # Maximum URLs to scan per target
            }),
            
            # Payload and exploitation settings (runtime customizable)
            "payloads": {
                "sql_injection_level": "basic",   # SQL injection test level (basic/medium/advanced)
                "xss_encoding": "standard",       # XSS payload encoding (standard/advanced/all)
                "command_injection_os": "auto",   # Target OS for command injection (auto/linux/windows)
                "payload_delay": 2,               # Delay for time-based payloads (seconds)
                "blind_sql_timeout": 5            # Timeout for blind SQL injection tests
            },
            
            # Output and reporting settings (runtime customizable)
            "output": yaml_defaults.get('output', {
                "verbose": True,                  # Enable verbose output
                "save_responses": False,          # Save HTTP responses to files
                "report_format": "json",          # Default report format (json/xml/html)
                "log_level": "INFO",             # Logging level (DEBUG/INFO/WARN/ERROR)
                "color_output": True             # Enable colored terminal output
            })
        }
        
        # Load existing configuration or create with defaults
        self.config = self._load_config()
    
    def execute(self, args=None):
        """
        Execute configuration command with argument parsing.
        
        Args:
            args (str, optional): Command arguments (show/set/reset)
            
        Returns:
            bool: True if command executed successfully
        """
        try:
            # Parse command arguments
            # NOTE: Splitting user input into action and parameters
            if not args or not args.strip():
                # No arguments = show current config
                return self._show_config()
            
            # Split arguments into parts
            parts = args.strip().split()
            action = parts[0].lower()
            
            # Route to appropriate action
            if action == "show":
                return self._show_config()
            elif action == "set" and len(parts) >= 3:
                # Format: config set setting value
                setting = parts[1]
                value = " ".join(parts[2:])  # Join remaining parts for values with spaces
                return self._set_config(setting, value)
            elif action == "reset":
                return self._reset_config()
            else:
                # Invalid command format
                print("Invalid config command format.")
                print("Usage: config [show|set|reset] [setting] [value]")
                print("Examples:")
                print("  config show")
                print("  config set proxy http://127.0.0.1:8080")
                print("  config reset")
                return False
                
        except Exception as e:
            # HACK: Basic error handling - should use proper logging system
            print(f"Error executing config command: {str(e)}")
            return False
    
    def _load_config(self):
        """
        Load configuration from file or create with defaults.
        
        Returns:
            dict: Configuration dictionary
        """
        try:
            # Try to load existing configuration file
            if self.config_file.exists():
                with open(self.config_file, 'r') as f:
                    loaded_config = json.load(f)
                
                # Merge with defaults to ensure all keys exist
                # NOTE: This handles cases where new settings are added to defaults
                return self._merge_configs(self.default_config, loaded_config)
            else:
                # No config file exists, create one with defaults
                self._save_config(self.default_config)
                return self.default_config.copy()
                
        except (json.JSONDecodeError, IOError) as e:
            # Config file is corrupted or unreadable
            print(f"Warning: Config file corrupted ({e}). Using defaults.")
            return self.default_config.copy()
    
    def _save_config(self, config):
        """
        Save configuration to persistent storage.
        
        Args:
            config (dict): Configuration to save
        """
        try:
            # Write configuration to JSON file with nice formatting
            with open(self.config_file, 'w') as f:
                json.dump(config, f, indent=2, sort_keys=True)
        except IOError as e:
            print(f"Error saving configuration: {e}")
    
    def _merge_configs(self, default, loaded):
        """
        Merge loaded config with defaults to handle missing keys.
        
        Args:
            default (dict): Default configuration
            loaded (dict): Loaded configuration
            
        Returns:
            dict: Merged configuration
        """
        # Deep merge two configuration dictionaries
        # NOTE: Ensures loaded config has all default keys even if some are missing
        merged = default.copy()
        
        for category, settings in loaded.items():
            if category in merged and isinstance(settings, dict):
                # Merge category-level settings
                merged[category].update(settings)
            else:
                # Add new category entirely
                merged[category] = settings
                
        return merged
    
    def _show_config(self):
        """Display current configuration in organized format."""
        print("\nRECONSCAN CONFIGURATION")
        print("=" * 50)
        
        # Display each configuration category
        for category, settings in self.config.items():
            print(f"\n{category.upper()} SETTINGS:")
            print("-" * 30)
            
            # Display each setting in the category
            for setting, value in settings.items():
                # Format value for display
                if value is None:
                    display_value = "Not set"
                elif isinstance(value, str) and value == "":
                    display_value = "Empty"
                else:
                    display_value = str(value)
                
                print(f"  {setting:<20} : {display_value}")
        
        print("\n" + "=" * 50)
        print("Use 'config set <category.setting> <value>' to change settings")
        print("Use 'config reset' to restore defaults")
        return True
    
    def _set_config(self, setting, value):
        """
        Set a configuration value with validation.
        
        Args:
            setting (str): Setting name in format 'category.setting'
            value (str): New value to set
            
        Returns:
            bool: True if setting was successful
        """
        try:
            # Parse setting path (e.g., "network.proxy")
            if "." not in setting:
                print(f"Invalid setting format. Use 'category.setting' format.")
                print("Example: network.proxy or scanning.threads")
                return False
            
            category, setting_name = setting.split(".", 1)
            
            # Validate category exists
            if category not in self.config:
                print(f"Unknown category '{category}'.")
                print(f"Available categories: {', '.join(self.config.keys())}")
                return False
            
            # Validate setting exists in category
            if setting_name not in self.config[category]:
                print(f"Unknown setting '{setting_name}' in category '{category}'.")
                print(f"Available settings: {', '.join(self.config[category].keys())}")
                return False
            
            # Convert and validate value based on current type
            old_value = self.config[category][setting_name]
            new_value = self._convert_value(value, type(old_value))
            
            if new_value is None and value.lower() not in ["none", "null", ""]:
                print(f"Invalid value '{value}' for setting '{setting}'.")
                return False
            
            # Update configuration
            self.config[category][setting_name] = new_value
            
            # Save to file
            self._save_config(self.config)
            
            # Confirm change
            print(f"Set {category}.{setting_name} = {new_value}")
            return True
            
        except Exception as e:
            print(f"Error setting configuration: {e}")
            return False
    
    def _convert_value(self, value, target_type):
        """
        Convert string value to appropriate type with validation.
        
        Args:
            value (str): String value to convert
            target_type (type): Target type for conversion
            
        Returns:
            Converted value or None if conversion fails
        """
        try:
            # Handle None/null values
            if value.lower() in ["none", "null", ""]:
                return None
            
            # Convert based on target type
            if target_type == bool:
                # Boolean conversion
                return value.lower() in ["true", "1", "yes", "on", "enabled"]
            elif target_type == int:
                # Integer conversion with validation
                result = int(value)
                if result < 0:
                    print("Warning: Negative values may cause issues.")
                return result
            elif target_type == float:
                # Float conversion with validation
                result = float(value)
                if result < 0:
                    print("Warning: Negative values may cause issues.")
                return result
            else:
                # String value (default)
                return value
                
        except ValueError:
            return None
    
    def _reset_config(self):
        """Reset configuration to default values."""
        try:
            # Confirm reset action
            print("This will reset ALL configuration to default values.")
            confirm = input("Are you sure? (yes/no): ").strip().lower()
            
            if confirm in ["yes", "y"]:
                # Reset to defaults and save
                self.config = self.default_config.copy()
                self._save_config(self.config)
                print("Configuration reset to defaults.")
                return True
            else:
                print("Reset cancelled.")
                return False
                
        except KeyboardInterrupt:
            print("\nReset cancelled.")
            return False
    
    def get_setting(self, category, setting):
        """
        Get a specific configuration value (for use by other modules).
        
        Args:
            category (str): Configuration category
            setting (str): Setting name
            
        Returns:
            Configuration value or None if not found
        """
        # NOTE: This method allows other modules to read configuration
        return self.config.get(category, {}).get(setting)
    
    def get_category(self, category):
        """
        Get all settings for a category (for use by other modules).
        
        Args:
            category (str): Configuration category
            
        Returns:
            dict: Category settings or empty dict if not found
        """
        return self.config.get(category, {})
