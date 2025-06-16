"""
ReconScan Configuration Command Module

Simplified configuration viewer and reset functionality.
Configuration changes are handled by the SetCommand.
"""

import json
from pathlib import Path

class ConfigCommand:
    """
    Simplified configuration management for ReconScan.
    
    Handles viewing and resetting configuration only.
    All setting changes are handled by SetCommand.
    """
    
    # Command metadata - self-documenting for help system
    description = "View and reset scanner configuration"
    usage = "config [show|reset]"
    example = "config show"
    category = "Configuration"
    
    def __init__(self):
        """Initialize configuration viewer."""
        self.config_file = Path("config") / "scanner_config.json"
        
    def execute(self, args=None):
        """
        Execute configuration command with argument parsing.
        
        Args:
            args (str, optional): Command arguments (show/reset)
            
        Returns:
            bool: True if command executed successfully
        """
        try:
            if not args or not args.strip():
                return self._show_config()
            
            action = args.strip().split()[0].lower()
            
            if action == "show":
                return self._show_config()
            elif action == "set":
                print("Use the 'set' command for configuration changes:")
                print("Examples:")
                print("  set proxy http://127.0.0.1:8080")
                print("  set threads 10")
                print("  set verbose false")
                return False
            elif action == "reset":
                return self._reset_config()
            else:
                print("Error: Invalid config command.")
                print("Usage: config [show|reset]")
                print("Examples:")
                print("  config show")
                print("  config reset")
                print("  set proxy http://127.0.0.1:8080  - Change settings")
                return False
                
        except Exception as e:
            print(f"Error executing config command: {str(e)}")
            return False
    
    def _show_config(self):
        """Display current configuration in organized format."""
        try:
            if not self.config_file.exists():
                print("No configuration file found. Use 'set' command to create settings.")
                return False
                
            with open(self.config_file, 'r') as f:
                config = json.load(f)
            
            print("\nRECONSCAN CONFIGURATION")
            print("=" * 50)
            
            for category, settings in config.items():
                print(f"\n{category.upper()} SETTINGS:")
                print("-" * 30)
                
                for setting, value in settings.items():
                    if value is None:
                        display_value = "Not set"
                    elif isinstance(value, str) and value == "":
                        display_value = "Empty"
                    else:
                        display_value = str(value)
                    
                    print(f"  {setting:<20} : {display_value}")
            
            print("\n" + "=" * 50)
            print("Use 'set <category.setting> <value>' to change settings")
            print("Use 'config reset' to restore defaults")
            return True
            
        except (json.JSONDecodeError, IOError) as e:
            print(f"Error reading configuration: {e}")
            return False
    
    def _reset_config(self):
        """Reset configuration to default values using SetCommand."""
        try:
            print("This will reset ALL configuration to default values.")
            confirm = input("Are you sure? (yes/no): ").strip().lower()
            
            if confirm in ["yes", "y"]:
                # Delete existing config file - SetCommand will recreate with defaults
                if self.config_file.exists():
                    self.config_file.unlink()
                print("Configuration reset to defaults.")
                print("New settings will be created when you use 'set' command.")
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
        try:
            if not self.config_file.exists():
                return None
                
            with open(self.config_file, 'r') as f:
                config = json.load(f)
                
            return config.get(category, {}).get(setting)
        except:
            return None
    
    def get_category(self, category):
        """
        Get all settings for a category (for use by other modules).
        
        Args:
            category (str): Configuration category
            
        Returns:
            dict: Category settings or empty dict if not found
        """
        try:
            if not self.config_file.exists():
                return {}
                
            with open(self.config_file, 'r') as f:
                config = json.load(f)
                
            return config.get(category, {})
        except:
            return {}
