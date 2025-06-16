"""
ReconScan Status Command Module

Displays comprehensive system status including configuration summary,
available modules, system information, and scanner readiness status.
"""

import json
import os
import sys
from pathlib import Path
import platform

class StatusCommand:
    """
    System status and information display for ReconScan.
    
    Provides comprehensive overview of scanner configuration, available
    modules, system environment, and operational readiness status.
    """
    
    # Command metadata - self-documenting for help system
    description = "Display system status and configuration summary"
    usage = "status [--verbose]"
    example = "status"
    category = "Information"
    
    def __init__(self):
        """Initialize status command with system information gathering."""
        
        # Load system configuration
        from scanner.config_loader import get_system_config
        self.system_config = get_system_config()
        
        # Load runtime configuration
        from scanner.commands.config import ConfigCommand
        self.config_cmd = ConfigCommand()
        
    def execute(self, args=None):
        """
        Execute status command with optional verbose output.
        
        Args:
            args (str, optional): Command arguments (--verbose for detailed output)
            
        Returns:
            bool: True if command executed successfully
        """
        try:
            verbose = args and "--verbose" in args.lower() if args else False
            
            print("=" * 60)
            print("ReconScan System Status")
            print("=" * 60)
            
            # Display basic system information
            self._show_system_info()
            
            # Display configuration summary
            self._show_config_summary(verbose)
            
            # Display available commands
            self._show_available_commands()
            
            # Display system readiness
            self._show_readiness_status()
            
            if verbose:
                self._show_detailed_info()
            
            print("=" * 60)
            return True
            
        except Exception as e:
            print(f"Error displaying status: {str(e)}")
            return False
    
    def _show_system_info(self):
        """Display basic system and application information."""
        app_info = self.system_config.get_app_info()
        
        print(f"\nApplication: {app_info['name']} v{app_info['version']} ({app_info['build']})")
        print(f"Author: {app_info['author']}")
        print(f"Description: {app_info['description']}")
        
        # System environment
        print(f"\nSystem: {platform.system()} {platform.release()}")
        print(f"Python: {platform.python_version()}")
        print(f"Architecture: {platform.machine()}")
        
    def _show_config_summary(self, verbose=False):
        """Display configuration summary."""
        print(f"\nConfiguration Summary:")
        print("-" * 25)
        
        config = self.config_cmd.config
        
        # Network settings
        network = config.get('network', {})
        proxy_status = "Enabled" if network.get('proxy') else "Disabled"
        print(f"Proxy: {proxy_status}")
        print(f"Timeout: {network.get('timeout', 'N/A')}s")
        print(f"SSL Verification: {'Enabled' if network.get('verify_ssl') else 'Disabled'}")
        
        # Scanning settings
        scanning = config.get('scanning', {})
        print(f"Threads: {scanning.get('threads', 'N/A')}")
        print(f"Deep Scan: {'Enabled' if scanning.get('deep_scan') else 'Disabled'}")
        print(f"Max URLs: {scanning.get('max_urls', 'N/A')}")
        
        # Output settings
        output = config.get('output', {})
        print(f"Verbose Output: {'Enabled' if output.get('verbose') else 'Disabled'}")
        print(f"Report Format: {output.get('report_format', 'N/A')}")
        print(f"Log Level: {output.get('log_level', 'N/A')}")
        
        if verbose:
            print(f"\nConfiguration File: {self.config_cmd.config_file}")
            
    def _show_available_commands(self):
        """Display available commands by category."""
        print(f"\nAvailable Commands:")
        print("-" * 20)
        
        try:
            # Import and use the command registry
            from scanner.commands.registry import CommandRegistry
            registry = CommandRegistry()
            
            # Get commands by category
            commands_by_category = registry.get_commands_by_category()
            
            for category, commands in commands_by_category.items():
                print(f"\n{category}:")
                for cmd_name, cmd_info in commands.items():
                    print(f"  {cmd_name:<12} - {cmd_info['description']}")
                    
        except Exception as e:
            # Fallback if registry isn't available
            print("  help         - Display help information")
            print("  config       - Configure scanner settings")
            print("  status       - Display system status")
            print("  clear        - Clear terminal screen")
            print("  exit         - Exit ReconScan")
            
    def _show_readiness_status(self):
        """Display system readiness and health checks."""
        print(f"\nSystem Readiness:")
        print("-" * 18)
        
        status_items = []
        
        # Check configuration file
        config_status = "✓ OK" if self.config_cmd.config_file.exists() else "✗ Missing"
        status_items.append(f"Configuration: {config_status}")
        
        # Check Python version
        python_version = sys.version_info
        python_status = "✓ OK" if python_version >= (3, 7) else "✗ Outdated"
        status_items.append(f"Python Version: {python_status}")
        
        # Check write permissions
        try:
            test_file = Path("config") / ".write_test"
            test_file.touch()
            test_file.unlink()
            write_status = "✓ OK"
        except:
            write_status = "✗ No Write Access"
        status_items.append(f"Write Permissions: {write_status}")
        
        # Check dependencies
        deps_status = "✓ OK"  # Assume OK since we're running
        try:
            import yaml
        except ImportError:
            deps_status = "✗ Missing PyYAML"
        status_items.append(f"Dependencies: {deps_status}")
        
        for item in status_items:
            print(f"  {item}")
            
        # Overall status
        all_ok = all("✓" in item for item in status_items)
        overall_status = "Ready" if all_ok else "Issues Detected"
        print(f"\nOverall Status: {overall_status}")
        
    def _show_detailed_info(self):
        """Display detailed verbose information."""
        print(f"\nDetailed Information:")
        print("-" * 22)
        
        # Environment variables
        relevant_vars = ['PATH', 'PYTHONPATH', 'HOME', 'USER']
        print("Environment Variables:")
        for var in relevant_vars:
            value = os.environ.get(var, 'Not Set')
            # Truncate long paths for readability
            if len(value) > 50:
                value = value[:47] + "..."
            print(f"  {var}: {value}")
            
        # Working directory
        print(f"\nWorking Directory: {os.getcwd()}")
        
        # Configuration file details
        if self.config_cmd.config_file.exists():
            stat = self.config_cmd.config_file.stat()
            print(f"Config File Size: {stat.st_size} bytes")
            print(f"Config Last Modified: {stat.st_mtime}")
