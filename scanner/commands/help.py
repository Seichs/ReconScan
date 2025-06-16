"""
ReconScan Help Command Module

Provides comprehensive help information for all available commands,
usage examples, and system status information.
"""

import os
import sys

class HelpCommand:
    """
    Professional help system for ReconScan CLI tool.
    
    Displays available commands, usage examples, and system information
    in a structured, user-friendly format.
    """
    
    # Command metadata - self-documenting
    description = "Display this help information"
    usage = "help [command]"
    example = "help scan"
    category = "Utilities"
    
    def __init__(self):
        """Initialize help command with dynamic command loading."""
        # Import here to avoid circular imports
        from scanner.commands.registry import CommandRegistry
        from scanner.config_loader import get_system_config
        
        self.registry = CommandRegistry()
        
        # Load version info from system configuration
        self.system_config = get_system_config()
        self.version_info = {
            'version': self.system_config.get_version(),
            'build': self.system_config.get_build(),
            'python_req': self.system_config.get_python_requirement()
        }
    
    def execute(self, args=None):
        """
        Execute help command with optional specific command lookup.
        
        Args:
            args (str, optional): Specific command to get help for
            
        Returns:
            bool: True if help was displayed successfully
        """
        try:
            if args and args.strip():
                # Show help for specific command
                command = args.strip().lower()
                self._show_command_help(command)
            else:
                # Show general help
                self._show_general_help()
            
            return True
            
        except Exception as e:
            # HACK: Basic error handling - should use proper logging
            print(f"Error displaying help: {str(e)}")
            return False
    
    def _show_general_help(self):
        """Display comprehensive help overview."""
        print("\n" + "="*60)
        print("RECONSCAN - Web Application Security Scanner")
        print("="*60)
        print(f"Version: {self.version_info['version']} ({self.version_info['build']})")
        print(f"Python: {self.version_info['python_req']} | Current: {sys.version.split()[0]}")
        print("="*60)
        
        print("\nAVAILABLE COMMANDS:")
        print("-" * 40)
        
        # Get commands grouped by category from registry
        categories = self.registry.get_commands_by_category()
        
        for category, commands in categories.items():
            print(f"\n{category}:")
            for cmd in commands:
                metadata = self.registry.get_command_metadata(cmd)
                print(f"  {cmd:<12} - {metadata['description']}")
        
        print("\n" + "-" * 40)
        print("USAGE:")
        print("  * Type 'help <command>' for detailed command information")
        print("  * Type 'status' to check system readiness")
        print("  * Type 'config show' to view current settings")
        
        # TODO: Add recent scan statistics
        # TODO: Add system health check indicators
        print("\n" + "="*60)
    
    def _show_command_help(self, command):
        """
        Display detailed help for a specific command.
        
        Args:
            command (str): Command name to show help for
        """
        if not self.registry.has_command(command):
            print(f"\n Unknown command: '{command}'")
            print(" Type 'help' to see all available commands.")
            return
        
        metadata = self.registry.get_command_metadata(command)
        
        print(f"\nCOMMAND HELP: {command.upper()}")
        print("="*50)
        print(f"Description: {metadata['description']}")
        print(f"Usage:       {metadata['usage']}")
        print(f"Example:     {metadata['example']}")
        
        # TODO: Add command-specific options and flags
        # TODO: Add related commands suggestions
        
        print("\n" + "="*50)
    
    def get_command_list(self):
        """
        Return list of available commands for other modules.
        
        Returns:
            list: Available command names
        """
        # NOTE: Used by other modules to get command availability
        return self.registry.list_commands()
