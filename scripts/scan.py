"""
ReconScan CLI Entry Point

Main command-line interface for ReconScan vulnerability scanner.
Provides interactive command prompt and banner display functionality.
"""

import sys
import os

# Add project root to path if needed
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from scanner.commands.registry import CommandRegistry
from scanner.banner import get_banner

class CLIInterface:
    """
    Command-line interface for ReconScan vulnerability scanner.
    
    Provides interactive command prompt with command auto-discovery,
    banner display, and user input handling for security testing operations.
    """
    
    def __init__(self):
        """Initialize the CLI interface with command registry."""
        self.command_registry = CommandRegistry()

    def display_welcome_screen(self):
        """
        Display the ReconScan welcome banner and available commands.
        
        Shows the ASCII art banner and organizes commands by category
        for easy user reference and navigation.
        """
        print(get_banner())
        print("Available commands:")
        
        # Get commands organized by category from registry
        commands_by_category = self.command_registry.get_commands_by_category()
        
        for category_name, command_list in commands_by_category.items():
            print(f"\n{category_name}:")
            for command_name in command_list:
                command_metadata = self.command_registry.get_command_metadata(command_name)
                print(f"  {command_name:<10} - {command_metadata['description']}")
        
        print("\nType a command to begin:")

    def start_interactive_prompt(self):
        """
        Start the interactive command prompt loop.
        
        Continuously prompts for user input, parses commands and arguments,
        and executes valid commands until the user exits the application.
        """
        while True:
            user_input = input("ReconScan> ").strip()
            
            if not user_input:
                continue
                
            # Parse command and arguments - split into command and remaining args
            input_parts = user_input.split(None, 1)  # Split into max 2 parts
            command_name = input_parts[0].lower()
            command_args = input_parts[1] if len(input_parts) > 1 else None
            
            if self.command_registry.has_command(command_name):
                execution_result = self.command_registry.execute(command_name, command_args)
                # Special handling for exit command - terminate the loop
                if command_name == "exit" and execution_result:
                    break
            else:
                print(f"Unknown command '{command_name}'. Type 'help' for available commands.")

    def display(self):
        """Legacy method for backward compatibility."""
        self.display_welcome_screen()

    def prompt(self):
        """Legacy method for backward compatibility."""
        self.start_interactive_prompt()

def main():
    """
    Main entry point for the ReconScan CLI application.
    
    Creates the CLI interface, displays the welcome screen,
    and starts the interactive command prompt.
    """
    cli_interface = CLIInterface()
    cli_interface.display_welcome_screen()
    cli_interface.start_interactive_prompt()

if __name__ == "__main__":
    main()