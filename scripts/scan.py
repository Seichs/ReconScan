import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from scanner.commands.registry import CommandRegistry

class CLIInterface:
    def __init__(self):
        self.banner = """
\033[92m
| ___ \\                   /  ___|
| |_/ /___  ___ ___  _ __ \\ `--.  ___ __ _ _ __
|    // _ \\/ __/ _ \\| '_ \\ `--. \\/ __/ _` | '_ |
| |\\ \\  __/ (_| (_) | | | /\\__/ / (_| (_| | | | |
\\_| \\_\\___|\\___\\___/|_| |_|\\____/\\___\\__,_|_| |_|

\033[91m              [:: ReconScan ::]\033[0m
\033[90m     Web Application Vulnerability Scanner\033[0m
"""

        # Initialize the command registry
        self.registry = CommandRegistry()
        
        # Define command descriptions for display
        self.command_descriptions = {
            "scan": "Run a scan against a target URL",
            "config": "Edit or view the scan configuration", 
            "report": "View or generate reports",
            "exit": "Exit the program",
            "help": "Show help information",
            "status": "Show scanner status",
            "clear": "Clear the screen",
            "payloads": "Manage payloads",
            "modules": "Manage scan modules",
            "deface": "Website defacement tools",
            "set": "Set configuration options",
            "run": "Run specific operations"
        }

    def display(self):
        print(self.banner)
        print("Available commands:")
        available_commands = self.registry.list_commands()
        for cmd in available_commands:
            desc = self.command_descriptions.get(cmd, "No description available")
            print(f"  {cmd:<10} - {desc}")
        print("\nType a command to begin:")

    def prompt(self):
        while True:
            user_input = input("ReconScan> ").strip()
            
            if not user_input:
                continue
                
            # Parse command and arguments
            parts = user_input.split(None, 1)  # Split into max 2 parts
            command = parts[0].lower()
            args = parts[1] if len(parts) > 1 else None
            
            if self.registry.has_command(command):
                result = self.registry.execute(command, args)
                # Special handling for exit command
                if command == "exit" and result:
                    break
            else:
                print("Unknown command.")

def main():
    cli = CLIInterface()
    cli.display()
    cli.prompt()

if __name__ == "__main__":
    main()