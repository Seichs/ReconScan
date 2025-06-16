import sys
import os

# Add project root to path if needed
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

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

    def display(self):
        print(self.banner)
        print("Available commands:")
        
        # Get commands organized by category from registry
        commands_by_category = self.registry.get_commands_by_category()
        
        for category, commands in commands_by_category.items():
            print(f"\n{category}:")
            for cmd in commands:
                metadata = self.registry.get_command_metadata(cmd)
                print(f"  {cmd:<10} - {metadata['description']}")
        
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