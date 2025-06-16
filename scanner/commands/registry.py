import os
import importlib

class CommandRegistry:
    def __init__(self):
        self.commands = {}
        self.load_commands()
    
    def load_commands(self):
        """Automatically load all command classes from the commands directory"""
        commands_dir = os.path.dirname(__file__)
        
        for file in os.listdir(commands_dir):
            if file.endswith('.py') and file not in ['__init__.py', 'registry.py', 'base_command.py']:
                try:
                    module_name = file[:-3]  # Remove .py extension
                    module = importlib.import_module(f'scanner.commands.{module_name}')
                    
                    # Look for a class ending with 'Command'
                    for attr_name in dir(module):
                        attr = getattr(module, attr_name)
                        if (isinstance(attr, type) and 
                            attr_name.endswith('Command') and 
                            hasattr(attr, 'execute')):
                            command_name = module_name  # Use filename as command name
                            self.commands[command_name] = attr
                            break
                except ImportError:
                    continue  # Skip files that can't be imported
    
    def execute(self, command_name):
        """Execute a command by name"""
        if command_name in self.commands:
            command_instance = self.commands[command_name]()
            return command_instance.execute()
        return False
    
    def list_commands(self):
        """Return list of available commands"""
        return list(self.commands.keys())
    
    def has_command(self, command_name):
        """Check if command exists"""
        return command_name in self.commands 