import os
import importlib

class CommandRegistry:
    def __init__(self):
        self.commands = {}
        self.metadata = {}  # Store command metadata
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
                            
                            # Extract metadata from command class
                            self.metadata[command_name] = self._extract_metadata(attr)
                            break
                except ImportError:
                    continue  # Skip files that can't be imported
    
    def _extract_metadata(self, command_class):
        """
        Extract metadata from command class.
        
        Args:
            command_class: The command class to extract metadata from
            
        Returns:
            dict: Command metadata
        """
        return {
            'description': getattr(command_class, 'description', 'No description available'),
            'usage': getattr(command_class, 'usage', f'{command_class.__name__.lower().replace("command", "")}'),
            'example': getattr(command_class, 'example', 'No example available'),
            'category': getattr(command_class, 'category', 'Uncategorized')
        }
    
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
    
    def get_command_metadata(self, command_name=None):
        """
        Get metadata for a specific command or all commands.
        
        Args:
            command_name (str, optional): Specific command name
            
        Returns:
            dict: Command metadata
        """
        if command_name:
            return self.metadata.get(command_name, {})
        return self.metadata
    
    def get_commands_by_category(self):
        """
        Group commands by category for organized display.
        
        Returns:
            dict: Commands grouped by category
        """
        categories = {}
        for cmd_name, metadata in self.metadata.items():
            category = metadata['category']
            if category not in categories:
                categories[category] = []
            categories[category].append(cmd_name)
        return categories

# TODO: Feature to implement later
# FIXME: Known issue that needs addressing  
# HACK: Temporary solution, needs refactoring
# NOTE: Important implementation detail
# WARNING: Security consideration 