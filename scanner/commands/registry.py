import os
import importlib

class CommandRegistry:
    def __init__(self):
        self.commands = {}
        self.metadata = {}  # Store command metadata
        # TODO: Implement lazy loading for better startup performance
        self._command_modules = {}  # Cache for loaded modules
        self._scanned_commands = None  # Cache for command discovery
        self.load_commands()
    
    def load_commands(self):
        """Scan for command modules without loading them immediately for better performance"""
        if self._scanned_commands is not None:
            return  # Already scanned
            
        commands_dir = os.path.dirname(__file__)
        self._scanned_commands = []
        
        for file in os.listdir(commands_dir):
            if file.endswith('.py') and file not in ['__init__.py', 'registry.py', 'base_command.py']:
                module_name = file[:-3]  # Remove .py extension
                self._scanned_commands.append(module_name)
        
        # Load commands immediately for now (can be optimized to lazy load later)
        for module_name in self._scanned_commands:
            self._load_command_module(module_name)
    
    def _load_command_module(self, module_name):
        """Load a specific command module and extract its command class"""
        if module_name in self._command_modules:
            return  # Already loaded
            
        try:
            module = importlib.import_module(f'scanner.commands.{module_name}')
            self._command_modules[module_name] = module
            
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
            pass  # Skip files that can't be imported
    
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
    
    def execute(self, command_name, args=None):
        """Execute a command by name with optional arguments"""
        if command_name in self.commands:
            command_instance = self.commands[command_name]()
            return command_instance.execute(args)
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

 