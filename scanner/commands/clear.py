"""
ReconScan Clear Command Module

Clears the terminal screen and redisplays the ReconScan home screen
by reusing the existing CLI display logic.
"""

import os

class ClearCommand:
    """
    Clear terminal and redisplay ReconScan home screen.
    
    Provides a clean slate by clearing the terminal and showing
    the welcome banner with available commands.
    """
    
    # Command metadata - self-documenting for help system
    description = "Clear the terminal screen and show home screen"
    usage = "clear"
    example = "clear"
    category = "Utilities"
    
    def execute(self, args=None):
        """
        Execute clear command to reset to home screen.
        
        Args:
            args (str, optional): Not used for clear command
            
        Returns:
            bool: True if screen was cleared and home displayed successfully
        """
        try:
            # Clear the terminal screen (Linux-based systems)
            os.system('clear')
            
            # Reuse the existing CLI display logic instead of duplicating code
            self._show_home_screen()
            
            return True
                
        except Exception as e:
            # FIXME: Implement proper logging system for error tracking
            print(f"Error clearing screen: {str(e)}")
            return False
    
    def _show_home_screen(self):
        """Display the ReconScan home screen by reusing CLI display logic."""
        try:
            # Import and use the existing CLI display logic
            from scripts.scan import CLIInterface
            
            # Create CLI instance and use its display method
            cli = CLIInterface()
            cli.display()
            
        except Exception as e:
            # Fallback to basic display if import fails
            print("ReconScan - Web Application Vulnerability Scanner")
            print("Type 'help' for available commands.")
