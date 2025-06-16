"""
ReconScan Exit Command Module

Provides clean exit functionality that clears the terminal to remove
all traces of the ReconScan session for security purposes.
"""

import os

class ExitCommand:
    """Exit command for ReconScan CLI with terminal cleanup."""
    
    # Command metadata - self-documenting
    description = "Exit ReconScan safely and clear terminal"
    usage = "exit"
    example = "exit"
    category = "Utilities"
    
    def execute(self, args=None):
        """
        Execute exit command with terminal cleanup.
        
        Args:
            args (str, optional): Not used for exit command
            
        Returns:
            bool: True to signal CLI loop to break
        """
        # Clear the terminal to remove all traces of ReconScan session
        os.system('clear')
        
        # Silent exit - no message to maintain complete OpSec
        return True  # Signal to break the loop