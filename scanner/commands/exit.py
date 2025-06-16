class ExitCommand:
    """Exit command for ReconScan CLI."""
    
    # Command metadata - self-documenting
    description = "Exit ReconScan safely"
    usage = "exit"
    example = "exit"
    category = "Utilities"
    
    def execute(self, args=None):
        print("Exiting ReconScan. Stay secure.")
        return True  # Signal to break the loop