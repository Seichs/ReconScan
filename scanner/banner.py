"""
Banner module for ReconScan CLI application.
Contains ASCII art and formatting for the application banner.
"""

def get_banner():
    """
    Returns the ASCII art banner for ReconScan.
    
    Returns:
        str: Formatted banner string with colors and branding
    """
    return """
\033[92m
| ___ \\                   /  ___|
| |_/ /___  ___ ___  _ __ \\ `--.  ___ __ _ _ __
|    // _ \\/ __/ _ \\| '_ \\ `--. \\/ __/ _` | '_ |
| |\\ \\  __/ (_| (_) | | | /\\__/ / (_| (_| | | | |
\\_| \\_\\___|\\___\\___/|_| |_|\\____/\\___\\__,_|_| |_|

\033[91m              [:: ReconScan ::]\033[0m
\033[90m     Web Application Vulnerability Scanner\033[0m
"""

def display_banner():
    """
    Prints the complete banner to console.
    
    This function is provided for convenience when you want to display
    the banner without additional formatting or version information.
    """
    print(get_banner()) 