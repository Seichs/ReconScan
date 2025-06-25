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

def get_version_info():
    """
    Returns version and build information.
    
    Returns:
        str: Version info string
    """
    return "\033[90mv1.4.0-dev | Built with Python\033[0m"

def display_banner():
    """
    Prints the complete banner to console.
    """
    print(get_banner())
    print(get_version_info())

if __name__ == "__main__":
    # For testing the banner directly
    display_banner() 