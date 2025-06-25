"""
Banner module for ReconScan CLI application.
Contains ASCII art and formatting for the application banner.
"""

import re

def hex_to_ansi_256(hex_color):
    """Convert hex color to closest ANSI 256-color code."""
    if hex_color.upper() == "#000000":
        return None  # Will be handled as invisible
    
    # Convert hex to RGB
    hex_color = hex_color.lstrip('#')
    if len(hex_color) != 6:
        return "\033[38;5;208m"  # Default orange
        
    r = int(hex_color[0:2], 16)
    g = int(hex_color[2:4], 16) 
    b = int(hex_color[4:6], 16)
    
    # Map the orange/red color palette from the HTML to ANSI colors
    if r >= 240:  # Very bright reds/oranges
        return "\033[38;5;202m"  # Bright red-orange
    elif r >= 220:  # Bright oranges
        return "\033[38;5;208m"  # Orange
    elif r >= 200:  # Medium oranges
        return "\033[38;5;214m"  # Yellow-orange
    elif r >= 180:  # Dark oranges
        return "\033[38;5;172m"  # Dark orange
    elif r >= 160:  # Browns
        return "\033[38;5;130m"  # Brown
    elif r >= 100:  # Dark browns
        return "\033[38;5;94m"   # Dark brown
    elif r >= 50:   # Very dark
        return "\033[38;5;52m"   # Dark red
    else:           # Nearly black but not black
        return "\033[38;5;16m"   # Very dark

def convert_html_line(html_line):
    """Convert a single HTML line to ANSI colored text."""
    line_result = ""
    
    # Parse the HTML line using regex to find all color segments
    pattern = r'<b style="color:(#[0-9A-Fa-f]{6})">([^<]*)</b>'
    matches = re.findall(pattern, html_line)
    
    # Convert each colored segment
    for color, text in matches:
        if color.upper() == "#000000":
            # Black text becomes invisible spaces
            line_result += " " * len(text)
        else:
            # Colored text gets ANSI color codes
            ansi_color = hex_to_ansi_256(color)
            if ansi_color:
                line_result += f"{ansi_color}{text}\033[0m"
            else:
                line_result += text
    
    return line_result

def get_html_banner():
    """
    Returns the complete ASCII art banner converted from HTML.
    All black characters are made invisible (spaces) to preserve the image.
    """
    import os
    
    try:
        # Try to read the HTML file directly
        html_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'tests', 'banner.html')
        with open(html_path, 'r', encoding='utf-8') as f:
            html_content = f.read()
        
        # Split into lines and extract just the content between <b> tags
        lines = html_content.split('\n')
        result_lines = []
        
        for line in lines:
            # Skip the opening <pre> tag and closing </pre> tag and style tag
            if ('<pre' in line or '</pre>' in line or 
                '<style>' in line or '</style>' in line or 
                'color: transparent' in line):
                continue
            if not line.strip():
                continue
                
            converted_line = convert_html_line(line)
            if converted_line:
                result_lines.append(converted_line)
        
        return "\n".join(result_lines)
        
    except FileNotFoundError:
        # Fallback to simple banner if HTML file not found
        return get_simple_banner()

def get_banner():
    """
    Returns the ASCII art banner - you can choose between simple or HTML version.
    """
    # Return the converted HTML banner
    return get_html_banner()

def get_simple_banner():
    """
    Returns a simple ASCII art banner as fallback.
    """
    return """
\033[38;5;208m    ____                     ____                 
   / __ \\___  _________  ____/ __ \\____  ____ ______
  / /_/ / _ \\/ ___/ __ \\/ __  / / / __ \\/ __ `/ ___/
 / _, _/  __/ /__/ /_/ / /_/ / /_/ / /_/ / /_/ / /    
/_/ |_|\\___/\\___/\\____/\\__,_/\\____/\\____/\\__,_/_/     
                                                      
\033[38;5;196m              [:: ReconScan ::]\033[0m
\033[38;5;244m     Web Application Vulnerability Scanner\033[0m
\033[38;5;220m            Advanced Security Testing Tool\033[0m
"""

def get_version_info():
    """
    Returns version and build information.
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
    print("HTML Banner Conversion:")
    print(get_html_banner())
    print("\nSimple Banner:")
    print(get_simple_banner()) 