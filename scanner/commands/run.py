"""
ReconScan Run Command Module

Quick preset scan configurations for common vulnerability testing scenarios.
Provides simplified scan execution with predefined module combinations.
"""

import asyncio
from pathlib import Path

class RunCommand:
    """
    Quick preset scan configurations for ReconScan.
    
    Provides simplified scan execution with predefined module combinations
    for common vulnerability testing scenarios without complex argument parsing.
    """
    
    # Command metadata - self-documenting for help system
    description = "Execute quick scans with preset configurations"
    usage = "run <preset> <target_url> [output_file]"
    example = "run quick https://example.com results.json"
    category = "Scanning"
    
    def __init__(self):
        """Initialize run command with preset configurations."""
        
        # Define scan presets
        self.presets = {
            'quick': {
                'name': 'Quick Scan',
                'description': 'Fast scan with basic vulnerability checks',
                'modules': ['headers', 'sqli', 'xss'],
                'threads': 10,
                'timeout': 5
            },
            'standard': {
                'name': 'Standard Scan',
                'description': 'Comprehensive scan with most vulnerability checks',
                'modules': ['headers', 'sqli', 'xss', 'lfi', 'dirtraversal'],
                'threads': 5,
                'timeout': 10
            },
            'deep': {
                'name': 'Deep Scan',
                'description': 'Thorough scan with all vulnerability modules',
                'modules': ['headers', 'sqli', 'xss', 'lfi', 'dirtraversal', 'cmdinjection'],
                'threads': 3,
                'timeout': 15
            },
            'headers': {
                'name': 'Headers Only',
                'description': 'Security headers analysis only',
                'modules': ['headers'],
                'threads': 1,
                'timeout': 10
            },
            'injection': {
                'name': 'Injection Tests',
                'description': 'Focus on injection vulnerabilities',
                'modules': ['sqli', 'xss', 'lfi', 'cmdinjection'],
                'threads': 5,
                'timeout': 10
            }
        }
        
    def execute(self, args=None):
        """
        Execute preset scan configuration.
        
        Args:
            args (str, optional): Preset name, target URL, and optional output file
            
        Returns:
            bool: True if scan was executed successfully
        """
        try:
            if not args or not args.strip():
                self._show_usage()
                return False
            
            # Parse arguments
            parts = args.strip().split()
            
            if len(parts) < 2:
                print("Error: Preset name and target URL required")
                self._show_usage()
                return False
            
            preset_name = parts[0].lower()
            target_url = parts[1]
            output_file = parts[2] if len(parts) > 2 else None
            
            # Validate preset
            if preset_name not in self.presets:
                print(f"Error: Unknown preset '{preset_name}'")
                self._show_available_presets()
                return False
            
            preset = self.presets[preset_name]
            
            # Display preset information
            print(f"Running {preset['name']}: {preset['description']}")
            print(f"Target: {target_url}")
            print(f"Modules: {', '.join(preset['modules'])}")
            
            if output_file:
                print(f"Output: {output_file}")
            
            print("=" * 60)
            
            # Execute scan using ScanCommand
            return self._execute_scan(preset_name, target_url, output_file)
            
        except Exception as e:
            print(f"Error executing run command: {str(e)}")
            return False
    
    def _execute_scan(self, preset_name, target_url, output_file=None):
        """
        Execute scan using the ScanCommand with preset configuration.
        
        Args:
            preset_name (str): Name of the preset to use
            target_url (str): Target URL to scan
            output_file (str, optional): Output file path
            
        Returns:
            bool: True if scan executed successfully
        """
        try:
            # Import ScanCommand
            from scanner.commands.scan import ScanCommand
            
            preset = self.presets[preset_name]
            
            # Build scan arguments
            scan_args = [
                target_url,
                '--modules', ','.join(preset['modules']),
                '--threads', str(preset['threads']),
                '--timeout', str(preset['timeout']),
                '--verbose'
            ]
            
            # Add output file if specified
            if output_file:
                scan_args.extend(['--output', output_file])
            
            # Create and execute scan command
            scanner = ScanCommand()
            return scanner.execute(' '.join(scan_args))
            
        except ImportError:
            print("Error: ScanCommand not available")
            return False
        except Exception as e:
            print(f"Error executing scan: {str(e)}")
            return False
    
    def _show_usage(self):
        """Display usage information with available presets."""
        print("Usage: run <preset> <target_url> [output_file]")
        print("\nAvailable presets:")
        
        for preset_name, preset_info in self.presets.items():
            modules_str = ', '.join(preset_info['modules'])
            print(f"  {preset_name:<12} - {preset_info['description']}")
            print(f"               Modules: {modules_str}")
        
        print("\nExamples:")
        print("  run quick https://example.com")
        print("  run standard https://example.com scan_results.txt")
        print("  run deep https://testsite.local detailed_scan.txt")
        print("  run headers https://example.com")
        print("  run injection https://vulnerable.site")
        
        print("\nFor custom scans, use: scan <target_url> --modules <list>")
    
    def _show_available_presets(self):
        """Display available presets with descriptions."""
        print("\nAvailable presets:")
        for preset_name, preset_info in self.presets.items():
            print(f"  {preset_name:<12} - {preset_info['description']}")
            print(f"               Modules: {', '.join(preset_info['modules'])}")
    
    def list_presets(self):
        """
        List all available presets with detailed information.
        This method can be called by other commands for reference.
        
        Returns:
            dict: Dictionary of available presets
        """
        return self.presets
