"""
ReconScan Scan Command Module

Main scanning functionality for web application vulnerability detection.
Refactored for modularity and maintainability.
"""

import asyncio
import aiohttp
import time
import urllib.parse
from pathlib import Path
from typing import List, Dict, Any, Optional
from urllib.parse import urlparse, urlencode, urlunparse, parse_qs, urljoin
from datetime import datetime
import json
import re

# ANSI color codes for terminal output
class Colors:
    PURPLE = '\033[95m'
    CYAN = '\033[96m'
    DARKCYAN = '\033[36m'
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    ENDC = '\033[0m'  # End color

# Import modular scanning components
from .scanning.false_positive_filters import FalsePositiveFilters
from .scanning.vulnerability_scanners.sql_injection_scanner import SQLInjectionScanner
from .scanning.vulnerability_scanners.xss_scanner import XSSScanner
from .scanning.vulnerability_scanners.lfi_scanner import LFIScanner
from .scanning.vulnerability_scanners.command_injection_scanner import CommandInjectionScanner
from .scanning.vulnerability_scanners.security_headers_scanner import SecurityHeadersScanner
from .scanning.vulnerability_scanners.directory_traversal_scanner import DirectoryTraversalScanner

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
        
        # Initialize false positive filters
        self.false_positive_filters = FalsePositiveFilters()
        
        # Initialize vulnerability scanners
        self.sql_scanner = SQLInjectionScanner()
        self.xss_scanner = XSSScanner()  # Now uses AI classifier internally
        self.lfi_scanner = LFIScanner()
        self.cmd_scanner = CommandInjectionScanner()
        self.headers_scanner = SecurityHeadersScanner()
        self.dir_scanner = DirectoryTraversalScanner()
        
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
        
        # Track found vulnerabilities to avoid duplicates
        self.found_vulnerabilities = set()
        
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
        
        # Clear previous scan data and initialize fresh tracking
        self.found_vulnerabilities.clear()
        
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
            
            # Discover pages and parameters
            if params['verbose']:
                print(f"\n[{Colors.PURPLE}+{Colors.ENDC}] Discovering pages and parameters...")
            
            discovered_urls = await self._discover_urls(session, params['target'], params['verbose'])
            
            # Store discovered URLs for use in modules
            self.discovered_urls = discovered_urls
            
            # Run each module
            for module in params['modules']:
                if params['verbose']:
                    print(f"\n[{Colors.PURPLE}+{Colors.ENDC}] Running {self.available_modules[module]}...")
                
                try:
                    await self._run_module(session, module, params)
                except Exception as e:
                    print(f"[{Colors.RED}-{Colors.ENDC}] Error in {module} module: {str(e)}")
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
    
    def _add_vulnerability(self, vulnerability):
        """Add vulnerability if not already found (deduplication)."""
        # Create a unique key for this vulnerability
        vuln_key = f"{vulnerability['type']}_{vulnerability['url']}_{vulnerability.get('payload', '')}"
        
        if vuln_key not in self.found_vulnerabilities:
            self.found_vulnerabilities.add(vuln_key)
            self.results['vulnerabilities'].append(vulnerability)
            return True
        return False
    
    async def _discover_urls(self, session, target, verbose=True):
        """
        Discover URLs and parameters by crawling the target site.
        
        Args:
            session: aiohttp session
            target (str): Target URL
            verbose (bool): Verbose output
            
        Returns:
            list: List of discovered URLs with parameters
        """
        discovered_urls = []
        visited_urls = set()
        
        try:
            # Parse base URL
            base_parsed = urlparse(target)
            base_domain = f"{base_parsed.scheme}://{base_parsed.netloc}"
            
            # URLs to crawl
            urls_to_crawl = [target]
            
            # Common pages to check
            common_pages = [
                '', 'index.php', 'index.html', 'index.asp', 'index.aspx',
                'login.php', 'admin.php', 'search.php', 'categories.php',
                'artists.php', 'guestbook.php', 'cart.php', 'profile.php',
                'signup.php', 'contact.php', 'about.php'
            ]
            
            # Add common pages to crawl list
            for page in common_pages:
                full_url = urljoin(base_domain + '/', page)
                if full_url not in urls_to_crawl:
                    urls_to_crawl.append(full_url)
            
            crawl_count = 0
            max_crawl = 10  # Limit crawling to avoid infinite loops
            
            for url in urls_to_crawl:
                if crawl_count >= max_crawl:
                    break
                    
                if url in visited_urls:
                    continue
                    
                try:
                    if verbose:
                        print(f"  → Crawling: {url}")
                    
                    async with session.get(url) as response:
                        if response.status == 200:
                            content = await response.text()
                            visited_urls.add(url)
                            crawl_count += 1
                            
                            # Extract links and forms
                            links = re.findall(r'href=["\']([^"\']+)["\']', content, re.IGNORECASE)
                            forms = re.findall(r'<form[^>]*action=["\']([^"\']*)["\'][^>]*>', content, re.IGNORECASE)
                            
                            # Process links
                            for link in links:
                                full_link = urljoin(url, link)
                                parsed_link = urlparse(full_link)
                                
                                # Only process links from same domain
                                if parsed_link.netloc == base_parsed.netloc:
                                    # Check if link has parameters
                                    if parsed_link.query:
                                        discovered_urls.append(full_link)
                                        if verbose:
                                            print(f"    Found URL with params: {full_link}")
                                    
                                    # Add to crawl list if it's a new page
                                    if full_link not in visited_urls and len(urls_to_crawl) < 20:
                                        urls_to_crawl.append(full_link)
                            
                            # Process forms
                            for form_action in forms:
                                if form_action:
                                    full_form_url = urljoin(url, form_action)
                                    if urlparse(full_form_url).netloc == base_parsed.netloc:
                                        discovered_urls.append(full_form_url)
                                        if verbose:
                                            print(f"    Found form action: {full_form_url}")
                
                except Exception as e:
                    if verbose:
                        print(f"    ! Error crawling {url}: {str(e)}")
                    continue
            
            # If no URLs with parameters found, create test URLs with common parameters
            if not discovered_urls:
                test_params = ['id', 'cat', 'page', 'search', 'artist', 'user']
                for param in test_params:
                    test_url = f"{target}?{param}=1"
                    discovered_urls.append(test_url)
            
            if verbose:
                print(f"  → Discovered {len(discovered_urls)} URLs for testing")
            
            return discovered_urls
            
        except Exception as e:
            if verbose:
                print(f"  ! Error during URL discovery: {str(e)}")
            # Fallback to basic parameter testing
            return [f"{target}?id=1", f"{target}?cat=1", f"{target}?search=test"]
    
    async def _run_module(self, session, module, params):
        """
        Run a specific vulnerability scan module using modular scanners.
        
        Args:
            session: aiohttp session
            module (str): Module name to run
            params (dict): Scan parameters
        """
        target = params['target']
        verbose = params['verbose']
        vulnerabilities = []
        
        if module == 'sqli':
            vulnerabilities = await self.sql_scanner.scan(session, target, getattr(self, 'discovered_urls', None), verbose)
        elif module == 'xss':
            vulnerabilities = await self.xss_scanner.scan(session, target, verbose)
        elif module == 'lfi':
            vulnerabilities = await self.lfi_scanner.scan(session, target, self.config, verbose)
        elif module == 'cmdinjection':
            vulnerabilities = await self.cmd_scanner.scan(session, target, verbose)
        elif module == 'headers':
            vulnerabilities = await self.headers_scanner.scan(session, target, verbose)
        elif module == 'dirtraversal':
            vulnerabilities = await self.dir_scanner.scan(session, target, verbose)
        
        # Add discovered vulnerabilities to results
        for vulnerability in vulnerabilities:
            self._add_vulnerability(vulnerability)
    





    
    def _generate_summary(self):
        """Generate scan summary statistics with vulnerability grouping."""
        vulnerabilities = self.results['vulnerabilities']
        
        # Count by severity
        severity_count = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0}
        type_count = {}
        grouped_vulnerabilities = {}
        
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'Unknown')
            vuln_type = vuln.get('type', 'Unknown')
            
            if severity in severity_count:
                severity_count[severity] += 1
            
            type_count[vuln_type] = type_count.get(vuln_type, 0) + 1
            
            # Group vulnerabilities by base type (remove subtypes in parentheses for grouping)
            base_type = vuln_type.split('(')[0].strip()
            if base_type not in grouped_vulnerabilities:
                grouped_vulnerabilities[base_type] = {
                    'count': 0,
                    'subtypes': {},
                    'examples': []
                }
            
            grouped_vulnerabilities[base_type]['count'] += 1
            
            # Track subtypes
            if vuln_type not in grouped_vulnerabilities[base_type]['subtypes']:
                grouped_vulnerabilities[base_type]['subtypes'][vuln_type] = 0
            grouped_vulnerabilities[base_type]['subtypes'][vuln_type] += 1
            
            # Store first few examples for display
            if len(grouped_vulnerabilities[base_type]['examples']) < 3:
                grouped_vulnerabilities[base_type]['examples'].append({
                    'url': vuln.get('url', 'N/A'),
                    'type': vuln_type,
                    'severity': severity
                })
        
        self.results['summary'] = {
            'total_vulnerabilities': len(vulnerabilities),
            'by_severity': severity_count,
            'by_type': type_count,
            'grouped_vulnerabilities': grouped_vulnerabilities
        }
    
    def _display_results(self, verbose=True):
        """Display scan results to console with grouped vulnerability summary."""
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
                    severity_icon = "🔴" if severity == 'Critical' else "🟠" if severity == 'High' else "🟡" if severity == 'Medium' else "🟢"
                    print(f"  {severity_icon} {severity}: {count}")
            
            # Display grouped vulnerabilities (cleaner CLI output)
            print("\nVulnerabilities Found:")
            grouped_vulns = summary.get('grouped_vulnerabilities', {})
            
            for base_type, group_info in grouped_vulns.items():
                count = group_info['count']
                subtypes = group_info['subtypes']
                examples = group_info['examples']
                
                # Main vulnerability type with count
                print(f"\n🔍 {base_type}: {count} vulnerabilities")
                
                # Show subtypes if there are multiple
                if len(subtypes) > 1:
                    for subtype, subcount in subtypes.items():
                        subtype_detail = subtype.split('(')[1].rstrip(')') if '(' in subtype else subtype
                        print(f"   • {subtype_detail}: {subcount}")
                
                # Show examples only for high-impact vulnerabilities
                show_examples = (
                    verbose and examples and 
                    base_type.lower() not in ['missing security headers', 'security headers']
                )
                
                if show_examples:
                    print(f"   Examples:")
                    for i, example in enumerate(examples[:2], 1):  # Show max 2 examples
                        url_short = example['url'][:60] + "..." if len(example['url']) > 60 else example['url']
                        print(f"     {i}. {url_short}")
                    
                    if count > 2:
                        print(f"     ... and {count - 2} more (see detailed report)")
                elif base_type.lower() in ['missing security headers', 'security headers']:
                    print(f"   → See report for detailed header analysis")
            
            # Option to show all details
            if not verbose and summary['total_vulnerabilities'] > 5:
                print(f"\n💡 Use --verbose flag or check the detailed report for all {summary['total_vulnerabilities']} vulnerabilities")
            elif verbose and summary['total_vulnerabilities'] > 10:
                print(f"\n📄 All {summary['total_vulnerabilities']} vulnerabilities with exploitation guidance saved to report file")
                
        else:
            print("\n✅ No vulnerabilities detected")
            print("   Target appears to be properly secured against tested attack vectors")
    
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
