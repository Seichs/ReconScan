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
    GREEN = '\033[1;38;5;28m'  # Bold forest green (256-color) for better visibility
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    ENDC = '\033[0m'  # End color

# Configuration constants for scan limits and thresholds
class ScanLimits:
    MAX_THREAD_WARNING_THRESHOLD = 100
    MAX_TIMEOUT_WARNING_THRESHOLD = 600  # 10 minutes in seconds
    MAX_CRAWL_URLS = 50  # Increased from 10 to 50
    MAX_DISCOVERED_URLS = 100  # Increased from 20 to 100
    MAX_QUEUE_SIZE = 100  # Increased from 20 to 100
    MAX_URLS_FOR_TESTING = 100  # Increased from 20 to 100
    CRAWL_TIMEOUT_SECONDS = 10  # Increased from 5 to 10
    MAX_DETAILS_DISPLAY = 10  # Increased from 5 to 10
    MAX_VERBOSE_DISPLAY = 20  # Increased from 10 to 20

# Import modular scanning components
from .scanning.shared.false_positive_filters import FalsePositiveFilters
# Note: Import paths updated for subdirectory structure

class ScanCommand:
    """
    Core vulnerability scanning command for ReconScan.
    
    Supports multiple scan types including SQL injection, XSS, LFI, command injection,
    and security header analysis with comprehensive reporting.
    """
    
    # Command metadata - self-documenting for help system
    description = "Perform web vulnerability scans on target URLs"
    usage = "scan <target_url> [options]"
    example = "scan http://testphp.vulnweb.com/ --modules sqli,xss --output report.txt"
    category = "Scanning"
    
    def __init__(self):
        """Initialize scanner with modules and configuration."""
        
        # Load configuration
        from scanner.config_loader import get_system_config
        self.system_config = get_system_config()
        self.config = self._load_scan_config()
        
        # Initialize false positive filters once
        from scanner.commands.scanning.shared.false_positive_filters import FalsePositiveFilters
        from scanner.ai import AIVulnerabilityValidator
        self.false_positive_filters = FalsePositiveFilters()
        self.ai_validator = AIVulnerabilityValidator()
        
        # TODO: Implement lazy loading for better performance - scanners only loaded when needed
        # Cache for lazy-loaded scanners
        self._scanner_cache = {}
        
        # Available scan modules
        self.available_modules = {
            'sqli': 'Professional SQL Injection Detection',  # Advanced SQL injection scanner integrated
            'xss': 'Cross-Site Scripting Detection', 
            'lfi': 'Local File Inclusion Detection',
            'cmdinjection': 'Command Injection Detection',
            'headers': 'Security Headers Analysis',
            'dirtraversal': 'Directory Traversal Detection'
        }
        
        # Default modules to run
        self.default_modules = ['sqli', 'xss', 'headers']  # SQL injection scanner now integrated
        
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
            args (str or list, optional): Scan arguments (target URL and options)
            
        Returns:
            bool: True if scan completed successfully
        """
        try:
            if not args:
                self._show_usage()
                return False
            
            # Handle both string and list input
            if isinstance(args, list):
                args_str = ' '.join(args)
            else:
                args_str = args.strip()
                
            if not args_str:
                self._show_usage()
                return False
            
            # Parse scan arguments
            scan_params = self._parse_args(args_str)
            
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
            'timeout': self.config.get('network', {}).get('timeout', 10),
            # Advanced exploitation options
            'dump': False,
            'dump_tables': False,
            'dump_data': False,
            'exploit': False,
            'file_read': None,
            'os_shell': False,
            'stealth': False
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
                    threads = int(parts[i + 1])
                    if threads <= 0:
                        print(f"[{Colors.YELLOW}!{Colors.ENDC}] Warning: Thread count must be positive, using default ({scan_params['threads']})")
                    elif threads > ScanLimits.MAX_THREAD_WARNING_THRESHOLD:
                        print(f"[{Colors.YELLOW}!{Colors.ENDC}] Warning: High thread count ({threads}) may cause rate limiting, consider lower values")
                        scan_params['threads'] = threads
                    else:
                        scan_params['threads'] = threads
                except ValueError:
                    print(f"[{Colors.YELLOW}!{Colors.ENDC}] Warning: Invalid thread count '{parts[i + 1]}', using default ({scan_params['threads']})")
                i += 2
            elif arg == '--timeout' and i + 1 < len(parts):
                try:
                    timeout = int(parts[i + 1])
                    if timeout <= 0:
                        print(f"[{Colors.YELLOW}!{Colors.ENDC}] Warning: Timeout must be positive, using default ({scan_params['timeout']}s)")
                    elif timeout > ScanLimits.MAX_TIMEOUT_WARNING_THRESHOLD:
                        print(f"[{Colors.YELLOW}!{Colors.ENDC}] Warning: Very high timeout ({timeout}s) may cause long waits")
                        scan_params['timeout'] = timeout
                    else:
                        scan_params['timeout'] = timeout
                except ValueError:
                    print(f"[{Colors.YELLOW}!{Colors.ENDC}] Warning: Invalid timeout '{parts[i + 1]}', using default ({scan_params['timeout']}s)")
                i += 2
            elif arg == '--verbose':
                scan_params['verbose'] = True
                i += 1
            elif arg == '--quiet':
                scan_params['verbose'] = False
                i += 1
            # Advanced exploitation options
            elif arg == '--dump':
                scan_params['dump'] = True
                i += 1
            elif arg == '--dump-tables':
                scan_params['dump_tables'] = True
                i += 1
            elif arg == '--dump-data':
                scan_params['dump_data'] = True
                i += 1
            elif arg == '--exploit':
                scan_params['exploit'] = True
                i += 1
            elif arg == '--file-read' and i + 1 < len(parts):
                scan_params['file_read'] = parts[i + 1]
                i += 2
            elif arg == '--os-shell':
                scan_params['os_shell'] = True
                i += 1
            elif arg == '--stealth':
                scan_params['stealth'] = True
                i += 1
            else:
                print(f"[{Colors.YELLOW}!{Colors.ENDC}] Warning: Unknown argument '{arg}', ignoring")
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
        # TODO: Optimize connection pooling for better performance
        connector = aiohttp.TCPConnector(
            limit=params['threads'],
            limit_per_host=min(params['threads'], 10),  # Limit per host to avoid overwhelming target
            ssl=not self.config.get('network', {}).get('verify_ssl', False),
            keepalive_timeout=30,  # Keep connections alive for reuse
            enable_cleanup_closed=True  # Clean up closed connections
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
        
        # Run advanced exploitation if requested
        if self._should_run_exploitation(params):
            await self._run_exploitation(session, params)
        
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
        Discover URLs with parameters for vulnerability testing.
        
        Crawls the target website to find pages with parameters that can be tested
        for vulnerabilities. Uses common page discovery and form parameter extraction.
        
        Args:
            session: aiohttp session for HTTP requests
            target (str): Target URL to crawl
            verbose (bool): Enable verbose output
            
        Returns:
            list: List of URLs with parameters for testing
        """
        discovered_parameter_urls = []
        crawled_pages = set()
        
        try:
            # Parse base URL for domain validation
            from urllib.parse import urlparse, urljoin, parse_qs
            target_parsed = urlparse(target)
            base_domain = f"{target_parsed.scheme}://{target_parsed.netloc}"
            
            # URLs to crawl for parameter discovery
            crawl_queue = [target]
            
            # Common pages to check for parameters
            common_test_pages = [
                'index.php', 'search.php', 'login.php', 'admin.php',
                'search', 'login', 'admin', 'user', 'profile',
                'view.php', 'show.php', 'display.php', 'page.php'
            ]
            
            # Add common pages to crawl list
            for page in common_test_pages:
                test_page_url = urljoin(target, page)
                if test_page_url not in crawl_queue:
                    crawl_queue.append(test_page_url)
            
            # Crawl each URL to discover parameters
            for current_url in crawl_queue[:ScanLimits.MAX_CRAWL_URLS]:
                if current_url in crawled_pages:
                    continue
                    
                crawled_pages.add(current_url)
                
                try:
                    async with session.get(current_url, timeout=aiohttp.ClientTimeout(total=5)) as response:
                        if response.status == 200:
                            page_content = await response.text()
                            
                            # Extract links and forms
                            import re
                            
                            # Process links with parameters
                            link_pattern = r'href=["\']([^"\']+)["\']'
                            discovered_links = re.findall(link_pattern, page_content, re.IGNORECASE)
                            
                            for link_url in discovered_links:
                                # Only process links from same domain
                                absolute_link = urljoin(current_url, link_url)
                                if urlparse(absolute_link).netloc == target_parsed.netloc:
                                    # Check if link has parameters
                                    if '?' in absolute_link and '=' in absolute_link:
                                        if absolute_link not in discovered_parameter_urls:
                                            discovered_parameter_urls.append(absolute_link)
                                    else:
                                        # Add to crawl list if it's a new page
                                        if absolute_link not in crawl_queue and len(crawl_queue) < 20:
                                            crawl_queue.append(absolute_link)
                            
                            # Process forms for parameter discovery
                            form_pattern = r'<form[^>]*action=["\']([^"\']*)["\'][^>]*>(.*?)</form>'
                            input_pattern = r'<input[^>]*name=["\']([^"\']+)["\']'
                            
                            discovered_forms = re.findall(form_pattern, page_content, re.IGNORECASE | re.DOTALL)
                            for form_action, form_content in discovered_forms:
                                form_url = urljoin(current_url, form_action) if form_action else current_url
                                input_names = re.findall(input_pattern, form_content, re.IGNORECASE)
                                
                                # Create test URLs with discovered parameters
                                for param_name in input_names:
                                    test_url_with_param = f"{form_url}?{param_name}=test"
                                    if test_url_with_param not in discovered_parameter_urls:
                                        discovered_parameter_urls.append(test_url_with_param)
                        
                except Exception:
                    continue  # Skip failed requests during discovery
            
            # If no URLs with parameters found, create test URLs with common parameters
            if not discovered_parameter_urls:
                common_test_parameters = ['id', 'cat', 'page', 'search', 'artist', 'user']
                for parameter_name in common_test_parameters:
                    fallback_test_url = f"{target}?{parameter_name}=1"
                    discovered_parameter_urls.append(fallback_test_url)
            
            if verbose:
                print(f"  {Colors.GREEN}→{Colors.ENDC} Discovered {len(discovered_parameter_urls)} URLs for testing")
            
            return discovered_parameter_urls[:ScanLimits.MAX_URLS_FOR_TESTING]
            
        except Exception:
            # Fallback to basic parameter testing
            if verbose:
                print(f"  {Colors.YELLOW}!{Colors.ENDC} URL discovery failed, using basic parameter testing")
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
        
        scanner = self._get_scanner(module)
        if scanner:
            # Handle different scanner method signatures for optimal performance
            if module == 'sqli':
                # Disable enhanced concurrency to use the reliable standard scan logic
                vulnerabilities = await scanner.scan(
                    session,
                    target,
                    getattr(self, 'discovered_urls', None),
                    verbose,
                    enhanced_mode=False
                )
            elif module == 'lfi':
                vulnerabilities = await scanner.scan(session, target, self.config, verbose)
            else:
                vulnerabilities = await scanner.scan(session, target, verbose)
        
        # Add discovered vulnerabilities to results
        for vulnerability in vulnerabilities:
            self._add_vulnerability(vulnerability)
    
    def _get_scanner(self, module_name):
        """
        Lazy load vulnerability scanners for better performance.
        
        Args:
            module_name (str): Name of the scanner module
            
        Returns:
            Scanner instance or None if module not found
        """
        if module_name in self._scanner_cache:
            return self._scanner_cache[module_name]
        
        # Lazy import and initialize scanners
        try:
            if module_name == 'sqli':
                from scanner.commands.scanning.vulnerability_scanners.sql_injection.sql_injection_scanner import SQLInjectionScanner
                scanner = SQLInjectionScanner(ai_validator=self.ai_validator)
            elif module_name == 'xss':
                from scanner.commands.scanning.vulnerability_scanners.xss.xss_scanner import XSSScanner
                scanner = XSSScanner(self.ai_validator)
            elif module_name == 'lfi':
                from scanner.commands.scanning.vulnerability_scanners.lfi.lfi_scanner import LFIScanner
                scanner = LFIScanner(self.ai_validator)
            elif module_name == 'cmdinjection':
                from scanner.commands.scanning.vulnerability_scanners.command_injection.command_injection_scanner import CommandInjectionScanner
                scanner = CommandInjectionScanner(self.ai_validator)
            elif module_name == 'headers':
                from scanner.commands.scanning.vulnerability_scanners.security_headers.security_headers_scanner import SecurityHeadersScanner
                scanner = SecurityHeadersScanner()  # Security headers don't need AI validation
            elif module_name == 'dirtraversal':
                from scanner.commands.scanning.vulnerability_scanners.directory_traversal.directory_traversal_scanner import DirectoryTraversalScanner
                scanner = DirectoryTraversalScanner(self.ai_validator)
            else:
                return None
            
            # Cache the scanner for reuse
            self._scanner_cache[module_name] = scanner
            return scanner
            
        except ImportError as e:
            print(f"[{Colors.RED}-{Colors.ENDC}] Error loading {module_name} scanner: {str(e)}")
            return None
    
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
                    if severity == 'Critical':
                        severity_display = f"{Colors.RED}[CRITICAL]{Colors.ENDC}"
                    elif severity == 'High':
                        severity_display = f"{Colors.RED}[HIGH]{Colors.ENDC}"
                    elif severity == 'Medium':
                        severity_display = f"{Colors.YELLOW}[MEDIUM]{Colors.ENDC}"
                    else:
                        severity_display = f"{Colors.GREEN}[LOW]{Colors.ENDC}"
                    print(f"  {severity_display} {severity}: {count}")
            
            # Display grouped vulnerabilities (cleaner CLI output)
            print("\nVulnerabilities Found:")
            grouped_vulns = summary.get('grouped_vulnerabilities', {})
            
            for base_type, group_info in grouped_vulns.items():
                count = group_info['count']
                subtypes = group_info['subtypes']
                examples = group_info['examples']
                
                # Main vulnerability type with count
                print(f"\n{Colors.CYAN}[SCAN]{Colors.ENDC} [{base_type}]: {count} vulnerabilities")
                
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
                    print(f"   {Colors.GREEN}→{Colors.ENDC} See report for detailed header analysis")
            
            # Option to show all details
            if not verbose and summary['total_vulnerabilities'] > ScanLimits.MAX_DETAILS_DISPLAY:
                print(f"\n{Colors.BLUE}[INFO]{Colors.ENDC} Use --verbose flag or check the detailed report for all {summary['total_vulnerabilities']} vulnerabilities")
            elif verbose and summary['total_vulnerabilities'] > ScanLimits.MAX_VERBOSE_DISPLAY:
                print(f"\n{Colors.BLUE}[REPORT]{Colors.ENDC} All {summary['total_vulnerabilities']} vulnerabilities with exploitation guidance saved to report file")
                
        else:
            print(f"\n{Colors.GREEN}[SECURE]{Colors.ENDC} No vulnerabilities detected")
            print("   Target appears to be properly secured against tested attack vectors")
    
    def _save_results(self, output_file):
        """Save scan results in all three formats (TXT, JSON, HTML) automatically."""
        try:
            from pathlib import Path
            from scanner.commands.scanning.vulnerability_scanners.educational_security_reporter import EducationalSecurityReporter
            
            # Create results directory in project root
            results_dir = Path("results")
            results_dir.mkdir(exist_ok=True)
            
            # Get base filename without extension  
            base_name = Path(output_file).stem
            
            # Generate TXT report
            txt_path = results_dir / f"{base_name}.txt"
            self._save_text_report(self.results, txt_path)
            
            # Generate JSON report
            json_path = results_dir / f"{base_name}.json"
            with open(json_path, 'w', encoding='utf-8') as f:
                import json
                json.dump(self.results, f, indent=2, ensure_ascii=False)
            
            # Generate HTML report
            html_path = results_dir / f"{base_name}.html"
            try:
                reporter = EducationalSecurityReporter()
                vulnerabilities = self.results.get('vulnerabilities', [])
                if vulnerabilities:
                    reporter.generate_educational_report(
                        vulnerabilities=vulnerabilities,
                        scan_metadata=self.results.get('scan_info', {}),
                        output_path=str(html_path),
                        format_type='html'
                    )
                else:
                    self._create_basic_html_report(html_path)
            except:
                self._create_basic_html_report(html_path)
            
            # Clean output - just show where reports were saved
            print(f"{Colors.GREEN}[+]{Colors.ENDC} Reports: {results_dir}/{base_name}.{{txt,json,html}}")
            
        except Exception as e:
            print(f"{Colors.RED}[-]{Colors.ENDC} Error saving results: {str(e)}")
    
    def _save_text_report(self, results, output_path):
        """Save scan results in traditional text format."""
        try:
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write("=" * 60 + "\n")
                f.write("RECONSCAN SECURITY ASSESSMENT REPORT\n")
                f.write("=" * 60 + "\n\n")
                
                # Scan information
                scan_info = results.get('scan_info', {})
                f.write(f"Target: {scan_info.get('target', 'Unknown')}\n")
                f.write(f"Scan Date: {scan_info.get('start_time', 'Unknown')}\n")
                f.write(f"Duration: {scan_info.get('duration', 'Unknown')}\n")
                f.write(f"Modules: {', '.join(scan_info.get('modules_used', []))}\n\n")
                
                # Summary
                summary = results.get('summary', {})
                f.write("SUMMARY\n")
                f.write("-" * 20 + "\n")
                f.write(f"Total Vulnerabilities: {summary.get('total_vulnerabilities', 0)}\n")
                
                severity_count = summary.get('by_severity', {})
                for severity, count in severity_count.items():
                    if count > 0:
                        f.write(f"{severity}: {count}\n")
                f.write("\n")
                
                # Detailed vulnerabilities
                vulnerabilities = results.get('vulnerabilities', [])
                if vulnerabilities:
                    f.write("VULNERABILITY DETAILS\n")
                    f.write("-" * 30 + "\n\n")
                    
                    for i, vuln in enumerate(vulnerabilities, 1):
                        f.write(f"[{i}] {vuln.get('type', 'Unknown Vulnerability')}\n")
                        f.write(f"    Severity: {vuln.get('severity', 'Unknown')}\n")
                        f.write(f"    URL: {vuln.get('url', 'N/A')}\n")
                        f.write(f"    Parameter: {vuln.get('parameter', 'N/A')}\n")
                        f.write(f"    Method: {vuln.get('method', 'N/A')}\n")
                        f.write(f"    Payload: {vuln.get('payload', 'N/A')}\n")
                        f.write(f"    Evidence: {vuln.get('evidence', 'N/A')}\n")
                        f.write(f"    Confidence: {vuln.get('confidence', 0.0):.1%}\n")
                        f.write("\n")
                else:
                    f.write("No vulnerabilities detected.\n")
                    f.write("Target appears to be properly secured.\n\n")
                
                f.write("=" * 60 + "\n")
                f.write("Report generated by ReconScan Professional Security Framework\n")
                f.write("=" * 60 + "\n")
            
            return str(output_path)
            
        except Exception as e:
            print(f"{Colors.RED}[-]{Colors.ENDC} Error generating text report: {e}")
            return None
            
    def _create_basic_html_report(self, html_path):
        """Create a basic HTML report when educational reporter is not available."""
        html_content = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ReconScan Security Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 40px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
        .header {{ text-align: center; border-bottom: 2px solid #2196F3; padding-bottom: 20px; margin-bottom: 30px; }}
        .success {{ color: #4CAF50; font-size: 24px; margin: 20px 0; }}
        .info {{ background: #E3F2FD; padding: 20px; border-radius: 5px; margin: 20px 0; }}
        .scan-info {{ display: grid; grid-template-columns: 1fr 1fr; gap: 20px; margin: 20px 0; }}
        .scan-detail {{ background: #F8F9FA; padding: 15px; border-radius: 5px; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>ReconScan Security Report</h1>
            <p>Target: {self.results.get('scan_info', {}).get('target', 'Unknown')}</p>
        </div>
        
        <div class="success">
            [SECURE] No vulnerabilities detected
        </div>
        
        <div class="info">
            <h3>[SUMMARY] Scan Summary</h3>
            <p>Your target appears to be properly secured against the tested attack vectors.</p>
        </div>
        
        <div class="scan-info">
            <div class="scan-detail">
                <h4>[INFO] Scan Information</h4>
                <p><strong>Duration:</strong> {self.results.get('scan_info', {}).get('duration', 'Unknown')}</p>
                <p><strong>Modules:</strong> {', '.join(self.results.get('scan_info', {}).get('modules_used', []))}</p>
            </div>
            <div class="scan-detail">
                <h4>[STATUS] Security Status</h4>
                <p><strong>Total Vulnerabilities:</strong> 0</p>
                <p><strong>Security Level:</strong> <span style="color: #4CAF50;">Good</span></p>
            </div>
        </div>
        
        <div class="info">
            <h3>[RESOURCES] Additional Resources</h3>
            <p>For comprehensive educational security reports with learning content, ensure all ReconScan components are properly installed.</p>
        </div>
    </div>
</body>
</html>
"""
        
        with open(html_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
    
    def _load_scan_config(self):
        """Load scan configuration from file with caching for better performance."""
        # TODO: Cache configuration to avoid repeated file I/O operations
        if hasattr(self, '_cached_config'):
            return self._cached_config
            
        try:
            config_file = Path("config/scanner_config.json")
            if config_file.exists():
                with open(config_file, 'r', encoding='utf-8') as f:
                    self._cached_config = json.load(f)
            else:
                # Return default configuration
                self._cached_config = {
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
            return self._cached_config
        except (json.JSONDecodeError, IOError) as e:
            # FIXME: Implement proper logging for configuration errors
            print(f"Warning: Error loading scan config ({e}), using defaults")
            self._cached_config = {}
            return self._cached_config
    
    def _show_usage(self):
        """Display usage information."""
        print("Usage: scan <target_url> [options]")
        print("\nBasic Options:")
        print("  --modules <list>    Comma-separated list of modules to run")
        print("                      Available: " + ", ".join(self.available_modules.keys()))
        print("  --output <file>     Save results in multiple formats (.txt, .json, .html)")
        print("  --threads <num>     Number of concurrent threads (default: 5)")
        print("  --timeout <sec>     HTTP timeout in seconds (default: 10)")
        print("  --verbose           Enable verbose output (default)")
        print("  --quiet             Disable verbose output")
        print("\nAdvanced SQL Exploitation:")
        print("  --dump              Enable database data extraction")
        print("  --dump-tables       Extract only table structures")
        print("  --dump-data         Extract only table data")
        print("  --exploit           Enable advanced exploitation attempts")
        print("  --file-read <path>  Attempt to read specific file from server")
        print("  --os-shell          Attempt to get OS command execution")
        print("  --stealth           Use slower, stealthier exploitation methods")
        print("\nOutput Formats:")
        print("  When using --output results, generates in results/ directory:")
        print("    • results.txt  - Traditional formatted scan results")
        print("    • results.json - Structured data for automation/tools")
        print("    • results.html - Interactive educational security report")
        print("\nBasic Examples:")
        print("  scan http://testphp.vulnweb.com/")
        print("  scan http://testphp.vulnweb.com/ --modules sqli,xss,headers")
        print("  scan http://testphp.vulnweb.com/ --output results --threads 10")
        print("\nAdvanced Exploitation Examples:")
        print("  scan http://testphp.vulnweb.com/ --dump --output exploit_results")
        print("  scan http://testphp.vulnweb.com/ --exploit --dump --stealth")
        print("  scan http://testphp.vulnweb.com/ --file-read /etc/passwd --output results")
        print("  scan http://testphp.vulnweb.com/ --dump-tables --dump-data --threads 5")
    
    def _should_run_exploitation(self, params):
        """Check if exploitation should be run based on parameters and findings."""
        # Check if any exploitation flags are set
        exploitation_flags = params.get('dump') or params.get('dump_tables') or \
                           params.get('dump_data') or params.get('exploit') or \
                           params.get('file_read') or params.get('os_shell')
        
        if not exploitation_flags:
            return False
        
        # Check if we have SQL injection vulnerabilities to exploit
        sql_vulns = [v for v in self.results.get('vulnerabilities', []) 
                    if 'SQL Injection' in v.get('type', '')]
        
        if not sql_vulns:
            if params.get('verbose'):
                print(f"\n{Colors.YELLOW}[!]{Colors.ENDC} Advanced exploitation requested but no SQL injection vulnerabilities found")
            return False
            
        return True
    
    async def _run_exploitation(self, session, params):
        """Run advanced SQL injection exploitation."""
        try:
            from scanner.commands.scanning.vulnerability_scanners.sql_injection.advanced_exploitation_engine import (
                AdvancedExploitationEngine, ExploitationContext, ExtractionTarget, ExtractionTechnique
            )
            from scanner.commands.scanning.vulnerability_scanners.sql_injection.sql_payload_crafting_engine import DatabaseType
            from scanner.commands.scanning.shared.injection_discovery import InjectionPoint, InjectionPointType
            
            print(f"\n{Colors.CYAN}[EXPLOIT]{Colors.ENDC} ADVANCED SQL INJECTION EXPLOITATION")
            print("=" * 60)
            
            # Get SQL injection vulnerabilities
            sql_vulns = [v for v in self.results.get('vulnerabilities', []) 
                        if 'SQL Injection' in v.get('type', '')]
            
            if not sql_vulns:
                return
            
            # Initialize exploitation engine
            engine = AdvancedExploitationEngine(session)
            
            # Track exploitation results
            exploitation_results = []
            
            # Process each SQL injection vulnerability
            for i, vuln in enumerate(sql_vulns[:3], 1):  # Limit to first 3 for demo
                print(f"\n{Colors.BLUE}[*]{Colors.ENDC} Exploiting vulnerability {i}/{min(len(sql_vulns), 3)}")
                print(f"    URL: {vuln.get('url', 'Unknown')}")
                print(f"    Parameter: {vuln.get('parameter', 'Unknown')}")
                
                try:
                    # Create injection point from vulnerability
                    injection_point = self._create_injection_point_from_vuln(vuln)
                    
                    # Create exploitation context
                    context = ExploitationContext(
                        injection_point=injection_point,
                        database_type=DatabaseType.MYSQL,  # Default, could be detected
                        extraction_technique=ExtractionTechnique.BINARY_SEARCH,
                        threads=params.get('threads', 5),
                        delay=0.5 if params.get('stealth') else 0.1
                    )
                    
                    # Run basic information extraction
                    basic_info = await self._extract_basic_info(engine, context, params)
                    exploitation_results.append(basic_info)
                    
                    # Run advanced exploitation based on flags
                    if params.get('dump') or params.get('dump_tables') or params.get('dump_data'):
                        schema_info = await self._extract_schema_info(engine, context, params)
                        exploitation_results.append(schema_info)
                    
                    if params.get('file_read'):
                        file_content = await self._attempt_file_read(engine, context, params)
                        exploitation_results.append(file_content)
                    
                    if params.get('exploit'):
                        advanced_results = await self._run_advanced_exploitation(engine, context, params)
                        exploitation_results.extend(advanced_results)
                        
                except Exception as e:
                    print(f"    {Colors.RED}[-]{Colors.ENDC} Exploitation failed: {str(e)}")
                    continue
            
            # Store exploitation results
            self.results['exploitation'] = {
                'enabled': True,
                'results': exploitation_results,
                'flags_used': {
                    'dump': params.get('dump', False),
                    'dump_tables': params.get('dump_tables', False),
                    'dump_data': params.get('dump_data', False),
                    'exploit': params.get('exploit', False),
                    'file_read': params.get('file_read'),
                    'os_shell': params.get('os_shell', False),
                    'stealth': params.get('stealth', False)
                }
            }
            
            print(f"\n{Colors.GREEN}[+]{Colors.ENDC} Advanced exploitation completed!")
            print(f"    Results: {len(exploitation_results)} extraction operations")
            
        except ImportError as e:
            print(f"{Colors.RED}[-]{Colors.ENDC} Advanced exploitation engine not available: {e}")
        except Exception as e:
            print(f"{Colors.RED}[-]{Colors.ENDC} Exploitation error: {str(e)}")
    
    def _create_injection_point_from_vuln(self, vuln):
        """Create an InjectionPoint object from vulnerability data."""
        from scanner.commands.scanning.shared.injection_discovery import InjectionPoint, InjectionPointType, ParameterType
        
        # Determine injection point type from vulnerability
        method = vuln.get('method', 'GET').upper()
        injection_type = InjectionPointType.QUERY_PARAMETER if method == 'GET' else InjectionPointType.POST_PARAMETER
        
        # Determine parameter type from value
        value = vuln.get('original_value', '1')
        if value.isdigit():
            parameter_type = ParameterType.NUMERIC
        else:
            parameter_type = ParameterType.STRING
        
        return InjectionPoint(
            name=vuln.get('parameter', ''),
            value=value,
            injection_type=injection_type,
            parameter_type=parameter_type,
            url=vuln.get('url', ''),
            method=method,
            location=injection_type.value,
            test_priority=8  # High priority for exploitation
        )
    
    async def _extract_basic_info(self, engine, context, params):
        """Extract basic database information."""
        from scanner.commands.scanning.vulnerability_scanners.sql_injection.advanced_exploitation_engine import ExtractionTarget
        
        print(f"    {Colors.CYAN}[*]{Colors.ENDC} Extracting basic database information...")
        
        results = {}
        
        # Extract database version
        try:
            version_result = await engine.extract_data(context, ExtractionTarget.DATABASE_VERSION)
            if version_result.success:
                print(f"        {Colors.GREEN}[+]{Colors.ENDC} Database version: {version_result.data}")
                results['version'] = version_result.data
        except Exception as e:
            print(f"        {Colors.YELLOW}[!]{Colors.ENDC} Version extraction failed: {e}")
        
        # Extract current user
        try:
            user_result = await engine.extract_data(context, ExtractionTarget.CURRENT_USER)
            if user_result.success:
                print(f"        {Colors.GREEN}[+]{Colors.ENDC} Current user: {user_result.data}")
                results['current_user'] = user_result.data
        except Exception as e:
            print(f"        {Colors.YELLOW}[!]{Colors.ENDC} User extraction failed: {e}")
        
        # Extract current database
        try:
            db_result = await engine.extract_data(context, ExtractionTarget.CURRENT_DATABASE)
            if db_result.success:
                print(f"        {Colors.GREEN}[+]{Colors.ENDC} Current database: {db_result.data}")
                results['current_database'] = db_result.data
        except Exception as e:
            print(f"        {Colors.YELLOW}[!]{Colors.ENDC} Database extraction failed: {e}")
        
        return {
            'type': 'basic_info',
            'data': results,
            'timestamp': time.time()
        }
    
    async def _extract_schema_info(self, engine, context, params):
        """Extract database schema information."""
        print(f"    {Colors.CYAN}[*]{Colors.ENDC} Extracting database schema...")
        
        results = {}
        
        if params.get('dump_tables') or params.get('dump'):
            try:
                schema_info = await engine.enumerate_schema(context)
                print(f"        {Colors.GREEN}[+]{Colors.ENDC} Found {len(schema_info.tables)} tables")
                for table in schema_info.tables[:5]:  # Show first 5
                    print(f"            • {table}")
                if len(schema_info.tables) > 5:
                    print(f"            ... and {len(schema_info.tables) - 5} more")
                
                results['schema'] = {
                    'database': schema_info.database_name,
                    'tables': schema_info.tables,
                    'columns': schema_info.columns,
                    'sensitive_tables': schema_info.sensitive_tables
                }
            except Exception as e:
                print(f"        {Colors.YELLOW}[!]{Colors.ENDC} Schema extraction failed: {e}")
        
        return {
            'type': 'schema_info',
            'data': results,
            'timestamp': time.time()
        }
    
    async def _attempt_file_read(self, engine, context, params):
        """Attempt to read files from the server."""
        file_path = params.get('file_read')
        print(f"    {Colors.CYAN}[*]{Colors.ENDC} Attempting to read file: {file_path}")
        
        results = {}
        
        try:
            # Create custom query for file reading (MySQL example)
            file_query = f"SELECT LOAD_FILE('{file_path}')"
            
            from scanner.commands.scanning.vulnerability_scanners.sql_injection.advanced_exploitation_engine import ExtractionTarget
            file_result = await engine.extract_data(context, ExtractionTarget.CUSTOM_QUERY, file_query)
            
            if file_result.success and file_result.data:
                print(f"        {Colors.GREEN}[+]{Colors.ENDC} File read successful!")
                print(f"        {Colors.GREEN}[+]{Colors.ENDC} Content length: {len(str(file_result.data))} chars")
                results['file_content'] = str(file_result.data)[:1000]  # Limit output
                results['file_path'] = file_path
            else:
                print(f"        {Colors.YELLOW}[!]{Colors.ENDC} File read failed or file not found")
        except Exception as e:
            print(f"        {Colors.RED}[-]{Colors.ENDC} File read error: {e}")
        
        return {
            'type': 'file_read',
            'data': results,
            'timestamp': time.time()
        }
    
    async def _run_advanced_exploitation(self, engine, context, params):
        """Run advanced exploitation techniques."""
        print(f"    {Colors.CYAN}[*]{Colors.ENDC} Running advanced exploitation...")
        
        results = []
        
        try:
            # Assess privileges
            privileges = await engine.assess_privileges(context)
            print(f"        {Colors.GREEN}[+]{Colors.ENDC} Privilege level: {privileges.name}")
            
            results.append({
                'type': 'privilege_assessment',
                'data': {'privilege_level': privileges.name},
                'timestamp': time.time()
            })
            
        except Exception as e:
            print(f"        {Colors.YELLOW}[!]{Colors.ENDC} Privilege assessment failed: {e}")
        
        return results
