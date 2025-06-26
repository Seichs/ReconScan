"""
ReconScan AI Vulnerability Classifier

Advanced AI-powered false positive detection system for vulnerability scanning.
Analyzes scan results to determine if detected vulnerabilities are exploitable
or false positives based on context, response patterns, and execution likelihood.
"""

import re
import html
import json
import pickle
import logging
from typing import Dict, List, Tuple, Optional, Any
from dataclasses import dataclass
from enum import Enum
import urllib.parse

class VulnerabilityType(Enum):
    """Supported vulnerability types for AI classification."""
    XSS_REFLECTED = "xss_reflected"
    XSS_STORED = "xss_stored" 
    XSS_DOM = "xss_dom"
    SQL_INJECTION = "sql_injection"
    COMMAND_INJECTION = "command_injection"
    LFI = "local_file_inclusion"
    DIRECTORY_TRAVERSAL = "directory_traversal"

class ConfidenceLevel(Enum):
    """AI confidence levels for vulnerability classification."""
    VERY_HIGH = 0.9
    HIGH = 0.75
    MEDIUM = 0.6
    LOW = 0.4
    VERY_LOW = 0.2

@dataclass
class VulnerabilityContext:
    """Context information for vulnerability analysis."""
    payload: str
    response_body: str
    response_headers: Dict[str, str]
    status_code: int
    response_time: float
    parameter_name: str
    injection_point: str
    vulnerability_type: VulnerabilityType

@dataclass
class ClassificationResult:
    """AI classification result with confidence scoring."""
    is_vulnerable: bool
    confidence: float
    confidence_level: ConfidenceLevel
    reasons: List[str]
    risk_factors: List[str]
    mitigation_evidence: List[str]
    execution_context: str
    recommendation: str

class AIVulnerabilityClassifier:
    """
    Advanced AI classifier for vulnerability false positive detection.
    
    Uses rule-based heuristics, context analysis, and pattern recognition
    to determine if detected vulnerabilities are actually exploitable.
    """
    
    def __init__(self, model_path: str = "models/classifier.pkl"):
        """Initialize AI classifier with optional pre-trained model."""
        self.model_path = model_path
        self.ml_model = None
        self.logger = logging.getLogger(__name__)
        
        # Load pre-trained model if available
        self._load_model()
        
        # Initialize XSS context patterns
        self._init_xss_patterns()
        
        # Initialize SQL injection patterns
        self._init_sql_patterns()
        
        # Initialize security header patterns
        self._init_security_patterns()
    
    def _load_model(self) -> None:
        """Load pre-trained ML model if available."""
        try:
            with open(self.model_path, 'rb') as f:
                self.ml_model = pickle.load(f)
                self.logger.info("Pre-trained ML model loaded successfully")
        except (FileNotFoundError, pickle.UnpicklingError, EOFError):
            self.logger.info("No pre-trained model found, using rule-based classification")
            self.ml_model = None
    
    def _init_xss_patterns(self) -> None:
        """Initialize XSS detection patterns for vulnerability classification."""
        # TODO: Pre-compile regex patterns for better performance
        
        # Dangerous XSS execution contexts - compiled patterns
        self.dangerous_xss_contexts = [
            re.compile(r'<script[^>]*>{payload}.*?</script>', re.IGNORECASE),
            re.compile(r'javascript:{payload}', re.IGNORECASE),
            re.compile(r'on\w+\s*=\s*["\']?{payload}', re.IGNORECASE),
            re.compile(r'<iframe[^>]*src\s*=\s*["\']?{payload}', re.IGNORECASE),
            re.compile(r'<img[^>]*src\s*=\s*["\']?{payload}', re.IGNORECASE)
        ]
        
        # Safe XSS contexts - compiled patterns  
        self.safe_xss_contexts = [
            re.compile(r'<input[^>]*value\s*=\s*["\']?{payload}["\']?', re.IGNORECASE),
            re.compile(r'<textarea[^>]*>{payload}</textarea>', re.IGNORECASE),
            re.compile(r'<!--.*?{payload}.*?-->', re.IGNORECASE),
            re.compile(r'<title[^>]*>{payload}</title>', re.IGNORECASE)
        ]
    
    def _init_sql_patterns(self) -> None:
        """Initialize SQL injection detection patterns."""
        # SQL error patterns indicating successful injection
        self.sql_error_patterns = [
            r'SQL syntax.*?error',
            r'mysql_fetch_array\(\)',
            r'ORA-\d{5}',
            r'Microsoft.*?ODBC.*?SQL',
            r'PostgreSQL.*?ERROR',
            r'Warning.*?mysql_.*',
            r'valid MySQL result',
            r'MySqlClient\.',
        ]
        
        # Database-specific fingerprint patterns
        self.db_fingerprints = {
            'mysql': [r'mysql', r'@@version', r'information_schema'],
            'postgresql': [r'postgresql', r'pg_', r'version\(\)'],
            'mssql': [r'microsoft', r'sql server', r'@@version'],
            'oracle': [r'ora-', r'oracle', r'dual'],
        }
    
    def _init_security_patterns(self) -> None:
        """Initialize security header and protection patterns."""
        self.security_headers = [
            'content-security-policy',
            'x-frame-options', 
            'x-xss-protection',
            'x-content-type-options',
            'strict-transport-security'
        ]
        
        # WAF detection patterns
        self.waf_patterns = [
            r'cloudflare', r'incapsula', r'sucuri', r'akamai',
            r'blocked', r'forbidden', r'access denied',
            r'security policy', r'firewall'
        ]
    
    def classify_vulnerability(self, context: VulnerabilityContext) -> ClassificationResult:
        """
        Main classification method to determine if vulnerability is real or false positive.
        
        Args:
            context: Vulnerability context information
            
        Returns:
            ClassificationResult with confidence scoring and analysis
        """
        if context.vulnerability_type in [VulnerabilityType.XSS_REFLECTED, 
                                        VulnerabilityType.XSS_STORED, 
                                        VulnerabilityType.XSS_DOM]:
            return self._classify_xss(context)
        elif context.vulnerability_type == VulnerabilityType.SQL_INJECTION:
            return self._classify_sql_injection(context)
        elif context.vulnerability_type == VulnerabilityType.COMMAND_INJECTION:
            return self._classify_command_injection(context)
        elif context.vulnerability_type in [VulnerabilityType.LFI, 
                                          VulnerabilityType.DIRECTORY_TRAVERSAL]:
            return self._classify_file_inclusion(context)
        else:
            return self._classify_generic(context)
    
    def _classify_xss(self, context: VulnerabilityContext) -> ClassificationResult:
        """Classify XSS vulnerability with context analysis."""
        reasons = []
        risk_factors = []
        mitigation_evidence = []
        confidence_score = 0.0
        
        payload = context.payload
        response = context.response_body.lower()
        headers = {k.lower(): v.lower() for k, v in context.response_headers.items()}
        
        # Check if payload is present in response
        if payload.lower() not in response:
            reasons.append("Payload not found in response")
            return ClassificationResult(
                is_vulnerable=False,
                confidence=0.1,
                confidence_level=ConfidenceLevel.VERY_LOW,
                reasons=reasons,
                risk_factors=risk_factors,
                mitigation_evidence=["Payload completely filtered"],
                execution_context="No reflection detected",
                recommendation="False positive - payload not reflected"
            )
        
        # Check for HTML encoding (major mitigation)
        encoded_payload = html.escape(payload)
        if encoded_payload.lower() in response:
            mitigation_evidence.append("HTML encoding detected")
            confidence_score -= 0.3
            reasons.append("Payload is HTML encoded")
        
        # Check for dangerous execution contexts
        dangerous_context_found = False
        for pattern_template in self.dangerous_xss_contexts:
            # Substitute payload into the pattern template for efficient matching
            pattern_str = pattern_template.pattern.replace('{payload}', re.escape(payload))
            if re.search(pattern_str, response, re.IGNORECASE):
                dangerous_context_found = True
                risk_factors.append(f"Dangerous context: {pattern_template.pattern.split('{')[0]}")
                confidence_score += 0.4
                break
        
        # Check for safe contexts
        safe_context_found = False
        for pattern_template in self.safe_xss_contexts:
            # Substitute payload into the pattern template for efficient matching
            pattern_str = pattern_template.pattern.replace('{payload}', re.escape(payload))
            if re.search(pattern_str, response, re.IGNORECASE):
                safe_context_found = True
                mitigation_evidence.append(f"Safe context: {pattern_template.pattern.split('{')[0]}")
                confidence_score -= 0.2
                break
        
        # Check Content Security Policy
        csp_header = headers.get('content-security-policy', '')
        if csp_header and 'unsafe-inline' not in csp_header:
            mitigation_evidence.append("Strong CSP detected")
            confidence_score -= 0.3
            reasons.append("CSP prevents inline script execution")
        
        # Check X-XSS-Protection header
        xss_protection = headers.get('x-xss-protection', '')
        if xss_protection and '1' in xss_protection:
            mitigation_evidence.append("XSS protection enabled")
            confidence_score -= 0.1
        
        # Check for JavaScript execution indicators
        if any(js_indicator in payload.lower() for js_indicator in ['alert(', 'prompt(', 'confirm(', 'console.log']):
            if dangerous_context_found:
                risk_factors.append("JavaScript execution payload in dangerous context")
                confidence_score += 0.3
            else:
                reasons.append("JavaScript payload but no dangerous context")
        
        # Determine final classification
        base_confidence = 0.5 if dangerous_context_found else 0.2
        final_confidence = max(0.0, min(1.0, base_confidence + confidence_score))
        
        is_vulnerable = final_confidence >= 0.6 and dangerous_context_found
        
        if not reasons:
            reasons.append("Context analysis completed")
        
        confidence_level = self._get_confidence_level(final_confidence)
        
        execution_context = "Dangerous execution context" if dangerous_context_found else \
                          "Safe context" if safe_context_found else "Unknown context"
        
        recommendation = self._generate_xss_recommendation(is_vulnerable, risk_factors, mitigation_evidence)
        
        return ClassificationResult(
            is_vulnerable=is_vulnerable,
            confidence=final_confidence,
            confidence_level=confidence_level,
            reasons=reasons,
            risk_factors=risk_factors,
            mitigation_evidence=mitigation_evidence,
            execution_context=execution_context,
            recommendation=recommendation
        )
    
    def _classify_sql_injection(self, context: VulnerabilityContext) -> ClassificationResult:
        """Classify SQL injection vulnerability."""
        reasons = []
        risk_factors = []
        mitigation_evidence = []
        confidence_score = 0.5
        
        response = context.response_body
        
        # Check for SQL error messages
        sql_errors_found = []
        for pattern in self.sql_error_patterns:
            if re.search(pattern, response, re.IGNORECASE):
                sql_errors_found.append(pattern)
                confidence_score += 0.2
        
        if sql_errors_found:
            risk_factors.extend([f"SQL error detected: {err}" for err in sql_errors_found])
            reasons.append("Database error messages indicate successful injection")
        
        # Check for time-based indicators
        if context.response_time > 5.0:  # 5+ second delay
            risk_factors.append(f"Significant response delay: {context.response_time:.2f}s")
            confidence_score += 0.3
            reasons.append("Time-based blind SQL injection indicators")
        
        # Check for database fingerprinting
        for db_type, patterns in self.db_fingerprints.items():
            for pattern in patterns:
                if re.search(pattern, response, re.IGNORECASE):
                    risk_factors.append(f"Database fingerprint detected: {db_type}")
                    confidence_score += 0.1
                    break
        
        # Check for WAF interference
        for waf_pattern in self.waf_patterns:
            if re.search(waf_pattern, response, re.IGNORECASE):
                mitigation_evidence.append("WAF protection detected")
                confidence_score -= 0.2
                break
        
        final_confidence = max(0.0, min(1.0, confidence_score))
        is_vulnerable = final_confidence >= 0.7
        
        return ClassificationResult(
            is_vulnerable=is_vulnerable,
            confidence=final_confidence,
            confidence_level=self._get_confidence_level(final_confidence),
            reasons=reasons or ["SQL injection analysis completed"],
            risk_factors=risk_factors,
            mitigation_evidence=mitigation_evidence,
            execution_context="Database interaction detected" if sql_errors_found else "No clear database interaction",
            recommendation=self._generate_sql_recommendation(is_vulnerable, risk_factors, mitigation_evidence)
        )
    
    def _classify_command_injection(self, context: VulnerabilityContext) -> ClassificationResult:
        """Classify command injection vulnerability."""
        reasons = []
        risk_factors = []
        mitigation_evidence = []
        confidence_score = 0.4
        
        response = context.response_body
        payload = context.payload
        
        # Check for command output patterns
        command_indicators = [
            r'uid=\d+', r'gid=\d+',  # Unix user info
            r'root:', r'/bin/', r'/usr/',  # Unix paths
            r'Windows.*?Version', r'Microsoft Windows',  # Windows version
            r'Volume.*?Serial Number',  # Windows dir command
        ]
        
        for pattern in command_indicators:
            if re.search(pattern, response, re.IGNORECASE):
                risk_factors.append(f"Command output pattern: {pattern}")
                confidence_score += 0.3
                reasons.append("System command output detected")
        
        # Time-based detection
        if context.response_time > 3.0:
            risk_factors.append(f"Response delay: {context.response_time:.2f}s")
            confidence_score += 0.2
            reasons.append("Time-based command injection indicators")
        
        # Check for error patterns
        error_patterns = [r'command not found', r'permission denied', r'access denied']
        for pattern in error_patterns:
            if re.search(pattern, response, re.IGNORECASE):
                mitigation_evidence.append(f"Command execution restricted: {pattern}")
                confidence_score -= 0.1
        
        final_confidence = max(0.0, min(1.0, confidence_score))
        is_vulnerable = final_confidence >= 0.6
        
        return ClassificationResult(
            is_vulnerable=is_vulnerable,
            confidence=final_confidence,
            confidence_level=self._get_confidence_level(final_confidence),
            reasons=reasons or ["Command injection analysis completed"],
            risk_factors=risk_factors,
            mitigation_evidence=mitigation_evidence,
            execution_context="System command execution" if risk_factors else "No command execution detected",
            recommendation=self._generate_command_recommendation(is_vulnerable, risk_factors, mitigation_evidence)
        )
    
    def _classify_file_inclusion(self, context: VulnerabilityContext) -> ClassificationResult:
        """Classify file inclusion vulnerability."""
        reasons = []
        risk_factors = []
        mitigation_evidence = []
        confidence_score = 0.4
        
        response = context.response_body
        
        # Check for file content indicators
        file_indicators = [
            r'root:.*?:/root:/bin/',  # /etc/passwd
            r'\[boot loader\]',  # Windows boot.ini
            r'<\?php', r'<?=',  # PHP code execution
            r'#.*?Apache.*?Configuration',  # Apache config
        ]
        
        for pattern in file_indicators:
            if re.search(pattern, response, re.IGNORECASE):
                risk_factors.append(f"File content detected: {pattern}")
                confidence_score += 0.4
                reasons.append("Sensitive file content exposed")
        
        # Check for directory listing
        if re.search(r'Index of /', response) or re.search(r'Directory listing', response):
            risk_factors.append("Directory listing exposed")
            confidence_score += 0.2
        
        final_confidence = max(0.0, min(1.0, confidence_score))
        is_vulnerable = final_confidence >= 0.6
        
        return ClassificationResult(
            is_vulnerable=is_vulnerable,
            confidence=final_confidence,
            confidence_level=self._get_confidence_level(final_confidence),
            reasons=reasons or ["File inclusion analysis completed"],
            risk_factors=risk_factors,
            mitigation_evidence=mitigation_evidence,
            execution_context="File system access" if risk_factors else "No file access detected",
            recommendation=self._generate_file_recommendation(is_vulnerable, risk_factors, mitigation_evidence)
        )
    
    def _classify_generic(self, context: VulnerabilityContext) -> ClassificationResult:
        """Generic classification for unsupported vulnerability types."""
        return ClassificationResult(
            is_vulnerable=False,
            confidence=0.5,
            confidence_level=ConfidenceLevel.MEDIUM,
            reasons=["Generic analysis - specific classifier not available"],
            risk_factors=[],
            mitigation_evidence=[],
            execution_context="Unknown",
            recommendation="Manual verification recommended"
        )
    
    def _get_confidence_level(self, confidence: float) -> ConfidenceLevel:
        """Convert confidence score to confidence level enum."""
        if confidence >= 0.9:
            return ConfidenceLevel.VERY_HIGH
        elif confidence >= 0.75:
            return ConfidenceLevel.HIGH
        elif confidence >= 0.6:
            return ConfidenceLevel.MEDIUM
        elif confidence >= 0.4:
            return ConfidenceLevel.LOW
        else:
            return ConfidenceLevel.VERY_LOW
    
    def _generate_xss_recommendation(self, is_vulnerable: bool, risk_factors: List[str], 
                                   mitigation_evidence: List[str]) -> str:
        """Generate XSS-specific recommendation."""
        if is_vulnerable:
            return "VERIFY MANUALLY: Execute payload in browser to confirm XSS execution"
        elif mitigation_evidence:
            return f"Likely false positive due to: {', '.join(mitigation_evidence)}"
        else:
            return "Low confidence - manual verification recommended"
    
    def _generate_sql_recommendation(self, is_vulnerable: bool, risk_factors: List[str],
                                   mitigation_evidence: List[str]) -> str:
        """Generate SQL injection-specific recommendation."""
        if is_vulnerable:
            return "HIGH RISK: Database errors indicate successful SQL injection"
        elif mitigation_evidence:
            return f"Blocked by security measures: {', '.join(mitigation_evidence)}"
        else:
            return "No clear SQL injection indicators - likely false positive"
    
    def _generate_command_recommendation(self, is_vulnerable: bool, risk_factors: List[str],
                                       mitigation_evidence: List[str]) -> str:
        """Generate command injection-specific recommendation."""
        if is_vulnerable:
            return "CRITICAL: System command execution detected"
        else:
            return "No command execution evidence - likely false positive"
    
    def _generate_file_recommendation(self, is_vulnerable: bool, risk_factors: List[str],
                                    mitigation_evidence: List[str]) -> str:
        """Generate file inclusion-specific recommendation."""
        if is_vulnerable:
            return "HIGH RISK: Sensitive file access detected"
        else:
            return "No file access evidence - likely false positive"
    
    def batch_classify(self, contexts: List[VulnerabilityContext]) -> List[ClassificationResult]:
        """Classify multiple vulnerabilities in batch."""
        results = []
        for context in contexts:
            try:
                result = self.classify_vulnerability(context)
                results.append(result)
            except Exception as e:
                self.logger.error(f"Classification error for {context.vulnerability_type}: {e}")
                # Return safe default for errors
                results.append(ClassificationResult(
                    is_vulnerable=False,
                    confidence=0.0,
                    confidence_level=ConfidenceLevel.VERY_LOW,
                    reasons=[f"Classification error: {str(e)}"],
                    risk_factors=[],
                    mitigation_evidence=[],
                    execution_context="Error",
                    recommendation="Manual verification required due to classification error"
                ))
        return results
    
    def get_statistics(self, results: List[ClassificationResult]) -> Dict[str, Any]:
        """Generate classification statistics."""
        total = len(results)
        if total == 0:
            return {}
        
        vulnerable_count = sum(1 for r in results if r.is_vulnerable)
        false_positive_count = total - vulnerable_count
        
        confidence_distribution = {}
        for level in ConfidenceLevel:
            confidence_distribution[level.name] = sum(
                1 for r in results if r.confidence_level == level
            )
        
        avg_confidence = sum(r.confidence for r in results) / total
        
        return {
            'total_analyzed': total,
            'vulnerable_count': vulnerable_count,
            'false_positive_count': false_positive_count,
            'false_positive_rate': false_positive_count / total * 100,
            'average_confidence': avg_confidence,
            'confidence_distribution': confidence_distribution
        }
