"""
ReconScan AI Vulnerability Validator

AI-powered vulnerability validation system that integrates with vulnerability scanners
to provide intelligent false positive detection and vulnerability confidence scoring.
"""

import logging
from typing import Dict, List, Optional, Any
from urllib.parse import urlparse

from .ai_classifier import (
    AIVulnerabilityClassifier, 
    VulnerabilityContext, 
    VulnerabilityType, 
    ConfidenceLevel
)

class AIVulnerabilityValidator:
    """
    AI-powered vulnerability validator for integration with scanners.
    
    Provides intelligent false positive detection using the AI classifier
    with a simplified interface for scanner integration.
    """
    
    def __init__(self, model_path: str = "models/classifier.pkl"):
        """Initialize AI validator with classifier."""
        self.classifier = AIVulnerabilityClassifier(model_path)
        self.logger = logging.getLogger(__name__)
        
        # Mapping from scanner types to AI vulnerability types
        self.vuln_type_mapping = {
            'sql_injection': VulnerabilityType.SQL_INJECTION,
            'xss_reflected': VulnerabilityType.XSS_REFLECTED,
            'xss_stored': VulnerabilityType.XSS_STORED,
            'xss_dom': VulnerabilityType.XSS_DOM,
            'command_injection': VulnerabilityType.COMMAND_INJECTION,
            'lfi': VulnerabilityType.LFI,
            'directory_traversal': VulnerabilityType.DIRECTORY_TRAVERSAL
        }
    
    def validate_sql_injection(self, test_url: str, param_name: str, payload: str, 
                             response_body: str, response_headers: Dict[str, str] = None,
                             status_code: int = 200, response_time: float = 0.0) -> Dict[str, Any]:
        """
        Validate SQL injection vulnerability using AI classifier.
        
        Args:
            test_url: URL that was tested
            param_name: Parameter name that was tested
            payload: SQL injection payload used
            response_body: Response body content
            response_headers: Response headers (optional)
            status_code: HTTP status code
            response_time: Response time in seconds
            
        Returns:
            dict: Validation result with is_vulnerable, confidence, and details
        """
        return self._validate_vulnerability(
            'sql_injection', test_url, param_name, payload,
            response_body, response_headers, status_code, response_time
        )
    
    def validate_xss(self, test_url: str, param_name: str, payload: str,
                    response_body: str, response_headers: Dict[str, str] = None,
                    status_code: int = 200, response_time: float = 0.0,
                    xss_type: str = 'reflected') -> Dict[str, Any]:
        """
        Validate XSS vulnerability using AI classifier.
        
        Args:
            test_url: URL that was tested
            param_name: Parameter name that was tested
            payload: XSS payload used
            response_body: Response body content
            response_headers: Response headers (optional)
            status_code: HTTP status code
            response_time: Response time in seconds
            xss_type: Type of XSS (reflected, stored, dom)
            
        Returns:
            dict: Validation result with is_vulnerable, confidence, and details
        """
        vuln_type = f'xss_{xss_type.lower()}'
        return self._validate_vulnerability(
            vuln_type, test_url, param_name, payload,
            response_body, response_headers, status_code, response_time
        )
    
    def validate_command_injection(self, test_url: str, param_name: str, payload: str,
                                 response_body: str, response_headers: Dict[str, str] = None,
                                 status_code: int = 200, response_time: float = 0.0) -> Dict[str, Any]:
        """
        Validate command injection vulnerability using AI classifier.
        
        Args:
            test_url: URL that was tested
            param_name: Parameter name that was tested
            payload: Command injection payload used
            response_body: Response body content
            response_headers: Response headers (optional)
            status_code: HTTP status code
            response_time: Response time in seconds
            
        Returns:
            dict: Validation result with is_vulnerable, confidence, and details
        """
        return self._validate_vulnerability(
            'command_injection', test_url, param_name, payload,
            response_body, response_headers, status_code, response_time
        )
    
    def validate_file_inclusion(self, test_url: str, param_name: str, payload: str,
                              response_body: str, response_headers: Dict[str, str] = None,
                              status_code: int = 200, response_time: float = 0.0,
                              inclusion_type: str = 'lfi') -> Dict[str, Any]:
        """
        Validate file inclusion vulnerability using AI classifier.
        
        Args:
            test_url: URL that was tested
            param_name: Parameter name that was tested
            payload: File inclusion payload used
            response_body: Response body content
            response_headers: Response headers (optional)
            status_code: HTTP status code
            response_time: Response time in seconds
            inclusion_type: Type of inclusion (lfi, directory_traversal)
            
        Returns:
            dict: Validation result with is_vulnerable, confidence, and details
        """
        return self._validate_vulnerability(
            inclusion_type, test_url, param_name, payload,
            response_body, response_headers, status_code, response_time
        )
    
    def _validate_vulnerability(self, vuln_type: str, test_url: str, param_name: str, 
                              payload: str, response_body: str, 
                              response_headers: Dict[str, str] = None,
                              status_code: int = 200, response_time: float = 0.0) -> Dict[str, Any]:
        """
        Internal method to validate vulnerability using AI classifier.
        
        Returns:
            dict: Contains is_vulnerable, confidence, ai_label, reason, recommendation
        """
        try:
            # Map to AI vulnerability type
            ai_vuln_type = self.vuln_type_mapping.get(vuln_type)
            if not ai_vuln_type:
                return self._create_fallback_result(f"Unknown vulnerability type: {vuln_type}")
            
            # Create vulnerability context
            context = VulnerabilityContext(
                payload=payload,
                response_body=response_body,
                response_headers=response_headers or {},
                status_code=status_code,
                response_time=response_time,
                parameter_name=param_name,
                injection_point=self._determine_injection_point(test_url, param_name),
                vulnerability_type=ai_vuln_type
            )
            
            # Get AI classification
            result = self.classifier.classify_vulnerability(context)
            
            # Convert to scanner-friendly format
            return {
                'is_vulnerable': result.is_vulnerable,
                'confidence': result.confidence,
                'confidence_level': result.confidence_level.name.lower(),
                'ai_label': f'ai_validated.{vuln_type}',
                'reason': '; '.join(result.reasons) if result.reasons else 'AI analysis completed',
                'risk_factors': result.risk_factors,
                'mitigation_evidence': result.mitigation_evidence,
                'recommendation': result.recommendation,
                'execution_context': result.execution_context
            }
            
        except Exception as e:
            self.logger.error(f"AI validation error for {vuln_type}: {str(e)}")
            return self._create_fallback_result(f"AI validation error: {str(e)}")
    
    def _determine_injection_point(self, test_url: str, param_name: str) -> str:
        """Determine the injection point context for AI analysis."""
        parsed_url = urlparse(test_url)
        
        # Check if it's in query parameters
        if f'{param_name}=' in parsed_url.query:
            return 'query_parameter'
        
        # Check common injection points
        path = parsed_url.path.lower()
        if '/search' in path or '/query' in path:
            return 'search_parameter'
        elif '/login' in path or '/auth' in path:
            return 'authentication_parameter'
        elif '/admin' in path:
            return 'admin_parameter'
        elif '/api' in path:
            return 'api_parameter'
        else:
            return 'generic_parameter'
    
    def _create_fallback_result(self, error_reason: str) -> Dict[str, Any]:
        """Create fallback result when AI validation fails."""
        return {
            'is_vulnerable': None,  # Unknown - let scanner decide
            'confidence': 0.0,
            'confidence_level': 'unknown',
            'ai_label': 'ai_validation_failed',
            'reason': error_reason,
            'risk_factors': [],
            'mitigation_evidence': [],
            'recommendation': 'Manual verification recommended due to AI validation failure',
            'execution_context': 'unknown'
        }
    
    def batch_validate(self, vulnerabilities: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Batch validate multiple vulnerabilities for efficiency.
        
        Args:
            vulnerabilities: List of vulnerability dictionaries with required fields
            
        Returns:
            List of validation results in same order
        """
        results = []
        
        for vuln in vulnerabilities:
            try:
                # Extract required fields
                vuln_type = vuln.get('type', '').lower().replace(' ', '_').replace('(', '').replace(')', '')
                test_url = vuln.get('url', '')
                param_name = vuln.get('parameter', '')
                payload = vuln.get('payload', '')
                response_body = vuln.get('response_body', '')
                response_headers = vuln.get('response_headers', {})
                status_code = vuln.get('status_code', 200)
                response_time = vuln.get('response_time', 0.0)
                
                # Map vulnerability types
                if 'sql' in vuln_type:
                    result = self.validate_sql_injection(
                        test_url, param_name, payload, response_body, 
                        response_headers, status_code, response_time
                    )
                elif 'xss' in vuln_type:
                    xss_type = 'reflected'  # Default
                    if 'stored' in vuln_type:
                        xss_type = 'stored'
                    elif 'dom' in vuln_type:
                        xss_type = 'dom'
                    
                    result = self.validate_xss(
                        test_url, param_name, payload, response_body,
                        response_headers, status_code, response_time, xss_type
                    )
                elif 'command' in vuln_type:
                    result = self.validate_command_injection(
                        test_url, param_name, payload, response_body,
                        response_headers, status_code, response_time
                    )
                elif 'lfi' in vuln_type or 'file' in vuln_type:
                    inclusion_type = 'lfi'
                    if 'directory' in vuln_type or 'traversal' in vuln_type:
                        inclusion_type = 'directory_traversal'
                    
                    result = self.validate_file_inclusion(
                        test_url, param_name, payload, response_body,
                        response_headers, status_code, response_time, inclusion_type
                    )
                else:
                    result = self._create_fallback_result(f"Unsupported vulnerability type: {vuln_type}")
                
                results.append(result)
                
            except Exception as e:
                self.logger.error(f"Error in batch validation: {str(e)}")
                results.append(self._create_fallback_result(f"Batch validation error: {str(e)}"))
        
        return results
    
    def get_validation_statistics(self, results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Get statistics about AI validation results."""
        total = len(results)
        if total == 0:
            return {'total': 0}
        
        vulnerable = sum(1 for r in results if r.get('is_vulnerable') is True)
        not_vulnerable = sum(1 for r in results if r.get('is_vulnerable') is False)
        unknown = sum(1 for r in results if r.get('is_vulnerable') is None)
        
        # Confidence distribution
        confidences = [r.get('confidence', 0.0) for r in results if r.get('confidence') is not None]
        avg_confidence = sum(confidences) / len(confidences) if confidences else 0.0
        
        return {
            'total': total,
            'vulnerable': vulnerable,
            'not_vulnerable': not_vulnerable,
            'unknown': unknown,
            'vulnerable_rate': vulnerable / total * 100,
            'false_positive_rate': not_vulnerable / total * 100,
            'unknown_rate': unknown / total * 100,
            'average_confidence': avg_confidence,
            'high_confidence': sum(1 for c in confidences if c >= 0.75)
        } 