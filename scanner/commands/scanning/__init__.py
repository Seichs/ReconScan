"""
ReconScan Security Scanning Framework

Professional vulnerability scanning framework with organized, modular architecture.
Each vulnerability type has its own dedicated module while sharing common functionality.

Architecture:
- shared/: Common components (injection discovery, payload management, filters)
- vulnerability_scanners/: Individual vulnerability modules
  - sql_injection/: SQL injection detection and exploitation
  - xss/: Cross-Site Scripting detection
  - lfi/: Local File Inclusion detection
  - command_injection/: OS command injection detection  
  - directory_traversal/: Path traversal detection
  - security_headers/: Security headers analysis

This organization provides clean separation of concerns while maintaining
shared functionality and professional code structure.
"""

# Import shared components
from .shared import (
    InjectionPointDiscovery,
    InjectionPoint,
    InjectionPointType, 
    ParameterType,
    DiscoveryResult,
        EnhancedPayloadManager,
    PayloadContext,
    VulnerabilityType,
    WAFType,
    FalsePositiveFilters
)

# Import vulnerability scanner modules
from .vulnerability_scanners import *

__all__ = [
    # Shared Components
    'InjectionPointDiscovery',
    'InjectionPoint',
    'InjectionPointType',
    'ParameterType', 
    'DiscoveryResult',
    'EnhancedPayloadManager',
    'PayloadContext',
    'VulnerabilityType',
    'WAFType',
    'FalsePositiveFilters',
    
    # SQL Injection Module
    'PayloadCraftingEngine',
    'PayloadTemplate',
    'PayloadCraftingContext',
    'DatabaseType',
    'InjectionTechnique',
    'EncodingType',
    
    # Other Vulnerability Scanners
    'XSSScanner',
    'XSSPayloads',
    'LFIScanner', 
    'LFIPayloads',
    'CommandInjectionScanner',
    'CommandInjectionPayloads',
    'DirectoryTraversalScanner',
    'DirectoryTraversalPayloads', 
    'SecurityHeadersScanner'
] 