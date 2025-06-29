#!/usr/bin/env python3
"""
Test script for professional HTML report generation
"""

import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), 'scanner'))

from scanner.commands.scanning.vulnerability_scanners.educational_security_reporter import EducationalSecurityReporter
from datetime import datetime

def test_professional_report():
    """Test the professional HTML report generation."""
    
    # Sample vulnerability data
    sample_vulnerabilities = [
        {
            "type": "sql_injection",
            "url": "http://testphp.vulnweb.com/listproducts.php",
            "parameter": "cat",
            "method": "GET",
            "payload": "' OR '1'='1",
            "evidence": "MySQL error detected",
            "confidence": 0.95
        },
        {
            "type": "xss",
            "url": "http://testphp.vulnweb.com/search.php",
            "parameter": "searchFor",
            "method": "GET", 
            "payload": "<script>alert('XSS')</script>",
            "evidence": "Script executed in response",
            "confidence": 0.85
        },
        {
            "type": "directory_traversal",
            "url": "http://testphp.vulnweb.com/showimage.php",
            "parameter": "file",
            "method": "GET",
            "payload": "../../../etc/passwd",
            "evidence": "File system access detected",
            "confidence": 0.75
        }
    ]
    
    # Sample scan metadata
    scan_metadata = {
        "target": "http://testphp.vulnweb.com",
        "scan_date": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        "scanner_version": "ReconScan Professional v1.0"
    }
    
    # Generate professional report
    reporter = EducationalSecurityReporter()
    output_path = "results/professional_security_report.html"
    
    print("Testing professional HTML report generation...")
    success = reporter.generate_educational_report(
        vulnerabilities=sample_vulnerabilities,
        scan_metadata=scan_metadata,
        output_path=output_path,
        format_type="html"
    )
    
    if success:
        print(f"\n✅ Professional report generated successfully!")
        print(f"📄 Report saved to: {output_path}")
        print(f"🌐 Open in browser to view the modern, professional styling")
        
        # Print file size for reference
        if os.path.exists(output_path):
            file_size = os.path.getsize(output_path) / 1024  # KB
            print(f"📊 Report size: {file_size:.1f} KB")
            
    else:
        print("❌ Failed to generate professional report")
        return False
    
    return True

if __name__ == "__main__":
    test_professional_report() 