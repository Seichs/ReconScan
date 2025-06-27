"""
ReconScan Educational Report Command

Advanced reporting command that generates comprehensive educational security reports
with detailed vulnerability explanations, remediation guidance, and learning resources.
This command transforms raw scan results into actionable learning experiences.

Features:
- Educational vulnerability analysis
- Step-by-step remediation guidance  
- Code examples and secure coding practices
- Interactive learning elements
- Compliance mapping (OWASP, CWE, CVSS)
- Multiple output formats (HTML, JSON, Markdown)

Author: ReconScan Security Framework
Version: 1.0.0
"""

import json
import os
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Any, Optional

from .scanning.vulnerability_scanners.educational_security_reporter import (
    EducationalSecurityReporter,
    SecurityReportConfig
)

class ReportCommand:
    """
    Educational Security Report Command for ReconScan.
    
    Generates comprehensive educational security reports that help developers
    and security teams understand vulnerabilities and improve their security posture.
    """
    
    # Command metadata
    description = "Generate educational security reports with learning content"
    usage = "report <action> [options]"
    example = "report generate scan_results.json --format html --output security_report.html"
    category = "Educational Reporting"
    
    def __init__(self):
        """Initialize the educational report command."""
        self.reports_dir = Path("reports")
        self.reports_dir.mkdir(exist_ok=True)
        
        # Initialize educational reporter
        self.config = SecurityReportConfig(
            include_executive_summary=True,
            include_technical_details=True,
            include_remediation_guide=True,
            include_learning_resources=True,
            include_code_examples=True,
            include_compliance_mapping=True,
            include_risk_matrix=True,
            include_knowledge_checks=True,
            education_level="intermediate"
        )
        
        self.reporter = EducationalSecurityReporter(self.config)
        
        # Supported formats
        self.supported_formats = ["html", "json", "markdown"]
    
    def execute(self, args=None):
        """Execute the educational report command."""
        try:
            if not args or not args.strip():
                self._show_help()
                return False
            
            # Parse arguments
            parts = args.strip().split()
            action = parts[0].lower()
            
            if action == "generate":
                return self._generate_report(parts[1:])
            elif action == "list":
                return self._list_reports()
            elif action == "view":
                return self._view_report(parts[1:])
            elif action == "help":
                self._show_help()
                return True
            else:
                print(f"❌ Unknown action: {action}")
                self._show_help()
                return False
                
        except Exception as e:
            print(f"❌ Error executing report command: {e}")
            return False
    
    def _generate_report(self, args: List[str]) -> bool:
        """Generate educational security report from scan results."""
        try:
            if not args:
                print("❌ Scan results file required")
                print("Usage: report generate <scan_results.json> [options]")
                return False
            
            input_file = args[0]
            
            # Parse options
            format_type = "html"
            output_file = None
            education_level = "intermediate"
            
            i = 1
            while i < len(args):
                if args[i] == "--format" and i + 1 < len(args):
                    format_type = args[i + 1].lower()
                    i += 2
                elif args[i] == "--output" and i + 1 < len(args):
                    output_file = args[i + 1]
                    i += 2
                elif args[i] == "--level" and i + 1 < len(args):
                    education_level = args[i + 1].lower()
                    i += 2
                else:
                    print(f"⚠️  Unknown option: {args[i]}")
                    i += 1
            
            # Validate format
            if format_type not in self.supported_formats:
                print(f"❌ Unsupported format: {format_type}")
                print(f"Supported formats: {', '.join(self.supported_formats)}")
                return False
            
            # Validate input file
            input_path = Path(input_file)
            if not input_path.exists():
                print(f"❌ Input file not found: {input_file}")
                return False
            
            # Generate output filename if not provided
            if not output_file:
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                output_file = f"educational_security_report_{timestamp}.{format_type}"
            
            output_path = self.reports_dir / output_file
            
            print(f"🎓 Generating Educational Security Report")
            print(f"   📥 Input: {input_file}")
            print(f"   📄 Format: {format_type.upper()}")
            print(f"   📚 Education Level: {education_level}")
            print(f"   📤 Output: {output_path}")
            print()
            
            # Load scan results
            with open(input_path, 'r') as f:
                scan_data = json.load(f)
            
            vulnerabilities = scan_data.get('vulnerabilities', [])
            metadata = scan_data.get('scan_info', {})
            
            if not vulnerabilities:
                print("⚠️  No vulnerabilities found in scan results")
                return False
            
            # Update config based on education level
            self.config.education_level = education_level
            if education_level == "beginner":
                self.config.include_knowledge_checks = True
                self.config.include_code_examples = True
            elif education_level == "advanced":
                self.config.include_compliance_mapping = True
                self.config.include_technical_details = True
            
            # Generate report
            success = self.reporter.generate_educational_report(
                vulnerabilities=vulnerabilities,
                scan_metadata=metadata,
                output_path=str(output_path),
                format_type=format_type
            )
            
            if success:
                print()
                print("✅ Educational Security Report Generated Successfully!")
                print(f"   📊 Report Statistics:")
                stats = self.reporter.report_stats
                print(f"   • {stats['vulnerabilities_processed']} vulnerabilities analyzed")
                print(f"   • {len(vulnerabilities)} learning opportunities created")
                print(f"   • Educational content includes:")
                print(f"     - Detailed vulnerability explanations")
                print(f"     - Business impact analysis")
                print(f"     - Step-by-step remediation guidance")
                print(f"     - Code examples (vulnerable vs secure)")
                print(f"     - Interactive learning elements")
                print(f"     - Curated learning resources")
                print(f"     - Compliance mapping (OWASP, CWE)")
                print()
                print(f"📖 Open the report to start learning: {output_path}")
                
                # Show quick preview
                print(f"\n🎯 Quick Preview:")
                severity_counts = {}
                for vuln in vulnerabilities:
                    severity = vuln.get('severity', 'unknown')
                    severity_counts[severity] = severity_counts.get(severity, 0) + 1
                
                for severity, count in severity_counts.items():
                    icon = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}.get(severity, "⚪")
                    print(f"   {icon} {severity.title()}: {count} vulnerabilities")
                
                print(f"\n💡 This report is designed to help you:")
                print(f"   • Understand what each vulnerability means")
                print(f"   • Learn how attackers exploit these issues")
                print(f"   • Implement proper security fixes")
                print(f"   • Improve your overall security knowledge")
                
                return True
            else:
                print("❌ Failed to generate report")
                return False
                
        except Exception as e:
            print(f"❌ Error generating report: {e}")
            return False
    
    def _list_reports(self) -> bool:
        """List existing educational reports."""
        try:
            report_files = list(self.reports_dir.glob("educational_security_report_*"))
            
            if not report_files:
                print("📁 No educational reports found")
                print("Generate your first report with: report generate <scan_results.json>")
                return True
            
            print("📚 Educational Security Reports")
            print("=" * 60)
            print(f"{'File':<35} {'Date':<20} {'Format':<10}")
            print("-" * 60)
            
            for report_file in sorted(report_files, key=lambda x: x.stat().st_mtime, reverse=True):
                try:
                    file_stats = report_file.stat()
                    modified_time = datetime.fromtimestamp(file_stats.st_mtime)
                    
                    file_name = report_file.name
                    date_str = modified_time.strftime("%Y-%m-%d %H:%M:%S")
                    format_type = report_file.suffix[1:].upper()
                    
                    print(f"{file_name:<35} {date_str:<20} {format_type:<10}")
                    
                except Exception as e:
                    print(f"{report_file.name:<35} {'Error reading file':<30}")
            
            print(f"\nTotal reports: {len(report_files)}")
            print(f"Reports directory: {self.reports_dir.absolute()}")
            
            return True
            
        except Exception as e:
            print(f"❌ Error listing reports: {e}")
            return False
    
    def _view_report(self, args: List[str]) -> bool:
        """View report summary or open report file."""
        try:
            if not args:
                print("❌ Report file required")
                print("Usage: report view <report_file>")
                return False
            
            report_file = args[0]
            report_path = Path(report_file)
            
            if not report_path.exists():
                # Try in reports directory
                report_path = self.reports_dir / report_file
                if not report_path.exists():
                    print(f"❌ Report file not found: {report_file}")
                    return False
            
            print(f"📖 Report Information: {report_path.name}")
            print("=" * 50)
            
            # Show file information
            file_stats = report_path.stat()
            print(f"File Size: {file_stats.st_size:,} bytes")
            print(f"Modified: {datetime.fromtimestamp(file_stats.st_mtime).strftime('%Y-%m-%d %H:%M:%S')}")
            print(f"Format: {report_path.suffix[1:].upper()}")
            
            # If HTML report, suggest opening in browser
            if report_path.suffix.lower() == '.html':
                print(f"\n💡 To view this educational report:")
                print(f"   Open in browser: file://{report_path.absolute()}")
                print(f"   Or double-click the file to open it")
            
            return True
            
        except Exception as e:
            print(f"❌ Error viewing report: {e}")
            return False
    
    def _show_help(self):
        """Show comprehensive help for the report command."""
        print("🎓 ReconScan Educational Report Command")
        print("=" * 50)
        print()
        print("DESCRIPTION:")
        print("  Generate comprehensive educational security reports that transform")
        print("  vulnerability findings into actionable learning experiences.")
        print()
        print("USAGE:")
        print("  report <action> [options]")
        print()
        print("ACTIONS:")
        print("  generate <file>     Generate educational report from scan results")
        print("  list               List existing educational reports")
        print("  view <file>        View report information")
        print("  help               Show this help message")
        print()
        print("GENERATE OPTIONS:")
        print("  --format <type>    Output format (html, json, markdown)")
        print("  --output <file>    Output filename")
        print("  --level <level>    Education level (beginner, intermediate, advanced)")
        print()
        print("EXAMPLES:")
        print("  report generate scan_results.json")
        print("  report generate results.json --format html --output security_report.html")
        print("  report generate results.json --level beginner")
        print("  report list")
        print("  report view security_report.html")
        print()
        print("EDUCATIONAL FEATURES:")
        print("  ✅ Detailed vulnerability explanations")
        print("  ✅ Business impact analysis")
        print("  ✅ Step-by-step remediation guidance")
        print("  ✅ Code examples (vulnerable vs secure)")
        print("  ✅ Interactive learning elements")
        print("  ✅ Knowledge validation quizzes")
        print("  ✅ Curated learning resources")
        print("  ✅ Compliance mapping (OWASP, CWE, CVSS)")
        print()
        print("💡 These reports are designed to help you learn and improve your")
        print("   security knowledge while fixing vulnerabilities!")
    
    @staticmethod
    def save_scan_results(scan_results: Dict[str, Any], output_file: str) -> str:
        """
        Save scan results to file in various formats.
        
        This method provides backward compatibility with the traditional scan command
        while also supporting the new educational reporting system.
        
        Args:
            scan_results (dict): Scan results data
            output_file (str): Output file path
            
        Returns:
            str: Path to the saved file
        """
        try:
            output_path = Path(output_file)
            
            # Determine output format based on file extension
            if output_path.suffix.lower() == '.json':
                # Save as JSON
                with open(output_path, 'w', encoding='utf-8') as f:
                    json.dump(scan_results, f, indent=2, ensure_ascii=False)
                return str(output_path)
            
            elif output_path.suffix.lower() in ['.txt', '.text']:
                # Save as formatted text report
                return ReportCommand._save_text_report(scan_results, output_path)
            
            else:
                # Default to JSON if no recognized extension
                json_path = output_path.with_suffix('.json')
                with open(json_path, 'w', encoding='utf-8') as f:
                    json.dump(scan_results, f, indent=2, ensure_ascii=False)
                return str(json_path)
                
        except Exception as e:
            print(f"Error saving scan results: {e}")
            # Fallback to JSON in current directory
            fallback_path = Path(f"scan_results_{int(datetime.now().timestamp())}.json")
            with open(fallback_path, 'w', encoding='utf-8') as f:
                json.dump(scan_results, f, indent=2, ensure_ascii=False)
            return str(fallback_path)
    
    @staticmethod
    def _save_text_report(scan_results: Dict[str, Any], output_path: Path) -> str:
        """
        Save scan results as a formatted text report.
        
        This provides traditional text-based reporting for users who prefer
        simple text output over educational HTML reports.
        
        Args:
            scan_results (dict): Scan results data
            output_path (Path): Output file path
            
        Returns:
            str: Path to the saved file
        """
        try:
            with open(output_path, 'w', encoding='utf-8') as f:
                # Write header
                f.write("=" * 80 + "\n")
                f.write("RECONSCAN VULNERABILITY SCAN REPORT\n")
                f.write("=" * 80 + "\n\n")
                
                # Scan information
                scan_info = scan_results.get('scan_info', {})
                f.write("SCAN INFORMATION\n")
                f.write("-" * 40 + "\n")
                f.write(f"Target: {scan_info.get('target', 'N/A')}\n")
                f.write(f"Start Time: {scan_info.get('start_time', 'N/A')}\n")
                f.write(f"Duration: {scan_info.get('duration', 'N/A')}\n")
                f.write(f"Modules: {', '.join(scan_info.get('modules', []))}\n")
                f.write(f"Scanner Version: {scan_info.get('scanner_version', 'N/A')}\n\n")
                
                # Summary
                summary = scan_results.get('summary', {})
                f.write("SUMMARY\n")
                f.write("-" * 40 + "\n")
                f.write(f"Total Vulnerabilities: {summary.get('total_vulnerabilities', 0)}\n")
                
                # Severity breakdown
                severity_counts = summary.get('by_severity', {})
                for severity, count in severity_counts.items():
                    if count > 0:
                        f.write(f"  {severity}: {count}\n")
                f.write("\n")
                
                # Detailed vulnerabilities
                vulnerabilities = scan_results.get('vulnerabilities', [])
                if vulnerabilities:
                    f.write("DETAILED VULNERABILITIES\n")
                    f.write("-" * 40 + "\n\n")
                    
                    for i, vuln in enumerate(vulnerabilities, 1):
                        f.write(f"[{i}] {vuln.get('type', 'Unknown')}\n")
                        f.write(f"    Severity: {vuln.get('severity', 'Unknown')}\n")
                        f.write(f"    URL: {vuln.get('url', 'N/A')}\n")
                        f.write(f"    Method: {vuln.get('method', 'GET')}\n")
                        
                        if vuln.get('parameter'):
                            f.write(f"    Parameter: {vuln.get('parameter')}\n")
                        
                        if vuln.get('payload'):
                            f.write(f"    Payload: {vuln.get('payload')}\n")
                        
                        if vuln.get('description'):
                            f.write(f"    Description: {vuln.get('description')}\n")
                        
                        f.write("\n")
                else:
                    f.write("No vulnerabilities detected.\n\n")
                
                # Footer
                f.write("=" * 80 + "\n")
                f.write("Generated by ReconScan Security Scanner\n")
                f.write(f"Report saved: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write("=" * 80 + "\n")
                
                # Educational note
                f.write("\nNOTE: For comprehensive learning and educational content,\n")
                f.write("use the 'report generate' command to create detailed\n")
                f.write("educational security reports with remediation guidance.\n")
            
            return str(output_path)
            
        except Exception as e:
            print(f"Error saving text report: {e}")
            raise 