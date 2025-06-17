"""
ReconScan Report Command Module

Scan result viewing and management functionality.
Provides capabilities to view, filter, export, and manage scan result files.
"""

import json
import os
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Any, Optional

class ReportCommand:
    """
    Scan result viewing and management for ReconScan.
    
    Provides capabilities to view scan results, filter vulnerabilities,
    export reports in different formats, and manage result files.
    Also handles report generation from scan results.
    """
    
    # Command metadata - self-documenting for help system
    description = "View and manage scan result files"
    usage = "report <action> [options]"
    example = "report view results.json --severity high"
    category = "Reports"
    
    def __init__(self):
        """Initialize report command with default paths."""
        
        # Default reports directory
        self.reports_dir = Path("reports")
        self.reports_dir.mkdir(exist_ok=True)
        
        # Supported severity levels for filtering
        self.severity_levels = ['Critical', 'High', 'Medium', 'Low']
        
        # Supported export formats
        self.export_formats = ['json', 'txt', 'csv', 'html']
        
    def execute(self, args=None):
        """
        Execute report command with specified action and options.
        
        Args:
            args (str, optional): Action and options for report management
            
        Returns:
            bool: True if command executed successfully
        """
        try:
            if not args or not args.strip():
                self._show_usage()
                return False
            
            # Parse arguments
            parts = args.strip().split()
            action = parts[0].lower()
            
            if action == 'list':
                return self._list_reports()
            elif action == 'view':
                if len(parts) < 2:
                    print("Error: Report file required for view action")
                    return False
                return self._view_report(parts[1:])
            elif action == 'summary':
                if len(parts) < 2:
                    print("Error: Report file required for summary action")
                    return False
                return self._show_summary(parts[1])
            elif action == 'export':
                if len(parts) < 3:
                    print("Error: Input file and output format required for export")
                    return False
                return self._export_report(parts[1], parts[2], parts[3:])
            elif action == 'clean':
                return self._clean_reports(parts[1:])
            elif action == 'compare':
                if len(parts) < 3:
                    print("Error: Two report files required for comparison")
                    return False
                return self._compare_reports(parts[1], parts[2])
            else:
                print(f"Error: Unknown action '{action}'")
                self._show_usage()
                return False
                
        except Exception as e:
            print(f"Error executing report command: {str(e)}")
            return False
    
    def _list_reports(self):
        """List all available report files with basic information."""
        try:
            # Find all TXT report files
            report_files = list(self.reports_dir.glob("*.txt"))
            
            if not report_files:
                print("No report files found in reports directory")
                return True
            
            print("Available Reports:")
            print("=" * 80)
            print(f"{'File':<30} {'Date':<20} {'Target':<25} {'Vulnerabilities':<15}")
            print("-" * 80)
            
            for report_file in sorted(report_files):
                try:
                    # Extract basic info from text file
                    with open(report_file, 'r', encoding='utf-8') as f:
                        content = f.read()
                    
                    file_name = report_file.name
                    
                    # Parse basic information from text format
                    target = 'Unknown'
                    scan_date = 'Unknown'
                    vuln_count = 0
                    
                    lines = content.split('\n')
                    for line in lines:
                        if line.startswith('Target URL      :'):
                            target = line.split(':', 1)[1].strip()
                        elif line.startswith('Scan Date       :'):
                            scan_date = line.split(':', 1)[1].strip()
                        elif line.startswith('Total Vulnerabilities Found:'):
                            try:
                                vuln_count = int(line.split(':')[1].strip())
                            except:
                                vuln_count = 0
                    
                    print(f"{file_name:<30} {scan_date:<20} {target:<25} {vuln_count:<15}")
                    
                except Exception as e:
                    print(f"{report_file.name:<30} {'Error reading file':<45}")
            
            print(f"\nTotal reports: {len(report_files)}")
            return True
            
        except Exception as e:
            print(f"Error listing reports: {str(e)}")
            return False
    
    def _view_report(self, args):
        """View detailed report with optional filtering."""
        try:
            if not args:
                print("Error: Report file required")
                return False
            
            report_file = args[0]
            
            # Parse view options
            severity_filter = None
            type_filter = None
            show_details = True
            
            i = 1
            while i < len(args):
                if args[i] == '--severity' and i + 1 < len(args):
                    severity_filter = args[i + 1].capitalize()
                    i += 2
                elif args[i] == '--type' and i + 1 < len(args):
                    type_filter = args[i + 1]
                    i += 2
                elif args[i] == '--summary':
                    show_details = False
                    i += 1
                else:
                    print(f"Warning: Unknown option '{args[i]}'")
                    i += 1
            
            # Load report data
            report_path = Path(report_file)
            if not report_path.exists():
                # Try in reports directory
                report_path = self.reports_dir / report_file
                if not report_path.exists():
                    print(f"Error: Report file '{report_file}' not found")
                    return False
            
            with open(report_path, 'r') as f:
                data = json.load(f)
            
            # Display report
            self._display_report(data, severity_filter, type_filter, show_details)
            return True
            
        except Exception as e:
            print(f"Error viewing report: {str(e)}")
            return False
    
    def _display_report(self, data, severity_filter=None, type_filter=None, show_details=True):
        """Display formatted report data."""
        scan_info = data.get('scan_info', {})
        vulnerabilities = data.get('vulnerabilities', [])
        summary = data.get('summary', {})
        
        # Display header
        print("=" * 80)
        print("VULNERABILITY SCAN REPORT")
        print("=" * 80)
        print(f"Target: {scan_info.get('target', 'Unknown')}")
        print(f"Date: {scan_info.get('start_time', 'Unknown')}")
        print(f"Duration: {scan_info.get('duration', 'Unknown')}")
        print(f"Scanner Version: {scan_info.get('scanner_version', 'Unknown')}")
        print(f"Modules: {', '.join(scan_info.get('modules', []))}")
        
        # Filter vulnerabilities
        filtered_vulns = vulnerabilities
        if severity_filter:
            filtered_vulns = [v for v in filtered_vulns if v.get('severity') == severity_filter]
        if type_filter:
            filtered_vulns = [v for v in filtered_vulns if type_filter.lower() in v.get('type', '').lower()]
        
        # Display summary
        print(f"\nSUMMARY:")
        print(f"Total vulnerabilities: {len(vulnerabilities)}")
        if severity_filter or type_filter:
            print(f"Filtered vulnerabilities: {len(filtered_vulns)}")
        
        # Display severity breakdown
        severity_counts = summary.get('by_severity', {})
        if severity_counts:
            print("\nBy Severity:")
            for severity in self.severity_levels:
                count = severity_counts.get(severity, 0)
                if count > 0:
                    print(f"  {severity}: {count}")
        
        # Display type breakdown
        type_counts = summary.get('by_type', {})
        if type_counts:
            print("\nBy Type:")
            for vuln_type, count in type_counts.items():
                print(f"  {vuln_type}: {count}")
        
        # Display detailed vulnerabilities
        if show_details and filtered_vulns:
            print(f"\nDETAILED RESULTS ({len(filtered_vulns)} vulnerabilities):")
            print("-" * 80)
            
            for i, vuln in enumerate(filtered_vulns, 1):
                print(f"\n{i}. {vuln.get('type', 'Unknown')} ({vuln.get('severity', 'Unknown')})")
                print(f"   URL: {vuln.get('url', 'N/A')}")
                print(f"   Description: {vuln.get('description', 'N/A')}")
                if vuln.get('payload'):
                    print(f"   Payload: {vuln['payload']}")
        
        print("\n" + "=" * 80)
    
    def _show_summary(self, report_file):
        """Show quick summary of a report file."""
        try:
            report_path = Path(report_file)
            if not report_path.exists():
                report_path = self.reports_dir / report_file
                if not report_path.exists():
                    print(f"Error: Report file '{report_file}' not found")
                    return False
            
            with open(report_path, 'r') as f:
                data = json.load(f)
            
            scan_info = data.get('scan_info', {})
            summary = data.get('summary', {})
            
            print(f"Report Summary: {report_path.name}")
            print(f"Target: {scan_info.get('target', 'Unknown')}")
            print(f"Date: {scan_info.get('start_time', 'Unknown')}")
            print(f"Duration: {scan_info.get('duration', 'Unknown')}")
            print(f"Total Vulnerabilities: {summary.get('total_vulnerabilities', 0)}")
            
            severity_counts = summary.get('by_severity', {})
            if any(severity_counts.values()):
                print("Severity Breakdown:")
                for severity in self.severity_levels:
                    count = severity_counts.get(severity, 0)
                    if count > 0:
                        print(f"  {severity}: {count}")
            
            return True
            
        except Exception as e:
            print(f"Error showing summary: {str(e)}")
            return False
    
    def _export_report(self, input_file, format_type, options):
        """Export report to different format."""
        try:
            # Validate format
            if format_type.lower() not in self.export_formats:
                print(f"Error: Unsupported format '{format_type}'")
                print(f"Supported formats: {', '.join(self.export_formats)}")
                return False
            
            # Load source report
            report_path = Path(input_file)
            if not report_path.exists():
                report_path = self.reports_dir / input_file
                if not report_path.exists():
                    print(f"Error: Report file '{input_file}' not found")
                    return False
            
            with open(report_path, 'r') as f:
                data = json.load(f)
            
            # Generate output filename if not provided
            output_file = None
            if options:
                output_file = options[0]
            else:
                base_name = report_path.stem
                output_file = f"{base_name}.{format_type.lower()}"
            
            output_path = Path(output_file)
            
            # Export based on format
            if format_type.lower() == 'txt':
                self._export_txt(data, output_path)
            elif format_type.lower() == 'csv':
                self._export_csv(data, output_path)
            elif format_type.lower() == 'html':
                self._export_html(data, output_path)
            elif format_type.lower() == 'json':
                # Just copy with pretty formatting
                with open(output_path, 'w') as f:
                    json.dump(data, f, indent=2)
            
            print(f"Report exported to: {output_path}")
            return True
            
        except Exception as e:
            print(f"Error exporting report: {str(e)}")
            return False
    
    def _export_txt(self, data, output_path):
        """Export report as plain text."""
        with open(output_path, 'w') as f:
            scan_info = data.get('scan_info', {})
            vulnerabilities = data.get('vulnerabilities', [])
            summary = data.get('summary', {})
            
            f.write("VULNERABILITY SCAN REPORT\n")
            f.write("=" * 50 + "\n")
            f.write(f"Target: {scan_info.get('target', 'Unknown')}\n")
            f.write(f"Date: {scan_info.get('start_time', 'Unknown')}\n")
            f.write(f"Duration: {scan_info.get('duration', 'Unknown')}\n")
            f.write(f"Total Vulnerabilities: {summary.get('total_vulnerabilities', 0)}\n\n")
            
            if vulnerabilities:
                f.write("VULNERABILITIES:\n")
                f.write("-" * 30 + "\n")
                for i, vuln in enumerate(vulnerabilities, 1):
                    f.write(f"{i}. {vuln.get('type', 'Unknown')} ({vuln.get('severity', 'Unknown')})\n")
                    f.write(f"   URL: {vuln.get('url', 'N/A')}\n")
                    f.write(f"   Description: {vuln.get('description', 'N/A')}\n")
                    if vuln.get('payload'):
                        f.write(f"   Payload: {vuln['payload']}\n")
                    f.write("\n")
    
    def _export_csv(self, data, output_path):
        """Export report as CSV."""
        with open(output_path, 'w') as f:
            vulnerabilities = data.get('vulnerabilities', [])
            
            # CSV header
            f.write("Type,Severity,URL,Description,Payload\n")
            
            # Vulnerability data
            for vuln in vulnerabilities:
                vuln_type = vuln.get('type', '').replace(',', ';')
                severity = vuln.get('severity', '')
                url = vuln.get('url', '').replace(',', ';')
                description = vuln.get('description', '').replace(',', ';')
                payload = vuln.get('payload', '').replace(',', ';')
                
                f.write(f'"{vuln_type}","{severity}","{url}","{description}","{payload}"\n')
    
    def _export_html(self, data, output_path):
        """Export report as HTML."""
        with open(output_path, 'w') as f:
            scan_info = data.get('scan_info', {})
            vulnerabilities = data.get('vulnerabilities', [])
            summary = data.get('summary', {})
            
            f.write("""<!DOCTYPE html>
<html>
<head>
    <title>ReconScan Vulnerability Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .header { background-color: #f0f0f0; padding: 15px; border-radius: 5px; }
        .summary { margin: 20px 0; }
        .vulnerability { border: 1px solid #ddd; margin: 10px 0; padding: 15px; border-radius: 5px; }
        .critical { border-left: 5px solid #d32f2f; }
        .high { border-left: 5px solid #f57c00; }
        .medium { border-left: 5px solid #fbc02d; }
        .low { border-left: 5px solid #388e3c; }
        .severity { font-weight: bold; padding: 2px 8px; border-radius: 3px; color: white; }
        .critical-badge { background-color: #d32f2f; }
        .high-badge { background-color: #f57c00; }
        .medium-badge { background-color: #fbc02d; }
        .low-badge { background-color: #388e3c; }
    </style>
</head>
<body>
""")
            
            f.write(f"""<div class="header">
    <h1>Vulnerability Scan Report</h1>
    <p><strong>Target:</strong> {scan_info.get('target', 'Unknown')}</p>
    <p><strong>Date:</strong> {scan_info.get('start_time', 'Unknown')}</p>
    <p><strong>Duration:</strong> {scan_info.get('duration', 'Unknown')}</p>
    <p><strong>Total Vulnerabilities:</strong> {summary.get('total_vulnerabilities', 0)}</p>
</div>
""")
            
            if vulnerabilities:
                f.write("<h2>Vulnerabilities</h2>")
                for i, vuln in enumerate(vulnerabilities, 1):
                    severity = vuln.get('severity', 'Unknown').lower()
                    f.write(f"""<div class="vulnerability {severity}">
    <h3>{i}. {vuln.get('type', 'Unknown')} 
        <span class="severity {severity}-badge">{vuln.get('severity', 'Unknown')}</span>
    </h3>
    <p><strong>URL:</strong> {vuln.get('url', 'N/A')}</p>
    <p><strong>Description:</strong> {vuln.get('description', 'N/A')}</p>
""")
                    if vuln.get('payload'):
                        f.write(f"    <p><strong>Payload:</strong> <code>{vuln['payload']}</code></p>")
                    f.write("</div>")
            
            f.write("</body></html>")
    
    def _clean_reports(self, options):
        """Clean old report files."""
        try:
            days = 30  # Default: clean files older than 30 days
            
            if options and options[0].isdigit():
                days = int(options[0])
            
            # Find old files
            cutoff_time = datetime.now().timestamp() - (days * 24 * 60 * 60)
            old_files = []
            
            for report_file in self.reports_dir.glob("*.json"):
                if report_file.stat().st_mtime < cutoff_time:
                    old_files.append(report_file)
            
            if not old_files:
                print(f"No report files older than {days} days found")
                return True
            
            print(f"Found {len(old_files)} report files older than {days} days:")
            for f in old_files:
                mod_time = datetime.fromtimestamp(f.stat().st_mtime)
                print(f"  {f.name} ({mod_time.strftime('%Y-%m-%d %H:%M')})")
            
            # Confirm deletion
            confirm = input("\nDelete these files? (y/N): ").lower()
            if confirm == 'y' or confirm == 'yes':
                for f in old_files:
                    f.unlink()
                print(f"Deleted {len(old_files)} old report files")
            else:
                print("Clean operation cancelled")
            
            return True
            
        except Exception as e:
            print(f"Error cleaning reports: {str(e)}")
            return False
    
    def _compare_reports(self, file1, file2):
        """Compare two report files."""
        try:
            # Load both reports
            reports = []
            for filename in [file1, file2]:
                report_path = Path(filename)
                if not report_path.exists():
                    report_path = self.reports_dir / filename
                    if not report_path.exists():
                        print(f"Error: Report file '{filename}' not found")
                        return False
                
                with open(report_path, 'r') as f:
                    reports.append(json.load(f))
            
            report1, report2 = reports
            
            print("REPORT COMPARISON")
            print("=" * 60)
            
            # Compare basic info
            info1 = report1.get('scan_info', {})
            info2 = report2.get('scan_info', {})
            
            print(f"Report 1: {info1.get('target', 'Unknown')} ({info1.get('start_time', 'Unknown')})")
            print(f"Report 2: {info2.get('target', 'Unknown')} ({info2.get('start_time', 'Unknown')})")
            
            # Compare vulnerability counts
            summary1 = report1.get('summary', {})
            summary2 = report2.get('summary', {})
            
            total1 = summary1.get('total_vulnerabilities', 0)
            total2 = summary2.get('total_vulnerabilities', 0)
            
            print(f"\nVulnerability Count:")
            print(f"Report 1: {total1}")
            print(f"Report 2: {total2}")
            print(f"Difference: {total2 - total1:+d}")
            
            # Compare by severity
            sev1 = summary1.get('by_severity', {})
            sev2 = summary2.get('by_severity', {})
            
            print(f"\nBy Severity:")
            for severity in self.severity_levels:
                count1 = sev1.get(severity, 0)
                count2 = sev2.get(severity, 0)
                diff = count2 - count1
                print(f"  {severity}: {count1} → {count2} ({diff:+d})")
            
            return True
            
        except Exception as e:
            print(f"Error comparing reports: {str(e)}")
            return False
    
    @staticmethod
    def generate_text_report(scan_results, output_path):
        """
        Generate a professional formatted text report from scan results.
        
        Args:
            scan_results (dict): Scan results data
            output_path (Path): Output file path
        """
        with open(output_path, 'w', encoding='utf-8') as f:
            scan_info = scan_results['scan_info']
            vulnerabilities = scan_results['vulnerabilities']
            summary = scan_results['summary']
            
            # Header section
            f.write("=" * 80 + "\n")
            f.write("                      RECONSCAN VULNERABILITY REPORT\n")
            f.write("=" * 80 + "\n\n")
            
            # Scan information
            f.write("SCAN INFORMATION\n")
            f.write("-" * 40 + "\n")
            f.write(f"Target URL      : {scan_info.get('target', 'Unknown')}\n")
            f.write(f"Scan Date       : {scan_info.get('start_time', 'Unknown')}\n")
            f.write(f"Duration        : {scan_info.get('duration', 'Unknown')}\n")
            f.write(f"Scanner Version : {scan_info.get('scanner_version', 'Unknown')}\n")
            f.write(f"Modules Used    : {', '.join(scan_info.get('modules', []))}\n\n")
            
            # Executive summary
            f.write("EXECUTIVE SUMMARY\n")
            f.write("-" * 40 + "\n")
            total_vulns = summary.get('total_vulnerabilities', 0)
            f.write(f"Total Vulnerabilities Found: {total_vulns}\n\n")
            
            if total_vulns > 0:
                # Severity breakdown
                severity_counts = summary.get('by_severity', {})
                f.write("Severity Breakdown:\n")
                for severity in ['Critical', 'High', 'Medium', 'Low']:
                    count = severity_counts.get(severity, 0)
                    if count > 0:
                        status_icon = "🔴" if severity == 'Critical' else "🟠" if severity == 'High' else "🟡" if severity == 'Medium' else "🟢"
                        f.write(f"  {status_icon} {severity:<10}: {count} vulnerabilities\n")
                
                f.write("\n")
                
                # Risk assessment
                f.write("RISK ASSESSMENT\n")
                f.write("-" * 40 + "\n")
                critical_count = severity_counts.get('Critical', 0)
                high_count = severity_counts.get('High', 0)
                
                if critical_count > 0:
                    f.write("🔴 CRITICAL RISK: Immediate action required!\n")
                    f.write(f"   {critical_count} critical vulnerabilities detected that could lead to\n")
                    f.write("   complete system compromise.\n\n")
                elif high_count > 0:
                    f.write("🟠 HIGH RISK: Urgent remediation needed.\n")
                    f.write(f"   {high_count} high-severity vulnerabilities could allow significant\n")
                    f.write("   unauthorized access or data exposure.\n\n")
                else:
                    f.write("🟡 MODERATE RISK: Address vulnerabilities in planned maintenance.\n\n")
                
                # Vulnerability types
                type_counts = summary.get('by_type', {})
                if type_counts:
                    f.write("Vulnerability Types:\n")
                    for vuln_type, count in sorted(type_counts.items()):
                        f.write(f"  • {vuln_type}: {count}\n")
                    f.write("\n")
            else:
                f.write("✅ No vulnerabilities detected in this scan.\n")
                f.write("   The target appears to be properly secured against\n")
                f.write("   the tested attack vectors.\n\n")
            
            # Detailed findings
            if vulnerabilities:
                f.write("DETAILED VULNERABILITY FINDINGS\n")
                f.write("=" * 80 + "\n\n")
                
                # Group by severity for better organization
                for severity in ['Critical', 'High', 'Medium', 'Low']:
                    severity_vulns = [v for v in vulnerabilities if v.get('severity') == severity]
                    if not severity_vulns:
                        continue
                    
                    f.write(f"{severity.upper()} SEVERITY VULNERABILITIES\n")
                    f.write("-" * 50 + "\n\n")
                    
                    for i, vuln in enumerate(severity_vulns, 1):
                        f.write(f"[{severity[0]}{i:02d}] {vuln.get('type', 'Unknown Vulnerability')}\n")
                        f.write("─" * 60 + "\n")
                        f.write(f"Severity     : {vuln.get('severity', 'Unknown')}\n")
                        f.write(f"URL          : {vuln.get('url', 'N/A')}\n")
                        f.write(f"Description  : {vuln.get('description', 'N/A')}\n")
                        
                        if vuln.get('payload'):
                            f.write(f"Payload Used : {vuln['payload']}\n")
                        
                        # Add remediation advice based on vulnerability type
                        vuln_type = vuln.get('type', '').lower()
                        f.write("Remediation  : ")
                        if 'sql injection' in vuln_type:
                            f.write("Use parameterized queries and input validation\n")
                        elif 'xss' in vuln_type:
                            f.write("Implement proper output encoding and CSP headers\n")
                        elif 'lfi' in vuln_type or 'file inclusion' in vuln_type:
                            f.write("Validate file paths and implement access controls\n")
                        elif 'command injection' in vuln_type:
                            f.write("Avoid system calls with user input, use safe APIs\n")
                        elif 'header' in vuln_type:
                            f.write("Configure proper security headers in web server\n")
                        else:
                            f.write("Review security best practices for this vulnerability type\n")
                        
                        f.write("\n")
                    
                    f.write("\n")
            
            # Recommendations section
            f.write("SECURITY RECOMMENDATIONS\n")
            f.write("=" * 80 + "\n\n")
            
            if total_vulns > 0:
                f.write("IMMEDIATE ACTIONS:\n")
                f.write("• Review and address all Critical and High severity vulnerabilities\n")
                f.write("• Implement proper input validation and output encoding\n")
                f.write("• Configure security headers (CSP, X-Frame-Options, etc.)\n")
                f.write("• Regular security testing and code reviews\n\n")
                
                f.write("LONG-TERM IMPROVEMENTS:\n")
                f.write("• Implement a Web Application Firewall (WAF)\n")
                f.write("• Regular penetration testing and vulnerability assessments\n")
                f.write("• Security awareness training for development team\n")
                f.write("• Automated security scanning in CI/CD pipeline\n\n")
            else:
                f.write("MAINTAIN SECURITY POSTURE:\n")
                f.write("• Continue regular security assessments\n")
                f.write("• Keep all software components updated\n")
                f.write("• Monitor for new vulnerability types and attack vectors\n")
                f.write("• Implement security logging and monitoring\n\n")
            
            # Footer
            f.write("=" * 80 + "\n")
            f.write("Report generated by ReconScan - Web Application Vulnerability Scanner\n")
            f.write(f"For questions or support, contact: {scan_info.get('scanner_version', 'ReconScan Team')}\n")
            f.write("=" * 80 + "\n")
    
    @staticmethod
    def save_scan_results(scan_results, output_file):
        """
        Save scan results to formatted text file in reports directory.
        
        Args:
            scan_results (dict): Scan results data
            output_file (str): Output filename
            
        Returns:
            Path: Path to saved report file
        """
        # Ensure we're saving to reports directory
        if not output_file.startswith('reports/'):
            output_file = f"reports/{output_file}"
        
        # Ensure .txt extension
        if not output_file.endswith('.txt'):
            output_file = output_file.replace('.json', '.txt') if '.json' in output_file else f"{output_file}.txt"
        
        output_path = Path(output_file)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Generate professional text report
        ReportCommand.generate_text_report(scan_results, output_path)
        
        return output_path
    
    def _show_usage(self):
        """Display usage information."""
        print("Usage: report <action> [options]")
        print("\nAvailable actions:")
        print("  list                           - List all available reports")
        print("  view <file> [filters]          - View detailed report")
        print("  summary <file>                 - Show quick summary")
        print("  export <file> <format> [out]   - Export to different format")
        print("  clean [days]                   - Clean old report files")
        print("  compare <file1> <file2>        - Compare two reports")
        print("\nView filters:")
        print("  --severity <level>             - Filter by severity (Critical, High, Medium, Low)")
        print("  --type <type>                  - Filter by vulnerability type")
        print("  --summary                      - Show summary only")
        print("\nExport formats:")
        print("  " + ", ".join(self.export_formats))
        print("\nExamples:")
        print("  report list")
        print("  report view scan_results.txt --severity High")
        print("  report summary latest_scan.txt")
        print("  report export results.txt html report.html")
        print("  report clean 7")
        print("  report compare old_scan.txt new_scan.txt")
