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
            # Find all JSON report files
            report_files = list(self.reports_dir.glob("*.json"))
            
            if not report_files:
                print("No report files found in reports directory")
                return True
            
            print("Available Reports:")
            print("=" * 80)
            print(f"{'File':<30} {'Date':<20} {'Target':<25} {'Vulnerabilities':<15}")
            print("-" * 80)
            
            for report_file in sorted(report_files):
                try:
                    with open(report_file, 'r') as f:
                        data = json.load(f)
                    
                    # Extract basic information
                    scan_info = data.get('scan_info', {})
                    summary = data.get('summary', {})
                    
                    file_name = report_file.name
                    scan_date = scan_info.get('start_time', 'Unknown')
                    target = scan_info.get('target', 'Unknown')
                    vuln_count = summary.get('total_vulnerabilities', 0)
                    
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
        print("  report view scan_results.json --severity High")
        print("  report summary latest_scan.json")
        print("  report export results.json html report.html")
        print("  report clean 7")
        print("  report compare old_scan.json new_scan.json")
