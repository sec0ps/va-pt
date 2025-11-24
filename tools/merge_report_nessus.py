#!/usr/bin/env python3
"""
Nessus File Merger & Report Generator
Merges .nessus files, deduplicates findings, and generates DOCX reports.
"""

import os
import sys
import json
import argparse
import subprocess
import xml.etree.ElementTree as ET
from pathlib import Path
from datetime import datetime
from collections import defaultdict


class NessusFinding:
    """Represents a deduplicated Nessus finding."""
    
    def __init__(self, plugin_id):
        self.plugin_id = plugin_id
        self.name = ""
        self.severity = ""
        self.cvss_score = ""
        self.description = ""
        self.solution = ""
        self.references = []
        self.affected_systems = []
        self.evidence = ""
        
    def to_dict(self):
        """Convert finding to dictionary for JSON serialization."""
        return {
            'plugin_id': self.plugin_id,
            'name': self.name,
            'severity': self.severity,
            'cvss_score': self.cvss_score,
            'description': self.description,
            'solution': self.solution,
            'references': self.references,
            'affected_systems': self.affected_systems,
            'evidence': self.evidence
        }


def find_nessus_files(directory):
    """Scan directory recursively for .nessus files."""
    nessus_files = []
    for root, dirs, files in os.walk(directory):
        for file in files:
            if file.endswith('.nessus'):
                nessus_files.append(os.path.join(root, file))
    return sorted(nessus_files)


def parse_nessus_file(filepath):
    """Parse a .nessus file and return the ElementTree."""
    try:
        tree = ET.parse(filepath)
        return tree
    except ET.ParseError as e:
        print(f"[!] Parse error in {filepath}: {e}")
        return None
    except Exception as e:
        print(f"[!] Error reading {filepath}: {e}")
        return None


def extract_text(element, tag):
    """Safely extract text from XML element."""
    child = element.find(tag)
    return child.text if child is not None and child.text else ""


def extract_references(report_item):
    """Extract and combine all references (CVE, xref, etc)."""
    refs = []
    
    # Extract CVE references
    for cve in report_item.findall('cve'):
        if cve.text:
            refs.append(f"CVE: {cve.text}")
    
    # Extract xref references
    for xref in report_item.findall('xref'):
        if xref.text:
            refs.append(xref.text)
    
    # Extract see_also references
    for see_also in report_item.findall('see_also'):
        if see_also.text:
            refs.append(see_also.text)
    
    return refs


def parse_findings(nessus_files):
    """
    Parse all .nessus files and deduplicate findings by plugin_id.
    Returns dictionary of findings organized by severity.
    """
    findings_map = {}  # plugin_id -> NessusFinding
    
    for nessus_file in nessus_files:
        tree = parse_nessus_file(nessus_file)
        if tree is None:
            continue
        
        root = tree.getroot()
        report = root.find('Report')
        if report is None:
            continue
        
        # Process each host
        for report_host in report.findall('ReportHost'):
            host_name = report_host.get('name', 'Unknown')
            
            # Process each finding on this host
            for report_item in report_host.findall('ReportItem'):
                plugin_id = report_item.get('pluginID', '')
                severity = extract_text(report_item, 'risk_factor')
                
                # Skip informational findings
                if severity.lower() in ['none', '']:
                    continue
                
                # Get or create finding
                if plugin_id not in findings_map:
                    finding = NessusFinding(plugin_id)
                    finding.name = report_item.get('pluginName', 'Unknown')
                    finding.severity = severity
                    finding.cvss_score = extract_text(report_item, 'cvss_base_score')
                    finding.description = extract_text(report_item, 'description')
                    finding.solution = extract_text(report_item, 'solution')
                    finding.references = extract_references(report_item)
                    finding.evidence = extract_text(report_item, 'plugin_output')
                    findings_map[plugin_id] = finding
                
                # Add this host to affected systems
                port = report_item.get('port', '')
                protocol = report_item.get('protocol', '')
                svc_name = report_item.get('svc_name', '')
                
                system_info = host_name
                if port and port != '0':
                    system_info += f":{port}"
                if protocol:
                    system_info += f" ({protocol}"
                    if svc_name:
                        system_info += f"/{svc_name}"
                    system_info += ")"
                
                if system_info not in findings_map[plugin_id].affected_systems:
                    findings_map[plugin_id].affected_systems.append(system_info)
    
    # Organize findings by severity
    severity_order = ['Critical', 'High', 'Medium', 'Low']
    organized = {sev: [] for sev in severity_order}
    
    for finding in findings_map.values():
        if finding.severity in organized:
            organized[finding.severity].append(finding)
    
    # Sort findings within each severity by name
    for sev in severity_order:
        organized[sev].sort(key=lambda x: x.name)
    
    return organized


def merge_nessus_files(nessus_files, output_file):
    """
    Merge multiple .nessus files into a single output file.
    Uses the Policy from the first file and combines all ReportHost elements.
    """
    if not nessus_files:
        print("[!] No .nessus files found to merge")
        return False
    
    print(f"[*] Found {len(nessus_files)} .nessus file(s)")
    
    # Parse first file as the base
    base_tree = parse_nessus_file(nessus_files[0])
    if base_tree is None:
        print(f"[!] Failed to parse base file: {nessus_files[0]}")
        return False
    
    base_root = base_tree.getroot()
    base_report = base_root.find('Report')
    
    if base_report is None:
        print("[!] No Report element found in base file")
        return False
    
    print(f"[+] Using {nessus_files[0]} as base structure")
    
    # Track statistics
    total_hosts = 0
    total_items = 0
    host_count_base = len(base_report.findall('ReportHost'))
    
    # Count items in base file
    for report_host in base_report.findall('ReportHost'):
        total_items += len(report_host.findall('ReportItem'))
    
    total_hosts = host_count_base
    
    # Merge remaining files
    for nessus_file in nessus_files[1:]:
        print(f"[*] Merging: {nessus_file}")
        tree = parse_nessus_file(nessus_file)
        
        if tree is None:
            print(f"[!] Skipping {nessus_file} due to parse error")
            continue
        
        root = tree.getroot()
        report = root.find('Report')
        
        if report is None:
            print(f"[!] No Report element in {nessus_file}, skipping")
            continue
        
        # Add all ReportHost elements from this file
        report_hosts = report.findall('ReportHost')
        for report_host in report_hosts:
            base_report.append(report_host)
            total_hosts += 1
            total_items += len(report_host.findall('ReportItem'))
        
        print(f"    Added {len(report_hosts)} host(s)")
    
    # Update Report name to indicate merged status
    report_name = base_report.get('name', 'merged_scan')
    base_report.set('name', f"{report_name}_merged_{datetime.now().strftime('%Y%m%d_%H%M%S')}")
    
    # Write merged output
    try:
        ET.indent(base_tree, space="  ")
        base_tree.write(output_file, encoding='utf-8', xml_declaration=True)
        print(f"\n[+] Successfully merged {len(nessus_files)} file(s)")
        print(f"[+] Total hosts: {total_hosts}")
        print(f"[+] Total findings: {total_items}")
        print(f"[+] Output written to: {output_file}")
        return True
    except Exception as e:
        print(f"[!] Error writing output file: {e}")
        return False


def display_test_finding(organized_findings):
    """Display the first parsed finding for testing."""
    print("\n" + "="*80)
    print("TEST MODE - Displaying First Parsed Finding")
    print("="*80 + "\n")
    
    # Find first finding across all severities
    for severity in ['Critical', 'High', 'Medium', 'Low']:
        if organized_findings[severity]:
            finding = organized_findings[severity][0]
            
            print(f"Severity: {finding.severity}")
            print(f"Finding: {finding.name}")
            print(f"Plugin ID: {finding.plugin_id}")
            if finding.cvss_score:
                print(f"CVSS Score: {finding.cvss_score}")
            print(f"\nAffected System(s):")
            for system in finding.affected_systems:
                print(f"  - {system}")
            print(f"\nDescription:")
            print(f"{finding.description[:500]}..." if len(finding.description) > 500 else finding.description)
            print(f"\nRemediation:")
            print(f"{finding.solution[:500]}..." if len(finding.solution) > 500 else finding.solution)
            if finding.references:
                print(f"\nReferences:")
                for ref in finding.references[:10]:  # Limit to first 10
                    print(f"  {ref}")
                if len(finding.references) > 10:
                    print(f"  ... and {len(finding.references) - 10} more")
            if finding.evidence:
                print(f"\nEvidence (first occurrence):")
                print(f"{finding.evidence[:500]}..." if len(finding.evidence) > 500 else finding.evidence)
            
            print("\n" + "="*80)
            return
    
    print("[!] No findings found to display")


def generate_report(organized_findings, output_file):
    """Generate DOCX report using Node.js script."""
    # Save findings to temporary JSON file
    json_file = "/tmp/nessus_findings.json"
    
    report_data = {
        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'findings': {sev: [f.to_dict() for f in findings] 
                    for sev, findings in organized_findings.items()}
    }
    
    with open(json_file, 'w') as f:
        json.dump(report_data, f, indent=2)
    
    print(f"[*] Generating DOCX report...")
    
    # Call Node.js script to generate DOCX
    script_dir = os.path.dirname(os.path.abspath(__file__))
    node_script = os.path.join(script_dir, 'generate_report.js')
    
    try:
        result = subprocess.run(
            ['node', node_script, json_file, output_file],
            capture_output=True,
            text=True,
            check=True
        )
        print(f"[+] Report generated: {output_file}")
        return True
    except subprocess.CalledProcessError as e:
        print(f"[!] Error generating report: {e.stderr}")
        return False
    except FileNotFoundError:
        print("[!] Node.js not found. Please install Node.js to generate reports.")
        return False


def main():
    """Main execution function."""
    parser = argparse.ArgumentParser(
        description='Nessus File Merger & Report Generator',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Merge and generate report
  python3 nessus_merger.py /path/to/scans
  
  # Test mode - view parsed data
  python3 nessus_merger.py /path/to/scans --test
  
  # Report only from single file
  python3 nessus_merger.py /path/to/scan.nessus --report
  
  # Merge without report
  python3 nessus_merger.py /path/to/scans --output merged.nessus --no-report
        """
    )
    
    parser.add_argument('path', help='Directory containing .nessus files or single .nessus file')
    parser.add_argument('--output', '-o', default='merged_scan.nessus',
                       help='Output filename for merged .nessus file (default: merged_scan.nessus)')
    parser.add_argument('--report', '-r', action='store_true',
                       help='Generate report only (use with single .nessus file)')
    parser.add_argument('--test', '-t', action='store_true',
                       help='Test mode: display first parsed finding without generating report')
    parser.add_argument('--no-report', action='store_true',
                       help='Skip report generation (merge only)')
    parser.add_argument('--report-output', default='nessus_report.docx',
                       help='Output filename for DOCX report (default: nessus_report.docx)')
    
    args = parser.parse_args()
    
    # Determine operation mode
    if args.report:
        # Report-only mode: single file
        if not os.path.isfile(args.path):
            print(f"[!] Error: {args.path} is not a valid file")
            sys.exit(1)
        
        if not args.path.endswith('.nessus'):
            print(f"[!] Error: {args.path} is not a .nessus file")
            sys.exit(1)
        
        print(f"[*] Report-only mode: {args.path}")
        nessus_files = [args.path]
        
    else:
        # Merge mode: directory or file
        if os.path.isfile(args.path):
            if not args.path.endswith('.nessus'):
                print(f"[!] Error: {args.path} is not a .nessus file")
                sys.exit(1)
            nessus_files = [args.path]
        elif os.path.isdir(args.path):
            print(f"[*] Scanning directory: {args.path}")
            nessus_files = find_nessus_files(args.path)
            
            if not nessus_files:
                print("[!] No .nessus files found in directory")
                sys.exit(1)
            
            print(f"\n[*] Files found:")
            for idx, file in enumerate(nessus_files, 1):
                file_size = os.path.getsize(file) / 1024
                print(f"    {idx}. {file} ({file_size:.1f} KB)")
        else:
            print(f"[!] Error: {args.path} is not a valid file or directory")
            sys.exit(1)
    
    # Merge files if not in report-only mode and multiple files exist
    if not args.report and len(nessus_files) > 1:
        print("\n[*] Starting merge process...")
        if not merge_nessus_files(nessus_files, args.output):
            print("[!] Merge failed")
            sys.exit(1)
        output_size = os.path.getsize(args.output) / 1024
        print(f"[+] Merged file size: {output_size:.1f} KB")
    
    # Parse findings for report/test
    if not args.no_report or args.test or args.report:
        print("\n[*] Parsing findings and deduplicating...")
        organized_findings = parse_findings(nessus_files)
        
        # Calculate statistics
        total_findings = sum(len(findings) for findings in organized_findings.values())
        print(f"[+] Unique findings after deduplication: {total_findings}")
        for severity in ['Critical', 'High', 'Medium', 'Low']:
            count = len(organized_findings[severity])
            if count > 0:
                print(f"    {severity}: {count}")
        
        # Test mode
        if args.test:
            display_test_finding(organized_findings)
            sys.exit(0)
        
        # Generate report
        if not args.no_report:
            if generate_report(organized_findings, args.report_output):
                report_size = os.path.getsize(args.report_output) / 1024
                print(f"[+] Report size: {report_size:.1f} KB")
            else:
                print("[!] Report generation failed")
                sys.exit(1)
    
    print("\n[+] Operation completed successfully")


if __name__ == "__main__":
    main()
